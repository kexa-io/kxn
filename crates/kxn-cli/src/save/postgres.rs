use anyhow::{Context, Result};
use kxn_rules::SaveConfig;
use tokio_postgres::{Client, NoTls};

use super::{LogRecord, MetricRecord, ScanRecord};

const CREATE_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS providers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS provider_items (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    provider_id INT REFERENCES providers(id),
    UNIQUE (name, provider_id)
);
CREATE TABLE IF NOT EXISTS origins (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT
);
CREATE TABLE IF NOT EXISTS resources (
    id SERIAL PRIMARY KEY,
    content JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    origin_id INT REFERENCES origins(id),
    provider_item_id INT REFERENCES provider_items(id)
);
CREATE TABLE IF NOT EXISTS rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    level INT,
    provider_id INT REFERENCES providers(id),
    provider_item_id INT REFERENCES provider_items(id)
);
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    error BOOLEAN,
    messages JSONB,
    conditions JSONB,
    resource_id INT REFERENCES resources(id),
    rule_id INT REFERENCES rules(id),
    batch_id VARCHAR(255),
    target VARCHAR(255)
);
CREATE TABLE IF NOT EXISTS tags (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    value TEXT,
    scan_id INT REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS metrics (
    time TIMESTAMPTZ NOT NULL,
    target VARCHAR(255) NOT NULL,
    provider VARCHAR(255) NOT NULL,
    resource_type VARCHAR(255) NOT NULL,
    metric_name VARCHAR(255) NOT NULL,
    value_num DOUBLE PRECISION,
    value_str TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_batch_id ON scans(batch_id);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_error ON scans(error);
CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics(time);
CREATE INDEX IF NOT EXISTS idx_metrics_target ON metrics(target);
CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(target, resource_type, metric_name);
"#;

pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let url = resolve_url(&config.url);
    let (client, connection) = tokio_postgres::connect(&url, NoTls)
        .await
        .context("PostgreSQL connection failed")?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("PostgreSQL connection error: {}", e);
        }
    });

    client
        .batch_execute(CREATE_TABLES)
        .await
        .context("Failed to create tables")?;

    let origin_id = get_or_create_origin(&client, &config.origin).await?;

    // Wrap records in a transaction for performance (single commit)
    client.execute("BEGIN", &[]).await
        .context("Failed to start transaction")?;
    for record in records {
        if config.only_errors && !record.error {
            continue;
        }
        save_record(&client, record, origin_id).await?;
    }
    client.execute("COMMIT", &[]).await
        .context("Failed to commit transaction")?;

    // Save metrics in a transaction for speed
    if !metrics.is_empty() {
        client.execute("BEGIN", &[]).await?;
        let stmt = client
            .prepare(
                "INSERT INTO metrics (time, target, provider, resource_type, metric_name, value_num, value_str) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .await?;
        for m in metrics {
            client
                .execute(
                    &stmt,
                    &[
                        &m.timestamp,
                        &m.target,
                        &m.provider,
                        &m.resource_type,
                        &m.metric_name,
                        &m.value_num,
                        &m.value_str,
                    ],
                )
                .await?;
        }
        client.execute("COMMIT", &[]).await?;
    }

    Ok(())
}

async fn get_or_create_origin(client: &Client, name: &str) -> Result<i32> {
    client
        .execute(
            "INSERT INTO origins (name) VALUES ($1) ON CONFLICT (name) DO NOTHING",
            &[&name],
        )
        .await?;
    let row = client
        .query_one("SELECT id FROM origins WHERE name = $1", &[&name])
        .await?;
    Ok(row.get(0))
}

async fn get_or_create_provider(client: &Client, name: &str) -> Result<i32> {
    client
        .execute(
            "INSERT INTO providers (name) VALUES ($1) ON CONFLICT (name) DO NOTHING",
            &[&name],
        )
        .await?;
    let row = client
        .query_one("SELECT id FROM providers WHERE name = $1", &[&name])
        .await?;
    Ok(row.get(0))
}

async fn get_or_create_provider_item(
    client: &Client,
    name: &str,
    provider_id: i32,
) -> Result<i32> {
    client
        .execute(
            "INSERT INTO provider_items (name, provider_id) VALUES ($1, $2) ON CONFLICT (name, provider_id) DO NOTHING",
            &[&name, &provider_id],
        )
        .await?;
    let row = client
        .query_one(
            "SELECT id FROM provider_items WHERE name = $1 AND provider_id = $2",
            &[&name, &provider_id],
        )
        .await?;
    Ok(row.get(0))
}

async fn get_or_create_rule(
    client: &Client,
    record: &ScanRecord,
    provider_id: i32,
    provider_item_id: i32,
) -> Result<i32> {
    client
        .execute(
            "INSERT INTO rules (name, description, level, provider_id, provider_item_id) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (name) DO UPDATE SET description = $2, level = $3",
            &[
                &record.rule_name,
                &record.rule_description,
                &(record.level as i32),
                &provider_id,
                &provider_item_id,
            ],
        )
        .await?;
    let row = client
        .query_one("SELECT id FROM rules WHERE name = $1", &[&record.rule_name])
        .await?;
    Ok(row.get(0))
}

async fn get_or_create_resource(
    client: &Client,
    content: &serde_json::Value,
    origin_id: i32,
    provider_item_id: i32,
) -> Result<i32> {
    let row = client
        .query_one(
            "INSERT INTO resources (content, origin_id, provider_item_id) VALUES ($1, $2, $3) RETURNING id",
            &[&content, &origin_id, &provider_item_id],
        )
        .await?;
    Ok(row.get(0))
}

async fn save_record(client: &Client, record: &ScanRecord, origin_id: i32) -> Result<()> {
    let provider_id = get_or_create_provider(client, &record.provider).await?;
    let provider_item_id =
        get_or_create_provider_item(client, &record.object_type, provider_id).await?;
    let rule_id = get_or_create_rule(client, record, provider_id, provider_item_id).await?;
    let resource_id =
        get_or_create_resource(client, &record.object_content, origin_id, provider_item_id)
            .await?;

    let messages_json = serde_json::to_value(&record.messages)?;

    let row = client
        .query_one(
            "INSERT INTO scans (error, messages, conditions, resource_id, rule_id, batch_id, target, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
            &[
                &record.error,
                &messages_json,
                &record.conditions,
                &resource_id,
                &rule_id,
                &record.batch_id,
                &record.target,
                &record.timestamp,
            ],
        )
        .await?;
    let scan_id: i32 = row.get(0);

    for (name, value) in &record.tags {
        client
            .execute(
                "INSERT INTO tags (name, value, scan_id) VALUES ($1, $2, $3)",
                &[&name, &value, &scan_id],
            )
            .await?;
    }

    Ok(())
}

const CREATE_LOGS_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS logs (
    id BIGSERIAL PRIMARY KEY,
    time TIMESTAMPTZ NOT NULL,
    target VARCHAR(255) NOT NULL,
    source VARCHAR(64) NOT NULL,
    level VARCHAR(32) NOT NULL,
    message TEXT NOT NULL,
    host VARCHAR(255),
    unit VARCHAR(255),
    batch_id VARCHAR(255),
    tags JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_logs_time ON logs(time);
CREATE INDEX IF NOT EXISTS idx_logs_target_level ON logs(target, level);
"#;

pub async fn save_logs(config: &SaveConfig, logs: &[LogRecord]) -> Result<()> {
    let url = resolve_url(&config.url);
    let (client, connection) = tokio_postgres::connect(&url, NoTls)
        .await
        .context("PostgreSQL connection failed")?;

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("PostgreSQL connection error: {}", e);
        }
    });

    client
        .batch_execute(CREATE_LOGS_TABLE)
        .await
        .context("Failed to create logs table")?;

    client.execute("BEGIN", &[]).await.ok();
    let stmt = client
        .prepare(
            "INSERT INTO logs (time, target, source, level, message, host, unit, batch_id, tags) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .await?;
    for log in logs {
        let tags_json = serde_json::to_value(&log.tags)?;
        client
            .execute(
                &stmt,
                &[
                    &log.collected_at,
                    &log.target,
                    &log.source,
                    &log.level,
                    &log.message,
                    &log.host,
                    &log.unit,
                    &log.batch_id,
                    &tags_json,
                ],
            )
            .await?;
    }
    client.execute("COMMIT", &[]).await.ok();

    Ok(())
}

use super::resolve_url;
