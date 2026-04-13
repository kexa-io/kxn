use anyhow::{Context, Result};
use kxn_rules::SaveConfig;
use mysql_async::prelude::*;
use mysql_async::Pool;

use super::{MetricRecord, ScanRecord};

const CREATE_TABLES: &str = r"
CREATE TABLE IF NOT EXISTS providers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS provider_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    provider_id INT,
    FOREIGN KEY (provider_id) REFERENCES providers(id),
    UNIQUE KEY uq_item (name, provider_id)
);
CREATE TABLE IF NOT EXISTS origins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT
);
CREATE TABLE IF NOT EXISTS resources (
    id INT AUTO_INCREMENT PRIMARY KEY,
    content JSON NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    origin_id INT,
    provider_item_id INT,
    FOREIGN KEY (origin_id) REFERENCES origins(id),
    FOREIGN KEY (provider_item_id) REFERENCES provider_items(id)
);
CREATE TABLE IF NOT EXISTS rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    level INT,
    provider_id INT,
    provider_item_id INT,
    FOREIGN KEY (provider_id) REFERENCES providers(id),
    FOREIGN KEY (provider_item_id) REFERENCES provider_items(id)
);
CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    error BOOLEAN,
    messages JSON,
    conditions JSON,
    resource_id INT,
    rule_id INT,
    batch_id VARCHAR(255),
    target VARCHAR(255),
    FOREIGN KEY (resource_id) REFERENCES resources(id),
    FOREIGN KEY (rule_id) REFERENCES rules(id),
    INDEX idx_scans_batch (batch_id),
    INDEX idx_scans_target (target),
    INDEX idx_scans_error (error),
    INDEX idx_scans_created (created_at)
);
CREATE TABLE IF NOT EXISTS tags (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    value TEXT,
    scan_id INT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS metrics (
    time TIMESTAMP NOT NULL,
    target VARCHAR(255) NOT NULL,
    provider VARCHAR(255) NOT NULL,
    resource_type VARCHAR(255) NOT NULL,
    metric_name VARCHAR(255) NOT NULL,
    value_num DOUBLE,
    value_str TEXT,
    INDEX idx_metrics_time (time),
    INDEX idx_metrics_target (target),
    INDEX idx_metrics_name (target, resource_type, metric_name)
);
";

pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let url = resolve_url(&config.url);
    let pool = Pool::new(url.as_str());
    let mut conn = pool.get_conn().await.context("MySQL connection failed")?;

    for stmt in CREATE_TABLES.split(';') {
        let stmt = stmt.trim();
        if !stmt.is_empty() {
            conn.query_drop(stmt)
                .await
                .context("Failed to create table")?;
        }
    }

    let origin_id = get_or_create_origin(&mut conn, &config.origin).await?;

    // Wrap records in transaction for performance
    conn.query_drop("START TRANSACTION").await.ok();
    for record in records {
        if config.only_errors && !record.error {
            continue;
        }
        save_record(&mut conn, record, origin_id).await?;
    }
    conn.query_drop("COMMIT").await.ok();

    // Save metrics
    for m in metrics {
        conn.exec_drop(
            "INSERT INTO metrics (time, target, provider, resource_type, metric_name, value_num, value_str) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                m.timestamp.format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
                &m.target,
                &m.provider,
                &m.resource_type,
                &m.metric_name,
                &m.value_num,
                &m.value_str,
            ),
        )
        .await?;
    }

    drop(conn);
    pool.disconnect().await?;
    Ok(())
}

async fn get_or_create_origin(conn: &mut mysql_async::Conn, name: &str) -> Result<u64> {
    conn.exec_drop(
        "INSERT IGNORE INTO origins (name) VALUES (?)",
        (name,),
    )
    .await?;
    let row: Option<u64> = conn
        .exec_first("SELECT id FROM origins WHERE name = ?", (name,))
        .await?;
    row.ok_or_else(|| anyhow::anyhow!("Row not found after upsert"))
}

async fn get_or_create_provider(conn: &mut mysql_async::Conn, name: &str) -> Result<u64> {
    conn.exec_drop(
        "INSERT IGNORE INTO providers (name) VALUES (?)",
        (name,),
    )
    .await?;
    let row: Option<u64> = conn
        .exec_first("SELECT id FROM providers WHERE name = ?", (name,))
        .await?;
    row.ok_or_else(|| anyhow::anyhow!("Row not found after upsert"))
}

async fn get_or_create_provider_item(
    conn: &mut mysql_async::Conn,
    name: &str,
    provider_id: u64,
) -> Result<u64> {
    conn.exec_drop(
        "INSERT IGNORE INTO provider_items (name, provider_id) VALUES (?, ?)",
        (name, provider_id),
    )
    .await?;
    let row: Option<u64> = conn
        .exec_first(
            "SELECT id FROM provider_items WHERE name = ? AND provider_id = ?",
            (name, provider_id),
        )
        .await?;
    row.ok_or_else(|| anyhow::anyhow!("Row not found after upsert"))
}

async fn get_or_create_rule(
    conn: &mut mysql_async::Conn,
    record: &ScanRecord,
    provider_id: u64,
    provider_item_id: u64,
) -> Result<u64> {
    conn.exec_drop(
        "INSERT INTO rules (name, description, level, provider_id, provider_item_id) \
         VALUES (?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE description = VALUES(description), level = VALUES(level)",
        (
            &record.rule_name,
            &record.rule_description,
            record.level as u32,
            provider_id,
            provider_item_id,
        ),
    )
    .await?;
    let row: Option<u64> = conn
        .exec_first("SELECT id FROM rules WHERE name = ?", (&record.rule_name,))
        .await?;
    row.ok_or_else(|| anyhow::anyhow!("Row not found after upsert"))
}

async fn save_record(
    conn: &mut mysql_async::Conn,
    record: &ScanRecord,
    origin_id: u64,
) -> Result<()> {
    let provider_id = get_or_create_provider(conn, &record.provider).await?;
    let provider_item_id =
        get_or_create_provider_item(conn, &record.object_type, provider_id).await?;
    let rule_id = get_or_create_rule(conn, record, provider_id, provider_item_id).await?;

    conn.exec_drop(
        "INSERT INTO resources (content, origin_id, provider_item_id) VALUES (?, ?, ?)",
        (
            serde_json::to_string(&record.object_content)?,
            origin_id,
            provider_item_id,
        ),
    )
    .await?;
    let resource_id: u64 = conn
        .exec_first("SELECT LAST_INSERT_ID()", ())
        .await?
        .ok_or_else(|| anyhow::anyhow!("LAST_INSERT_ID() returned no result"))?;

    let messages_json = serde_json::to_string(&record.messages)?;
    let conditions_json = serde_json::to_string(&record.conditions)?;

    conn.exec_drop(
        "INSERT INTO scans (error, messages, conditions, resource_id, rule_id, batch_id, target) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            record.error,
            &messages_json,
            &conditions_json,
            resource_id,
            rule_id,
            &record.batch_id,
            &record.target,
        ),
    )
    .await?;
    let scan_id: u64 = conn
        .exec_first("SELECT LAST_INSERT_ID()", ())
        .await?
        .ok_or_else(|| anyhow::anyhow!("LAST_INSERT_ID() returned no result"))?;

    for (name, value) in &record.tags {
        conn.exec_drop(
            "INSERT INTO tags (name, value, scan_id) VALUES (?, ?, ?)",
            (name, value, scan_id),
        )
        .await?;
    }

    Ok(())
}

use super::resolve_url;
