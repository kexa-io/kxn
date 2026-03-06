use anyhow::{Context, Result};
use kxn_rules::SaveConfig;
use mongodb::{bson::doc, Client};
use serde_json::Value;

use super::{MetricRecord, ScanRecord};

pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let url = resolve_url(&config.url);
    let client = Client::with_uri_str(&url)
        .await
        .context("MongoDB connection failed")?;

    let db_name = extract_db_name(&url).unwrap_or_else(|| "kxn".to_string());
    let db = client.database(&db_name);

    // Save scan results
    let scans_coll = db.collection::<mongodb::bson::Document>("scans");
    for record in records {
        if config.only_errors && !record.error {
            continue;
        }
        let doc = scan_to_bson(record, &config.origin, &config.tags)?;
        scans_coll
            .insert_one(doc)
            .await
            .context("MongoDB scan insert failed")?;
    }

    // Save metrics
    if !metrics.is_empty() {
        let metrics_coll = db.collection::<mongodb::bson::Document>("metrics");
        let docs: Vec<mongodb::bson::Document> = metrics
            .iter()
            .map(metric_to_bson)
            .collect::<Result<Vec<_>>>()?;
        metrics_coll
            .insert_many(docs)
            .await
            .context("MongoDB metrics insert failed")?;
    }

    Ok(())
}

fn metric_to_bson(m: &MetricRecord) -> Result<mongodb::bson::Document> {
    let mut doc = doc! {
        "time": mongodb::bson::DateTime::from_millis(m.timestamp.timestamp_millis()),
        "target": &m.target,
        "provider": &m.provider,
        "resource_type": &m.resource_type,
        "metric_name": &m.metric_name,
    };
    if let Some(n) = m.value_num {
        doc.insert("value_num", n);
    }
    if let Some(ref s) = m.value_str {
        doc.insert("value_str", s.as_str());
    }
    Ok(doc)
}

fn scan_to_bson(
    record: &ScanRecord,
    origin: &str,
    config_tags: &toml::Table,
) -> Result<mongodb::bson::Document> {
    let mut tags = mongodb::bson::Document::new();
    for (k, v) in config_tags {
        tags.insert(k.clone(), v.to_string().trim_matches('"').to_string());
    }
    for (k, v) in &record.tags {
        tags.insert(k.clone(), v.clone());
    }

    let object_content = value_to_bson(&record.object_content);
    let conditions = value_to_bson(&record.conditions);
    let messages: Vec<String> = record.messages.clone();

    Ok(doc! {
        "target": &record.target,
        "provider": &record.provider,
        "rule_name": &record.rule_name,
        "rule_description": &record.rule_description,
        "level": record.level as i32,
        "level_label": &record.level_label,
        "object_type": &record.object_type,
        "object_content": object_content,
        "error": record.error,
        "messages": messages,
        "conditions": conditions,
        "batch_id": &record.batch_id,
        "origin": origin,
        "tags": tags,
        "timestamp": mongodb::bson::DateTime::from_millis(record.timestamp.timestamp_millis()),
    })
}

fn value_to_bson(value: &Value) -> mongodb::bson::Bson {
    mongodb::bson::to_bson(value).unwrap_or(mongodb::bson::Bson::Null)
}

fn extract_db_name(url: &str) -> Option<String> {
    let url = url.split('?').next()?;
    let after_host = url.rsplit('/').next()?;
    if after_host.is_empty() || after_host.contains(':') {
        None
    } else {
        Some(after_host.to_string())
    }
}

fn resolve_url(url: &str) -> String {
    if !url.contains("://") {
        std::env::var(url).unwrap_or_else(|_| url.to_string())
    } else {
        url.to_string()
    }
}
