use anyhow::{Context, Result};
use kxn_rules::SaveConfig;

use super::{MetricRecord, ScanRecord};

/// Save scan results + metrics to Elasticsearch or OpenSearch.
///
/// URL format: elasticsearch://host:9200/index or opensearch://host:9200/index
pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let (base_url, index) = parse_es_url(&config.url)?;
    let client = crate::alerts::shared_client();

    // Bulk index scan records
    if !records.is_empty() {
        let mut body = String::new();
        for record in records {
            if config.only_errors && !record.error {
                continue;
            }
            let doc = serde_json::json!({
                "target": record.target,
                "provider": record.provider,
                "rule_name": record.rule_name,
                "rule_description": record.rule_description,
                "level": record.level,
                "level_label": record.level_label,
                "object_type": record.object_type,
                "object_content": record.object_content,
                "error": record.error,
                "messages": record.messages,
                "conditions": record.conditions,
                "compliance": record.compliance,
                "batch_id": record.batch_id,
                "origin": config.origin,
                "tags": record.tags,
                "@timestamp": record.timestamp.to_rfc3339(),
                "type": "scan",
            });
            body.push_str(&format!(
                "{{\"index\":{{\"_index\":\"{}\"}}}}\n{}\n",
                index,
                serde_json::to_string(&doc)?
            ));
        }

        if !body.is_empty() {
            bulk_index(&client, &base_url, &body).await?;
        }
    }

    // Bulk index metrics
    if !metrics.is_empty() {
        let mut body = String::new();
        for m in metrics {
            let doc = serde_json::json!({
                "target": m.target,
                "provider": m.provider,
                "resource_type": m.resource_type,
                "metric_name": m.metric_name,
                "value_num": m.value_num,
                "value_str": m.value_str,
                "@timestamp": m.timestamp.to_rfc3339(),
                "type": "metric",
            });
            body.push_str(&format!(
                "{{\"index\":{{\"_index\":\"{}-metrics\"}}}}\n{}\n",
                index,
                serde_json::to_string(&doc)?
            ));
        }
        bulk_index(&client, &base_url, &body).await?;
    }

    Ok(())
}

fn parse_es_url(url: &str) -> Result<(String, String)> {
    // elasticsearch://host:9200/index → (http://host:9200, index)
    // opensearch://host:9200/index    → (http://host:9200, index)
    let url = url
        .replace("elasticsearch://", "http://")
        .replace("opensearch://", "http://");

    let parsed = url::Url::parse(&url).context("invalid Elasticsearch URL")?;
    let host = parsed.host_str().context("no host in ES URL")?;
    let port = parsed.port().unwrap_or(9200);
    let base_url = format!("http://{}:{}", host, port);

    let index = parsed
        .path()
        .trim_start_matches('/')
        .to_string();
    let index = if index.is_empty() {
        "kxn".to_string()
    } else {
        index
    };

    Ok((base_url, index))
}

async fn bulk_index(client: &reqwest::Client, base_url: &str, body: &str) -> Result<()> {
    let url = format!("{}/_bulk", base_url);

    let mut req = client
        .post(&url)
        .header("Content-Type", "application/x-ndjson")
        .body(body.to_string());

    // Support basic auth via env vars
    if let (Ok(user), Ok(pass)) = (
        std::env::var("ES_USER"),
        std::env::var("ES_PASSWORD"),
    ) {
        req = req.basic_auth(user, Some(pass));
    }

    let resp = req.send().await.context("Elasticsearch bulk request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Elasticsearch bulk failed ({}): {}", status, text);
    }

    Ok(())
}
