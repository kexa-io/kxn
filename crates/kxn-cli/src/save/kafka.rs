use anyhow::{Context, Result};
use kxn_rules::SaveConfig;

use super::{LogRecord, MetricRecord, ScanRecord};

/// Save scan results + metrics to Kafka via REST Proxy (Confluent-compatible).
///
/// URL format: kafka://broker:8082/topic
pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let (broker, topic) = parse_kafka_url(&config.url)?;
    let client = crate::alerts::shared_client();

    let mut kafka_records = Vec::new();

    for r in records {
        if config.only_errors && !r.error {
            continue;
        }
        kafka_records.push(serde_json::json!({
            "value": {
                "type": "scan",
                "target": r.target,
                "provider": r.provider,
                "rule_name": r.rule_name,
                "rule_description": r.rule_description,
                "level": r.level,
                "level_label": r.level_label,
                "object_type": r.object_type,
                "error": r.error,
                "messages": r.messages,
                "compliance": r.compliance,
                "batch_id": r.batch_id,
                "origin": config.origin,
                "timestamp": r.timestamp.to_rfc3339(),
            }
        }));
    }

    for m in metrics {
        kafka_records.push(serde_json::json!({
            "value": {
                "type": "metric",
                "target": m.target,
                "provider": m.provider,
                "resource_type": m.resource_type,
                "metric_name": m.metric_name,
                "value_num": m.value_num,
                "value_str": m.value_str,
                "timestamp": m.timestamp.to_rfc3339(),
            }
        }));
    }

    if kafka_records.is_empty() {
        return Ok(());
    }

    let payload = serde_json::json!({ "records": kafka_records });
    let url = format!("http://{}/topics/{}", broker, topic);

    client
        .post(&url)
        .header("Content-Type", "application/vnd.kafka.json.v2+json")
        .json(&payload)
        .send()
        .await?
        .error_for_status()
        .context("Kafka REST Proxy error")?;

    Ok(())
}

pub async fn save_logs(config: &SaveConfig, logs: &[LogRecord]) -> Result<()> {
    let (broker, topic) = parse_kafka_url(&config.url)?;
    let client = crate::alerts::shared_client();

    let kafka_records: Vec<serde_json::Value> = logs
        .iter()
        .map(|l| {
            serde_json::json!({
                "value": {
                    "type": "log",
                    "target": l.target,
                    "source": l.source,
                    "level": l.level,
                    "message": l.message,
                    "host": l.host,
                    "unit": l.unit,
                    "batch_id": l.batch_id,
                    "timestamp": l.collected_at.to_rfc3339(),
                }
            })
        })
        .collect();

    if kafka_records.is_empty() {
        return Ok(());
    }

    let payload = serde_json::json!({ "records": kafka_records });
    let url = format!("http://{}/topics/{}-logs", broker, topic);

    client
        .post(&url)
        .header("Content-Type", "application/vnd.kafka.json.v2+json")
        .json(&payload)
        .send()
        .await?
        .error_for_status()
        .context("Kafka REST Proxy error")?;

    Ok(())
}

fn parse_kafka_url(url: &str) -> Result<(String, String)> {
    let rest = url
        .strip_prefix("kafka://")
        .context("Invalid Kafka save URI")?;
    let (broker, topic) = rest
        .rsplit_once('/')
        .context("Kafka URI must be: kafka://broker:8082/topic")?;
    if broker.is_empty() || topic.is_empty() {
        anyhow::bail!("Kafka URI must include broker and topic");
    }
    Ok((broker.to_string(), topic.to_string()))
}
