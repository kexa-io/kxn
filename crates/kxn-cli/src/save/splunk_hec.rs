use anyhow::{Context, Result};
use kxn_rules::SaveConfig;

use super::{LogRecord, MetricRecord, ScanRecord};

/// Save scan results to Splunk via HTTP Event Collector (HEC).
///
/// URL format: splunk://host:8088/index
/// Auth: SPLUNK_HEC_TOKEN env var
pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let (base_url, index) = parse_url(&config.url)?;
    let token = std::env::var("SPLUNK_HEC_TOKEN")
        .context("SPLUNK_HEC_TOKEN env var required for Splunk HEC")?;
    let client = crate::alerts::shared_client();

    let mut body = String::new();

    for r in records {
        if config.only_errors && !r.error {
            continue;
        }
        let event = serde_json::json!({
            "event": {
                "type": "scan",
                "target": r.target,
                "provider": r.provider,
                "rule_name": r.rule_name,
                "rule_description": r.rule_description,
                "level": r.level,
                "level_label": r.level_label,
                "error": r.error,
                "messages": r.messages,
                "compliance": r.compliance,
                "batch_id": r.batch_id,
            },
            "sourcetype": "kxn:scan",
            "source": "kxn",
            "index": index,
            "time": r.timestamp.timestamp(),
        });
        body.push_str(&serde_json::to_string(&event)?);
        body.push('\n');
    }

    for m in metrics {
        let event = serde_json::json!({
            "event": {
                "type": "metric",
                "target": m.target,
                "provider": m.provider,
                "resource_type": m.resource_type,
                "metric_name": m.metric_name,
                "value_num": m.value_num,
                "value_str": m.value_str,
            },
            "sourcetype": "kxn:metric",
            "source": "kxn",
            "index": index,
            "time": m.timestamp.timestamp(),
        });
        body.push_str(&serde_json::to_string(&event)?);
        body.push('\n');
    }

    if body.is_empty() {
        return Ok(());
    }

    let url = format!("{}/services/collector/event", base_url);

    let (payload, encoding) = super::compress_payload(body, config.compression.as_deref());
    let mut req = client
        .post(&url)
        .header("Authorization", format!("Splunk {}", token))
        .header("Content-Type", "application/json");
    if let Some(enc) = encoding {
        req = req.header("Content-Encoding", enc);
    }
    req.body(payload)
        .send()
        .await?
        .error_for_status()
        .context("Splunk HEC error")?;

    Ok(())
}

pub async fn save_logs(config: &SaveConfig, logs: &[LogRecord]) -> Result<()> {
    let (base_url, index) = parse_url(&config.url)?;
    let token = std::env::var("SPLUNK_HEC_TOKEN")
        .context("SPLUNK_HEC_TOKEN env var required for Splunk HEC")?;
    let client = crate::alerts::shared_client();

    let mut body = String::new();
    for log in logs {
        let event = serde_json::json!({
            "event": {
                "type": "log",
                "target": log.target,
                "source": log.source,
                "level": log.level,
                "message": log.message,
                "host": log.host,
                "unit": log.unit,
                "batch_id": log.batch_id,
            },
            "sourcetype": "kxn:log",
            "source": "kxn",
            "index": index,
            "time": log.collected_at.timestamp(),
        });
        body.push_str(&serde_json::to_string(&event)?);
        body.push('\n');
    }

    if body.is_empty() {
        return Ok(());
    }

    let url = format!("{}/services/collector/event", base_url);

    let (payload, encoding) = super::compress_payload(body, config.compression.as_deref());
    let mut req = client
        .post(&url)
        .header("Authorization", format!("Splunk {}", token))
        .header("Content-Type", "application/json");
    if let Some(enc) = encoding {
        req = req.header("Content-Encoding", enc);
    }
    req.body(payload)
        .send()
        .await?
        .error_for_status()
        .context("Splunk HEC error")?;

    Ok(())
}

fn parse_url(url: &str) -> Result<(String, String)> {
    // splunkhec://host:8088/index → (https://host:8088, index)
    let rest = url
        .strip_prefix("splunkhec://")
        .or_else(|| url.strip_prefix("splunk-hec://"))
        .context("Invalid Splunk HEC URI")?;

    let (host_port, index) = rest
        .split_once('/')
        .unwrap_or((rest, "kxn"));

    let base = format!("https://{}", host_port);
    let index = if index.is_empty() { "kxn" } else { index };

    Ok((base, index.to_string()))
}
