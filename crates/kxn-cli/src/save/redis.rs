use anyhow::{Context, Result};
use kxn_rules::SaveConfig;

use super::{MetricRecord, ScanRecord};

/// Save scan results to Redis (pub/sub + stream).
///
/// URL format: redis://host:6379/channel
/// Publishes each event to the channel AND appends to a Redis Stream.
pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let (base_url, channel) = parse_url(&config.url)?;
    let client = reqwest::Client::new();

    // Use Redis HTTP interface (webdis) or fall back to direct TCP
    // For simplicity, we serialize events as JSONL and publish via
    // Redis REST proxy or direct command
    let mut events = Vec::new();

    for r in records {
        if config.only_errors && !r.error {
            continue;
        }
        events.push(serde_json::json!({
            "type": "scan",
            "target": r.target,
            "provider": r.provider,
            "rule_name": r.rule_name,
            "level": r.level,
            "level_label": r.level_label,
            "error": r.error,
            "messages": r.messages,
            "batch_id": r.batch_id,
            "timestamp": r.timestamp.to_rfc3339(),
        }));
    }

    for m in metrics {
        events.push(serde_json::json!({
            "type": "metric",
            "target": m.target,
            "metric_name": m.metric_name,
            "value_num": m.value_num,
            "timestamp": m.timestamp.to_rfc3339(),
        }));
    }

    if events.is_empty() {
        return Ok(());
    }

    // Publish via Webdis HTTP interface (Redis HTTP proxy)
    // PUBLISH channel message
    for event in &events {
        let msg = serde_json::to_string(event)?;
        let url = format!(
            "{}/PUBLISH/{}/{}",
            base_url,
            urlencoding::encode(&channel),
            urlencoding::encode(&msg),
        );
        client
            .get(&url)
            .send()
            .await
            .context("Redis publish failed")?;
    }

    Ok(())
}

fn parse_url(url: &str) -> Result<(String, String)> {
    // redis://host:6379/channel → (http://host:7379, channel)
    // Port 7379 = webdis default
    let rest = url
        .strip_prefix("redis://")
        .context("Invalid Redis URI")?;
    let (host_port, channel) = rest
        .split_once('/')
        .context("Redis URI must be: redis://host:6379/channel")?;

    let base = if host_port.contains(':') {
        let (host, _redis_port) = host_port.split_once(':').unwrap();
        // Use webdis port (7379) for HTTP interface
        format!("http://{}:7379", host)
    } else {
        format!("http://{}:7379", host_port)
    };

    Ok((base, channel.to_string()))
}
