use anyhow::{Context, Result};
use kxn_rules::SaveConfig;
use std::io::Write;

use super::{MetricRecord, ScanRecord};

/// Save scan results + metrics as JSONL (one JSON per line) to a local file.
///
/// URL format: file://./kxn-results.jsonl or file:///var/log/kxn/results.jsonl
pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let path = config
        .url
        .strip_prefix("file://")
        .unwrap_or(&config.url);

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .context(format!("Failed to open {}", path))?;

    for record in records {
        if config.only_errors && !record.error {
            continue;
        }
        let doc = serde_json::json!({
            "type": "scan",
            "target": record.target,
            "provider": record.provider,
            "rule_name": record.rule_name,
            "rule_description": record.rule_description,
            "level": record.level,
            "level_label": record.level_label,
            "object_type": record.object_type,
            "error": record.error,
            "messages": record.messages,
            "compliance": record.compliance,
            "batch_id": record.batch_id,
            "origin": config.origin,
            "timestamp": record.timestamp.to_rfc3339(),
        });
        writeln!(file, "{}", serde_json::to_string(&doc)?)?;
    }

    for m in metrics {
        let doc = serde_json::json!({
            "type": "metric",
            "target": m.target,
            "provider": m.provider,
            "resource_type": m.resource_type,
            "metric_name": m.metric_name,
            "value_num": m.value_num,
            "value_str": m.value_str,
            "timestamp": m.timestamp.to_rfc3339(),
        });
        writeln!(file, "{}", serde_json::to_string(&doc)?)?;
    }

    Ok(())
}
