use anyhow::{Context, Result};
use kxn_rules::SaveConfig;

use super::{MetricRecord, ScanRecord};

/// Save scan results + metrics to Azure Event Hubs via REST API.
///
/// URL format: eventhubs://namespace.servicebus.windows.net/hubname
/// Auth: EVENTHUB_SAS env var (SharedAccessSignature)
pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let (endpoint, hub) = parse_url(&config.url)?;
    let sas = std::env::var("EVENTHUB_SAS")
        .context("EVENTHUB_SAS env var required for Azure Event Hubs")?;
    let client = reqwest::Client::new();

    let mut events = Vec::new();

    for r in records {
        if config.only_errors && !r.error {
            continue;
        }
        events.push(serde_json::json!({
            "Body": {
                "type": "scan",
                "target": r.target,
                "provider": r.provider,
                "rule_name": r.rule_name,
                "level": r.level,
                "level_label": r.level_label,
                "error": r.error,
                "messages": r.messages,
                "compliance": r.compliance,
                "batch_id": r.batch_id,
                "timestamp": r.timestamp.to_rfc3339(),
            }
        }));
    }

    for m in metrics {
        events.push(serde_json::json!({
            "Body": {
                "type": "metric",
                "target": m.target,
                "provider": m.provider,
                "resource_type": m.resource_type,
                "metric_name": m.metric_name,
                "value_num": m.value_num,
                "timestamp": m.timestamp.to_rfc3339(),
            }
        }));
    }

    if events.is_empty() {
        return Ok(());
    }

    // Azure Event Hubs batch send
    let url = format!(
        "https://{}/{}/messages?api-version=2014-01",
        endpoint, hub
    );

    client
        .post(&url)
        .header("Authorization", &sas)
        .header("Content-Type", "application/vnd.microsoft.servicebus.json")
        .json(&events)
        .send()
        .await?
        .error_for_status()
        .context("Azure Event Hubs error")?;

    Ok(())
}

fn parse_url(url: &str) -> Result<(String, String)> {
    let rest = url
        .strip_prefix("eventhubs://")
        .context("Invalid Event Hubs URI")?;
    let (namespace, hub) = rest
        .rsplit_once('/')
        .context("Event Hubs URI must be: eventhubs://namespace.servicebus.windows.net/hub")?;
    if namespace.is_empty() || hub.is_empty() {
        anyhow::bail!("Event Hubs URI must include namespace and hub name");
    }
    Ok((namespace.to_string(), hub.to_string()))
}
