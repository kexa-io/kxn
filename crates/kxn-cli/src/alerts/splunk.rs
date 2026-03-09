use anyhow::{Context, Result};

use crate::commands::watch::Violation;

/// Parse Splunk On-Call (VictorOps) URI: `splunk://routing-key`
/// Posts to the Splunk On-Call REST endpoint.
fn parse_config(url: &str) -> Result<String> {
    let key = url
        .strip_prefix("splunk://")
        .context("Invalid Splunk On-Call URI")?
        .to_string();
    if key.is_empty() {
        anyhow::bail!("Splunk URI must include a routing key");
    }
    Ok(key)
}

/// Map max violation level to Splunk On-Call message_type.
fn message_type(violations: &[Violation]) -> &'static str {
    let max_level = violations.iter().map(|v| v.level).max().unwrap_or(0);
    match max_level {
        0 => "INFO",
        1 => "WARNING",
        2 => "CRITICAL",
        _ => "CRITICAL",
    }
}

/// Send alert to Splunk On-Call (VictorOps) REST API.
pub async fn send(
    client: &reqwest::Client,
    url: &str,
    violations: &[Violation],
    target: &str,
) -> Result<()> {
    let routing_key = parse_config(url)?;

    let details: Vec<serde_json::Value> = violations
        .iter()
        .take(20)
        .map(|v| {
            serde_json::json!({
                "rule": v.rule,
                "level": v.level_label,
                "description": v.description,
            })
        })
        .collect();

    let payload = serde_json::json!({
        "message_type": message_type(violations),
        "entity_id": format!("kxn-{}", target),
        "entity_display_name": format!("kxn | {} violation(s)", violations.len()),
        "state_message": format!(
            "kxn scan on {} found {} violation(s)",
            target,
            violations.len()
        ),
        "monitoring_tool": "kxn",
        "details": details,
    });

    let api_url = format!(
        "https://alert.victorops.com/integrations/generic/20131114/alert/{}/kxn",
        routing_key
    );

    client
        .post(&api_url)
        .json(&payload)
        .send()
        .await?
        .error_for_status()
        .context("Splunk On-Call API error")?;

    Ok(())
}
