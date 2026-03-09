use anyhow::{Context, Result};

use crate::commands::watch::Violation;

const EVENTS_URL: &str = "https://events.pagerduty.com/v2/enqueue";

/// Extract routing key from `pagerduty://routing-key`.
fn parse_routing_key(url: &str) -> Result<String> {
    let key = url
        .strip_prefix("pagerduty://")
        .context("Invalid PagerDuty URI")?
        .to_string();
    if key.is_empty() {
        anyhow::bail!("PagerDuty URI must include a routing key");
    }
    Ok(key)
}

/// Map max violation level to PagerDuty severity.
fn severity_from_level(violations: &[Violation]) -> &'static str {
    let max_level = violations.iter().map(|v| v.level).max().unwrap_or(0);
    match max_level {
        0 => "info",
        1 => "warning",
        2 => "error",
        _ => "critical",
    }
}

/// Build custom details for the PagerDuty event.
fn build_details(violations: &[Violation]) -> serde_json::Value {
    let items: Vec<serde_json::Value> = violations
        .iter()
        .take(20)
        .map(|v| {
            serde_json::json!({
                "rule": v.rule,
                "level": v.level_label,
                "description": v.description,
                "messages": v.messages,
            })
        })
        .collect();
    serde_json::json!({ "violations": items })
}

/// Trigger a PagerDuty event via Events API v2.
pub async fn send(
    client: &reqwest::Client,
    url: &str,
    violations: &[Violation],
    target: &str,
) -> Result<()> {
    let routing_key = parse_routing_key(url)?;

    let payload = serde_json::json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": format!(
                "kxn | {} | {} violation(s)",
                target,
                violations.len()
            ),
            "source": target,
            "severity": severity_from_level(violations),
            "custom_details": build_details(violations),
        }
    });

    client
        .post(EVENTS_URL)
        .json(&payload)
        .send()
        .await?
        .error_for_status()
        .context("PagerDuty API error")?;

    Ok(())
}
