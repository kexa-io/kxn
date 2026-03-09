use anyhow::{Context, Result};

use crate::commands::watch::Violation;

const API_URL: &str = "https://api.opsgenie.com/v2/alerts";

/// Extract API key from `opsgenie://api-key`.
fn parse_api_key(url: &str) -> Result<String> {
    let key = url
        .strip_prefix("opsgenie://")
        .context("Invalid OpsGenie URI")?
        .to_string();
    if key.is_empty() {
        anyhow::bail!("OpsGenie URI must include an API key");
    }
    Ok(key)
}

/// Map max violation level to OpsGenie priority (P1-P5).
fn priority_from_level(violations: &[Violation]) -> &'static str {
    let max_level = violations.iter().map(|v| v.level).max().unwrap_or(0);
    match max_level {
        0 => "P5",
        1 => "P3",
        2 => "P2",
        _ => "P1",
    }
}

/// Build a description string with violation details.
fn build_description(violations: &[Violation], target: &str) -> String {
    let mut desc = format!("Target: {}\n\n", target);
    for v in violations.iter().take(20) {
        desc.push_str(&format!(
            "[{}] {} - {}\n",
            v.level_label, v.rule, v.description
        ));
        for msg in &v.messages {
            desc.push_str(&format!("  {}\n", msg));
        }
    }
    if violations.len() > 20 {
        desc.push_str(&format!("...and {} more\n", violations.len() - 20));
    }
    desc
}

/// Create an OpsGenie alert.
pub async fn send(
    client: &reqwest::Client,
    url: &str,
    violations: &[Violation],
    target: &str,
) -> Result<()> {
    let api_key = parse_api_key(url)?;

    let payload = serde_json::json!({
        "message": format!(
            "kxn | {} | {} violation(s)",
            target,
            violations.len()
        ),
        "description": build_description(violations, target),
        "priority": priority_from_level(violations),
        "source": "kxn",
        "tags": ["kxn", "compliance"],
    });

    client
        .post(API_URL)
        .header("Authorization", format!("GenieKey {}", api_key))
        .json(&payload)
        .send()
        .await?
        .error_for_status()
        .context("OpsGenie API error")?;

    Ok(())
}
