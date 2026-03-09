use anyhow::{Context, Result};

use crate::commands::watch::Violation;

/// Parse Zendesk URI: `zendesk://user:token@subdomain.zendesk.com`
fn parse_config(url: &str) -> Result<(String, String, String)> {
    let rest = url
        .strip_prefix("zendesk://")
        .context("Invalid Zendesk URI")?;

    let (creds, host) = rest
        .split_once('@')
        .context("Zendesk URI must be: zendesk://user:token@subdomain.zendesk.com")?;

    let (user, token) = creds
        .split_once(':')
        .context("Zendesk URI must include user:token")?;

    Ok((
        user.to_string(),
        token.to_string(),
        host.to_string(),
    ))
}

/// Map max violation level to Zendesk priority.
fn priority(violations: &[Violation]) -> &'static str {
    let max_level = violations.iter().map(|v| v.level).max().unwrap_or(0);
    match max_level {
        0 => "low",
        1 => "normal",
        2 => "high",
        _ => "urgent",
    }
}

/// Build ticket description from violations.
fn build_description(violations: &[Violation], target: &str) -> String {
    let mut desc = format!("kxn compliance scan on {}\n\n", target);
    for v in violations.iter().take(20) {
        desc.push_str(&format!(
            "[{}] {} — {}\n",
            v.level_label, v.rule, v.description
        ));
        for msg in &v.messages {
            desc.push_str(&format!("  {}\n", msg));
        }
    }
    if violations.len() > 20 {
        desc.push_str(&format!("\n...and {} more violations\n", violations.len() - 20));
    }
    desc
}

/// Create a Zendesk ticket via Tickets API.
pub async fn send(
    client: &reqwest::Client,
    url: &str,
    violations: &[Violation],
    target: &str,
) -> Result<()> {
    let (user, token, host) = parse_config(url)?;

    let payload = serde_json::json!({
        "ticket": {
            "subject": format!("kxn | {} | {} violation(s)", target, violations.len()),
            "description": build_description(violations, target),
            "priority": priority(violations),
            "tags": ["kxn", "compliance"],
        }
    });

    let api_url = format!("https://{}/api/v2/tickets.json", host);

    client
        .post(&api_url)
        .basic_auth(format!("{}/token", user), Some(token))
        .json(&payload)
        .send()
        .await?
        .error_for_status()
        .context("Zendesk API error")?;

    Ok(())
}
