use anyhow::{Context, Result};

use crate::commands::watch::Violation;

/// ServiceNow config parsed from URI.
///
/// Format: `servicenow://user:pass@instance.service-now.com`
struct ServiceNowConfig {
    instance: String,
    user: String,
    password: String,
}

fn parse_servicenow_uri(url: &str) -> Result<ServiceNowConfig> {
    let parsed = url::Url::parse(url).context("Invalid ServiceNow URI")?;
    let instance = parsed
        .host_str()
        .context("Missing ServiceNow instance")?
        .to_string();
    let user = urlencoding::decode(parsed.username())
        .context("Invalid user encoding")?
        .to_string();
    let password = urlencoding::decode(parsed.password().unwrap_or(""))
        .context("Invalid password encoding")?
        .to_string();

    if user.is_empty() || password.is_empty() {
        anyhow::bail!("ServiceNow URI must include user:pass");
    }

    Ok(ServiceNowConfig {
        instance,
        user,
        password,
    })
}

/// Map max violation level to ServiceNow impact/urgency (1=high, 3=low).
fn impact_from_level(violations: &[Violation]) -> u8 {
    let max_level = violations.iter().map(|v| v.level).max().unwrap_or(0);
    match max_level {
        0 => 3,
        1 => 2,
        _ => 1,
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

/// Create a ServiceNow incident.
pub async fn send(
    client: &reqwest::Client,
    url: &str,
    violations: &[Violation],
    target: &str,
) -> Result<()> {
    let cfg = parse_servicenow_uri(url)?;

    let impact = impact_from_level(violations);

    let payload = serde_json::json!({
        "short_description": format!(
            "kxn | {} | {} violation(s)",
            target,
            violations.len()
        ),
        "description": build_description(violations, target),
        "impact": impact,
        "urgency": impact,
        "category": "Compliance",
    });

    let api_url = format!(
        "https://{}/api/now/table/incident",
        cfg.instance
    );

    client
        .post(&api_url)
        .basic_auth(&cfg.user, Some(&cfg.password))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?
        .error_for_status()
        .context("ServiceNow API error")?;

    Ok(())
}
