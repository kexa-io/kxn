use anyhow::{Context, Result};
use base64::Engine;

use crate::commands::watch::Violation;

/// Jira Cloud config parsed from URI.
///
/// Format: `jira://user:token@instance.atlassian.net/PROJECT`
struct JiraConfig {
    instance: String,
    user: String,
    token: String,
    project_key: String,
}

fn parse_jira_uri(url: &str) -> Result<JiraConfig> {
    let parsed = url::Url::parse(url).context("Invalid Jira URI")?;
    let instance = parsed
        .host_str()
        .context("Missing Jira instance host")?
        .to_string();
    let user = urlencoding::decode(parsed.username())
        .context("Invalid user encoding")?
        .to_string();
    let token = urlencoding::decode(parsed.password().unwrap_or(""))
        .context("Invalid token encoding")?
        .to_string();
    let project_key = parsed
        .path()
        .trim_start_matches('/')
        .to_string();

    if user.is_empty() || token.is_empty() {
        anyhow::bail!("Jira URI must include user:token");
    }
    if project_key.is_empty() {
        anyhow::bail!("Jira URI must include project key in path");
    }

    Ok(JiraConfig {
        instance,
        user,
        token,
        project_key,
    })
}

/// Map max violation level to Jira priority name.
fn priority_from_level(violations: &[Violation]) -> &'static str {
    let max_level = violations.iter().map(|v| v.level).max().unwrap_or(0);
    match max_level {
        0 => "Low",
        1 => "Medium",
        2 => "High",
        _ => "Highest",
    }
}

/// Build Atlassian Document Format (ADF) description.
fn build_adf_description(violations: &[Violation], target: &str) -> serde_json::Value {
    let mut text = format!("Target: {}\n\n", target);
    for v in violations.iter().take(20) {
        text.push_str(&format!(
            "[{}] {} - {}\n",
            v.level_label, v.rule, v.description
        ));
        for msg in &v.messages {
            text.push_str(&format!("  {}\n", msg));
        }
    }
    if violations.len() > 20 {
        text.push_str(&format!("...and {} more\n", violations.len() - 20));
    }

    serde_json::json!({
        "version": 1,
        "type": "doc",
        "content": [{
            "type": "codeBlock",
            "content": [{
                "type": "text",
                "text": text,
            }]
        }]
    })
}

/// Create a Jira issue for the violations.
pub async fn send(
    client: &reqwest::Client,
    url: &str,
    violations: &[Violation],
    target: &str,
) -> Result<()> {
    let cfg = parse_jira_uri(url)?;

    let credentials = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", cfg.user, cfg.token));

    let summary = format!(
        "kxn | {} | {} violation(s)",
        target,
        violations.len()
    );

    let payload = serde_json::json!({
        "fields": {
            "project": { "key": cfg.project_key },
            "summary": summary,
            "description": build_adf_description(violations, target),
            "issuetype": { "name": "Bug" },
            "priority": { "name": priority_from_level(violations) },
        }
    });

    let api_url = format!("https://{}/rest/api/3/issue", cfg.instance);

    client
        .post(&api_url)
        .header("Authorization", format!("Basic {}", credentials))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?
        .error_for_status()
        .context("Jira API error")?;

    Ok(())
}
