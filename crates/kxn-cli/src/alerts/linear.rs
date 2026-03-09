use anyhow::{Context, Result};

use crate::commands::watch::Violation;

const API_URL: &str = "https://api.linear.app/graphql";

/// Linear config parsed from URI.
///
/// Format: `linear://api-key/TEAM`
struct LinearConfig {
    api_key: String,
    team_key: String,
}

fn parse_linear_uri(url: &str) -> Result<LinearConfig> {
    let rest = url
        .strip_prefix("linear://")
        .context("Invalid Linear URI")?;
    let parts: Vec<&str> = rest.splitn(2, '/').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        anyhow::bail!("Linear URI must be: linear://api-key/TEAM");
    }

    Ok(LinearConfig {
        api_key: parts[0].to_string(),
        team_key: parts[1].to_string(),
    })
}

/// Map max violation level to Linear priority (0=none, 1=urgent, 4=low).
fn priority_from_level(violations: &[Violation]) -> u8 {
    let max_level = violations.iter().map(|v| v.level).max().unwrap_or(0);
    match max_level {
        0 => 4, // Low
        1 => 3, // Medium
        2 => 2, // High
        _ => 1, // Urgent
    }
}

/// Build a markdown description.
fn build_description(violations: &[Violation], target: &str) -> String {
    let mut desc = format!("**Target:** `{}`\n\n", target);
    for v in violations.iter().take(20) {
        desc.push_str(&format!(
            "- **[{}] {}** - {}\n",
            v.level_label, v.rule, v.description
        ));
        for msg in &v.messages {
            desc.push_str(&format!("  - {}\n", msg));
        }
    }
    if violations.len() > 20 {
        desc.push_str(&format!(
            "\n...and {} more violations\n",
            violations.len() - 20
        ));
    }
    desc
}

/// Create a Linear issue via GraphQL.
pub async fn send(
    client: &reqwest::Client,
    url: &str,
    violations: &[Violation],
    target: &str,
) -> Result<()> {
    let cfg = parse_linear_uri(url)?;

    let title = format!(
        "kxn | {} | {} violation(s)",
        target,
        violations.len()
    );
    let description = build_description(violations, target);
    let priority = priority_from_level(violations);

    // First, look up the team ID from the team key
    let team_query = serde_json::json!({
        "query": format!(
            r#"query {{ teams(filter: {{ key: {{ eq: "{}" }} }}) {{ nodes {{ id }} }} }}"#,
            cfg.team_key
        ),
    });

    let team_resp = client
        .post(API_URL)
        .header("Authorization", &cfg.api_key)
        .header("Content-Type", "application/json")
        .json(&team_query)
        .send()
        .await?
        .error_for_status()
        .context("Linear API error (team lookup)")?
        .json::<serde_json::Value>()
        .await?;

    let team_id = team_resp["data"]["teams"]["nodes"][0]["id"]
        .as_str()
        .context("Team not found in Linear")?
        .to_string();

    // Create the issue
    let mutation = serde_json::json!({
        "query": "mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }",
        "variables": {
            "input": {
                "teamId": team_id,
                "title": title,
                "description": description,
                "priority": priority,
            }
        }
    });

    client
        .post(API_URL)
        .header("Authorization", &cfg.api_key)
        .header("Content-Type", "application/json")
        .json(&mutation)
        .send()
        .await?
        .error_for_status()
        .context("Linear API error (issue create)")?;

    Ok(())
}
