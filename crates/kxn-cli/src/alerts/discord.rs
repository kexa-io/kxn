use anyhow::Result;
use serde_json::Value;

use crate::commands::watch::Violation;

/// Format a Discord webhook payload with embeds.
fn format_payload(violations: &[Violation], target: &str) -> Value {
    if violations.is_empty() {
        return serde_json::json!({
            "content": format!("**kxn** | `{}` | ALL PASSED", target),
        });
    }

    let mut description = String::new();
    for v in violations.iter().take(10) {
        let icon = match v.level {
            0 => "info",
            1 => "warning",
            2 => "error",
            _ => "fatal",
        };

        description.push_str(&format!(
            "{} **{}**\n{}\n",
            icon, v.rule, v.description
        ));

        if !v.compliance.is_empty() {
            let refs: Vec<String> = v
                .compliance
                .iter()
                .map(|c| format!("{} {}", c.framework, c.control))
                .collect();
            description.push_str(&format!("Compliance: {}\n", refs.join(", ")));
        }
        description.push('\n');
    }

    if violations.len() > 10 {
        description.push_str(&format!(
            "...and {} more violations\n",
            violations.len() - 10
        ));
    }

    serde_json::json!({
        "embeds": [{
            "title": format!("kxn | {} violation(s)", violations.len()),
            "description": description,
            "color": 15158332,
            "footer": {
                "text": format!("Target: {}", target),
            }
        }]
    })
}

/// Send violations to a Discord webhook.
pub async fn send(
    client: &reqwest::Client,
    url: &str,
    violations: &[Violation],
    target: &str,
) -> Result<()> {
    let payload = format_payload(violations, target);
    client
        .post(url)
        .json(&payload)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}
