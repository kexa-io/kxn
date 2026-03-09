use anyhow::Result;
use serde_json::Value;

use crate::commands::watch::Violation;

/// Format a Slack Block Kit payload for violations.
fn format_payload(violations: &[Violation], target: &str) -> Value {
    if violations.is_empty() {
        return serde_json::json!({
            "text": format!("kxn | {} | ALL PASSED", target),
        });
    }

    let mut blocks = Vec::new();

    blocks.push(serde_json::json!({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": format!("kxn | {} violation(s)", violations.len()),
        }
    }));

    blocks.push(serde_json::json!({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": format!("*Target:* `{}`", target),
        }
    }));

    for v in violations.iter().take(10) {
        let level_icon = match v.level {
            0 => "info",
            1 => "warning",
            2 => "error",
            _ => "fatal",
        };

        let mut text = format!("*[{}] {}*\n{}", level_icon, v.rule, v.description);

        if !v.compliance.is_empty() {
            let refs: Vec<String> = v
                .compliance
                .iter()
                .map(|c| format!("{} {}", c.framework, c.control))
                .collect();
            text.push_str(&format!("\n_Compliance:_ {}", refs.join(", ")));
        }

        if !v.messages.is_empty() {
            text.push_str(&format!("\n`{}`", v.messages.join("; ")));
        }

        blocks.push(serde_json::json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": text,
            }
        }));
    }

    if violations.len() > 10 {
        blocks.push(serde_json::json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!(
                    "_...and {} more violations_",
                    violations.len() - 10
                ),
            }
        }));
    }

    serde_json::json!({ "blocks": blocks })
}

/// Send violations to a Slack incoming webhook.
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
