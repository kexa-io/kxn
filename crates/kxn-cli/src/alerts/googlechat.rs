use anyhow::Result;
use serde_json::Value;

use crate::commands::watch::Violation;

/// Build a Google Chat `cardsV2` payload for an incoming webhook.
fn format_payload(violations: &[Violation], target: &str) -> Value {
    if violations.is_empty() {
        return serde_json::json!({
            "text": format!("kxn | {} | ALL PASSED", target),
        });
    }

    let mut widgets: Vec<Value> = Vec::new();

    widgets.push(serde_json::json!({
        "decoratedText": {
            "topLabel": "Target",
            "text": target,
        }
    }));

    for v in violations.iter().take(10) {
        let level = match v.level {
            0 => "info",
            1 => "warning",
            2 => "error",
            _ => "fatal",
        };

        let mut body = v.description.clone();

        if !v.compliance.is_empty() {
            let refs: Vec<String> = v
                .compliance
                .iter()
                .map(|c| format!("{} {}", c.framework, c.control))
                .collect();
            body.push_str(&format!("\nCompliance: {}", refs.join(", ")));
        }

        if !v.messages.is_empty() {
            body.push_str(&format!("\n{}", v.messages.join("; ")));
        }

        widgets.push(serde_json::json!({
            "decoratedText": {
                "topLabel": format!("[{}] {}", level, v.rule),
                "text": body,
                "wrapText": true,
            }
        }));
    }

    if violations.len() > 10 {
        widgets.push(serde_json::json!({
            "textParagraph": {
                "text": format!("...and {} more violations", violations.len() - 10),
            }
        }));
    }

    serde_json::json!({
        "cardsV2": [{
            "cardId": "kxn-violations",
            "card": {
                "header": {
                    "title": format!("kxn | {} violation(s)", violations.len()),
                    "subtitle": target,
                },
                "sections": [{
                    "widgets": widgets,
                }],
            }
        }]
    })
}

/// Send violations to a Google Chat incoming webhook.
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
