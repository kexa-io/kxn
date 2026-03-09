use anyhow::Result;
use serde_json::Value;

use crate::commands::watch::Violation;

/// Build a Microsoft Teams MessageCard payload.
fn format_payload(violations: &[Violation], target: &str) -> Value {
    if violations.is_empty() {
        return serde_json::json!({
            "@type": "MessageCard",
            "summary": format!("kxn | {} | ALL PASSED", target),
            "themeColor": "00FF00",
            "sections": [{
                "activityTitle": format!("kxn | {} | ALL PASSED", target),
            }]
        });
    }

    let facts: Vec<Value> = violations
        .iter()
        .take(10)
        .map(|v| {
            let level = match v.level {
                0 => "info",
                1 => "warning",
                2 => "error",
                _ => "fatal",
            };
            serde_json::json!({
                "name": format!("[{}] {}", level, v.rule),
                "value": v.description,
            })
        })
        .collect();

    let mut sections = vec![serde_json::json!({
        "activityTitle": format!("kxn | {} violation(s) on {}", violations.len(), target),
        "facts": facts,
    })];

    if violations.len() > 10 {
        sections.push(serde_json::json!({
            "activityTitle": format!("...and {} more violations", violations.len() - 10),
        }));
    }

    serde_json::json!({
        "@type": "MessageCard",
        "summary": format!("kxn | {} violation(s)", violations.len()),
        "themeColor": "FF0000",
        "sections": sections,
    })
}

/// Send violations to a Microsoft Teams incoming webhook.
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
