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

        // Pull identifying fields from the offending object so the alert
        // says WHICH pod / node / secret tripped the rule, not just the
        // rule name. Falls back gracefully when the object has no metadata
        // (cluster-scope rules, raw scalar checks, etc.).
        let identity = identify_object(&v.object_content);
        if !identity.is_empty() {
            description.push_str(&format!("`{}`\n", identity));
        }

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

/// Best-effort identifier for an offending object so the Discord embed
/// can name what tripped the rule (`namespace/name`, `name`, plain
/// fingerprint, …). Tries the K8s metadata locations first, then falls
/// back to flat top-level `name` / `namespace` fields used by the SSH,
/// HTTP and database providers. Returns "" when no identity can be
/// extracted (cluster-stats, single-counter rules, etc.) so the embed
/// stays clean instead of showing `null`.
fn identify_object(obj: &Value) -> String {
    if obj.is_null() {
        return String::new();
    }
    let metadata_name = obj
        .pointer("/metadata/name")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("name").and_then(|v| v.as_str()));
    let metadata_ns = obj
        .pointer("/metadata/namespace")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("namespace").and_then(|v| v.as_str()));
    match (metadata_ns, metadata_name) {
        (Some(ns), Some(n)) if !ns.is_empty() && !n.is_empty() => format!("{}/{}", ns, n),
        (None, Some(n)) | (Some(""), Some(n)) if !n.is_empty() => n.to_string(),
        _ => String::new(),
    }
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
