//! One URI can stand for several targets: `gcp://` (or `gcp://*`) with no
//! project means every active project the credentials can see.

use anyhow::{anyhow, Result};

/// The concrete targets behind `uri` — itself, or one URI per GCP project.
pub async fn expand(uri: &str) -> Result<Vec<String>> {
    let rest = uri
        .strip_prefix("gcp://")
        .or_else(|| uri.strip_prefix("google://"));
    match rest {
        Some(r) if r.is_empty() || r == "*" || r == "/" => {
            let projects = kxn_providers::native::gcp::list_projects()
                .await
                .map_err(|e| anyhow!("{}", e))?;
            if projects.is_empty() {
                anyhow::bail!("no active GCP project is visible to these credentials");
            }
            Ok(projects.into_iter().map(|p| format!("gcp://{p}")).collect())
        }
        _ => Ok(vec![uri.to_string()]),
    }
}

/// One line for an error of one target among several: the `"message"` of a
/// Google-style JSON error body when there is one, else the first line,
/// truncated — ten projects without some API must not print ten JSON bodies.
pub fn short_error(e: &anyhow::Error) -> String {
    let text = e.to_string();
    let line = text
        .split("\"message\": \"")
        .nth(1)
        .and_then(|m| m.split('"').next())
        .map(String::from)
        .unwrap_or_else(|| text.lines().next().unwrap_or_default().to_string());
    if line.chars().count() > 160 {
        format!("{}…", line.chars().take(159).collect::<String>())
    } else {
        line
    }
}

#[cfg(test)]
mod tests {
    use super::short_error;

    #[test]
    fn google_errors_shrink_to_their_message() {
        let e = anyhow::anyhow!(
            "metrics: Query failed: GET https://x (403): {{\n  \"error\": {{\n    \"code\": 403,\n    \"message\": \"Cloud Monitoring API has not been used\",\n  }}\n}}"
        );
        assert_eq!(short_error(&e), "Cloud Monitoring API has not been used");
        assert_eq!(short_error(&anyhow::anyhow!("plain\nmore")), "plain");
    }
}
