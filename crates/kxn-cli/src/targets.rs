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
