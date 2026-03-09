//! Config file discovery, loading, and secret resolution.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use kxn_rules::config::ScanConfig;
use kxn_rules::secrets::{self, SecretRef};

/// Discover kxn.toml config file.
///
/// Search order: `./kxn.toml`, `~/.config/kxn/kxn.toml`, `~/.kxn.toml`
pub fn discover_config() -> Option<PathBuf> {
    let candidates = vec![
        Some(PathBuf::from("kxn.toml")),
        dirs::config_dir().map(|d| d.join("kxn/kxn.toml")),
        dirs::home_dir().map(|d| d.join(".kxn.toml")),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|p| p.exists())
}

/// Load and parse a kxn.toml config file.
pub fn load_config(path: &Path) -> Result<ScanConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let config: ScanConfig = toml::from_str(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(config)
}

/// Resolve all `${...}` secret references in target URIs.
///
/// Currently resolves `SecretRef::EnvVar` from environment variables.
/// Cloud secret backends (Azure, AWS, Vault, GCP) will be resolved
/// via `kxn_providers::secrets::resolve_ref()` once implemented.
pub async fn resolve_targets(config: &mut ScanConfig) -> Result<()> {
    for target in &mut config.targets {
        if let Some(uri) = &target.uri {
            let refs = secrets::extract_refs(uri);
            if refs.is_empty() {
                continue;
            }

            let mut resolved = HashMap::new();
            for (placeholder, secret_ref) in &refs {
                let value = resolve_secret(secret_ref).await?;
                resolved.insert(placeholder.clone(), value);
            }
            target.uri = Some(secrets::interpolate(uri, &resolved));
        }
    }
    Ok(())
}

/// Resolve a single secret reference.
async fn resolve_secret(secret_ref: &SecretRef) -> Result<String> {
    match secret_ref {
        SecretRef::EnvVar(name) => std::env::var(name)
            .with_context(|| format!("env var ${{{name}}} not set")),
        SecretRef::Azure { vault, name } => {
            // TODO: delegate to kxn_providers::secrets::resolve_ref()
            anyhow::bail!(
                "Azure Key Vault resolution not yet implemented \
                 (vault={vault}, name={name})"
            )
        }
        SecretRef::Aws { secret_name, key } => {
            // TODO: delegate to kxn_providers::secrets::resolve_ref()
            anyhow::bail!(
                "AWS Secrets Manager resolution not yet implemented \
                 (secret={secret_name}, key={key})"
            )
        }
        SecretRef::Vault { path, key } => {
            // TODO: delegate to kxn_providers::secrets::resolve_ref()
            anyhow::bail!(
                "HashiCorp Vault resolution not yet implemented \
                 (path={path}, key={key})"
            )
        }
        SecretRef::Gcp { project, name } => {
            // TODO: delegate to kxn_providers::secrets::resolve_ref()
            anyhow::bail!(
                "GCP Secret Manager resolution not yet implemented \
                 (project={project}, name={name})"
            )
        }
    }
}
