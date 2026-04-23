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

/// Resolve all `${...}` secret references in target URIs and config values.
pub async fn resolve_targets(config: &mut ScanConfig) -> Result<()> {
    for target in &mut config.targets {
        if let Some(uri) = &target.uri {
            let refs = secrets::extract_refs(uri);
            if !refs.is_empty() {
                let mut resolved = HashMap::new();
                for (placeholder, secret_ref) in &refs {
                    let value = resolve_secret(secret_ref).await?;
                    resolved.insert(placeholder.clone(), value);
                }
                target.uri = Some(secrets::interpolate(uri, &resolved));
            }
        }

        // Resolve secrets in config string values
        let keys: Vec<String> = target.config.keys().cloned().collect();
        for key in keys {
            if let Some(toml::Value::String(s)) = target.config.get(&key).cloned() {
                let refs = secrets::extract_refs(&s);
                if !refs.is_empty() {
                    let mut resolved = HashMap::new();
                    for (placeholder, secret_ref) in &refs {
                        let value = resolve_secret(secret_ref).await?;
                        resolved.insert(placeholder.clone(), value);
                    }
                    let interpolated = secrets::interpolate(&s, &resolved);
                    target.config.insert(key, toml::Value::String(interpolated));
                }
            }
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
            kxn_providers::secrets::azure_keyvault::get_secret(vault, name).await
        }
        SecretRef::Aws { secret_name, key } => {
            kxn_providers::secrets::aws_secrets::get_secret(secret_name, key).await
        }
        SecretRef::Vault { path, key } => {
            kxn_providers::secrets::hashicorp_vault::get_secret(path, key).await
        }
        SecretRef::Gcp { project, name } => {
            kxn_providers::secrets::gcp_secrets::get_secret(project, name).await
        }
    }
}
