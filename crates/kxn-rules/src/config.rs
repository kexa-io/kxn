use serde::Deserialize;
use std::path::{Path, PathBuf};

use crate::filter::RuleFilter;
use crate::parser::parse_file;
use crate::types::RuleFile;

/// Top-level kxn.toml config
#[derive(Debug, Clone, Deserialize)]
pub struct ScanConfig {
    pub rules: RulesConfig,
    #[serde(default)]
    pub targets: Vec<TargetConfig>,
    #[serde(default)]
    pub save: Vec<SaveConfig>,
}

/// A [[save]] entry for persisting scan results
#[derive(Debug, Clone, Deserialize)]
pub struct SaveConfig {
    /// Backend type: "postgres", "mysql", "mongodb"
    #[serde(rename = "type")]
    pub backend: String,
    /// Connection URL or env var name
    pub url: String,
    /// Origin name for this kxn instance
    #[serde(default = "default_origin")]
    pub origin: String,
    /// Only save errors (skip passed rules)
    #[serde(default)]
    pub only_errors: bool,
    /// Custom tags to attach to scans
    #[serde(default)]
    pub tags: toml::Table,
}

fn default_origin() -> String {
    "kxn".to_string()
}

/// A [[targets]] entry for daemon/watch mode
#[derive(Debug, Clone, Deserialize)]
pub struct TargetConfig {
    pub name: String,
    /// Provider name — optional if `uri` is set (derived from URI scheme)
    #[serde(default)]
    pub provider: Option<String>,
    /// Target URI (e.g. postgresql://user:pass@host:5432/db)
    /// Supports ${...} interpolation for secrets
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub config: toml::Table,
    /// Rule names or glob patterns to include for this target
    #[serde(default)]
    pub rules: Vec<String>,
    /// Scan interval in seconds (overrides global)
    #[serde(default)]
    pub interval: Option<u64>,
    /// Webhook URLs (overrides global)
    #[serde(default)]
    pub webhook: Vec<String>,
}

/// The [rules] section
#[derive(Debug, Clone, Deserialize)]
pub struct RulesConfig {
    #[serde(default)]
    pub min_level: Option<u8>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub mandatory: Vec<RuleSet>,
    #[serde(default)]
    pub optional: Vec<RuleSet>,
}

/// A named rule set pointing to a TOML file
#[derive(Debug, Clone, Deserialize)]
pub struct RuleSet {
    pub name: String,
    pub path: String,
    /// Only used for optional sets
    #[serde(default)]
    pub enabled: bool,
}

/// Parse kxn.toml from a path
pub fn parse_config(path: &Path) -> Result<ScanConfig, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    toml::from_str(&content).map_err(|e| format!("Failed to parse {}: {}", path.display(), e))
}

/// Resolved rule sets ready for scanning
pub struct ResolvedRules {
    pub files: Vec<(String, RuleFile)>,
    pub filter: RuleFilter,
}

/// Load rules based on kxn.toml config + CLI overrides
pub fn resolve_rules(
    config: &ScanConfig,
    base_dir: &Path,
    enable: &[String],
    disable: &[String],
    only_mandatory: bool,
    all: bool,
) -> Result<ResolvedRules, String> {
    let mut files = Vec::new();

    // Always load mandatory
    for rs in &config.rules.mandatory {
        let path = resolve_path(base_dir, &rs.path);
        let rf = parse_file(&path)?;
        files.push((rs.name.clone(), rf));
    }

    // Load optional based on enabled/disabled state
    if !only_mandatory {
        for rs in &config.rules.optional {
            let should_enable = if all {
                true
            } else if disable.iter().any(|d| d == &rs.name) {
                false
            } else if enable.iter().any(|e| e == &rs.name) {
                true
            } else {
                rs.enabled
            };

            if should_enable {
                let path = resolve_path(base_dir, &rs.path);
                let rf = parse_file(&path)?;
                files.push((rs.name.clone(), rf));
            }
        }
    }

    let filter = RuleFilter {
        include: config.rules.include.clone(),
        exclude: config.rules.exclude.clone(),
        tags: config.rules.tags.clone(),
        min_level: config.rules.min_level,
        ..Default::default()
    };

    Ok(ResolvedRules { files, filter })
}

fn resolve_path(base: &Path, relative: &str) -> PathBuf {
    let p = Path::new(relative);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let toml = r#"
[rules]
min_level = 1

[[rules.mandatory]]
name = "ssh"
path = "rules/ssh.toml"

[[rules.optional]]
name = "mysql"
path = "rules/mysql.toml"
enabled = false
"#;
        let config: ScanConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.rules.mandatory.len(), 1);
        assert_eq!(config.rules.optional.len(), 1);
        assert!(!config.rules.optional[0].enabled);
        assert_eq!(config.rules.min_level, Some(1));
    }

    #[test]
    fn test_parse_config_with_targets() {
        let toml = r#"
[rules]
min_level = 0

[[rules.mandatory]]
name = "ssh-cis"
path = "rules/ssh-cis.toml"

[[targets]]
name = "pg-prod"
provider = "ssh"
rules = ["ssh-cis", "monitoring"]
interval = 30

[targets.config]
SSH_HOST = "postgresql"
SSH_USER = "root"

[[targets]]
name = "mysql-prod"
provider = "ssh"
webhook = ["https://hooks.example.com/alert"]

[targets.config]
SSH_HOST = "mysql"
"#;
        let config: ScanConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.targets.len(), 2);
        assert_eq!(config.targets[0].name, "pg-prod");
        assert_eq!(config.targets[0].provider.as_deref(), Some("ssh"));
        assert_eq!(config.targets[0].interval, Some(30));
        assert_eq!(config.targets[0].rules, vec!["ssh-cis", "monitoring"]);
        assert_eq!(
            config.targets[0].config.get("SSH_HOST").unwrap().as_str(),
            Some("postgresql")
        );
        assert_eq!(config.targets[1].webhook.len(), 1);
        assert!(config.targets[1].interval.is_none());
    }

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
[rules]

[[rules.mandatory]]
name = "ssh"
path = "rules/ssh.toml"
"#;
        let config: ScanConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.rules.mandatory.len(), 1);
        assert!(config.rules.optional.is_empty());
    }
}
