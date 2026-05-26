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
    /// Payload compression for HTTP save backends (elasticsearch, splunk_hec).
    /// Supported: `"gzip"` / `"gz"` (RFC 1952, via flate2). Unset (`None`) = no compression.
    /// `"zstd"` is not yet implemented — planned for a future release.
    /// Loki compression support is also planned but not yet wired.
    /// Non-HTTP backends (postgres, mysql, file, …) ignore this field.
    #[serde(default)]
    pub compression: Option<String>,
    /// Inline retention windows for time-series tables (postgres backend).
    /// When set, rows older than the window are pruned right after each save,
    /// so the database self-bounds without an external cleanup cronjob.
    /// Durations use a compact format: `"30m"`, `"48h"`, `"7d"`, `"2w"`.
    /// Unset tables are never pruned. The env vars
    /// `KXN_RETENTION_{LOGS,METRICS,RESOURCES,SCANS}` override the TOML value.
    #[serde(default)]
    pub retention: RetentionConfig,
}

/// Per-table retention windows applied inline after each save on supported
/// backends (currently postgres). See [`SaveConfig::retention`].
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RetentionConfig {
    /// Retention for the `logs` table (pruned on the `time` column).
    #[serde(default)]
    pub logs: Option<String>,
    /// Retention for the `metrics` table (pruned on the `time` column).
    #[serde(default)]
    pub metrics: Option<String>,
    /// Retention for the `resources` table (pruned on `created_at`). Only rows
    /// not referenced by a `scans` row are pruned, to keep scan history intact.
    #[serde(default)]
    pub resources: Option<String>,
    /// Retention for the `scans` table (pruned on `created_at`).
    #[serde(default)]
    pub scans: Option<String>,
}

impl RetentionConfig {
    /// Resolve the retention window for `table` as a number of seconds, with
    /// the `KXN_RETENTION_<TABLE>` env var taking precedence over the TOML
    /// value. Returns `Ok(None)` when unset, empty, or non-positive (pruning
    /// disabled), and `Err` when a value is set but cannot be parsed.
    pub fn window_secs(&self, table: &str) -> Result<Option<i64>, String> {
        let env = std::env::var(format!("KXN_RETENTION_{}", table.to_ascii_uppercase())).ok();
        let value = env.or_else(|| self.raw_value(table));
        match value {
            Some(v) if !v.trim().is_empty() => {
                let secs = parse_duration_secs(&v)?;
                Ok((secs > 0).then_some(secs))
            }
            _ => Ok(None),
        }
    }

    fn raw_value(&self, table: &str) -> Option<String> {
        match table {
            "logs" => self.logs.clone(),
            "metrics" => self.metrics.clone(),
            "resources" => self.resources.clone(),
            "scans" => self.scans.clone(),
            _ => None,
        }
    }
}

/// Parse a compact duration string into seconds.
///
/// Accepts an integer with an optional unit suffix: `s` (seconds, the default
/// when no unit is given), `m` (minutes), `h` (hours), `d` (days), `w` (weeks).
/// Examples: `"3600"`, `"30m"`, `"48h"`, `"7d"`, `"2w"`.
pub fn parse_duration_secs(input: &str) -> Result<i64, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: i64 = num
        .parse()
        .map_err(|_| format!("invalid duration number in '{}'", input))?;
    let mult = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600,
        "d" | "day" | "days" => 86_400,
        "w" | "week" | "weeks" => 604_800,
        other => return Err(format!("unknown duration unit '{}' in '{}'", other, input)),
    };
    Ok(n * mult)
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

    #[test]
    fn test_parse_duration_secs_units() {
        assert_eq!(parse_duration_secs("3600").unwrap(), 3600);
        assert_eq!(parse_duration_secs("90s").unwrap(), 90);
        assert_eq!(parse_duration_secs("30m").unwrap(), 1800);
        assert_eq!(parse_duration_secs("48h").unwrap(), 172_800);
        assert_eq!(parse_duration_secs("7d").unwrap(), 604_800);
        assert_eq!(parse_duration_secs("2w").unwrap(), 1_209_600);
        assert_eq!(parse_duration_secs(" 7d ").unwrap(), 604_800);
    }

    #[test]
    fn test_parse_duration_secs_errors() {
        assert!(parse_duration_secs("").is_err());
        assert!(parse_duration_secs("abc").is_err());
        assert!(parse_duration_secs("7y").is_err());
    }

    #[test]
    fn test_retention_window_secs() {
        let r = RetentionConfig {
            logs: Some("48h".to_string()),
            metrics: Some("7d".to_string()),
            resources: None,
            scans: Some("0".to_string()),
        };
        assert_eq!(r.window_secs("logs").unwrap(), Some(172_800));
        assert_eq!(r.window_secs("metrics").unwrap(), Some(604_800));
        assert_eq!(r.window_secs("resources").unwrap(), None);
        // "0" disables pruning.
        assert_eq!(r.window_secs("scans").unwrap(), None);
        // Unknown table is never pruned.
        assert_eq!(r.window_secs("unknown").unwrap(), None);
    }

    #[test]
    fn test_parse_save_with_retention() {
        let toml = r#"
[rules]

[[rules.mandatory]]
name = "ssh"
path = "rules/ssh.toml"

[[save]]
type = "postgres"
url = "DATABASE_URL"
retention = { logs = "48h", metrics = "7d", resources = "7d" }
"#;
        let config: ScanConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.save.len(), 1);
        let ret = &config.save[0].retention;
        assert_eq!(ret.window_secs("logs").unwrap(), Some(172_800));
        assert_eq!(ret.window_secs("metrics").unwrap(), Some(604_800));
        assert_eq!(ret.window_secs("scans").unwrap(), None);
    }
}
