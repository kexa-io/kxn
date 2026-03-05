use kxn_core::Rule;
use serde::Deserialize;

/// Metadata section of a TOML rule file
#[derive(Debug, Clone, Deserialize)]
pub struct RuleMetadata {
    pub version: Option<String>,
    pub provider: Option<String>,
    pub description: Option<String>,
}

/// A TOML rule file with metadata and rules
#[derive(Debug, Clone, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub metadata: Option<RuleMetadata>,
    pub rules: Vec<Rule>,
}
