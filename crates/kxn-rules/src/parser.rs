use std::path::Path;

use kxn_core::Rule;
use tracing::debug;

use crate::types::RuleFile;

/// Parse a TOML rule file from a string
pub fn parse_string(content: &str) -> Result<RuleFile, String> {
    toml::from_str(content).map_err(|e| format!("Failed to parse TOML: {}", e))
}

/// Parse a TOML rule file from a file path
pub fn parse_file(path: &Path) -> Result<RuleFile, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    debug!("Parsing rule file: {}", path.display());
    parse_string(&content)
}

/// Parse all .toml rule files in a directory
pub fn parse_directory(dir: &Path) -> Result<Vec<(String, RuleFile)>, String> {
    let pattern = dir.join("**/*.toml");
    let pattern_str = pattern
        .to_str()
        .ok_or_else(|| "Invalid path".to_string())?;

    let mut results = Vec::new();
    for entry in glob::glob(pattern_str).map_err(|e| format!("Invalid glob pattern: {}", e))? {
        let path = entry.map_err(|e| format!("Glob error: {}", e))?;
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        match parse_file(&path) {
            Ok(rule_file) => results.push((name, rule_file)),
            Err(e) => tracing::warn!("Skipping {}: {}", path.display(), e),
        }
    }
    Ok(results)
}

/// Extract all rules from parsed files, flattened
pub fn all_rules(files: &[(String, RuleFile)]) -> Vec<&Rule> {
    files.iter().flat_map(|(_, rf)| &rf.rules).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let toml = r#"
[metadata]
version = "1.0.0"
provider = "ssh"

[[rules]]
name = "test-rule"
description = "Test"
level = 2
object = "sshd_config"

  [[rules.conditions]]
  property = "permitrootlogin"
  condition = "EQUAL"
  value = "no"
"#;
        let rf = parse_string(toml).unwrap();
        assert_eq!(rf.rules.len(), 1);
        assert_eq!(rf.rules[0].name, "test-rule");
        assert_eq!(rf.metadata.unwrap().provider.unwrap(), "ssh");
    }

    #[test]
    fn test_parse_parent_rule() {
        let toml = r#"
[[rules]]
name = "parent-test"
level = 1
object = "config"

  [[rules.conditions]]
  operator = "OR"
  criteria = [
    { property = "a", condition = "EQUAL", value = "x" },
    { property = "b", condition = "EQUAL", value = "y" },
  ]
"#;
        let rf = parse_string(toml).unwrap();
        assert_eq!(rf.rules.len(), 1);
        let cond = &rf.rules[0].conditions[0];
        assert!(matches!(cond, kxn_core::ConditionNode::Parent(_)));
    }

    #[test]
    fn test_parse_compliance_and_remediation() {
        let toml = r#"
[[rules]]
name = "ssh-root-login"
description = "Disable root login"
level = 2
object = "sshd_config"

  [[rules.compliance]]
  framework = "CIS"
  control = "5.2.10"
  section = "SSH Server Configuration"

  [[rules.compliance]]
  framework = "PCI-DSS"
  control = "2.2.4"

  [[rules.conditions]]
  property = "permitrootlogin"
  condition = "EQUAL"
  value = "no"

  [[rules.remediation]]
  type = "shell"
  command = "sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config"
  timeout = 10

  [[rules.remediation]]
  type = "webhook"
  url = "https://hooks.example.com/fix"
"#;
        let rf = parse_string(toml).unwrap();
        let rule = &rf.rules[0];
        assert_eq!(rule.compliance.len(), 2);
        assert_eq!(rule.compliance[0].framework, "CIS");
        assert_eq!(rule.compliance[0].control, "5.2.10");
        assert_eq!(rule.compliance[0].section.as_deref(), Some("SSH Server Configuration"));
        assert_eq!(rule.compliance[1].framework, "PCI-DSS");
        assert_eq!(rule.remediation.len(), 2);
        assert!(matches!(&rule.remediation[0], kxn_core::RemediationAction::Shell { .. }));
        assert!(matches!(&rule.remediation[1], kxn_core::RemediationAction::Webhook { .. }));
    }

    #[test]
    fn test_parse_remediation_binary_and_lua() {
        let toml = r#"
[[rules]]
name = "test-binary-lua"
level = 1
object = "test"

  [[rules.conditions]]
  property = "x"
  condition = "EQUAL"
  value = "y"

  [[rules.remediation]]
  type = "binary"
  path = "/usr/local/bin/fix-it"
  args = ["--rule", "test"]
  timeout = 60

  [[rules.remediation]]
  type = "lua"
  script = "scripts/fix.lua"
"#;
        let rf = parse_string(toml).unwrap();
        let rule = &rf.rules[0];
        assert_eq!(rule.remediation.len(), 2);
        if let kxn_core::RemediationAction::Binary { path, args, timeout } = &rule.remediation[0] {
            assert_eq!(path, "/usr/local/bin/fix-it");
            assert_eq!(args, &["--rule", "test"]);
            assert_eq!(*timeout, Some(60));
        } else {
            panic!("expected Binary");
        }
        assert!(matches!(&rule.remediation[1], kxn_core::RemediationAction::Lua { .. }));
    }

    #[test]
    fn test_parse_nested_parent_rule() {
        let toml = r#"
[[rules]]
name = "nested-test"
level = 2
object = "resource"

  [[rules.conditions]]
  operator = "AND"
  criteria = [
    { property = "enabled", condition = "EQUAL", value = true },
    { operator = "OR", criteria = [
      { property = "region", condition = "EQUAL", value = "us-east-1" },
      { property = "region", condition = "EQUAL", value = "eu-west-1" },
    ] },
  ]
"#;
        let rf = parse_string(toml).unwrap();
        assert_eq!(rf.rules.len(), 1);
    }
}
