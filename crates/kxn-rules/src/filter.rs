use kxn_core::Rule;
use serde::Deserialize;

use crate::types::RuleFile;

/// Scan configuration — controls which rules are active
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuleFilter {
    /// Include rules matching these glob patterns (on rule name)
    #[serde(default)]
    pub include: Vec<String>,
    /// Exclude rules matching these glob patterns (on rule name)
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Only include rules that have ALL of these tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Only include rules that have ANY of these tags
    #[serde(default)]
    pub any_tags: Vec<String>,
    /// Minimum severity level (0=info, 1=warning, 2=error, 3=fatal)
    #[serde(default)]
    pub min_level: Option<u8>,
}

impl RuleFilter {
    pub fn is_empty(&self) -> bool {
        self.include.is_empty()
            && self.exclude.is_empty()
            && self.tags.is_empty()
            && self.any_tags.is_empty()
            && self.min_level.is_none()
    }

    /// Filter rules from parsed files. Returns a new vec of (name, RuleFile)
    /// with only matching rules. Metadata tags are merged into each rule's tags.
    pub fn apply(&self, files: &[(String, RuleFile)]) -> Vec<(String, RuleFile)> {
        files
            .iter()
            .filter_map(|(name, rf)| {
                let meta_tags = rf
                    .metadata
                    .as_ref()
                    .map(|m| &m.tags[..])
                    .unwrap_or_default();

                let filtered: Vec<Rule> = rf
                    .rules
                    .iter()
                    .filter(|rule| self.matches(rule, meta_tags))
                    .cloned()
                    .collect();

                if filtered.is_empty() {
                    None
                } else {
                    Some((
                        name.clone(),
                        RuleFile {
                            metadata: rf.metadata.clone(),
                            rules: filtered,
                        },
                    ))
                }
            })
            .collect()
    }

    fn matches(&self, rule: &Rule, meta_tags: &[String]) -> bool {
        // Min level filter
        if let Some(min) = self.min_level {
            if (rule.level as u8) < min {
                return false;
            }
        }

        // Include filter (glob on rule name) — if set, rule must match at least one
        if !self.include.is_empty()
            && !self
                .include
                .iter()
                .any(|pat| glob_match(pat, &rule.name))
        {
            return false;
        }

        // Exclude filter — if any matches, rule is excluded
        if self
            .exclude
            .iter()
            .any(|pat| glob_match(pat, &rule.name))
        {
            return false;
        }

        // Collect all tags (rule + metadata)
        let all_tags: Vec<&str> = rule
            .tags
            .iter()
            .chain(meta_tags.iter())
            .map(|s| s.as_str())
            .collect();

        // Tags filter (AND) — rule must have ALL specified tags
        if !self.tags.is_empty() && !self.tags.iter().all(|t| all_tags.contains(&t.as_str())) {
            return false;
        }

        // Any tags filter (OR) — rule must have at least one
        if !self.any_tags.is_empty()
            && !self
                .any_tags
                .iter()
                .any(|t| all_tags.contains(&t.as_str()))
        {
            return false;
        }

        true
    }
}

/// Simple glob matching: supports `*` as wildcard
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }

    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match text[pos..].find(part) {
            Some(idx) => {
                // First part must match at start
                if i == 0 && idx != 0 {
                    return false;
                }
                pos += idx + part.len();
            }
            None => return false,
        }
    }

    // Last part must match at end
    if let Some(last) = parts.last() {
        if !last.is_empty() && !text.ends_with(last) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("aws-*", "aws-s3-public"));
        assert!(glob_match("*-cis-*", "pg-cis-ssl"));
        assert!(glob_match("ssh-*", "ssh-cis-5.2.10"));
        assert!(!glob_match("aws-*", "gcp-compute"));
        assert!(glob_match("exact-name", "exact-name"));
        assert!(!glob_match("exact-name", "other-name"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*ssl*", "pg-cis-ssl-enabled"));
    }

    #[test]
    fn test_filter_by_include() {
        let filter = RuleFilter {
            include: vec!["ssh-*".into()],
            ..Default::default()
        };
        let rule = make_rule("ssh-cis-root", 2, vec![]);
        assert!(filter.matches(&rule, &[]));

        let rule2 = make_rule("pg-cis-ssl", 2, vec![]);
        assert!(!filter.matches(&rule2, &[]));
    }

    #[test]
    fn test_filter_by_exclude() {
        let filter = RuleFilter {
            exclude: vec!["*-deprecated".into()],
            ..Default::default()
        };
        let rule = make_rule("ssh-cis-deprecated", 2, vec![]);
        assert!(!filter.matches(&rule, &[]));

        let rule2 = make_rule("ssh-cis-root", 2, vec![]);
        assert!(filter.matches(&rule2, &[]));
    }

    #[test]
    fn test_filter_by_tags() {
        let filter = RuleFilter {
            tags: vec!["cis".into(), "level-1".into()],
            ..Default::default()
        };
        let rule = make_rule("test", 2, vec!["cis".into(), "level-1".into()]);
        assert!(filter.matches(&rule, &[]));

        let rule2 = make_rule("test", 2, vec!["cis".into()]);
        assert!(!filter.matches(&rule2, &[]));
    }

    #[test]
    fn test_filter_by_any_tags() {
        let filter = RuleFilter {
            any_tags: vec!["soc2".into(), "hipaa".into()],
            ..Default::default()
        };
        let rule = make_rule("test", 2, vec!["hipaa".into()]);
        assert!(filter.matches(&rule, &[]));

        let rule2 = make_rule("test", 2, vec!["pci".into()]);
        assert!(!filter.matches(&rule2, &[]));
    }

    #[test]
    fn test_filter_by_min_level() {
        let filter = RuleFilter {
            min_level: Some(2),
            ..Default::default()
        };
        let error_rule = make_rule("test", 2, vec![]);
        assert!(filter.matches(&error_rule, &[]));

        let warn_rule = make_rule("test", 1, vec![]);
        assert!(!filter.matches(&warn_rule, &[]));
    }

    #[test]
    fn test_metadata_tags_inherited() {
        let filter = RuleFilter {
            tags: vec!["cis".into()],
            ..Default::default()
        };
        // Rule has no tags, but metadata has "cis"
        let rule = make_rule("test", 2, vec![]);
        let meta_tags = vec!["cis".into()];
        assert!(filter.matches(&rule, &meta_tags));
    }

    fn make_rule(name: &str, level: u8, tags: Vec<String>) -> Rule {
        use kxn_core::models::enums::Level;
        Rule {
            name: name.into(),
            description: String::new(),
            level: Level::from_u8(level),
            object: String::new(),
            tags,
            conditions: vec![],
        }
    }
}
