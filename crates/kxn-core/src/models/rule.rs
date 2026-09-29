use serde::{Deserialize, Serialize};

use super::enums::{Condition, Level, Operator};

/// A single leaf condition that checks a property against a value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesCondition {
    pub property: String,
    pub condition: Condition,
    pub value: serde_json::Value,
    /// Date format string (for DATE_* conditions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

/// A parent rule that groups conditions with a logical operator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub operator: Operator,
    pub criteria: Vec<ConditionNode>,
}

/// A condition node: either a leaf condition or a parent rule with nested conditions.
/// IMPORTANT: ParentRule MUST be listed before RulesCondition for serde(untagged)
/// to try it first (ParentRule has "operator"+"criteria", RulesCondition has "property"+"condition").
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionNode {
    Parent(ParentRule),
    Leaf(RulesCondition),
}

/// Compliance framework mapping (e.g. CIS, PCI-DSS, ISO27001)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRef {
    #[serde(default, alias = "name")]
    pub framework: String,
    #[serde(default, alias = "reference")]
    pub control: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
}

/// Remediation action to execute when a rule fails
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RemediationAction {
    /// Call a webhook URL with violation context as JSON body
    Webhook {
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        method: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        headers: Option<std::collections::HashMap<String, String>>,
    },
    /// Execute a shell command (sh -c)
    Shell {
        command: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout: Option<u64>,
    },
    /// Execute a binary with args
    Binary {
        path: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout: Option<u64>,
    },
    /// Execute a Lua script
    Lua {
        script: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout: Option<u64>,
    },
    /// Execute SQL on the target database (postgresql, mysql)
    Sql {
        query: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reload: Option<bool>,
    },
    /// Rotate an Azure service principal secret and store in Key Vault.
    /// The `vault` field is the Key Vault name (without .vault.azure.net).
    /// The `secret_name` field is the Key Vault secret name to store the new value.
    /// Azure credentials are read from AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET env vars.
    #[serde(rename = "rotateSPSecret")]
    RotateSpSecret {
        vault: String,
        secret_name: String,
    },
    /// Rotate a GCP Service Account key and store the new JSON key in Secret Manager.
    /// The `project` field is the GCP project ID.
    /// The `secret` field is the Secret Manager secret name (created if missing).
    /// GCP credentials are read from GOOGLE_APPLICATION_CREDENTIALS / GCP_CREDENTIALS_JSON env vars.
    #[serde(rename = "rotateSAKey")]
    RotateSAKey {
        project: String,
        secret: String,
    },
}

/// A complete rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(deserialize_with = "deserialize_level")]
    pub level: Level,
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub conditions: Vec<ConditionNode>,
    /// Filter: only apply to resources where a property matches a value.
    /// Example: `apply_to = "docker.service"` matches resources where `name == "docker.service"`
    /// Format: `"value"` (matches `name` property) or `"property=value"` (matches specific property)
    #[serde(default)]
    pub apply_to: Option<String>,
    /// Per-rule webhook URLs (override global)
    #[serde(default)]
    pub webhook: Vec<String>,
    /// Compliance framework mappings
    #[serde(default)]
    pub compliance: Vec<ComplianceRef>,
    /// Remediation actions (executed on violation, premium feature)
    #[serde(default)]
    pub remediation: Vec<RemediationAction>,
}

/// The value half of an `apply_to` filter: everything after the first `=`, or
/// the whole filter when it names no property.
fn filter_value(filter: &str) -> &str {
    match filter.split_once('=') {
        Some((_, value)) => value,
        None => filter,
    }
}

impl Rule {
    /// Check if a resource matches the `apply_to` filter.
    /// Returns true if no filter is set, or if the resource matches.
    pub fn matches_apply_to(&self, resource: &serde_json::Value) -> bool {
        let filter = match &self.apply_to {
            Some(f) => f,
            None => return true,
        };
        let matches = |value: Option<&serde_json::Value>| -> bool {
            // Compared as text rather than as a string only: a collector that
            // publishes `rolcanlogin` as a JSON boolean or a port as a number
            // could not be filtered at all, since `as_str()` answers None for
            // both and every resource fell through the filter.
            match value {
                Some(serde_json::Value::String(s)) => s == filter_value(filter),
                Some(serde_json::Value::Bool(b)) => b.to_string() == filter_value(filter),
                Some(serde_json::Value::Number(n)) => n.to_string() == filter_value(filter),
                _ => false,
            }
        };
        if let Some((prop, _)) = filter.split_once('=') {
            // Explicit property=value: e.g. "state=enabled"
            matches(resource.get(prop))
        } else {
            // Simple value: match against "name" property
            matches(resource.get("name"))
        }
    }
}

fn deserialize_level<'de, D>(deserializer: D) -> Result<Level, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum LevelOrInt {
        Level(Level),
        Int(u8),
    }
    match LevelOrInt::deserialize(deserializer)? {
        LevelOrInt::Level(l) => Ok(l),
        LevelOrInt::Int(i) => Ok(Level::from_u8(i)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_node_deserialize_leaf() {
        let json = r#"{"property":"name","condition":"EQUAL","value":"test"}"#;
        let node: ConditionNode = serde_json::from_str(json).unwrap();
        assert!(matches!(node, ConditionNode::Leaf(_)));
    }

    #[test]
    fn test_condition_node_deserialize_parent() {
        let json = r#"{"operator":"OR","criteria":[
            {"property":"a","condition":"EQUAL","value":"x"},
            {"property":"b","condition":"EQUAL","value":"y"}
        ]}"#;
        let node: ConditionNode = serde_json::from_str(json).unwrap();
        assert!(matches!(node, ConditionNode::Parent(_)));
    }

    #[test]
    fn test_rule_deserialize_with_int_level() {
        let json = r#"{
            "name": "test-rule",
            "level": 2,
            "object": "sshd_config",
            "conditions": [{"property":"x","condition":"EQUAL","value":"y"}]
        }"#;
        let rule: Rule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.level, Level::Error);
    }
}

#[cfg(test)]
mod apply_to_tests {
    use super::*;
    use serde_json::json;

    fn rule(apply_to: Option<&str>) -> Rule {
        let mut r: Rule = serde_json::from_value(json!({
            "name": "r",
            "description": "d",
            "level": 1,
            "object": "roles",
            "conditions": []
        }))
        .expect("rule");
        r.apply_to = apply_to.map(String::from);
        r
    }

    /// A collector publishes `rolcanlogin` as a JSON boolean, not as the string
    /// "true". Comparing with `as_str()` answered None for it, so the filter
    /// matched nothing and the rule was scored against every role — including
    /// the fifteen built-in ones that cannot connect at all.
    #[test]
    fn filters_on_a_boolean_property() {
        let r = rule(Some("rolcanlogin=true"));
        assert!(r.matches_apply_to(&json!({ "rolname": "app", "rolcanlogin": true })));
        assert!(!r.matches_apply_to(&json!({ "rolname": "pg_read_all_data", "rolcanlogin": false })));
    }

    #[test]
    fn filters_on_a_numeric_property() {
        let r = rule(Some("port=443"));
        assert!(r.matches_apply_to(&json!({ "port": 443 })));
        assert!(!r.matches_apply_to(&json!({ "port": 80 })));
    }

    #[test]
    fn a_string_property_and_the_name_shorthand_still_work() {
        assert!(rule(Some("state=enabled")).matches_apply_to(&json!({ "state": "enabled" })));
        assert!(rule(Some("docker.service")).matches_apply_to(&json!({ "name": "docker.service" })));
        assert!(!rule(Some("docker.service")).matches_apply_to(&json!({ "name": "sshd" })));
    }

    #[test]
    fn no_filter_applies_to_everything() {
        assert!(rule(None).matches_apply_to(&json!({ "anything": 1 })));
    }

    /// A filter naming a property the resource does not have must not match:
    /// silently applying to everything is how the connection-limit rule came to
    /// be scored against roles it was never meant for.
    #[test]
    fn a_missing_property_does_not_match() {
        assert!(!rule(Some("rolcanlogin=true")).matches_apply_to(&json!({ "rolname": "x" })));
    }
}
