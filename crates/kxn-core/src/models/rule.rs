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
