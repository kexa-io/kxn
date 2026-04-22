//! Rule evaluation engine.
//! Port of Kexa checkRule, checkParentRule, checkCondition from analyse.service.ts.

use serde_json::Value;
use tracing::debug;

use crate::models::enums::{Condition, Operator};
use crate::models::rule::{ConditionNode, ParentRule, RulesCondition};
use crate::models::scan::SubResultScan;

use super::conditions::*;
use super::property::get_sub_property;

fn display_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        Value::Array(arr) => arr.iter().map(display_value).collect::<Vec<_>>().join(", "),
        Value::Object(_) => v.to_string(),
    }
}

/// Evaluate a list of condition nodes against a resource.
/// Returns a SubResultScan for each top-level condition.
pub fn check_rule(conditions: &[ConditionNode], resource: &Value) -> Vec<SubResultScan> {
    conditions
        .iter()
        .map(|cond| match cond {
            ConditionNode::Parent(parent) => check_parent_rule(parent, resource),
            ConditionNode::Leaf(leaf) => check_condition(leaf, resource),
        })
        .collect()
}

/// Evaluate a parent rule (logical grouping) against a resource.
fn check_parent_rule(parent: &ParentRule, resource: &Value) -> SubResultScan {
    debug!("check_parent_rule operator={}", parent.operator);
    let results = check_rule(&parent.criteria, resource);

    let combined = match parent.operator {
        Operator::And => results.iter().all(|r| r.result),
        Operator::Or => results.iter().any(|r| r.result),
        Operator::Xor => results.iter().filter(|r| r.result).count() == 1,
        Operator::Nand => !results.iter().all(|r| r.result),
        Operator::Nor => !results.iter().any(|r| r.result),
        Operator::Xnor => results.iter().filter(|r| r.result).count() != 1,
        Operator::Not => !results.first().map(|r| r.result).unwrap_or(false),
    };

    let all_conditions = results
        .iter()
        .flat_map(|r| r.condition.clone())
        .collect();
    let message = results
        .iter()
        .filter_map(|r| r.message.clone())
        .filter(|m| !m.is_empty())
        .collect::<Vec<_>>()
        .join(" || ");

    SubResultScan {
        value: Value::Null,
        result: combined,
        condition: all_conditions,
        message: if message.is_empty() {
            None
        } else {
            Some(message)
        },
    }
}

/// Evaluate a single leaf condition against a resource.
fn check_condition(condition: &RulesCondition, resource: &Value) -> SubResultScan {
    debug!("check_condition: property={}", condition.property);

    let raw_value = get_sub_property(resource, &condition.property);
    let value = raw_value.cloned().unwrap_or(Value::String(String::new()));
    let expected = &condition.value;

    let result = match &condition.condition {
        Condition::Equal => check_equal(expected, &value),
        Condition::Different => !check_equal(expected, &value),
        Condition::Sup => check_greater_than(expected, &value),
        Condition::SupOrEqual => check_greater_than(expected, &value) || check_equal(expected, &value),
        Condition::Inf => check_less_than(expected, &value),
        Condition::InfOrEqual => check_less_than(expected, &value) || check_equal(expected, &value),
        Condition::Include => check_include(expected, &value),
        Condition::NotInclude => !check_include(expected, &value),
        Condition::IncludeNotSensitive => check_include_not_sensitive(expected, &value),
        Condition::NotIncludeNotSensitive => !check_include_not_sensitive(expected, &value),
        Condition::StartsWith => check_starts_with(expected, &value),
        Condition::NotStartsWith => !check_starts_with(expected, &value),
        Condition::EndsWith => check_ends_with(expected, &value),
        Condition::NotEndsWith => !check_ends_with(expected, &value),
        Condition::Regex => check_regex(expected, &value),
        Condition::All => check_all(expected, &value),
        Condition::NotAny => !check_some(expected, &value),
        Condition::Some => check_some(expected, &value),
        Condition::One => check_one(expected, &value),
        Condition::Count => {
            let len = value.as_array().map(|a| a.len()).unwrap_or(0);
            check_equal(expected, &Value::from(len))
        }
        Condition::CountSup => {
            let len = value.as_array().map(|a| a.len()).unwrap_or(0);
            check_greater_than(expected, &Value::from(len))
        }
        Condition::CountSupOrEqual => {
            let len = value.as_array().map(|a| a.len()).unwrap_or(0);
            check_greater_than(expected, &Value::from(len)) || check_equal(expected, &Value::from(len))
        }
        Condition::CountInf => {
            let len = value.as_array().map(|a| a.len()).unwrap_or(0);
            check_less_than(expected, &Value::from(len))
        }
        Condition::CountInfOrEqual => {
            let len = value.as_array().map(|a| a.len()).unwrap_or(0);
            check_less_than(expected, &Value::from(len)) || check_equal(expected, &Value::from(len))
        }
        Condition::DateEqual => check_equal_date(condition, &value),
        Condition::DateSup => check_greater_than_date(condition, &value),
        Condition::DateSupOrEqual => check_greater_than_date_or_equal(condition, &value),
        Condition::DateInf => check_less_than_date(condition, &value),
        Condition::DateInfOrEqual => check_less_than_date_or_equal(condition, &value),
        Condition::Interval => check_interval(expected, &value),
        Condition::DateInterval => check_interval_date(condition, &value),
        Condition::In => check_in(expected, &value),
        Condition::NotIn => check_not_in(expected, &value),
    };

    SubResultScan {
        value: value.clone(),
        result,
        condition: vec![condition.clone()],
        message: if result {
            None
        } else {
            Some(format!(
                "{} {} {} but got {}",
                condition.property, condition.condition,
                display_value(expected), display_value(&value)
            ))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn leaf(property: &str, condition: Condition, value: Value) -> ConditionNode {
        ConditionNode::Leaf(RulesCondition {
            property: property.to_string(),
            condition,
            value,
            date: None,
        })
    }

    #[test]
    fn test_check_rule_equal_pass() {
        let conditions = vec![leaf("name", Condition::Equal, json!("test"))];
        let resource = json!({"name": "test"});
        let results = check_rule(&conditions, &resource);
        assert!(results[0].result);
    }

    #[test]
    fn test_check_rule_equal_fail() {
        let conditions = vec![leaf("name", Condition::Equal, json!("test"))];
        let resource = json!({"name": "other"});
        let results = check_rule(&conditions, &resource);
        assert!(!results[0].result);
    }

    #[test]
    fn test_check_parent_rule_or() {
        let parent = ConditionNode::Parent(ParentRule {
            name: None,
            description: None,
            operator: Operator::Or,
            criteria: vec![
                leaf("a", Condition::Equal, json!("x")),
                leaf("b", Condition::Equal, json!("y")),
            ],
        });
        // Only 'b' matches
        let resource = json!({"a": "nope", "b": "y"});
        let results = check_rule(&[parent], &resource);
        assert!(results[0].result);
    }

    #[test]
    fn test_check_parent_rule_and_fail() {
        let parent = ConditionNode::Parent(ParentRule {
            name: None,
            description: None,
            operator: Operator::And,
            criteria: vec![
                leaf("a", Condition::Equal, json!("x")),
                leaf("b", Condition::Equal, json!("y")),
            ],
        });
        let resource = json!({"a": "x", "b": "nope"});
        let results = check_rule(&[parent], &resource);
        assert!(!results[0].result);
    }

    #[test]
    fn test_check_parent_rule_not() {
        let parent = ConditionNode::Parent(ParentRule {
            name: None,
            description: None,
            operator: Operator::Not,
            criteria: vec![leaf("enabled", Condition::Equal, json!(true))],
        });
        let resource = json!({"enabled": false});
        let results = check_rule(&[parent], &resource);
        assert!(results[0].result);
    }

    #[test]
    fn test_nested_property() {
        let conditions = vec![leaf("config.ssh.port", Condition::Equal, json!(22))];
        let resource = json!({"config": {"ssh": {"port": 22}}});
        let results = check_rule(&conditions, &resource);
        assert!(results[0].result);
    }

    #[test]
    fn test_missing_property_defaults_empty() {
        let conditions = vec![leaf("missing", Condition::Equal, json!(""))];
        let resource = json!({"other": "value"});
        let results = check_rule(&conditions, &resource);
        assert!(results[0].result);
    }

    #[test]
    fn test_different_condition() {
        let conditions = vec![leaf("status", Condition::Different, json!("disabled"))];
        let resource = json!({"status": "enabled"});
        let results = check_rule(&conditions, &resource);
        assert!(results[0].result);
    }

    #[test]
    fn test_include_condition() {
        let conditions = vec![leaf("tags", Condition::Include, json!("prod"))];
        let resource = json!({"tags": ["dev", "prod", "us-east"]});
        let results = check_rule(&conditions, &resource);
        assert!(results[0].result);
    }

    #[test]
    fn test_in_condition() {
        let conditions = vec![leaf(
            "region",
            Condition::In,
            json!(["us-east-1", "eu-west-1"]),
        )];
        let resource = json!({"region": "us-east-1"});
        let results = check_rule(&conditions, &resource);
        assert!(results[0].result);
    }

    #[test]
    fn test_regex_condition() {
        let conditions = vec![leaf("email", Condition::Regex, json!(r"^.+@.+\..+$"))];
        let resource = json!({"email": "user@example.com"});
        let results = check_rule(&conditions, &resource);
        assert!(results[0].result);
    }

    #[test]
    fn test_count_condition() {
        let conditions = vec![leaf("items", Condition::CountSupOrEqual, json!(3))];
        let resource = json!({"items": [1, 2, 3, 4]});
        let results = check_rule(&conditions, &resource);
        assert!(results[0].result);
    }
}
