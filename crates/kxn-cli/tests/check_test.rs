//! Integration tests: TOML rules → engine evaluation → pass/fail

use kxn_core::check_rule;
use kxn_rules::parse_string;
use serde_json::json;

/// Helper: parse a TOML rule string and evaluate against a resource
fn eval(toml: &str, resource: serde_json::Value) -> Vec<kxn_core::SubResultScan> {
    let files = parse_string(toml).expect("valid TOML");
    let mut all = Vec::new();
    for rule in &files.rules {
        let results = check_rule(&rule.conditions, &resource);
        all.extend(results);
    }
    all
}

fn all_pass(results: &[kxn_core::SubResultScan]) -> bool {
    results.iter().all(|r| r.result)
}

fn all_fail(results: &[kxn_core::SubResultScan]) -> bool {
    results.iter().all(|r| !r.result)
}

// === SSH CIS rules (full file) ===

const SSH_CIS_TOML: &str = r#"
[metadata]
version = "1.0.0"
provider = "ssh"

[[rules]]
name = "no-root-login"
description = "Disable root login"
level = 2
object = "sshd_config"

  [[rules.conditions]]
  property = "permitrootlogin"
  condition = "EQUAL"
  value = "no"

[[rules]]
name = "disable-empty-passwords"
description = "Disable empty passwords"
level = 2
object = "sshd_config"

  [[rules.conditions]]
  operator = "OR"
  criteria = [
    { property = "permitemptypasswords", condition = "EQUAL", value = "no" },
    { property = "permitemptypasswords", condition = "EQUAL", value = "" },
  ]

[[rules]]
name = "max-auth-tries"
description = "Max auth tries <= 4"
level = 1
object = "sshd_config"

  [[rules.conditions]]
  property = "maxauthtries"
  condition = "INF_OR_EQUAL"
  value = 4
"#;

#[test]
fn ssh_cis_compliant_server() {
    let resource = json!({
        "permitrootlogin": "no",
        "permitemptypasswords": "no",
        "maxauthtries": 3
    });
    let results = eval(SSH_CIS_TOML, resource);
    assert_eq!(results.len(), 3);
    assert!(all_pass(&results), "All CIS rules should pass");
}

#[test]
fn ssh_cis_non_compliant_server() {
    let resource = json!({
        "permitrootlogin": "yes",
        "permitemptypasswords": "yes",
        "maxauthtries": 10
    });
    let results = eval(SSH_CIS_TOML, resource);
    assert_eq!(results.len(), 3);
    assert!(all_fail(&results), "All CIS rules should fail");
}

#[test]
fn ssh_cis_partial_compliance() {
    let resource = json!({
        "permitrootlogin": "no",
        "permitemptypasswords": "yes",
        "maxauthtries": 4
    });
    let results = eval(SSH_CIS_TOML, resource);
    assert!(results[0].result, "no-root-login should pass");
    assert!(!results[1].result, "empty-passwords should fail");
    assert!(results[2].result, "max-auth-tries 4 <= 4 should pass");
}

// === Condition type coverage ===

#[test]
fn condition_equal_and_different() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "eq"
description = "equal test"
level = 0
  [[rules.conditions]]
  property = "val"
  condition = "EQUAL"
  value = "hello"

[[rules]]
name = "diff"
description = "different test"
level = 0
  [[rules.conditions]]
  property = "val"
  condition = "DIFFERENT"
  value = "world"
"#;
    let results = eval(toml, json!({"val": "hello"}));
    assert!(results[0].result, "EQUAL hello == hello");
    assert!(results[1].result, "DIFFERENT hello != world");
}

#[test]
fn condition_numeric_comparisons() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "sup"
description = "sup"
level = 0
  [[rules.conditions]]
  property = "count"
  condition = "SUP"
  value = 5

[[rules]]
name = "inf"
description = "inf"
level = 0
  [[rules.conditions]]
  property = "count"
  condition = "INF"
  value = 10

[[rules]]
name = "sup-or-equal"
description = "sup or equal"
level = 0
  [[rules.conditions]]
  property = "count"
  condition = "SUP_OR_EQUAL"
  value = 7

[[rules]]
name = "inf-or-equal"
description = "inf or equal"
level = 0
  [[rules.conditions]]
  property = "count"
  condition = "INF_OR_EQUAL"
  value = 7
"#;
    let results = eval(toml, json!({"count": 7}));
    assert!(results[0].result, "7 > 5");
    assert!(results[1].result, "7 < 10");
    assert!(results[2].result, "7 >= 7");
    assert!(results[3].result, "7 <= 7");
}

#[test]
fn condition_string_operations() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "starts"
description = "starts with"
level = 0
  [[rules.conditions]]
  property = "name"
  condition = "STARTS_WITH"
  value = "prod-"

[[rules]]
name = "ends"
description = "ends with"
level = 0
  [[rules.conditions]]
  property = "name"
  condition = "ENDS_WITH"
  value = "-server"

[[rules]]
name = "include"
description = "include"
level = 0
  [[rules.conditions]]
  property = "name"
  condition = "INCLUDE"
  value = "web"

[[rules]]
name = "regex"
description = "regex"
level = 0
  [[rules.conditions]]
  property = "name"
  condition = "REGEX"
  value = "^prod-.*-server$"
"#;
    let results = eval(toml, json!({"name": "prod-web-server"}));
    assert!(all_pass(&results), "All string ops should pass");
}

#[test]
fn condition_not_variants() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "not-include"
description = "not include"
level = 0
  [[rules.conditions]]
  property = "ciphers"
  condition = "NOT_INCLUDE"
  value = "3des"

[[rules]]
name = "not-starts"
description = "not starts with"
level = 0
  [[rules.conditions]]
  property = "name"
  condition = "NOT_STARTS_WITH"
  value = "dev-"

[[rules]]
name = "not-ends"
description = "not ends with"
level = 0
  [[rules.conditions]]
  property = "name"
  condition = "NOT_ENDS_WITH"
  value = ".tmp"
"#;
    let results = eval(
        toml,
        json!({"ciphers": ["aes256-ctr", "chacha20"], "name": "prod-main"}),
    );
    assert!(all_pass(&results));
}

#[test]
fn condition_in_and_not_in() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "in-list"
description = "in"
level = 0
  [[rules.conditions]]
  property = "region"
  condition = "IN"
  value = ["us-east-1", "eu-west-1", "ap-southeast-1"]

[[rules]]
name = "not-in-list"
description = "not in"
level = 0
  [[rules.conditions]]
  property = "region"
  condition = "NOT_IN"
  value = ["cn-north-1", "cn-northwest-1"]
"#;
    let results = eval(toml, json!({"region": "eu-west-1"}));
    assert!(all_pass(&results));
}

#[test]
fn condition_count_variants() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "count-eq"
description = "count"
level = 0
  [[rules.conditions]]
  property = "items"
  condition = "COUNT"
  value = 3

[[rules]]
name = "count-sup"
description = "count sup"
level = 0
  [[rules.conditions]]
  property = "items"
  condition = "COUNT_SUP"
  value = 2

[[rules]]
name = "count-inf"
description = "count inf"
level = 0
  [[rules.conditions]]
  property = "items"
  condition = "COUNT_INF"
  value = 5
"#;
    let results = eval(toml, json!({"items": ["a", "b", "c"]}));
    assert!(all_pass(&results));
}

#[test]
fn condition_include_not_sensitive() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "case-insensitive"
description = "include not sensitive"
level = 0
  [[rules.conditions]]
  property = "message"
  condition = "INCLUDE_NOT_SENSITIVE"
  value = "ERROR"
"#;
    let results = eval(toml, json!({"message": "An error occurred"}));
    assert!(results[0].result, "Case-insensitive include should match");
}

// === Nested property access ===

#[test]
fn nested_property_deep() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "deep"
description = "deep property"
level = 0
  [[rules.conditions]]
  property = "config.database.ssl.enabled"
  condition = "EQUAL"
  value = true
"#;
    let resource = json!({
        "config": {
            "database": {
                "ssl": {
                    "enabled": true
                }
            }
        }
    });
    let results = eval(toml, resource);
    assert!(results[0].result);
}

// === Parent rules (logical operators) ===

#[test]
fn parent_rule_and() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "and-rule"
description = "AND operator"
level = 0

  [[rules.conditions]]
  operator = "AND"
  criteria = [
    { property = "ssl", condition = "EQUAL", value = true },
    { property = "port", condition = "EQUAL", value = 443 },
  ]
"#;
    let pass = eval(toml, json!({"ssl": true, "port": 443}));
    assert!(pass[0].result);

    let fail = eval(toml, json!({"ssl": true, "port": 80}));
    assert!(!fail[0].result);
}

#[test]
fn parent_rule_or() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "or-rule"
description = "OR operator"
level = 0

  [[rules.conditions]]
  operator = "OR"
  criteria = [
    { property = "protocol", condition = "EQUAL", value = "https" },
    { property = "protocol", condition = "EQUAL", value = "tls" },
  ]
"#;
    let pass = eval(toml, json!({"protocol": "tls"}));
    assert!(pass[0].result);

    let fail = eval(toml, json!({"protocol": "http"}));
    assert!(!fail[0].result);
}

#[test]
fn parent_rule_xor() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "xor-rule"
description = "XOR operator"
level = 0

  [[rules.conditions]]
  operator = "XOR"
  criteria = [
    { property = "a", condition = "EQUAL", value = true },
    { property = "b", condition = "EQUAL", value = true },
  ]
"#;
    // Exactly one true → pass
    let pass = eval(toml, json!({"a": true, "b": false}));
    assert!(pass[0].result);

    // Both true → fail
    let fail = eval(toml, json!({"a": true, "b": true}));
    assert!(!fail[0].result);
}

#[test]
fn parent_rule_not() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "not-rule"
description = "NOT operator"
level = 0

  [[rules.conditions]]
  operator = "NOT"
  criteria = [
    { property = "debug", condition = "EQUAL", value = true },
  ]
"#;
    let pass = eval(toml, json!({"debug": false}));
    assert!(pass[0].result, "NOT(false) should be true");

    let fail = eval(toml, json!({"debug": true}));
    assert!(!fail[0].result, "NOT(true) should be false");
}

#[test]
fn parent_rule_nand() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "nand"
description = "NAND"
level = 0

  [[rules.conditions]]
  operator = "NAND"
  criteria = [
    { property = "a", condition = "EQUAL", value = true },
    { property = "b", condition = "EQUAL", value = true },
  ]
"#;
    // NAND: true when NOT all true
    let pass = eval(toml, json!({"a": true, "b": false}));
    assert!(pass[0].result);

    let fail = eval(toml, json!({"a": true, "b": true}));
    assert!(!fail[0].result);
}

// === Nested parent rules (recursive) ===

#[test]
fn nested_parent_rules() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "nested"
description = "Nested AND inside OR"
level = 1

  [[rules.conditions]]
  operator = "OR"

    [[rules.conditions.criteria]]
    operator = "AND"
    criteria = [
      { property = "protocol", condition = "EQUAL", value = "https" },
      { property = "port", condition = "EQUAL", value = 443 },
    ]

    [[rules.conditions.criteria]]
    operator = "AND"
    criteria = [
      { property = "protocol", condition = "EQUAL", value = "http" },
      { property = "port", condition = "EQUAL", value = 80 },
    ]
"#;
    // https:443 → pass (first AND passes)
    let pass1 = eval(toml, json!({"protocol": "https", "port": 443}));
    assert!(pass1[0].result);

    // http:80 → pass (second AND passes)
    let pass2 = eval(toml, json!({"protocol": "http", "port": 80}));
    assert!(pass2[0].result);

    // https:80 → fail (neither AND group passes fully)
    let fail = eval(toml, json!({"protocol": "https", "port": 80}));
    assert!(!fail[0].result);
}

// === Mixed conditions (leaf + parent in same rule) ===

#[test]
fn mixed_leaf_and_parent() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "mixed"
description = "leaf + parent"
level = 0

  [[rules.conditions]]
  property = "enabled"
  condition = "EQUAL"
  value = true

  [[rules.conditions]]
  operator = "OR"
  criteria = [
    { property = "mode", condition = "EQUAL", value = "strict" },
    { property = "mode", condition = "EQUAL", value = "enforced" },
  ]
"#;
    let pass = eval(toml, json!({"enabled": true, "mode": "strict"}));
    assert!(all_pass(&pass));

    let fail = eval(toml, json!({"enabled": true, "mode": "permissive"}));
    assert!(pass[0].result, "leaf should pass");
    assert!(!fail[1].result, "parent should fail");
}

// === Multiple rules in single file ===

#[test]
fn multiple_rules_independent() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "rule-1"
description = "first rule"
level = 1
  [[rules.conditions]]
  property = "a"
  condition = "EQUAL"
  value = 1

[[rules]]
name = "rule-2"
description = "second rule"
level = 2
  [[rules.conditions]]
  property = "b"
  condition = "SUP"
  value = 10
"#;
    let results = eval(toml, json!({"a": 1, "b": 20}));
    assert_eq!(results.len(), 2);
    assert!(all_pass(&results));
}

// === Level parsing (int and string) ===

#[test]
fn level_parsed_from_integer() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "level-int"
description = "level as int"
level = 3
  [[rules.conditions]]
  property = "x"
  condition = "EQUAL"
  value = 1
"#;
    let files = parse_string(toml).unwrap();
    assert_eq!(files.rules[0].level, kxn_core::Level::Fatal);
}

#[test]
fn level_parsed_from_string() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "level-str"
description = "level as string"
level = "warning"
  [[rules.conditions]]
  property = "x"
  condition = "EQUAL"
  value = 1
"#;
    let files = parse_string(toml).unwrap();
    assert_eq!(files.rules[0].level, kxn_core::Level::Warning);
}

// === Edge cases ===

#[test]
fn missing_property_treated_as_empty_string() {
    let toml = r#"
[metadata]
version = "1.0.0"
provider = "test"

[[rules]]
name = "missing-prop"
description = "missing"
level = 0
  [[rules.conditions]]
  property = "nonexistent"
  condition = "EQUAL"
  value = ""
"#;
    let results = eval(toml, json!({"other": "value"}));
    assert!(results[0].result, "Missing property should default to empty string");
}

#[test]
fn empty_conditions_array_produces_no_results() {
    let conditions: Vec<kxn_core::ConditionNode> = vec![];
    let results = check_rule(&conditions, &json!({}));
    assert!(results.is_empty());
}
