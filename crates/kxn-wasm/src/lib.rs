//! WebAssembly bindings for the kxn rule engine.
//!
//! Exposes rule parsing and evaluation (same semantics as `kxn check`) to
//! JavaScript environments: browsers, Node.js and other wasm runtimes.
//! Only the pure-logic crates (`kxn-core`, `kxn-rules`) are included —
//! providers, network and database access stay in the native CLI.

use kxn_core::{check_rule, ResultScan, ScanSummary};
use kxn_rules::parse_string;
use wasm_bindgen::prelude::*;

/// Version of the kxn rule engine embedded in this wasm module.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Parse and validate a TOML rule file.
///
/// Returns the parsed rules serialized as JSON, or throws a JS error with
/// the TOML parse failure.
#[wasm_bindgen]
pub fn validate_rules(rules_toml: &str) -> Result<String, JsError> {
    validate_rules_impl(rules_toml).map_err(|e| JsError::new(&e))
}

// JsError can only be constructed on actual wasm targets, so the logic lives
// in plain-Result functions that native `cargo test` can exercise.
fn validate_rules_impl(rules_toml: &str) -> Result<String, String> {
    let rule_file = parse_string(rules_toml)?;
    serde_json::to_string(&rule_file).map_err(|e| e.to_string())
}

/// Evaluate a TOML rule file against a JSON resource document.
///
/// Mirrors the `kxn check` command: for each rule, resources are extracted
/// from the document by the rule's `object` key (falling back to the root
/// object), filtered by `apply_to`, then every condition is checked.
/// Returns a `ScanSummary` serialized as JSON.
#[wasm_bindgen]
pub fn evaluate(rules_toml: &str, resources_json: &str) -> Result<String, JsError> {
    evaluate_impl(rules_toml, resources_json).map_err(|e| JsError::new(&e))
}

fn evaluate_impl(rules_toml: &str, resources_json: &str) -> Result<String, String> {
    let rule_file = parse_string(rules_toml)?;
    let root: serde_json::Value = serde_json::from_str(resources_json)
        .map_err(|e| format!("Failed to parse resources JSON: {}", e))?;

    let mut results: Vec<ResultScan> = Vec::new();
    let mut passed = 0usize;
    let mut failed = 0usize;

    for rule in &rule_file.rules {
        let resources = extract_resources(&root, &rule.object);
        let targets: Vec<&serde_json::Value> = if resources.is_empty() {
            vec![&root]
        } else {
            resources
        };

        let mut rule_failed = false;
        for resource in targets {
            if !rule.matches_apply_to(resource) {
                continue;
            }
            let sub_results = check_rule(&rule.conditions, resource);
            let errors: Vec<_> = sub_results.into_iter().filter(|r| !r.result).collect();
            if !errors.is_empty() {
                rule_failed = true;
                results.push(ResultScan {
                    object_content: resource.clone(),
                    rule_name: rule.name.clone(),
                    errors,
                    compliance: rule.compliance.clone(),
                });
            }
        }
        if rule_failed {
            failed += 1;
        } else {
            passed += 1;
        }
    }

    let summary = ScanSummary {
        total_rules: rule_file.rules.len(),
        passed,
        failed,
        results,
    };
    serde_json::to_string(&summary).map_err(|e| e.to_string())
}

/// Extract resources matching an object key from the root JSON document.
/// Same behavior as the CLI helper in `kxn-cli/src/commands/mod.rs`.
fn extract_resources<'a>(root: &'a serde_json::Value, object: &str) -> Vec<&'a serde_json::Value> {
    if object.is_empty() {
        return vec![];
    }
    match root.get(object) {
        Some(serde_json::Value::Array(arr)) => arr.iter().collect(),
        Some(val) => vec![val],
        None => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
[[rules]]
name = "bucket-must-be-private"
description = "Buckets must not be public"
level = "error"
object = "buckets"

[[rules.conditions]]
property = "public"
condition = "EQUAL"
value = false
"#;

    #[test]
    fn evaluate_reports_failing_resource() {
        let resources = r#"{"buckets": [{"name": "a", "public": false}, {"name": "b", "public": true}]}"#;
        let summary: serde_json::Value =
            serde_json::from_str(&evaluate_impl(RULES, resources).unwrap()).unwrap();
        assert_eq!(summary["total_rules"], 1);
        assert_eq!(summary["failed"], 1);
        assert_eq!(summary["results"][0]["rule_name"], "bucket-must-be-private");
        assert_eq!(summary["results"][0]["object_content"]["name"], "b");
    }

    #[test]
    fn evaluate_passes_compliant_resources() {
        let resources = r#"{"buckets": [{"name": "a", "public": false}]}"#;
        let summary: serde_json::Value =
            serde_json::from_str(&evaluate_impl(RULES, resources).unwrap()).unwrap();
        assert_eq!(summary["passed"], 1);
        assert_eq!(summary["failed"], 0);
    }

    #[test]
    fn validate_rejects_bad_toml() {
        assert!(validate_rules_impl("not [ valid").is_err());
    }
}
