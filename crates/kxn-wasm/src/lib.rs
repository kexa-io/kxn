//! WebAssembly bindings for the kxn rule engine.
//!
//! Exposes rule parsing and evaluation (same semantics as `kxn check`) to
//! JavaScript environments: browsers, Node.js and other wasm runtimes.
//! Only the pure-logic crates (`kxn-core`, `kxn-rules`) are included —
//! providers, network and database access stay in the native CLI.

use kxn_core::{ResultScan, ScanSummary};
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
    // The shared scan loop, so the browser answers exactly what the CLI does.
    // No target provider and no catalogue here: a page is handed a payload, not
    // a target, so a rule pack is never ruled out and a missing object is
    // reported as absent rather than as an uncollected one.
    let files = vec![(String::new(), rule_file)];
    let resources = vec![root];
    let totals = kxn_rules::scan(
        &files,
        &resources,
        &kxn_rules::ScanOptions::default(),
        |event| {
            if let kxn_rules::Event::Violation {
                rule,
                resource,
                failures,
                ..
            } = event
            {
                results.push(ResultScan {
                    object_content: resource.clone(),
                    rule_name: rule.name.clone(),
                    errors: failures,
                    compliance: rule.compliance.clone(),
                });
            }
        },
    );

    let summary = ScanSummary {
        total_rules: totals.evaluated() + totals.not_evaluated,
        passed: totals.passed,
        failed: totals.failed,
        results,
    };
    serde_json::to_string(&summary).map_err(|e| e.to_string())
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
        // One rule judged against two buckets is two verdicts, and
        // `total_rules` is what `passed + failed` must add up to — the field
        // counts evaluations, not distinct rules, as it does everywhere else.
        assert_eq!(summary["total_rules"], 2);
        assert_eq!(summary["passed"], 1);
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
