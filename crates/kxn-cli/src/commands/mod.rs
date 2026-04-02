pub mod check;
pub mod cve_update;

/// Extract resources from a gathered JSON object by object type name.
/// Returns references into the original data to avoid cloning.
pub fn extract_resources<'a>(root: &'a serde_json::Value, object: &str) -> Vec<&'a serde_json::Value> {
    if object.is_empty() {
        return vec![];
    }
    match root.get(object) {
        Some(serde_json::Value::Array(arr)) => arr.iter().collect(),
        Some(val) => vec![val],
        None => vec![],
    }
}
pub mod gather;
pub mod init;
pub mod list_providers;
pub mod list_rules;
pub mod list_targets;
pub mod monitor;
pub mod rules;
pub mod scan;
pub mod serve;
pub mod tools;
pub mod watch;
pub mod webhook;
