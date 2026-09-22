//! Semantics of the shipped Kubernetes CPU/RAM rules against representative
//! `pod_efficiency` / `node_metrics` / `pods` rows. Guards the "missing
//! percentage passes" contract the rules rely on.

use kxn_core::check_rule;
use kxn_rules::{parse_file, RuleFile};
use serde_json::{json, Value};
use std::path::PathBuf;

fn load(file: &str) -> RuleFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .join("rules")
        .join(file);
    parse_file(&path).unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e))
}

/// true when every condition of `rule_name` passes on `row`.
fn passes(rf: &RuleFile, rule_name: &str, row: &Value) -> bool {
    let rule = rf
        .rules
        .iter()
        .find(|r| r.name == rule_name)
        .unwrap_or_else(|| panic!("rule {} not found", rule_name));
    check_rule(&rule.conditions, row).iter().all(|r| r.result)
}

#[test]
fn resources_pack_declares_kubernetes_provider() {
    let rf = load("kubernetes-resources.toml");
    assert_eq!(
        rf.metadata.as_ref().and_then(|m| m.provider.as_deref()),
        Some("kubernetes")
    );
    assert!(rf.rules.iter().all(|r| r.object == "pod_efficiency" || r.object == "node_metrics"));
}

#[test]
fn node_saturation_thresholds() {
    let rf = load("kubernetes-resources.toml");
    assert!(passes(&rf, "k8s-node-cpu-usage-high", &json!({"cpu_pct": 42.0})));
    assert!(!passes(&rf, "k8s-node-cpu-usage-high", &json!({"cpu_pct": 95.5})));
    // allocatable unknown → no pct → must not fire
    assert!(passes(&rf, "k8s-node-cpu-usage-high", &json!({"cpu_millicores": 900.0})));
    assert!(!passes(&rf, "k8s-node-memory-usage-high", &json!({"memory_pct": 91.0})));
}

#[test]
fn memory_near_limit_only_when_limit_exists() {
    let rf = load("kubernetes-resources.toml");
    let hot = json!({"has_memory_limit": true, "memory_limit_pct": 96.2});
    let cold = json!({"has_memory_limit": true, "memory_limit_pct": 40.0});
    let unlimited = json!({"has_memory_limit": false, "memory_usage_mib": 4096.0});
    assert!(!passes(&rf, "k8s-container-memory-near-limit", &hot));
    assert!(passes(&rf, "k8s-container-memory-near-limit", &cold));
    assert!(passes(&rf, "k8s-container-memory-near-limit", &unlimited));
    assert!(!passes(&rf, "k8s-container-no-memory-limit", &unlimited));
    assert!(passes(&rf, "k8s-container-no-memory-limit", &cold));
}

#[test]
fn overprovisioning_needs_a_large_idle_request() {
    let rf = load("kubernetes-resources.toml");
    let idle_big = json!({"has_cpu_request": true, "cpu_request_millicores": 1000.0, "cpu_request_pct": 3.0});
    let idle_small = json!({"has_cpu_request": true, "cpu_request_millicores": 100.0, "cpu_request_pct": 3.0});
    let busy = json!({"has_cpu_request": true, "cpu_request_millicores": 1000.0, "cpu_request_pct": 55.0});
    let none = json!({"has_cpu_request": false, "cpu_usage_millicores": 2.0});
    assert!(!passes(&rf, "k8s-container-cpu-overprovisioned", &idle_big));
    assert!(passes(&rf, "k8s-container-cpu-overprovisioned", &idle_small));
    assert!(passes(&rf, "k8s-container-cpu-overprovisioned", &busy));
    assert!(passes(&rf, "k8s-container-cpu-overprovisioned", &none));

    let mem_idle = json!({"has_memory_request": true, "memory_request_mib": 2048.0, "memory_request_pct": 8.0});
    assert!(!passes(&rf, "k8s-container-memory-overprovisioned", &mem_idle));
}

#[test]
fn pod_resource_limits_rule_checks_every_container() {
    let rf = load("kubernetes.toml");
    let all_limited = json!({"containers": [
        {"name": "a", "resources": {"limits": {"memory": "128Mi"}}},
        {"name": "b", "resources": {"limits": {"cpu": "1", "memory": "1Gi"}}},
    ]});
    let one_missing = json!({"containers": [
        {"name": "a", "resources": {"limits": {"memory": "128Mi"}}},
        {"name": "b", "resources": {"requests": {"cpu": "100m"}}},
    ]});
    let no_resources = json!({"containers": [{"name": "a", "resources": null}]});
    assert!(passes(&rf, "k8s-pod-resource-limits", &all_limited));
    assert!(!passes(&rf, "k8s-pod-resource-limits", &one_missing));
    assert!(!passes(&rf, "k8s-pod-resource-limits", &no_resources));
}
