//! The secrets-rotation packs, evaluated on resources shaped like their
//! collectors'. Conditions state what COMPLIANT looks like; these packs were
//! written the other way round (`DATE_SUP 90 days` = older than 90 days was
//! the compliant state), so a secret rotated last week was a violation.

use kxn_core::check_rule;
use kxn_rules::parse_string;
use serde_json::{json, Value};

fn days_ago(d: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::days(d)).to_rfc3339()
}

/// Rule name → passes, for every rule of `toml` whose object is `object`.
fn verdicts(toml: &str, object: &str, resource: &Value) -> Vec<(String, bool)> {
    let file = parse_string(toml).expect("the shipped rule file parses");
    file.rules
        .iter()
        .filter(|r| r.object == object)
        .map(|r| (r.name.clone(), check_rule(&r.conditions, resource).iter().all(|c| c.result)))
        .collect()
}

fn passes(toml: &str, object: &str, resource: Value, rule: &str) -> bool {
    verdicts(toml, object, &resource)
        .into_iter()
        .find(|(n, _)| n == rule)
        .unwrap_or_else(|| panic!("no rule {rule}"))
        .1
}

const AWS: &str = include_str!("../../../rules/aws-secrets-rotation.toml");
const GCP: &str = include_str!("../../../rules/gcp-secrets-rotation.toml");
const VAULT: &str = include_str!("../../../rules/vault-secrets-rotation.toml");
const AZURE: &str = include_str!("../../../rules/azure-secrets-rotation.toml");

#[test]
fn aws() {
    let s = |on: bool, d: i64| json!({"rotation_enabled": on, "last_rotated_date": days_ago(d)});
    let o = "aws_secretsmanager_secret";
    assert!(passes(AWS, o, s(true, 10), "aws-secret-not-rotated-90-days"));
    assert!(!passes(AWS, o, s(true, 120), "aws-secret-not-rotated-90-days"));
    assert!(passes(AWS, o, s(true, 120), "aws-secret-not-rotated-180-days"));
    assert!(!passes(AWS, o, s(true, 200), "aws-secret-not-rotated-180-days"));
    assert!(passes(AWS, o, s(true, 10), "aws-secret-rotation-disabled"));
    assert!(!passes(AWS, o, s(false, 10), "aws-secret-rotation-disabled"));
    let k = |m: &str, on: bool| json!({"key_manager": m, "enable_key_rotation": on});
    assert!(passes(AWS, "aws_kms_key", k("CUSTOMER", true), "aws-kms-key-rotation-disabled"));
    assert!(!passes(AWS, "aws_kms_key", k("CUSTOMER", false), "aws-kms-key-rotation-disabled"));
    assert!(passes(AWS, "aws_kms_key", k("AWS", false), "aws-kms-key-rotation-disabled"));
}

#[test]
fn gcp() {
    let v = |state: &str, d: i64| json!({"state": state, "create_time": days_ago(d)});
    let o = "secret_versions";
    assert!(passes(GCP, o, v("ENABLED", 10), "gcp-secret-version-older-than-90-days"));
    assert!(!passes(GCP, o, v("ENABLED", 120), "gcp-secret-version-older-than-90-days"));
    assert!(passes(GCP, o, v("DISABLED", 400), "gcp-secret-version-older-than-180-days"));
    let o = "secrets";
    assert!(passes(GCP, o, json!({"rotation": {"rotationPeriod": "7776000s"}}), "gcp-secret-without-rotation-policy"));
    assert!(!passes(GCP, o, json!({}), "gcp-secret-without-rotation-policy"));
}

#[test]
fn vault() {
    let k = |d: i64| json!({"metadata": {"updated_time": days_ago(d)}});
    let o = "vault_kv_secret_v2";
    assert!(passes(VAULT, o, k(10), "vault-kv-secret-not-rotated-90-days"));
    assert!(!passes(VAULT, o, k(120), "vault-kv-secret-not-rotated-90-days"));
    assert!(passes(VAULT, o, k(200), "vault-kv-secret-stale-365-days"));
    assert!(!passes(VAULT, o, k(400), "vault-kv-secret-stale-365-days"));
}

#[test]
fn azure() {
    let o = "azurerm_key_vault_secret";
    assert!(passes(AZURE, o, json!({"expiration_date": days_ago(-30)}), "azure-kv-secret-past-expiration"));
    assert!(!passes(AZURE, o, json!({"expiration_date": days_ago(3)}), "azure-kv-secret-past-expiration"));
    assert!(passes(AZURE, o, json!({"expiration_date": days_ago(-30)}), "azure-kv-secret-no-expiration"));
    assert!(!passes(AZURE, o, json!({}), "azure-kv-secret-no-expiration"));
    let o = "azurerm_key_vault_key";
    assert!(passes(AZURE, o, json!({"rotation_policy": {"expire_after": "P90D"}}), "azure-kv-key-no-rotation-policy"));
    assert!(!passes(AZURE, o, json!({}), "azure-kv-key-no-rotation-policy"));
}
