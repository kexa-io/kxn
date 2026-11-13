//! rules/github-cve-2026-119618.toml against resources shaped like the github provider's.

use kxn_core::check_rule;
use kxn_rules::parse_string;
use serde_json::{json, Value};

const RULES: &str = include_str!("../../../rules/github-cve-2026-119618.toml");

/// Names of the rules that apply to this resource (`object` and `apply_to`) and fail.
fn violations(object: &str, resource: &Value) -> Vec<String> {
    let file = parse_string(RULES).expect("the shipped rule file parses");
    file.rules
        .iter()
        .filter(|r| r.object == object && r.matches_apply_to(resource))
        .filter(|r| check_rule(&r.conditions, resource).iter().any(|res| !res.result))
        .map(|r| r.name.clone())
        .collect()
}

fn image(name: &str, tag: Option<&str>) -> Value {
    json!({"repository": "web", "path": "Dockerfile", "kind": "dockerfile", "registry": "docker.io", "name": name, "tag": tag})
}

#[test]
fn flags_pinned_vulnerable_httpd_images() {
    for tag in ["2.4.55", "2.4.62", "2.4.62-alpine", "2.4.70-bookworm"] {
        assert_eq!(violations("container_images", &image("httpd", Some(tag))), ["github-image-httpd-cve-2026-119618"], "httpd:{tag}");
    }
    assert_eq!(
        violations("container_images", &image("bitnami/apache", Some("2.4.62-debian-12-r3"))),
        ["github-image-bitnami-apache-cve-2026-119618"]
    );
}

#[test]
fn ignores_fixed_floating_and_unrelated_images() {
    for tag in [Some("2.4.54"), Some("2.4.71"), Some("2.4.7"), Some("2.4"), Some("latest"), None] {
        assert!(violations("container_images", &image("httpd", tag)).is_empty(), "httpd:{tag:?}");
    }
    assert!(violations("container_images", &image("nginx", Some("2.4.62"))).is_empty());
}

#[test]
fn flags_a_dependabot_alert_for_the_cve_only() {
    let alert = |cve: &str| json!({"number": 1, "state": "open", "security_advisory": {"cve_id": cve, "ghsa_id": "GHSA-xxxx"}});
    assert_eq!(violations("dependabot_alerts", &alert("CVE-2026-119618")), ["github-dependabot-cve-2026-119618"]);
    assert!(violations("dependabot_alerts", &alert("CVE-2026-00001")).is_empty());
    assert!(violations("dependabot_alerts", &json!({"number": 2, "security_advisory": {"cve_id": null}})).is_empty());
}
