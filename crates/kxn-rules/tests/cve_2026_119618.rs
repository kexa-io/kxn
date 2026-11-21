//! The shipped CVE-2026-119618 rule files, evaluated against provider-shaped resources.

use kxn_core::check_rule;
use kxn_rules::parse_string;
use serde_json::{json, Value};

const HTTP_RULES: &str = include_str!("../../../rules/http-cve-2026-119618.toml");
const SSH_RULES: &str = include_str!("../../../rules/ssh-cve-2026-119618.toml");

/// True when every rule of the file passes for this resource.
fn compliant(toml: &str, resource: &Value) -> bool {
    let file = parse_string(toml).expect("the shipped rule file parses");
    assert!(!file.rules.is_empty());
    file.rules.iter().all(|rule| check_rule(&rule.conditions, resource).iter().all(|r| r.result))
}

/// Shaped like the http provider's `request` object: `upgrade` is None when the
/// server sends no Upgrade header.
fn request(server: &str, http_version: &str, upgrade: Option<&str>) -> Value {
    let mut headers = json!({"server": server});
    if let Some(u) = upgrade {
        headers["upgrade"] = json!(u);
    }
    json!({"security": {"server": server}, "headers": headers, "http_version": http_version})
}

#[test]
fn http_rule_flags_vulnerable_apache_offering_http2() {
    for server in ["Apache/2.4.55 (Debian)", "Apache/2.4.62 (Unix) OpenSSL/3.0.15", "Apache/2.4.70"] {
        assert!(!compliant(HTTP_RULES, &request(server, "HTTP/1.1", Some("h2"))), "{server} announcing h2 must be flagged");
        assert!(!compliant(HTTP_RULES, &request(server, "HTTP/1.1", Some("h2c"))), "{server} announcing h2c must be flagged");
        assert!(!compliant(HTTP_RULES, &request(server, "HTTP/2.0", None)), "{server} negotiated over HTTP/2 must be flagged");
        assert!(compliant(HTTP_RULES, &request(server, "HTTP/1.1", None)), "{server} without HTTP/2 is mitigated");
    }
}

#[test]
fn http_rule_ignores_fixed_unrelated_or_hidden_versions() {
    for server in ["Apache/2.4.54 (Debian)", "Apache/2.4.71", "Apache/2.4.7 (Ubuntu)", "Apache/2.4.700", "Apache", "nginx/1.27.0"] {
        assert!(compliant(HTTP_RULES, &request(server, "HTTP/1.1", Some("h2"))), "{server} must not be flagged");
    }
}

#[test]
fn ssh_rules_flag_only_vulnerable_package_versions() {
    let package = |version: &str| json!({"name": "apache2", "version": version});

    for version in ["2.4.55-1", "2.4.62-1~deb12u2", "2.4.58-1ubuntu8.5", "2.4.70", "2.4.57-11.el9"] {
        assert!(!compliant(SSH_RULES, &package(version)), "{version} must be flagged");
    }
    for version in ["2.4.54-1~deb11u1", "2.4.71-1", "2.4.7-1ubuntu4", "2.4.700-1", "2.2.34-1"] {
        assert!(compliant(SSH_RULES, &package(version)), "{version} must not be flagged");
    }
}
