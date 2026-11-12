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

#[test]
fn http_rule_flags_only_vulnerable_apache_serving_http2() {
    let request = |server: &str, version: &str| json!({"security": {"server": server}, "http_version": version});

    for server in ["Apache/2.4.55 (Debian)", "Apache/2.4.62 (Unix) OpenSSL/3.0.13", "Apache/2.4.70"] {
        assert!(!compliant(HTTP_RULES, &request(server, "HTTP/2.0")), "{server} on HTTP/2 must be flagged");
        assert!(compliant(HTTP_RULES, &request(server, "HTTP/1.1")), "{server} without HTTP/2 is mitigated");
    }
    for server in ["Apache/2.4.54 (Debian)", "Apache/2.4.71", "Apache/2.4.7 (Ubuntu)", "Apache/2.4.700", "Apache", "nginx/1.27.0"] {
        assert!(compliant(HTTP_RULES, &request(server, "HTTP/2.0")), "{server} must not be flagged");
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
