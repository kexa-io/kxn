//! Secret reference parsing and string interpolation.
//!
//! Handles `${...}` interpolation syntax for config files.
//! Pure string parsing — no HTTP, no async, no secret resolution.

use regex::Regex;
use std::collections::HashMap;

/// A parsed secret reference from a `${...}` placeholder.
#[derive(Debug, Clone, PartialEq)]
pub enum SecretRef {
    /// Environment variable: `${MY_VAR}`
    EnvVar(String),
    /// Azure Key Vault: `${secret:azure:vault-name/secret-name}`
    Azure { vault: String, name: String },
    /// AWS Secrets Manager: `${secret:aws:secret-name/key}`
    Aws { secret_name: String, key: String },
    /// HashiCorp Vault: `${secret:vault:path/key}`
    Vault { path: String, key: String },
    /// GCP Secret Manager: `${secret:gcp:project/secret-name}`
    Gcp { project: String, name: String },
}

/// Extract all `${...}` secret references from a string.
///
/// Returns a vec of `(full_placeholder, SecretRef)` pairs.
pub fn extract_refs(s: &str) -> Vec<(String, SecretRef)> {
    let re = Regex::new(r"\$\{([^}]+)\}").expect("invalid regex");
    let mut refs = Vec::new();

    for cap in re.captures_iter(s) {
        let full = cap[0].to_string();
        let content = &cap[1];
        if let Some(secret_ref) = parse_ref(content) {
            refs.push((full, secret_ref));
        }
    }

    refs
}

/// Replace all `${...}` placeholders with resolved values.
///
/// Keys in `resolved` must be the full placeholder string (e.g. `${MY_VAR}`).
pub fn interpolate(s: &str, resolved: &HashMap<String, String>) -> String {
    let mut result = s.to_string();
    for (placeholder, value) in resolved {
        result = result.replace(placeholder, value);
    }
    result
}

/// Redact secrets in a string:
/// - `${...}` placeholders → `***`
/// - URI credentials (scheme://user:pass@host) → `scheme://***:***@host`
pub fn redact(s: &str) -> String {
    // `${...}` placeholders first: whether or not they were resolved, the
    // reference itself names a secret.
    let re_var = Regex::new(r"\$\{[^}]+\}").expect("invalid regex");
    let result = re_var.replace_all(s, "***").to_string();

    // Then the credentials of a connection URI. The user name is masked too:
    // some schemes carry an access key there. The greedy `.+` matters — a
    // password may contain `@`, and stopping at the first one left the rest of
    // it in the clear.
    let re_uri = Regex::new(r"(://)([^/@:]+):(.+)(@)").expect("invalid regex");
    let result = re_uri.replace_all(&result, "${1}***:***${4}").to_string();

    // Finally the query string: `parse_target_uri` accepts secrets there —
    // `kubernetes://c?token=…`, `azure://sub?client_secret=…`,
    // `prometheus://h?bearer_token=…` — and they went through untouched.
    let re_query = Regex::new(
        r"(?i)([?&](?:[a-z0-9_\-]*(?:token|secret|password|passwd|pwd|key|credential)[a-z0-9_\-]*)=)[^&\s]*",
    )
    .expect("invalid regex");
    re_query.replace_all(&result, "${1}***").to_string()
}

/// Parse the content inside `${...}` (without the delimiters).
fn parse_ref(content: &str) -> Option<SecretRef> {
    if let Some(rest) = content.strip_prefix("secret:azure:") {
        let (vault, name) = split_once_slash(rest)?;
        Some(SecretRef::Azure {
            vault: vault.to_string(),
            name: name.to_string(),
        })
    } else if let Some(rest) = content.strip_prefix("secret:aws:") {
        let (secret_name, key) = split_once_slash(rest)?;
        Some(SecretRef::Aws {
            secret_name: secret_name.to_string(),
            key: key.to_string(),
        })
    } else if let Some(rest) = content.strip_prefix("secret:vault:") {
        let (path, key) = split_once_slash(rest)?;
        Some(SecretRef::Vault {
            path: path.to_string(),
            key: key.to_string(),
        })
    } else if let Some(rest) = content.strip_prefix("secret:gcp:") {
        let (project, name) = split_once_slash(rest)?;
        Some(SecretRef::Gcp {
            project: project.to_string(),
            name: name.to_string(),
        })
    } else {
        // Plain env var name
        Some(SecretRef::EnvVar(content.to_string()))
    }
}

/// Split on the first `/` character.
fn split_once_slash(s: &str) -> Option<(&str, &str)> {
    let idx = s.find('/')?;
    Some((&s[..idx], &s[idx + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_env_var() {
        let refs = extract_refs("${MY_VAR}");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, "${MY_VAR}");
        assert_eq!(refs[0].1, SecretRef::EnvVar("MY_VAR".to_string()));
    }

    #[test]
    fn test_parse_azure_secret() {
        let refs = extract_refs("${secret:azure:my-vault/db-password}");
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0].1,
            SecretRef::Azure {
                vault: "my-vault".to_string(),
                name: "db-password".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_aws_secret() {
        let refs = extract_refs("${secret:aws:prod/db-credentials/password}");
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0].1,
            SecretRef::Aws {
                secret_name: "prod".to_string(),
                key: "db-credentials/password".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_vault_secret() {
        let refs = extract_refs("${secret:vault:secret/data/myapp/db-pass}");
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0].1,
            SecretRef::Vault {
                path: "secret".to_string(),
                key: "data/myapp/db-pass".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_gcp_secret() {
        let refs = extract_refs("${secret:gcp:my-project/db-password}");
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0].1,
            SecretRef::Gcp {
                project: "my-project".to_string(),
                name: "db-password".to_string(),
            }
        );
    }

    #[test]
    fn test_multiple_refs() {
        let s = "postgresql://${DB_USER}:${secret:azure:vault/pass}@host:5432";
        let refs = extract_refs(s);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].1, SecretRef::EnvVar("DB_USER".to_string()));
        assert_eq!(
            refs[1].1,
            SecretRef::Azure {
                vault: "vault".to_string(),
                name: "pass".to_string(),
            }
        );
    }

    #[test]
    fn test_no_refs() {
        let refs = extract_refs("postgresql://user:pass@host:5432");
        assert!(refs.is_empty());
    }

    #[test]
    fn test_interpolate() {
        let s = "postgresql://${DB_USER}:${DB_PASS}@host:5432";
        let mut resolved = HashMap::new();
        resolved.insert("${DB_USER}".to_string(), "admin".to_string());
        resolved.insert("${DB_PASS}".to_string(), "s3cret".to_string());
        let result = interpolate(s, &resolved);
        assert_eq!(result, "postgresql://admin:s3cret@host:5432");
    }

    #[test]
    fn test_interpolate_partial() {
        let s = "postgresql://${DB_USER}:${DB_PASS}@host";
        let mut resolved = HashMap::new();
        resolved.insert("${DB_USER}".to_string(), "admin".to_string());
        // DB_PASS not resolved — should remain as-is
        let result = interpolate(s, &resolved);
        assert_eq!(result, "postgresql://admin:${DB_PASS}@host");
    }

    #[test]
    fn test_redact() {
        let s = "postgresql://${DB_USER}:${secret:azure:vault/pass}@host:5432";
        let result = redact(s);
        assert_eq!(result, "postgresql://***:***@host:5432");
    }

    #[test]
    fn test_redact_uri_credentials() {
        let s = "postgresql://user:pass@host:5432";
        assert_eq!(redact(s), "postgresql://***:***@host:5432");
    }

    #[test]
    fn test_redact_no_secrets() {
        let s = "ssh://root@host";
        assert_eq!(redact(s), s);
    }
}

#[cfg(test)]
mod redact_tests {
    use super::redact;

    #[test]
    fn masks_a_connection_password_but_keeps_the_target_readable() {
        // The user name is masked as well: some schemes put an access key
        // there, and the host is enough to tell targets apart.
        let out = redact("postgresql://admin:s3cr3t@db.prod:5432/app");
        assert_eq!(out, "postgresql://***:***@db.prod:5432/app");
    }

    /// A password containing `@` used to be only half masked — the regex
    /// stopped at the first one and published the rest.
    #[test]
    fn masks_a_password_containing_an_at_sign() {
        let out = redact("mysql://root:p@ss@w0rd@db.internal:3306/x");
        assert!(!out.contains("p@ss"), "got: {out}");
        assert!(out.contains("@db.internal:3306/x"), "got: {out}");
    }

    /// `parse_target_uri` reads secrets from the query string, so redaction
    /// has to look there too.
    #[test]
    fn masks_secrets_carried_in_the_query_string() {
        for (uri, leaked) in [
            ("kubernetes://c?token=eyJhbGciOiJIUzI1", "eyJhbGciOiJIUzI1"),
            ("azure://sub?client_secret=abc123", "abc123"),
            ("prometheus://h:9090?bearer_token=xyz789", "xyz789"),
            ("http://h/?api_key=k-12345", "k-12345"),
        ] {
            let out = redact(uri);
            assert!(!out.contains(leaked), "{uri} a fuite: {out}");
            assert!(out.contains("***"), "{uri} -> {out}");
        }
    }

    #[test]
    fn leaves_ordinary_parameters_alone() {
        let out = redact("kubernetes://c?namespace=prod&insecure=true");
        assert_eq!(out, "kubernetes://c?namespace=prod&insecure=true");
    }

    #[test]
    fn masks_secret_references() {
        assert_eq!(
            redact("postgresql://u:${secret:gcp:proj/pg-pass}@h/db"),
            "postgresql://***:***@h/db"
        );
    }
}
