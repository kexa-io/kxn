use crate::error::ProviderError;
use crate::native::native_provider_names;
use serde_json::Value;

/// Resolve a config value: JSON config > env `PREFIX_KEY` > env `KEY`.
pub fn get_config_or_env(config: &Value, key: &str, prefix: Option<&str>) -> Option<String> {
    // 1. JSON config (case-insensitive key lookup)
    if let Value::Object(map) = config {
        let key_upper = key.to_uppercase();
        let key_lower = key.to_lowercase();
        for (k, v) in map {
            if k == key || k.to_uppercase() == key_upper || k.to_lowercase() == key_lower {
                return match v {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    Value::Bool(b) => Some(b.to_string()),
                    _ => Some(v.to_string()),
                };
            }
        }
    }

    // 2. Env PREFIX_KEY
    if let Some(pfx) = prefix {
        let env_key = format!("{}_{}", pfx, key.to_uppercase());
        if let Ok(val) = std::env::var(&env_key) {
            return Some(val);
        }
    }

    // 3. Env KEY
    if let Ok(val) = std::env::var(key.to_uppercase()) {
        return Some(val);
    }

    None
}

/// Like `get_config_or_env` but returns an error if the key is missing.
pub fn require_config(
    config: &Value,
    key: &str,
    prefix: Option<&str>,
) -> Result<String, ProviderError> {
    get_config_or_env(config, key, prefix).ok_or_else(|| {
        let sources = if let Some(pfx) = prefix {
            format!(
                "config[\"{}\"], env ${}_{}, or env ${}",
                key,
                pfx,
                key.to_uppercase(),
                key.to_uppercase()
            )
        } else {
            format!("config[\"{}\"] or env ${}", key, key.to_uppercase())
        };
        ProviderError::InvalidConfig(format!("Missing required config: {}", sources))
    })
}

/// Resolve a configured target to the provider that scans it and the config
/// that provider expects.
///
/// Both documented target forms are accepted, and they compose:
///
/// - `uri = "postgresql://user:pass@host/db"` — provider and connection
///   settings come from the scheme (the form used by `kxn.toml.example` and
///   docs/configuration.md);
/// - `provider = "cve"` + `[targets.config]` — for providers with no
///   connection URI.
///
/// `extra` (the `[targets.config]` table) overlays whatever the URI supplied,
/// so a URI can be completed key by key. An explicit `provider` that disagrees
/// with the URI scheme wins, with a warning; the scheme still supplies config.
///
/// Callers must interpolate `${secret:...}` placeholders before calling.
pub fn resolve_target(
    uri: Option<&str>,
    provider: Option<&str>,
    extra: Value,
) -> Result<(String, Value), ProviderError> {
    let from_uri = match uri {
        Some(u) => Some(parse_target_uri(u)?),
        None => None,
    };

    let (name, mut config) = match (provider, from_uri) {
        (Some(explicit), Some((uri_provider, uri_config))) => {
            if explicit != uri_provider {
                tracing::warn!(
                    explicit = %explicit, from_uri = %uri_provider,
                    "target declares a provider that disagrees with its URI scheme; using the explicit one"
                );
            }
            (explicit.to_string(), uri_config)
        }
        (Some(explicit), None) => (explicit.to_string(), Value::Object(Default::default())),
        (None, Some((uri_provider, uri_config))) => (uri_provider, uri_config),
        (None, None) => {
            return Err(ProviderError::InvalidConfig(
                "target has neither `uri` nor `provider`".to_string(),
            ))
        }
    };

    if let Value::Object(extra) = extra {
        if !config.is_object() {
            config = Value::Object(Default::default());
        }
        let map = config.as_object_mut().expect("config is an object");
        for (k, v) in extra {
            map.insert(k, v);
        }
    }

    Ok((name, config))
}

/// Copy a database URI's query parameters into the provider config.
///
/// libpq-style URIs carry the TLS settings there, and they were dropped on the
/// floor: `postgresql://…?sslmode=require` connected exactly like one without
/// it, so an operator who had asked for encryption got none and was told
/// nothing. A parameter this code does not understand is refused rather than
/// ignored, for the same reason.
fn db_query_params(parsed: &url::Url, config: &mut Value) -> Result<(), ProviderError> {
    for (key, value) in parsed.query_pairs() {
        let suffix = match key.as_ref() {
            "sslmode" | "ssl_mode" => "SSLMODE",
            "sslrootcert" | "ssl_root_cert" | "sslca" => "SSLROOTCERT",
            "dbname" | "database" => "DATABASE",
            other => {
                return Err(ProviderError::InvalidConfig(format!(
                    "unknown URI parameter '{other}'; supported: sslmode, sslrootcert, dbname"
                )))
            }
        };
        // Unprefixed: `get_config_or_env` looks the key up literally in the
        // config and only prefixes when falling back to the environment, so
        // `PG_SSLMODE` in the JSON would never be read.
        config[suffix] = Value::String(value.to_string());
    }
    Ok(())
}

/// Every scheme `parse_target_uri` understands.
///
/// The CLI decides whether a bare first argument is a target or a subcommand by
/// looking for one of these, and it used to keep its own shorter copy: the
/// parser accepted `prometheus://`, `local://`, `msgraph://` and `k8s://` while
/// the dispatcher answered "unrecognized subcommand" for all four. One list,
/// read by both, and a test that keeps it in step with the match below.
pub const URI_SCHEMES: &[&str] = &[
    "aws",
    "postgresql",
    "postgres",
    "mysql",
    "mongodb",
    "mongodb+srv",
    "ssh",
    "local",
    "oracle",
    "http",
    "https",
    "grpc",
    "cve",
    "azure",
    "azurerm",
    "msgraph",
    "microsoft.graph",
    "gcp",
    "google",
    "prometheus",
    "prom",
    "helm",
    "kubernetes",
    "k8s",
];

/// Parse a target URI into (provider_name, config JSON).
///
/// Supported schemes: postgresql, mysql, mongodb, ssh, local, oracle, http, https, grpc
pub fn parse_target_uri(uri: &str) -> Result<(String, Value), ProviderError> {
    // `local://` has no host and url::Url::parse rejects it — short-circuit.
    if uri == "local://" || uri.starts_with("local://") {
        return Ok(("local".to_string(), serde_json::json!({})));
    }

    let parsed = url::Url::parse(uri)
        .map_err(|e| ProviderError::InvalidConfig(format!("Invalid URI: {}", e)))?;
    let scheme = parsed.scheme().to_lowercase();

    let (provider, config) = match scheme.as_str() {
        "postgresql" | "postgres" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(5432);
            let user = parsed.username();
            let password = parsed.password().unwrap_or("");
            if user.is_empty() {
                return Err(ProviderError::InvalidConfig(
                    "PostgreSQL URI must include a user".into(),
                ));
            }
            let mut config = serde_json::json!({
                "PG_HOST": host,
                "PG_PORT": port.to_string(),
                "PG_USER": user,
                "PG_PASSWORD": password,
            });
            // The path names the database, as in every libpq URI.
            let dbname = parsed.path().trim_start_matches('/');
            if !dbname.is_empty() {
                config["DATABASE"] = Value::String(dbname.to_string());
            }
            db_query_params(&parsed, &mut config)?;
            ("postgresql".to_string(), config)
        }
        "mysql" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(3306);
            let user = parsed.username();
            let password = parsed.password().unwrap_or("");
            if user.is_empty() {
                return Err(ProviderError::InvalidConfig(
                    "MySQL URI must include a user".into(),
                ));
            }
            let mut config = serde_json::json!({
                "MYSQL_HOST": host,
                "MYSQL_PORT": port.to_string(),
                "MYSQL_USER": user,
                "MYSQL_PASSWORD": password,
            });
            let dbname = parsed.path().trim_start_matches('/');
            if !dbname.is_empty() {
                config["DATABASE"] = Value::String(dbname.to_string());
            }
            db_query_params(&parsed, &mut config)?;
            ("mysql".to_string(), config)
        }
        "mongodb" | "mongodb+srv" => (
            "mongodb".to_string(),
            serde_json::json!({ "MONGODB_URI": uri }),
        ),
        "ssh" => {
            let host = parsed.host_str().unwrap_or("");
            if host.is_empty() {
                return Err(ProviderError::InvalidConfig(
                    "SSH URI must include a host (e.g. ssh://root@myserver)".into(),
                ));
            }
            let port = parsed.port().unwrap_or(22);
            let user = if parsed.username().is_empty() {
                "root"
            } else {
                parsed.username()
            };
            let password = parsed.password().unwrap_or("");
            let mut config = serde_json::json!({
                "SSH_HOST": host,
                "SSH_PORT": port.to_string(),
                "SSH_USER": user,
            });
            if !password.is_empty() {
                config["SSH_PASSWORD"] = Value::String(password.to_string());
            } else if let Ok(p) = std::env::var("SSH_PASSWORD") {
                config["SSH_PASSWORD"] = Value::String(p);
            } else if let Ok(k) = std::env::var("SSH_KEY_PATH") {
                config["SSH_KEY_PATH"] = Value::String(k);
            } else if let Some(home) = dirs::home_dir() {
                for name in &["id_ed25519", "id_rsa", "id_ecdsa"] {
                    let path = home.join(".ssh").join(name);
                    if path.exists() {
                        config["SSH_KEY_PATH"] =
                            Value::String(path.to_string_lossy().to_string());
                        break;
                    }
                }
            }
            ("ssh".to_string(), config)
        }
        "oracle" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(1521);
            let user = parsed.username();
            let password = parsed.password().unwrap_or("");
            let service = parsed.path().trim_start_matches('/');
            if user.is_empty() {
                return Err(ProviderError::InvalidConfig(
                    "Oracle URI must include a user".into(),
                ));
            }
            (
                "oracle".to_string(),
                serde_json::json!({
                    "ORACLE_HOST": host,
                    "ORACLE_PORT": port.to_string(),
                    "ORACLE_USER": user,
                    "ORACLE_PASSWORD": password,
                    "ORACLE_SERVICE_NAME": if service.is_empty() { "XEPDB1" } else { service },
                }),
            )
        }
        "http" | "https" => (
            "http".to_string(),
            serde_json::json!({ "URL": uri }),
        ),
        "grpc" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(443);
            (
                "grpc".to_string(),
                serde_json::json!({
                    "GRPC_HOST": host,
                    "GRPC_PORT": port.to_string(),
                }),
            )
        }
        "cve" => {
            // cve://nvd — defaults to NVD + KEV + EPSS public feeds
            // cve://nvd?keywords=openssh,nginx&severity=critical&days=7
            let mut config = serde_json::json!({});
            // Parse query params as config
            for (key, value) in parsed.query_pairs() {
                config[key.to_uppercase().to_string()] =
                    Value::String(value.to_string());
            }
            // Host part as a hint (ignored, feeds are configured via env/config)
            ("cve".to_string(), config)
        }
        // azure://<subscription-id> or azure:// — Azure Resource Manager.
        // With no host the first subscription the credentials can see is used.
        "azure" | "azurerm" => {
            let mut config = serde_json::json!({});
            if let Some(sub) = parsed.host_str() {
                if !sub.is_empty() {
                    config["SUBSCRIPTION_ID"] = Value::String(sub.to_string());
                }
            }
            for (key, value) in parsed.query_pairs() {
                let upper = match key.as_ref() {
                    "subscription" | "subscription_id" => "SUBSCRIPTION_ID".to_string(),
                    "concurrency" => "CONCURRENCY".to_string(),
                    other => format!("AZURE_{}", other.to_uppercase()),
                };
                config[upper] = Value::String(value.to_string());
            }
            ("azure".to_string(), config)
        }
        // msgraph:// — Microsoft Graph API provider (uses AZURE_* env vars)
        "msgraph" | "microsoft.graph" => {
            ("microsoft.graph".to_string(), serde_json::json!({}))
        }
        // gcp:// — GCP IAM provider; host is the project ID (gcp://my-project)
        // `aws://eu-west-3` — the region is the host, because a scan pointed at
        // the wrong region reports zero findings for the one that mattered and
        // the provider refuses to guess it.
        "aws" => {
            let region = parsed.host_str().unwrap_or_default();
            if region.is_empty() {
                return Err(ProviderError::InvalidConfig(
                    "AWS URI must name a region (e.g. aws://eu-west-3)".into(),
                ));
            }
            let mut config = serde_json::json!({ "REGION": region });
            for (key, value) in parsed.query_pairs() {
                let upper = match key.as_ref() {
                    "concurrency" => "CONCURRENCY".to_string(),
                    other => other.to_uppercase(),
                };
                config[upper] = Value::String(value.to_string());
            }
            ("aws".to_string(), config)
        }
        "gcp" | "google" => {
            let project = parsed.host_str().unwrap_or("").to_string();
            if project.is_empty() {
                return Err(ProviderError::InvalidConfig(
                    "GCP URI must include a project ID (e.g. gcp://my-project-id)".into(),
                ));
            }
            let mut config = serde_json::json!({ "PROJECT": project });
            // Forward optional query params (e.g. gcp://project?key_max_age_days=30)
            for (key, value) in parsed.query_pairs() {
                config[key.to_uppercase().to_string()] = Value::String(value.to_string());
            }
            ("gcp".to_string(), config)
        }
        // prometheus:// — scrape any Prometheus exposition endpoint.
        // The URL is reconstructed (scheme stripped, http:// added) so
        // both `prometheus://host:9100/metrics` and
        // `prometheus://host:9100/metrics?include_prefixes=traefik_,go_`
        // work. Optional query params map to PROM_* config keys.
        "prometheus" | "prom" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().map(|p| format!(":{}", p)).unwrap_or_default();
            let path = if parsed.path().is_empty() { "/metrics" } else { parsed.path() };
            let mut config = serde_json::json!({
                "PROM_URL": format!("http://{}{}{}", host, port, path),
            });
            for (key, value) in parsed.query_pairs() {
                let upper = match key.as_ref() {
                    "include_prefixes" => "PROM_INCLUDE_PREFIXES".to_string(),
                    "exclude_prefixes" => "PROM_EXCLUDE_PREFIXES".to_string(),
                    "bearer_token" => "PROM_BEARER_TOKEN".to_string(),
                    "insecure" => "PROM_INSECURE".to_string(),
                    other => format!("PROM_{}", other.to_uppercase()),
                };
                config[upper] = Value::String(value.to_string());
            }
            ("prometheus".to_string(), config)
        }
        // helm:// — Helm releases, read from the cluster's own state. Takes the
        // same options as kubernetes:// since that is where Helm keeps them.
        "helm" => {
            let mut config = serde_json::json!({});
            for (key, value) in parsed.query_pairs() {
                let upper = match key.as_ref() {
                    "namespace" | "ns" => "K8S_NAMESPACE".to_string(),
                    "insecure" => "K8S_INSECURE".to_string(),
                    "api_url" => "K8S_API_URL".to_string(),
                    "token" => "K8S_TOKEN".to_string(),
                    "ca_file" => "K8S_CA_FILE".to_string(),
                    "token_file" => "K8S_TOKEN_FILE".to_string(),
                    other => format!("K8S_{}", other.to_uppercase()),
                };
                config[upper] = Value::String(value.to_string());
            }
            ("helm".to_string(), config)
        }
        // kubernetes:// or k8s:// — Kubernetes provider.
        // Host segment is informational (e.g. `in-cluster`, `prod-cluster`);
        // the API URL resolves from K8S_API_URL or the in-cluster ServiceAccount
        // mount. Optional query params override defaults:
        //   kubernetes://in-cluster?namespace=foo&insecure=true
        "kubernetes" | "k8s" => {
            let mut config = serde_json::json!({});
            for (key, value) in parsed.query_pairs() {
                let upper = match key.as_ref() {
                    "namespace" | "ns" => "K8S_NAMESPACE".to_string(),
                    "insecure" => "K8S_INSECURE".to_string(),
                    "api_url" => "K8S_API_URL".to_string(),
                    "token" => "K8S_TOKEN".to_string(),
                    "ca_file" => "K8S_CA_FILE".to_string(),
                    "token_file" => "K8S_TOKEN_FILE".to_string(),
                    other => format!("K8S_{}", other.to_uppercase()),
                };
                config[upper] = Value::String(value.to_string());
            }
            ("kubernetes".to_string(), config)
        }
        _ => {
            return Err(ProviderError::InvalidConfig(format!(
                "Unsupported URI scheme '{}'. Supported: {}",
                scheme,
                URI_SCHEMES.join(", ")
            )));
        }
    };

    let native = native_provider_names();
    if !native.contains(&provider.as_str()) {
        return Err(ProviderError::NotFound(format!(
            "Provider '{}' is not available",
            provider
        )));
    }

    Ok((provider, config))
}

#[cfg(test)]
mod uri_scheme_tests {
    use super::*;

    /// The dispatcher and the parser must agree: a scheme listed in
    /// `URI_SCHEMES` has to reach a real branch of the match, and a scheme that
    /// is not listed has to be refused. Without this the two lists drift, which
    /// is how `prometheus://` became unreachable from the command line while
    /// the parser handled it.
    #[test]
    fn every_listed_scheme_is_parsed() {
        for scheme in URI_SCHEMES {
            let uri = format!("{scheme}://host");
            if let Err(e) = parse_target_uri(&uri) {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "{scheme} is advertised but not parsed: {msg}"
                );
            }
        }
    }

    #[test]
    fn an_unlisted_scheme_is_refused() {
        let err = parse_target_uri("ftp://host").expect_err("ftp is not a target");
        assert!(err.to_string().contains("Unsupported URI scheme"));
    }
}
