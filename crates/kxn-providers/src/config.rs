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
            (
                "postgresql".to_string(),
                serde_json::json!({
                    "PG_HOST": host,
                    "PG_PORT": port.to_string(),
                    "PG_USER": user,
                    "PG_PASSWORD": password,
                }),
            )
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
            (
                "mysql".to_string(),
                serde_json::json!({
                    "MYSQL_HOST": host,
                    "MYSQL_PORT": port.to_string(),
                    "MYSQL_USER": user,
                    "MYSQL_PASSWORD": password,
                }),
            )
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
        // msgraph:// — Microsoft Graph API provider (uses AZURE_* env vars)
        "msgraph" | "microsoft.graph" => {
            ("microsoft.graph".to_string(), serde_json::json!({}))
        }
        // gcp:// — GCP IAM provider; host is the project ID (gcp://my-project)
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
                "Unsupported URI scheme '{}'. Supported: postgresql, mysql, mongodb, oracle, ssh, local, http, https, grpc, cve, msgraph, gcp, kubernetes, prometheus",
                scheme
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
