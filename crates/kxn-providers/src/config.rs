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
/// Supported schemes: postgresql, mysql, mongodb, ssh, oracle, http, https, grpc
pub fn parse_target_uri(uri: &str) -> Result<(String, Value), ProviderError> {
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
            let host = parsed.host_str().unwrap_or("localhost");
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
        _ => {
            return Err(ProviderError::InvalidConfig(format!(
                "Unsupported URI scheme '{}'. Supported: postgresql, mysql, mongodb, oracle, ssh, http, https, grpc, cve",
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
