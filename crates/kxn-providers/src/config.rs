use crate::error::ProviderError;
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
