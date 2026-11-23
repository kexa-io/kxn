use anyhow::Result;

pub mod aws_secrets;
pub mod azure_keyvault;
pub mod gcp_secrets;
pub mod hashicorp_vault;

/// Split `path/key` on the last `/`; both parts must be non-empty.
fn split_key(rest: &str) -> Option<(&str, &str)> {
    rest.rsplit_once('/')
        .filter(|(path, key)| !path.is_empty() && !key.is_empty())
}

/// Resolve a secret from any backend.
///
/// Formats:
///   "secret:azure:vault/name"      -> Azure Key Vault
///   "secret:aws:name/key"          -> AWS Secrets Manager (name may contain '/')
///   "secret:vault:path/key"        -> HashiCorp Vault / OpenBao (path may contain '/')
///   "secret:gcp:project/name"      -> GCP Secret Manager
///   "ENV_VAR"                       -> Environment variable
pub async fn resolve_ref(ref_str: &str) -> Result<String> {
    if let Some(rest) = ref_str.strip_prefix("secret:azure:") {
        let (vault, name) = rest
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("invalid azure ref: {}", ref_str))?;
        azure_keyvault::get_secret(vault, name).await
    } else if let Some(rest) = ref_str.strip_prefix("secret:aws:") {
        // The key is the last segment: secret names may contain '/' (prod/db/creds).
        let (secret_name, key) = split_key(rest)
            .ok_or_else(|| anyhow::anyhow!("invalid aws ref: {}", ref_str))?;
        aws_secrets::get_secret(secret_name, key).await
    } else if let Some(rest) = ref_str.strip_prefix("secret:vault:") {
        // The key is the last segment: KV paths always contain '/' (secret/data/app).
        let (path, key) = split_key(rest)
            .ok_or_else(|| anyhow::anyhow!("invalid vault ref: {}", ref_str))?;
        hashicorp_vault::get_secret(path, key).await
    } else if let Some(rest) = ref_str.strip_prefix("secret:gcp:") {
        let (project, name) = rest
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("invalid gcp ref: {}", ref_str))?;
        gcp_secrets::get_secret(project, name).await
    } else {
        // Environment variable fallback
        std::env::var(ref_str)
            .map_err(|_| anyhow::anyhow!("env var {} not set", ref_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_env_var() {
        std::env::set_var("KXN_TEST_SECRET_123", "hello");
        let val = resolve_ref("KXN_TEST_SECRET_123").await.unwrap();
        assert_eq!(val, "hello");
        std::env::remove_var("KXN_TEST_SECRET_123");
    }

    #[tokio::test]
    async fn test_resolve_env_var_missing() {
        let res = resolve_ref("KXN_NONEXISTENT_VAR_XYZ").await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("not set"));
    }

    #[tokio::test]
    async fn test_invalid_azure_ref() {
        let res = resolve_ref("secret:azure:no-slash").await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("invalid azure ref"));
    }

    #[tokio::test]
    async fn test_invalid_aws_ref() {
        let res = resolve_ref("secret:aws:no-slash").await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("invalid aws ref"));
    }

    #[test]
    fn test_split_key_keeps_slashes_in_path() {
        assert_eq!(
            split_key("secret/data/kxn/db/password"),
            Some(("secret/data/kxn/db", "password"))
        );
        assert_eq!(split_key("prod/db/creds/user"), Some(("prod/db/creds", "user")));
        assert_eq!(split_key("kxn-alerts/slack"), Some(("kxn-alerts", "slack")));
        assert_eq!(split_key("no-slash"), None);
        assert_eq!(split_key("path/"), None);
        assert_eq!(split_key("/key"), None);
    }

    #[tokio::test]
    async fn test_invalid_vault_ref() {
        let res = resolve_ref("secret:vault:no-slash").await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("invalid vault ref"));
    }

    #[tokio::test]
    async fn test_invalid_gcp_ref() {
        let res = resolve_ref("secret:gcp:no-slash").await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("invalid gcp ref"));
    }
}
