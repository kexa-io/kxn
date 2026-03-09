use anyhow::{Context, Result};

/// Get a secret from HashiCorp Vault.
///
/// Tries HCP (HashiCorp Cloud Platform) first if HCP_CLIENT_ID,
/// HCP_CLIENT_SECRET, and HCP_API_URL are set.
/// Otherwise falls back to local Vault with VAULT_ADDR + VAULT_TOKEN.
pub async fn get_secret(path: &str, key: &str) -> Result<String> {
    let client = reqwest::Client::new();

    // Try HCP first
    if let (Ok(client_id), Ok(client_secret), Ok(api_url)) = (
        std::env::var("HCP_CLIENT_ID"),
        std::env::var("HCP_CLIENT_SECRET"),
        std::env::var("HCP_API_URL"),
    ) {
        return get_secret_hcp(
            &client,
            &client_id,
            &client_secret,
            &api_url,
            path,
            key,
        )
        .await;
    }

    // Local Vault with token auth
    get_secret_local(&client, path, key).await
}

/// Fetch a secret from a local/self-hosted Vault instance.
async fn get_secret_local(
    client: &reqwest::Client,
    path: &str,
    key: &str,
) -> Result<String> {
    let addr = std::env::var("VAULT_ADDR").context("VAULT_ADDR not set")?;
    let token = std::env::var("VAULT_TOKEN").context("VAULT_TOKEN not set")?;

    let url = format!("{}/v1/{}", addr.trim_end_matches('/'), path);
    let resp = client
        .get(&url)
        .header("X-Vault-Token", &token)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Vault GET failed ({}) for {}: {}", status, path, text);
    }

    let body: serde_json::Value = resp.json().await?;

    // KV v2: data.data.{key}, KV v1: data.{key}
    let value = body["data"]["data"][key]
        .as_str()
        .or_else(|| body["data"][key].as_str())
        .with_context(|| {
            format!("key '{}' not found at path '{}'", key, path)
        })?;

    Ok(value.to_string())
}

/// Fetch a secret from HashiCorp Cloud Platform (HCP).
async fn get_secret_hcp(
    client: &reqwest::Client,
    client_id: &str,
    client_secret: &str,
    api_url: &str,
    path: &str,
    key: &str,
) -> Result<String> {
    let token = get_hcp_token(client, client_id, client_secret).await?;

    let secret_url = format!(
        "{}/{}:{}",
        api_url.trim_end_matches('/'),
        path,
        key
    );
    let resp = client
        .get(&secret_url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "HCP secret GET failed ({}) for {}:{}: {}",
            status,
            path,
            key,
            text
        );
    }

    let body: serde_json::Value = resp.json().await?;
    body["secret"]["version"]["value"]
        .as_str()
        .map(|s| s.to_string())
        .with_context(|| format!("HCP secret not found: {}:{}", path, key))
}

/// Authenticate with HCP via OAuth2 client credentials.
async fn get_hcp_token(
    client: &reqwest::Client,
    client_id: &str,
    client_secret: &str,
) -> Result<String> {
    let resp = client
        .post("https://auth.idp.hashicorp.com/oauth2/token")
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("audience", "https://api.hashicorp.cloud"),
        ])
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    resp["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .context("no access_token in HCP OAuth response")
}
