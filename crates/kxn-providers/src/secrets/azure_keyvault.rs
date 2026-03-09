use anyhow::{Context, Result};

/// Get a secret from Azure Key Vault via REST API.
///
/// Requires env vars: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
pub async fn get_secret(vault_name: &str, secret_name: &str) -> Result<String> {
    let token = get_azure_token(vault_name).await?;
    fetch_secret(vault_name, secret_name, &token).await
}

/// Authenticate via OAuth2 client credentials flow.
async fn get_azure_token(vault_name: &str) -> Result<String> {
    let client_id =
        std::env::var("AZURE_CLIENT_ID").context("AZURE_CLIENT_ID not set")?;
    let client_secret =
        std::env::var("AZURE_CLIENT_SECRET").context("AZURE_CLIENT_SECRET not set")?;
    let tenant_id =
        std::env::var("AZURE_TENANT_ID").context("AZURE_TENANT_ID not set")?;

    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );

    let client = reqwest::Client::new();
    let token_resp = client
        .post(&token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("scope", "https://vault.azure.net/.default"),
        ])
        .send()
        .await
        .with_context(|| {
            format!("Azure OAuth2 request failed for vault '{}'", vault_name)
        })?
        .json::<serde_json::Value>()
        .await?;

    token_resp["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .context("no access_token in Azure OAuth response")
}

/// Fetch a secret value from Key Vault.
async fn fetch_secret(
    vault_name: &str,
    secret_name: &str,
    token: &str,
) -> Result<String> {
    // Key Vault convention: underscores become hyphens
    let secret_name_kv = secret_name.replace('_', "-");
    let secret_url = format!(
        "https://{}.vault.azure.net/secrets/{}?api-version=7.4",
        vault_name, secret_name_kv
    );

    let client = reqwest::Client::new();
    let resp = client
        .get(&secret_url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Azure Key Vault GET failed ({}) for {}/{}: {}",
            status,
            vault_name,
            secret_name,
            text
        );
    }

    let body: serde_json::Value = resp.json().await?;
    body["value"]
        .as_str()
        .map(|s| s.to_string())
        .context("no value in Azure Key Vault response")
}
