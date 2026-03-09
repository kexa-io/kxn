use anyhow::{Context, Result};

/// Get a secret from Google Cloud Secret Manager via REST API.
///
/// Uses `gcp_auth` crate for authentication (supports service account JSON,
/// metadata server, and application default credentials).
pub async fn get_secret(project: &str, secret_name: &str) -> Result<String> {
    let token = get_gcp_token().await?;
    fetch_secret(project, secret_name, &token).await
}

/// Obtain a GCP access token via the gcp_auth provider.
async fn get_gcp_token() -> Result<String> {
    let provider = gcp_auth::provider()
        .await
        .context("GCP auth failed — set GOOGLE_APPLICATION_CREDENTIALS or run on GCP")?;

    let token = provider
        .token(&["https://www.googleapis.com/auth/cloud-platform"])
        .await
        .context("GCP token acquisition failed")?;

    Ok(token.as_str().to_string())
}

/// Fetch and decode the latest version of a secret.
async fn fetch_secret(
    project: &str,
    secret_name: &str,
    token: &str,
) -> Result<String> {
    let url = format!(
        "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}/versions/latest:access",
        project, secret_name
    );

    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "GCP Secret Manager failed ({}) for {}/{}: {}",
            status,
            project,
            secret_name,
            text
        );
    }

    let body: serde_json::Value = resp.json().await?;
    let b64_data = body["payload"]["data"]
        .as_str()
        .context("no payload.data in GCP response")?;

    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        b64_data,
    )?;

    String::from_utf8(decoded).context("secret is not valid UTF-8")
}
