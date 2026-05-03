use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use anyhow::Context;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

const RESOURCE_TYPES: &[&str] = &["service_principals"];

pub struct MicrosoftGraphProvider {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    client: reqwest::Client,
}

impl MicrosoftGraphProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let tenant_id = get_config_or_env(&config, "TENANT_ID", Some("AZURE"))
            .ok_or_else(|| ProviderError::InvalidConfig("AZURE_TENANT_ID not set".into()))?;
        let client_id = get_config_or_env(&config, "CLIENT_ID", Some("AZURE"))
            .ok_or_else(|| ProviderError::InvalidConfig("AZURE_CLIENT_ID not set".into()))?;
        let client_secret = get_config_or_env(&config, "CLIENT_SECRET", Some("AZURE"))
            .ok_or_else(|| ProviderError::InvalidConfig("AZURE_CLIENT_SECRET not set".into()))?;

        let client = reqwest::Client::builder()
            .user_agent("kxn")
            .build()
            .map_err(|e| ProviderError::Connection(format!("HTTP client: {}", e)))?;

        Ok(Self { tenant_id, client_id, client_secret, client })
    }

    async fn get_token(&self) -> Result<String, ProviderError> {
        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );
        let resp = self.client
            .post(&url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("scope", "https://graph.microsoft.com/.default"),
            ])
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("Graph token request failed: {}", e)))?
            .json::<Value>()
            .await
            .map_err(|e| ProviderError::Connection(format!("Graph token parse failed: {}", e)))?;

        resp["access_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ProviderError::Connection("No access_token in response".into()))
    }

    async fn graph_get(&self, token: &str, path: &str) -> Result<Value, ProviderError> {
        let url = format!("https://graph.microsoft.com/v1.0{}", path);
        let resp = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("Graph GET failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Connection(format!("Graph GET {} failed ({}): {}", path, status, text)));
        }
        resp.json::<Value>().await
            .map_err(|e| ProviderError::Connection(format!("Graph response parse failed: {}", e)))
    }

    async fn gather_service_principals(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let now = Utc::now();

        // Fetch all applications (which have passwordCredentials)
        let mut apps: Vec<Value> = Vec::new();
        let mut url = "/applications?$select=id,appId,displayName,passwordCredentials&$top=100".to_string();
        loop {
            let page = self.graph_get(&token, &url).await?;
            if let Some(arr) = page["value"].as_array() {
                apps.extend(arr.iter().cloned());
            }
            match page["@odata.nextLink"].as_str() {
                Some(next) => {
                    // nextLink is absolute URL, strip the base
                    url = next.replace("https://graph.microsoft.com/v1.0", "").to_string();
                }
                None => break,
            }
        }

        let mut results = Vec::new();
        for app in apps {
            let app_id = app["appId"].as_str().unwrap_or("").to_string();
            let app_object_id = app["id"].as_str().unwrap_or("").to_string();
            let display_name = app["displayName"].as_str().unwrap_or("").to_string();

            if let Some(creds) = app["passwordCredentials"].as_array() {
                for cred in creds {
                    let end_dt_str = cred["endDateTime"].as_str().unwrap_or("");
                    let (days_until_expiry, expired) = if end_dt_str.is_empty() {
                        (i64::MAX, false)
                    } else {
                        match end_dt_str.parse::<DateTime<Utc>>() {
                            Ok(end_dt) => {
                                let diff = (end_dt - now).num_days();
                                (diff, diff < 0)
                            }
                            Err(_) => (i64::MAX, false),
                        }
                    };

                    results.push(json!({
                        "app_id": app_id,
                        "app_object_id": app_object_id,
                        "display_name": display_name,
                        "credential_id": cred["keyId"],
                        "credential_name": cred["displayName"],
                        "end_date_time": end_dt_str,
                        "days_until_expiry": days_until_expiry,
                        "expired": expired,
                    }));
                }
            }

            // Also include apps with no credentials (to detect missing rotation policy)
            if app["passwordCredentials"].as_array().map(|a| a.is_empty()).unwrap_or(true) {
                results.push(json!({
                    "app_id": app_id,
                    "app_object_id": app_object_id,
                    "display_name": display_name,
                    "credential_id": null,
                    "credential_name": null,
                    "end_date_time": null,
                    "days_until_expiry": null,
                    "expired": false,
                }));
            }
        }

        Ok(results)
    }
}

#[async_trait::async_trait]
impl Provider for MicrosoftGraphProvider {
    fn name(&self) -> &str {
        "microsoft.graph"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        match resource_type {
            "service_principals" => self.gather_service_principals().await,
            _ => Err(ProviderError::NotFound(format!(
                "Unknown resource type '{}' for microsoft.graph provider", resource_type
            ))),
        }
    }
}

/// Rotate a service principal secret and store the new value in Azure Key Vault.
///
/// Returns the new secret value.
#[allow(clippy::too_many_arguments)]
pub async fn rotate_sp_secret(
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
    app_object_id: &str,
    credential_key_id: &str,
    display_name: &str,
    vault_name: &str,
    vault_secret_name: &str,
) -> anyhow::Result<String> {
    let http = crate::http::shared_client();

    // 1. Get Graph token
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );
    let token_resp = http
        .post(&token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", "https://graph.microsoft.com/.default"),
        ])
        .send().await.context("Graph token request")?
        .json::<Value>().await?;
    let graph_token = token_resp["access_token"]
        .as_str()
        .context("no access_token")?
        .to_string();

    // 2. Add new password credential (1-year validity)
    let add_url = format!(
        "https://graph.microsoft.com/v1.0/applications/{}/addPassword",
        app_object_id
    );
    let add_resp = http
        .post(&add_url)
        .header("Authorization", format!("Bearer {}", graph_token))
        .header("Content-Type", "application/json")
        .json(&json!({
            "passwordCredential": {
                "displayName": format!("{} (rotated by kxn)", display_name),
                "endDateTime": (Utc::now() + chrono::Duration::days(365))
                    .format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            }
        }))
        .send().await.context("Graph addPassword request")?;

    if !add_resp.status().is_success() {
        let status = add_resp.status();
        let body = add_resp.text().await.unwrap_or_default();
        anyhow::bail!("addPassword failed ({}): {}", status, body);
    }
    let new_cred: Value = add_resp.json().await.context("addPassword response parse")?;
    let new_secret = new_cred["secretText"]
        .as_str()
        .context("no secretText in addPassword response")?
        .to_string();

    // 3. Store new secret in Key Vault
    let kv_token = get_kv_token(tenant_id, client_id, client_secret).await?;
    let secret_name_kv = vault_secret_name.replace('_', "-");
    let kv_url = format!(
        "https://{}.vault.azure.net/secrets/{}?api-version=7.4",
        vault_name, secret_name_kv
    );
    let kv_resp = http
        .put(&kv_url)
        .header("Authorization", format!("Bearer {}", kv_token))
        .header("Content-Type", "application/json")
        .json(&json!({ "value": new_secret }))
        .send().await.context("Key Vault PUT secret")?;

    if !kv_resp.status().is_success() {
        let status = kv_resp.status();
        let body = kv_resp.text().await.unwrap_or_default();
        anyhow::bail!("Key Vault PUT failed ({}): {}", status, body);
    }

    // 4. Remove old credential (retry up to 3 times for concurrency errors)
    if !credential_key_id.is_empty() {
        let remove_url = format!(
            "https://graph.microsoft.com/v1.0/applications/{}/removePassword",
            app_object_id
        );
        let mut removed = false;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            let remove_resp = http
                .post(&remove_url)
                .header("Authorization", format!("Bearer {}", graph_token))
                .header("Content-Type", "application/json")
                .json(&json!({ "keyId": credential_key_id }))
                .send().await.context("Graph removePassword request")?;

            if remove_resp.status().is_success() {
                removed = true;
                break;
            }
            let body = remove_resp.text().await.unwrap_or_default();
            if attempt == 2 {
                eprintln!("[remediation] Warning: removePassword failed after 3 attempts: {}", body);
            }
        }
        let _ = removed;
    }

    Ok(new_secret)
}

async fn get_kv_token(tenant_id: &str, client_id: &str, client_secret: &str) -> anyhow::Result<String> {
    let url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );
    let resp = crate::http::shared_client()
        .post(&url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", "https://vault.azure.net/.default"),
        ])
        .send().await.context("KV token request")?
        .json::<Value>().await?;

    resp["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .context("no access_token in KV token response")
}
