use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use anyhow::Context;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

const RESOURCE_TYPES: &[&str] = &["service_account_keys"];
/// Default key age threshold (days) after which rotation is recommended.
const DEFAULT_KEY_MAX_AGE_DAYS: i64 = 90;

pub struct GcpProvider {
    project: String,
    key_max_age_days: i64,
    client: reqwest::Client,
}

impl GcpProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let project = get_config_or_env(&config, "PROJECT", Some("GCP"))
            .ok_or_else(|| ProviderError::InvalidConfig(
                "GCP project not set — use gcp://project-id or GCP_PROJECT env".into()
            ))?;
        let key_max_age_days = get_config_or_env(&config, "KEY_MAX_AGE_DAYS", Some("GCP"))
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(DEFAULT_KEY_MAX_AGE_DAYS);
        let client = reqwest::Client::builder()
            .user_agent("kxn")
            .build()
            .map_err(|e| ProviderError::Connection(format!("HTTP client: {}", e)))?;
        Ok(Self { project, key_max_age_days, client })
    }

    async fn get_token(&self) -> Result<String, ProviderError> {
        let provider = gcp_auth::provider()
            .await
            .map_err(|e| ProviderError::Connection(format!("GCP auth failed: {}", e)))?;
        let token = provider
            .token(&["https://www.googleapis.com/auth/cloud-platform"])
            .await
            .map_err(|e| ProviderError::Connection(format!("GCP token failed: {}", e)))?;
        Ok(token.as_str().to_string())
    }

    async fn iam_get(&self, token: &str, path: &str) -> Result<Value, ProviderError> {
        let url = format!("https://iam.googleapis.com/v1{}", path);
        let resp = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send().await
            .map_err(|e| ProviderError::Connection(format!("IAM GET failed: {}", e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Connection(format!("IAM GET {} failed ({}): {}", path, status, text)));
        }
        resp.json::<Value>().await
            .map_err(|e| ProviderError::Connection(format!("IAM response parse failed: {}", e)))
    }

    async fn list_service_accounts(&self, token: &str) -> Result<Vec<Value>, ProviderError> {
        let mut accounts: Vec<Value> = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut path = format!("/projects/{}/serviceAccounts?pageSize=100", self.project);
            if let Some(pt) = &page_token {
                path.push_str(&format!("&pageToken={}", pt));
            }
            let page = self.iam_get(token, &path).await?;
            if let Some(arr) = page["accounts"].as_array() {
                accounts.extend(arr.iter().cloned());
            }
            match page["nextPageToken"].as_str() {
                Some(pt) if !pt.is_empty() => page_token = Some(pt.to_string()),
                _ => break,
            }
        }
        Ok(accounts)
    }

    async fn list_sa_keys(&self, token: &str, sa_name: &str) -> Result<Vec<Value>, ProviderError> {
        let path = format!("/{}/keys?keyTypes=USER_MANAGED", sa_name);
        let resp = self.iam_get(token, &path).await?;
        Ok(resp["keys"].as_array().cloned().unwrap_or_default())
    }

    async fn gather_service_account_keys(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let now = Utc::now();
        let accounts = self.list_service_accounts(&token).await?;

        let mut results = Vec::new();
        for sa in accounts {
            let email = sa["email"].as_str().unwrap_or("").to_string();
            let sa_name = sa["name"].as_str().unwrap_or("").to_string();
            if sa_name.is_empty() {
                continue;
            }

            let keys = match self.list_sa_keys(&token, &sa_name).await {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(sa = %email, error = %e, "Failed to list keys for SA");
                    continue;
                }
            };

            for key in keys {
                let key_name = key["name"].as_str().unwrap_or("").to_string();
                let key_id = key_name.split('/').next_back().unwrap_or("").to_string();
                if key_id.is_empty() {
                    continue;
                }
                let valid_after_str = key["validAfterTime"].as_str().unwrap_or("").to_string();
                let valid_before_str = key["validBeforeTime"].as_str().unwrap_or("").to_string();
                let algorithm = key["keyAlgorithm"].as_str().unwrap_or("").to_string();

                let (days_until_expiry, effective_expiry) =
                    compute_days_until_expiry(&valid_after_str, &valid_before_str, self.key_max_age_days, &now);

                results.push(json!({
                    "email": email,
                    "key_id": key_id,
                    "key_algorithm": algorithm,
                    "valid_after_time": valid_after_str,
                    "valid_before_time": effective_expiry,
                    "days_until_expiry": days_until_expiry,
                    "key_type": "USER_MANAGED",
                }));
            }
        }

        Ok(results)
    }
}

/// Compute days until expiry for a GCP SA key.
///
/// If `valid_before_time` is far in the future (year >= 9990), falls back to
/// `valid_after_time + max_age_days` as the effective expiry date.
fn compute_days_until_expiry(
    valid_after_str: &str,
    valid_before_str: &str,
    max_age_days: i64,
    now: &DateTime<Utc>,
) -> (i64, String) {
    // Check if validBeforeTime is a real expiry or the GCP "no expiry" sentinel
    let use_explicit_expiry = valid_before_str
        .split('-')
        .next()
        .and_then(|y| y.parse::<i32>().ok())
        .map(|year| year < 9990)
        .unwrap_or(false);

    if use_explicit_expiry {
        if let Ok(expiry) = valid_before_str.parse::<DateTime<Utc>>() {
            let days = (expiry - *now).num_days();
            return (days, valid_before_str.to_string());
        }
    }

    // Fall back to age-based expiry: creation_date + max_age_days
    if let Ok(created) = valid_after_str.parse::<DateTime<Utc>>() {
        let effective_expiry = created + chrono::Duration::days(max_age_days);
        let days = (effective_expiry - *now).num_days();
        let expiry_str = effective_expiry.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        return (days, expiry_str);
    }

    (i64::MAX, String::new())
}

#[async_trait::async_trait]
impl Provider for GcpProvider {
    fn name(&self) -> &str { "gcp" }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        match resource_type {
            "service_account_keys" => self.gather_service_account_keys().await,
            _ => Err(ProviderError::NotFound(format!(
                "Unknown resource type '{}' for gcp provider", resource_type
            ))),
        }
    }
}

/// Rotate a GCP service account key and store the new JSON key in Secret Manager.
///
/// Steps:
/// 1. Create a new SA key (JSON format)
/// 2. Store the JSON in Secret Manager (new version)
/// 3. Delete the old key
///
/// Returns the new key ID.
pub async fn rotate_sa_key(
    project: &str,
    sa_email: &str,
    old_key_id: &str,
    secret_name: &str,
) -> anyhow::Result<String> {
    let http = crate::http::shared_client();

    // 1. Get GCP token
    let provider = gcp_auth::provider()
        .await
        .context("GCP auth failed")?;
    let token = provider
        .token(&["https://www.googleapis.com/auth/cloud-platform"])
        .await
        .context("GCP token failed")?;
    let token_str = token.as_str();

    // 2. Create new SA key
    let sa_resource = format!("projects/{}/serviceAccounts/{}", project, sa_email);
    let create_url = format!("https://iam.googleapis.com/v1/{}/keys", sa_resource);
    let create_resp = http
        .post(&create_url)
        .header("Authorization", format!("Bearer {}", token_str))
        .header("Content-Type", "application/json")
        .json(&json!({
            "keyAlgorithm": "KEY_ALG_RSA_2048",
            "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE"
        }))
        .send().await.context("GCP createServiceAccountKey request")?;

    if !create_resp.status().is_success() {
        let status = create_resp.status();
        let body = create_resp.text().await.unwrap_or_default();
        anyhow::bail!("createServiceAccountKey failed ({}): {}", status, body);
    }

    let new_key: Value = create_resp.json().await.context("createServiceAccountKey response parse")?;
    let new_key_id = new_key["name"]
        .as_str()
        .and_then(|n| n.split('/').next_back())
        .context("no key name in createServiceAccountKey response")?
        .to_string();
    let private_key_data_b64 = new_key["privateKeyData"]
        .as_str()
        .context("no privateKeyData in createServiceAccountKey response")?;

    // privateKeyData is base64-encoded JSON key file
    let key_json_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        private_key_data_b64,
    ).context("base64 decode of privateKeyData")?;

    // 3. Ensure the Secret Manager secret exists (create if needed)
    let secret_resource = format!("projects/{}/secrets/{}", project, secret_name);
    let ensure_url = format!("https://secretmanager.googleapis.com/v1/{}", secret_resource);
    let ensure_resp = http
        .get(&ensure_url)
        .header("Authorization", format!("Bearer {}", token_str))
        .send().await.context("Secret Manager GET secret")?;

    if ensure_resp.status() == reqwest::StatusCode::NOT_FOUND {
        // Create the secret
        let create_secret_url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets?secretId={}",
            project, secret_name
        );
        let cs_resp = http
            .post(&create_secret_url)
            .header("Authorization", format!("Bearer {}", token_str))
            .header("Content-Type", "application/json")
            .json(&json!({ "replication": { "automatic": {} } }))
            .send().await.context("Secret Manager create secret")?;
        if !cs_resp.status().is_success() {
            let body = cs_resp.text().await.unwrap_or_default();
            anyhow::bail!("Secret Manager create secret failed: {}", body);
        }
    }

    // 4. Add new secret version
    let add_version_url = format!(
        "https://secretmanager.googleapis.com/v1/{}:addVersion",
        secret_resource
    );
    let payload_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &key_json_bytes,
    );
    let sv_resp = http
        .post(&add_version_url)
        .header("Authorization", format!("Bearer {}", token_str))
        .header("Content-Type", "application/json")
        .json(&json!({ "payload": { "data": payload_b64 } }))
        .send().await.context("Secret Manager addSecretVersion")?;

    if !sv_resp.status().is_success() {
        let status = sv_resp.status();
        let body = sv_resp.text().await.unwrap_or_default();
        anyhow::bail!("Secret Manager addSecretVersion failed ({}): {}", status, body);
    }

    // 5. Delete old key (retry for transient errors)
    if !old_key_id.is_empty() {
        let delete_url = format!(
            "https://iam.googleapis.com/v1/{}/keys/{}",
            sa_resource, old_key_id
        );
        let mut deleted = false;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
            let del_resp = http
                .delete(&delete_url)
                .header("Authorization", format!("Bearer {}", token_str))
                .send().await.context("GCP deleteServiceAccountKey")?;
            if del_resp.status().is_success() || del_resp.status() == reqwest::StatusCode::NOT_FOUND {
                deleted = true;
                break;
            }
            if attempt == 2 {
                let body = del_resp.text().await.unwrap_or_default();
                eprintln!("[remediation] Warning: deleteServiceAccountKey failed after 3 attempts: {}", body);
            }
        }
        let _ = deleted;
    }

    Ok(new_key_id)
}
