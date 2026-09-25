use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use anyhow::Context;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

pub(crate) const RESOURCE_TYPES: &[&str] =
    &["container_cluster", "service_account_keys", "storage_bucket"];
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


    /// GET on any Google API. Every service has its own host and its own
    /// listing shape, so unlike Azure there is no single inventory endpoint —
    /// Cloud Asset Inventory would be that endpoint, but it has to be enabled
    /// on the project first, so it cannot be the only path.
    async fn get_json(&self, token: &str, url: &str) -> Result<Value, ProviderError> {
        let resp = self
            .client
            .get(url)
            .header("Authorization", format!("Bearer {}", token))
            // User credentials (`gcloud auth application-default login`) need a
            // billing project for several APIs; service accounts carry their own.
            .header("x-goog-user-project", &self.project)
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("GET {} failed: {}", url, e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Query(format!("GET {} ({}): {}", url, status, text)));
        }
        resp.json::<Value>()
            .await
            .map_err(|e| ProviderError::Query(format!("parse {}: {}", url, e)))
    }

    /// Cloud Storage buckets, normalized to the names the rules read.
    ///
    /// GCS omits `versioning` entirely on a bucket where it was never turned
    /// on, and object versioning is off by default — so absent means disabled
    /// here, unlike an API that simply declines to answer.
    async fn gather_storage_buckets(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b?project={}",
            self.project
        );
        let resp = self.get_json(&token, &url).await?;

        Ok(resp
            .get("items")
            .and_then(|i| i.as_array())
            .map(|items| items.iter().map(normalize_bucket).collect())
            .unwrap_or_default())
    }

    /// GKE clusters, normalized to the Terraform-shaped names the rules read —
    /// including its single-element-list convention (`network_policy.0.enabled`),
    /// which is why nested blocks are wrapped in an array of one.
    ///
    /// GCP omits false booleans on the wire (proto3), so a missing flag here
    /// means disabled; that is the API's documented encoding, not a refusal to
    /// answer.
    async fn gather_container_clusters(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let url = format!(
            "https://container.googleapis.com/v1/projects/{}/locations/-/clusters",
            self.project
        );
        let resp = self.get_json(&token, &url).await?;

        Ok(resp
            .get("clusters")
            .and_then(|c| c.as_array())
            .map(|clusters| clusters.iter().map(normalize_cluster).collect())
            .unwrap_or_default())
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
            "container_cluster" => self.gather_container_clusters().await,
            "service_account_keys" => self.gather_service_account_keys().await,
            "storage_bucket" => self.gather_storage_buckets().await,
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

/// Map a Cloud Storage bucket to the object the rules describe.
fn normalize_bucket(b: &Value) -> Value {
    let iam = b.get("iamConfiguration").cloned().unwrap_or(Value::Null);
    let mut out = json!({
        "name": b.get("name"),
        "location": b.get("location"),
        "storage_class": b.get("storageClass"),
        "uniform_bucket_level_access": iam
            .pointer("/uniformBucketLevelAccess/enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        // GCS omits `versioning` on a bucket where it was never turned on, and
        // object versioning is off by default — absent means disabled here.
        "versioning_enabled": b
            .pointer("/versioning/enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    });
    if let Some(pap) = iam.get("publicAccessPrevention") {
        out["public_access_prevention"] = pap.clone();
    }
    out
}

/// Map a GKE cluster to the object the rules describe.
///
/// `node_config.0.management.0.auto_upgrade` is an aggregate: GKE carries
/// auto-upgrade per node pool, the rule asks one question of the cluster, so it
/// holds only when every pool has it. A cluster with no pool at all answers
/// nothing rather than inventing a `true`.
fn normalize_cluster(c: &Value) -> Value {
    let mut out = json!({
        "name": c.get("name"),
        "location": c.get("location"),
        "status": c.get("status"),
        "logging_service": c.get("loggingService"),
        "monitoring_service": c.get("monitoringService"),
        "enable_legacy_abac": c.pointer("/legacyAbac/enabled").and_then(|v| v.as_bool()).unwrap_or(false),
        "network_policy": [{
            "enabled": c.pointer("/networkPolicy/enabled").and_then(|v| v.as_bool()).unwrap_or(false)
        }],
        "private_cluster_config": [{
            "enable_private_nodes": c
                .pointer("/privateClusterConfig/enablePrivateNodes")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        }],
        "master_authorized_networks_config": [{
            "cidr_blocks": c
                .pointer("/masterAuthorizedNetworksConfig/cidrBlocks")
                .cloned()
                .unwrap_or_else(|| Value::Array(vec![]))
        }],
    });

    if let Some(pools) = c.get("nodePools").and_then(|p| p.as_array()) {
        if !pools.is_empty() {
            let all_auto_upgrade = pools.iter().all(|p| {
                p.pointer("/management/autoUpgrade")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            });
            out["node_config"] = json!([{ "management": [{ "auto_upgrade": all_auto_upgrade }] }]);
        }
    }

    if let Some(psp) = c.pointer("/podSecurityPolicyConfig/enabled").and_then(|v| v.as_bool()) {
        out["pod_security_policy_config"] = json!([{ "enabled": psp }]);
    }

    out
}

#[cfg(test)]
mod normalize_tests {
    use super::*;

    /// Payload shapes taken from a live project rather than from docs.
    #[test]
    fn normalizes_a_bucket() {
        let b = json!({
            "name": "rtk-cloud-backups-prd",
            "location": "EU",
            "storageClass": "STANDARD",
            "iamConfiguration": {
                "uniformBucketLevelAccess": { "enabled": true },
                "publicAccessPrevention": "enforced"
            }
        });
        let out = normalize_bucket(&b);
        assert_eq!(out["uniform_bucket_level_access"], json!(true));
        assert_eq!(out["public_access_prevention"], json!("enforced"));
        // No `versioning` block at all: GCS omits it when never enabled.
        assert_eq!(out["versioning_enabled"], json!(false));
    }

    #[test]
    fn a_bucket_without_public_access_prevention_does_not_get_an_invented_one() {
        let out = normalize_bucket(&json!({ "name": "b", "iamConfiguration": {} }));
        assert!(out.get("public_access_prevention").is_none());
    }

    /// The rules were written against Terraform's schema, which represents a
    /// nested block as a one-element list — hence `network_policy.0.enabled`.
    #[test]
    fn wraps_cluster_blocks_the_way_the_rules_index_them() {
        let c = json!({
            "name": "rtk-bench",
            "location": "europe-west9-a",
            "status": "RUNNING",
            "loggingService": "logging.googleapis.com/kubernetes",
            "monitoringService": "monitoring.googleapis.com/kubernetes",
            "legacyAbac": {},
            "networkPolicy": null,
            "privateClusterConfig": { "publicEndpoint": "34.155.119.190" },
            "masterAuthorizedNetworksConfig": {}
        });
        let out = normalize_cluster(&c);
        assert_eq!(out["network_policy"][0]["enabled"], json!(false));
        assert_eq!(out["private_cluster_config"][0]["enable_private_nodes"], json!(false));
        assert_eq!(out["master_authorized_networks_config"][0]["cidr_blocks"], json!([]));
        assert_eq!(out["enable_legacy_abac"], json!(false));
        assert_eq!(out["logging_service"], json!("logging.googleapis.com/kubernetes"));
    }

    /// Auto-upgrade is per node pool but the rule asks the cluster, so it only
    /// holds when every pool has it.
    #[test]
    fn node_auto_upgrade_holds_only_when_every_pool_has_it() {
        let with = |pools: Value| {
            let c = json!({ "name": "c", "nodePools": pools });
            normalize_cluster(&c)["node_config"][0]["management"][0]["auto_upgrade"].clone()
        };
        assert_eq!(with(json!([{ "management": { "autoUpgrade": true } }])), json!(true));
        assert_eq!(
            with(json!([
                { "management": { "autoUpgrade": true } },
                { "management": { "autoUpgrade": false } }
            ])),
            json!(false)
        );
        // A pool that does not say: GCP omits false booleans on the wire.
        assert_eq!(with(json!([{ "management": {} }])), json!(false));
    }

    #[test]
    fn a_cluster_without_node_pools_says_nothing_about_auto_upgrade() {
        let out = normalize_cluster(&json!({ "name": "c" }));
        assert!(out.get("node_config").is_none());
    }
}
