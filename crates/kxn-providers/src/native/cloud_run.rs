use crate::config::{get_config_or_env, require_config};
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::Value;

const RESOURCE_TYPES: &[&str] = &["services", "revisions", "jobs"];

pub struct CloudRunProvider {
    project_id: String,
    region: String,
    client: reqwest::Client,
}

impl CloudRunProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let project_id = require_config(&config, "GCP_PROJECT_ID", Some("GCP"))?;
        let region = get_config_or_env(&config, "GCP_REGION", Some("GCP"))
            .unwrap_or_else(|| "us-central1".into());

        Ok(Self {
            project_id,
            region,
            client: reqwest::Client::new(),
        })
    }

    async fn get_token(&self) -> Result<String, ProviderError> {
        let provider = gcp_auth::provider()
            .await
            .map_err(|e| ProviderError::Connection(format!("GCP auth: {}", e)))?;
        let token = provider
            .token(&["https://www.googleapis.com/auth/cloud-platform"])
            .await
            .map_err(|e| ProviderError::Connection(format!("GCP token: {}", e)))?;
        Ok(token.as_str().to_string())
    }

    async fn api_get(&self, url: &str) -> Result<Value, ProviderError> {
        let token = self.get_token().await?;
        let resp = self.client
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| ProviderError::Query(format!("Cloud Run API: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Query(format!("Cloud Run {} ({}): {}", url, status, text)));
        }

        resp.json().await
            .map_err(|e| ProviderError::Query(format!("Cloud Run parse: {}", e)))
    }

    fn base_url(&self) -> String {
        format!(
            "https://run.googleapis.com/v2/projects/{}/locations/{}",
            self.project_id, self.region
        )
    }
}

#[async_trait::async_trait]
impl Provider for CloudRunProvider {
    fn name(&self) -> &str {
        "cloud_run"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        match resource_type {
            "services" => {
                let resp = self.api_get(&format!("{}/services", self.base_url())).await?;
                Ok(resp.get("services").and_then(|v| v.as_array()).cloned().unwrap_or_default())
            }
            "revisions" => {
                // List all revisions across services
                let svc_resp = self.api_get(&format!("{}/services", self.base_url())).await?;
                let services = svc_resp.get("services").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                let mut all_revisions = Vec::new();
                for svc in &services {
                    if let Some(name) = svc.get("name").and_then(|v| v.as_str()) {
                        if let Ok(rev_resp) = self.api_get(&format!("https://run.googleapis.com/v2/{}/revisions", name)).await {
                            if let Some(revs) = rev_resp.get("revisions").and_then(|v| v.as_array()) {
                                all_revisions.extend(revs.clone());
                            }
                        }
                    }
                }
                Ok(all_revisions)
            }
            "jobs" => {
                let resp = self.api_get(&format!("{}/jobs", self.base_url())).await?;
                Ok(resp.get("jobs").and_then(|v| v.as_array()).cloned().unwrap_or_default())
            }
            _ => Err(ProviderError::UnsupportedResourceType(resource_type.to_string())),
        }
    }
}
