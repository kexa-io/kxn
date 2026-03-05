use crate::config::{get_config_or_env, require_config};
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::Value;

const RESOURCE_TYPES: &[&str] = &["webapps", "app_service_plans", "webapp_config"];

pub struct AzureWebAppProvider {
    subscription_id: String,
    resource_group: Option<String>,
    client: reqwest::Client,
}

impl AzureWebAppProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let subscription_id = require_config(&config, "AZURE_SUBSCRIPTION_ID", Some("AZURE"))?;
        let resource_group = get_config_or_env(&config, "AZURE_RESOURCE_GROUP", Some("AZURE"));

        Ok(Self {
            subscription_id,
            resource_group,
            client: reqwest::Client::new(),
        })
    }

    async fn get_token(&self) -> Result<String, ProviderError> {
        // Use Azure CLI token or AZURE_ACCESS_TOKEN env var
        if let Ok(token) = std::env::var("AZURE_ACCESS_TOKEN") {
            return Ok(token);
        }

        // Try az cli
        let output = tokio::process::Command::new("az")
            .args(["account", "get-access-token", "--query", "accessToken", "-o", "tsv"])
            .output()
            .await
            .map_err(|e| ProviderError::Connection(format!("az CLI: {}", e)))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(ProviderError::Connection("Azure auth failed: set AZURE_ACCESS_TOKEN or install az CLI".into()))
        }
    }

    async fn api_get(&self, url: &str) -> Result<Value, ProviderError> {
        let token = self.get_token().await?;
        let resp = self.client
            .get(url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| ProviderError::Query(format!("Azure API: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Query(format!("Azure {} ({}): {}", url, status, text)));
        }

        resp.json().await
            .map_err(|e| ProviderError::Query(format!("Azure parse: {}", e)))
    }

    fn base_url(&self) -> String {
        match &self.resource_group {
            Some(rg) => format!(
                "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Web",
                self.subscription_id, rg
            ),
            None => format!(
                "https://management.azure.com/subscriptions/{}/providers/Microsoft.Web",
                self.subscription_id
            ),
        }
    }
}

#[async_trait::async_trait]
impl Provider for AzureWebAppProvider {
    fn name(&self) -> &str {
        "azure_webapp"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        let api_version = "api-version=2023-12-01";
        match resource_type {
            "webapps" => {
                let url = format!("{}/sites?{}", self.base_url(), api_version);
                let resp = self.api_get(&url).await?;
                Ok(resp.get("value").and_then(|v| v.as_array()).cloned().unwrap_or_default())
            }
            "app_service_plans" => {
                let url = format!("{}/serverfarms?{}", self.base_url(), api_version);
                let resp = self.api_get(&url).await?;
                Ok(resp.get("value").and_then(|v| v.as_array()).cloned().unwrap_or_default())
            }
            "webapp_config" => {
                // First get all webapps, then get config for each
                let sites_url = format!("{}/sites?{}", self.base_url(), api_version);
                let sites_resp = self.api_get(&sites_url).await?;
                let sites = sites_resp.get("value").and_then(|v| v.as_array()).cloned().unwrap_or_default();

                let mut configs = Vec::new();
                for site in &sites {
                    if let Some(id) = site.get("id").and_then(|v| v.as_str()) {
                        let config_url = format!(
                            "https://management.azure.com{}/config/web?{}",
                            id, api_version
                        );
                        if let Ok(config) = self.api_get(&config_url).await {
                            configs.push(config);
                        }
                    }
                }
                Ok(configs)
            }
            _ => Err(ProviderError::UnsupportedResourceType(resource_type.to_string())),
        }
    }
}
