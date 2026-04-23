use anyhow::{Context, Result};
use serde_json::Value;

/// Fetch a resource from Azure Resource Manager REST API.
///
/// `resource_uri` is the ARM path, e.g.:
/// `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}`
///
/// Credentials are read from env: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
pub async fn fetch_resource(resource_uri: &str) -> Result<Value> {
    let token = get_arm_token().await?;
    let api_version = infer_api_version(resource_uri);
    let url = format!(
        "https://management.azure.com{}?api-version={}",
        resource_uri, api_version
    );

    let client = crate::http::shared_client();
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .context("Azure ARM request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Azure ARM GET failed ({}) for {}: {}", status, resource_uri, text);
    }

    resp.json().await.context("Failed to parse Azure ARM response")
}

/// OAuth2 client credentials flow for management.azure.com scope.
async fn get_arm_token() -> Result<String> {
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

    let client = crate::http::shared_client();
    let resp = client
        .post(&token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("scope", "https://management.azure.com/.default"),
        ])
        .send()
        .await
        .context("Azure OAuth2 token request failed")?
        .json::<Value>()
        .await?;

    resp["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .context("no access_token in Azure OAuth response")
}

/// Map an ARM resource URI to its stable API version.
pub fn infer_api_version(resource_uri: &str) -> &'static str {
    let u = resource_uri.to_lowercase();
    if u.contains("microsoft.compute/virtualmachines/") && !u.contains("/extensions") {
        "2023-09-01"
    } else if u.contains("microsoft.compute/virtualmachines") {
        "2023-09-01"
    } else if u.contains("microsoft.compute/disks") {
        "2023-10-02"
    } else if u.contains("microsoft.network/networksecuritygroups") {
        "2023-09-01"
    } else if u.contains("microsoft.network/virtualnetworks") {
        "2023-09-01"
    } else if u.contains("microsoft.network/publicipaddresses") {
        "2023-09-01"
    } else if u.contains("microsoft.network/loadbalancers") {
        "2023-09-01"
    } else if u.contains("microsoft.storage/storageaccounts") {
        "2023-01-01"
    } else if u.contains("microsoft.keyvault/vaults") {
        "2023-07-01"
    } else if u.contains("microsoft.sql/servers/databases") {
        "2023-05-01-preview"
    } else if u.contains("microsoft.sql/servers") {
        "2023-05-01-preview"
    } else if u.contains("microsoft.web/sites") {
        "2023-01-01"
    } else if u.contains("microsoft.containerservice/managedclusters") {
        "2024-01-01"
    } else if u.contains("microsoft.authorization/roleassignments") {
        "2022-04-01"
    } else if u.contains("microsoft.resources/resourcegroups") {
        "2023-07-01"
    } else if u.contains("microsoft.insights") {
        "2023-01-01"
    } else {
        "2021-04-01"
    }
}
