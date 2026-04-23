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

    let mut resource: Value = resp.json().await.context("Failed to parse Azure ARM response")?;
    normalize_for_rules(&mut resource);
    Ok(resource)
}

/// Inject Terraform-style flat fields alongside the ARM JSON so that CIS rules
/// written for the Terraform provider can evaluate ARM REST API responses.
pub fn normalize_for_rules(resource: &mut Value) {
    let arm_type = resource
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();

    if arm_type.contains("microsoft.storage/storageaccounts") {
        normalize_storage_account(resource);
    } else if arm_type.contains("microsoft.keyvault/vaults") {
        normalize_key_vault(resource);
    } else if arm_type.contains("microsoft.network/networksecuritygroups") {
        normalize_nsg(resource);
    } else if arm_type.contains("microsoft.compute/virtualmachines") {
        normalize_vm(resource);
    } else if arm_type.contains("microsoft.compute/disks") {
        normalize_disk(resource);
    }
}

fn normalize_storage_account(r: &mut Value) {
    let p = r.get("properties").cloned().unwrap_or(Value::Null);

    set(r, "enable_https_traffic_only",
        p.get("supportsHttpsTrafficOnly").cloned().unwrap_or(Value::Bool(false)));
    set(r, "allow_blob_public_access",
        p.get("allowBlobPublicAccess").cloned().unwrap_or(Value::Bool(true)));
    set(r, "min_tls_version",
        p.get("minimumTlsVersion").cloned().unwrap_or(Value::Null));
    set(r, "infrastructure_encryption_enabled",
        p.pointer("/encryption/requireInfrastructureEncryption")
            .cloned().unwrap_or(Value::Bool(false)));
    // network_rules.default_action
    let default_action = p
        .pointer("/networkAcls/defaultAction")
        .and_then(|v| v.as_str())
        .unwrap_or("Allow")
        .to_string();
    if let Some(obj) = r.as_object_mut() {
        obj.entry("network_rules")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .unwrap()
            .insert("default_action".to_string(), Value::String(default_action));
    }
}

fn normalize_key_vault(r: &mut Value) {
    let p = r.get("properties").cloned().unwrap_or(Value::Null);

    set(r, "soft_delete_enabled",
        p.get("enableSoftDelete").cloned().unwrap_or(Value::Bool(false)));
    set(r, "purge_protection_enabled",
        p.get("enablePurgeProtection").cloned().unwrap_or(Value::Bool(false)));
    set(r, "enable_rbac",
        p.get("enableRbacAuthorization").cloned().unwrap_or(Value::Bool(false)));
    set(r, "public_network_access_enabled",
        Value::Bool(p.get("publicNetworkAccess").and_then(|v| v.as_str()) != Some("Disabled")));
}

fn normalize_nsg(r: &mut Value) {
    // Map properties.securityRules → security_rules array
    if let Some(rules) = r.pointer("/properties/securityRules") {
        if let Value::Array(rules_arr) = rules.clone() {
            let mapped: Vec<Value> = rules_arr.iter().map(|rule| {
                let props = rule.get("properties").cloned().unwrap_or(Value::Null);
                serde_json::json!({
                    "name": rule.get("name"),
                    "access": props.get("access"),
                    "direction": props.get("direction"),
                    "source_address_prefix": props.get("sourceAddressPrefix"),
                    "destination_port_range": props.get("destinationPortRange"),
                    "protocol": props.get("protocol"),
                    "priority": props.get("priority"),
                })
            }).collect();
            set(r, "security_rules", Value::Array(mapped));
        }
    }
}

fn normalize_vm(r: &mut Value) {
    set(r, "extensions",
        r.pointer("/properties/extensionProfiles").cloned().unwrap_or(Value::Array(vec![])));
    // managed disk: present if storageProfile.osDisk.managedDisk is not null
    let has_managed = r.pointer("/properties/storageProfile/osDisk/managedDisk").is_some();
    if let Some(obj) = r.as_object_mut() {
        obj.entry("storage_profile")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .unwrap()
            .entry("os_disk")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .unwrap()
            .insert("managed_disk".to_string(), Value::Bool(has_managed));
    }
}

fn normalize_disk(r: &mut Value) {
    set(r, "managed_by",
        r.get("managedBy").cloned().unwrap_or(Value::String(String::new())));
    let enc_enabled = r
        .pointer("/properties/encryptionSettingsCollection/enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if let Some(obj) = r.as_object_mut() {
        obj.entry("encryption_settings")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .unwrap()
            .insert("enabled".to_string(), Value::Bool(enc_enabled));
    }
}

fn set(resource: &mut Value, key: &str, value: Value) {
    if let Some(obj) = resource.as_object_mut() {
        obj.insert(key.to_string(), value);
    }
}

/// OAuth2 client credentials flow for management.azure.com scope.
/// If AZURE_ACCESS_TOKEN is set (e.g. from `az account get-access-token`), it is used directly.
async fn get_arm_token() -> Result<String> {
    if let Ok(token) = std::env::var("AZURE_ACCESS_TOKEN") {
        return Ok(token);
    }

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
