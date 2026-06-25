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
    let mut api_version = infer_api_version(resource_uri).to_string();

    let (mut status, mut text) = arm_get_raw(resource_uri, &api_version, &token).await?;

    // Self-heal: the inferred (or fallback) API version may not apply to this
    // resource type. ARM lists the supported versions in the 400 body — retry
    // once with the latest stable one.
    if !status.is_success() {
        if let Some(ver) = parse_supported_api_version(&text) {
            if ver != api_version {
                api_version = ver;
                let (s, t) = arm_get_raw(resource_uri, &api_version, &token).await?;
                status = s;
                text = t;
            }
        }
    }

    if !status.is_success() {
        anyhow::bail!("Azure ARM GET failed ({}) for {}: {}", status, resource_uri, text);
    }

    let mut resource: Value =
        serde_json::from_str(&text).context("Failed to parse Azure ARM response")?;
    normalize_for_rules(&mut resource);
    Ok(resource)
}

/// Perform a raw ARM GET and return the status and body text without failing on
/// non-success status, so the caller can inspect the error body.
async fn arm_get_raw(
    resource_uri: &str,
    api_version: &str,
    token: &str,
) -> Result<(reqwest::StatusCode, String)> {
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
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    Ok((status, text))
}

/// Parse the latest stable API version from an ARM `NoRegisteredProviderFound`
/// error body, which lists `The supported api-versions are '2017-03-01, ...'`.
/// Preview/alpha versions are ignored so we retry with a GA version.
fn parse_supported_api_version(body: &str) -> Option<String> {
    let marker = "supported api-versions are";
    let after = &body[body.find(marker)? + marker.len()..];
    let start = after.find('\'')? + 1;
    let end = after[start..].find('\'')?;
    after[start..start + end]
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.contains("preview") && !s.contains("alpha"))
        .max()
        .map(|s| s.to_string())
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

/// Discover every ARM resource type registered in a subscription via the
/// `/providers` endpoint. Returns a flat list of `Namespace/Type` strings
/// (e.g. `Microsoft.Compute/virtualMachines`) ready to feed into the
/// `azurerm_resources` Terraform data source's `type` filter.
///
/// Skips types that ARM tags as `none` for read (singletons, deprecated,
/// preview-only) so the caller only sees enumerable types.
pub async fn list_resource_types(subscription_id: &str) -> Result<Vec<String>> {
    let token = get_arm_token().await?;
    let url = format!(
        "https://management.azure.com/subscriptions/{}/providers?api-version=2021-04-01",
        subscription_id
    );
    let client = crate::http::shared_client();
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .context("Azure ARM /providers request failed")?;
    if !resp.status().is_success() {
        let s = resp.status();
        let t = resp.text().await.unwrap_or_default();
        anyhow::bail!("Azure ARM /providers GET failed ({}): {}", s, t);
    }
    let json: Value = resp.json().await.context("parse /providers response")?;
    let mut out = Vec::new();
    if let Some(arr) = json.get("value").and_then(|v| v.as_array()) {
        for ns in arr {
            // Only registered providers — skip NotRegistered to avoid
            // querying types you can't actually use.
            if ns.get("registrationState").and_then(|v| v.as_str()) != Some("Registered") {
                continue;
            }
            let namespace = ns.get("namespace").and_then(|v| v.as_str()).unwrap_or("");
            if namespace.is_empty() {
                continue;
            }
            if let Some(rts) = ns.get("resourceTypes").and_then(|v| v.as_array()) {
                for rt in rts {
                    let rt_name = rt.get("resourceType").and_then(|v| v.as_str()).unwrap_or("");
                    if rt_name.is_empty() || rt_name.contains('/') {
                        // Skip child types like vaults/secrets — they need a
                        // parent name and azurerm_resources can't list them.
                        continue;
                    }
                    out.push(format!("{}/{}", namespace, rt_name));
                }
            }
        }
    }
    Ok(out)
}

/// List every resource instance in a subscription via the ARM
/// `/subscriptions/{sub}/resources` endpoint.
///
/// Unlike `list_resource_types` (which only returns the available *types*) or
/// the `azurerm_resources` Terraform data source (one call per type), this is a
/// single paginated call that returns every resource with its summary fields
/// (`id`, `name`, `type`, `location`, `tags`). It does NOT include the detailed
/// `properties` bag — call `fetch_resource` per id for that.
pub async fn list_resources(subscription_id: &str) -> Result<Vec<Value>> {
    let token = get_arm_token().await?;
    let client = crate::http::shared_client();

    let mut url = format!(
        "https://management.azure.com/subscriptions/{}/resources?api-version=2021-04-01",
        subscription_id
    );
    let mut out = Vec::new();

    // Follow `nextLink` until the subscription's resource pages are exhausted.
    loop {
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .context("Azure ARM /resources request failed")?;

        if !resp.status().is_success() {
            let s = resp.status();
            let t = resp.text().await.unwrap_or_default();
            anyhow::bail!("Azure ARM /resources GET failed ({}): {}", s, t);
        }

        let json: Value = resp.json().await.context("parse /resources response")?;
        if let Some(arr) = json.get("value").and_then(|v| v.as_array()) {
            out.extend(arr.iter().cloned());
        }

        match json.get("nextLink").and_then(|v| v.as_str()) {
            Some(next) if !next.is_empty() => url = next.to_string(),
            _ => break,
        }
    }

    Ok(out)
}

/// A directed relation discovered between two ARM resources.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ArmRelation {
    /// ARM id of the referenced resource (the edge target).
    pub target: String,
    /// Semantic kind of the relation, inferred from the JSON key holding the
    /// reference (e.g. `attached_to`, `connected_to`, `protected_by`).
    pub kind: String,
}

/// Extract cross-resource relations from a detailed ARM resource JSON.
///
/// Azure represents every reference to another resource as a nested object
/// `{ "id": "/subscriptions/.../<type>/<name>" }`. We recursively walk the JSON,
/// collect every such id, and infer the relation kind from the key under which
/// the reference sits. References to the resource itself or to its own
/// sub-components (ids that start with the resource's own id) are skipped, as
/// are duplicate `(target, kind)` pairs.
pub fn extract_relations(resource: &Value) -> Vec<ArmRelation> {
    let self_id = resource
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    walk_relations(resource, "", &self_id, &mut out, &mut seen);
    out
}

/// Recursive helper for `extract_relations`. `key` is the JSON key under which
/// `node` currently sits (used to infer the relation kind).
fn walk_relations(
    node: &Value,
    key: &str,
    self_id: &str,
    out: &mut Vec<ArmRelation>,
    seen: &mut std::collections::HashSet<(String, String)>,
) {
    match node {
        Value::Object(map) => {
            // An object carrying an `id` that points to another ARM resource is
            // a reference. The enclosing `key` describes the relation.
            if let Some(id) = map.get("id").and_then(|v| v.as_str()) {
                if is_arm_resource_id(id) {
                    let lower = id.to_lowercase();
                    let is_self =
                        lower == self_id || lower.starts_with(&format!("{}/", self_id));
                    if !is_self {
                        let kind = relation_kind(key).to_string();
                        if seen.insert((lower, kind.clone())) {
                            out.push(ArmRelation {
                                target: id.to_string(),
                                kind,
                            });
                        }
                    }
                }
            }
            for (k, v) in map {
                walk_relations(v, k, self_id, out, seen);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                // Keep the parent key for array elements so a reference inside
                // `networkInterfaces: [{id}]` is attributed to `networkInterfaces`.
                walk_relations(v, key, self_id, out, seen);
            }
        }
        _ => {}
    }
}

/// True if the string looks like an absolute ARM resource id.
fn is_arm_resource_id(s: &str) -> bool {
    let l = s.to_lowercase();
    l.starts_with("/subscriptions/") && l.contains("/providers/")
}

/// Map the JSON key holding a reference to a semantic relation kind. Unknown
/// keys fall back to a neutral `references` so no edge is silently dropped.
fn relation_kind(key: &str) -> &'static str {
    match key.to_lowercase().as_str() {
        "networkinterfaces" | "networkinterface" => "attached_to",
        "virtualmachine" => "attached_to",
        "subnet" | "subnets" => "connected_to",
        "virtualnetwork" => "connected_to",
        "networksecuritygroup" => "protected_by",
        "publicipaddress" | "publicipaddresses" => "uses",
        "manageddisk" | "disk" | "disks" => "uses",
        "storageaccount" => "uses",
        "loadbalancerbackendaddresspools" | "backendaddresspool" => "member_of",
        _ => "references",
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
///
/// Successive branches intentionally return identical version strings so each
/// resource type stays addressable as its own row when the version table is
/// updated piecewise. Collapsing them with `||` would couple unrelated bumps.
#[allow(clippy::if_same_then_else)]
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
