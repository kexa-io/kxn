//! Azure Resource Manager provider.
//!
//! ARM exposes one inventory endpoint and one detail endpoint for every
//! service, so this is a single generic collector rather than one collector per
//! service: `/subscriptions/{id}/resources` lists everything with its type, and
//! each resource's detail is read back through its own id. Adding a service
//! means adding a line to `TYPE_MAP` and, when the rules read fields ARM spells
//! differently, a normalizer in `azure_arm` — no new API client, no new auth.
//!
//! An object is listed in `RESOURCE_TYPES` only once *every* field the rules
//! read for it is produced. A half-normalized object is worse than an absent
//! one: the engine reads a missing property as an empty string, so the rule
//! fails and the resource is reported as violating something it does not.

use std::sync::Arc;

use futures::stream::{self, StreamExt};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::azure_arm;
use crate::error::ProviderError;
use crate::traits::Provider;

/// Objects this provider can serve, fully normalized.
///
/// Deliberately absent for now: `storage_account`, `vm`, `disk` — their
/// normalizers cover only part of what the CIS rules read (blob/queue logging
/// live in the data plane, `storage_profile.os_disk.managed_disk` and
/// `encryption_settings.enabled` are not mapped yet). And `key_vault`, for a
/// sharper reason: ARM does not return `enableSoftDelete` /
/// `enablePurgeProtection` at all on vaults where they were never set, so
/// neither CIS 8.4 nor 8.5 can be answered from ARM data without inventing a
/// verdict. Serving those objects half-done would replace today's silent skip
/// with a false violation, which is worse.
pub(crate) const RESOURCE_TYPES: &[&str] = &[
    "container_registry",
    "log_analytics_workspace",
    "network_watcher",
    "nsg",
];

/// ARM resource type (lowercase) → the object name rules use.
const TYPE_MAP: &[(&str, &str)] = &[
    ("microsoft.containerregistry/registries", "container_registry"),
    ("microsoft.operationalinsights/workspaces", "log_analytics_workspace"),
    ("microsoft.network/networkwatchers", "network_watcher"),
    ("microsoft.network/networksecuritygroups", "nsg"),
];

/// Object name for an ARM type, if kxn maps it.
fn object_for(arm_type: &str) -> Option<&'static str> {
    let lower = arm_type.to_lowercase();
    TYPE_MAP
        .iter()
        .find(|(t, _)| *t == lower)
        .map(|(_, object)| *object)
}

pub struct AzureProvider {
    /// None until resolved: an unset subscription falls back to the first one
    /// the credentials can see.
    subscription: Mutex<Option<String>>,
    /// Detail lookups run in parallel; ARM throttles per subscription, so this
    /// stays modest by default.
    concurrency: usize,
    /// The inventory is one call for the whole subscription — fetched once and
    /// shared by every resource type of a scan.
    inventory: Mutex<Option<Arc<Vec<Value>>>>,
}

impl AzureProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let subscription = crate::config::get_config_or_env(&config, "SUBSCRIPTION_ID", Some("AZURE"))
            .filter(|s| !s.trim().is_empty());
        let concurrency = crate::config::get_config_or_env(&config, "CONCURRENCY", Some("AZURE"))
            .and_then(|c| c.parse().ok())
            .unwrap_or(16);

        Ok(Self {
            subscription: Mutex::new(subscription),
            concurrency,
            inventory: Mutex::new(None),
        })
    }

    async fn subscription_id(&self) -> Result<String, ProviderError> {
        let mut slot = self.subscription.lock().await;
        if let Some(id) = slot.as_ref() {
            return Ok(id.clone());
        }
        let subs = azure_arm::list_subscriptions()
            .await
            .map_err(|e| ProviderError::Api(format!("{}", e)))?;
        let first = subs.into_iter().next().ok_or_else(|| {
            ProviderError::InvalidConfig(
                "no Azure subscription visible with these credentials; set AZURE_SUBSCRIPTION_ID"
                    .to_string(),
            )
        })?;
        tracing::info!(subscription = %first.display_name, "Azure: no subscription configured, using the first visible one");
        *slot = Some(first.subscription_id.clone());
        Ok(first.subscription_id)
    }

    async fn inventory(&self) -> Result<Arc<Vec<Value>>, ProviderError> {
        let mut slot = self.inventory.lock().await;
        if let Some(inv) = slot.as_ref() {
            return Ok(inv.clone());
        }
        let subscription = self.subscription_id().await?;
        let resources = azure_arm::list_resources(&subscription)
            .await
            .map_err(|e| ProviderError::Api(format!("{}", e)))?;
        let inv = Arc::new(resources);
        *slot = Some(inv.clone());
        Ok(inv)
    }

    /// Read back each id in parallel and normalize what comes out. The listing
    /// only carries id/name/type/location/tags; every field a rule reads lives
    /// in the detail payload.
    async fn details(&self, ids: Vec<String>) -> Vec<Value> {
        stream::iter(ids)
            .map(|id| async move {
                match azure_arm::fetch_resource(&id).await {
                    Ok(mut detail) => {
                        azure_arm::normalize_for_rules(&mut detail);
                        Some(detail)
                    }
                    Err(e) => {
                        tracing::warn!(resource = %id, error = %e, "Azure: detail lookup failed");
                        None
                    }
                }
            })
            .buffer_unordered(self.concurrency)
            .filter_map(|r| async move { r })
            .collect()
            .await
    }
}

#[async_trait::async_trait]
impl Provider for AzureProvider {
    fn name(&self) -> &str {
        "azure"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        if !RESOURCE_TYPES.contains(&resource_type) {
            return Err(ProviderError::UnsupportedResourceType(resource_type.to_string()));
        }
        let inventory = self.inventory().await?;
        let ids: Vec<String> = inventory
            .iter()
            .filter(|r| {
                r.get("type")
                    .and_then(|t| t.as_str())
                    .and_then(object_for)
                    == Some(resource_type)
            })
            .filter_map(|r| r.get("id").and_then(|i| i.as_str()).map(String::from))
            .collect();

        Ok(self.details(ids).await)
    }

    /// One listing and one parallel detail pass for every mapped resource,
    /// instead of walking the subscription once per resource type.
    async fn gather_all(&self) -> Result<std::collections::HashMap<String, Vec<Value>>, ProviderError> {
        let inventory = self.inventory().await?;
        let ids: Vec<String> = inventory
            .iter()
            .filter(|r| r.get("type").and_then(|t| t.as_str()).and_then(object_for).is_some())
            .filter_map(|r| r.get("id").and_then(|i| i.as_str()).map(String::from))
            .collect();

        let mut grouped: std::collections::HashMap<String, Vec<Value>> = RESOURCE_TYPES
            .iter()
            .map(|rt| ((*rt).to_string(), Vec::new()))
            .collect();

        for detail in self.details(ids).await {
            if let Some(object) = detail.get("type").and_then(|t| t.as_str()).and_then(object_for) {
                grouped.entry(object.to_string()).or_default().push(detail);
            }
        }
        Ok(grouped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_arm_types_case_insensitively() {
        assert_eq!(
            object_for("Microsoft.ContainerRegistry/registries"),
            Some("container_registry")
        );
        assert_eq!(
            object_for("microsoft.containerregistry/registries"),
            Some("container_registry")
        );
        assert_eq!(
            object_for("Microsoft.OperationalInsights/workspaces"),
            Some("log_analytics_workspace")
        );
    }

    /// An unmapped type is not collected at all — better an object nothing
    /// serves than an object served without the fields its rules read.
    #[test]
    fn unmapped_types_are_not_collected() {
        assert_eq!(object_for("Microsoft.Communication/EmailServices"), None);
        assert_eq!(object_for("Microsoft.KeyVault/vaults"), None);
    }

    /// ARM leaves the Key Vault flags out when they were never set; a
    /// normalizer must not turn that silence into `false`.
    #[test]
    fn an_unanswered_key_vault_flag_stays_absent() {
        let mut r = json!({
            "type": "Microsoft.KeyVault/vaults",
            "properties": { "enableRbacAuthorization": true, "publicNetworkAccess": "Enabled" }
        });
        azure_arm::normalize_for_rules(&mut r);
        assert!(r.get("soft_delete_enabled").is_none());
        assert!(r.get("purge_protection_enabled").is_none());
        assert_eq!(r["enable_rbac"], json!(true));
        assert_eq!(r["public_network_access_enabled"], json!(true));
    }

    #[test]
    fn every_mapped_object_is_declared() {
        for (_, object) in TYPE_MAP {
            assert!(
                RESOURCE_TYPES.contains(object),
                "{object} is mapped but not declared in RESOURCE_TYPES"
            );
        }
    }

    /// The registry payload is the one a real subscription returns; the rules
    /// read booleans while ARM answers "Enabled"/"Disabled".
    #[test]
    fn normalizes_a_container_registry_the_way_rules_read_it() {
        let mut r = json!({
            "id": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/acme",
            "type": "Microsoft.ContainerRegistry/registries",
            "properties": { "adminUserEnabled": true, "publicNetworkAccess": "Enabled" }
        });
        azure_arm::normalize_for_rules(&mut r);
        assert_eq!(r["admin_enabled"], json!(true));
        assert_eq!(r["public_network_access_enabled"], json!(true));

        let mut locked = json!({
            "type": "Microsoft.ContainerRegistry/registries",
            "properties": { "adminUserEnabled": false, "publicNetworkAccess": "Disabled" }
        });
        azure_arm::normalize_for_rules(&mut locked);
        assert_eq!(locked["admin_enabled"], json!(false));
        assert_eq!(locked["public_network_access_enabled"], json!(false));
    }

    #[test]
    fn normalizes_a_log_analytics_workspace() {
        let mut r = json!({
            "type": "Microsoft.OperationalInsights/workspaces",
            "properties": { "retentionInDays": 30 }
        });
        azure_arm::normalize_for_rules(&mut r);
        assert_eq!(r["retention_in_days"], json!(30));
    }
}
