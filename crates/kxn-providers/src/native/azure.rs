//! Native Azure Resource Manager provider.
//!
//! The `hashicorp/azurerm` Terraform provider pins API versions that current
//! Azure subscriptions reject (400 `InvalidApiVersionParameter`), so gathering
//! per-resource-type through it fails. This provider talks to the ARM REST API
//! directly via [`crate::azure_arm`], which self-heals the API version and
//! normalizes each resource with Terraform-style flat fields so rules written
//! for the `azurerm_*` types still match.
//!
//! Credentials come from `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` /
//! `AZURE_TENANT_ID` (or `AZURE_ACCESS_TOKEN`); the subscription from
//! `AZURE_SUBSCRIPTION_ID` / `ARM_SUBSCRIPTION_ID` or `azure://<sub-id>`.

use crate::azure_arm;
use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::Value;

/// Terraform resource type -> ARM `Namespace/Type`. Several Terraform types can
/// map to the same ARM type (e.g. the VM variants) so rules written against any
/// of them still receive the resources.
const TYPE_MAP: &[(&str, &str)] = &[
    ("azurerm_storage_account", "Microsoft.Storage/storageAccounts"),
    ("azurerm_key_vault", "Microsoft.KeyVault/vaults"),
    ("azurerm_network_security_group", "Microsoft.Network/networkSecurityGroups"),
    ("azurerm_virtual_network", "Microsoft.Network/virtualNetworks"),
    ("azurerm_public_ip", "Microsoft.Network/publicIPAddresses"),
    ("azurerm_lb", "Microsoft.Network/loadBalancers"),
    ("azurerm_managed_disk", "Microsoft.Compute/disks"),
    ("azurerm_virtual_machine", "Microsoft.Compute/virtualMachines"),
    ("azurerm_linux_virtual_machine", "Microsoft.Compute/virtualMachines"),
    ("azurerm_windows_virtual_machine", "Microsoft.Compute/virtualMachines"),
    ("azurerm_network_interface", "Microsoft.Network/networkInterfaces"),
    ("azurerm_mssql_server", "Microsoft.Sql/servers"),
    ("azurerm_kubernetes_cluster", "Microsoft.ContainerService/managedClusters"),
    ("azurerm_container_registry", "Microsoft.ContainerRegistry/registries"),
    ("azurerm_linux_web_app", "Microsoft.Web/sites"),
    ("azurerm_app_service", "Microsoft.Web/sites"),
    ("azurerm_cosmosdb_account", "Microsoft.DocumentDB/databaseAccounts"),
    ("azurerm_redis_cache", "Microsoft.Cache/Redis"),
];

pub struct AzureProvider {
    subscription_id: String,
}

impl AzureProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let subscription_id = get_config_or_env(&config, "SUBSCRIPTION_ID", Some("AZURE"))
            .or_else(|| std::env::var("ARM_SUBSCRIPTION_ID").ok())
            // `azure://<sub-id>` lands in config as the bare address string.
            .or_else(|| match &config {
                Value::String(s) if !s.is_empty() => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                ProviderError::InvalidConfig(
                    "Azure subscription not set — use azure://<subscription-id> or \
                     AZURE_SUBSCRIPTION_ID / ARM_SUBSCRIPTION_ID env"
                        .into(),
                )
            })?;
        Ok(Self { subscription_id })
    }

    fn arm_type(resource_type: &str) -> Option<&'static str> {
        TYPE_MAP
            .iter()
            .find(|(tf, _)| *tf == resource_type)
            .map(|(_, arm)| *arm)
    }
}

#[async_trait::async_trait]
impl Provider for AzureProvider {
    fn name(&self) -> &str {
        "azure"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(TYPE_MAP.iter().map(|(tf, _)| tf.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        let arm_type = Self::arm_type(resource_type).ok_or_else(|| {
            ProviderError::NotFound(format!(
                "Unknown resource type '{}' for azure provider",
                resource_type
            ))
        })?;

        // One paginated ARM /resources call lists every instance in the
        // subscription with its type; filter to the requested ARM type, then
        // fetch each one's full (normalized) representation.
        let all = azure_arm::list_resources(&self.subscription_id)
            .await
            .map_err(|e| ProviderError::Connection(format!("ARM list_resources failed: {}", e)))?;

        let mut out = Vec::new();
        for summary in all {
            let ty = summary.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if !ty.eq_ignore_ascii_case(arm_type) {
                continue;
            }
            let id = match summary.get("id").and_then(|v| v.as_str()) {
                Some(id) if !id.is_empty() => id,
                _ => continue,
            };
            match azure_arm::fetch_resource(id).await {
                Ok(full) => out.push(full),
                Err(e) => {
                    tracing::warn!(id = %id, error = %e, "azure: fetch_resource failed");
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_terraform_types() {
        assert_eq!(
            AzureProvider::arm_type("azurerm_storage_account"),
            Some("Microsoft.Storage/storageAccounts")
        );
        assert_eq!(
            AzureProvider::arm_type("azurerm_managed_disk"),
            Some("Microsoft.Compute/disks")
        );
        assert_eq!(AzureProvider::arm_type("nope"), None);
    }

    #[test]
    fn new_reads_subscription_from_config() {
        let cfg = serde_json::json!({ "subscription_id": "abc-123" });
        let p = AzureProvider::new(cfg).unwrap();
        assert_eq!(p.subscription_id, "abc-123");
    }
}
