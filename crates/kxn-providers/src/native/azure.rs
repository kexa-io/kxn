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
/// Deliberately absent: `storage_account`, because CIS 3.9 and 3.10 read
/// `blob_properties.0.logging.0.read` / `queue_properties.0.logging.0.read` —
/// Storage Analytics logging, which lives in the data plane behind an account
/// key and which no ARM call answers. `vm` and `disk`, whose rules read
/// `storage_profile.os_disk.managed_disk` and `encryption_settings.enabled`
/// against a `disk` object nothing populates yet. And `key_vault`, for a
/// sharper reason: ARM does not return `enableSoftDelete` /
/// `enablePurgeProtection` at all on vaults where they were never set, so
/// neither CIS 8.4 nor 8.5 can be answered from ARM data without inventing a
/// verdict. Serving those objects half-done would replace today's silent skip
/// with a false violation, which is worse.
///
/// `postgresql_flexible_server` is absent for the same reason: CIS 4.3.8 reads
/// `infrastructure_encryption_enabled`, a Single Server property. The flexible
/// server ARM contract has no equivalent — its `ServerProperties` carries no
/// `infrastructureEncryption` — so half of the object's rules cannot be
/// answered. Its sibling `mysql_flexible_server` only needs SSL enforcement,
/// which the engine parameter does answer, so that one is served.
pub(crate) const RESOURCE_TYPES: &[&str] = &[
    "container_registry",
    "log_analytics_workspace",
    "monitor_diagnostic_setting",
    "mysql_flexible_server",
    "network_watcher",
    "nsg",
    "security_center_subscription_pricing",
    "virtual_machine",
];

/// ARM resource type (lowercase) → the object name rules use.
const TYPE_MAP: &[(&str, &str)] = &[
    ("microsoft.containerregistry/registries", "container_registry"),
    ("microsoft.operationalinsights/workspaces", "log_analytics_workspace"),
    ("microsoft.network/networkwatchers", "network_watcher"),
    ("microsoft.network/networksecuritygroups", "nsg"),
    ("microsoft.dbformysql/flexibleservers", "mysql_flexible_server"),
    ("microsoft.compute/virtualmachines", "virtual_machine"),
];

/// Objects that are not resources of the subscription inventory and are read by
/// their own endpoint instead of the `/resources` walk.
const SUBSCRIPTION_SCOPED: &[&str] = &[
    "security_center_subscription_pricing",
    "monitor_diagnostic_setting",
];

/// Object name for an ARM type, if kxn maps it.
fn object_for(arm_type: &str) -> Option<&'static str> {
    let lower = arm_type.to_lowercase();
    TYPE_MAP
        .iter()
        .find(|(t, _)| *t == lower)
        .map(|(_, object)| *object)
}

/// A Defender plan Azure marks deprecated is superseded by another one, which
/// is evaluated on its own row (`KubernetesService` by `Containers`, for
/// instance). Its tier is frozen, so reporting it would be a violation nobody
/// can act on.
fn is_deprecated_plan(pricing: &Value) -> bool {
    pricing.pointer("/properties/deprecated").and_then(|d| d.as_bool()) == Some(true)
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
                        self.complete(&id, &mut detail).await.then_some(detail)
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

    /// Fill the fields the resource read does not carry, and say whether the
    /// resource can be served at all.
    ///
    /// A resource reaching the engine without one of the properties its rules
    /// read is worse than a resource nobody collected: the missing property is
    /// read as an empty string and reported as a violation. So a failed
    /// follow-up call drops the resource rather than leaving a hole in it.
    async fn complete(&self, id: &str, detail: &mut Value) -> bool {
        match detail.get("type").and_then(|t| t.as_str()).and_then(object_for) {
            Some("virtual_machine") => match azure_arm::list_vm_extensions(id).await {
                Ok(extensions) => {
                    azure_arm::set_vm_extensions(detail, &extensions);
                    true
                }
                Err(e) => {
                    tracing::warn!(resource = %id, error = %e, "Azure: VM extension list failed, skipping the VM");
                    false
                }
            },
            Some("mysql_flexible_server") => {
                match azure_arm::fetch_server_configuration(id, "require_secure_transport").await {
                    Ok(configuration) => {
                        let mapped = azure_arm::set_mysql_ssl_enforcement(detail, &configuration);
                        if !mapped {
                            tracing::warn!(resource = %id, "Azure: require_secure_transport carried no value, skipping the server");
                        }
                        mapped
                    }
                    Err(e) => {
                        tracing::warn!(resource = %id, error = %e, "Azure: server parameter read failed, skipping the server");
                        false
                    }
                }
            }
            _ => true,
        }
    }

    /// Defender for Cloud plans of the subscription.
    async fn security_pricings(&self) -> Result<Vec<Value>, ProviderError> {
        let subscription = self.subscription_id().await?;
        let pricings = azure_arm::list_security_pricings(&subscription)
            .await
            .map_err(|e| ProviderError::Api(format!("{}", e)))?;
        Ok(pricings
            .into_iter()
            .filter(|p| !is_deprecated_plan(p))
            .filter_map(|mut p| azure_arm::normalize_security_pricing(&mut p).then_some(p))
            .collect())
    }

    /// Diagnostic settings, which hang off a scope rather than existing as
    /// resources of their own.
    ///
    /// Scopes read: the subscription — that one is what CIS 5.1 is actually
    /// about, the activity log export — plus the resources kxn already reads
    /// one by one. Sweeping every resource of the subscription instead would
    /// cost one ARM call per resource while only ever judging settings that
    /// already exist: a resource with no setting returns an empty list and
    /// produces no object, so the absence CIS cares about stays unreported
    /// either way. The calls share the provider's concurrency bound.
    async fn diagnostic_settings(&self) -> Result<Vec<Value>, ProviderError> {
        let subscription = self.subscription_id().await?;
        let inventory = self.inventory().await?;

        let mut scopes = vec![format!("/subscriptions/{}", subscription)];
        scopes.extend(
            inventory
                .iter()
                .filter(|r| r.get("type").and_then(|t| t.as_str()).and_then(object_for).is_some())
                .filter_map(|r| r.get("id").and_then(|i| i.as_str()).map(String::from)),
        );

        let settings: Vec<Value> = stream::iter(scopes)
            .map(|scope| async move {
                match azure_arm::list_diagnostic_settings(&scope).await {
                    Ok(settings) => settings,
                    // A type that cannot carry diagnostic settings at all
                    // (network watchers, for one) is answered with a 400
                    // instead of an empty list. That is an answer, and warning
                    // about it on every scan would train the reader to ignore
                    // the warnings that do mean something.
                    Err(e) if e.to_string().contains("ResourceTypeNotSupported") => {
                        tracing::debug!(scope = %scope, "Azure: type carries no diagnostic settings");
                        Vec::new()
                    }
                    Err(e) => {
                        tracing::warn!(scope = %scope, error = %e, "Azure: diagnostic settings lookup failed");
                        Vec::new()
                    }
                }
            })
            .buffer_unordered(self.concurrency)
            .flat_map(stream::iter)
            .collect()
            .await;

        Ok(settings
            .into_iter()
            // A setting carries the parent's `type`, not its own, so running it
            // through the generic normalizer would dress it up as a storage
            // account or a registry.
            .filter_map(|mut s| azure_arm::normalize_diagnostic_setting(&mut s).then_some(s))
            .collect())
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
        match resource_type {
            "security_center_subscription_pricing" => return self.security_pricings().await,
            "monitor_diagnostic_setting" => return self.diagnostic_settings().await,
            _ => {}
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

        // One failing side endpoint leaves its own object empty instead of
        // sinking the whole scan, the same way a failed detail read does.
        for object in SUBSCRIPTION_SCOPED {
            match self.gather(object).await {
                Ok(resources) => {
                    grouped.insert((*object).to_string(), resources);
                }
                Err(e) => {
                    tracing::warn!(object = %object, error = %e, "Azure: subscription-scoped gather failed")
                }
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

    /// Payload captured from the pricings endpoint of a live subscription.
    #[test]
    fn normalizes_defender_plans_the_way_cis_2_1_reads_them() {
        let mut free = json!({
            "id": "/subscriptions/x/providers/Microsoft.Security/pricings/VirtualMachines",
            "name": "VirtualMachines",
            "type": "Microsoft.Security/pricings",
            "properties": { "pricingTier": "Free", "freeTrialRemainingTime": "P30D" }
        });
        assert!(azure_arm::normalize_security_pricing(&mut free));
        assert_eq!(free["tier"], json!("Free"));

        let mut standard = json!({
            "name": "FoundationalCspm",
            "type": "Microsoft.Security/pricings",
            "properties": { "resourcesCoverageStatus": "FullyCovered", "pricingTier": "Standard", "freeTrialRemainingTime": "PT0S" }
        });
        assert!(azure_arm::normalize_security_pricing(&mut standard));
        assert_eq!(standard["tier"], json!("Standard"));
    }

    /// No tier, no verdict: the engine would read the missing property as an
    /// empty string and report the plan as not Standard.
    #[test]
    fn a_plan_without_a_tier_is_not_served() {
        let mut p = json!({ "name": "Api", "properties": { "freeTrialRemainingTime": "P30D" } });
        assert!(!azure_arm::normalize_security_pricing(&mut p));
        assert!(p.get("tier").is_none());
    }

    /// Both deprecated forms the live subscription returned.
    #[test]
    fn deprecated_plans_are_dropped() {
        let deprecated = json!({
            "name": "KubernetesService",
            "properties": { "pricingTier": "Free", "deprecated": true, "replacedBy": ["Containers"] }
        });
        assert!(is_deprecated_plan(&deprecated));
        assert!(!is_deprecated_plan(&json!({
            "name": "Containers",
            "properties": { "pricingTier": "Free", "freeTrialRemainingTime": "P30D" }
        })));
    }

    /// The portal writes a category *group*; an ARM template usually writes
    /// individual categories. Both have to land in `enabled_log`.
    #[test]
    fn normalizes_a_diagnostic_setting_from_either_category_form() {
        let mut group = json!({
            "name": "mysetting",
            "type": "Microsoft.Insights/diagnosticSettings",
            "properties": {
                "workspaceId": "/subscriptions/x/…/workspaces/w",
                "logs": [{ "categoryGroup": "allLogs", "enabled": true, "retentionPolicy": { "days": 0, "enabled": false } }],
                "metrics": [{ "category": "AllMetrics", "enabled": true }]
            }
        });
        assert!(azure_arm::normalize_diagnostic_setting(&mut group));
        assert_eq!(group["enabled_log"], json!("allLogs"));

        let mut categories = json!({
            "name": "mysetting",
            "properties": {
                "logs": [
                    { "category": "WorkflowRuntime", "enabled": true },
                    { "category": "Administrative", "enabled": true }
                ]
            }
        });
        assert!(azure_arm::normalize_diagnostic_setting(&mut categories));
        assert_eq!(categories["enabled_log"], json!("WorkflowRuntime,Administrative"));
    }

    /// A setting that captures nothing must read as empty, not as an empty
    /// list: the engine compares `enabled_log` to "" and any array differs from
    /// it, so a list shape would declare this setting compliant.
    #[test]
    fn a_setting_capturing_no_log_reads_as_empty() {
        let mut disabled = json!({
            "name": "metrics-only",
            "properties": {
                "logs": [{ "category": "AuditEvent", "enabled": false }],
                "metrics": [{ "category": "AllMetrics", "enabled": true }]
            }
        });
        assert!(azure_arm::normalize_diagnostic_setting(&mut disabled));
        assert_eq!(disabled["enabled_log"], json!(""));

        let mut no_logs_at_all = json!({
            "name": "metrics-only",
            "properties": { "metrics": [{ "category": "AllMetrics", "enabled": true }] }
        });
        assert!(azure_arm::normalize_diagnostic_setting(&mut no_logs_at_all));
        assert_eq!(no_logs_at_all["enabled_log"], json!(""));
    }

    /// A diagnostic setting reports the *parent's* resource type in `type`
    /// (verified in the ARM reference), so it must never be handed to the
    /// generic normalizer — it would come back dressed as a storage account.
    #[test]
    fn a_diagnostic_setting_is_not_normalized_as_its_parent() {
        let mut s = json!({
            "name": "mysetting",
            "type": "Microsoft.Storage/storageAccounts",
            "properties": { "logs": [{ "categoryGroup": "allLogs", "enabled": true }] }
        });
        assert!(azure_arm::normalize_diagnostic_setting(&mut s));
        assert_eq!(s["enabled_log"], json!("allLogs"));
        assert!(s.get("enable_https_traffic_only").is_none());
        assert!(s.get("network_rules").is_none());
    }

    /// CIS 7.5 asks `extensions` to equal "": a VM carrying none has to produce
    /// the empty string, and a VM carrying some has to produce something else.
    #[test]
    fn vm_extensions_are_a_scalar_the_rule_can_compare() {
        let mut bare = json!({ "type": "Microsoft.Compute/virtualMachines", "name": "vm1" });
        azure_arm::set_vm_extensions(&mut bare, &[]);
        assert_eq!(bare["extensions"], json!(""));

        let mut loaded = json!({ "type": "Microsoft.Compute/virtualMachines", "name": "vm1" });
        azure_arm::set_vm_extensions(
            &mut loaded,
            &[json!({
                "name": "AzureMonitorLinuxAgent",
                "type": "Microsoft.Compute/virtualMachines/extensions",
                "properties": { "publisher": "Microsoft.Azure.Monitor", "type": "AzureMonitorLinuxAgent" }
            })],
        );
        assert_eq!(loaded["extensions"], json!("AzureMonitorLinuxAgent"));
    }

    /// ARM has no `extensionProfiles` on a VM — the field the old normalizer
    /// read. Nothing may invent an extension list out of the VM payload.
    #[test]
    fn the_vm_payload_alone_answers_nothing_about_extensions() {
        let mut vm = json!({
            "type": "Microsoft.Compute/virtualMachines",
            "properties": { "storageProfile": { "osDisk": { "name": "osdisk", "createOption": "FromImage" } } }
        });
        azure_arm::normalize_for_rules(&mut vm);
        assert!(vm.get("extensions").is_none());
        // Unmanaged OS disk: absent, which the engine reads as "" and CIS 7.1
        // then reports — where a `false` would have compared unequal to "" and
        // passed.
        assert!(vm.pointer("/storage_profile/os_disk/managed_disk").is_none());
    }

    #[test]
    fn a_managed_os_disk_is_reported_by_its_id() {
        let mut vm = json!({
            "type": "Microsoft.Compute/virtualMachines",
            "properties": { "storageProfile": { "osDisk": { "managedDisk": { "id": "/subscriptions/x/…/disks/osdisk", "storageAccountType": "Premium_LRS" } } } }
        });
        azure_arm::normalize_for_rules(&mut vm);
        assert_eq!(
            vm.pointer("/storage_profile/os_disk/managed_disk"),
            Some(&json!("/subscriptions/x/…/disks/osdisk"))
        );
    }

    /// A MySQL flexible server has no `sslEnforcement`; the parameter read is
    /// the only answer, and its two values must both map.
    #[test]
    fn mysql_ssl_enforcement_comes_from_the_server_parameter() {
        let mut on = json!({ "type": "Microsoft.DBforMySQL/flexibleServers", "name": "db1" });
        assert!(azure_arm::set_mysql_ssl_enforcement(
            &mut on,
            &json!({
                "name": "require_secure_transport",
                "type": "Microsoft.DBforMySQL/flexibleServers/configurations",
                "properties": { "value": "ON", "defaultValue": "ON", "dataType": "Enumeration", "allowedValues": "ON,OFF", "source": "system-default" }
            })
        ));
        assert_eq!(on["ssl_enforcement_enabled"], json!(true));

        let mut off = json!({ "type": "Microsoft.DBforMySQL/flexibleServers", "name": "db1" });
        assert!(azure_arm::set_mysql_ssl_enforcement(
            &mut off,
            &json!({ "properties": { "value": "OFF", "source": "user-override" } })
        ));
        assert_eq!(off["ssl_enforcement_enabled"], json!(false));
    }

    /// `value` is optional in the configuration contract. No value, no server:
    /// defaulting to false would report every server as accepting clear text.
    #[test]
    fn an_unanswered_server_parameter_drops_the_server() {
        let mut server = json!({ "type": "Microsoft.DBforMySQL/flexibleServers", "name": "db1" });
        assert!(!azure_arm::set_mysql_ssl_enforcement(
            &mut server,
            &json!({ "properties": { "description": "…", "dataType": "Enumeration" } })
        ));
        assert!(server.get("ssl_enforcement_enabled").is_none());

        // `currentValue` is what the engine is running with when `value` is
        // absent, so it still answers the question.
        let mut current_only = json!({ "type": "Microsoft.DBforMySQL/flexibleServers" });
        assert!(azure_arm::set_mysql_ssl_enforcement(
            &mut current_only,
            &json!({ "properties": { "currentValue": "ON" } })
        ));
        assert_eq!(current_only["ssl_enforcement_enabled"], json!(true));
    }

    /// The objects read by their own endpoint are still objects the provider
    /// declares, or `gather` would refuse them.
    #[test]
    fn subscription_scoped_objects_are_declared() {
        for object in SUBSCRIPTION_SCOPED {
            assert!(RESOURCE_TYPES.contains(object), "{object} is not declared");
        }
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
