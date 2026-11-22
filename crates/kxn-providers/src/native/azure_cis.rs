//! Objects the CIS Microsoft Azure Foundations Benchmark reads that no single
//! ARM resource answers: a storage account with its blob and file services, a
//! key vault with its keys, secrets and diagnostic settings, the activity log
//! alerts CIS 6.1.2 asks for, and the subscription-wide settings.
//!
//! Each builder is a pure function over the API answers, so the shapes are
//! tested against captured payloads. An answer that could not be read is
//! `None`, and the field it feeds is `null` — never a default: `null` fails an
//! `EQUAL true` rule, which is the honest result of not being able to look.

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

const OWNER_ROLE: &str = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
const USER_ACCESS_ADMIN_ROLE: &str = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9";
/// Microsoft cloud security benchmark, the initiative Defender for Cloud assigns.
const MCSB_INITIATIVE: &str = "1f3afdf9-d0c9-4c3d-847f-89da613e70a8";
/// Activity log categories CIS 6.1.1.2 wants exported.
pub(crate) const ACTIVITY_LOG_CATEGORIES: &[&str] = &["Administrative", "Alert", "Policy", "Security"];

fn days_since(ts: &str, now: &DateTime<Utc>) -> Option<i64> {
    ts.parse::<DateTime<Utc>>().ok().map(|t| (*now - t).num_days())
}

fn approved_private_endpoints(props: &Value) -> usize {
    props["privateEndpointConnections"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| {
            c.pointer("/properties/privateLinkServiceConnectionState/status")
                .and_then(|s| s.as_str())
                .map_or(true, |s| s.eq_ignore_ascii_case("approved"))
        })
        .count()
}

fn insert(row: &mut Value, key: &str, value: Value) {
    if let Some(o) = row.as_object_mut() {
        o.insert(key.to_string(), value);
    }
}

/// A storage account: its Resource Graph row, plus the fields CIS section 9
/// reads, some of which live in the blob and file service children.
pub(crate) fn storage_row(
    arg: &Value,
    blob: Option<&Value>,
    file: Option<&Value>,
    now: &DateTime<Utc>,
) -> Value {
    let mut row = arg.clone();
    let p = &arg["properties"];
    let kind = arg["kind"].as_str().unwrap_or("");

    let key_ages: Vec<i64> = ["key1", "key2"]
        .iter()
        .filter_map(|k| p["keyCreationTime"][k].as_str())
        .filter_map(|t| days_since(t, now))
        .collect();
    insert(&mut row, "key_age_days", key_ages.iter().max().map_or(Value::Null, |d| json!(d)));
    insert(&mut row, "key_rotation_reminder", json!(p["keyPolicy"]["keyExpirationPeriodInDays"].is_number()));
    insert(&mut row, "private_endpoints", json!(approved_private_endpoints(p)));
    insert(
        &mut row,
        "public_network_access",
        json!(p["publicNetworkAccess"].as_str().unwrap_or("Enabled")),
    );
    insert(
        &mut row,
        "trusted_services_bypass",
        json!(p["networkAcls"]["bypass"].as_str().unwrap_or("").contains("AzureServices")),
    );
    let sku = arg["sku"]["name"].as_str().unwrap_or("");
    insert(&mut row, "geo_redundant", json!(sku.contains("GRS") || sku.contains("GZRS")));

    // Premium block-blob accounts have no file service, premium file accounts
    // no blob service: the controls about the missing one do not apply.
    let has_blob = kind != "FileStorage";
    let has_file = kind != "BlockBlobStorage" && kind != "BlobStorage";
    insert(&mut row, "blob_service", json!(has_blob));
    insert(&mut row, "file_service", json!(has_file));

    let bp = blob.map(|b| &b["properties"]);
    insert(&mut row, "blob_soft_delete", bp.map_or(Value::Null, |p| json!(p["deleteRetentionPolicy"]["enabled"].as_bool().unwrap_or(false))));
    insert(&mut row, "container_soft_delete", bp.map_or(Value::Null, |p| json!(p["containerDeleteRetentionPolicy"]["enabled"].as_bool().unwrap_or(false))));
    insert(&mut row, "blob_versioning", bp.map_or(Value::Null, |p| json!(p["isVersioningEnabled"].as_bool().unwrap_or(false))));

    let fp = file.map(|f| &f["properties"]);
    insert(&mut row, "file_soft_delete", fp.map_or(Value::Null, |p| json!(p["shareDeleteRetentionPolicy"]["enabled"].as_bool().unwrap_or(false))));
    // Unset SMB settings mean every version and every cipher Azure supports.
    insert(&mut row, "smb_versions", fp.map_or(Value::Null, |p| {
        json!(p["protocolSettings"]["smb"]["versions"].as_str().unwrap_or("SMB2.1;SMB3.0;SMB3.1.1"))
    }));
    insert(&mut row, "smb_channel_encryption", fp.map_or(Value::Null, |p| {
        json!(p["protocolSettings"]["smb"]["channelEncryption"].as_str().unwrap_or("AES-128-CCM;AES-128-GCM;AES-256-GCM"))
    }));
    row
}

/// Names of the enabled items of a vault (keys or secrets) failing `bad`.
fn enabled_names_where(items: &[Value], bad: impl Fn(&Value) -> bool) -> Value {
    json!(items
        .iter()
        .filter(|i| i.pointer("/properties/attributes/enabled").and_then(|e| e.as_bool()).unwrap_or(true))
        .filter(|i| bad(i))
        .filter_map(|i| i["name"].as_str())
        .collect::<Vec<_>>())
}

fn has_expiry(item: &Value) -> bool {
    item.pointer("/properties/attributes/exp").is_some_and(|e| !e.is_null())
}

fn has_auto_rotation(key: &Value) -> bool {
    key.pointer("/properties/rotationPolicy/lifetimeActions")
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
        .any(|a| a.pointer("/action/type").and_then(|t| t.as_str()).is_some_and(|t| t.eq_ignore_ascii_case("rotate")))
}

/// Whether one of the diagnostic settings exports the vault's audit events.
pub(crate) fn exports_audit_logs(settings: &[Value]) -> bool {
    settings.iter().any(|s| {
        s.pointer("/properties/logs").and_then(|l| l.as_array()).into_iter().flatten().any(|l| {
            l["enabled"].as_bool() == Some(true)
                && (l["category"].as_str() == Some("AuditEvent")
                    || matches!(l["categoryGroup"].as_str(), Some("audit") | Some("allLogs")))
        })
    })
}

/// A key vault: its Resource Graph row, plus what CIS 6.1.1.4 and 8.3 read.
pub(crate) fn key_vault_row(
    arg: &Value,
    keys: Option<&[Value]>,
    secrets: Option<&[Value]>,
    diagnostics: Option<&[Value]>,
) -> Value {
    let mut row = arg.clone();
    let p = &arg["properties"];
    insert(&mut row, "purge_protection", json!(p["enablePurgeProtection"].as_bool().unwrap_or(false)));
    insert(&mut row, "rbac", json!(p["enableRbacAuthorization"].as_bool().unwrap_or(false)));
    insert(&mut row, "public_network_access", json!(p["publicNetworkAccess"].as_str().unwrap_or("Enabled")));
    insert(&mut row, "private_endpoints", json!(approved_private_endpoints(p)));
    insert(&mut row, "audit_logging", diagnostics.map_or(Value::Null, |d| json!(exports_audit_logs(d))));
    insert(&mut row, "keys_without_expiry", keys.map_or(Value::Null, |k| enabled_names_where(k, |i| !has_expiry(i))));
    insert(&mut row, "keys_without_rotation", keys.map_or(Value::Null, |k| enabled_names_where(k, |i| !has_auto_rotation(i))));
    insert(&mut row, "secrets_without_expiry", secrets.map_or(Value::Null, |s| enabled_names_where(s, |i| !has_expiry(i))));
    row
}

/// One key or secret of a vault, in the shape `azure-secrets-rotation` reads.
pub(crate) fn vault_item_row(vault: &str, item: &Value) -> Value {
    let attrs = &item["properties"]["attributes"];
    let mut row = json!({
        "vault": vault,
        "name": item["name"],
        "id": item["id"],
        "enabled": attrs["enabled"].as_bool().unwrap_or(true),
    });
    if let Some(exp) = attrs["exp"].as_i64() {
        if let Some(t) = DateTime::<Utc>::from_timestamp(exp, 0) {
            row["expiration_date"] = json!(t.to_rfc3339());
        }
    }
    // A policy counts once it does something: an expiry to set on new
    // versions, or a lifetime action. An empty policy object is no policy.
    if let Some(policy) = item.pointer("/properties/rotationPolicy") {
        let after = policy.pointer("/attributes/expiryTime").and_then(|e| e.as_str());
        let actions = policy["lifetimeActions"].as_array().is_some_and(|a| !a.is_empty());
        if after.is_some() || actions {
            row["rotation_policy"] = json!({ "expire_after": after, "auto_rotate": has_auto_rotation(item) });
        }
    }
    row
}

/// CIS 6.1.2.1–6.1.2.11: the operation (or category) each control wants an
/// activity log alert on.
pub(crate) const ACTIVITY_ALERT_CONTROLS: &[(&str, &str, &str)] = &[
    ("6.1.2.1", "create_policy_assignment", "microsoft.authorization/policyassignments/write"),
    ("6.1.2.2", "delete_policy_assignment", "microsoft.authorization/policyassignments/delete"),
    ("6.1.2.3", "create_update_nsg", "microsoft.network/networksecuritygroups/write"),
    ("6.1.2.4", "delete_nsg", "microsoft.network/networksecuritygroups/delete"),
    ("6.1.2.5", "create_update_security_solution", "microsoft.security/securitysolutions/write"),
    ("6.1.2.6", "delete_security_solution", "microsoft.security/securitysolutions/delete"),
    ("6.1.2.7", "create_update_sql_firewall_rule", "microsoft.sql/servers/firewallrules/write"),
    ("6.1.2.8", "delete_sql_firewall_rule", "microsoft.sql/servers/firewallrules/delete"),
    ("6.1.2.9", "create_update_public_ip", "microsoft.network/publicipaddresses/write"),
    ("6.1.2.10", "delete_public_ip", "microsoft.network/publicipaddresses/delete"),
    ("6.1.2.11", "service_health", "category:servicehealth"),
];

/// One row per CIS 6.1.2 control: whether an enabled activity log alert on the
/// subscription watches that operation.
pub(crate) fn activity_alert_rows(alerts: &[Value], subscription_id: &str) -> Vec<Value> {
    let sub_scope = format!("/subscriptions/{}", subscription_id.to_lowercase());
    let watching: Vec<(String, String)> = alerts
        .iter()
        .filter(|a| a.pointer("/properties/enabled").and_then(|e| e.as_bool()).unwrap_or(true))
        .filter(|a| {
            a.pointer("/properties/scopes").and_then(|s| s.as_array()).into_iter().flatten().any(|s| {
                s.as_str().is_some_and(|s| s.to_lowercase().starts_with(&sub_scope))
            })
        })
        .map(|a| {
            (
                a["name"].as_str().unwrap_or("").to_string(),
                a.pointer("/properties/condition").map(|c| c.to_string().to_lowercase()).unwrap_or_default(),
            )
        })
        .collect();
    ACTIVITY_ALERT_CONTROLS
        .iter()
        .map(|(control, name, op)| {
            let needle = match op.strip_prefix("category:") {
                Some(cat) => format!("\"equals\":\"{cat}\""),
                None => format!("\"equals\":\"{op}\""),
            };
            let alert = watching.iter().find(|(_, c)| c.contains(&needle)).map(|(n, _)| n.as_str());
            json!({
                "name": name,
                "control": control,
                "operation": op,
                "alert": alert.unwrap_or(""),
                "alert_enabled": alert.is_some(),
            })
        })
        .collect()
}

/// Inputs of the subscription row, each `None` when it could not be read.
#[derive(Default)]
pub(crate) struct SubscriptionFacts<'a> {
    pub subscription_id: &'a str,
    pub name: &'a str,
    pub diagnostic_settings: Option<&'a [Value]>,
    pub storage_accounts: &'a [Value],
    pub role_assignments: Option<&'a [Value]>,
    pub custom_roles: Option<&'a [Value]>,
    pub security_contacts: Option<&'a [Value]>,
    pub mde_setting: Option<&'a Value>,
    pub resources: &'a [Value],
    pub policy_assignments: Option<&'a [Value]>,
}

fn role_guid(assignment: &Value) -> String {
    assignment
        .pointer("/properties/roleDefinitionId")
        .and_then(|r| r.as_str())
        .and_then(|r| r.rsplit('/').next())
        .unwrap_or("")
        .to_lowercase()
}

/// The subscription-wide settings CIS reads, as one row.
pub(crate) fn subscription_row(f: &SubscriptionFacts) -> Value {
    let sub_scope = format!("/subscriptions/{}", f.subscription_id).to_lowercase();
    let mut row = Map::new();
    row.insert("name".into(), json!(f.name));
    row.insert("subscription_id".into(), json!(f.subscription_id));

    // 6.1.1.1–6.1.1.3: activity log export.
    match f.diagnostic_settings {
        Some(settings) => {
            let mut categories: Vec<String> = Vec::new();
            for s in settings {
                for l in s.pointer("/properties/logs").and_then(|l| l.as_array()).into_iter().flatten() {
                    if l["enabled"].as_bool() == Some(true) {
                        if let Some(c) = l["category"].as_str().or_else(|| l["categoryGroup"].as_str()) {
                            if c == "allLogs" {
                                categories.extend(ACTIVITY_LOG_CATEGORIES.iter().map(|c| c.to_string()));
                            } else if !categories.iter().any(|x| x == c) {
                                categories.push(c.to_string());
                            }
                        }
                    }
                }
            }
            categories.dedup();
            row.insert("activity_log_exported".into(), json!(!settings.is_empty()));
            row.insert("activity_log_categories".into(), json!(categories));
            let storage_ids: Vec<String> = settings
                .iter()
                .filter_map(|s| s.pointer("/properties/storageAccountId").and_then(|i| i.as_str()))
                .map(str::to_lowercase)
                .collect();
            row.insert("activity_log_to_storage".into(), json!(!storage_ids.is_empty()));
            let cmk = storage_ids.iter().all(|id| {
                f.storage_accounts.iter().any(|a| {
                    a["id"].as_str().map(str::to_lowercase).as_deref() == Some(id.as_str())
                        && a.pointer("/properties/encryption/keySource").and_then(|k| k.as_str())
                            == Some("Microsoft.Keyvault")
                })
            });
            row.insert("activity_log_storage_cmk".into(), json!(cmk));
        }
        None => {
            for k in ["activity_log_exported", "activity_log_categories", "activity_log_to_storage", "activity_log_storage_cmk"] {
                row.insert(k.into(), Value::Null);
            }
        }
    }

    // 5.3.3, 5.7: owners and User Access Administrators at subscription scope.
    match f.role_assignments {
        Some(assignments) => {
            let at_sub = |a: &&Value| {
                a.pointer("/properties/scope").and_then(|s| s.as_str()).map(str::to_lowercase).as_deref()
                    == Some(sub_scope.as_str())
            };
            let owners = assignments.iter().filter(at_sub).filter(|a| role_guid(a) == OWNER_ROLE).count();
            let uaa = assignments
                .iter()
                .filter(|a| {
                    let scope = a.pointer("/properties/scope").and_then(|s| s.as_str()).unwrap_or("").to_lowercase();
                    scope == "/" || scope == sub_scope
                })
                .filter(|a| role_guid(a) == USER_ACCESS_ADMIN_ROLE)
                .count();
            row.insert("owners".into(), json!(owners));
            row.insert("user_access_administrators".into(), json!(uaa));
        }
        None => {
            row.insert("owners".into(), Value::Null);
            row.insert("user_access_administrators".into(), Value::Null);
        }
    }

    // 5.4: custom roles granting everything over the subscription.
    row.insert(
        "custom_owner_roles".into(),
        f.custom_roles.map_or(Value::Null, |roles| {
            json!(roles
                .iter()
                .filter(|r| {
                    let p = &r["properties"];
                    let everything = p["permissions"].as_array().into_iter().flatten().any(|perm| {
                        perm["actions"].as_array().into_iter().flatten().any(|a| a.as_str() == Some("*"))
                    });
                    let over_sub = p["assignableScopes"].as_array().into_iter().flatten().any(|s| {
                        let s = s.as_str().unwrap_or("").to_lowercase();
                        s == "/" || s == sub_scope || s.starts_with("/providers/microsoft.management/managementgroups/")
                    });
                    everything && over_sub
                })
                .filter_map(|r| r.pointer("/properties/roleName").and_then(|n| n.as_str()))
                .collect::<Vec<_>>())
        }),
    );

    // 8.1.12–8.1.15: Defender for Cloud security contact.
    match f.security_contacts {
        Some(contacts) => {
            let c = contacts.first().map(|c| &c["properties"]);
            let by_role_on = c.is_some_and(|c| c["notificationsByRole"]["state"].as_str() == Some("On"));
            let roles: Vec<&str> = c
                .map(|c| c["notificationsByRole"]["roles"].as_array().into_iter().flatten().filter_map(|r| r.as_str()).collect())
                .unwrap_or_default();
            let source = |kind: &str| {
                c.and_then(|c| {
                    c["notificationsSources"].as_array().into_iter().flatten().find(|s| s["sourceType"].as_str() == Some(kind)).cloned()
                })
            };
            let alert = source("Alert");
            let attack = source("AttackPath");
            row.insert("notify_owners".into(), json!(by_role_on && roles.contains(&"Owner")));
            row.insert(
                "security_contact_emails".into(),
                json!(c.and_then(|c| c["emails"].as_str()).unwrap_or("")),
            );
            row.insert(
                "alert_notification_severity".into(),
                json!(alert.as_ref().and_then(|a| a["minimalSeverity"].as_str()).unwrap_or("")),
            );
            row.insert(
                "attack_path_notification_risk".into(),
                json!(attack.as_ref().and_then(|a| a["minimalRiskLevel"].as_str()).unwrap_or("")),
            );
        }
        None => {
            for k in ["notify_owners", "security_contact_emails", "alert_notification_severity", "attack_path_notification_risk"] {
                row.insert(k.into(), Value::Null);
            }
        }
    }

    // 8.1.3.3: Defender for Endpoint integration.
    row.insert(
        "endpoint_protection_integration".into(),
        f.mde_setting.map_or(Value::Null, |s| json!(s.pointer("/properties/enabled").and_then(|e| e.as_bool()).unwrap_or(false))),
    );

    // 6.1.3.1, 7.6, 8.4.1: what exists in the subscription.
    fn of_type<'r>(resources: &'r [Value], t: &'static str) -> impl Iterator<Item = &'r Value> {
        resources.iter().filter(move |r| r["type"].as_str().is_some_and(|x| x.eq_ignore_ascii_case(t)))
    }
    row.insert("application_insights".into(), json!(of_type(f.resources, "microsoft.insights/components").count()));
    row.insert("bastion_hosts".into(), json!(of_type(f.resources, "microsoft.network/bastionhosts").count()));
    let watched: Vec<String> = of_type(f.resources, "microsoft.network/networkwatchers")
        .filter_map(|w| w["location"].as_str().map(str::to_lowercase))
        .collect();
    let mut used: Vec<String> = f
        .resources
        .iter()
        .filter_map(|r| r["location"].as_str().map(str::to_lowercase))
        .filter(|l| l != "global" && !l.is_empty())
        .collect();
    used.sort();
    used.dedup();
    row.insert(
        "regions_without_network_watcher".into(),
        json!(used.into_iter().filter(|l| !watched.contains(l)).collect::<Vec<_>>()),
    );

    // 8.1.11: the Microsoft cloud security benchmark initiative is assigned.
    row.insert(
        "mcsb_assigned".into(),
        f.policy_assignments.map_or(Value::Null, |assignments| {
            json!(assignments.iter().any(|a| {
                a.pointer("/properties/policyDefinitionId")
                    .and_then(|d| d.as_str())
                    .is_some_and(|d| d.to_lowercase().ends_with(MCSB_INITIATIVE))
            }))
        }),
    );
    Value::Object(row)
}

/// Whether an NSG source prefix means "anywhere on the internet".
fn is_internet_source(prefix: &str) -> bool {
    matches!(prefix.to_lowercase().as_str(), "*" | "internet" | "any" | "0.0.0.0/0" | "0.0.0.0" | "::/0")
        || prefix.ends_with("/0")
}

/// Whether an NSG port spec (`*`, `3389`, `3000-4000`) covers `port`.
fn port_covers(spec: &str, port: u16) -> bool {
    let spec = spec.trim();
    if spec == "*" {
        return true;
    }
    match spec.split_once('-') {
        Some((lo, hi)) => match (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()) {
            (Ok(lo), Ok(hi)) => lo <= port && port <= hi,
            _ => false,
        },
        None => spec.parse::<u16>().ok() == Some(port),
    }
}

fn strings(v: &Value, one: &str, many: &str) -> Vec<String> {
    let mut out: Vec<String> = v[many].as_array().into_iter().flatten().filter_map(|s| s.as_str().map(String::from)).collect();
    if let Some(s) = v[one].as_str() {
        out.push(s.to_string());
    }
    out
}

/// CIS 7.1–7.4: what an NSG lets in from the internet. Reads the
/// user-defined `securityRules` (ARM shape: each rule's fields under
/// `properties`); the default rules never allow internet traffic in.
pub(crate) fn nsg_exposure(security_rules: &[Value]) -> Value {
    let open = |proto_ok: &dyn Fn(&str) -> bool, port: Option<u16>| {
        security_rules.iter().any(|r| {
            let p = &r["properties"];
            p["access"].as_str().is_some_and(|a| a.eq_ignore_ascii_case("allow"))
                && p["direction"].as_str().is_some_and(|d| d.eq_ignore_ascii_case("inbound"))
                && proto_ok(p["protocol"].as_str().unwrap_or("*"))
                && strings(p, "sourceAddressPrefix", "sourceAddressPrefixes").iter().any(|s| is_internet_source(s))
                && match port {
                    None => true,
                    Some(port) => strings(p, "destinationPortRange", "destinationPortRanges").iter().any(|s| port_covers(s, port)),
                }
        })
    };
    let tcp = |p: &str| p == "*" || p.eq_ignore_ascii_case("tcp");
    let udp = |p: &str| p == "*" || p.eq_ignore_ascii_case("udp");
    json!({
        "rdp_from_internet": open(&tcp, Some(3389)),
        "ssh_from_internet": open(&tcp, Some(22)),
        "udp_from_internet": open(&udp, None),
        "http_from_internet": open(&tcp, Some(80)) || open(&tcp, Some(443)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        "2026-11-22T00:00:00Z".parse().unwrap()
    }

    /// Properties as Resource Graph returned them for a live account.
    fn live_storage() -> Value {
        json!({
            "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/rtk",
            "name": "rtk", "type": "microsoft.storage/storageaccounts", "kind": "StorageV2",
            "sku": {"name": "Standard_LRS", "tier": "Standard"},
            "properties": {
                "allowBlobPublicAccess": true, "allowCrossTenantReplication": false,
                "keyCreationTime": {"key1": "2026-05-03T12:07:42.3126535Z", "key2": "2026-05-03T12:07:42.3126535Z"},
                "minimumTlsVersion": "TLS1_0",
                "networkAcls": {"bypass": "None", "defaultAction": "Allow"},
                "privateEndpointConnections": [], "supportsHttpsTrafficOnly": true
            }
        })
    }

    #[test]
    fn storage_row_from_a_live_account() {
        let blob = json!({"properties": {"deleteRetentionPolicy": {"enabled": true, "days": 7}}});
        let row = storage_row(&live_storage(), Some(&blob), None, &now());
        assert_eq!(row["key_age_days"], 202);
        assert_eq!(row["key_rotation_reminder"], false);
        assert_eq!(row["public_network_access"], "Enabled");
        assert_eq!(row["trusted_services_bypass"], false);
        assert_eq!(row["geo_redundant"], false);
        assert_eq!(row["blob_soft_delete"], true);
        assert_eq!(row["container_soft_delete"], false);
        assert_eq!(row["blob_versioning"], false);
        // File service unread: unknown, not compliant.
        assert!(row["file_soft_delete"].is_null());
        assert!(row["smb_versions"].is_null());
        assert_eq!(row["properties"]["minimumTlsVersion"], "TLS1_0");
    }

    #[test]
    fn unset_smb_settings_mean_every_version_and_cipher() {
        let file = json!({"properties": {"shareDeleteRetentionPolicy": {"enabled": true}}});
        let row = storage_row(&live_storage(), None, Some(&file), &now());
        assert_eq!(row["smb_versions"], "SMB2.1;SMB3.0;SMB3.1.1");
        assert_eq!(row["smb_channel_encryption"], "AES-128-CCM;AES-128-GCM;AES-256-GCM");
        assert_eq!(row["file_soft_delete"], true);
    }

    #[test]
    fn premium_block_blob_accounts_have_no_file_service() {
        let mut a = live_storage();
        a["kind"] = json!("BlockBlobStorage");
        assert_eq!(storage_row(&a, None, None, &now())["file_service"], false);
    }

    #[test]
    fn key_vault_items_without_expiry_or_rotation() {
        let keys = vec![
            json!({"name": "k1", "properties": {"attributes": {"enabled": true, "exp": 1900000000},
                "rotationPolicy": {"lifetimeActions": [{"action": {"type": "Rotate"}}]}}}),
            json!({"name": "k2", "properties": {"attributes": {"enabled": true}}}),
            json!({"name": "off", "properties": {"attributes": {"enabled": false}}}),
        ];
        let secrets = vec![json!({"name": "s1", "properties": {"attributes": {"enabled": true, "created": 1532796447}}})];
        let diag = vec![json!({"properties": {"logs": [{"categoryGroup": "audit", "enabled": true}]}})];
        let row = key_vault_row(
            &json!({"name": "kv", "properties": {"enableRbacAuthorization": false}}),
            Some(&keys), Some(&secrets), Some(&diag),
        );
        assert_eq!(row["keys_without_expiry"], json!(["k2"]));
        assert_eq!(row["keys_without_rotation"], json!(["k2"]));
        assert_eq!(row["secrets_without_expiry"], json!(["s1"]));
        assert_eq!(row["audit_logging"], true);
        assert_eq!(row["purge_protection"], false);
        assert_eq!(row["rbac"], false);
        // Keys unreadable (a vault of another tenant): unknown.
        assert!(key_vault_row(&json!({}), None, None, None)["keys_without_expiry"].is_null());
    }

    #[test]
    fn vault_item_rows_carry_iso_expiry_and_rotation() {
        let row = vault_item_row("kv", &json!({"name": "k", "properties": {
            "attributes": {"enabled": true, "exp": 1767225600},
            "rotationPolicy": {"attributes": {"expiryTime": "P90D"}}}}));
        assert_eq!(row["expiration_date"], "2026-01-01T00:00:00+00:00");
        assert_eq!(row["rotation_policy"]["expire_after"], "P90D");
    }

    #[test]
    fn activity_alerts_match_operation_scope_and_state() {
        let alert = |enabled: bool, scope: &str| json!({"name": "nsg-write", "properties": {
            "enabled": enabled, "scopes": [scope],
            "condition": {"allOf": [{"field": "category", "equals": "Administrative"},
                                    {"field": "operationName", "equals": "Microsoft.Network/networkSecurityGroups/write"}]}}});
        let row = |alerts: &[Value]| activity_alert_rows(alerts, "S1").into_iter().find(|r| r["control"] == "6.1.2.3").unwrap();
        assert_eq!(row(&[alert(true, "/subscriptions/s1")])["alert_enabled"], true);
        assert_eq!(row(&[alert(false, "/subscriptions/s1")])["alert_enabled"], false);
        assert_eq!(row(&[alert(true, "/subscriptions/other")])["alert_enabled"], false);
        // write must not satisfy delete.
        let all = activity_alert_rows(&[alert(true, "/subscriptions/s1")], "s1");
        assert_eq!(all.iter().filter(|r| r["alert_enabled"] == true).count(), 1);
        assert_eq!(all.len(), 11);
    }

    #[test]
    fn subscription_row_counts_owners_and_reads_contacts() {
        let ra = |role: &str, scope: &str| json!({"properties": {"scope": scope,
            "roleDefinitionId": format!("/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/{role}")}});
        let assignments = vec![
            ra(OWNER_ROLE, "/subscriptions/S"), ra(OWNER_ROLE, "/subscriptions/s"),
            ra(OWNER_ROLE, "/subscriptions/s/resourceGroups/rg"), ra(USER_ACCESS_ADMIN_ROLE, "/"),
        ];
        let custom = vec![json!({"properties": {"roleName": "god", "assignableScopes": ["/subscriptions/s"],
            "permissions": [{"actions": ["*"]}]}})];
        let contacts = vec![json!({"properties": {"emails": "sec@x.org",
            "notificationsByRole": {"state": "On", "roles": ["Owner"]},
            "notificationsSources": [{"sourceType": "Alert", "minimalSeverity": "High"}]}})];
        let diag = vec![json!({"properties": {"logs": [{"category": "Administrative", "enabled": true},
            {"category": "Security", "enabled": true}, {"category": "Policy", "enabled": false}]}})];
        let resources = vec![
            json!({"type": "Microsoft.KeyVault/vaults", "location": "westeurope"}),
            json!({"type": "microsoft.network/networkwatchers", "location": "westeurope"}),
            json!({"type": "Microsoft.Storage/storageAccounts", "location": "francecentral"}),
            json!({"type": "microsoft.insights/actiongroups", "location": "global"}),
        ];
        let row = subscription_row(&SubscriptionFacts {
            subscription_id: "s", name: "sub",
            diagnostic_settings: Some(&diag), role_assignments: Some(&assignments),
            custom_roles: Some(&custom), security_contacts: Some(&contacts),
            resources: &resources, ..Default::default()
        });
        assert_eq!(row["owners"], 2);
        assert_eq!(row["user_access_administrators"], 1);
        assert_eq!(row["custom_owner_roles"], json!(["god"]));
        assert_eq!(row["notify_owners"], true);
        assert_eq!(row["alert_notification_severity"], "High");
        assert_eq!(row["attack_path_notification_risk"], "");
        assert_eq!(row["activity_log_categories"], json!(["Administrative", "Security"]));
        assert_eq!(row["activity_log_to_storage"], false);
        assert_eq!(row["regions_without_network_watcher"], json!(["francecentral"]));
        assert!(row["endpoint_protection_integration"].is_null());
        assert!(row["mcsb_assigned"].is_null());
    }

    #[test]
    fn nsg_exposure_reads_ranges_lists_and_service_tags() {
        let rule = |proto: &str, src: Value, ports: Value| json!({"properties": {
            "access": "Allow", "direction": "Inbound", "protocol": proto,
            "sourceAddressPrefixes": src, "destinationPortRanges": ports}});
        let e = nsg_exposure(&[rule("Tcp", json!(["10.0.0.0/8", "Internet"]), json!(["3000-4000"]))]);
        assert_eq!(e["rdp_from_internet"], true);
        assert_eq!(e["ssh_from_internet"], false);
        assert_eq!(e["udp_from_internet"], false);
        let e = nsg_exposure(&[rule("*", json!(["0.0.0.0/0"]), json!(["443"]))]);
        assert_eq!(e["http_from_internet"], true);
        assert_eq!(e["udp_from_internet"], true);
        let e = nsg_exposure(&[rule("Tcp", json!(["10.0.0.0/8"]), json!(["*"]))]);
        assert_eq!(e, json!({"rdp_from_internet": false, "ssh_from_internet": false, "udp_from_internet": false, "http_from_internet": false}));
        let deny = json!({"properties": {"access": "Deny", "direction": "Inbound", "protocol": "*", "sourceAddressPrefix": "*", "destinationPortRange": "*"}});
        assert_eq!(nsg_exposure(&[deny])["ssh_from_internet"], false);
    }
}
