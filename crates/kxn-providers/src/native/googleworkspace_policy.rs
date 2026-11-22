//! Google Workspace settings through the Cloud Identity Policy API.
//!
//! `policies.list` answers every policy of the customer: the defaults Google
//! applies (`type: SYSTEM`) and the administrator's own (`ADMIN`), each scoped
//! to an organizational unit or a group, and ordered by `sortOrder` within its
//! setting type. The value in force for an OU is what Google calls the
//! reduction: for each field, the policy with the greatest `sortOrder` that
//! sets it. A setting the API leaves out takes the default Google documents
//! ("Default field values"); one with no documented default is left out
//! rather than guessed.
//!
//! The `settings` object is that reduction, one row per OU, keyed the way the
//! setting types are named: `gmail.links_and_external_images.enableShortenerScanning`.
//! Durations (`"1209600s"`) get a numeric twin (`webSessionDurationSeconds`).
//!
//! Limits, stated rather than hidden: the API does not say how OUs nest, so a
//! sub-OU row is its own policies over the root's (an intermediate OU's
//! overrides are not inherited); group-scoped policies stay in `policies` and
//! are not folded into any OU.

use std::collections::{BTreeMap, HashMap};

use serde_json::{json, Map, Value};

const ALERTS: &str = "rule.system_defined_alerts";

/// Google's documented default field values, for the settings the API may
/// leave out (camelCase, as the API spells fields).
const DEFAULTS: &[(&str, &str, &str)] = &[
    ("drive_and_docs.external_sharing", "externalSharingMode", r#""ALLOWED""#),
    ("drive_and_docs.external_sharing", "allowReceivingExternalFiles", "true"),
    ("drive_and_docs.external_sharing", "warnForSharingOutsideAllowlistedDomains", "true"),
    ("drive_and_docs.external_sharing", "allowNonGoogleInvitesInAllowlistedDomains", "false"),
    ("drive_and_docs.external_sharing", "allowReceivingFilesOutsideAllowlistedDomains", "true"),
    ("drive_and_docs.external_sharing", "warnForExternalSharing", "true"),
    ("drive_and_docs.external_sharing", "allowNonGoogleInvites", "true"),
    ("drive_and_docs.external_sharing", "allowPublishingFiles", "true"),
    ("drive_and_docs.external_sharing", "accessCheckerSuggestions", r#""RECIPIENTS_OR_AUDIENCE_OR_PUBLIC""#),
    ("drive_and_docs.external_sharing", "allowedPartiesForDistributingContent", r#""ALL_ELIGIBLE_USERS""#),
    ("gmail.auto_forwarding", "enableAutoForwarding", "true"),
    ("gmail.email_spam_filter_ip_allowlist", "allowedIpAddresses", "[]"),
    ("gmail.mail_delegation", "enableMailDelegation", "false"),
    ("gmail.links_and_external_images", "enableAggressiveWarningsOnUntrustedLinks", "false"),
    ("groups_for_business.groups_sharing", "collaborationCapability", r#""DOMAIN_USERS_ONLY""#),
    ("groups_for_business.groups_sharing", "createGroupsAccessLevel", r#""USERS_IN_DOMAIN""#),
    ("groups_for_business.groups_sharing", "viewTopicsDefaultAccessLevel", r#""DOMAIN_USERS""#),
    ("groups_for_business.groups_sharing", "ownersCanAllowExternalMembers", "false"),
    ("groups_for_business.groups_sharing", "ownersCanAllowIncomingMailFromPublic", "true"),
    ("groups_for_business.groups_sharing", "ownersCanHideGroups", "false"),
    ("groups_for_business.groups_sharing", "newGroupsAreHidden", "false"),
    ("calendar.external_invitations", "warnOnInvite", "true"),
    ("calendar.primary_calendar_max_allowed_external_sharing", "maxAllowedExternalSharing", r#""EXTERNAL_FREE_BUSY_ONLY""#),
    ("calendar.secondary_calendar_max_allowed_external_sharing", "maxAllowedExternalSharing", r#""EXTERNAL_ALL_INFO_READ_ONLY""#),
    // "For K12 customers: ALLOW_NONE, otherwise: ALLOW_ALL" — kxn audits
    // businesses; a K12 tenant reports its own policy anyway.
    ("workspace_marketplace.apps_access_options", "accessLevel", r#""ALLOW_ALL""#),
    ("workspace_marketplace.apps_access_options", "allowAllInternalApps", "false"),
    ("security.super_admin_account_recovery", "enableAccountRecovery", "false"),
    ("security.user_account_recovery", "enableAccountRecovery", "false"),
    ("security.two_step_verification_enforcement_factor", "allowedSignInFactorSet", r#""ALL""#),
    ("security.less_secure_apps", "allowLessSecureApps", "false"),
    ("security.password", "allowedStrength", r#""STRONG""#),
    ("security.password", "minimumLength", "8"),
    ("security.password", "maximumLength", "100"),
    ("security.password", "enforceRequirementsAtLogin", "false"),
    ("security.password", "allowReuse", "false"),
    ("security.password", "expirationDuration", r#""0s""#),
    ("chat.external_chat_restriction", "allowExternalChat", "false"),
    ("chat.external_chat_restriction", "externalChatRestriction", r#""NO_RESTRICTION""#),
];

fn setting_type(p: &Value) -> &str {
    p["setting"]["type"].as_str().unwrap_or("").trim_start_matches("settings/")
}

fn sort_order(p: &Value) -> f64 {
    p["policyQuery"]["sortOrder"].as_f64().unwrap_or(0.0)
}

fn org_unit(p: &Value) -> Option<&str> {
    p["policyQuery"]["orgUnit"].as_str()
}

/// The raw policies, flattened for reading: one row per policy.
pub(crate) fn policy_rows(policies: &[Value]) -> Vec<Value> {
    policies
        .iter()
        .map(|p| {
            json!({
                "name": p["name"],
                "setting": setting_type(p),
                "type": p["type"],
                "org_unit": p["policyQuery"]["orgUnit"],
                "group": p["policyQuery"]["group"],
                "sort_order": p["policyQuery"]["sortOrder"],
                "value": p["setting"]["value"],
            })
        })
        .collect()
}

/// The root OU: the one Google's SYSTEM defaults are attached to.
fn root_ou(policies: &[Value]) -> Option<String> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for p in policies.iter().filter(|p| p["type"] == "SYSTEM") {
        if let Some(ou) = org_unit(p) {
            *counts.entry(ou).or_default() += 1;
        }
    }
    counts.into_iter().max_by_key(|(_, n)| *n).map(|(ou, _)| ou.to_string())
}

/// Reduce the policies of one setting type: each field from the policy with
/// the greatest `sortOrder` that sets it.
fn reduce(mut policies: Vec<&Value>) -> Map<String, Value> {
    policies.sort_by(|a, b| sort_order(a).total_cmp(&sort_order(b)));
    let mut out = Map::new();
    for p in policies {
        if let Value::Object(fields) = &p["setting"]["value"] {
            for (k, v) in fields {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    out
}

/// `"1209600s"` → 1209600.
pub(crate) fn duration_seconds(v: &Value) -> Option<f64> {
    v.as_str()?.strip_suffix('s')?.parse().ok()
}

/// The settings in force, one row per organizational unit.
pub(crate) fn effective_settings(policies: &[Value]) -> Vec<Value> {
    let root = root_ou(policies);
    let mut ous: Vec<String> = policies
        .iter()
        .filter(|p| p["policyQuery"]["group"].is_null())
        .filter_map(|p| org_unit(p).map(String::from))
        .collect();
    ous.sort();
    ous.dedup();

    ous.iter()
        .map(|ou| {
            let applicable: Vec<&Value> = policies
                .iter()
                .filter(|p| p["policyQuery"]["group"].is_null() && setting_type(p) != ALERTS)
                .filter(|p| org_unit(p).is_some_and(|o| o == ou || Some(o) == root.as_deref()))
                .collect();
            let mut by_type: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
            for p in applicable {
                by_type.entry(setting_type(p)).or_default().push(p);
            }
            let mut reduced: BTreeMap<String, Map<String, Value>> =
                by_type.into_iter().map(|(t, ps)| (t.to_string(), reduce(ps))).collect();
            for (t, field, default) in DEFAULTS {
                let fields = reduced.entry((*t).to_string()).or_default();
                fields.entry((*field).to_string()).or_insert_with(|| serde_json::from_str(default).unwrap_or(Value::Null));
            }

            let mut row = Map::new();
            for (t, mut fields) in reduced {
                let twins: Vec<(String, Value)> = fields
                    .iter()
                    .filter_map(|(k, v)| duration_seconds(v).map(|s| (format!("{k}Seconds"), json!(s))))
                    .collect();
                fields.extend(twins);
                let (app, name) = t.split_once('.').unwrap_or((t.as_str(), ""));
                let app_entry = row.entry(app.to_string()).or_insert_with(|| Value::Object(Map::new()));
                if let Value::Object(m) = app_entry {
                    m.insert(name.to_string(), Value::Object(fields));
                }
            }
            row.insert("org_unit".into(), json!(ou));
            row.insert("root".into(), json!(Some(ou.as_str()) == root.as_deref()));
            Value::Object(row)
        })
        .collect()
}

fn severity_rank(s: &str) -> i64 {
    match s {
        "LOW" => 1,
        "MEDIUM" => 2,
        "HIGH" => 3,
        _ => 0,
    }
}

/// System-defined alert rules (Admin console › Rules), one row per rule, as
/// they stand for the customer.
pub(crate) fn alert_rows(policies: &[Value]) -> Vec<Value> {
    let mut latest: BTreeMap<String, &Value> = BTreeMap::new();
    for p in policies.iter().filter(|p| setting_type(p) == ALERTS) {
        let Some(name) = p["setting"]["value"]["displayName"].as_str() else { continue };
        match latest.get(name) {
            Some(prev) if sort_order(prev) >= sort_order(p) => {}
            _ => {
                latest.insert(name.to_string(), p);
            }
        }
    }
    latest
        .into_iter()
        .map(|(name, p)| {
            let v = &p["setting"]["value"];
            let action = &v["action"]["alertCenterAction"];
            let severity = action["alertCenterConfig"]["severity"].as_str().unwrap_or("");
            let notifies = action["recipients"]
                .as_array()
                .is_some_and(|r| r.iter().any(|x| x["allSuperAdmins"] == true));
            json!({
                "name": name,
                "state": v["state"],
                "active": v["state"] == "ACTIVE",
                "severity": severity,
                "severity_rank": severity_rank(severity),
                "notifies_super_admins": notifies,
                "description": v["description"],
            })
        })
        .collect()
}

/// The system-defined alerts CISA SCuBA GWS.COMMONCONTROLS.13.1 requires on.
pub(crate) const SCUBA_REQUIRED_ALERTS: &[&str] = &[
    "Government-backed attacks", "User-reported phishing", "User's Admin privilege revoked",
    "User suspended for spamming through relay", "User suspended for spamming",
    "User suspended due to suspicious activity", "User suspended (Google identity alert)",
    "User granted Admin privilege", "Suspicious programmatic login", "Suspicious message reported",
    "Suspicious login", "Suspicious device activity", "Spike in user-reported spam", "Rate limited recipient",
    "Phishing message detected post-delivery", "Phishing in inboxes due to bad whitelist", "Mobile settings changed",
    "Malware message detected post-delivery", "Leaked password", "Google Operations",
    "Gmail potential employee spoofing", "Email settings changed", "Drive settings changed",
    "Domain data export initiated", "Device compromised", "Calendar settings changed", "Account suspension warning",
    "Super admin password reset", "SSO profile added", "SSO profile updated",
];

/// The required alerts that are not active. The Admin console shows "Super
/// admin password reset" as "Admin password reset".
pub(crate) fn required_alerts_off(alerts: &[Value]) -> Vec<&'static str> {
    SCUBA_REQUIRED_ALERTS
        .iter()
        .copied()
        .filter(|name| {
            let alias = if *name == "Super admin password reset" { "Admin password reset" } else { name };
            !alerts.iter().any(|a| (a["name"] == *name || a["name"] == alias) && a["active"] == true)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(t: &str, ou: &str, kind: &str, order: f64, value: Value) -> Value {
        json!({"type": kind, "policyQuery": {"orgUnit": ou, "sortOrder": order},
               "setting": {"type": format!("settings/{t}"), "value": value}})
    }

    #[test]
    fn the_greatest_sort_order_wins_field_by_field() {
        let ps = vec![
            policy("gmail.links_and_external_images", "orgUnits/root", "SYSTEM", 100.00001,
                   json!({"enableShortenerScanning": false, "enableExternalImageScanning": false})),
            policy("gmail.links_and_external_images", "orgUnits/root", "SYSTEM", 100.00015,
                   json!({"enableShortenerScanning": true})),
        ];
        let rows = effective_settings(&ps);
        assert_eq!(rows.len(), 1);
        let l = &rows[0]["gmail"]["links_and_external_images"];
        assert_eq!(l["enableShortenerScanning"], true);
        assert_eq!(l["enableExternalImageScanning"], false);
        assert_eq!(rows[0]["root"], true);
    }

    #[test]
    fn a_sub_ou_overrides_the_root_and_absent_settings_take_documented_defaults() {
        let ps = vec![
            policy("security.session_controls", "orgUnits/root", "SYSTEM", 100.1, json!({"webSessionDuration": "1209600s"})),
            policy("security.session_controls", "orgUnits/sales", "ADMIN", 201.0, json!({"webSessionDuration": "43200s"})),
        ];
        let rows = effective_settings(&ps);
        let sales = rows.iter().find(|r| r["org_unit"] == "orgUnits/sales").unwrap();
        assert_eq!(sales["security"]["session_controls"]["webSessionDurationSeconds"], 43200.0);
        assert_eq!(sales["root"], false);
        let root = rows.iter().find(|r| r["root"] == true).unwrap();
        assert_eq!(root["security"]["session_controls"]["webSessionDurationSeconds"], 1_209_600.0);
        assert_eq!(root["drive_and_docs"]["external_sharing"]["allowPublishingFiles"], true);
        assert_eq!(root["gmail"]["auto_forwarding"]["enableAutoForwarding"], true);
    }

    #[test]
    fn group_policies_are_not_folded_into_an_ou() {
        let mut g = policy("security.session_controls", "orgUnits/root", "ADMIN", 300.0, json!({"webSessionDuration": "3600s"}));
        g["policyQuery"] = json!({"group": "groups/x", "sortOrder": 300.0});
        let ps = vec![policy("security.session_controls", "orgUnits/root", "SYSTEM", 100.0, json!({"webSessionDuration": "1209600s"})), g];
        let rows = effective_settings(&ps);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["security"]["session_controls"]["webSessionDuration"], "1209600s");
        assert_eq!(policy_rows(&ps)[1]["group"], "groups/x");
    }

    #[test]
    fn required_alerts_accept_the_console_name() {
        let on = |n: &str| json!({"name": n, "active": true});
        let mut alerts: Vec<Value> = SCUBA_REQUIRED_ALERTS.iter().map(|n| on(n)).collect();
        assert!(required_alerts_off(&alerts).is_empty());
        alerts.retain(|a| a["name"] != "Super admin password reset" && a["name"] != "Leaked password");
        alerts.push(on("Admin password reset"));
        assert_eq!(required_alerts_off(&alerts), ["Leaked password"]);
    }

    #[test]
    fn alerts_report_state_severity_and_recipients() {
        let a = |state: &str, order: f64| {
            policy(ALERTS, "orgUnits/root", "ADMIN", order, json!({"displayName": "Leaked password", "state": state,
                "action": {"alertCenterAction": {"recipients": [{"allSuperAdmins": true}], "alertCenterConfig": {"severity": "HIGH"}}}}))
        };
        let rows = alert_rows(&[a("INACTIVE", 1.0), a("ACTIVE", 2.0)]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["active"], true);
        assert_eq!(rows[0]["severity_rank"], 3);
        assert_eq!(rows[0]["notifies_super_admins"], true);
    }
}
