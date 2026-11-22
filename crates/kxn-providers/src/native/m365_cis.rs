//! What the CIS Microsoft 365 Foundations Benchmark v7.0.0 asks of more than
//! one object at a time, computed once per tenant so a rule reads a single
//! field.
//!
//! "Is there a Conditional Access policy that requires MFA of every
//! administrator role, on every resource?" is a question about the whole set
//! of policies, not about any one of them; the rule engine evaluates rules row
//! by row, so the answer is worked out here, with the audit procedure of the
//! benchmark as the specification, and the policies that satisfy it are kept
//! as evidence.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{json, Value};

pub(crate) const GLOBAL_ADMINISTRATOR: &str = "62e90394-69f5-4237-9190-012177145e10";
pub(crate) const PRIVILEGED_ROLE_ADMINISTRATOR: &str = "e8611ab8-c189-46e8-94e1-60213ab1f814";

/// The directory roles CIS 5.2.2.1, 5.2.2.4 and 5.2.2.5 require a policy to
/// target "at a minimum".
pub(crate) const ADMIN_ROLES: &[(&str, &str)] = &[
    ("9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "Application Administrator"),
    ("c4e39bd9-1100-46d3-8c65-fb160da0071f", "Authentication Administrator"),
    ("b0f54661-2d74-4c50-afa3-1ec803f12efe", "Billing Administrator"),
    ("158c047a-c907-4556-b7ef-446551a6b5f7", "Cloud Application Administrator"),
    ("b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "Conditional Access Administrator"),
    ("29232cdf-9323-42fd-ade2-1d097af3e4de", "Exchange Administrator"),
    (GLOBAL_ADMINISTRATOR, "Global Administrator"),
    ("f2ef992c-3afb-46b9-b7cf-a126ee74c451", "Global Reader"),
    ("729827e3-9c14-49f7-bb1b-9608f156bbb8", "Helpdesk Administrator"),
    ("966707d0-3269-4727-9be2-8c3a10f19b9d", "Password Administrator"),
    ("7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "Privileged Authentication Administrator"),
    (PRIVILEGED_ROLE_ADMINISTRATOR, "Privileged Role Administrator"),
    ("194ae4cb-b126-40b2-bd5b-6091b380977d", "Security Administrator"),
    ("f28a1f50-f6e7-4571-818b-6a12f2af6b6c", "SharePoint Administrator"),
    ("fe930be7-5e62-47db-91af-98c3a49a38b1", "User Administrator"),
];

/// CIS 5.3.3: the six privileged roles that each need an access review.
pub(crate) const REVIEWED_ROLES: &[&str] = &[
    GLOBAL_ADMINISTRATOR,
    PRIVILEGED_ROLE_ADMINISTRATOR,
    "29232cdf-9323-42fd-ade2-1d097af3e4de",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
    "69091246-20e8-4a56-aa4d-066075b2a7a8",
    "194ae4cb-b126-40b2-bd5b-6091b380977d",
];

const INTUNE_ENROLLMENT_APP: &str = "d4ebce55-015a-49b5-a083-c84d1797ae8c";
const TOKEN_PROTECTION_APPS: &[&str] = &[
    "00000002-0000-0ff1-ce00-000000000000", // Office 365 Exchange Online
    "00000003-0000-0ff1-ce00-000000000000", // Office 365 SharePoint Online
    "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe", // Microsoft Teams Services
];
const PHISHING_RESISTANT: &[&str] = &["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"];

// ── Conditional Access (5.2.2) ──────────────────────────────────────────────

fn strs(v: &Value) -> Vec<&str> {
    v.as_array().into_iter().flatten().filter_map(Value::as_str).collect()
}

fn has(v: &Value, wanted: &str) -> bool {
    strs(v).iter().any(|s| s.eq_ignore_ascii_case(wanted))
}

fn enabled(p: &Value) -> bool {
    p["state"] == "enabled"
}

fn all_users(p: &Value) -> bool {
    has(&p["conditions"]["users"]["includeUsers"], "All")
}

fn all_resources(p: &Value) -> bool {
    has(&p["conditions"]["applications"]["includeApplications"], "All")
}

fn admin_roles(p: &Value) -> bool {
    let included: HashSet<&str> = strs(&p["conditions"]["users"]["includeRoles"]).into_iter().collect();
    ADMIN_ROLES.iter().all(|(id, _)| included.contains(id))
}

fn requires_mfa(p: &Value) -> bool {
    has(&p["grantControls"]["builtInControls"], "mfa")
        || p["grantControls"]["authenticationStrength"]["id"].as_str().is_some_and(|s| !s.is_empty())
}

fn blocks(p: &Value) -> bool {
    has(&p["grantControls"]["builtInControls"], "block")
}

fn sign_in_every_time(p: &Value) -> bool {
    let f = &p["sessionControls"]["signInFrequency"];
    f["isEnabled"] == true && f["frequencyInterval"] == "everyTime"
}

/// Reauthentication interval of a time-based sign-in frequency, in hours.
fn sign_in_hours(p: &Value) -> Option<f64> {
    let f = &p["sessionControls"]["signInFrequency"];
    if f["isEnabled"] != true || f["frequencyInterval"] == "everyTime" {
        return None;
    }
    let value = f["value"].as_f64()?;
    match f["type"].as_str()? {
        "hours" => Some(value),
        "days" => Some(value * 24.0),
        _ => None,
    }
}

/// Only compliant-device / hybrid-joined grants, any one of them sufficing.
fn device_grant_only(p: &Value) -> bool {
    let controls = strs(&p["grantControls"]["builtInControls"]);
    controls.contains(&"compliantDevice")
        && controls.iter().all(|c| matches!(*c, "compliantDevice" | "domainJoinedDevice"))
        && p["grantControls"]["operator"].as_str().is_some_and(|o| o.eq_ignore_ascii_case("OR"))
}

/// One named Conditional Access requirement of the benchmark.
type CaTest = fn(&Value, &CaContext) -> bool;

/// What a policy is judged against besides itself.
pub(crate) struct CaContext {
    trusted_locations: HashSet<String>,
    untrusted_locations: HashSet<String>,
}

impl CaContext {
    pub(crate) fn new(named_locations: &[Value]) -> Self {
        let mut trusted = HashSet::new();
        let mut untrusted = HashSet::new();
        for l in named_locations {
            let Some(id) = l["id"].as_str() else { continue };
            if l["isTrusted"] == true {
                trusted.insert(id.to_string());
            } else {
                untrusted.insert(id.to_string());
            }
        }
        CaContext { trusted_locations: trusted, untrusted_locations: untrusted }
    }
}

/// (field of the `tenant` row, CIS control, test). A policy must be enabled
/// to count: report-only and disabled policies enforce nothing.
pub(crate) const CA_CONTROLS: &[(&str, &str, CaTest)] = &[
    ("ca_mfa_admins", "5.2.2.1", |p, _| admin_roles(p) && all_resources(p) && requires_mfa(p)),
    ("ca_mfa_all_users", "5.2.2.2", |p, _| all_users(p) && all_resources(p) && requires_mfa(p)),
    ("ca_block_legacy_auth", "5.2.2.3", |p, _| {
        let apps = &p["conditions"]["clientAppTypes"];
        all_users(p) && all_resources(p) && has(apps, "exchangeActiveSync") && has(apps, "other") && blocks(p)
    }),
    ("ca_admin_sign_in_frequency", "5.2.2.4", |p, _| {
        let browser = &p["sessionControls"]["persistentBrowser"];
        admin_roles(p)
            && all_resources(p)
            && (sign_in_every_time(p) || sign_in_hours(p).is_some_and(|h| h <= 4.0))
            && browser["isEnabled"] == true
            && browser["mode"] == "never"
    }),
    ("ca_admin_phishing_resistant_mfa", "5.2.2.5", |p, _| {
        let combos = strs(&p["grantControls"]["authenticationStrength"]["allowedCombinations"]);
        admin_roles(p)
            && all_resources(p)
            && !combos.is_empty()
            && combos.iter().all(|c| PHISHING_RESISTANT.contains(c))
    }),
    ("ca_user_risk", "5.2.2.6", |p, _| {
        all_users(p)
            && all_resources(p)
            && has(&p["conditions"]["userRiskLevels"], "high")
            && has(&p["grantControls"]["builtInControls"], "passwordChange")
            && requires_mfa(p)
            && sign_in_every_time(p)
    }),
    ("ca_sign_in_risk", "5.2.2.7", |p, _| {
        let levels = &p["conditions"]["signInRiskLevels"];
        all_users(p)
            && all_resources(p)
            && has(levels, "high")
            && has(levels, "medium")
            && (blocks(p) || (requires_mfa(p) && sign_in_every_time(p)))
    }),
    ("ca_block_sign_in_risk", "5.2.2.8", |p, _| {
        let levels = &p["conditions"]["signInRiskLevels"];
        all_users(p)
            && all_resources(p)
            && strs(&p["conditions"]["applications"]["excludeApplications"]).is_empty()
            && has(levels, "high")
            && has(levels, "medium")
            && blocks(p)
    }),
    ("ca_managed_device", "5.2.2.9", |p, _| all_users(p) && all_resources(p) && device_grant_only(p)),
    ("ca_managed_device_for_security_info", "5.2.2.10", |p, _| {
        all_users(p)
            && strs(&p["conditions"]["applications"]["includeUserActions"]) == ["urn:user:registersecurityinfo"]
            && device_grant_only(p)
    }),
    ("ca_intune_enrollment_reauthentication", "5.2.2.11", |p, _| {
        all_users(p)
            && has(&p["conditions"]["applications"]["includeApplications"], INTUNE_ENROLLMENT_APP)
            && requires_mfa(p)
            && sign_in_every_time(p)
    }),
    ("ca_block_device_code_flow", "5.2.2.12", |p, _| {
        all_users(p)
            && all_resources(p)
            && has(&p["conditions"]["authenticationFlows"]["transferMethods"], "deviceCodeFlow")
            && blocks(p)
    }),
    ("ca_all_users_sign_in_frequency", "5.2.2.13", |p, _| {
        let c = &p["conditions"];
        strs(&c["signInRiskLevels"]).is_empty()
            && strs(&c["userRiskLevels"]).is_empty()
            && all_users(p)
            && all_resources(p)
            && sign_in_hours(p).is_some_and(|h| h <= 7.0 * 24.0)
    }),
    ("ca_block_untrusted_locations", "5.2.2.15", |p, ctx| {
        let l = &p["conditions"]["locations"];
        all_users(p)
            && all_resources(p)
            && strs(&l["includeLocations"]).iter().any(|id| ctx.untrusted_locations.contains(*id))
            && strs(&l["excludeLocations"])
                .iter()
                .any(|id| *id == "AllTrusted" || ctx.trusted_locations.contains(*id))
            && blocks(p)
    }),
    ("ca_token_protection", "5.2.2.16", |p, _| {
        let users = strs(&p["conditions"]["users"]["includeUsers"]);
        let apps = &p["conditions"]["applications"]["includeApplications"];
        !(users.is_empty() || users == ["None"])
            && TOKEN_PROTECTION_APPS.iter().all(|a| has(apps, a))
            && has(&p["conditions"]["platforms"]["includePlatforms"], "windows")
            && strs(&p["conditions"]["clientAppTypes"]) == ["mobileAppsAndDesktopClients"]
            && p["sessionControls"]["secureSignInSession"]["isEnabled"] == true
    }),
    ("ca_block_authentication_transfer", "5.2.2.17", |p, _| {
        all_users(p)
            && all_resources(p)
            && has(&p["conditions"]["authenticationFlows"]["transferMethods"], "authenticationTransfer")
            && blocks(p)
    }),
    // 1.3.2, step 2: Office 365 in the browser under app-enforced restrictions.
    ("ca_app_enforced_restrictions", "1.3.2", |p, _| {
        all_users(p)
            && strs(&p["conditions"]["applications"]["includeApplications"]) == ["Office365"]
            && strs(&p["conditions"]["clientAppTypes"]) == ["browser"]
            && p["sessionControls"]["applicationEnforcedRestrictions"]["isEnabled"] == true
    }),
];

/// Every CA requirement as `field: bool`, plus `ca_matches`: the enabled
/// policies satisfying each one, by display name.
pub(crate) fn conditional_access_fields(policies: &[Value], named_locations: &[Value]) -> serde_json::Map<String, Value> {
    let ctx = CaContext::new(named_locations);
    let mut out = serde_json::Map::new();
    let mut matches = serde_json::Map::new();
    for (field, _, test) in CA_CONTROLS {
        let names: Vec<Value> = policies
            .iter()
            .filter(|p| enabled(p) && test(p, &ctx))
            .map(|p| p["displayName"].clone())
            .collect();
        out.insert((*field).to_string(), Value::Bool(!names.is_empty()));
        matches.insert((*field).to_string(), Value::Array(names));
    }
    out.insert(
        "trusted_named_location".into(),
        Value::Bool(named_locations.iter().any(|l| {
            l["@odata.type"] == "#microsoft.graph.ipNamedLocation"
                && l["isTrusted"] == true
                && l["ipRanges"].as_array().is_some_and(|r| !r.is_empty())
        })),
    );
    out.insert("ca_matches".into(), Value::Object(matches));
    out
}

// ── CISA SCuBA (ScubaGear) Conditional Access ───────────────────────────────

/// ScubaGear's default "highly privileged roles" (MS.AAD.3.6, 7.x).
pub(crate) const SCUBA_PRIVILEGED_ROLES: &[&str] = &[
    GLOBAL_ADMINISTRATOR,
    PRIVILEGED_ROLE_ADMINISTRATOR,
    "fe930be7-5e62-47db-91af-98c3a49a38b1", // User Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", // SharePoint Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de", // Exchange Administrator
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", // Hybrid Identity Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", // Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7", // Cloud Application Administrator
];

fn no_excluded_roles(p: &Value) -> bool {
    strs(&p["conditions"]["users"]["excludeRoles"]).is_empty()
}

fn phishing_resistant(p: &Value) -> bool {
    let combos = strs(&p["grantControls"]["authenticationStrength"]["allowedCombinations"]);
    !combos.is_empty() && combos.iter().all(|c| PHISHING_RESISTANT.contains(c))
}

/// The policies ScubaGear's checks look for, as `tenant` fields.
pub(crate) const SCUBA_CA_CONTROLS: &[(&str, CaTest)] = &[
    ("scuba_block_high_risk_users", |p, _| {
        all_users(p) && all_resources(p) && no_excluded_roles(p) && has(&p["conditions"]["userRiskLevels"], "high") && blocks(p)
    }),
    ("scuba_block_high_risk_sign_ins", |p, _| {
        all_users(p) && all_resources(p) && no_excluded_roles(p) && has(&p["conditions"]["signInRiskLevels"], "high") && blocks(p)
    }),
    ("scuba_phishing_resistant_mfa_all_users", |p, _| {
        all_users(p) && all_resources(p) && no_excluded_roles(p) && phishing_resistant(p)
    }),
    ("scuba_phishing_resistant_mfa_privileged_roles", |p, _| {
        let included: HashSet<&str> = strs(&p["conditions"]["users"]["includeRoles"]).into_iter().collect();
        all_resources(p) && no_excluded_roles(p) && SCUBA_PRIVILEGED_ROLES.iter().all(|r| included.contains(r)) && phishing_resistant(p)
    }),
];

pub(crate) fn scuba_ca_fields(policies: &[Value], named_locations: &[Value]) -> serde_json::Map<String, Value> {
    let ctx = CaContext::new(named_locations);
    SCUBA_CA_CONTROLS
        .iter()
        .map(|(field, test)| ((*field).to_string(), Value::Bool(policies.iter().any(|p| enabled(p) && test(p, &ctx)))))
        .collect()
}

// ── Roles and users (1.1.x, 5.3.x) ──────────────────────────────────────────

/// Licences an administrator account may hold (CIS 1.1.4): Entra ID P1/P2
/// only, never a productivity suite.
const ADMIN_LICENCES: &[&str] = &["AAD_PREMIUM", "AAD_PREMIUM_P2"];

/// A role counts as privileged for 1.1.1 and 1.1.4 when its name says
/// "Administrator", plus Global Reader: the benchmark's own filter.
pub(crate) fn is_admin_role_name(name: &str) -> bool {
    name.contains("Administrator") || name == "Global Reader"
}

pub(crate) struct Directory<'a> {
    /// `roleAssignments?$expand=principal` rows.
    pub assignments: &'a [Value],
    /// roleDefinitionId → displayName.
    pub role_names: HashMap<String, String>,
    /// group id → its transitive user members.
    pub group_members: HashMap<String, Vec<Value>>,
    /// userId → user (with `assignedLicenses`, `onPremisesSyncEnabled`).
    pub users: HashMap<String, &'a Value>,
    /// skuId → skuPartNumber.
    pub skus: HashMap<String, String>,
}

impl Directory<'_> {
    /// The users holding `role_id`, directly or through a role-assignable group.
    fn holders(&self, role_filter: impl Fn(&str, &str) -> bool) -> BTreeMap<String, Value> {
        let mut out = BTreeMap::new();
        for a in self.assignments {
            let role_id = a["roleDefinitionId"].as_str().unwrap_or("");
            let role_name = self.role_names.get(role_id).map(String::as_str).unwrap_or("");
            if !role_filter(role_id, role_name) {
                continue;
            }
            let principal = &a["principal"];
            match principal["@odata.type"].as_str() {
                Some("#microsoft.graph.user") => {
                    if let Some(id) = principal["id"].as_str() {
                        out.insert(id.to_string(), principal.clone());
                    }
                }
                Some("#microsoft.graph.group") => {
                    let gid = principal["id"].as_str().unwrap_or("");
                    for m in self.group_members.get(gid).into_iter().flatten() {
                        if m["@odata.type"] == "#microsoft.graph.user" {
                            if let Some(id) = m["id"].as_str() {
                                out.insert(id.to_string(), m.clone());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    pub(crate) fn fields(&self) -> serde_json::Map<String, Value> {
        let gas = self.holders(|id, _| id == GLOBAL_ADMINISTRATOR);
        let admins = self.holders(|_, name| is_admin_role_name(name));
        let upn = |id: &str, fallback: &Value| -> Value {
            self.users.get(id).map(|u| u["userPrincipalName"].clone()).unwrap_or_else(|| fallback["userPrincipalName"].clone())
        };
        let synced: Vec<Value> = admins
            .iter()
            .filter(|(id, _)| self.users.get(*id).is_some_and(|u| u["onPremisesSyncEnabled"] == true))
            .map(|(id, p)| upn(id, p))
            .collect();
        let licensed: Vec<Value> = admins
            .iter()
            .filter_map(|(id, p)| {
                let user = self.users.get(id)?;
                let extra: Vec<String> = user["assignedLicenses"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|l| l["skuId"].as_str())
                    .map(|sku| self.skus.get(sku).cloned().unwrap_or_else(|| sku.to_string()))
                    .filter(|part| !ADMIN_LICENCES.contains(&part.as_str()))
                    .collect();
                (!extra.is_empty()).then(|| json!({ "user": upn(id, p), "licenses": extra }))
            })
            .collect();
        // MS.AAD.7.2: fewer Global Administrators than holders of finer roles.
        let finer = admins.keys().filter(|id| !gas.contains_key(*id)).count();
        let mut out = serde_json::Map::new();
        out.insert("privileged_users_not_global_admin".into(), json!(finer));
        out.insert("least_privilege_ok".into(), json!(finer > 0 && gas.len() < finer));
        out.insert("global_admins".into(), json!(gas.len()));
        out.insert("global_admin_users".into(), json!(gas.iter().map(|(id, p)| upn(id, p)).collect::<Vec<_>>()));
        out.insert("synced_admins".into(), Value::Array(synced));
        out.insert("licensed_admins".into(), Value::Array(licensed));
        out
    }
}

/// CIS 5.3.1: every active privileged assignment of a user or group is a
/// just-in-time activation, every service principal's is time-bound; at most
/// two permanent Global Administrators (the break-glass accounts).
pub(crate) fn pim_violations(instances: &[Value], privileged_roles: &HashSet<String>) -> Vec<Value> {
    let mut permanent_gas = 0;
    let mut out = Vec::new();
    for i in instances {
        let role = i["roleDefinitionId"].as_str().unwrap_or("");
        if !privileged_roles.contains(role) {
            continue;
        }
        let kind = i["principal"]["@odata.type"].as_str().unwrap_or("");
        let assignment = i["assignmentType"].as_str().unwrap_or("");
        let ok = match kind {
            "#microsoft.graph.servicePrincipal" => assignment == "Assigned" && !i["endDateTime"].is_null(),
            _ if assignment == "Activated" => true,
            _ if role == GLOBAL_ADMINISTRATOR && assignment == "Assigned" => {
                permanent_gas += 1;
                permanent_gas <= 2
            }
            _ => false,
        };
        if !ok {
            out.push(json!({
                "principal": i["principal"]["displayName"],
                "role": role,
                "assignment_type": assignment,
            }));
        }
    }
    out
}

fn monthly_or_more(d: &Value) -> bool {
    matches!(d["settings"]["recurrence"]["pattern"]["type"].as_str(), Some("absoluteMonthly" | "weekly"))
}

fn review_settings_ok(d: &Value, default_decision: &str) -> bool {
    let s = &d["settings"];
    monthly_or_more(d)
        && d["reviewers"].as_array().is_some_and(|r| !r.is_empty())
        && s["mailNotificationsEnabled"] == true
        && s["reminderNotificationsEnabled"] == true
        && s["justificationRequiredOnApproval"] == true
        && s["instanceDurationInDays"].as_i64().is_some_and(|d| d <= 14)
        && s["autoApplyDecisionsEnabled"] == true
        && s["defaultDecision"] == default_decision
        && s["recurrence"]["range"]["type"] == "noEnd"
}

fn scope_queries(d: &Value) -> Vec<String> {
    let scope = &d["scope"];
    let mut q: Vec<String> = scope["query"].as_str().map(String::from).into_iter().collect();
    for rs in scope["resourceScopes"].as_array().into_iter().flatten() {
        q.extend(rs["query"].as_str().map(String::from));
    }
    for ps in scope["principalScopes"].as_array().into_iter().flatten() {
        q.extend(ps["query"].as_str().map(String::from));
    }
    q
}

/// CIS 5.3.2: an access review of guest users, monthly, auto-applied, denying
/// on no answer.
pub(crate) fn guest_access_review(definitions: &[Value]) -> bool {
    definitions.iter().any(|d| {
        scope_queries(d).iter().any(|q| q.contains("userType eq 'Guest'")) && review_settings_ok(d, "Deny")
    })
}

/// CIS 5.3.3: the privileged roles of [`REVIEWED_ROLES`] without a compliant
/// access review of their eligible and active assignments.
pub(crate) fn unreviewed_privileged_roles(definitions: &[Value]) -> Vec<&'static str> {
    REVIEWED_ROLES
        .iter()
        .copied()
        .filter(|role| {
            !definitions.iter().any(|d| {
                let qs = scope_queries(d);
                let principal_qs: Vec<&str> = d["scope"]["principalScopes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|p| p["query"].as_str())
                    .collect();
                qs.iter().any(|q| q.contains("/directory/roleDefinitions/") && q.contains(role))
                    && principal_qs.iter().any(|q| q.contains("/v1.0/users"))
                    && principal_qs.iter().any(|q| q.contains("/v1.0/groups"))
                    && review_settings_ok(d, "None")
            })
        })
        .collect()
}

/// CIS 5.3.4/5.3.5: activating the role needs an approval, with an approver.
pub(crate) fn approval_required(rule: &Value) -> bool {
    let setting = &rule["setting"];
    setting["isApprovalRequired"] == true
        && setting["approvalStages"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|s| s["primaryApprovers"].as_array().is_some_and(|a| !a.is_empty()))
}

// ── Entra settings parsed out of their JSON-in-a-string envelopes ───────────

/// CIS 1.3.2: the idle web session timeout, in seconds, of the
/// activity-based timeout policy; `None` when no policy sets one.
pub(crate) fn idle_session_timeout_seconds(policies: &[Value]) -> Option<i64> {
    policies.iter().find_map(|p| {
        let def = p["definition"].as_array()?.first()?.as_str()?;
        let def: Value = serde_json::from_str(def).ok()?;
        let apps = def["ActivityBasedTimeoutPolicy"]["ApplicationPolicies"].as_array()?;
        apps.iter().find_map(|a| a["WebSessionIdleTimeout"].as_str().and_then(timespan_seconds))
    })
}

/// A .NET TimeSpan ("03:00:00", "1.00:00:00") in seconds.
pub(crate) fn timespan_seconds(s: &str) -> Option<i64> {
    let (days, rest) = match s.split_once('.') {
        Some((d, r)) if !d.contains(':') => (d.parse::<i64>().ok()?, r),
        _ => (0, s),
    };
    let parts: Vec<i64> = rest.split(':').map(|p| p.split('.').next().unwrap_or("0").parse().ok()).collect::<Option<_>>()?;
    let [h, m, sec] = parts[..] else { return None };
    Some(days * 86_400 + h * 3_600 + m * 60 + sec)
}

/// CIS 5.1.6.1: the B2B invitation domain policy. Compliant when it is an
/// allow list (possibly empty); a block list, or no policy at all, is not.
pub(crate) fn b2b_invitations_allow_list(legacy_policies: &[Value]) -> Value {
    let Some(policy) = legacy_policies.iter().find(|p| p["type"] == "B2BManagementPolicy") else {
        return json!({ "b2b_invitations_restricted": false, "b2b_allowed_domains": null });
    };
    let def = policy["definition"].as_array().and_then(|d| d.first()).and_then(Value::as_str).unwrap_or("{}");
    let def: Value = serde_json::from_str(def).unwrap_or(Value::Null);
    let domains = &def["B2BManagementPolicy"]["InvitationsAllowedAndBlockedDomainsPolicy"];
    let restricted = domains.get("AllowedDomains").is_some() && domains.get("BlockedDomains").is_none();
    json!({ "b2b_invitations_restricted": restricted, "b2b_allowed_domains": domains.get("AllowedDomains").cloned().unwrap_or(Value::Null) })
}

/// Settings of a directory setting object (`groupSettings`) as a name → value
/// map, with "true"/"false" and integers read as such.
pub(crate) fn setting_values(setting: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for v in setting["values"].as_array().into_iter().flatten() {
        let (Some(name), Some(raw)) = (v["name"].as_str(), v["value"].as_str()) else { continue };
        let value = match raw {
            "true" | "True" => Value::Bool(true),
            "false" | "False" => Value::Bool(false),
            _ => raw.parse::<i64>().map(Value::from).unwrap_or_else(|_| Value::String(raw.to_string())),
        };
        out.insert(name.to_string(), value);
    }
    Value::Object(out)
}

/// CIS 5.1.5.3–5.1.5.6: one restriction of the default app management policy,
/// enforced for both applications and service principals, for apps created at
/// any time up to now. `max_days` bounds `maxLifetime` when given.
pub(crate) fn app_restriction_enforced(policy: &Value, kind: &str, restriction: &str, max_days: Option<i64>) -> bool {
    if policy["isEnabled"] != true {
        return false;
    }
    let now = chrono::Utc::now();
    ["applicationRestrictions", "servicePrincipalRestrictions"].iter().all(|side| {
        policy[*side][kind].as_array().into_iter().flatten().any(|r| {
            let since = r["restrictForAppsCreatedAfterDateTime"].as_str().unwrap_or("0001-01-01T00:00:00Z");
            let in_force = since.starts_with("0001-01-01")
                || chrono::DateTime::parse_from_rfc3339(since).is_ok_and(|d| d <= now);
            r["restrictionType"] == restriction
                && r["state"] == "enabled"
                && in_force
                && max_days.is_none_or(|max| r["maxLifetime"].as_str().and_then(iso_days).is_some_and(|d| d <= max))
        })
    })
}

/// Days of an ISO 8601 duration such as `P180D` or `P1Y`.
fn iso_days(d: &str) -> Option<i64> {
    let body = d.strip_prefix('P')?.split('T').next()?;
    let (mut total, mut num) = (0i64, String::new());
    for c in body.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let n: i64 = num.parse().ok()?;
        num.clear();
        total += n * match c {
            'Y' => 365,
            'M' => 30,
            'W' => 7,
            'D' => 1,
            _ => return None,
        };
    }
    Some(total)
}

const PASSWORD_RULE_TEMPLATE: &str = "5cf42378-d67d-4f36-ba46-e8b86229381d";
const UNIFIED_GROUP_TEMPLATE: &str = "62375ab9-6b52-47ed-826b-58e47e0e304b";

/// The password-rule and group-creation directory settings as maps, `null`
/// when the tenant never created them (the default state, which CIS 5.1.3.4
/// and 5.2.3.2 count as non-compliant).
pub(crate) fn directory_setting_fields(group_settings: &[Value]) -> serde_json::Map<String, Value> {
    let by_template = |t: &str| {
        group_settings.iter().find(|s| s["templateId"] == t).map(setting_values).unwrap_or(Value::Null)
    };
    let mut out = serde_json::Map::new();
    let password_rule = by_template(PASSWORD_RULE_TEMPLATE);
    // Without a password-rule setting the tenant runs on Entra's defaults:
    // ten attempts, sixty seconds (CIS 5.2.3.8 and 5.2.3.9 pass on them).
    out.insert("lockout_threshold".into(), password_rule["LockoutThreshold"].as_i64().map_or(json!(10), Value::from));
    out.insert(
        "lockout_duration_seconds".into(),
        password_rule["LockoutDurationInSeconds"].as_i64().map_or(json!(60), Value::from),
    );
    out.insert("password_rule_settings".into(), password_rule);
    out.insert("group_creation_settings".into(), by_template(UNIFIED_GROUP_TEMPLATE));
    out
}

/// CIS 4.2: the default platform restrictions (priority 0) block personally
/// owned devices, or the platform altogether, on every platform.
pub(crate) fn personal_enrollment_blocked(configurations: &[Value]) -> Value {
    let Some(c) = configurations.iter().find(|c| {
        c["id"].as_str().is_some_and(|id| id.ends_with("DefaultPlatformRestrictions")) && c["priority"] == 0
    }) else {
        return Value::Null;
    };
    let platforms = ["windowsRestriction", "iosRestriction", "androidForWorkRestriction", "macOSRestriction", "androidRestriction"];
    Value::Bool(platforms.iter().all(|p| c[*p]["personalDeviceEnrollmentBlocked"] == true || c[*p]["platformBlocked"] == true))
}

/// The authentication methods policy with its method configurations keyed by
/// id (`methods.Sms.state`), so a rule can name the method it reads.
pub(crate) fn authentication_methods_row(policy: &Value) -> Value {
    let mut row = policy.clone();
    let methods: serde_json::Map<String, Value> = policy["authenticationMethodConfigurations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| Some((m["id"].as_str()?.to_string(), m.clone())))
        .collect();
    row["methods"] = Value::Object(methods);
    row
}

// ── Intune ──────────────────────────────────────────────────────────────────

/// One Intune managed device, flattened to the fields rules are written against.
pub(crate) fn intune_device(d: &Value) -> Value {
    let os = d["operatingSystem"].as_str().unwrap_or("");
    let os_version = d["osVersion"].as_str().unwrap_or("");
    // Windows reports "10.0.<build>.<ubr>": the build and update revision are
    // what a cumulative update moves, and what a CVE's fixed version names.
    let (build, ubr) = if os.eq_ignore_ascii_case("windows") {
        let parts: Vec<&str> = os_version.split('.').collect();
        (parts.get(2).and_then(|p| p.parse::<u64>().ok()), parts.get(3).and_then(|p| p.parse::<u64>().ok()))
    } else {
        (None, None)
    };
    json!({
        "id": d["id"],
        "name": d["deviceName"],
        "os": os,
        "os_version": os_version,
        "build": build,
        "ubr": ubr,
        "compliance_state": d["complianceState"],
        "last_sync": d["lastSyncDateTime"],
        "enrolled": d["enrolledDateTime"],
        "encrypted": d["isEncrypted"],
        // Graph answers "True", "False" or "Unknown" as a string.
        "jailbroken": match d["jailBroken"].as_str().map(str::to_ascii_lowercase).as_deref() {
            Some("true") => json!(true),
            Some("false") => json!(false),
            _ => Value::Null,
        },
        "supervised": d["isSupervised"],
        "model": d["model"],
        "manufacturer": d["manufacturer"],
        "serial": d["serialNumber"],
        "owner_type": d["managedDeviceOwnerType"],
        "management_agent": d["managementAgent"],
        "user": d["userPrincipalName"],
        "entra_device_id": d["azureADDeviceId"],
    })
}

/// The platform a compliance policy type applies to.
fn compliance_policy_platform(odata_type: &str) -> Option<&'static str> {
    let t = odata_type.to_ascii_lowercase();
    if t.contains("windows") {
        Some("windows")
    } else if t.contains("androidworkprofile") || t.contains("androiddeviceowner") || t.contains("android") {
        Some("android")
    } else if t.contains("ios") {
        Some("ios")
    } else if t.contains("macos") {
        Some("macos")
    } else {
        None
    }
}

/// Platforms with enrolled devices but no assigned compliance policy: their
/// devices are judged against nothing but the tenant default (CIS 4.1).
pub(crate) fn platforms_without_compliance_policy(devices: &[Value], policies: &[Value]) -> Vec<String> {
    let covered: HashSet<&str> = policies
        .iter()
        .filter(|p| p["assignments"].as_array().is_some_and(|a| !a.is_empty()))
        .filter_map(|p| p["@odata.type"].as_str().and_then(compliance_policy_platform))
        .collect();
    let mut missing: Vec<String> = devices
        .iter()
        .filter_map(|d| d["operatingSystem"].as_str())
        .map(|os| match os.to_ascii_lowercase().as_str() {
            "ipados" | "ios" => "ios".to_string(),
            other => other.to_string(),
        })
        .filter(|os| ["windows", "android", "ios", "macos"].contains(&os.as_str()) && !covered.contains(os.as_str()))
        .collect();
    missing.sort();
    missing.dedup();
    missing
}

// ── Exchange Online and Defender for Office 365 ─────────────────────────────

/// The 53 file types of the default common attachment filter (CIS 2.1.2).
pub(crate) const DEFAULT_FILE_TYPES: &[&str] = &[
    "ani", "apk", "app", "appx", "arj", "bat", "cab", "cmd", "com", "deb", "dex", "dll", "docm", "elf", "exe",
    "hta", "img", "iso", "jar", "jnlp", "kext", "lha", "lib", "library", "lnk", "lzh", "macho", "msc", "msi",
    "msix", "msp", "mst", "pif", "ppa", "ppam", "reg", "rev", "scf", "scr", "sct", "sys", "uif", "vb", "vbe",
    "vbs", "vxd", "wsc", "wsf", "wsh", "xll", "xz", "z", "ace",
];

/// The comprehensive extension list of CIS 2.1.11.
pub(crate) const COMPREHENSIVE_FILE_TYPES: &[&str] = &[
    "7z", "a3x", "ace", "ade", "adp", "ani", "apk", "app", "appinstaller", "applescript", "application",
    "appref-ms", "appx", "appxbundle", "arj", "asd", "asx", "bas", "bat", "bgi", "bz2", "cab", "chm", "cmd",
    "com", "cpl", "crt", "cs", "csh", "daa", "dbf", "dcr", "deb", "desktopthemepackfile", "dex", "diagcab",
    "dif", "dir", "dll", "dmg", "doc", "docm", "dot", "dotm", "elf", "eml", "exe", "fxp", "gadget", "gz",
    "hlp", "hta", "htc", "htm", "html", "hwpx", "ics", "img", "inf", "ins", "iqy", "iso", "isp", "jar", "jnlp",
    "js", "jse", "kext", "ksh", "lha", "lib", "library", "library-ms", "lnk", "lzh", "macho", "mam", "mda",
    "mdb", "mde", "mdt", "mdw", "mdz", "mht", "mhtml", "mof", "msc", "msi", "msix", "msp", "msrcincident",
    "mst", "ocx", "odt", "ops", "oxps", "pcd", "pif", "plg", "pot", "potm", "ppa", "ppam", "ppkg", "pps",
    "ppsm", "ppt", "pptm", "prf", "prg", "ps1", "ps11", "ps11xml", "ps1xml", "ps2", "ps2xml", "psc1", "psc2",
    "pub", "py", "pyc", "pyo", "pyw", "pyz", "pyzw", "rar", "reg", "rev", "rtf", "scf", "scpt", "scr", "sct",
    "searchConnector-ms", "service", "settingcontent-ms", "sh", "shb", "shs", "shtm", "shtml", "sldm", "slk",
    "so", "spl", "stm", "svg", "swf", "sys", "tar", "theme", "themepack", "timer", "uif", "url", "uue", "vb",
    "vbe", "vbs", "vhd", "vhdx", "vxd", "wbk", "website", "wim", "wiz", "ws", "wsc", "wsf", "wsh", "xla",
    "xlam", "xlc", "xll", "xlm", "xls", "xlsb", "xlsm", "xlt", "xltm", "xlw", "xnk", "xps", "xsl", "xz", "z",
];

fn missing_types(policy: &Value, reference: &[&str]) -> Vec<String> {
    let have: HashSet<String> = strs(&policy["FileTypes"]).iter().map(|t| t.to_ascii_lowercase()).collect();
    reference.iter().filter(|t| !have.contains(&t.to_ascii_lowercase())).map(|t| (*t).to_string()).collect()
}

/// Malware filter policy with what CIS 2.1.2 and 2.1.11 read from it.
pub(crate) fn malware_policy_row(policy: &Value, rules: &[Value]) -> Value {
    let mut row = policy.clone();
    let name = policy["Identity"].as_str().or(policy["Name"].as_str()).unwrap_or("");
    let rule_state = rules
        .iter()
        .find(|r| r["MalwareFilterPolicy"].as_str() == Some(name))
        .map(|r| r["State"].clone())
        .unwrap_or(Value::Null);
    let missing_comprehensive = missing_types(policy, COMPREHENSIVE_FILE_TYPES);
    let fail_threshold = (COMPREHENSIVE_FILE_TYPES.len() as f64 * 0.1) as usize;
    let comprehensive = strs(&policy["FileTypes"]).len() > 120
        && missing_comprehensive.len() < fail_threshold
        && policy["EnableFileFilter"] == true
        && rule_state == "Enabled";
    row["_missing_default_file_types"] = json!(missing_types(policy, DEFAULT_FILE_TYPES));
    row["_missing_comprehensive_file_types"] = json!(missing_comprehensive);
    row["_rule_state"] = rule_state;
    row["_comprehensive_filter"] = Value::Bool(comprehensive);
    row
}

const ADMIN_AUDIT: &[&str] = &[
    "ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete", "MailItemsAccessed", "Move", "MoveToDeletedItems",
    "SendAs", "SendOnBehalf", "Send", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions",
    "UpdateInboxRules",
];
const DELEGATE_AUDIT: &[&str] = &[
    "ApplyRecord", "Create", "FolderBind", "HardDelete", "Move", "MailItemsAccessed", "MoveToDeletedItems", "SendAs",
    "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules",
];
const OWNER_AUDIT: &[&str] = &[
    "ApplyRecord", "Create", "HardDelete", "MailboxLogin", "Move", "MailItemsAccessed", "MoveToDeletedItems", "Send",
    "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules",
];

/// A mailbox with the audit actions CIS 6.1.2 expects and does not find.
pub(crate) fn mailbox_row(mailbox: &Value) -> Value {
    let missing = |field: &str, expected: &[&str]| -> Value {
        let have = strs(&mailbox[field]);
        json!(expected.iter().filter(|a| !have.contains(a)).collect::<Vec<_>>())
    };
    let mut row = mailbox.clone();
    row["_audit_admin_missing"] = missing("AuditAdmin", ADMIN_AUDIT);
    row["_audit_delegate_missing"] = missing("AuditDelegate", DELEGATE_AUDIT);
    row["_audit_owner_missing"] = missing("AuditOwner", OWNER_AUDIT);
    row
}

/// The domain part of an address or a bare domain, lower-cased.
fn domain_of(address: &str) -> String {
    let a = address.trim().trim_start_matches("smtp:").trim_start_matches("SMTP:");
    a.rsplit('@').next().unwrap_or(a).to_ascii_lowercase()
}

/// A transport rule with what CIS 6.2.1 and 6.2.2 read from it.
pub(crate) fn transport_rule_row(rule: &Value, accepted_domains: &HashSet<String>) -> Value {
    let mut row = rule.clone();
    let external: Vec<&str> = strs(&rule["RedirectMessageTo"])
        .into_iter()
        .filter(|a| !accepted_domains.contains(&domain_of(a)))
        .collect();
    row["_external_redirects"] = json!(external);
    let scl_bypass = rule["SetSCL"].as_i64() == Some(-1) && !strs(&rule["SenderDomainIs"]).is_empty();
    row["_whitelists_sender_domains"] = Value::Bool(scl_bypass);
    row
}

/// A sharing policy with what MS.EXO.6.1/6.2 read: an entry for every
/// domain (`*`) sharing contacts or calendar.
pub(crate) fn sharing_policy_row(policy: &Value) -> Value {
    let mut row = policy.clone();
    let all_domains: Vec<&str> = strs(&policy["Domains"]).into_iter().filter(|d| d.contains('*')).collect();
    row["_shares_contacts_with_all_domains"] = json!(all_domains.iter().any(|d| d.contains("Contacts")));
    row["_shares_calendar_with_all_domains"] = json!(all_domains.iter().any(|d| d.contains("Calendar")));
    row
}

/// MS.EXO.7.1: an enforced transport rule tagging mail from outside the
/// organization (subject prefix).
pub(crate) fn external_sender_warning_rule(rules: &[Value]) -> bool {
    rules.iter().any(|r| {
        r["State"] == "Enabled"
            && r["Mode"] == "Enforce"
            && r["FromScope"] == "NotInOrganization"
            && r["PrependSubject"].as_str().is_some_and(|s| !s.is_empty())
    })
}

/// MS.SECURITYSUITE.2.x and 7.x: what at least one enabled anti-phishing
/// or Safe Links policy provides.
pub(crate) fn scuba_defender_fields(anti_phish: &[Value], safe_links: &[Value]) -> serde_json::Map<String, Value> {
    let phish: Vec<&Value> = anti_phish.iter().filter(|p| p["Enabled"] != false).collect();
    let links: Vec<&Value> = safe_links.iter().collect();
    let mut out = serde_json::Map::new();
    let mut put = |k: &str, v: bool| {
        out.insert(k.into(), Value::Bool(v));
    };
    put("scuba_user_impersonation", phish.iter().any(|p| p["EnableTargetedUserProtection"] == true && !strs(&p["TargetedUsersToProtect"]).is_empty()));
    put("scuba_domain_impersonation", phish.iter().any(|p| p["EnableOrganizationDomainsProtection"] == true));
    put("scuba_partner_domain_impersonation", phish.iter().any(|p| p["EnableTargetedDomainsProtection"] == true && !strs(&p["TargetedDomainsToProtect"]).is_empty()));
    put(
        "scuba_safety_tips",
        phish.iter().any(|p| {
            ["EnableFirstContactSafetyTips", "EnableSimilarUsersSafetyTips", "EnableSimilarDomainsSafetyTips", "EnableUnusualCharactersSafetyTips"]
                .iter()
                .all(|k| p[*k] == true)
        }),
    );
    put(
        "scuba_safe_links_everywhere",
        links.iter().any(|p| p["EnableSafeLinksForEmail"] == true && p["EnableSafeLinksForTeams"] == true && p["EnableSafeLinksForOffice"] == true),
    );
    put("scuba_safe_links_scan_downloads", links.iter().any(|p| p["ScanUrls"] == true));
    put("scuba_safe_links_track_clicks", links.iter().any(|p| p["TrackClicks"] == true));
    out
}

/// CIS 2.1.1: a Safe Links policy configured as the benchmark lists.
pub(crate) fn safe_links_cis(p: &Value) -> bool {
    p["EnableSafeLinksForEmail"] == true
        && p["EnableSafeLinksForTeams"] == true
        && p["EnableSafeLinksForOffice"] == true
        && p["TrackClicks"] == true
        && p["AllowClickThrough"] == false
        && p["ScanUrls"] == true
        && p["EnableForInternalSenders"] == true
        && p["DeliverMessageAfterScan"] == true
        && p["DisableUrlRewrite"] == false
}

/// CIS 2.1.4: a Safe Attachments policy that blocks and quarantines for admins.
pub(crate) fn safe_attachments_cis(p: &Value) -> bool {
    p["Enable"] == true && p["Action"] == "Block" && p["QuarantineTag"] == "AdminOnlyAccessPolicy"
}

/// CIS 2.1.7: an anti-phishing policy with every protection the benchmark lists.
pub(crate) fn anti_phish_cis(p: &Value) -> bool {
    p["Enabled"] != false
        && p["PhishThresholdLevel"].as_i64().is_some_and(|l| l >= 3)
        && p["EnableTargetedUserProtection"] == true
        && p["EnableOrganizationDomainsProtection"] == true
        && p["EnableMailboxIntelligence"] == true
        && p["EnableMailboxIntelligenceProtection"] == true
        && p["EnableSpoofIntelligence"] == true
        && p["TargetedUserProtectionAction"] == "Quarantine"
        && p["TargetedDomainProtectionAction"] == "Quarantine"
        && p["MailboxIntelligenceProtectionAction"] == "Quarantine"
        && p["EnableFirstContactSafetyTips"] == true
        && p["EnableSimilarUsersSafetyTips"] == true
        && p["EnableSimilarDomainsSafetyTips"] == true
        && p["EnableUnusualCharactersSafetyTips"] == true
        && p["HonorDmarcPolicy"] == true
        && !strs(&p["TargetedUsersToProtect"]).is_empty()
}

/// CIS 2.4.2: the strict preset rule is on and targets someone.
pub(crate) fn strict_preset_on(rules: &[Value]) -> bool {
    rules.iter().any(|r| {
        r["Identity"] == "Strict Preset Security Policy"
            && r["State"] == "Enabled"
            && ["SentTo", "SentToMemberOf", "RecipientDomainIs"].iter().any(|k| !strs(&r[*k]).is_empty())
    })
}

// ── Mail domains: SPF, DKIM, DMARC (2.1.8–2.1.10) ───────────────────────────

/// The qualifier an SPF record ends on (`-all`, `~all`, …) or its
/// `redirect=` target.
pub(crate) enum SpfEnd {
    All(String),
    Redirect(String),
    None,
}

pub(crate) fn spf_end(record: &str) -> SpfEnd {
    let terms: Vec<&str> = record.split_whitespace().collect();
    if let Some(r) = terms.iter().find_map(|t| t.strip_prefix("redirect=")) {
        return SpfEnd::Redirect(r.to_ascii_lowercase());
    }
    match terms.last() {
        Some(t) if t.ends_with("all") => SpfEnd::All((*t).to_string()),
        _ => SpfEnd::None,
    }
}

/// The tags of a DMARC record, keys lower-cased.
pub(crate) fn dmarc_tags(record: &str) -> HashMap<String, String> {
    record
        .split(';')
        .filter_map(|t| t.split_once('='))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect()
}

/// CIS 2.1.10: `v=DMARC1`, `p=quarantine|reject`, `pct` absent or 100, and
/// both aggregate (`rua`) and forensic (`ruf`) reports going somewhere.
/// `subdomain` applies the organizational domain's `sp=` when it has one.
pub(crate) fn dmarc_compliant(record: &str, subdomain: bool) -> bool {
    let tags = dmarc_tags(record);
    let policy = if subdomain { tags.get("sp").or(tags.get("p")) } else { tags.get("p") };
    tags.get("v").is_some_and(|v| v.eq_ignore_ascii_case("DMARC1"))
        && policy.is_some_and(|p| p.eq_ignore_ascii_case("quarantine") || p.eq_ignore_ascii_case("reject"))
        && tags.get("pct").is_none_or(|p| p == "100")
        && tags.get("rua").is_some_and(|v| v.starts_with("mailto:"))
        && tags.get("ruf").is_some_and(|v| v.starts_with("mailto:"))
}

// ── Teams (8.2.x, 8.6.1) ─────────────────────────────────────────────────────

fn global(rows: &[Value]) -> Value {
    rows.iter()
        .find(|r| r["Identity"] == "Global" || r["Identity"] == "Tag:Global")
        .or(rows.first())
        .cloned()
        .unwrap_or(Value::Null)
}

/// The external-access controls, each passing on either the Global external
/// access policy or the tenant federation settings, as the benchmark allows.
pub(crate) fn teams_fields(external_access_policies: &[Value], federation: &[Value]) -> serde_json::Map<String, Value> {
    let policy = global(external_access_policies);
    let fed = global(federation);
    let allowed = &fed["AllowedDomains"];
    let allowed_is_list = allowed.is_array() || allowed["AllowedDomain"].is_array();
    let mut out = serde_json::Map::new();
    out.insert(
        "teams_external_domains_restricted".into(),
        Value::Bool(policy["EnableFederationAccess"] == false || fed["AllowFederatedUsers"] == false || allowed_is_list),
    );
    out.insert(
        "teams_unmanaged_communication_disabled".into(),
        Value::Bool(policy["EnableTeamsConsumerAccess"] == false || fed["AllowTeamsConsumer"] == false),
    );
    out.insert(
        "teams_unmanaged_inbound_disabled".into(),
        Value::Bool(policy["EnableTeamsConsumerInbound"] == false || fed["AllowTeamsConsumerInbound"] == false),
    );
    out
}

/// CIS 8.6.1: users can report messages, and reports reach the organization.
pub(crate) fn user_reporting(messaging_policies: &[Value], submission: &[Value]) -> bool {
    let teams = global(messaging_policies)["AllowSecurityEndUserReporting"] == true;
    let defender = submission.iter().any(|s| {
        s["ReportJunkToCustomizedAddress"] == true
            && s["ReportNotJunkToCustomizedAddress"] == true
            && s["ReportPhishToCustomizedAddress"] == true
            && !strs(&s["ReportJunkAddresses"]).is_empty()
            && !strs(&s["ReportNotJunkAddresses"]).is_empty()
            && !strs(&s["ReportPhishAddresses"]).is_empty()
            && s["ReportChatMessageEnabled"] != false
            && s["ReportChatMessageToCustomizedAddressEnabled"] == true
    });
    teams && defender
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(v: Value) -> Value {
        let mut p = json!({"state": "enabled", "displayName": "p"});
        crate::native::m365_cis::tests::merge(&mut p, v);
        p
    }

    pub(super) fn merge(a: &mut Value, b: Value) {
        if let (Value::Object(a), Value::Object(b)) = (a, b) {
            for (k, v) in b {
                a.insert(k, v);
            }
        }
    }

    fn admin_ids() -> Vec<&'static str> {
        ADMIN_ROLES.iter().map(|(id, _)| *id).collect()
    }

    #[test]
    fn mfa_for_every_admin_role_on_every_resource_satisfies_5_2_2_1() {
        let p = policy(json!({
            "conditions": {"users": {"includeRoles": admin_ids()}, "applications": {"includeApplications": ["All"]}},
            "grantControls": {"builtInControls": ["mfa"]}
        }));
        let f = conditional_access_fields(&[p.clone()], &[]);
        assert_eq!(f["ca_mfa_admins"], true);
        assert_eq!(f["ca_mfa_all_users"], false);

        let mut partial = p.clone();
        partial["conditions"]["users"]["includeRoles"] = json!([GLOBAL_ADMINISTRATOR]);
        assert_eq!(conditional_access_fields(&[partial], &[])["ca_mfa_admins"], false);

        let mut report_only = p;
        report_only["state"] = json!("enabledForReportingButNotEnforced");
        assert_eq!(conditional_access_fields(&[report_only], &[])["ca_mfa_admins"], false);
    }

    #[test]
    fn an_authentication_strength_counts_as_mfa() {
        let p = policy(json!({
            "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}},
            "grantControls": {"builtInControls": [], "authenticationStrength": {"id": "00000000-0000-0000-0000-000000000002"}}
        }));
        assert_eq!(conditional_access_fields(&[p], &[])["ca_mfa_all_users"], true);
    }

    #[test]
    fn legacy_auth_is_blocked_only_for_both_client_types() {
        let mut p = policy(json!({
            "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]},
                           "clientAppTypes": ["exchangeActiveSync", "other"]},
            "grantControls": {"builtInControls": ["block"]}
        }));
        assert_eq!(conditional_access_fields(&[p.clone()], &[])["ca_block_legacy_auth"], true);
        p["conditions"]["clientAppTypes"] = json!(["other"]);
        assert_eq!(conditional_access_fields(&[p], &[])["ca_block_legacy_auth"], false);
    }

    #[test]
    fn sign_in_frequency_bounds_follow_the_benchmark() {
        let base = |kind: &str, value: i64| {
            policy(json!({
                "conditions": {"users": {"includeUsers": ["All"], "includeRoles": admin_ids()},
                               "applications": {"includeApplications": ["All"]}},
                "sessionControls": {
                    "signInFrequency": {"isEnabled": true, "frequencyInterval": "timeBased", "type": kind, "value": value},
                    "persistentBrowser": {"isEnabled": true, "mode": "never"}
                }
            }))
        };
        let f = conditional_access_fields(&[base("hours", 4)], &[]);
        assert_eq!(f["ca_admin_sign_in_frequency"], true);
        assert_eq!(f["ca_all_users_sign_in_frequency"], true);
        let f = conditional_access_fields(&[base("days", 1)], &[]);
        assert_eq!(f["ca_admin_sign_in_frequency"], false);
        assert_eq!(f["ca_all_users_sign_in_frequency"], true);
        assert_eq!(conditional_access_fields(&[base("days", 8)], &[])["ca_all_users_sign_in_frequency"], false);
    }

    #[test]
    fn phishing_resistant_strength_admits_only_strong_combinations() {
        let p = |combos: Value| {
            policy(json!({
                "conditions": {"users": {"includeRoles": admin_ids()}, "applications": {"includeApplications": ["All"]}},
                "grantControls": {"authenticationStrength": {"id": "x", "allowedCombinations": combos}}
            }))
        };
        assert_eq!(conditional_access_fields(&[p(json!(["fido2", "windowsHelloForBusiness"]))], &[])["ca_admin_phishing_resistant_mfa"], true);
        assert_eq!(conditional_access_fields(&[p(json!(["fido2", "password,sms"]))], &[])["ca_admin_phishing_resistant_mfa"], false);
    }

    #[test]
    fn untrusted_locations_must_be_blocked_with_trusted_ones_excluded() {
        let locations = vec![
            json!({"id": "t", "isTrusted": true, "@odata.type": "#microsoft.graph.ipNamedLocation", "ipRanges": [{"cidrAddress": "1.2.3.0/24"}]}),
            json!({"id": "u", "isTrusted": false, "@odata.type": "#microsoft.graph.countryNamedLocation"}),
        ];
        let p = policy(json!({
            "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]},
                           "locations": {"includeLocations": ["u"], "excludeLocations": ["AllTrusted"]}},
            "grantControls": {"builtInControls": ["block"]}
        }));
        let f = conditional_access_fields(&[p], &locations);
        assert_eq!(f["ca_block_untrusted_locations"], true);
        assert_eq!(f["trusted_named_location"], true);
        assert_eq!(f["ca_matches"]["ca_block_untrusted_locations"], json!(["p"]));
    }

    #[test]
    fn global_admins_are_counted_through_role_assignable_groups() {
        let assignments = vec![
            json!({"roleDefinitionId": GLOBAL_ADMINISTRATOR, "principal": {"@odata.type": "#microsoft.graph.user", "id": "u1", "userPrincipalName": "a@x"}}),
            json!({"roleDefinitionId": GLOBAL_ADMINISTRATOR, "principal": {"@odata.type": "#microsoft.graph.group", "id": "g"}}),
            json!({"roleDefinitionId": "r2", "principal": {"@odata.type": "#microsoft.graph.user", "id": "u3", "userPrincipalName": "c@x"}}),
        ];
        let users = [
            json!({"id": "u1", "userPrincipalName": "a@x", "onPremisesSyncEnabled": true, "assignedLicenses": [{"skuId": "s1"}]}),
            json!({"id": "u2", "userPrincipalName": "b@x", "assignedLicenses": [{"skuId": "s2"}]}),
            json!({"id": "u3", "userPrincipalName": "c@x", "assignedLicenses": []}),
        ];
        let dir = Directory {
            assignments: &assignments,
            role_names: HashMap::from([
                (GLOBAL_ADMINISTRATOR.to_string(), "Global Administrator".to_string()),
                ("r2".to_string(), "Directory Readers".to_string()),
            ]),
            group_members: HashMap::from([("g".to_string(), vec![json!({"@odata.type": "#microsoft.graph.user", "id": "u2"})])]),
            users: users.iter().map(|u| (u["id"].as_str().unwrap().to_string(), u)).collect(),
            skus: HashMap::from([("s1".to_string(), "SPE_E5".to_string()), ("s2".to_string(), "AAD_PREMIUM".to_string())]),
        };
        let f = dir.fields();
        assert_eq!(f["global_admins"], 2);
        assert_eq!(f["synced_admins"], json!(["a@x"]));
        assert_eq!(f["licensed_admins"], json!([{"user": "a@x", "licenses": ["SPE_E5"]}]));
    }

    #[test]
    fn permanent_privileged_assignments_are_violations_beyond_two_break_glass_admins() {
        let roles: HashSet<String> = [GLOBAL_ADMINISTRATOR.to_string(), "r".to_string()].into();
        let user = |name: &str, role: &str, kind: &str| {
            json!({"roleDefinitionId": role, "assignmentType": kind,
                   "principal": {"@odata.type": "#microsoft.graph.user", "displayName": name}})
        };
        let v = pim_violations(
            &[
                user("bg1", GLOBAL_ADMINISTRATOR, "Assigned"),
                user("bg2", GLOBAL_ADMINISTRATOR, "Assigned"),
                user("bg3", GLOBAL_ADMINISTRATOR, "Assigned"),
                user("jit", "r", "Activated"),
                user("perm", "r", "Assigned"),
                json!({"roleDefinitionId": "r", "assignmentType": "Assigned", "endDateTime": null,
                       "principal": {"@odata.type": "#microsoft.graph.servicePrincipal", "displayName": "sp"}}),
            ],
            &roles,
        );
        let names: Vec<&str> = v.iter().map(|x| x["principal"].as_str().unwrap()).collect();
        assert_eq!(names, ["bg3", "perm", "sp"]);
    }

    #[test]
    fn idle_timeout_is_read_from_the_policy_definition() {
        let def = r#"{"ActivityBasedTimeoutPolicy":{"Version":1,"ApplicationPolicies":[{"ApplicationId":"default","WebSessionIdleTimeout":"03:00:00"}]}}"#;
        assert_eq!(idle_session_timeout_seconds(&[json!({"definition": [def]})]), Some(10_800));
        assert_eq!(timespan_seconds("1.00:00:00"), Some(86_400));
        assert_eq!(idle_session_timeout_seconds(&[]), None);
    }

    #[test]
    fn b2b_invitations_are_restricted_by_an_allow_list_only() {
        let p = |def: &str| vec![json!({"type": "B2BManagementPolicy", "definition": [def]})];
        let allow = r#"{"B2BManagementPolicy":{"InvitationsAllowedAndBlockedDomainsPolicy":{"AllowedDomains":[]}}}"#;
        let block = r#"{"B2BManagementPolicy":{"InvitationsAllowedAndBlockedDomainsPolicy":{"BlockedDomains":["x.org"]}}}"#;
        assert_eq!(b2b_invitations_allow_list(&p(allow))["b2b_invitations_restricted"], true);
        assert_eq!(b2b_invitations_allow_list(&p(block))["b2b_invitations_restricted"], false);
        assert_eq!(b2b_invitations_allow_list(&[])["b2b_invitations_restricted"], false);
    }

    #[test]
    fn app_restrictions_need_both_sides_and_a_bounded_lifetime() {
        let side = json!({"passwordCredentials": [{"restrictionType": "passwordLifetime", "state": "enabled",
                          "maxLifetime": "P90D", "restrictForAppsCreatedAfterDateTime": "0001-01-01T00:00:00Z"}]});
        let mut p = json!({"isEnabled": true, "applicationRestrictions": side.clone(), "servicePrincipalRestrictions": side});
        assert!(app_restriction_enforced(&p, "passwordCredentials", "passwordLifetime", Some(180)));
        assert!(!app_restriction_enforced(&p, "passwordCredentials", "passwordLifetime", Some(60)));
        p["servicePrincipalRestrictions"] = json!({});
        assert!(!app_restriction_enforced(&p, "passwordCredentials", "passwordLifetime", Some(180)));
    }

    #[test]
    fn group_settings_values_are_typed() {
        let v = setting_values(&json!({"values": [
            {"name": "LockoutThreshold", "value": "10"}, {"name": "EnableBannedPasswordCheck", "value": "True"},
            {"name": "BannedPasswordList", "value": "a\tb"}]}));
        assert_eq!(v, json!({"LockoutThreshold": 10, "EnableBannedPasswordCheck": true, "BannedPasswordList": "a\tb"}));
    }

    #[test]
    fn directory_settings_and_enrollment_restrictions() {
        let f = directory_setting_fields(&[json!({"templateId": PASSWORD_RULE_TEMPLATE, "values": [{"name": "LockoutThreshold", "value": "10"}]})]);
        assert_eq!(f["password_rule_settings"]["LockoutThreshold"], 10);
        assert!(f["group_creation_settings"].is_null());
        let blocked = json!({"personalDeviceEnrollmentBlocked": true});
        let mut c = json!({"id": "t_DefaultPlatformRestrictions", "priority": 0, "windowsRestriction": blocked,
            "iosRestriction": blocked, "androidForWorkRestriction": blocked, "macOSRestriction": {"platformBlocked": true},
            "androidRestriction": blocked});
        assert_eq!(personal_enrollment_blocked(&[c.clone()]), true);
        c["androidRestriction"] = json!({"personalDeviceEnrollmentBlocked": false});
        assert_eq!(personal_enrollment_blocked(&[c]), false);
        assert!(personal_enrollment_blocked(&[]).is_null());
        let row = authentication_methods_row(&json!({"authenticationMethodConfigurations": [{"id": "Sms", "state": "disabled"}]}));
        assert_eq!(row["methods"]["Sms"]["state"], "disabled");
    }

    #[test]
    fn intune_devices_and_compliance_coverage() {
        let d = intune_device(&json!({"deviceName": "PC-01", "operatingSystem": "Windows", "osVersion": "10.0.26100.4652",
            "complianceState": "compliant", "jailBroken": "Unknown", "isEncrypted": true}));
        assert_eq!((d["build"].clone(), d["ubr"].clone()), (json!(26100), json!(4652)));
        assert_eq!(d["jailbroken"], Value::Null);
        assert_eq!(intune_device(&json!({"operatingSystem": "iOS", "jailBroken": "True"}))["jailbroken"], true);
        let devices = [json!({"operatingSystem": "Windows"}), json!({"operatingSystem": "iPadOS"}), json!({"operatingSystem": "Android"})];
        let policies = [
            json!({"@odata.type": "#microsoft.graph.androidCompliancePolicy", "assignments": [{"id": "a"}]}),
            json!({"@odata.type": "#microsoft.graph.iosCompliancePolicy", "assignments": []}),
        ];
        assert_eq!(platforms_without_compliance_policy(&devices, &policies), ["ios", "windows"]);
    }

    #[test]
    fn scuba_checks() {
        let p = policy(json!({
            "conditions": {"users": {"includeUsers": ["All"], "excludeRoles": []}, "applications": {"includeApplications": ["All"]},
                           "userRiskLevels": ["high"]},
            "grantControls": {"builtInControls": ["block"]}
        }));
        let f = scuba_ca_fields(&[p.clone()], &[]);
        assert_eq!(f["scuba_block_high_risk_users"], true);
        assert_eq!(f["scuba_block_high_risk_sign_ins"], false);
        let mut excluded = p;
        excluded["conditions"]["users"]["excludeRoles"] = json!([GLOBAL_ADMINISTRATOR]);
        assert_eq!(scuba_ca_fields(&[excluded], &[])["scuba_block_high_risk_users"], false);

        let row = sharing_policy_row(&json!({"Domains": ["Anonymous:CalendarSharingFreeBusyReviewer", "*:CalendarSharingFreeBusySimple"]}));
        assert_eq!(row["_shares_calendar_with_all_domains"], true);
        assert_eq!(row["_shares_contacts_with_all_domains"], false);

        assert!(external_sender_warning_rule(&[json!({"State": "Enabled", "Mode": "Enforce", "FromScope": "NotInOrganization", "PrependSubject": "[EXT] "})]));
        assert!(!external_sender_warning_rule(&[json!({"State": "Disabled", "Mode": "Enforce", "FromScope": "NotInOrganization", "PrependSubject": "[EXT] "})]));

        let d = scuba_defender_fields(&[json!({"Enabled": true, "EnableOrganizationDomainsProtection": true, "EnableTargetedUserProtection": true, "TargetedUsersToProtect": []})], &[]);
        assert_eq!(d["scuba_domain_impersonation"], true);
        assert_eq!(d["scuba_user_impersonation"], false);
    }

    #[test]
    fn malware_policies_report_missing_file_types() {
        let mut types: Vec<&str> = COMPREHENSIVE_FILE_TYPES.to_vec();
        types.retain(|t| *t != "exe");
        let row = malware_policy_row(
            &json!({"Identity": "Default", "EnableFileFilter": true, "FileTypes": types}),
            &[json!({"MalwareFilterPolicy": "Default", "State": "Enabled"})],
        );
        assert_eq!(row["_missing_default_file_types"], json!(["exe"]));
        assert_eq!(row["_comprehensive_filter"], true);
        let row = malware_policy_row(&json!({"Identity": "Default", "EnableFileFilter": true, "FileTypes": ["exe"]}), &[]);
        assert_eq!(row["_comprehensive_filter"], false);
    }

    #[test]
    fn mailbox_audit_gaps_are_listed_per_scope() {
        let row = mailbox_row(&json!({"AuditAdmin": ADMIN_AUDIT, "AuditDelegate": [], "AuditOwner": OWNER_AUDIT}));
        assert_eq!(row["_audit_admin_missing"], json!([]));
        assert_eq!(row["_audit_delegate_missing"].as_array().unwrap().len(), DELEGATE_AUDIT.len());
    }

    #[test]
    fn transport_rules_flag_external_redirects_and_scl_bypass() {
        let accepted: HashSet<String> = ["contoso.com".to_string()].into();
        let row = transport_rule_row(
            &json!({"RedirectMessageTo": ["a@contoso.com", "b@evil.org"], "SetSCL": -1, "SenderDomainIs": ["x.org"]}),
            &accepted,
        );
        assert_eq!(row["_external_redirects"], json!(["b@evil.org"]));
        assert_eq!(row["_whitelists_sender_domains"], true);
    }

    #[test]
    fn spf_and_dmarc_follow_the_benchmark() {
        assert!(matches!(spf_end("v=spf1 include:spf.protection.outlook.com -all"), SpfEnd::All(q) if q == "-all"));
        assert!(matches!(spf_end("v=spf1 redirect=_spf.example.com"), SpfEnd::Redirect(d) if d == "_spf.example.com"));
        assert!(matches!(spf_end("v=spf1 include:x"), SpfEnd::None));
        assert!(dmarc_compliant("v=DMARC1; p=reject; rua=mailto:a@x.org; ruf=mailto:a@x.org", false));
        assert!(!dmarc_compliant("v=DMARC1; p=none; rua=mailto:a@x.org; ruf=mailto:a@x.org", false));
        assert!(!dmarc_compliant("v=DMARC1; p=reject; pct=50; rua=mailto:a@x.org; ruf=mailto:a@x.org", false));
        assert!(!dmarc_compliant("v=DMARC1; p=reject; rua=mailto:a@x.org", false));
        assert!(!dmarc_compliant("v=DMARC1; p=reject; sp=none; rua=mailto:a@x.org; ruf=mailto:a@x.org", true));
    }

    #[test]
    fn teams_external_access_passes_on_either_policy_or_federation() {
        let f = teams_fields(
            &[json!({"Identity": "Global", "EnableFederationAccess": true, "EnableTeamsConsumerAccess": false, "EnableTeamsConsumerInbound": true})],
            &[json!({"Identity": "Global", "AllowFederatedUsers": false, "AllowTeamsConsumer": true, "AllowTeamsConsumerInbound": true})],
        );
        assert_eq!(f["teams_external_domains_restricted"], true);
        assert_eq!(f["teams_unmanaged_communication_disabled"], true);
        assert_eq!(f["teams_unmanaged_inbound_disabled"], false);
    }
}
