//! Microsoft 365: Entra ID, the Microsoft 365 admin center, Intune,
//! SharePoint, Exchange Online, Defender for Office 365 and Teams, read with
//! one read-only application.
//!
//! Three APIs answer, each served as objects named after what they return:
//!
//! - **Microsoft Graph** (`conditional_access_policies`, `authorization_policy`,
//!   `sharepoint_settings`, …): the resource exactly as Graph returns it.
//! - **Exchange Online admin API** (`exchange_*`): the output of the
//!   `Get-*` cmdlet, through the REST endpoint the ExchangeOnlineManagement
//!   module itself calls (`/adminapi/beta/{tenant}/InvokeCommand`), so no
//!   PowerShell is needed. Defender for Office 365 policies live here too.
//! - **Teams admin API** (`teams_*`): the `Get-Cs*` configurations, through
//!   the endpoint the MicrosoftTeams module calls.
//!
//! Three computed objects answer what spans several of them: `tenant` (one
//! row: Conditional Access coverage, privileged roles, PIM, access reviews,
//! the Defender policies the benchmark requires one of), `mail_domains` (SPF,
//! DKIM and DMARC of each accepted domain) and `shared_mailboxes`.
//!
//! Credentials: a service principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
//! `AZURE_CLIENT_SECRET`) with read-only Graph application permissions,
//! `Exchange.ManageAsApp` and the Global Reader role. Without one, the Azure
//! CLI's session reads Graph; Exchange and Teams then answer an error.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use serde_json::{json, Value};
use tokio::sync::{Mutex, OnceCell};

use super::m365_cis as cis;
use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;

const GRAPH: &str = "https://graph.microsoft.com";
const EXCHANGE: &str = "https://outlook.office365.com";
const TEAMS_RESOURCE: &str = "48ac35b8-9aa8-4d74-927d-1f4a14a0b239";
const TEAMS_API: &str = "https://api.interfaces.records.teams.microsoft.com/Skype.Policy/configurations";
/// The service principal behind "open files stored in third-party storage in
/// Microsoft 365 on the web" (CIS 1.3.7).
const THIRD_PARTY_STORAGE_APP: &str = "c1f33bc0-bdb4-4248-ba9b-096807ddb43e";

/// (object, Graph path, a collection rather than a single resource).
pub(crate) const GRAPH_OBJECTS: &[(&str, &str, bool)] = &[
    ("access_review_definitions", "/v1.0/identityGovernance/accessReviews/definitions", true),
    ("admin_consent_request_policy", "/v1.0/policies/adminConsentRequestPolicy", false),
    ("app_management_policy", "/v1.0/policies/defaultAppManagementPolicy", false),
    ("apps_and_services_settings", "/beta/admin/appsAndServices/settings", false),
    ("authentication_methods_policy", "/beta/policies/authenticationMethodsPolicy", false),
    ("authentication_strength_policies", "/v1.0/policies/authenticationStrengthPolicies", true),
    ("authorization_policy", "/v1.0/policies/authorizationPolicy", false),
    ("conditional_access_policies", "/beta/identity/conditionalAccess/policies", true),
    ("cross_tenant_access_policy", "/v1.0/policies/crossTenantAccessPolicy/default", false),
    ("device_enrollment_configurations", "/beta/deviceManagement/deviceEnrollmentConfigurations", true),
    ("device_registration_policy", "/beta/policies/deviceRegistrationPolicy", false),
    ("directory_sync", "/v1.0/directory/onPremisesSynchronization", true),
    ("domains", "/v1.0/domains", true),
    ("forms_settings", "/beta/admin/forms/settings", false),
    ("group_settings", "/v1.0/groupSettings", true),
    ("groups", "/v1.0/groups?$filter=groupTypes/any(c:c eq 'Unified')&$select=id,displayName,visibility,groupTypes&$top=999", true),
    ("intune_compliance_policies", "/v1.0/deviceManagement/deviceCompliancePolicies?$expand=assignments", true),
    (
        "intune_managed_devices",
        "/v1.0/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,complianceState,\
         lastSyncDateTime,enrolledDateTime,isEncrypted,jailBroken,model,manufacturer,serialNumber,\
         managedDeviceOwnerType,managementAgent,userPrincipalName,azureADDeviceId,isSupervised",
        true,
    ),
    ("intune_settings", "/v1.0/deviceManagement/settings", false),
    ("named_locations", "/v1.0/identity/conditionalAccess/namedLocations", true),
    ("organization", "/v1.0/organization", true),
    ("role_assignments", "/v1.0/roleManagement/directory/roleAssignments?$expand=principal", true),
    ("role_definitions", "/v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn,templateId", true),
    ("security_defaults", "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy", false),
    ("sharepoint_settings", "/v1.0/admin/sharepoint/settings", false),
    ("subscribed_skus", "/v1.0/subscribedSkus", true),
    ("user_registration_details", "/v1.0/reports/authenticationMethods/userRegistrationDetails", true),
    ("users", "/v1.0/users?$select=id,userPrincipalName,displayName,userType,accountEnabled,onPremisesSyncEnabled,assignedLicenses&$top=999", true),
];

/// (object, cmdlet, parameters).
pub(crate) const EXCHANGE_OBJECTS: &[(&str, &str, &str)] = &[
    ("exchange_accepted_domains", "Get-AcceptedDomain", "{}"),
    ("exchange_admin_audit_log_config", "Get-AdminAuditLogConfig", "{}"),
    ("exchange_anti_phish_policies", "Get-AntiPhishPolicy", "{}"),
    ("exchange_atp_policy", "Get-AtpPolicyForO365", "{}"),
    ("exchange_atp_protection_policy_rules", "Get-ATPProtectionPolicyRule", "{}"),
    ("exchange_audit_bypass", "Get-MailboxAuditBypassAssociation", r#"{"ResultSize":"Unlimited"}"#),
    ("exchange_connection_filter_policies", "Get-HostedConnectionFilterPolicy", "{}"),
    ("exchange_content_filter_policies", "Get-HostedContentFilterPolicy", "{}"),
    ("exchange_dkim_signing_configs", "Get-DkimSigningConfig", "{}"),
    ("exchange_email_tenant_settings", "Get-EmailTenantSettings", "{}"),
    ("exchange_eop_protection_policy_rules", "Get-EOPProtectionPolicyRule", "{}"),
    ("exchange_external_in_outlook", "Get-ExternalInOutlook", "{}"),
    ("exchange_mailboxes", "Get-Mailbox", r#"{"ResultSize":"Unlimited"}"#),
    ("exchange_malware_filter_policies", "Get-MalwareFilterPolicy", "{}"),
    ("exchange_malware_filter_rules", "Get-MalwareFilterRule", "{}"),
    ("exchange_organization_config", "Get-OrganizationConfig", "{}"),
    ("exchange_outbound_spam_policies", "Get-HostedOutboundSpamFilterPolicy", "{}"),
    ("exchange_owa_mailbox_policies", "Get-OwaMailboxPolicy", "{}"),
    ("exchange_remote_domains", "Get-RemoteDomain", "{}"),
    ("exchange_report_submission_policies", "Get-ReportSubmissionPolicy", "{}"),
    ("exchange_role_assignment_policies", "Get-RoleAssignmentPolicy", "{}"),
    ("exchange_safe_attachment_policies", "Get-SafeAttachmentPolicy", "{}"),
    ("exchange_safe_attachment_rules", "Get-SafeAttachmentRule", "{}"),
    ("exchange_safe_links_policies", "Get-SafeLinksPolicy", "{}"),
    ("exchange_sharing_policies", "Get-SharingPolicy", "{}"),
    ("exchange_teams_protection_policies", "Get-TeamsProtectionPolicy", "{}"),
    ("exchange_transport_config", "Get-TransportConfig", "{}"),
    ("exchange_transport_rules", "Get-TransportRule", "{}"),
];

/// (object, Skype.Policy configuration).
pub(crate) const TEAMS_OBJECTS: &[(&str, &str)] = &[
    ("teams_app_permission_policies", "TeamsAppPermissionPolicy"),
    ("teams_broadcast_policies", "TeamsMeetingBroadcastPolicy"),
    ("teams_client_configuration", "TeamsClientConfiguration"),
    ("teams_external_access_policies", "ExternalAccessPolicy"),
    ("teams_federation_configuration", "TenantFederationSettings"),
    ("teams_meeting_policies", "TeamsMeetingPolicy"),
    ("teams_messaging_policies", "TeamsMessagingPolicy"),
];

pub(crate) const COMPUTED_OBJECTS: &[&str] = &["mail_domains", "shared_mailboxes", "tenant"];

pub(crate) static RESOURCE_TYPES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let mut t: Vec<&'static str> = GRAPH_OBJECTS
        .iter()
        .map(|(o, _, _)| *o)
        .chain(EXCHANGE_OBJECTS.iter().map(|(o, _, _)| *o))
        .chain(TEAMS_OBJECTS.iter().map(|(o, _)| *o))
        .chain(COMPUTED_OBJECTS.iter().copied())
        .collect();
    t.sort_unstable();
    t
});

struct ServicePrincipal {
    tenant_id: String,
    client_id: String,
    client_secret: String,
}

type Shared<T> = Arc<OnceCell<Result<T, ProviderError>>>;

pub struct M365Provider {
    service_principal: Option<ServicePrincipal>,
    tokens: Mutex<HashMap<String, Shared<String>>>,
    /// Every read, once per scan: the computed objects reuse what the raw
    /// objects already fetched.
    reads: Mutex<HashMap<String, Shared<Vec<Value>>>>,
}

impl M365Provider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let service_principal = match (
            get_config_or_env(&config, "TENANT_ID", Some("AZURE")),
            get_config_or_env(&config, "CLIENT_ID", Some("AZURE")),
            get_config_or_env(&config, "CLIENT_SECRET", Some("AZURE")),
        ) {
            (Some(tenant_id), Some(client_id), Some(client_secret)) => {
                Some(ServicePrincipal { tenant_id, client_id, client_secret })
            }
            _ => None,
        };
        Ok(Self { service_principal, tokens: Mutex::default(), reads: Mutex::default() })
    }

    // ── tokens ──────────────────────────────────────────────────────────────

    async fn token(&self, resource: &str) -> Result<String, ProviderError> {
        let cell = self.tokens.lock().await.entry(resource.to_string()).or_default().clone();
        cell.get_or_init(|| self.fetch_token(resource)).await.clone()
    }

    async fn fetch_token(&self, resource: &str) -> Result<String, ProviderError> {
        let Some(sp) = &self.service_principal else {
            if resource != GRAPH {
                return Err(ProviderError::Auth(format!(
                    "Microsoft 365: {resource} needs a service principal (AZURE_TENANT_ID, AZURE_CLIENT_ID, \
                     AZURE_CLIENT_SECRET) with Exchange.ManageAsApp and the Global Reader role; the Azure CLI \
                     session only reads Microsoft Graph"
                )));
            }
            return az_cli_token(resource).await;
        };
        let resp: Value = crate::http::shared_client()
            .post(format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", sp.tenant_id))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", sp.client_id.as_str()),
                ("client_secret", sp.client_secret.as_str()),
                ("scope", &format!("{resource}/.default")),
            ])
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("Microsoft 365 token request: {e}")))?
            .json()
            .await
            .map_err(|e| ProviderError::Connection(format!("Microsoft 365 token response: {e}")))?;
        resp["access_token"].as_str().map(String::from).ok_or_else(|| {
            ProviderError::Auth(format!(
                "Microsoft 365: no token for {resource}: {}",
                resp["error_description"].as_str().unwrap_or("unknown error")
            ))
        })
    }

    // ── reads, once per scan ────────────────────────────────────────────────

    async fn once<F, Fut>(&self, key: &str, read: F) -> Result<Vec<Value>, ProviderError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<Value>, ProviderError>>,
    {
        let cell = self.reads.lock().await.entry(key.to_string()).or_default().clone();
        cell.get_or_init(read).await.clone()
    }

    /// GET a Graph path (`/v1.0/...` or `/beta/...`), following `@odata.nextLink`.
    async fn graph(&self, path: &str, collection: bool) -> Result<Vec<Value>, ProviderError> {
        self.once(&format!("graph {path}"), || async {
            let token = self.token(GRAPH).await?;
            let mut url = format!("{GRAPH}{path}");
            let mut out = Vec::new();
            for _ in 0..200 {
                let mut page = send(
                    || {
                        crate::http::shared_client()
                            .get(&url)
                            .bearer_auth(&token)
                            .header("ConsistencyLevel", "eventual")
                    },
                    path,
                )
                .await?;
                if !collection {
                    if let Value::Object(m) = &mut page {
                        m.remove("@odata.context");
                    }
                    return Ok(vec![page]);
                }
                out.extend(page["value"].as_array().cloned().unwrap_or_default());
                match page["@odata.nextLink"].as_str() {
                    Some(next) if next.starts_with(GRAPH) => url = next.to_string(),
                    _ => return Ok(out),
                }
            }
            Ok(out)
        })
        .await
    }

    async fn graph_object(&self, object: &str) -> Result<Vec<Value>, ProviderError> {
        let (_, path, collection) = GRAPH_OBJECTS
            .iter()
            .find(|(o, _, _)| *o == object)
            .ok_or_else(|| ProviderError::NotFound(object.to_string()))?;
        let rows = self.graph(path, *collection).await?;
        Ok(match object {
            "authentication_methods_policy" => rows.iter().map(cis::authentication_methods_row).collect(),
            "intune_managed_devices" => rows.iter().map(cis::intune_device).collect(),
            "group_settings" => rows
                .into_iter()
                .map(|mut s| {
                    s["settings"] = cis::setting_values(&s);
                    s
                })
                .collect(),
            _ => rows,
        })
    }

    async fn tenant_id(&self) -> Result<String, ProviderError> {
        if let Some(sp) = &self.service_principal {
            return Ok(sp.tenant_id.clone());
        }
        let org = self.graph_object("organization").await?;
        org.first().and_then(|o| o["id"].as_str()).map(String::from).ok_or_else(|| ProviderError::Api("no organization".into()))
    }

    /// The tenant's `*.onmicrosoft.com` domain, which Exchange routes on.
    async fn initial_domain(&self) -> Result<String, ProviderError> {
        let org = self.graph_object("organization").await?;
        org.iter()
            .flat_map(|o| o["verifiedDomains"].as_array().cloned().unwrap_or_default())
            .find(|d| d["isInitial"] == true)
            .and_then(|d| d["name"].as_str().map(String::from))
            .ok_or_else(|| ProviderError::Api("Microsoft 365: no initial domain in the organization".into()))
    }

    /// Run an Exchange Online `Get-*` cmdlet.
    async fn exchange(&self, cmdlet: &str, params: &str) -> Result<Vec<Value>, ProviderError> {
        self.once(&format!("exchange {cmdlet}"), || async {
            let token = self.token(EXCHANGE).await?;
            let tenant = self.tenant_id().await?;
            let anchor = format!("UPN:SystemMailbox{{bb558c35-97f1-4cb9-8ff7-d53741dc928c}}@{}", self.initial_domain().await?);
            let params: Value = serde_json::from_str(params).unwrap_or_else(|_| json!({}));
            let body = json!({ "CmdletInput": { "CmdletName": cmdlet, "Parameters": params } });
            let mut url = format!("{EXCHANGE}/adminapi/beta/{tenant}/InvokeCommand");
            let mut out = Vec::new();
            for _ in 0..200 {
                let page = send(
                    || {
                        crate::http::shared_client()
                            .post(&url)
                            .bearer_auth(&token)
                            .header("X-AnchorMailbox", &anchor)
                            .json(&body)
                    },
                    cmdlet,
                )
                .await?;
                out.extend(page["value"].as_array().cloned().unwrap_or_default());
                match page["@odata.nextLink"].as_str() {
                    Some(next) if next.starts_with(EXCHANGE) => url = next.to_string(),
                    _ => break,
                }
            }
            Ok(out.into_iter().map(strip_odata).collect())
        })
        .await
    }

    async fn exchange_object(&self, object: &str) -> Result<Vec<Value>, ProviderError> {
        let (_, cmdlet, params) = EXCHANGE_OBJECTS
            .iter()
            .find(|(o, _, _)| *o == object)
            .ok_or_else(|| ProviderError::NotFound(object.to_string()))?;
        let rows = self.exchange(cmdlet, params).await?;
        Ok(match object {
            "exchange_mailboxes" => rows.iter().map(cis::mailbox_row).collect(),
            "exchange_sharing_policies" => rows.iter().map(cis::sharing_policy_row).collect(),
            "exchange_malware_filter_policies" => {
                let rules = self.exchange("Get-MalwareFilterRule", "{}").await.unwrap_or_default();
                rows.iter().map(|p| cis::malware_policy_row(p, &rules)).collect()
            }
            "exchange_transport_rules" => {
                let accepted = self.accepted_domains().await?;
                rows.iter().map(|r| cis::transport_rule_row(r, &accepted)).collect()
            }
            _ => rows,
        })
    }

    async fn accepted_domains(&self) -> Result<HashSet<String>, ProviderError> {
        Ok(self
            .exchange("Get-AcceptedDomain", "{}")
            .await?
            .iter()
            .filter_map(|d| d["DomainName"].as_str().or(d["Name"].as_str()))
            .map(str::to_ascii_lowercase)
            .collect())
    }

    async fn teams(&self, configuration: &str) -> Result<Vec<Value>, ProviderError> {
        self.once(&format!("teams {configuration}"), || async {
            let token = self.token(TEAMS_RESOURCE).await?;
            let url = format!("{TEAMS_API}/{configuration}");
            let v = send(|| crate::http::shared_client().get(&url).bearer_auth(&token), configuration).await?;
            let rows = match v {
                Value::Array(rows) => rows,
                other => vec![other],
            };
            Ok(rows.into_iter().map(teams_identity).collect())
        })
        .await
    }

    // ── computed objects ────────────────────────────────────────────────────

    /// SPF, DKIM and DMARC of every accepted domain but the hybrid
    /// coexistence one (CIS 2.1.8–2.1.10).
    async fn mail_domains(&self) -> Result<Vec<Value>, ProviderError> {
        let domains = self.exchange("Get-AcceptedDomain", "{}").await?;
        let dkim = self.exchange("Get-DkimSigningConfig", "{}").await.unwrap_or_default();
        let resolver = hickory_resolver::TokioResolver::builder_tokio()
            .and_then(|b| b.build())
            .map_err(|e| ProviderError::Dns(e.to_string()))?;
        let mut out = Vec::new();
        for d in domains.iter().filter(|d| d["IsCoexistenceDomain"] != true) {
            let Some(name) = d["DomainName"].as_str().or(d["Name"].as_str()).map(str::to_ascii_lowercase) else {
                continue;
            };
            let (spf_record, spf_qualifier) = spf_check(&resolver, &name).await;
            let spf_compliant = matches!(spf_qualifier.as_deref(), Some("-all" | "~all"));
            let (dmarc_record, dmarc_compliant) = dmarc_check(&resolver, &name).await;
            let dmarc_tags = cis::dmarc_tags(dmarc_record.as_str().unwrap_or(""));
            let signing = dkim.iter().find(|c| c["Name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(&name)));
            out.push(json!({
                "name": name,
                "initial": d["InitialDomain"] == true,
                "domain_type": d["DomainType"],
                "spf_record": spf_record,
                "spf_compliant": spf_compliant,
                "spf_hard_fail": spf_qualifier.as_deref() == Some("-all"),
                "dmarc_record": dmarc_record,
                "dmarc_compliant": dmarc_compliant,
                "dmarc_policy": dmarc_tags.get("p").cloned().unwrap_or_default(),
                "dmarc_reporting": (["rua", "ruf"].iter().all(|t| dmarc_tags.get(*t).is_some_and(|v| v.starts_with("mailto:")))),
                "dkim_enabled": signing.is_some_and(|c| c["Enabled"] == true),
                "dkim_status": signing.map(|c| c["Status"].clone()).unwrap_or(json!("Not Configured")),
            }));
        }
        Ok(out)
    }

    /// CIS 1.2.2: each shared mailbox with the sign-in state of its account.
    async fn shared_mailboxes(&self) -> Result<Vec<Value>, ProviderError> {
        let mailboxes = self.exchange("Get-Mailbox", r#"{"ResultSize":"Unlimited"}"#).await?;
        let users = self.graph_object("users").await?;
        let by_id: HashMap<&str, &Value> = users.iter().filter_map(|u| Some((u["id"].as_str()?, u))).collect();
        Ok(mailboxes
            .iter()
            .filter(|m| m["RecipientTypeDetails"] == "SharedMailbox")
            .map(|m| {
                let user = m["ExternalDirectoryObjectId"].as_str().and_then(|id| by_id.get(id));
                json!({
                    "name": m["PrimarySmtpAddress"],
                    "display_name": m["DisplayName"],
                    "account_enabled": user.map(|u| u["accountEnabled"].clone()).unwrap_or(Value::Null),
                })
            })
            .collect())
    }

    /// The one-row `tenant` object. A part that cannot be read leaves its
    /// fields `null` and says why under `errors`, so the rules that need it
    /// fail instead of passing on an absence.
    async fn tenant(&self) -> Result<Vec<Value>, ProviderError> {
        let mut row = serde_json::Map::new();
        let mut errors = serde_json::Map::new();
        let mut note = |key: &str, e: ProviderError| {
            errors.insert(key.to_string(), json!(e.to_string()));
        };

        // Conditional Access
        match (self.graph_object("conditional_access_policies").await, self.graph_object("named_locations").await) {
            (Ok(policies), Ok(locations)) => {
                row.extend(cis::conditional_access_fields(&policies, &locations));
                row.extend(cis::scuba_ca_fields(&policies, &locations));
            }
            (Err(e), _) | (_, Err(e)) => note("conditional_access", e),
        }

        // Privileged roles and the accounts holding them
        match self.directory_fields().await {
            Ok(fields) => row.extend(fields),
            Err(e) => note("roles", e),
        }

        // PIM (needs Entra ID P2)
        match self.pim_fields().await {
            Ok(fields) => row.extend(fields),
            Err(e) => {
                for k in ["privileged_assignment_violations", "global_admin_activation_approval", "privileged_role_admin_activation_approval"] {
                    row.insert(k.into(), Value::Null);
                }
                note("pim", e)
            }
        }

        // Access reviews
        match self.graph_object("access_review_definitions").await {
            Ok(defs) => {
                row.insert("guest_access_review".into(), json!(cis::guest_access_review(&defs)));
                row.insert("unreviewed_privileged_roles".into(), json!(cis::unreviewed_privileged_roles(&defs)));
            }
            Err(e) => note("access_reviews", e),
        }

        match self.graph_object("group_settings").await {
            Ok(settings) => row.extend(cis::directory_setting_fields(&settings)),
            Err(e) => note("group_settings", e),
        }
        match (self.graph_object("organization").await, self.graph_object("directory_sync").await) {
            (Ok(org), Ok(sync)) => {
                // CIS 5.1.8.1 concerns hybrid tenants only.
                let hybrid = org.first().is_some_and(|o| o["onPremisesSyncEnabled"] == true);
                let phs = sync.first().is_some_and(|s| s["features"]["passwordSyncEnabled"] == true);
                row.insert("hybrid".into(), json!(hybrid));
                row.insert("password_hash_sync_ok".into(), json!(!hybrid || phs));
            }
            (Err(e), _) | (_, Err(e)) => note("directory_sync", e),
        }
        match (
            self.graph(GRAPH_OBJECTS.iter().find(|(o, _, _)| *o == "intune_managed_devices").map(|(_, p, _)| *p).unwrap_or_default(), true).await,
            self.graph_object("intune_compliance_policies").await,
        ) {
            (Ok(devices), Ok(policies)) => {
                row.insert(
                    "intune_platforms_without_compliance_policy".into(),
                    json!(cis::platforms_without_compliance_policy(&devices, &policies)),
                );
            }
            (Err(e), _) | (_, Err(e)) => note("intune", e),
        }
        match self.graph_object("device_enrollment_configurations").await {
            Ok(c) => {
                row.insert("personal_device_enrollment_blocked".into(), cis::personal_enrollment_blocked(&c));
            }
            Err(e) => note("device_enrollment", e),
        }

        // Entra policies kept in JSON strings
        match self.graph("/v1.0/policies/activityBasedTimeoutPolicies", true).await {
            Ok(p) => {
                let timeout = cis::idle_session_timeout_seconds(&p);
                row.insert("idle_session_timeout_seconds".into(), json!(timeout));
                row.insert("idle_session_timeout_set".into(), json!(timeout.is_some_and(|t| t > 0 && t <= 3 * 3600)));
            }
            Err(e) => note("idle_session_timeout", e),
        }
        match self.graph("/beta/legacy/policies", true).await {
            Ok(p) => {
                if let Value::Object(m) = cis::b2b_invitations_allow_list(&p) {
                    row.extend(m);
                }
            }
            Err(e) => note("b2b_management_policy", e),
        }
        match self.graph_object("app_management_policy").await {
            Ok(p) => {
                let p = p.first().cloned().unwrap_or(Value::Null);
                for (field, kind, restriction, max) in [
                    ("app_password_addition_blocked", "passwordCredentials", "passwordAddition", None),
                    ("app_password_lifetime_limited", "passwordCredentials", "passwordLifetime", Some(180)),
                    ("app_custom_password_blocked", "passwordCredentials", "customPasswordAddition", None),
                    ("app_certificate_lifetime_limited", "keyCredentials", "asymmetricKeyLifetime", Some(180)),
                    ("app_certificate_lifetime_365", "keyCredentials", "asymmetricKeyLifetime", Some(365)),
                ] {
                    row.insert(field.into(), json!(cis::app_restriction_enforced(&p, kind, restriction, max)));
                }
            }
            Err(e) => note("app_management_policy", e),
        }
        match self.graph(&format!("/v1.0/servicePrincipals?$filter=appId eq '{THIRD_PARTY_STORAGE_APP}'&$select=accountEnabled"), true).await {
            Ok(sps) => {
                // No service principal leaves the feature on (the benchmark's own reading).
                let disabled = sps.first().is_some_and(|s| s["accountEnabled"] == false);
                row.insert("third_party_storage_disabled".into(), json!(disabled));
            }
            Err(e) => note("third_party_storage", e),
        }

        // Exchange and Defender for Office 365
        match self.defender_fields().await {
            Ok(fields) => row.extend(fields),
            Err(e) => note("exchange", e),
        }

        // Teams
        match (
            self.teams("ExternalAccessPolicy").await,
            self.teams("TenantFederationSettings").await,
            self.teams("TeamsMessagingPolicy").await,
            self.exchange("Get-ReportSubmissionPolicy", "{}").await,
        ) {
            (Ok(access), Ok(federation), Ok(messaging), Ok(submission)) => {
                row.extend(cis::teams_fields(&access, &federation));
                row.insert("user_reporting_configured".into(), json!(cis::user_reporting(&messaging, &submission)));
            }
            (Err(e), ..) | (_, Err(e), ..) | (_, _, Err(e), _) | (.., Err(e)) => note("teams", e),
        }

        row.insert("errors".into(), Value::Object(errors));
        row.insert("name".into(), json!(self.initial_domain().await.unwrap_or_default()));
        Ok(vec![Value::Object(row)])
    }

    async fn directory_fields(&self) -> Result<serde_json::Map<String, Value>, ProviderError> {
        let assignments = self.graph_object("role_assignments").await?;
        let definitions = self.graph_object("role_definitions").await?;
        let users = self.graph_object("users").await?;
        let skus = self.graph_object("subscribed_skus").await?;
        let role_names: HashMap<String, String> = definitions
            .iter()
            .filter_map(|d| Some((d["id"].as_str()?.to_string(), d["displayName"].as_str()?.to_string())))
            .collect();
        let mut group_members = HashMap::new();
        for a in &assignments {
            let p = &a["principal"];
            if p["@odata.type"] != "#microsoft.graph.group" {
                continue;
            }
            let Some(gid) = p["id"].as_str() else { continue };
            let members = self
                .graph(&format!("/v1.0/groups/{gid}/transitiveMembers?$select=id,userPrincipalName"), true)
                .await?;
            group_members.insert(gid.to_string(), members);
        }
        let dir = cis::Directory {
            assignments: &assignments,
            role_names,
            group_members,
            users: users.iter().filter_map(|u| Some((u["id"].as_str()?.to_string(), u))).collect(),
            skus: skus
                .iter()
                .filter_map(|s| Some((s["skuId"].as_str()?.to_string(), s["skuPartNumber"].as_str()?.to_string())))
                .collect(),
        };
        Ok(dir.fields())
    }

    async fn pim_fields(&self) -> Result<serde_json::Map<String, Value>, ProviderError> {
        let privileged: HashSet<String> = self
            .graph("/beta/roleManagement/directory/roleDefinitions?$filter=isPrivileged eq true&$select=id", true)
            .await?
            .iter()
            .filter_map(|d| d["id"].as_str().map(String::from))
            .collect();
        let instances = self.graph("/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$expand=principal", true).await?;
        let mut out = serde_json::Map::new();
        out.insert("privileged_assignment_violations".into(), json!(cis::pim_violations(&instances, &privileged)));
        for (field, role) in [
            ("global_admin_activation_approval", cis::GLOBAL_ADMINISTRATOR),
            ("privileged_role_admin_activation_approval", cis::PRIVILEGED_ROLE_ADMINISTRATOR),
        ] {
            let assignment = self
                .graph(
                    &format!(
                        "/v1.0/policies/roleManagementPolicyAssignments?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '{role}'&$select=policyId"
                    ),
                    true,
                )
                .await?;
            let approved = match assignment.first().and_then(|a| a["policyId"].as_str()) {
                Some(policy) => {
                    let rule = self
                        .graph(&format!("/v1.0/policies/roleManagementPolicies/{policy}/rules/Approval_EndUser_Assignment"), false)
                        .await?;
                    rule.first().is_some_and(cis::approval_required)
                }
                None => false,
            };
            out.insert(field.into(), json!(approved));
        }
        Ok(out)
    }

    async fn defender_fields(&self) -> Result<serde_json::Map<String, Value>, ProviderError> {
        let mut out = serde_json::Map::new();
        let safe_links = self.exchange("Get-SafeLinksPolicy", "{}").await?;
        let anti_phish_policies = self.exchange("Get-AntiPhishPolicy", "{}").await?;
        out.extend(cis::scuba_defender_fields(&anti_phish_policies, &safe_links));
        out.insert("safe_links_policy".into(), json!(safe_links.iter().any(cis::safe_links_cis)));
        let safe_attachments = self.exchange("Get-SafeAttachmentPolicy", "{}").await?;
        out.insert("safe_attachments_policy".into(), json!(safe_attachments.iter().any(cis::safe_attachments_cis)));
        let anti_phish = self.exchange("Get-AntiPhishPolicy", "{}").await?;
        out.insert("anti_phish_policy".into(), json!(anti_phish.iter().any(cis::anti_phish_cis)));
        let atp = self.exchange("Get-ATPProtectionPolicyRule", "{}").await?;
        let eop = self.exchange("Get-EOPProtectionPolicyRule", "{}").await?;
        out.insert("strict_preset_policy".into(), json!(cis::strict_preset_on(&atp) && cis::strict_preset_on(&eop)));
        let malware = self.exchange_object("exchange_malware_filter_policies").await?;
        out.insert("comprehensive_attachment_filter".into(), json!(malware.iter().any(|p| p["_comprehensive_filter"] == true)));
        let org = self.exchange("Get-OrganizationConfig", "{}").await?;
        let owa = self.exchange("Get-OwaMailboxPolicy", "{}").await?;
        let bookings_off_org = org.first().is_some_and(|o| o["BookingsEnabled"] == false);
        let bookings_off_owa = owa
            .iter()
            .find(|p| p["IsDefault"] == true || p["Name"] == "OwaMailboxPolicy-Default")
            .is_some_and(|p| p["BookingsMailboxCreationEnabled"] == false);
        out.insert("shared_bookings_restricted".into(), json!(bookings_off_org || bookings_off_owa));
        let rules = self.exchange_object("exchange_transport_rules").await?;
        let redirects: Vec<Value> = rules
            .iter()
            .filter(|r| r["_external_redirects"].as_array().is_some_and(|a| !a.is_empty()))
            .map(|r| json!({ "rule": r["Name"], "to": r["_external_redirects"] }))
            .collect();
        out.insert("external_redirect_rules".into(), Value::Array(redirects));
        out.insert("external_sender_warning_rule".into(), json!(cis::external_sender_warning_rule(&rules)));
        let outbound = self.exchange("Get-HostedOutboundSpamFilterPolicy", "{}").await?;
        out.insert(
            "auto_forwarding_disabled".into(),
            json!(!outbound.is_empty() && outbound.iter().all(|p| p["AutoForwardingMode"] == "Off")),
        );
        Ok(out)
    }
}

/// Send a request, retrying throttling (429) and transient 5xx the way the
/// services ask (`Retry-After`).
async fn send<F>(build: F, what: &str) -> Result<Value, ProviderError>
where
    F: Fn() -> reqwest::RequestBuilder,
{
    for attempt in 1..=6u64 {
        let resp = build()
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("Microsoft 365 {what}: {e}")))?;
        let status = resp.status();
        if status.as_u16() == 429 || status.as_u16() == 503 || status.as_u16() == 504 {
            let wait = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5 * attempt)
                .min(60);
            tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            continue;
        }
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let detail: String = text.chars().take(400).collect();
            return Err(ProviderError::Api(format!("Microsoft 365 {what} ({status}): {detail}")));
        }
        return serde_json::from_str(&text)
            .map_err(|e| ProviderError::Api(format!("Microsoft 365 {what}: unreadable response: {e}")));
    }
    Err(ProviderError::RateLimited { retry_after_secs: 60 })
}

/// Some Teams configurations carry their scope only in `Key`: give every row
/// the `Identity` the PowerShell cmdlets show (`Global`, `Tag:<name>`).
fn teams_identity(mut row: Value) -> Value {
    if row.get("Identity").is_none() {
        let key = &row["Key"];
        let identity = match (key["ScopeClass"].as_str(), key["ScopeId"].as_str()) {
            (Some("Global"), _) | (None, None) => "Global".to_string(),
            (Some(_), Some(id)) => format!("Tag:{id}"),
            (Some(class), None) => class.to_string(),
            (None, Some(id)) => format!("Tag:{id}"),
        };
        row["Identity"] = json!(identity);
    }
    row
}

/// Drop the `@odata.type` / `*@data.type` annotations Exchange adds to every
/// property: they double the size of a row and no rule reads them.
fn strip_odata(mut row: Value) -> Value {
    if let Value::Object(m) = &mut row {
        m.retain(|k, _| !k.contains("@data.type") && !k.starts_with("@odata"));
    }
    row
}

async fn az_cli_token(resource: &str) -> Result<String, ProviderError> {
    let output = tokio::process::Command::new("az")
        .args(["account", "get-access-token", "--resource", resource, "--query", "accessToken", "-o", "tsv"])
        .output()
        .await
        .map_err(|e| {
            ProviderError::Auth(format!(
                "Microsoft 365: no service principal configured (AZURE_TENANT_ID, AZURE_CLIENT_ID, \
                 AZURE_CLIENT_SECRET) and the Azure CLI could not be run: {e}"
            ))
        })?;
    let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !output.status.success() || token.is_empty() {
        return Err(ProviderError::Auth(format!(
            "Microsoft 365: `az account get-access-token` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(token)
}

/// TXT records at `name`, chunks joined.
async fn txt(resolver: &hickory_resolver::TokioResolver, name: &str) -> Vec<String> {
    use hickory_resolver::proto::rr::{RData, RecordType};
    match resolver.lookup(name, RecordType::TXT).await {
        Ok(lookup) => lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::TXT(t) => Some(t.txt_data.iter().map(|c| String::from_utf8_lossy(c).into_owned()).collect()),
                _ => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// The domain's `v=spf1` record and the `all` qualifier it ends on, through
/// up to five `redirect=` hops (CIS 2.1.8 accepts `-all`/`~all`, SCuBA
/// MS.EXO.2.2 only `-all`).
async fn spf_check(resolver: &hickory_resolver::TokioResolver, domain: &str) -> (Value, Option<String>) {
    let mut name = domain.to_string();
    let mut first: Option<String> = None;
    for _ in 0..5 {
        let Some(record) = txt(resolver, &name).await.into_iter().find(|r| r.to_ascii_lowercase().starts_with("v=spf1")) else {
            return (json!(first), None);
        };
        first.get_or_insert(record.clone());
        match cis::spf_end(&record) {
            cis::SpfEnd::All(q) => return (json!(first), Some(q)),
            cis::SpfEnd::Redirect(target) => name = target,
            cis::SpfEnd::None => return (json!(first), None),
        }
    }
    (json!(first), None)
}

/// CIS 2.1.10: the domain's DMARC record, or its organizational domain's for
/// a subdomain without one of its own (RFC 7489 §6.6.3).
async fn dmarc_check(resolver: &hickory_resolver::TokioResolver, domain: &str) -> (Value, bool) {
    let find = |name: String| async move {
        txt(resolver, &name).await.into_iter().find(|r| r.to_ascii_lowercase().starts_with("v=dmarc1"))
    };
    if let Some(r) = find(format!("_dmarc.{domain}")).await {
        let ok = cis::dmarc_compliant(&r, false);
        return (json!(r), ok);
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() > 2 {
        let org = labels[labels.len() - 2..].join(".");
        if let Some(r) = find(format!("_dmarc.{org}")).await {
            let ok = cis::dmarc_compliant(&r, true);
            return (json!(r), ok);
        }
    }
    (Value::Null, false)
}

#[async_trait::async_trait]
impl Provider for M365Provider {
    fn name(&self) -> &str {
        "m365"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        if GRAPH_OBJECTS.iter().any(|(o, _, _)| *o == resource_type) {
            return self.graph_object(resource_type).await;
        }
        if EXCHANGE_OBJECTS.iter().any(|(o, _, _)| *o == resource_type) {
            return self.exchange_object(resource_type).await;
        }
        if let Some((_, config)) = TEAMS_OBJECTS.iter().find(|(o, _)| *o == resource_type) {
            return self.teams(config).await;
        }
        match resource_type {
            "tenant" => self.tenant().await,
            "mail_domains" => self.mail_domains().await,
            "shared_mailboxes" => self.shared_mailboxes().await,
            _ => Err(ProviderError::UnsupportedResourceType(format!(
                "'{resource_type}' is not a Microsoft 365 object; available: {}",
                RESOURCE_TYPES.join(", ")
            ))),
        }
    }

    /// Every object concurrently: the reads they share are made once.
    async fn gather_all(&self) -> Result<HashMap<String, Vec<Value>>, ProviderError> {
        let results = futures::future::join_all(RESOURCE_TYPES.iter().map(|t| async move { (*t, self.gather(t).await) })).await;
        let mut out = HashMap::new();
        for (t, r) in results {
            match r {
                Ok(rows) => {
                    out.insert(t.to_string(), rows);
                }
                Err(e) => {
                    tracing::warn!(object = %t, error = %e, "Microsoft 365: gather failed");
                    out.insert(t.to_string(), vec![json!({ "error": e.to_string() })]);
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
    fn objects_are_unique_and_snake_case() {
        let mut seen = HashSet::new();
        for t in RESOURCE_TYPES.iter() {
            assert!(seen.insert(*t), "{t} listed twice");
            assert!(t.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{t}");
        }
        assert!(RESOURCE_TYPES.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn exchange_annotations_are_dropped() {
        let row = strip_odata(json!({"Name": "x", "Name@data.type": "System.String", "@odata.id": "y"}));
        assert_eq!(row, json!({"Name": "x"}));
    }
}
