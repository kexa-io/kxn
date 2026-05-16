//! Google Workspace provider — audits the configuration surface that Google
//! exposes through read APIs: user 2-Step Verification (2FA/MFA), Drive file
//! sharing, third-party OAuth app grants, groups, devices, domains and admin
//! role assignments.
//!
//! Two authentication modes:
//!
//!   * **OAuth / Application Default Credentials** — scans the authenticated
//!     account only. Run once:
//!     `gcloud auth application-default login --scopes=<see docs>`.
//!     The directory/device/group/role resources additionally require the
//!     account to be a Workspace admin.
//!
//!   * **Service account with domain-wide delegation** — audits the whole
//!     domain. Provide `credentials_file` (service account key JSON) and
//!     `subject` (the admin email to impersonate). Set `scan_all_users` to
//!     walk every user's Drive and OAuth grants.
//!
//! Resource types: `users`, `domains`, `groups`, `oauth_tokens`,
//! `mobile_devices`, `chromeos_devices`, `role_assignments`, `drive_files`.
//!
//! Some Workspace security settings — org-wide Gmail/Drive/Calendar/Apps
//! policies, Marketplace restrictions, context-aware access — have no read
//! API and cannot be audited by any tool; they are out of scope here.

use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Value};

const RESOURCE_TYPES: &[&str] = &[
    "users",
    "domains",
    "groups",
    "oauth_tokens",
    "mobile_devices",
    "chromeos_devices",
    "role_assignments",
    "drive_files",
];

/// Read-only scopes requested for every token. The Workspace admin authorizes
/// this exact set when configuring domain-wide delegation.
const SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.security",
    "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
    "https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly",
    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
    "https://www.googleapis.com/auth/apps.groups.settings",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
];

const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const DIRECTORY_BASE: &str = "https://admin.googleapis.com/admin/directory/v1";

/// Service account key material used for domain-wide delegation.
struct ServiceAccount {
    client_email: String,
    private_key: String,
}

pub struct GoogleWorkspaceProvider {
    client: reqwest::Client,
    /// Service account key, set when running in domain-wide delegation mode.
    service_account: Option<ServiceAccount>,
    /// Admin user to impersonate (service account mode).
    subject: Option<String>,
    /// Static access token override — skips all token minting.
    access_token: Option<String>,
    /// Directory API customer ID (defaults to `my_customer`).
    customer: String,
    /// Organization primary domain, used to classify external Drive sharing.
    domain: Option<String>,
    /// When true, per-user resources iterate every directory user
    /// (service account mode only).
    scan_all_users: bool,
}

impl GoogleWorkspaceProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let client = reqwest::Client::builder()
            .user_agent("kxn")
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| ProviderError::Connection(format!("HTTP client: {}", e)))?;

        let access_token = get_config_or_env(&config, "ACCESS_TOKEN", Some("GOOGLE_WORKSPACE"));

        // Service account: explicit key file path or inline JSON.
        let sa_path = get_config_or_env(&config, "CREDENTIALS_FILE", Some("GOOGLE_WORKSPACE"));
        let sa_inline = get_config_or_env(&config, "CREDENTIALS", Some("GOOGLE_WORKSPACE"));
        let service_account = match (sa_path, sa_inline) {
            (Some(path), _) => Some(load_service_account_file(&path)?),
            (None, Some(raw)) => Some(parse_service_account(&raw)?),
            (None, None) => None,
        };

        let subject = get_config_or_env(&config, "SUBJECT", Some("GOOGLE_WORKSPACE"))
            .or_else(|| get_config_or_env(&config, "IMPERSONATE", Some("GOOGLE_WORKSPACE")));

        if service_account.is_some() && subject.is_none() {
            return Err(ProviderError::InvalidConfig(
                "Service account mode requires `subject` — the Workspace admin email \
                 to impersonate via domain-wide delegation"
                    .into(),
            ));
        }

        let customer = get_config_or_env(&config, "CUSTOMER", Some("GOOGLE_WORKSPACE"))
            .unwrap_or_else(|| "my_customer".to_string());
        let domain = get_config_or_env(&config, "DOMAIN", Some("GOOGLE_WORKSPACE"));
        let scan_all_users = get_config_or_env(&config, "SCAN_ALL_USERS", Some("GOOGLE_WORKSPACE"))
            .map(|s| matches!(s.as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);

        Ok(Self {
            client,
            service_account,
            subject,
            access_token,
            customer,
            domain,
            scan_all_users,
        })
    }

    /// Obtain an access token. In service account mode the token impersonates
    /// `subject` (or the override) via domain-wide delegation; otherwise
    /// Application Default Credentials are used.
    async fn token(&self, subject: Option<&str>) -> Result<String, ProviderError> {
        if let Some(tok) = &self.access_token {
            return Ok(tok.clone());
        }

        if let Some(sa) = &self.service_account {
            let sub = subject.or(self.subject.as_deref()).ok_or_else(|| {
                ProviderError::InvalidConfig("missing `subject` for domain-wide delegation".into())
            })?;
            return self.mint_delegated_token(sa, sub).await;
        }

        let provider = gcp_auth::provider().await.map_err(|e| {
            ProviderError::Connection(format!(
                "Google ADC auth failed: {} — run \
                 `gcloud auth application-default login` or configure a service account",
                e
            ))
        })?;
        let token = provider
            .token(SCOPES)
            .await
            .map_err(|e| ProviderError::Connection(format!("Google token request failed: {}", e)))?;
        Ok(token.as_str().to_string())
    }

    /// Sign a JWT assertion and exchange it for an access token impersonating
    /// `subject` (domain-wide delegation flow).
    async fn mint_delegated_token(
        &self,
        sa: &ServiceAccount,
        subject: &str,
    ) -> Result<String, ProviderError> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        #[derive(serde::Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            sub: &'a str,
            scope: &'a str,
            aud: &'a str,
            iat: i64,
            exp: i64,
        }

        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            iss: &sa.client_email,
            sub: subject,
            scope: &SCOPES.join(" "),
            aud: TOKEN_URI,
            iat: now,
            exp: now + 3600,
        };
        let key = EncodingKey::from_rsa_pem(sa.private_key.as_bytes()).map_err(|e| {
            ProviderError::InvalidConfig(format!("invalid service account private key: {}", e))
        })?;
        let jwt = encode(&Header::new(Algorithm::RS256), &claims, &key)
            .map_err(|e| ProviderError::Connection(format!("JWT signing failed: {}", e)))?;

        let resp = self
            .client
            .post(TOKEN_URI)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", jwt.as_str()),
            ])
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("token request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Connection(format!(
                "domain-wide delegation token request failed ({}): {} — verify the service \
                 account's client ID is authorized for the requested scopes in the Admin console \
                 (Security > API controls > Domain-wide delegation)",
                status, body
            )));
        }

        let body: Value = resp
            .json()
            .await
            .map_err(|e| ProviderError::Connection(format!("token response parse failed: {}", e)))?;
        body["access_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ProviderError::Connection("no access_token in token response".into()))
    }

    /// GET a JSON document from a Google API endpoint.
    async fn api_get(&self, token: &str, url: &str) -> Result<Value, ProviderError> {
        let resp = self
            .client
            .get(url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("GET failed: {}", e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Connection(format!(
                "Google API request failed ({}): {}",
                status, body
            )));
        }
        resp.json::<Value>()
            .await
            .map_err(|e| ProviderError::Connection(format!("response parse failed: {}", e)))
    }

    /// Paginate a Directory API list endpoint, collecting `items_key`.
    /// `path` must already include its query string (customer, maxResults…).
    async fn directory_list(
        &self,
        token: &str,
        path: &str,
        items_key: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut url = format!("{}/{}", DIRECTORY_BASE, path);
            if let Some(pt) = &page_token {
                url.push_str("&pageToken=");
                url.push_str(pt);
            }
            let page = self.api_get(token, &url).await?;
            if let Some(arr) = page[items_key].as_array() {
                out.extend(arr.iter().cloned());
            }
            match page["nextPageToken"].as_str() {
                Some(pt) if !pt.is_empty() => page_token = Some(pt.to_string()),
                _ => break,
            }
        }
        Ok(out)
    }

    /// The list of user accounts to scan for per-user resources
    /// (`drive_files`, `oauth_tokens`).
    ///
    ///   * service account + `scan_all_users` → every active directory user
    ///   * service account                   → just `subject`
    ///   * OAuth / ADC                        → the authenticated account
    async fn target_users(&self) -> Result<Vec<String>, ProviderError> {
        if self.service_account.is_none() {
            return Ok(vec!["me".to_string()]);
        }
        if !self.scan_all_users {
            let sub = self.subject.clone().ok_or_else(|| {
                ProviderError::InvalidConfig("missing `subject` for domain-wide delegation".into())
            })?;
            return Ok(vec![sub]);
        }
        let users = self.gather_users().await?;
        Ok(users
            .iter()
            .filter(|u| {
                !u["suspended"].as_bool().unwrap_or(false)
                    && !u["archived"].as_bool().unwrap_or(false)
            })
            .filter_map(|u| u["email"].as_str())
            .filter(|e| !e.is_empty())
            .map(String::from)
            .collect())
    }

    // --- Resource gatherers ---------------------------------------------------

    async fn gather_users(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.token(None).await?;
        let path = format!(
            "users?customer={}&maxResults=500&projection=full&viewType=admin_view",
            self.customer
        );
        let raw = self.directory_list(&token, &path, "users").await?;
        Ok(raw.iter().map(map_user).collect())
    }

    async fn gather_domains(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.token(None).await?;
        let path = format!("customer/{}/domains?", self.customer);
        let raw = self.directory_list(&token, &path, "domains").await?;
        Ok(raw.iter().map(map_domain).collect())
    }

    async fn gather_mobile_devices(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.token(None).await?;
        let path = format!(
            "customer/{}/devices/mobile?maxResults=100&projection=FULL",
            self.customer
        );
        let raw = self.directory_list(&token, &path, "mobiledevices").await?;
        Ok(raw.iter().map(map_mobile_device).collect())
    }

    async fn gather_chromeos_devices(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.token(None).await?;
        let path = format!(
            "customer/{}/devices/chromeos?maxResults=100&projection=FULL",
            self.customer
        );
        let raw = self.directory_list(&token, &path, "chromeosdevices").await?;
        Ok(raw.iter().map(map_chromeos_device).collect())
    }

    async fn gather_role_assignments(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.token(None).await?;
        // Resolve role IDs to names / privilege level.
        let roles_path = format!("customer/{}/roles?maxResults=100", self.customer);
        let roles = self.directory_list(&token, &roles_path, "items").await?;
        let role_index: std::collections::HashMap<String, (String, bool)> = roles
            .iter()
            .filter_map(|r| {
                let id = r["roleId"].as_str()?.to_string();
                let name = r["roleName"].as_str().unwrap_or("").to_string();
                let is_super = r["isSuperAdminRole"].as_bool().unwrap_or(false);
                Some((id, (name, is_super)))
            })
            .collect();

        let path = format!("customer/{}/roleassignments?maxResults=200", self.customer);
        let raw = self.directory_list(&token, &path, "items").await?;
        Ok(raw
            .iter()
            .map(|ra| map_role_assignment(ra, &role_index))
            .collect())
    }

    async fn gather_groups(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.token(None).await?;
        let path = format!("groups?customer={}&maxResults=200", self.customer);
        let raw = self.directory_list(&token, &path, "groups").await?;

        let mut out = Vec::new();
        for g in &raw {
            let email = g["email"].as_str().unwrap_or("");
            // Group security settings live in the separate Groups Settings API.
            let settings = if email.is_empty() {
                Value::Null
            } else {
                let url = format!(
                    "https://www.googleapis.com/groups/v1/groups/{}?alt=json",
                    email
                );
                match self.api_get(&token, &url).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(group = %email, error = %e, "group settings fetch failed");
                        Value::Null
                    }
                }
            };
            out.push(map_group(g, &settings));
        }
        Ok(out)
    }

    async fn gather_oauth_tokens(&self) -> Result<Vec<Value>, ProviderError> {
        let mut out = Vec::new();
        for email in self.target_users().await? {
            let subject = if self.service_account.is_some() {
                Some(email.as_str())
            } else {
                None
            };
            let token = self.token(subject).await?;
            let key = if email == "me" { "me" } else { email.as_str() };
            let url = format!("{}/users/{}/tokens", DIRECTORY_BASE, key);
            match self.api_get(&token, &url).await {
                Ok(page) => {
                    if let Some(arr) = page["items"].as_array() {
                        for t in arr {
                            out.push(map_oauth_token(t, &email));
                        }
                    }
                }
                Err(e) => tracing::warn!(user = %email, error = %e, "OAuth token scan failed"),
            }
        }
        Ok(out)
    }

    async fn gather_drive_files(&self) -> Result<Vec<Value>, ProviderError> {
        let mut out = Vec::new();
        for email in self.target_users().await? {
            let subject = if self.service_account.is_some() {
                Some(email.as_str())
            } else {
                None
            };
            match self.drive_files_for(subject, &email).await {
                Ok(mut files) => out.append(&mut files),
                Err(e) => tracing::warn!(user = %email, error = %e, "Drive scan failed for user"),
            }
        }
        Ok(out)
    }

    /// List Drive files owned by one user with their sharing classification.
    async fn drive_files_for(
        &self,
        subject: Option<&str>,
        scanned_user: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        let token = self.token(subject).await?;
        let fields = "nextPageToken,files(id,name,mimeType,owners(emailAddress,displayName),\
                      shared,webViewLink,modifiedTime,\
                      permissions(id,type,role,emailAddress,domain,allowFileDiscovery))";
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut req = self
                .client
                .get("https://www.googleapis.com/drive/v3/files")
                .header("Authorization", format!("Bearer {}", token))
                .query(&[
                    ("q", "'me' in owners and trashed = false"),
                    ("fields", fields),
                    ("pageSize", "1000"),
                    ("corpora", "user"),
                    ("orderBy", "modifiedTime desc"),
                ]);
            if let Some(pt) = &page_token {
                req = req.query(&[("pageToken", pt.as_str())]);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| ProviderError::Connection(format!("Drive list failed: {}", e)))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(ProviderError::Connection(format!(
                    "Drive files.list failed for {} ({}): {}",
                    scanned_user, status, body
                )));
            }
            let page: Value = resp.json().await.map_err(|e| {
                ProviderError::Connection(format!("Drive response parse failed: {}", e))
            })?;
            if let Some(arr) = page["files"].as_array() {
                for f in arr {
                    out.push(self.map_drive_file(f, scanned_user));
                }
            }
            match page["nextPageToken"].as_str() {
                Some(pt) if !pt.is_empty() => page_token = Some(pt.to_string()),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Classify a single Drive file's sharing exposure.
    fn map_drive_file(&self, f: &Value, scanned_user: &str) -> Value {
        let owner_email = f["owners"][0]["emailAddress"].as_str().unwrap_or("");
        let org_domain = self
            .domain
            .clone()
            .or_else(|| owner_email.rsplit('@').next().map(|s| s.to_string()))
            .unwrap_or_default();

        let mut shared_with_anyone = false;
        let mut public_discoverable = false;
        let mut external: Vec<String> = Vec::new();
        if let Some(perms) = f["permissions"].as_array() {
            for p in perms {
                match p["type"].as_str().unwrap_or("") {
                    "anyone" => {
                        shared_with_anyone = true;
                        if p["allowFileDiscovery"].as_bool().unwrap_or(false) {
                            public_discoverable = true;
                        }
                    }
                    "domain" => {
                        let d = p["domain"].as_str().unwrap_or("");
                        if !org_domain.is_empty() && !d.is_empty() && d != org_domain {
                            external.push(format!("domain:{}", d));
                        }
                    }
                    "user" | "group" => {
                        let email = p["emailAddress"].as_str().unwrap_or("");
                        let edom = email.rsplit('@').next().unwrap_or("");
                        if !org_domain.is_empty() && !edom.is_empty() && edom != org_domain {
                            external.push(email.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
        let shared_externally = shared_with_anyone || !external.is_empty();

        json!({
            "id": f["id"].as_str().unwrap_or(""),
            "name": f["name"].as_str().unwrap_or(""),
            "mime_type": f["mimeType"].as_str().unwrap_or(""),
            "owner": owner_email,
            "scanned_user": scanned_user,
            "web_view_link": f["webViewLink"].as_str().unwrap_or(""),
            "modified_time": f["modifiedTime"].as_str().unwrap_or(""),
            "shared": f["shared"].as_bool().unwrap_or(false),
            "shared_with_anyone": shared_with_anyone,
            "public_discoverable": public_discoverable,
            "shared_externally": shared_externally,
            "external_recipients": external,
            "permission_count": f["permissions"].as_array().map(|a| a.len()).unwrap_or(0),
        })
    }
}

// --- Mapping helpers ----------------------------------------------------------

/// Days elapsed since an RFC3339 timestamp; `-1` if it cannot be parsed.
fn days_since(ts: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|d| (chrono::Utc::now() - d.with_timezone(&chrono::Utc)).num_days())
        .unwrap_or(-1)
}

/// Map a Directory API user to kxn's snake_case shape.
fn map_user(u: &Value) -> Value {
    let last_login = u["lastLoginTime"].as_str().unwrap_or("");
    json!({
        "email": u["primaryEmail"].as_str().unwrap_or(""),
        "full_name": u["name"]["fullName"].as_str().unwrap_or(""),
        "is_admin": u["isAdmin"].as_bool().unwrap_or(false),
        "is_delegated_admin": u["isDelegatedAdmin"].as_bool().unwrap_or(false),
        "is_enrolled_2sv": u["isEnrolledIn2Sv"].as_bool().unwrap_or(false),
        "is_enforced_2sv": u["isEnforcedIn2Sv"].as_bool().unwrap_or(false),
        "suspended": u["suspended"].as_bool().unwrap_or(false),
        "archived": u["archived"].as_bool().unwrap_or(false),
        "last_login_time": last_login,
        "days_since_last_login": days_since(last_login),
        "creation_time": u["creationTime"].as_str().unwrap_or(""),
        "org_unit_path": u["orgUnitPath"].as_str().unwrap_or("/"),
    })
}

/// Map a Directory API domain object.
fn map_domain(d: &Value) -> Value {
    json!({
        "domain_name": d["domainName"].as_str().unwrap_or(""),
        "verified": d["verified"].as_bool().unwrap_or(false),
        "is_primary": d["isPrimary"].as_bool().unwrap_or(false),
        "creation_time": d["creationTime"].as_str().unwrap_or(""),
    })
}

/// Map a Directory API mobile device object.
fn map_mobile_device(d: &Value) -> Value {
    let encryption_status = d["encryptionStatus"].as_str().unwrap_or("");
    // iOS devices are hardware-encrypted by default and Google's Admin SDK
    // leaves `encryptionStatus` empty for them. Treat a device as encrypted
    // unless the API explicitly reports it as not encrypted, so iOS and
    // devices with an unknown status are not flagged as false positives.
    let encrypted = !encryption_status.eq_ignore_ascii_case("notEncrypted");
    json!({
        "device_id": d["deviceId"].as_str().unwrap_or(""),
        "user": d["email"][0].as_str().unwrap_or(""),
        "model": d["model"].as_str().unwrap_or(""),
        "os": d["os"].as_str().unwrap_or(""),
        "type": d["type"].as_str().unwrap_or(""),
        "status": d["status"].as_str().unwrap_or(""),
        "encryption_status": encryption_status,
        "encrypted": encrypted,
        "security_patch_level": d["securityPatchLevel"].as_str().unwrap_or(""),
        "last_sync": d["lastSync"].as_str().unwrap_or(""),
    })
}

/// Map a Directory API ChromeOS device object.
fn map_chromeos_device(d: &Value) -> Value {
    json!({
        "device_id": d["deviceId"].as_str().unwrap_or(""),
        "serial_number": d["serialNumber"].as_str().unwrap_or(""),
        "status": d["status"].as_str().unwrap_or(""),
        "os_version": d["osVersion"].as_str().unwrap_or(""),
        "model": d["model"].as_str().unwrap_or(""),
        "annotated_user": d["annotatedUser"].as_str().unwrap_or(""),
        "last_sync": d["lastSync"].as_str().unwrap_or(""),
    })
}

/// Map a Directory API role assignment, enriched with the role name and
/// whether it grants super-admin privileges.
fn map_role_assignment(
    ra: &Value,
    role_index: &std::collections::HashMap<String, (String, bool)>,
) -> Value {
    let role_id = ra["roleId"].as_str().unwrap_or("");
    let (role_name, is_super) = role_index
        .get(role_id)
        .cloned()
        .unwrap_or_else(|| (String::new(), false));
    json!({
        "assigned_to": ra["assignedTo"].as_str().unwrap_or(""),
        "role_id": role_id,
        "role_name": role_name,
        "is_super_admin_role": is_super,
        "scope_type": ra["scopeType"].as_str().unwrap_or(""),
        "org_unit_id": ra["orgUnitId"].as_str().unwrap_or(""),
    })
}

/// Map a Directory API group, merged with its Groups Settings API record.
/// The Groups Settings API returns booleans as the strings `"true"`/`"false"`.
fn map_group(g: &Value, settings: &Value) -> Value {
    let str_bool = |v: &Value| v.as_str() == Some("true");
    json!({
        "email": g["email"].as_str().unwrap_or(""),
        "name": g["name"].as_str().unwrap_or(""),
        "description": g["description"].as_str().unwrap_or(""),
        "direct_members_count": g["directMembersCount"].as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .or_else(|| g["directMembersCount"].as_i64())
            .unwrap_or(0),
        "allow_external_members": str_bool(&settings["allowExternalMembers"]),
        "who_can_post_message": settings["whoCanPostMessage"].as_str().unwrap_or(""),
        "who_can_join": settings["whoCanJoin"].as_str().unwrap_or(""),
        "who_can_view_group": settings["whoCanViewGroup"].as_str().unwrap_or(""),
        "who_can_view_membership": settings["whoCanViewMembership"].as_str().unwrap_or(""),
        "who_can_contact_owner": settings["whoCanContactOwner"].as_str().unwrap_or(""),
    })
}

/// True when an OAuth scope grants broad access to user data (mail, Drive,
/// directory, the whole cloud platform).
fn is_high_risk_scope(s: &str) -> bool {
    const RISKY: &[&str] = &[
        "mail.google.com",
        "/auth/gmail",
        "/auth/drive",
        "/auth/admin.directory",
        "/auth/cloud-platform",
        "/auth/spreadsheets",
        "/auth/documents",
    ];
    RISKY.iter().any(|r| s.contains(r))
}

/// Map a Directory API OAuth token (a third-party app grant).
fn map_oauth_token(t: &Value, user: &str) -> Value {
    let scopes: Vec<String> = t["scopes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let has_high_risk = scopes.iter().any(|s| is_high_risk_scope(s));
    json!({
        "user": if user == "me" { t["userKey"].as_str().unwrap_or("me") } else { user },
        "app": t["displayText"].as_str().unwrap_or(""),
        "client_id": t["clientId"].as_str().unwrap_or(""),
        "native_app": t["nativeApp"].as_bool().unwrap_or(false),
        "anonymous": t["anonymous"].as_bool().unwrap_or(false),
        "scope_count": scopes.len(),
        "has_high_risk_scope": has_high_risk,
        "scopes": scopes,
    })
}

/// Parse a service account key JSON document.
fn parse_service_account(raw: &str) -> Result<ServiceAccount, ProviderError> {
    let v: Value = serde_json::from_str(raw)
        .map_err(|e| ProviderError::InvalidConfig(format!("invalid service account JSON: {}", e)))?;
    let client_email = v["client_email"]
        .as_str()
        .ok_or_else(|| {
            ProviderError::InvalidConfig("service account JSON missing `client_email`".into())
        })?
        .to_string();
    let private_key = v["private_key"]
        .as_str()
        .ok_or_else(|| {
            ProviderError::InvalidConfig("service account JSON missing `private_key`".into())
        })?
        .to_string();
    Ok(ServiceAccount {
        client_email,
        private_key,
    })
}

/// Load and parse a service account key file from disk.
fn load_service_account_file(path: &str) -> Result<ServiceAccount, ProviderError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        ProviderError::InvalidConfig(format!("cannot read service account file '{}': {}", path, e))
    })?;
    parse_service_account(&content)
}

#[async_trait::async_trait]
impl Provider for GoogleWorkspaceProvider {
    fn name(&self) -> &str {
        "googleworkspace"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        match resource_type {
            "users" => self.gather_users().await,
            "domains" => self.gather_domains().await,
            "groups" => self.gather_groups().await,
            "oauth_tokens" => self.gather_oauth_tokens().await,
            "mobile_devices" => self.gather_mobile_devices().await,
            "chromeos_devices" => self.gather_chromeos_devices().await,
            "role_assignments" => self.gather_role_assignments().await,
            "drive_files" => self.gather_drive_files().await,
            _ => Err(ProviderError::NotFound(format!(
                "Unknown resource type '{}' for googleworkspace provider (expected one of: {})",
                resource_type,
                RESOURCE_TYPES.join(", ")
            ))),
        }
    }
}
