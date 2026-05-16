//! Google Workspace provider — audits user 2-Step Verification (2FA/MFA)
//! enrollment and Google Drive file sharing exposure.
//!
//! Two authentication modes:
//!
//!   * **OAuth / Application Default Credentials** — scans the authenticated
//!     account only. Run once:
//!     `gcloud auth application-default login --scopes=<directory>,<drive>`.
//!     No admin rights required for the Drive scan; the `users` resource
//!     additionally needs the account to be a Workspace admin.
//!
//!   * **Service account with domain-wide delegation** — audits the whole
//!     domain. Provide `credentials_file` (service account key JSON) and
//!     `subject` (the admin email to impersonate). Set `scan_all_users` to
//!     iterate every user's Drive.
//!
//! Resource types:
//!   * `users`       — directory users with 2SV/MFA and admin status
//!   * `drive_files` — owned Drive files with their sharing classification

use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Value};

const RESOURCE_TYPES: &[&str] = &["users", "drive_files"];

const SCOPE_DIRECTORY: &str = "https://www.googleapis.com/auth/admin.directory.user.readonly";
const SCOPE_DRIVE: &str = "https://www.googleapis.com/auth/drive.metadata.readonly";
const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// Service account key material used for domain-wide delegation.
struct ServiceAccount {
    client_email: String,
    private_key: String,
}

pub struct GoogleWorkspaceProvider {
    client: reqwest::Client,
    /// Service account key, set when running in domain-wide delegation mode.
    service_account: Option<ServiceAccount>,
    /// Admin user to impersonate for the Directory API (service account mode).
    subject: Option<String>,
    /// Static access token override — skips all token minting.
    access_token: Option<String>,
    /// Directory API customer ID (defaults to `my_customer`).
    customer: String,
    /// Organization primary domain, used to classify external Drive sharing.
    domain: Option<String>,
    /// When true, `drive_files` iterates every directory user's Drive
    /// (service account mode only).
    scan_all_users: bool,
    /// Single user whose Drive to scan; defaults to `subject` in service
    /// account mode, or the authenticated account in OAuth mode.
    drive_user: Option<String>,
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
        let drive_user = get_config_or_env(&config, "DRIVE_USER", Some("GOOGLE_WORKSPACE"));

        Ok(Self {
            client,
            service_account,
            subject,
            access_token,
            customer,
            domain,
            scan_all_users,
            drive_user,
        })
    }

    /// Obtain an access token for `scope`. In service account mode the token
    /// is minted for `subject` (or the override) via domain-wide delegation;
    /// otherwise Application Default Credentials are used.
    async fn token(&self, scope: &str, subject: Option<&str>) -> Result<String, ProviderError> {
        if let Some(tok) = &self.access_token {
            return Ok(tok.clone());
        }

        if let Some(sa) = &self.service_account {
            let sub = subject.or(self.subject.as_deref()).ok_or_else(|| {
                ProviderError::InvalidConfig("missing `subject` for domain-wide delegation".into())
            })?;
            return self.mint_delegated_token(sa, sub, scope).await;
        }

        // Application Default Credentials (OAuth user via gcloud, or a
        // service account picked up from GOOGLE_APPLICATION_CREDENTIALS).
        let provider = gcp_auth::provider().await.map_err(|e| {
            ProviderError::Connection(format!(
                "Google ADC auth failed: {} — run \
                 `gcloud auth application-default login` or configure a service account",
                e
            ))
        })?;
        let token = provider
            .token(&[scope])
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
        scope: &str,
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
            scope,
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

    /// List directory users with their 2SV/MFA and admin status.
    async fn gather_users(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.token(SCOPE_DIRECTORY, None).await?;
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut url = format!(
                "https://admin.googleapis.com/admin/directory/v1/users\
                 ?customer={}&maxResults=500&projection=full&viewType=admin_view",
                self.customer
            );
            if let Some(pt) = &page_token {
                url.push_str("&pageToken=");
                url.push_str(pt);
            }
            let page = self.api_get(&token, &url).await?;
            if let Some(arr) = page["users"].as_array() {
                for u in arr {
                    out.push(map_user(u));
                }
            }
            match page["nextPageToken"].as_str() {
                Some(pt) if !pt.is_empty() => page_token = Some(pt.to_string()),
                _ => break,
            }
        }
        Ok(out)
    }

    /// List Drive files owned by `subject` (or the authenticated account when
    /// `subject` is `None`) with their sharing classification.
    async fn drive_files(&self, subject: Option<&str>) -> Result<Vec<Value>, ProviderError> {
        let token = self.token(SCOPE_DRIVE, subject).await?;
        let scanned_user = subject.unwrap_or("me");
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

    /// Iterate every active directory user and gather their owned Drive files.
    async fn drive_files_all_users(&self) -> Result<Vec<Value>, ProviderError> {
        if self.service_account.is_none() {
            return Err(ProviderError::InvalidConfig(
                "`scan_all_users` requires a service account with domain-wide delegation".into(),
            ));
        }
        let users = self.gather_users().await?;
        let mut out = Vec::new();
        for u in &users {
            let email = u["email"].as_str().unwrap_or("");
            if email.is_empty()
                || u["suspended"].as_bool().unwrap_or(false)
                || u["archived"].as_bool().unwrap_or(false)
            {
                continue;
            }
            match self.drive_files(Some(email)).await {
                Ok(mut files) => out.append(&mut files),
                Err(e) => tracing::warn!(user = %email, error = %e, "Drive scan failed for user"),
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

/// Map a Directory API user object to kxn's snake_case shape.
fn map_user(u: &Value) -> Value {
    json!({
        "email": u["primaryEmail"].as_str().unwrap_or(""),
        "full_name": u["name"]["fullName"].as_str().unwrap_or(""),
        "is_admin": u["isAdmin"].as_bool().unwrap_or(false),
        "is_delegated_admin": u["isDelegatedAdmin"].as_bool().unwrap_or(false),
        "is_enrolled_2sv": u["isEnrolledIn2Sv"].as_bool().unwrap_or(false),
        "is_enforced_2sv": u["isEnforcedIn2Sv"].as_bool().unwrap_or(false),
        "suspended": u["suspended"].as_bool().unwrap_or(false),
        "archived": u["archived"].as_bool().unwrap_or(false),
        "last_login_time": u["lastLoginTime"].as_str().unwrap_or(""),
        "creation_time": u["creationTime"].as_str().unwrap_or(""),
        "org_unit_path": u["orgUnitPath"].as_str().unwrap_or("/"),
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
            "drive_files" => {
                if self.scan_all_users {
                    self.drive_files_all_users().await
                } else {
                    let subject = self.drive_user.as_deref().or(if self.service_account.is_some() {
                        self.subject.as_deref()
                    } else {
                        None
                    });
                    self.drive_files(subject).await
                }
            }
            _ => Err(ProviderError::NotFound(format!(
                "Unknown resource type '{}' for googleworkspace provider (expected: users, drive_files)",
                resource_type
            ))),
        }
    }
}
