//! GitLab (self-managed or gitlab.com) through its REST API v4.
//!
//! `gitlab://gitlab.example.com` with a token in GITLAB_TOKEN (scope
//! `read_api`; an administrator's token also reads the instance settings,
//! every user's 2FA status and every personal access token). What a token
//! may not read comes back empty, so its rules show as not evaluated.

use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::secrets;
use crate::traits::Provider;
use serde_json::{json, Value};
use tokio::sync::OnceCell;

pub(crate) const RESOURCE_TYPES: &[&str] = &[
    "version",
    "settings",
    "users",
    "projects",
    "personal_access_tokens",
];

/// At most this many pages of 100 per list.
const MAX_PAGES: u32 = 50;

pub struct GitlabProvider {
    base_url: String,
    token_ref: Option<String>,
    token: OnceCell<Option<String>>,
    client: reqwest::Client,
}

impl GitlabProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let mut base_url = get_config_or_env(&config, "URL", Some("GITLAB"))
            .unwrap_or_else(|| "https://gitlab.com".to_string())
            .trim_end_matches('/')
            .to_string();
        let insecure = get_config_or_env(&config, "INSECURE", Some("GITLAB"))
            .is_some_and(|v| v == "true" || v == "1");
        if insecure {
            base_url = base_url.replacen("https://", "http://", 1);
        }
        let token_ref = get_config_or_env(&config, "TOKEN", Some("GITLAB"))
            .or_else(|| std::env::var("GITLAB_TOKEN").ok())
            .filter(|t| !t.is_empty());
        let client = reqwest::Client::builder()
            .user_agent(concat!("kxn/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| ProviderError::Connection(format!("HTTP client: {}", e)))?;
        Ok(Self { base_url, token_ref, token: OnceCell::new(), client })
    }

    /// A literal token, an env var name or a `secret:…` reference.
    async fn token(&self) -> Result<Option<&str>, ProviderError> {
        self.token
            .get_or_try_init(|| async {
                let Some(r) = &self.token_ref else { return Ok(None) };
                if r.starts_with("secret:") {
                    secrets::resolve_ref(r)
                        .await
                        .map(Some)
                        .map_err(|e| ProviderError::InvalidConfig(format!("GitLab token `{}`: {}", r, e)))
                } else {
                    Ok(Some(r.clone()))
                }
            })
            .await
            .map(|t| t.as_deref())
    }

    /// GET one API path. `Ok(None)` when the token may not read it (401/403/404).
    async fn get(&self, path: &str) -> Result<Option<(Value, Option<String>)>, ProviderError> {
        let mut req = self.client.get(format!("{}/api/v4{}", self.base_url, path));
        if let Some(t) = self.token().await? {
            req = req.header("PRIVATE-TOKEN", t);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("GitLab {}: {}", self.base_url, e)))?;
        let status = resp.status();
        if matches!(status.as_u16(), 401 | 403 | 404) {
            if path == "/version" {
                return Err(ProviderError::Auth(format!(
                    "GitLab {} answered {} on /api/v4/version: set GITLAB_TOKEN (scope read_api)",
                    self.base_url, status
                )));
            }
            return Ok(None);
        }
        if !status.is_success() {
            return Err(ProviderError::Query(format!("GitLab {}{}: HTTP {}", self.base_url, path, status)));
        }
        let next = resp
            .headers()
            .get("x-next-page")
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            .map(String::from);
        let body = resp
            .json::<Value>()
            .await
            .map_err(|e| ProviderError::Query(format!("GitLab {}: {}", path, e)))?;
        Ok(Some((body, next)))
    }

    /// Every page of a list endpoint.
    async fn list(&self, path: &str) -> Result<Vec<Value>, ProviderError> {
        let sep = if path.contains('?') { '&' } else { '?' };
        let mut out = Vec::new();
        let mut page = "1".to_string();
        for _ in 0..MAX_PAGES {
            let Some((body, next)) = self.get(&format!("{path}{sep}per_page=100&page={page}")).await? else {
                break;
            };
            match body {
                Value::Array(items) if !items.is_empty() => out.extend(items),
                _ => break,
            }
            match next {
                Some(n) => page = n,
                None => break,
            }
        }
        Ok(out)
    }

    async fn version(&self) -> Result<Vec<Value>, ProviderError> {
        let Some((mut v, _)) = self.get("/version").await? else { return Ok(vec![]) };
        // "17.5.1-ee" → version_number 17.5.1, edition ee: what advisories name.
        let full = v.get("version").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let (number, edition) = match full.split_once('-') {
            Some((n, e)) => (n.to_string(), e.to_string()),
            None => (full.clone(), "ce".to_string()),
        };
        v["version_number"] = json!(number);
        v["edition"] = json!(edition);
        v["url"] = json!(self.base_url);
        Ok(vec![v])
    }
}

#[async_trait::async_trait]
impl Provider for GitlabProvider {
    fn name(&self) -> &str {
        "gitlab"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        match resource_type {
            "version" => self.version().await,
            // Administrators only.
            "settings" => Ok(self
                .get("/application/settings")
                .await?
                .map(|(v, _)| vec![v])
                .unwrap_or_default()),
            "users" => {
                // `without_project_bots`: project and group access tokens
                // are users too, and cannot have 2FA.
                self.list("/users?without_project_bots=true").await
            }
            "projects" => {
                let mut items = self.list("/projects?simple=false&statistics=false").await?;
                // The full object carries links and owner trees: keep what
                // rules judge.
                for p in items.iter_mut() {
                    if let Value::Object(o) = p {
                        o.retain(|k, _| {
                            matches!(
                                k.as_str(),
                                "id" | "path_with_namespace" | "name" | "visibility" | "archived"
                                    | "created_at" | "last_activity_at" | "default_branch"
                                    | "forking_access_level" | "request_access_enabled"
                                    | "only_allow_merge_if_pipeline_succeeds" | "web_url"
                                    | "container_registry_access_level" | "packages_enabled"
                                    | "public_jobs" | "shared_runners_enabled"
                            )
                        });
                    }
                }
                Ok(items)
            }
            // Administrators see every user's tokens, others their own.
            "personal_access_tokens" => self.list("/personal_access_tokens?state=active").await,
            other => Err(ProviderError::UnsupportedResourceType(other.to_string())),
        }
    }
}
