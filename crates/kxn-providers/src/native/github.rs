use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Value};

const RESOURCE_TYPES: &[&str] = &[
    "organization",
    "repositories",
    "webhooks",
    "actions_org_secrets",
    "members",
    "teams",
    "dependabot_alerts",
    "actions_permissions",
];

pub struct GithubProvider {
    token: String,
    org: String,
    client: reqwest::Client,
}

impl GithubProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let token = get_config_or_env(&config, "TOKEN", Some("GITHUB"))
            .or_else(|| get_config_or_env(&config, "GITHUB_TOKEN", None))
            .ok_or_else(|| {
                ProviderError::InvalidConfig(
                    "GitHub provider requires TOKEN (config, GITHUB_TOKEN, or env)".into(),
                )
            })?;

        let org = get_config_or_env(&config, "ORG", Some("GITHUB"))
            .or_else(|| get_config_or_env(&config, "GITHUB_ORG", None))
            .ok_or_else(|| {
                ProviderError::InvalidConfig(
                    "GitHub provider requires ORG (config, GITHUB_ORG, or env)".into(),
                )
            })?;

        let client = reqwest::Client::builder()
            .user_agent("kxn")
            .build()
            .map_err(|e| ProviderError::Connection(format!("HTTP client: {}", e)))?;

        Ok(Self { token, org, client })
    }

    async fn api_get(&self, path: &str) -> Result<Value, ProviderError> {
        let url = if path.starts_with("https://") {
            path.to_string()
        } else {
            format!("https://api.github.com{}", path)
        };

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("GitHub API: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Connection(format!(
                "GitHub API {} {}: {}",
                status.as_u16(),
                path,
                body.chars().take(200).collect::<String>()
            )));
        }

        resp.json::<Value>()
            .await
            .map_err(|e| ProviderError::Connection(format!("GitHub JSON parse: {}", e)))
    }

    /// Paginated GET — fetches all pages and returns a flat array.
    async fn api_get_all(&self, path: &str) -> Result<Vec<Value>, ProviderError> {
        let mut results = Vec::new();
        let mut page = 1u32;
        let separator = if path.contains('?') { '&' } else { '?' };

        loop {
            let url = format!(
                "https://api.github.com{}{}per_page=100&page={}",
                path, separator, page
            );
            let resp = self
                .client
                .get(&url)
                .bearer_auth(&self.token)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send()
                .await
                .map_err(|e| ProviderError::Connection(format!("GitHub API: {}", e)))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(ProviderError::Connection(format!(
                    "GitHub API {} {}: {}",
                    status.as_u16(),
                    path,
                    body.chars().take(200).collect::<String>()
                )));
            }

            let items: Vec<Value> = resp
                .json()
                .await
                .map_err(|e| ProviderError::Connection(format!("GitHub JSON parse: {}", e)))?;

            if items.is_empty() {
                break;
            }
            let count = items.len();
            results.extend(items);
            if count < 100 {
                break;
            }
            page += 1;
            // Safety: max 10 pages (1000 items)
            if page > 10 {
                break;
            }
        }

        Ok(results)
    }

    async fn gather_organization(&self) -> Result<Vec<Value>, ProviderError> {
        let org = self.api_get(&format!("/orgs/{}", self.org)).await?;
        Ok(vec![org])
    }

    async fn gather_repositories(&self) -> Result<Vec<Value>, ProviderError> {
        let repos = self
            .api_get_all(&format!("/orgs/{}/repos", self.org))
            .await?;

        let mut enriched = Vec::with_capacity(repos.len());
        for repo in repos {
            let name = repo["name"].as_str().unwrap_or_default();
            let default_branch = repo["default_branch"].as_str().unwrap_or("main");

            let mut repo_data = repo.clone();

            // Fetch branch protection for the default branch
            let protection = self
                .api_get(&format!(
                    "/repos/{}/{}/branches/{}/protection",
                    self.org, name, default_branch
                ))
                .await;

            match protection {
                Ok(bp) => {
                    repo_data["default_branch_protection"] = json!({
                        "enabled": true,
                        "required_pull_request_reviews": {
                            "enabled": bp.get("required_pull_request_reviews").is_some(),
                            "required_approving_review_count": bp
                                .get("required_pull_request_reviews")
                                .and_then(|r| r.get("required_approving_review_count"))
                                .unwrap_or(&json!(0)),
                            "dismiss_stale_reviews": bp
                                .get("required_pull_request_reviews")
                                .and_then(|r| r.get("dismiss_stale_reviews"))
                                .unwrap_or(&json!(false)),
                        },
                        "required_status_checks": bp.get("required_status_checks").is_some(),
                        "enforce_admins": bp
                            .get("enforce_admins")
                            .and_then(|e| e.get("enabled"))
                            .unwrap_or(&json!(false)),
                        "allow_force_pushes": bp
                            .get("allow_force_pushes")
                            .and_then(|e| e.get("enabled"))
                            .unwrap_or(&json!(false)),
                        "allow_deletions": bp
                            .get("allow_deletions")
                            .and_then(|e| e.get("enabled"))
                            .unwrap_or(&json!(false)),
                        "required_signatures": bp
                            .get("required_signatures")
                            .and_then(|e| e.get("enabled"))
                            .unwrap_or(&json!(false)),
                    });
                }
                Err(_) => {
                    // 404 = no branch protection
                    repo_data["default_branch_protection"] = json!({
                        "enabled": false,
                        "required_pull_request_reviews": { "enabled": false },
                        "allow_force_pushes": true,
                        "allow_deletions": true,
                    });
                }
            }

            // Vulnerability alerts
            let vuln_status = self
                .client
                .get(format!(
                    "https://api.github.com/repos/{}/{}/vulnerability-alerts",
                    self.org, name
                ))
                .bearer_auth(&self.token)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send()
                .await;

            repo_data["vulnerability_alerts_enabled"] = match vuln_status {
                Ok(r) => json!(r.status().as_u16() == 204),
                Err(_) => json!(false),
            };

            enriched.push(repo_data);
        }

        Ok(enriched)
    }

    async fn gather_webhooks(&self) -> Result<Vec<Value>, ProviderError> {
        let hooks = self
            .api_get_all(&format!("/orgs/{}/hooks", self.org))
            .await?;

        let enriched: Vec<Value> = hooks
            .into_iter()
            .map(|mut hook| {
                // Flatten config.insecure_ssl to top-level for rules
                if let Some(insecure) = hook
                    .get("config")
                    .and_then(|c| c.get("insecure_ssl"))
                    .cloned()
                {
                    hook["insecure_ssl"] = insecure;
                }
                hook
            })
            .collect();

        Ok(enriched)
    }

    async fn gather_actions_org_secrets(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self
            .api_get(&format!("/orgs/{}/actions/secrets", self.org))
            .await?;

        match resp.get("secrets") {
            Some(Value::Array(arr)) => Ok(arr.clone()),
            _ => Ok(vec![]),
        }
    }

    async fn gather_members(&self) -> Result<Vec<Value>, ProviderError> {
        let members = self
            .api_get_all(&format!("/orgs/{}/members", self.org))
            .await?;

        let mut enriched = Vec::with_capacity(members.len());
        for member in members {
            let login = member["login"].as_str().unwrap_or_default();
            let mut m = member.clone();

            // Get membership details (role, state)
            if let Ok(membership) = self
                .api_get(&format!("/orgs/{}/memberships/{}", self.org, login))
                .await
            {
                m["role"] = membership
                    .get("role")
                    .cloned()
                    .unwrap_or(json!("member"));
                m["state"] = membership
                    .get("state")
                    .cloned()
                    .unwrap_or(json!("unknown"));
            }

            enriched.push(m);
        }

        Ok(enriched)
    }

    async fn gather_teams(&self) -> Result<Vec<Value>, ProviderError> {
        self.api_get_all(&format!("/orgs/{}/teams", self.org)).await
    }

    async fn gather_dependabot_alerts(&self) -> Result<Vec<Value>, ProviderError> {
        let alerts = self
            .api_get_all(&format!(
                "/orgs/{}/dependabot/alerts?state=open",
                self.org
            ))
            .await?;
        Ok(alerts)
    }

    async fn gather_actions_permissions(&self) -> Result<Vec<Value>, ProviderError> {
        let perms = self
            .api_get(&format!("/orgs/{}/actions/permissions", self.org))
            .await?;
        Ok(vec![perms])
    }
}

#[async_trait::async_trait]
impl Provider for GithubProvider {
    fn name(&self) -> &str {
        "github"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        match resource_type {
            "organization" => self.gather_organization().await,
            "repositories" => self.gather_repositories().await,
            "webhooks" => self.gather_webhooks().await,
            "actions_org_secrets" => self.gather_actions_org_secrets().await,
            "members" => self.gather_members().await,
            "teams" => self.gather_teams().await,
            "dependabot_alerts" => self.gather_dependabot_alerts().await,
            "actions_permissions" => self.gather_actions_permissions().await,
            _ => Err(ProviderError::UnsupportedResourceType(
                resource_type.to_string(),
            )),
        }
    }
}
