use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Value};

const RESOURCE_TYPES: &[&str] = &[
    // Organization
    "organization",
    "members",
    "outside_collaborators",
    "teams",
    "webhooks",
    "audit_log",
    "security_managers",
    "custom_roles",
    // Repositories
    "repositories",
    "rulesets",
    "environments",
    "deploy_keys",
    "autolinks",
    // Security & alerts
    "dependabot_alerts",
    "secret_scanning_alerts",
    "code_scanning_alerts",
    // Actions
    "actions_permissions",
    "actions_org_secrets",
    "actions_org_variables",
    "actions_runners",
    "actions_workflows",
    // Packages & Copilot
    "packages",
    "copilot_usage",
    // Code & content
    "codeowners",
    "community_metrics",
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

    /// GET that returns 204/404 as a boolean (e.g. vulnerability-alerts check).
    async fn api_check(&self, path: &str) -> bool {
        let url = format!("https://api.github.com{}", path);
        match self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
        {
            Ok(r) => r.status().as_u16() == 204,
            Err(_) => false,
        }
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
            if page > 10 {
                break;
            }
        }

        Ok(results)
    }

    /// GET returning a wrapped list (e.g. { "secrets": [...] }).
    async fn api_get_wrapped(
        &self,
        path: &str,
        key: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(path).await?;
        match resp.get(key) {
            Some(Value::Array(arr)) => Ok(arr.clone()),
            _ => Ok(vec![]),
        }
    }

    // ── Organization ──────────────────────────────────────────────────

    async fn gather_organization(&self) -> Result<Vec<Value>, ProviderError> {
        let org = self.api_get(&format!("/orgs/{}", self.org)).await?;
        Ok(vec![org])
    }

    async fn gather_members(&self) -> Result<Vec<Value>, ProviderError> {
        let members = self
            .api_get_all(&format!("/orgs/{}/members", self.org))
            .await?;

        let mut enriched = Vec::with_capacity(members.len());
        for member in members {
            let login = member["login"].as_str().unwrap_or_default();
            let mut m = member.clone();

            if let Ok(membership) = self
                .api_get(&format!("/orgs/{}/memberships/{}", self.org, login))
                .await
            {
                m["role"] = membership.get("role").cloned().unwrap_or(json!("member"));
                m["state"] = membership
                    .get("state")
                    .cloned()
                    .unwrap_or(json!("unknown"));
                m["two_factor_enabled"] = membership
                    .get("two_factor_enabled")
                    .cloned()
                    .unwrap_or(json!(null));
            }

            enriched.push(m);
        }

        Ok(enriched)
    }

    async fn gather_outside_collaborators(&self) -> Result<Vec<Value>, ProviderError> {
        self.api_get_all(&format!("/orgs/{}/outside_collaborators", self.org))
            .await
    }

    async fn gather_teams(&self) -> Result<Vec<Value>, ProviderError> {
        let teams = self
            .api_get_all(&format!("/orgs/{}/teams", self.org))
            .await?;

        let mut enriched = Vec::with_capacity(teams.len());
        for team in teams {
            let slug = team["slug"].as_str().unwrap_or_default();
            let mut t = team.clone();

            // Get team members count
            if let Ok(members) = self
                .api_get_all(&format!("/orgs/{}/teams/{}/members", self.org, slug))
                .await
            {
                t["members_count"] = json!(members.len());
            }

            // Get team repos
            if let Ok(repos) = self
                .api_get_all(&format!("/orgs/{}/teams/{}/repos", self.org, slug))
                .await
            {
                t["repos_count"] = json!(repos.len());
                let repo_names: Vec<&str> = repos
                    .iter()
                    .filter_map(|r| r["name"].as_str())
                    .collect();
                t["repo_names"] = json!(repo_names);
            }

            enriched.push(t);
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

    async fn gather_audit_log(&self) -> Result<Vec<Value>, ProviderError> {
        // Last 100 events (most recent)
        self.api_get_all(&format!(
            "/orgs/{}/audit-log?include=all",
            self.org
        ))
        .await
    }

    async fn gather_security_managers(&self) -> Result<Vec<Value>, ProviderError> {
        self.api_get_all(&format!(
            "/orgs/{}/security-managers",
            self.org
        ))
        .await
    }

    async fn gather_custom_roles(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self
            .api_get(&format!("/orgs/{}/custom-repository-roles", self.org))
            .await?;
        match resp.get("custom_roles") {
            Some(Value::Array(arr)) => Ok(arr.clone()),
            _ => Ok(vec![]),
        }
    }

    // ── Repositories ──────────────────────────────────────────────────

    async fn gather_repositories(&self) -> Result<Vec<Value>, ProviderError> {
        let repos = self
            .api_get_all(&format!("/orgs/{}/repos", self.org))
            .await?;

        let mut enriched = Vec::with_capacity(repos.len());
        for repo in repos {
            let name = repo["name"].as_str().unwrap_or_default();
            let default_branch = repo["default_branch"].as_str().unwrap_or("main");

            let mut r = repo.clone();

            // Branch protection
            let protection = self
                .api_get(&format!(
                    "/repos/{}/{}/branches/{}/protection",
                    self.org, name, default_branch
                ))
                .await;

            match protection {
                Ok(bp) => {
                    r["default_branch_protection"] = json!({
                        "enabled": true,
                        "required_pull_request_reviews": {
                            "enabled": bp.get("required_pull_request_reviews").is_some(),
                            "required_approving_review_count": bp
                                .get("required_pull_request_reviews")
                                .and_then(|pr| pr.get("required_approving_review_count"))
                                .unwrap_or(&json!(0)),
                            "dismiss_stale_reviews": bp
                                .get("required_pull_request_reviews")
                                .and_then(|pr| pr.get("dismiss_stale_reviews"))
                                .unwrap_or(&json!(false)),
                            "require_code_owner_reviews": bp
                                .get("required_pull_request_reviews")
                                .and_then(|pr| pr.get("require_code_owner_reviews"))
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
                        "required_linear_history": bp
                            .get("required_linear_history")
                            .and_then(|e| e.get("enabled"))
                            .unwrap_or(&json!(false)),
                        "required_conversation_resolution": bp
                            .get("required_conversation_resolution")
                            .and_then(|e| e.get("enabled"))
                            .unwrap_or(&json!(false)),
                    });
                }
                Err(_) => {
                    r["default_branch_protection"] = json!({
                        "enabled": false,
                        "required_pull_request_reviews": { "enabled": false },
                        "allow_force_pushes": true,
                        "allow_deletions": true,
                    });
                }
            }

            // Vulnerability alerts (204 = enabled)
            r["vulnerability_alerts_enabled"] = json!(self
                .api_check(&format!(
                    "/repos/{}/{}/vulnerability-alerts",
                    self.org, name
                ))
                .await);

            // Automated security fixes (204 = enabled)
            r["automated_security_fixes_enabled"] = json!(self
                .api_check(&format!(
                    "/repos/{}/{}/automated-security-fixes",
                    self.org, name
                ))
                .await);

            // Secret scanning push protection
            if let Ok(settings) = self
                .api_get(&format!(
                    "/repos/{}/{}/code-security-and-analysis",
                    self.org, name
                ))
                .await
            {
                r["secret_scanning"] = settings
                    .get("secret_scanning")
                    .cloned()
                    .unwrap_or(json!({"status": "disabled"}));
                r["secret_scanning_push_protection"] = settings
                    .get("secret_scanning_push_protection")
                    .cloned()
                    .unwrap_or(json!({"status": "disabled"}));
                r["dependabot_security_updates"] = settings
                    .get("dependabot_security_updates")
                    .cloned()
                    .unwrap_or(json!({"status": "disabled"}));
            }

            enriched.push(r);
        }

        Ok(enriched)
    }

    async fn gather_rulesets(&self) -> Result<Vec<Value>, ProviderError> {
        self.api_get_all(&format!("/orgs/{}/rulesets", self.org))
            .await
    }

    async fn gather_environments(&self) -> Result<Vec<Value>, ProviderError> {
        let repos = self
            .api_get_all(&format!("/orgs/{}/repos", self.org))
            .await?;

        let mut all_envs = Vec::new();
        for repo in &repos {
            let name = repo["name"].as_str().unwrap_or_default();
            if let Ok(resp) = self
                .api_get(&format!(
                    "/repos/{}/{}/environments",
                    self.org, name
                ))
                .await
            {
                if let Some(Value::Array(envs)) = resp.get("environments") {
                    for env in envs {
                        let mut e = env.clone();
                        e["repository"] = json!(name);
                        all_envs.push(e);
                    }
                }
            }
        }

        Ok(all_envs)
    }

    async fn gather_deploy_keys(&self) -> Result<Vec<Value>, ProviderError> {
        let repos = self
            .api_get_all(&format!("/orgs/{}/repos", self.org))
            .await?;

        let mut all_keys = Vec::new();
        for repo in &repos {
            let name = repo["name"].as_str().unwrap_or_default();
            if let Ok(keys) = self
                .api_get_all(&format!("/repos/{}/{}/keys", self.org, name))
                .await
            {
                for key in keys {
                    let mut k = key.clone();
                    k["repository"] = json!(name);
                    all_keys.push(k);
                }
            }
        }

        Ok(all_keys)
    }

    async fn gather_autolinks(&self) -> Result<Vec<Value>, ProviderError> {
        let repos = self
            .api_get_all(&format!("/orgs/{}/repos", self.org))
            .await?;

        let mut all_autolinks = Vec::new();
        for repo in &repos {
            let name = repo["name"].as_str().unwrap_or_default();
            if let Ok(links) = self
                .api_get_all(&format!(
                    "/repos/{}/{}/autolinks",
                    self.org, name
                ))
                .await
            {
                for link in links {
                    let mut l = link.clone();
                    l["repository"] = json!(name);
                    all_autolinks.push(l);
                }
            }
        }

        Ok(all_autolinks)
    }

    // ── Security & alerts ─────────────────────────────────────────────

    async fn gather_dependabot_alerts(&self) -> Result<Vec<Value>, ProviderError> {
        self.api_get_all(&format!(
            "/orgs/{}/dependabot/alerts?state=open",
            self.org
        ))
        .await
    }

    async fn gather_secret_scanning_alerts(&self) -> Result<Vec<Value>, ProviderError> {
        self.api_get_all(&format!(
            "/orgs/{}/secret-scanning/alerts?state=open",
            self.org
        ))
        .await
    }

    async fn gather_code_scanning_alerts(&self) -> Result<Vec<Value>, ProviderError> {
        self.api_get_all(&format!(
            "/orgs/{}/code-scanning/alerts?state=open",
            self.org
        ))
        .await
    }

    // ── Actions ───────────────────────────────────────────────────────

    async fn gather_actions_permissions(&self) -> Result<Vec<Value>, ProviderError> {
        let perms = self
            .api_get(&format!("/orgs/{}/actions/permissions", self.org))
            .await?;
        Ok(vec![perms])
    }

    async fn gather_actions_org_secrets(&self) -> Result<Vec<Value>, ProviderError> {
        self.api_get_wrapped(
            &format!("/orgs/{}/actions/secrets", self.org),
            "secrets",
        )
        .await
    }

    async fn gather_actions_org_variables(&self) -> Result<Vec<Value>, ProviderError> {
        self.api_get_wrapped(
            &format!("/orgs/{}/actions/variables", self.org),
            "variables",
        )
        .await
    }

    async fn gather_actions_runners(&self) -> Result<Vec<Value>, ProviderError> {
        self.api_get_wrapped(
            &format!("/orgs/{}/actions/runners", self.org),
            "runners",
        )
        .await
    }

    async fn gather_actions_workflows(&self) -> Result<Vec<Value>, ProviderError> {
        let repos = self
            .api_get_all(&format!("/orgs/{}/repos", self.org))
            .await?;

        let mut all_workflows = Vec::new();
        for repo in &repos {
            let name = repo["name"].as_str().unwrap_or_default();
            if let Ok(resp) = self
                .api_get(&format!(
                    "/repos/{}/{}/actions/workflows",
                    self.org, name
                ))
                .await
            {
                if let Some(Value::Array(wfs)) = resp.get("workflows") {
                    for wf in wfs {
                        let mut w = wf.clone();
                        w["repository"] = json!(name);
                        all_workflows.push(w);
                    }
                }
            }
        }

        Ok(all_workflows)
    }

    // ── Packages & Copilot ────────────────────────────────────────────

    async fn gather_packages(&self) -> Result<Vec<Value>, ProviderError> {
        let mut all_packages = Vec::new();
        for pkg_type in &[
            "npm", "maven", "rubygems", "docker", "nuget", "container",
        ] {
            if let Ok(pkgs) = self
                .api_get_all(&format!(
                    "/orgs/{}/packages?package_type={}",
                    self.org, pkg_type
                ))
                .await
            {
                all_packages.extend(pkgs);
            }
        }
        Ok(all_packages)
    }

    async fn gather_copilot_usage(&self) -> Result<Vec<Value>, ProviderError> {
        let billing = self
            .api_get(&format!("/orgs/{}/copilot/billing", self.org))
            .await?;
        Ok(vec![billing])
    }

    // ── Code & content ────────────────────────────────────────────────

    async fn gather_codeowners(&self) -> Result<Vec<Value>, ProviderError> {
        let repos = self
            .api_get_all(&format!("/orgs/{}/repos", self.org))
            .await?;

        let mut results = Vec::new();
        for repo in &repos {
            let name = repo["name"].as_str().unwrap_or_default();

            // Check common CODEOWNERS locations
            let mut found = false;
            for path in &["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"] {
                if let Ok(content) = self
                    .api_get(&format!(
                        "/repos/{}/{}/contents/{}",
                        self.org, name, path
                    ))
                    .await
                {
                    results.push(json!({
                        "repository": name,
                        "path": path,
                        "exists": true,
                        "size": content.get("size").unwrap_or(&json!(0)),
                    }));
                    found = true;
                    break;
                }
            }
            if !found {
                results.push(json!({
                    "repository": name,
                    "exists": false,
                }));
            }
        }

        Ok(results)
    }

    async fn gather_community_metrics(&self) -> Result<Vec<Value>, ProviderError> {
        let repos = self
            .api_get_all(&format!("/orgs/{}/repos", self.org))
            .await?;

        let mut results = Vec::new();
        for repo in &repos {
            let name = repo["name"].as_str().unwrap_or_default();
            if repo["private"].as_bool() == Some(true) {
                continue;
            }
            if let Ok(mut metrics) = self
                .api_get(&format!(
                    "/repos/{}/{}/community/profile",
                    self.org, name
                ))
                .await
            {
                metrics["repository"] = json!(name);
                results.push(metrics);
            }
        }

        Ok(results)
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
            "members" => self.gather_members().await,
            "outside_collaborators" => self.gather_outside_collaborators().await,
            "teams" => self.gather_teams().await,
            "webhooks" => self.gather_webhooks().await,
            "audit_log" => self.gather_audit_log().await,
            "security_managers" => self.gather_security_managers().await,
            "custom_roles" => self.gather_custom_roles().await,
            "repositories" => self.gather_repositories().await,
            "rulesets" => self.gather_rulesets().await,
            "environments" => self.gather_environments().await,
            "deploy_keys" => self.gather_deploy_keys().await,
            "autolinks" => self.gather_autolinks().await,
            "dependabot_alerts" => self.gather_dependabot_alerts().await,
            "secret_scanning_alerts" => self.gather_secret_scanning_alerts().await,
            "code_scanning_alerts" => self.gather_code_scanning_alerts().await,
            "actions_permissions" => self.gather_actions_permissions().await,
            "actions_org_secrets" => self.gather_actions_org_secrets().await,
            "actions_org_variables" => self.gather_actions_org_variables().await,
            "actions_runners" => self.gather_actions_runners().await,
            "actions_workflows" => self.gather_actions_workflows().await,
            "packages" => self.gather_packages().await,
            "copilot_usage" => self.gather_copilot_usage().await,
            "codeowners" => self.gather_codeowners().await,
            "community_metrics" => self.gather_community_metrics().await,
            _ => Err(ProviderError::UnsupportedResourceType(
                resource_type.to_string(),
            )),
        }
    }
}
