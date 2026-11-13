use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Value};

pub(crate) const RESOURCE_TYPES: &[&str] = &[
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
    "container_images",
];

/// Files larger than this are not image manifests worth reading.
const IMAGE_FILE_MAX_BYTES: u64 = 512 * 1024;
/// Bounds the API calls one repository can cost.
const IMAGE_FILES_PER_REPO: usize = 200;

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

    /// Paginated GET — follows the `Link: rel="next"` header (up to 10 pages)
    /// and returns a flat array. Some endpoints (Dependabot alerts) reject a
    /// `page` parameter and only paginate by cursor, which the link carries.
    async fn api_get_all(&self, path: &str) -> Result<Vec<Value>, ProviderError> {
        let mut results = Vec::new();
        let separator = if path.contains('?') { '&' } else { '?' };
        let mut url = format!("https://api.github.com{}{}per_page=100", path, separator);

        for _ in 0..10 {
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

            let next = resp
                .headers()
                .get(reqwest::header::LINK)
                .and_then(|v| v.to_str().ok())
                .and_then(next_link);
            let items: Vec<Value> = resp
                .json()
                .await
                .map_err(|e| ProviderError::Connection(format!("GitHub JSON parse: {}", e)))?;
            results.extend(items);

            match next {
                Some(n) => url = n,
                None => break,
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

    /// Container images referenced on each repository's default branch by
    /// Dockerfiles, Compose files and Helm values files.
    async fn gather_container_images(&self) -> Result<Vec<Value>, ProviderError> {
        let repos = self
            .api_get_all(&format!("/orgs/{}/repos", self.org))
            .await?;

        let mut results = Vec::new();
        for repo in &repos {
            let name = repo["name"].as_str().unwrap_or_default();
            let branch = repo["default_branch"].as_str().unwrap_or("main");
            // An empty repository has no tree (409).
            let Ok(tree) = self
                .api_get(&format!(
                    "/repos/{}/{}/git/trees/{}?recursive=1",
                    self.org, name, branch
                ))
                .await
            else {
                continue;
            };
            if tree["truncated"].as_bool() == Some(true) {
                tracing::warn!("github: {}/{} tree is truncated, some image files are not read", self.org, name);
            }

            let files = tree["tree"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|e| e["type"] == "blob")
                .filter(|e| e["size"].as_u64().unwrap_or(0) <= IMAGE_FILE_MAX_BYTES)
                .filter_map(|e| {
                    let path = e["path"].as_str()?;
                    Some((path, e["sha"].as_str()?, image_file_kind(path)?))
                })
                .take(IMAGE_FILES_PER_REPO);

            for (path, sha, kind) in files {
                let Ok(blob) = self
                    .api_get(&format!("/repos/{}/{}/git/blobs/{}", self.org, name, sha))
                    .await
                else {
                    continue;
                };
                let Some(content) = decode_blob(&blob) else {
                    continue;
                };
                let refs = if kind == "dockerfile" {
                    dockerfile_images(&content)
                } else {
                    yaml_images(&content)
                };
                for (line, image) in refs {
                    let mut r = parse_image_ref(&image);
                    r["repository"] = json!(name);
                    r["archived"] = repo["archived"].clone();
                    r["path"] = json!(path);
                    r["line"] = json!(line);
                    r["kind"] = json!(kind);
                    results.push(r);
                }
            }
        }

        Ok(results)
    }
}

/// The `rel="next"` URL of a GitHub `Link` header.
fn next_link(header: &str) -> Option<String> {
    header.split(',').find_map(|part| {
        let (url, params) = part.split_once(';')?;
        params
            .split(';')
            .any(|p| p.trim() == "rel=\"next\"")
            .then(|| url.trim().trim_start_matches('<').trim_end_matches('>').to_string())
    })
}

/// `dockerfile`, `compose` or `helm_values` for a file that can reference
/// container images.
fn image_file_kind(path: &str) -> Option<&'static str> {
    let base = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if base.ends_with(".md") || base.ends_with(".txt") {
        return None;
    }
    if base == "dockerfile"
        || base == "containerfile"
        || base.starts_with("dockerfile.")
        || base.starts_with("containerfile.")
        || base.ends_with(".dockerfile")
    {
        return Some("dockerfile");
    }
    if !(base.ends_with(".yml") || base.ends_with(".yaml")) {
        return None;
    }
    if base.starts_with("docker-compose") || base.starts_with("compose") {
        Some("compose")
    } else if base.starts_with("values") {
        Some("helm_values")
    } else {
        None
    }
}

/// Text of a `git/blobs` response (base64 with line breaks).
fn decode_blob(blob: &Value) -> Option<String> {
    use base64::Engine;
    if blob["encoding"] != "base64" {
        return None;
    }
    let encoded: String = blob["content"].as_str()?.split_whitespace().collect();
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Splits `[registry/]name[:tag][@digest]`. Docker Hub images are named
/// without `docker.io/` and `library/`, as people write them (`httpd`).
fn parse_image_ref(raw: &str) -> Value {
    let (rest, digest) = match raw.split_once('@') {
        Some((r, d)) => (r, Some(d)),
        None => (raw, None),
    };
    let name_start = rest.rfind('/').map_or(0, |i| i + 1);
    let (path, tag) = match rest[name_start..].rfind(':') {
        Some(i) => (&rest[..name_start + i], Some(&rest[name_start + i + 1..])),
        None => (rest, None),
    };
    let mut parts: Vec<&str> = path.split('/').collect();
    let registry = if parts.len() > 1
        && (parts[0].contains('.') || parts[0].contains(':') || parts[0] == "localhost")
    {
        parts.remove(0)
    } else {
        "docker.io"
    };
    let mut name = parts.join("/");
    if matches!(registry, "docker.io" | "index.docker.io" | "registry-1.docker.io") {
        if let Some(short) = name.strip_prefix("library/") {
            name = short.to_string();
        }
    }
    json!({ "image": raw, "registry": registry, "name": name, "tag": tag, "digest": digest })
}

/// `(line, image)` for every `FROM` that pulls an image. Stage names and
/// `scratch` are skipped; `ARG` defaults are substituted, and an image still
/// holding a variable after that is skipped because its value is unknown.
fn dockerfile_images(content: &str) -> Vec<(usize, String)> {
    let mut args: Vec<(String, String)> = Vec::new();
    let mut stages: Vec<String> = Vec::new();
    let mut out = Vec::new();

    for (i, line) in content.lines().enumerate() {
        let mut words = line.split_whitespace();
        let Some(instruction) = words.next() else { continue };

        if instruction.eq_ignore_ascii_case("ARG") {
            for decl in words {
                if let Some((k, v)) = decl.split_once('=') {
                    args.push((k.to_string(), v.trim_matches(|c| c == '"' || c == '\'').to_string()));
                }
            }
            continue;
        }
        if !instruction.eq_ignore_ascii_case("FROM") {
            continue;
        }

        let operands: Vec<&str> = words.filter(|w| !w.starts_with("--")).collect();
        let Some(&image) = operands.first() else { continue };
        let mut image = image.to_string();
        for (k, v) in args.iter().rev() {
            image = image.replace(&format!("${{{k}}}"), v).replace(&format!("${k}"), v);
        }
        let lower = image.to_ascii_lowercase();
        if !image.contains('$') && lower != "scratch" && !stages.contains(&lower) {
            out.push((i + 1, image));
        }
        if let [_, kw, alias] = operands[..] {
            if kw.eq_ignore_ascii_case("as") {
                stages.push(alias.to_ascii_lowercase());
            }
        }
    }
    out
}

/// `(line, image)` for every `image:` in a Compose or Helm values file, either
/// a string or the Helm `image: {registry, repository, tag}` map. Read line by
/// line: templated values (`{{ }}`, `${}`) are skipped.
fn yaml_images(content: &str) -> Vec<(usize, String)> {
    struct Block {
        indent: usize,
        line: usize,
        registry: Option<String>,
        repository: Option<String>,
        tag: Option<String>,
    }
    fn flush(block: Block, out: &mut Vec<(usize, String)>) {
        let Some(repo) = block.repository else { return };
        let mut image = match block.registry {
            Some(r) if !r.is_empty() => format!("{r}/{repo}"),
            _ => repo,
        };
        if let Some(tag) = block.tag.filter(|t| !t.is_empty()) {
            image = format!("{image}:{tag}");
        }
        out.push((block.line, image));
    }

    let mut out = Vec::new();
    let mut block: Option<Block> = None;

    for (i, raw) in content.lines().enumerate() {
        let line = raw.split(" #").next().unwrap_or(raw).trim_end();
        let body = line.trim_start();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        let indent = line.len() - body.len();
        if block.as_ref().is_some_and(|b| indent <= b.indent) {
            flush(block.take().expect("checked above"), &mut out);
        }

        let item = body.strip_prefix("- ").unwrap_or(body);
        let Some((key, value)) = item.split_once(':') else { continue };
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        if value.contains("{{") || value.contains("${") {
            continue;
        }

        match (key.trim(), block.as_mut()) {
            ("image", _) if value.is_empty() => {
                block = Some(Block { indent, line: i + 1, registry: None, repository: None, tag: None });
            }
            ("image", _) => out.push((i + 1, value.to_string())),
            ("registry", Some(b)) => b.registry = Some(value.to_string()),
            ("repository", Some(b)) => b.repository = Some(value.to_string()),
            ("tag", Some(b)) => b.tag = Some(value.to_string()),
            _ => {}
        }
    }
    if let Some(b) = block {
        flush(b, &mut out);
    }
    out
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
            "container_images" => self.gather_container_images().await,
            _ => Err(ProviderError::UnsupportedResourceType(
                resource_type.to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn follows_the_next_link_for_page_and_cursor_pagination() {
        let pages = r#"<https://api.github.com/organizations/1/repos?per_page=100&page=2>; rel="next", <https://api.github.com/organizations/1/repos?per_page=100&page=5>; rel="last""#;
        assert_eq!(next_link(pages).as_deref(), Some("https://api.github.com/organizations/1/repos?per_page=100&page=2"));

        let cursor = r#"<https://api.github.com/orgs/o/dependabot/alerts?per_page=100&before=Y3Vy>; rel="prev", <https://api.github.com/orgs/o/dependabot/alerts?per_page=100&after=Y3Vy>; rel="next""#;
        assert_eq!(next_link(cursor).as_deref(), Some("https://api.github.com/orgs/o/dependabot/alerts?per_page=100&after=Y3Vy"));

        let last_page = r#"<https://api.github.com/x?page=1>; rel="first", <https://api.github.com/x?page=4>; rel="prev""#;
        assert_eq!(next_link(last_page), None);
    }

    #[test]
    fn recognises_image_files_by_name() {
        for (path, kind) in [
            ("Dockerfile", Some("dockerfile")),
            ("docker/web/Dockerfile.prod", Some("dockerfile")),
            ("build/api.dockerfile", Some("dockerfile")),
            ("Containerfile", Some("dockerfile")),
            ("docker-compose.yml", Some("compose")),
            ("deploy/compose.prod.yaml", Some("compose")),
            ("charts/web/values.yaml", Some("helm_values")),
            ("charts/web/values-prod.yml", Some("helm_values")),
            ("charts/web/templates/deployment.yaml", None),
            ("README.md", None),
            ("Dockerfile.md", None),
        ] {
            assert_eq!(image_file_kind(path), kind, "{path}");
        }
    }

    #[test]
    fn splits_image_references() {
        let r = parse_image_ref("httpd:2.4.62-alpine");
        assert_eq!((r["registry"].as_str(), r["name"].as_str(), r["tag"].as_str()), (Some("docker.io"), Some("httpd"), Some("2.4.62-alpine")));

        let r = parse_image_ref("docker.io/library/httpd:2.4.70");
        assert_eq!((r["name"].as_str(), r["tag"].as_str()), (Some("httpd"), Some("2.4.70")));

        let r = parse_image_ref("registry.example.com:5000/team/web:1.2@sha256:abc");
        assert_eq!(r["registry"], "registry.example.com:5000");
        assert_eq!(r["name"], "team/web");
        assert_eq!(r["tag"], "1.2");
        assert_eq!(r["digest"], "sha256:abc");

        let r = parse_image_ref("bitnami/apache");
        assert_eq!((r["name"].as_str(), r["tag"].is_null()), (Some("bitnami/apache"), true));

        let r = parse_image_ref("localhost/library/httpd:2.4.62");
        assert_eq!((r["registry"].as_str(), r["name"].as_str()), (Some("localhost"), Some("library/httpd")));
    }

    #[test]
    fn reads_from_lines_of_a_dockerfile() {
        let dockerfile = "\
ARG HTTPD_VERSION=2.4.62
FROM --platform=linux/amd64 rust:1.95 AS build
RUN cargo build
FROM build AS test
FROM httpd:${HTTPD_VERSION}-alpine
from scratch
FROM $UNKNOWN_BASE
";
        assert_eq!(
            dockerfile_images(dockerfile),
            vec![(2, "rust:1.95".to_string()), (5, "httpd:2.4.62-alpine".to_string())]
        );
    }

    #[test]
    fn reads_compose_and_helm_image_values() {
        let compose = "\
services:
  web:
    image: \"httpd:2.4.62\"  # pinned
  db:
    image: postgres:18
  app:
    image: ${APP_IMAGE}
";
        assert_eq!(
            yaml_images(compose),
            vec![(3, "httpd:2.4.62".to_string()), (5, "postgres:18".to_string())]
        );

        let values = "\
image:
  registry: docker.io
  repository: bitnami/apache
  tag: 2.4.62-debian-12-r3
replicaCount: 2
sidecars:
  - name: exporter
    image: quay.io/prometheus/node-exporter:v1.8.2
proxy:
  image:
    repository: httpd
    tag: \"{{ .Values.tag }}\"
";
        assert_eq!(
            yaml_images(values),
            vec![
                (1, "docker.io/bitnami/apache:2.4.62-debian-12-r3".to_string()),
                (8, "quay.io/prometheus/node-exporter:v1.8.2".to_string()),
                (10, "httpd".to_string()),
            ]
        );
    }

    #[test]
    fn decodes_blob_content() {
        let blob = json!({"encoding": "base64", "content": "RlJPTSBo\ndHRwZDoy\nLjQuNjIK\n"});
        assert_eq!(decode_blob(&blob).as_deref(), Some("FROM httpd:2.4.62\n"));
        assert_eq!(decode_blob(&json!({"encoding": "utf-8", "content": "x"})), None);
    }
}
