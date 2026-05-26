use crate::config::{get_config_or_env, require_config};
use crate::error::ProviderError;
use crate::secrets;
use crate::traits::Provider;
use serde_json::{json, Value};
use tokio::sync::OnceCell;
use tracing::{debug, warn};

const RESOURCE_TYPES: &[&str] = &[
    "pipeline_runs",
    "pipeline_jobs",
    "pipeline_logs",
];

/// Forgejo (and Gitea) Actions pipelines collector.
///
/// Exposes three resource types so the watch+save pipeline can persist
/// CI history in Postgres and render it in Grafana:
///
///   - `pipeline_runs`: one row per workflow run with status / conclusion
///     / branch / commit / actor / timing.
///   - `pipeline_jobs`: one row per job inside a completed run, with
///     the runner name and per-step timing.
///   - `pipeline_logs`: one row per completed job carrying the raw log
///     text the runner uploaded.
///
/// The API surface is the GitHub Actions REST API that Forgejo and
/// Gitea implement compatibly:
///   - `GET /api/v1/repos/{owner}/{repo}/actions/runs`
///   - `GET /api/v1/repos/{owner}/{repo}/actions/runs/{id}/jobs`
///   - `GET /api/v1/repos/{owner}/{repo}/actions/jobs/{id}/logs`
pub struct ForgejoProvider {
    base_url: String,
    /// Raw token reference as configured. May be either a literal token, an
    /// env var name, or a `secret:gcp:project/name` style URI handled by
    /// `secrets::resolve_ref`. Resolution is deferred to first use so the
    /// synchronous `new()` factory does not need to block on the network.
    token_ref: String,
    resolved_token: OnceCell<String>,
    repos: Vec<(String, String)>,
    max_runs_per_repo: usize,
    client: reqwest::Client,
}

impl ForgejoProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let base_url = require_config(&config, "URL", Some("FORGEJO"))?
            .trim_end_matches('/')
            .to_string();

        let token_ref = get_config_or_env(&config, "TOKEN", Some("FORGEJO"))
            .or_else(|| get_config_or_env(&config, "FORGEJO_TOKEN", None))
            .ok_or_else(|| {
                ProviderError::InvalidConfig(
                    "Forgejo provider requires TOKEN (config, FORGEJO_TOKEN env, or \
                     a `secret:gcp:project/name` reference)".into(),
                )
            })?;

        let repos_raw = require_config(&config, "REPOS", Some("FORGEJO"))?;
        let repos: Vec<(String, String)> = repos_raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| {
                s.split_once('/').map(|(o, r)| (o.to_string(), r.to_string()))
            })
            .collect();
        if repos.is_empty() {
            return Err(ProviderError::InvalidConfig(
                "Forgejo REPOS must list at least one `owner/repo` entry, comma-separated".into(),
            ));
        }

        let max_runs_per_repo: usize = get_config_or_env(&config, "MAX_RUNS_PER_REPO", Some("FORGEJO"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        let client = reqwest::Client::builder()
            .user_agent("kxn")
            .build()
            .map_err(|e| ProviderError::Connection(format!("HTTP client: {}", e)))?;

        Ok(Self {
            base_url,
            token_ref,
            resolved_token: OnceCell::new(),
            repos,
            max_runs_per_repo,
            client,
        })
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}/api/v1{}", self.base_url, path)
    }

    /// Resolve the configured token reference exactly once, then reuse the
    /// materialised string for every subsequent API call. Handles literal
    /// tokens, env var names, and `secret:<backend>:...` URIs uniformly.
    async fn token(&self) -> Result<&str, ProviderError> {
        self.resolved_token
            .get_or_try_init(|| async {
                if self.token_ref.starts_with("secret:")
                    || (!self.token_ref.contains(' ') && self.token_ref.chars().all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()))
                {
                    secrets::resolve_ref(&self.token_ref).await.map_err(|e| {
                        ProviderError::InvalidConfig(format!(
                            "Forgejo token resolve `{}`: {}",
                            self.token_ref, e
                        ))
                    })
                } else {
                    Ok(self.token_ref.clone())
                }
            })
            .await
            .map(|s| s.as_str())
    }

    async fn api_get_json(&self, path: &str) -> Result<Value, ProviderError> {
        let url = self.api_url(path);
        let token = self.token().await?;
        debug!(url = %url, "Forgejo GET");
        let resp = self
            .client
            .get(&url)
            .bearer_auth(token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("Forgejo API: {}", e)))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Connection(format!(
                "Forgejo API {} {}: {}",
                status.as_u16(),
                path,
                body.chars().take(200).collect::<String>()
            )));
        }

        resp.json::<Value>()
            .await
            .map_err(|e| ProviderError::Api(format!("Forgejo JSON decode: {}", e)))
    }

    async fn api_get_text(&self, path: &str) -> Result<String, ProviderError> {
        let url = self.api_url(path);
        let token = self.token().await?;
        debug!(url = %url, "Forgejo GET (text)");
        let resp = self
            .client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("Forgejo API: {}", e)))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Connection(format!(
                "Forgejo API {} {}: {}",
                status.as_u16(),
                path,
                body.chars().take(200).collect::<String>()
            )));
        }

        resp.text()
            .await
            .map_err(|e| ProviderError::Api(format!("Forgejo body read: {}", e)))
    }

    /// Fetch all pipeline runs (with paging) across configured repos.
    async fn gather_pipeline_runs(&self) -> Result<Vec<Value>, ProviderError> {
        let mut out = Vec::new();
        for (owner, repo) in &self.repos {
            let mut fetched = 0usize;
            let mut page = 1u32;
            let page_size = 50u32;
            while fetched < self.max_runs_per_repo {
                let path = format!(
                    "/repos/{}/{}/actions/runs?page={}&limit={}",
                    owner, repo, page, page_size
                );
                let resp = match self.api_get_json(&path).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(repo = %format!("{}/{}", owner, repo), error = %e, "Forgejo runs fetch failed");
                        break;
                    }
                };

                // Forgejo wraps under `workflow_runs` (GitHub-compatible).
                let runs_arr = resp
                    .get("workflow_runs")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                if runs_arr.is_empty() {
                    break;
                }

                for run in runs_arr.iter() {
                    out.push(enrich_run(run, owner, repo));
                    fetched += 1;
                    if fetched >= self.max_runs_per_repo {
                        break;
                    }
                }
                page += 1;
            }
        }
        Ok(out)
    }

    /// Fetch jobs for every recent run across configured repos.
    async fn gather_pipeline_jobs(&self) -> Result<Vec<Value>, ProviderError> {
        let mut out = Vec::new();
        for (owner, repo) in &self.repos {
            // Reuse the runs listing to know which run_ids to dive into.
            let runs_path = format!(
                "/repos/{}/{}/actions/runs?page=1&limit={}",
                owner, repo, self.max_runs_per_repo.min(100)
            );
            let runs_resp = match self.api_get_json(&runs_path).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(repo = %format!("{}/{}", owner, repo), error = %e, "Forgejo runs fetch failed (jobs)");
                    continue;
                }
            };
            let runs_arr = runs_resp
                .get("workflow_runs")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            for run in runs_arr.iter() {
                let run_id = run.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                if run_id == 0 {
                    continue;
                }
                let path = format!("/repos/{}/{}/actions/runs/{}/jobs", owner, repo, run_id);
                let resp = match self.api_get_json(&path).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(run_id, error = %e, "Forgejo jobs fetch failed");
                        continue;
                    }
                };
                let jobs_arr = resp
                    .get("jobs")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                for job in jobs_arr.iter() {
                    out.push(enrich_job(job, owner, repo, run_id));
                }
            }
        }
        Ok(out)
    }

    /// Fetch the raw log blob for every completed job across configured
    /// repos. Skips jobs that are still running or queued — their logs
    /// will materialise on the next watch cycle.
    async fn gather_pipeline_logs(&self) -> Result<Vec<Value>, ProviderError> {
        let mut out = Vec::new();
        for (owner, repo) in &self.repos {
            let runs_path = format!(
                "/repos/{}/{}/actions/runs?page=1&limit={}",
                owner, repo, self.max_runs_per_repo.min(100)
            );
            let runs_resp = match self.api_get_json(&runs_path).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(repo = %format!("{}/{}", owner, repo), error = %e, "Forgejo runs fetch failed (logs)");
                    continue;
                }
            };
            let runs_arr = runs_resp
                .get("workflow_runs")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            for run in runs_arr.iter() {
                let run_id = run.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                if run_id == 0 {
                    continue;
                }
                let jobs_path = format!("/repos/{}/{}/actions/runs/{}/jobs", owner, repo, run_id);
                let jobs_resp = match self.api_get_json(&jobs_path).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let jobs_arr = jobs_resp
                    .get("jobs")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                for job in jobs_arr.iter() {
                    let status = job.get("status").and_then(|v| v.as_str()).unwrap_or("");
                    if status != "completed" {
                        continue;
                    }
                    let job_id = job.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                    if job_id == 0 {
                        continue;
                    }
                    let log_path = format!("/repos/{}/{}/actions/jobs/{}/logs", owner, repo, job_id);
                    let log_text = match self.api_get_text(&log_path).await {
                        Ok(t) => t,
                        Err(e) => {
                            warn!(job_id, error = %e, "Forgejo logs fetch failed");
                            continue;
                        }
                    };
                    let size = log_text.len() as i64;
                    out.push(json!({
                        "id": job_id,
                        "job_id": job_id,
                        "run_id": run_id,
                        "repo": format!("{}/{}", owner, repo),
                        "log_text": log_text,
                        "log_size_bytes": size,
                    }));
                }
            }
        }
        Ok(out)
    }
}

fn str_or_null(v: &Value, key: &str) -> Value {
    v.get(key).cloned().unwrap_or(Value::Null)
}

fn enrich_run(run: &Value, owner: &str, repo: &str) -> Value {
    let id = run.get("id").cloned().unwrap_or(Value::Null);
    json!({
        "id": id,
        "run_id": id,
        "repo": format!("{}/{}", owner, repo),
        "owner": owner,
        "repo_name": repo,
        "workflow_name": str_or_null(run, "name"),
        "workflow_id": str_or_null(run, "workflow_id"),
        "run_number": str_or_null(run, "run_number"),
        "event": str_or_null(run, "event"),
        "status": str_or_null(run, "status"),
        "conclusion": str_or_null(run, "conclusion"),
        "head_branch": str_or_null(run, "head_branch"),
        "head_sha": str_or_null(run, "head_sha"),
        "actor": run.get("actor").and_then(|a| a.get("login")).cloned().unwrap_or(Value::Null),
        "triggering_actor": run.get("triggering_actor").and_then(|a| a.get("login")).cloned().unwrap_or(Value::Null),
        "created_at": str_or_null(run, "created_at"),
        "started_at": str_or_null(run, "run_started_at"),
        "updated_at": str_or_null(run, "updated_at"),
        "html_url": str_or_null(run, "html_url"),
    })
}

fn enrich_job(job: &Value, owner: &str, repo: &str, run_id: i64) -> Value {
    let id = job.get("id").cloned().unwrap_or(Value::Null);
    let steps = job.get("steps").cloned().unwrap_or(Value::Null);
    json!({
        "id": id,
        "job_id": id,
        "run_id": run_id,
        "repo": format!("{}/{}", owner, repo),
        "name": str_or_null(job, "name"),
        "status": str_or_null(job, "status"),
        "conclusion": str_or_null(job, "conclusion"),
        "started_at": str_or_null(job, "started_at"),
        "completed_at": str_or_null(job, "completed_at"),
        "runner_name": str_or_null(job, "runner_name"),
        "runner_group_name": str_or_null(job, "runner_group_name"),
        "labels": job.get("labels").cloned().unwrap_or(Value::Null),
        "html_url": str_or_null(job, "html_url"),
        "steps": steps,
    })
}

#[async_trait::async_trait]
impl Provider for ForgejoProvider {
    fn name(&self) -> &str {
        "forgejo"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        match resource_type {
            "pipeline_runs" => self.gather_pipeline_runs().await,
            "pipeline_jobs" => self.gather_pipeline_jobs().await,
            "pipeline_logs" => self.gather_pipeline_logs().await,
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
    fn enrich_run_minimal() {
        let run = json!({
            "id": 42,
            "name": "build",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": "abc123",
            "actor": {"login": "alice"},
            "run_started_at": "2026-05-26T15:00:00Z",
        });
        let out = enrich_run(&run, "rtk", "kxn");
        assert_eq!(out["id"], 42);
        assert_eq!(out["repo"], "rtk/kxn");
        assert_eq!(out["actor"], "alice");
        assert_eq!(out["status"], "completed");
        assert_eq!(out["started_at"], "2026-05-26T15:00:00Z");
    }

    #[test]
    fn enrich_job_minimal() {
        let job = json!({
            "id": 7,
            "name": "test-rust",
            "status": "completed",
            "conclusion": "failure",
            "runner_name": "rtk-runner-1",
            "steps": [{"name": "checkout", "status": "completed"}],
        });
        let out = enrich_job(&job, "rtk", "kxn", 42);
        assert_eq!(out["job_id"], 7);
        assert_eq!(out["run_id"], 42);
        assert_eq!(out["repo"], "rtk/kxn");
        assert_eq!(out["conclusion"], "failure");
        assert_eq!(out["runner_name"], "rtk-runner-1");
        assert_eq!(out["steps"].as_array().unwrap().len(), 1);
    }
}
