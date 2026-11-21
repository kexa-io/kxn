use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use anyhow::Context;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

/// Objects this provider can serve, fully normalized.
///
/// An object is listed here only once *every* field the rules read for it is
/// produced. A half-normalized object is worse than an absent one: the engine
/// reads a missing property as an empty string, so the rule fails and the
/// resource is reported as violating something it does not.
///
/// Cloud Asset Inventory types (`compute.googleapis.com/Instance`, …) are
/// served on top of these — see `gcp_assets` — so [`RESOURCE_TYPES`] is both.
pub(crate) const NATIVE_TYPES: &[&str] = &[
    "api_keys",
    "assets",
    "bigquery_dataset",
    "cloud_functions",
    "cloud_run_services",
    "cloud_sql_instances",
    "compute_disk",
    "compute_firewall",
    "compute_instance",
    "compute_ssl_policy",
    "compute_subnetwork",
    "container_cluster",
    "dns_zones",
    "iam_service_accounts",
    "kms_crypto_key",
    "logging_metric_alerts",
    "logging_project_sink",
    "metrics",
    "networks",
    "org_policies",
    "project",
    "project_iam_member",
    "pubsub_subscriptions",
    "pubsub_topics",
    "secret_versions",
    "secrets",
    "service_account_keys",
    "storage_bucket",
];

/// Every object the provider serves: the native ones, then every Cloud Asset
/// type.
pub(crate) static RESOURCE_TYPES: std::sync::LazyLock<Vec<&'static str>> =
    std::sync::LazyLock::new(|| {
        NATIVE_TYPES.iter().chain(super::gcp_assets::ASSET_TYPES).copied().collect()
    });

fn is_asset_type(resource_type: &str) -> bool {
    super::gcp_assets::ASSET_TYPES.binary_search(&resource_type).is_ok()
}

/// Default key age threshold (days) after which rotation is recommended.
const DEFAULT_KEY_MAX_AGE_DAYS: i64 = 90;

const COMPUTE_V1: &str = "https://compute.googleapis.com/compute/v1";

pub struct GcpProvider {
    project: String,
    key_max_age_days: i64,
    client: reqwest::Client,
    /// The project's Cloud Asset inventory, read once per provider and shared
    /// by every asset type (see `gcp_assets`).
    inventory: tokio::sync::OnceCell<std::collections::HashMap<String, Vec<Value>>>,
}

impl GcpProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let project = get_config_or_env(&config, "PROJECT", Some("GCP"))
            .ok_or_else(|| ProviderError::InvalidConfig(
                "GCP project not set — use gcp://project-id or GCP_PROJECT env".into()
            ))?;
        let key_max_age_days = get_config_or_env(&config, "KEY_MAX_AGE_DAYS", Some("GCP"))
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(DEFAULT_KEY_MAX_AGE_DAYS);
        let client = reqwest::Client::builder()
            .user_agent("kxn")
            .build()
            .map_err(|e| ProviderError::Connection(format!("HTTP client: {}", e)))?;
        Ok(Self { project, key_max_age_days, client, inventory: tokio::sync::OnceCell::new() })
    }

    async fn get_token(&self) -> Result<String, ProviderError> {
        let provider = gcp_auth::provider()
            .await
            .map_err(|e| ProviderError::Connection(format!("GCP auth failed: {}", e)))?;
        let token = provider
            .token(&["https://www.googleapis.com/auth/cloud-platform"])
            .await
            .map_err(|e| ProviderError::Connection(format!("GCP token failed: {}", e)))?;
        Ok(token.as_str().to_string())
    }

    async fn iam_get(&self, token: &str, path: &str) -> Result<Value, ProviderError> {
        let url = format!("https://iam.googleapis.com/v1{}", path);
        let resp = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send().await
            .map_err(|e| ProviderError::Connection(format!("IAM GET failed: {}", e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Connection(format!("IAM GET {} failed ({}): {}", path, status, text)));
        }
        resp.json::<Value>().await
            .map_err(|e| ProviderError::Connection(format!("IAM response parse failed: {}", e)))
    }

    async fn list_service_accounts(&self, token: &str) -> Result<Vec<Value>, ProviderError> {
        let mut accounts: Vec<Value> = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut path = format!("/projects/{}/serviceAccounts?pageSize=100", self.project);
            if let Some(pt) = &page_token {
                path.push_str(&format!("&pageToken={}", pt));
            }
            let page = self.iam_get(token, &path).await?;
            if let Some(arr) = page["accounts"].as_array() {
                accounts.extend(arr.iter().cloned());
            }
            match page["nextPageToken"].as_str() {
                Some(pt) if !pt.is_empty() => page_token = Some(pt.to_string()),
                _ => break,
            }
        }
        Ok(accounts)
    }

    async fn list_sa_keys(&self, token: &str, sa_name: &str) -> Result<Vec<Value>, ProviderError> {
        let path = format!("/{}/keys?keyTypes=USER_MANAGED", sa_name);
        let resp = self.iam_get(token, &path).await?;
        Ok(resp["keys"].as_array().cloned().unwrap_or_default())
    }


    /// GET on any Google API. Every service has its own host and its own
    /// listing shape, so unlike Azure there is no single inventory endpoint —
    /// Cloud Asset Inventory would be that endpoint, but it has to be enabled
    /// on the project first, so it cannot be the only path.
    async fn get_json(&self, token: &str, url: &str) -> Result<Value, ProviderError> {
        // Per-minute quotas (Cloud Asset's ListAssets above all) answer 429:
        // waiting for the next minute is the documented remedy.
        let mut attempt = 0u32;
        let resp = loop {
            let resp = self
                .client
                .get(url)
                .header("Authorization", format!("Bearer {}", token))
                // User credentials (`gcloud auth application-default login`) need a
                // billing project for several APIs; service accounts carry their own.
                .header("x-goog-user-project", &self.project)
                .send()
                .await
                .map_err(|e| ProviderError::Connection(format!("GET {} failed: {}", url, e)))?;
            if resp.status().as_u16() == 429 && attempt < 6 {
                attempt += 1;
                tracing::info!(url, attempt, "GCP quota exceeded, waiting for the next minute");
                tokio::time::sleep(std::time::Duration::from_secs(15 * attempt as u64)).await;
                continue;
            }
            break resp;
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Query(format!("GET {} ({}): {}", url, status, text)));
        }
        resp.json::<Value>()
            .await
            .map_err(|e| ProviderError::Query(format!("parse {}: {}", url, e)))
    }

    /// Cloud Storage buckets, normalized to the names the rules read.
    ///
    /// GCS omits `versioning` entirely on a bucket where it was never turned
    /// on, and object versioning is off by default — so absent means disabled
    /// here, unlike an API that simply declines to answer.
    async fn gather_storage_buckets(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let url = format!(
            "https://storage.googleapis.com/storage/v1/b?project={}",
            self.project
        );
        let resp = self.get_json(&token, &url).await?;

        Ok(resp
            .get("items")
            .and_then(|i| i.as_array())
            .map(|items| items.iter().map(normalize_bucket).collect())
            .unwrap_or_default())
    }

    /// GKE clusters, normalized to the Terraform-shaped names the rules read —
    /// including its single-element-list convention (`network_policy.0.enabled`),
    /// which is why nested blocks are wrapped in an array of one.
    ///
    /// GCP omits false booleans on the wire (proto3), so a missing flag here
    /// means disabled; that is the API's documented encoding, not a refusal to
    /// answer.
    async fn gather_container_clusters(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let url = format!(
            "https://container.googleapis.com/v1/projects/{}/locations/-/clusters",
            self.project
        );
        let resp = self.get_json(&token, &url).await?;

        Ok(resp
            .get("clusters")
            .and_then(|c| c.as_array())
            .map(|clusters| clusters.iter().map(normalize_cluster).collect())
            .unwrap_or_default())
    }

    /// Walk a Compute aggregated list and flatten it to the resources it holds.
    ///
    /// An aggregated answer is keyed by scope (`zones/europe-west9-a`,
    /// `regions/us-east1`, `global`) and most scopes carry nothing but a
    /// `warning` saying so, which is why the inner key has to be named.
    /// `returnPartialSuccess` keeps one scope the caller cannot read from
    /// turning the whole call into a 403 — without it a single restricted zone
    /// costs the entire inventory.
    async fn list_aggregated(
        &self,
        token: &str,
        resource: &str,
        key: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut url = format!(
                "{}/projects/{}/aggregated/{}?returnPartialSuccess=true&maxResults=500",
                COMPUTE_V1, self.project, resource
            );
            if let Some(pt) = &page_token {
                url.push_str(&format!("&pageToken={}", pt));
            }
            let page = self.get_json(token, &url).await?;
            if let Some(scopes) = page.get("items").and_then(|i| i.as_object()) {
                for body in scopes.values() {
                    if let Some(arr) = body.get(key).and_then(|a| a.as_array()) {
                        out.extend(arr.iter().cloned());
                    }
                }
            }
            match page.get("nextPageToken").and_then(|t| t.as_str()) {
                Some(pt) if !pt.is_empty() => page_token = Some(pt.to_string()),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Walk a flat Google list endpoint, following `nextPageToken`.
    ///
    /// The listing key differs per service (`items` on Compute, `sinks` on
    /// Logging, `datasets` on BigQuery) and every one of them omits the key
    /// entirely when the project holds nothing — an empty project answers
    /// `{}`, not `{"items": []}`, so an absent key is zero resources.
    async fn list_paged(
        &self,
        token: &str,
        base_url: &str,
        key: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        let sep = if base_url.contains('?') { '&' } else { '?' };
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let url = match &page_token {
                Some(pt) => format!("{}{}pageToken={}", base_url, sep, pt),
                None => base_url.to_string(),
            };
            let page = self.get_json(token, &url).await?;
            if let Some(arr) = page.get(key).and_then(|a| a.as_array()) {
                out.extend(arr.iter().cloned());
            }
            match page.get("nextPageToken").and_then(|t| t.as_str()) {
                Some(pt) if !pt.is_empty() => page_token = Some(pt.to_string()),
                _ => break,
            }
        }
        Ok(out)
    }

    async fn gather_compute_instances(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let instances = self.list_aggregated(&token, "instances", "instances").await?;
        Ok(instances.iter().map(normalize_instance).collect())
    }

    async fn gather_compute_disks(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let disks = self.list_aggregated(&token, "disks", "disks").await?;
        Ok(disks.iter().map(normalize_disk).collect())
    }

    async fn gather_compute_subnetworks(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let subnets = self
            .list_aggregated(&token, "subnetworks", "subnetworks")
            .await?;
        Ok(subnets.iter().map(normalize_subnetwork).collect())
    }

    /// SSL policies live in `global` and in every region, so they are read
    /// through the aggregated list even though most projects only ever create
    /// global ones.
    async fn gather_compute_ssl_policies(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let policies = self
            .list_aggregated(&token, "sslPolicies", "sslPolicies")
            .await?;
        Ok(policies.iter().map(normalize_ssl_policy).collect())
    }

    /// VPC firewall rules. These are global objects, not aggregated ones.
    async fn gather_compute_firewalls(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let url = format!(
            "{}/projects/{}/global/firewalls?maxResults=500",
            COMPUTE_V1, self.project
        );
        let rules = self.list_paged(&token, &url, "items").await?;
        Ok(rules.iter().map(normalize_firewall).collect())
    }

    /// Latest value of the main Cloud Monitoring metrics, one object per
    /// resource: bucket size and object count, VM and Cloud SQL CPU.
    ///
    /// Storage metrics are sampled once a day, so they are read over the last
    /// two days; CPU over the last ten minutes. A metric the project does not
    /// produce (or a Monitoring API that is disabled) is skipped; the call
    /// fails only when none could be read.
    async fn gather_metrics(&self) -> Result<Vec<Value>, ProviderError> {
        const METRICS: &[(&str, &str, &str, &str, i64)] = &[
            // (metric type, resource label, kind, field, window seconds)
            ("storage.googleapis.com/storage/total_bytes", "bucket_name", "bucket", "size_bytes", 172_800),
            ("storage.googleapis.com/storage/object_count", "bucket_name", "bucket", "objects", 172_800),
            ("compute.googleapis.com/instance/cpu/utilization", "instance_id", "vm", "cpu_pct", 600),
            ("cloudsql.googleapis.com/database/cpu/utilization", "database_id", "cloudsql", "cpu_pct", 600),
        ];
        let token = self.get_token().await?;
        let end = chrono::Utc::now();
        let mut by_resource: std::collections::BTreeMap<(String, String), serde_json::Map<String, Value>> =
            Default::default();
        let mut last_error = None;
        let mut any_ok = false;

        for (metric, label, kind, field, window) in METRICS {
            let start = end - chrono::Duration::seconds(*window);
            let url = format!(
                "https://monitoring.googleapis.com/v3/projects/{}/timeSeries?filter={}&interval.startTime={}&interval.endTime={}",
                self.project,
                urlencoding::encode(&format!("metric.type=\"{metric}\"")),
                urlencoding::encode(&start.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
                urlencoding::encode(&end.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            );
            let series = match self.list_paged(&token, &url, "timeSeries").await {
                Ok(s) => {
                    any_ok = true;
                    s
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            };
            for ts in series {
                // A VM is better known by its name than by its numeric id.
                let resource = ts["metric"]["labels"]["instance_name"]
                    .as_str()
                    .or_else(|| ts["resource"]["labels"][*label].as_str())
                    .unwrap_or("?")
                    .to_string();
                // Points come newest first.
                let point = &ts["points"][0];
                let value = point["value"]["doubleValue"]
                    .as_f64()
                    .or_else(|| point["value"]["int64Value"].as_str().and_then(|v| v.parse().ok()))
                    .or_else(|| point["value"]["int64Value"].as_f64());
                let Some(mut value) = value else { continue };
                if *field == "cpu_pct" {
                    value = (value * 1000.0).round() / 10.0;
                }
                let entry = by_resource.entry((kind.to_string(), resource.clone())).or_insert_with(|| {
                    let mut m = serde_json::Map::new();
                    m.insert("kind".into(), json!(kind));
                    m.insert("resource".into(), json!(resource));
                    if let Some(zone) = ts["resource"]["labels"]["zone"].as_str()
                        .or_else(|| ts["resource"]["labels"]["location"].as_str())
                        .or_else(|| ts["resource"]["labels"]["region"].as_str())
                    {
                        m.insert("location".into(), json!(zone));
                    }
                    m
                });
                entry.insert(field.to_string(), json!(value));
                if let Some(t) = point["interval"]["endTime"].as_str() {
                    entry.insert("time".into(), json!(t));
                }
            }
        }
        if !any_ok {
            return Err(last_error.unwrap_or_else(|| {
                ProviderError::Query("Cloud Monitoring returned nothing".into())
            }));
        }
        Ok(by_resource.into_values().map(Value::Object).collect())
    }

    /// Objects described as the API returns them, for `kxn get`: no rule
    /// reads these types, so nothing is normalized — or invented. Secret
    /// Manager entries are metadata only; values are never read.
    async fn list_raw(&self, url_template: &str, key: &str) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let url = url_template.replace("{p}", &self.project);
        self.list_paged(&token, &url, key).await
    }

    async fn gather_logging_sinks(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let url = format!(
            "https://logging.googleapis.com/v2/projects/{}/sinks",
            self.project
        );
        let sinks = self.list_paged(&token, &url, "sinks").await?;
        let mut rows: Vec<Value> = sinks.iter().map(normalize_log_sink).collect();
        // CIS 2.3: a sink exporting to Cloud Storage needs a locked retention
        // policy on its bucket. `null` when the bucket could not be read.
        for row in &mut rows {
            let Some(bucket) = row["destination"]
                .as_str()
                .and_then(|d| d.strip_prefix("storage.googleapis.com/"))
                .map(String::from)
            else {
                continue;
            };
            let url = format!("https://storage.googleapis.com/storage/v1/b/{bucket}?fields=retentionPolicy");
            row["retention_locked"] = match self.get_json(&token, &url).await {
                Ok(b) => json!(b["retentionPolicy"]["isLocked"].as_bool().unwrap_or(false)),
                Err(_) => Value::Null,
            };
        }
        Ok(rows)
    }

    /// VPC networks, with the DNS policies that log their queries.
    async fn gather_networks(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let networks = self
            .list_paged(&token, &format!("{COMPUTE_V1}/projects/{}/global/networks", self.project), "items")
            .await?;
        let policies = match self
            .list_paged(&token, &format!("https://dns.googleapis.com/dns/v1/projects/{}/policies", self.project), "policies")
            .await
        {
            Ok(p) => p,
            // No Cloud DNS API, no DNS policy: nothing logs.
            Err(e) if is_service_disabled(&e) => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(networks.iter().map(|n| normalize_network(n, &policies)).collect())
    }

    /// BigQuery datasets, one GET per dataset.
    ///
    /// `datasets.list` answers a stub — `datasetReference`, `location`, `type`
    /// and nothing else (checked against a live dataset). Neither `access` nor
    /// `defaultEncryptionConfiguration` is in it, and both rules read exactly
    /// those, so the detail call is not an optimization to skip.
    async fn gather_bigquery_datasets(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let list_url = format!(
            "https://bigquery.googleapis.com/bigquery/v2/projects/{}/datasets?maxResults=1000",
            self.project
        );
        let stubs = self.list_paged(&token, &list_url, "datasets").await?;

        let mut results = Vec::new();
        for stub in stubs {
            let dataset_id = match stub.pointer("/datasetReference/datasetId").and_then(|v| v.as_str()) {
                Some(id) => id.to_string(),
                None => continue,
            };
            // The dataset's own project, not ours: a listing can surface
            // datasets that live elsewhere and are only linked here.
            let owner = stub
                .pointer("/datasetReference/projectId")
                .and_then(|v| v.as_str())
                .unwrap_or(&self.project)
                .to_string();
            let url = format!(
                "https://bigquery.googleapis.com/bigquery/v2/projects/{}/datasets/{}",
                owner, dataset_id
            );
            match self.get_json(&token, &url).await {
                Ok(detail) => results.push(normalize_dataset(&detail)),
                // Skipping the dataset leaves it unscanned, which is visible in
                // the logs; emitting the stub instead would answer both rules
                // from fields the stub never carried.
                Err(e) => tracing::warn!(dataset = %dataset_id, error = %e, "Failed to read BigQuery dataset"),
            }
        }
        Ok(results)
    }


    async fn post_json(&self, token: &str, url: &str, body: &Value) -> Result<Value, ProviderError> {
        let resp = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {}", token))
            .header("x-goog-user-project", &self.project)
            .json(body)
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("POST {} failed: {}", url, e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Query(format!("POST {} ({}): {}", url, status, text)));
        }
        resp.json::<Value>()
            .await
            .map_err(|e| ProviderError::Query(format!("parse {}: {}", url, e)))
    }

    async fn project_iam_policy(&self, token: &str) -> Result<Value, ProviderError> {
        let url = format!(
            "https://cloudresourcemanager.googleapis.com/v1/projects/{}:getIamPolicy",
            self.project
        );
        self.post_json(token, &url, &json!({"options": {"requestedPolicyVersion": 3}})).await
    }

    /// One row per (role, member) of the project's IAM policy.
    async fn gather_project_iam_members(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let policy = self.project_iam_policy(&token).await?;
        Ok(iam_members(&policy))
    }

    /// Service accounts with what CIS asks about them: user-managed keys and
    /// the roles they hold on the project.
    async fn gather_service_accounts(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let accounts = self.list_service_accounts(&token).await?;
        let members = self.project_iam_policy(&token).await.map(|p| iam_members(&p))?;
        let now = Utc::now();
        let mut out = Vec::new();
        for sa in accounts {
            let email = sa["email"].as_str().unwrap_or("").to_string();
            let name = sa["name"].as_str().unwrap_or("");
            let keys = match self.list_sa_keys(&token, name).await {
                Ok(k) => Some(k),
                Err(e) => {
                    tracing::warn!(sa = %email, error = %e, "Failed to list keys for SA");
                    None
                }
            };
            let roles: Vec<&Value> = members
                .iter()
                .filter(|m| m["member"].as_str() == Some(&format!("serviceAccount:{email}")))
                .map(|m| &m["role"])
                .collect();
            let mut row = sa.clone();
            row["roles"] = json!(roles);
            // Unknown when the key listing failed: a rule must not read
            // "no keys" from a call that never answered.
            row["key_count"] = keys.as_ref().map(|k| json!(k.len())).unwrap_or(Value::Null);
            row["oldest_key_age_days"] = keys
                .as_ref()
                .and_then(|k| k.iter().filter_map(|k| age_days(k["validAfterTime"].as_str(), &now)).max())
                .map(|d| json!(d))
                .unwrap_or(Value::Null);
            row["default_compute"] = json!(email.ends_with("-compute@developer.gserviceaccount.com"));
            out.push(row);
        }
        Ok(out)
    }

    /// Every resource of every type in the project, through Cloud Asset
    /// Inventory — the one endpoint that sees all of GCP. Needs
    /// `cloudasset.googleapis.com` enabled on the project.
    async fn gather_assets(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let url = format!(
            "https://cloudasset.googleapis.com/v1/projects/{}:searchAllResources?pageSize=500",
            self.project
        );
        let assets = self
            .list_paged(&token, &url, "results")
            .await
            .map_err(|e| self.asset_error(e))?;
        Ok(assets.iter().map(normalize_asset).collect())
    }

    /// Turn "Cloud Asset is not enabled" into the command that fixes it.
    fn asset_error(&self, e: ProviderError) -> ProviderError {
        if is_service_disabled(&e) {
            ProviderError::Query(format!(
                "Cloud Asset API is not enabled on project {}: run `gcloud services enable \
                 cloudasset.googleapis.com --project {}` to inventory every resource",
                self.project, self.project
            ))
        } else {
            e
        }
    }

    /// The whole project's Cloud Asset inventory — every resource with its
    /// configuration, and the IAM policy of each — listed once and shared by
    /// all asset types. Listing each type on its own would cost a request per
    /// type, and `ListAssets` is rate-limited per minute.
    async fn asset_inventory(
        &self,
    ) -> Result<&std::collections::HashMap<String, Vec<Value>>, ProviderError> {
        self.inventory
            .get_or_try_init(|| async {
                let token = self.get_token().await?;
                let base = format!(
                    "https://cloudasset.googleapis.com/v1/projects/{}/assets?pageSize=1000",
                    self.project
                );
                let resources = self
                    .list_paged(&token, &format!("{base}&contentType=RESOURCE"), "assets")
                    .await
                    .map_err(|e| self.asset_error(e))?;
                let policies = match self
                    .list_paged(&token, &format!("{base}&contentType=IAM_POLICY"), "assets")
                    .await
                {
                    Ok(p) => Some(p),
                    Err(e) => {
                        tracing::warn!(project = %self.project, error = %e, "Cloud Asset IAM policies unreadable: `_iam` left unknown");
                        None
                    }
                };
                Ok(super::gcp_assets::group_assets(&resources, policies.as_deref(), &self.project))
            })
            .await
    }

    /// Project-wide settings CIS asks about, as one row: audit logging,
    /// log export, essential contacts, Access Approval, Cloud Asset, OS Login.
    ///
    /// A setting that could not be read is `null`, never a guess: `null` fails
    /// an `EQUAL true` rule, which is the honest answer to "is it on?" when
    /// nobody could look.
    async fn gather_project(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let p = &self.project;

        let policy = self.project_iam_policy(&token).await?;
        let (audit_log_types, audit_exempted) = all_services_audit(&policy);

        let sinks_url = format!("https://logging.googleapis.com/v2/projects/{p}/sinks");
        let log_sink_all_entries = match self.list_paged(&token, &sinks_url, "sinks").await {
            Ok(sinks) => json!(sinks.iter().any(|s| {
                !s["disabled"].as_bool().unwrap_or(false)
                    && s["filter"].as_str().map(str::trim).unwrap_or("").is_empty()
            })),
            Err(e) if is_service_disabled(&e) => json!(false),
            Err(_) => Value::Null,
        };

        let mut missing = Vec::new();
        let mut contacts_known = true;
        for category in ESSENTIAL_CONTACT_CATEGORIES {
            let url = format!(
                "https://essentialcontacts.googleapis.com/v1/projects/{p}/contacts:compute?notificationCategories={category}"
            );
            match self.get_json(&token, &url).await {
                Ok(v) if v["contacts"].as_array().is_some_and(|a| !a.is_empty()) => {}
                Ok(_) => missing.push(*category),
                // Contacts are managed through this API: a project that never
                // enabled it has none of its own to notify.
                Err(e) if is_service_disabled(&e) => missing.push(*category),
                Err(_) => contacts_known = false,
            }
        }
        let essential_contacts_configured =
            if contacts_known { json!(missing.is_empty()) } else { Value::Null };

        let aa_url = format!("https://accessapproval.googleapis.com/v1/projects/{p}/accessApprovalSettings");
        let access_approval_enabled = match self.get_json(&token, &aa_url).await {
            Ok(v) => json!(v["enrolledServices"].as_array().is_some_and(|a| !a.is_empty())),
            Err(e) if is_service_disabled(&e) || e.to_string().contains("(404") => json!(false),
            Err(_) => Value::Null,
        };

        let su_url = format!("https://serviceusage.googleapis.com/v1/projects/{p}/services/cloudasset.googleapis.com");
        let asset_inventory_enabled = match self.get_json(&token, &su_url).await {
            Ok(v) => json!(v["state"].as_str() == Some("ENABLED")),
            Err(_) => Value::Null,
        };

        let os_login_enabled = match self.get_json(&token, &format!("{COMPUTE_V1}/projects/{p}")).await {
            Ok(v) => json!(metadata_map(v.get("commonInstanceMetadata"))["enable-oslogin"]
                .as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case("true"))),
            Err(e) if is_service_disabled(&e) => json!(false),
            Err(_) => Value::Null,
        };

        Ok(vec![json!({
            "name": p,
            "audit_log_types": audit_log_types,
            "audit_exempted_members": audit_exempted,
            "log_sink_all_entries": log_sink_all_entries,
            "essential_contacts_configured": essential_contacts_configured,
            "essential_contacts_missing": missing,
            "access_approval_enabled": access_approval_enabled,
            "asset_inventory_enabled": asset_inventory_enabled,
            "os_login_enabled": os_login_enabled,
        })])
    }

    /// CIS 2.4–2.11: for each change CIS wants alerted on, whether a log-based
    /// metric matches it and an enabled alert policy watches that metric. One
    /// row per control, always — a project with neither has eight rows saying
    /// so, rather than no rows and nothing to fail.
    async fn gather_logging_metric_alerts(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let p = &self.project;
        let metrics = self
            .list_paged(&token, &format!("https://logging.googleapis.com/v2/projects/{p}/metrics"), "metrics")
            .await
            .or_else(|e| if is_service_disabled(&e) { Ok(Vec::new()) } else { Err(e) })?;
        let policies = self
            .list_paged(&token, &format!("https://monitoring.googleapis.com/v3/projects/{p}/alertPolicies"), "alertPolicies")
            .await
            .or_else(|e| if is_service_disabled(&e) { Ok(Vec::new()) } else { Err(e) })?;
        Ok(metric_alert_rows(&metrics, &policies))
    }

    /// Cloud KMS keys. KMS has no `-` location wildcard: list the locations,
    /// then the key rings of each, then their keys.
    async fn gather_kms_keys(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let base = format!("https://cloudkms.googleapis.com/v1/projects/{}", self.project);
        let locations = self
            .list_paged(&token, &format!("{base}/locations?pageSize=500"), "locations")
            .await?;
        let mut out = Vec::new();
        for loc in locations {
            let Some(loc_id) = loc["locationId"].as_str() else { continue };
            let rings = self
                .list_paged(&token, &format!("{base}/locations/{loc_id}/keyRings?pageSize=1000"), "keyRings")
                .await?;
            for ring in rings {
                let Some(ring_name) = ring["name"].as_str() else { continue };
                let keys = self
                    .list_paged(
                        &token,
                        &format!("https://cloudkms.googleapis.com/v1/{ring_name}/cryptoKeys?pageSize=1000"),
                        "cryptoKeys",
                    )
                    .await?;
                out.extend(keys.iter().map(normalize_kms_key));
            }
        }
        Ok(out)
    }

    /// API keys of the project, with whether each is restricted.
    async fn gather_api_keys(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let url = format!(
            "https://apikeys.googleapis.com/v2/projects/{}/locations/global/keys?pageSize=300",
            self.project
        );
        let now = Utc::now();
        Ok(self
            .list_paged(&token, &url, "keys")
            .await?
            .iter()
            .map(|k| normalize_api_key(k, &now))
            .collect())
    }

    /// The effective value, on this project, of the organization policy
    /// constraints CIS checks — set here, inherited, or Google's default.
    async fn gather_org_policies(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let mut out = Vec::new();
        for constraint in ORG_POLICY_CONSTRAINTS {
            let url = format!(
                "https://orgpolicy.googleapis.com/v2/projects/{}/policies/{}:getEffectivePolicy",
                self.project, constraint
            );
            match self.get_json(&token, &url).await {
                Ok(p) => out.push(normalize_org_policy(constraint, &p)),
                Err(e) if is_service_disabled(&e) => return Err(e),
                // A constraint unknown to this organization: nothing to report.
                Err(e) => tracing::debug!(constraint, error = %e, "org policy not readable"),
            }
        }
        Ok(out)
    }

    /// Every version of every Secret Manager secret.
    async fn gather_secret_versions(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let secrets = self
            .list_paged(
                &token,
                &format!("https://secretmanager.googleapis.com/v1/projects/{}/secrets?pageSize=250", self.project),
                "secrets",
            )
            .await?;
        let now = Utc::now();
        let mut out = Vec::new();
        for secret in secrets {
            let Some(name) = secret["name"].as_str() else { continue };
            let versions = self
                .list_paged(
                    &token,
                    &format!("https://secretmanager.googleapis.com/v1/{name}/versions?pageSize=250"),
                    "versions",
                )
                .await?;
            for v in versions {
                out.push(json!({
                    "secret": name.rsplit('/').next().unwrap_or(name),
                    "version": v["name"].as_str().and_then(|n| n.rsplit('/').next()),
                    "state": v["state"],
                    "create_time": v["createTime"],
                    "age_days": age_days(v["createTime"].as_str(), &now),
                    "destroy_time": v["destroyTime"],
                }));
            }
        }
        Ok(out)
    }

    async fn gather_service_account_keys(&self) -> Result<Vec<Value>, ProviderError> {
        let token = self.get_token().await?;
        let now = Utc::now();
        let accounts = self.list_service_accounts(&token).await?;

        let mut results = Vec::new();
        for sa in accounts {
            let email = sa["email"].as_str().unwrap_or("").to_string();
            let sa_name = sa["name"].as_str().unwrap_or("").to_string();
            if sa_name.is_empty() {
                continue;
            }

            let keys = match self.list_sa_keys(&token, &sa_name).await {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(sa = %email, error = %e, "Failed to list keys for SA");
                    continue;
                }
            };

            for key in keys {
                let key_name = key["name"].as_str().unwrap_or("").to_string();
                let key_id = key_name.split('/').next_back().unwrap_or("").to_string();
                if key_id.is_empty() {
                    continue;
                }
                let valid_after_str = key["validAfterTime"].as_str().unwrap_or("").to_string();
                let valid_before_str = key["validBeforeTime"].as_str().unwrap_or("").to_string();
                let algorithm = key["keyAlgorithm"].as_str().unwrap_or("").to_string();

                let (days_until_expiry, effective_expiry) =
                    compute_days_until_expiry(&valid_after_str, &valid_before_str, self.key_max_age_days, &now);

                results.push(json!({
                    "email": email,
                    "key_id": key_id,
                    "key_algorithm": algorithm,
                    "valid_after_time": valid_after_str,
                    "valid_before_time": effective_expiry,
                    "days_until_expiry": days_until_expiry,
                    "key_type": "USER_MANAGED",
                }));
            }
        }

        Ok(results)
    }
}

/// Compute days until expiry for a GCP SA key.
///
/// If `valid_before_time` is far in the future (year >= 9990), falls back to
/// `valid_after_time + max_age_days` as the effective expiry date.
fn compute_days_until_expiry(
    valid_after_str: &str,
    valid_before_str: &str,
    max_age_days: i64,
    now: &DateTime<Utc>,
) -> (i64, String) {
    // Check if validBeforeTime is a real expiry or the GCP "no expiry" sentinel
    let use_explicit_expiry = valid_before_str
        .split('-')
        .next()
        .and_then(|y| y.parse::<i32>().ok())
        .map(|year| year < 9990)
        .unwrap_or(false);

    if use_explicit_expiry {
        if let Ok(expiry) = valid_before_str.parse::<DateTime<Utc>>() {
            let days = (expiry - *now).num_days();
            return (days, valid_before_str.to_string());
        }
    }

    // Fall back to age-based expiry: creation_date + max_age_days
    if let Ok(created) = valid_after_str.parse::<DateTime<Utc>>() {
        let effective_expiry = created + chrono::Duration::days(max_age_days);
        let days = (effective_expiry - *now).num_days();
        let expiry_str = effective_expiry.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        return (days, expiry_str);
    }

    (i64::MAX, String::new())
}

#[async_trait::async_trait]
impl Provider for GcpProvider {
    fn name(&self) -> &str { "gcp" }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        match self.gather_one(resource_type).await {
            // A project that never enabled an API has none of its resources:
            // Google answers 403 SERVICE_DISABLED rather than an empty list.
            // Reporting that as a failure made every scan of a small project
            // end in a wall of errors for services it does not use. Cloud Asset
            // is the exception: its absence hides everything, so it is said.
            Err(e)
                if resource_type != "assets"
                    && !is_asset_type(resource_type)
                    && is_service_disabled(&e) =>
            {
                tracing::info!(project = %self.project, resource_type, "API not enabled on the project: no resources");
                Ok(Vec::new())
            }
            other => other,
        }
    }
}

impl GcpProvider {
    async fn gather_one(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        if is_asset_type(resource_type) {
            let inventory = self.asset_inventory().await?;
            return Ok(inventory.get(resource_type).cloned().unwrap_or_default());
        }
        match resource_type {
            "api_keys" => self.gather_api_keys().await,
            "assets" => self.gather_assets().await,
            "kms_crypto_key" => self.gather_kms_keys().await,
            "org_policies" => self.gather_org_policies().await,
            "project_iam_member" => self.gather_project_iam_members().await,
            "secret_versions" => self.gather_secret_versions().await,
            "bigquery_dataset" => self.gather_bigquery_datasets().await,
            "compute_disk" => self.gather_compute_disks().await,
            "compute_firewall" => self.gather_compute_firewalls().await,
            "compute_instance" => self.gather_compute_instances().await,
            "compute_ssl_policy" => self.gather_compute_ssl_policies().await,
            "compute_subnetwork" => self.gather_compute_subnetworks().await,
            "container_cluster" => self.gather_container_clusters().await,
            "logging_project_sink" => self.gather_logging_sinks().await,
            "logging_metric_alerts" => self.gather_logging_metric_alerts().await,
            "project" => self.gather_project().await,
            "cloud_functions" => Ok(self
                .list_raw("https://cloudfunctions.googleapis.com/v2/projects/{p}/locations/-/functions", "functions")
                .await?
                .iter()
                .map(normalize_function)
                .collect()),
            "cloud_run_services" => self.list_raw("https://run.googleapis.com/v2/projects/{p}/locations/-/services", "services").await,
            "cloud_sql_instances" => Ok(self
                .list_raw("https://sqladmin.googleapis.com/v1/projects/{p}/instances", "items")
                .await?
                .iter()
                .map(normalize_sql_instance)
                .collect()),
            "dns_zones" => Ok(self
                .list_raw("https://dns.googleapis.com/dns/v1/projects/{p}/managedZones", "managedZones")
                .await?
                .iter()
                .map(normalize_dns_zone)
                .collect()),
            "iam_service_accounts" => self.gather_service_accounts().await,
            "networks" => self.gather_networks().await,
            "pubsub_subscriptions" => self.list_raw("https://pubsub.googleapis.com/v1/projects/{p}/subscriptions", "subscriptions").await,
            "pubsub_topics" => self.list_raw("https://pubsub.googleapis.com/v1/projects/{p}/topics", "topics").await,
            "secrets" => self.list_raw("https://secretmanager.googleapis.com/v1/projects/{p}/secrets", "secrets").await,
            "metrics" => self.gather_metrics().await,
            "service_account_keys" => self.gather_service_account_keys().await,
            "storage_bucket" => self.gather_storage_buckets().await,
            _ => Err(ProviderError::NotFound(format!(
                "Unknown resource type '{}' for gcp provider", resource_type
            ))),
        }
    }
}

/// IDs of the active projects the credentials can see, for `gcp://` with no
/// project (scan, get or top every project). Same credentials as a scan:
/// `GOOGLE_OAUTH_ACCESS_TOKEN`, else Application Default Credentials or the
/// gcloud login.
pub async fn list_projects() -> Result<Vec<String>, ProviderError> {
    let token = match std::env::var("GOOGLE_OAUTH_ACCESS_TOKEN") {
        Ok(t) if !t.trim().is_empty() => t,
        _ => {
            let provider = gcp_auth::provider()
                .await
                .map_err(|e| ProviderError::Connection(format!("GCP auth failed: {}", e)))?;
            provider
                .token(&["https://www.googleapis.com/auth/cloud-platform"])
                .await
                .map_err(|e| ProviderError::Connection(format!("GCP token failed: {}", e)))?
                .as_str()
                .to_string()
        }
    };
    let client = crate::http::shared_client();
    let mut ids = Vec::new();
    let mut page: Option<String> = None;
    loop {
        let mut url = "https://cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState%3AACTIVE&pageSize=500".to_string();
        if let Some(p) = &page {
            url.push_str(&format!("&pageToken={}", urlencoding::encode(p)));
        }
        let resp = client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("listing projects: {e}")))?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or_default();
        if !status.is_success() {
            return Err(ProviderError::Query(format!(
                "listing projects ({status}): {}",
                body["error"]["message"].as_str().unwrap_or("")
            )));
        }
        ids.extend(
            body["projects"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|p| p["projectId"].as_str().map(String::from)),
        );
        match body["nextPageToken"].as_str() {
            Some(t) if !t.is_empty() => page = Some(t.to_string()),
            _ => break,
        }
    }
    ids.sort();
    Ok(ids)
}

/// Rotate a GCP service account key and store the new JSON key in Secret Manager.
///
/// Steps:
/// 1. Create a new SA key (JSON format)
/// 2. Store the JSON in Secret Manager (new version)
/// 3. Delete the old key
///
/// Returns the new key ID.
pub async fn rotate_sa_key(
    project: &str,
    sa_email: &str,
    old_key_id: &str,
    secret_name: &str,
) -> anyhow::Result<String> {
    let http = crate::http::shared_client();

    // 1. Get GCP token
    let provider = gcp_auth::provider()
        .await
        .context("GCP auth failed")?;
    let token = provider
        .token(&["https://www.googleapis.com/auth/cloud-platform"])
        .await
        .context("GCP token failed")?;
    let token_str = token.as_str();

    // 2. Create new SA key
    let sa_resource = format!("projects/{}/serviceAccounts/{}", project, sa_email);
    let create_url = format!("https://iam.googleapis.com/v1/{}/keys", sa_resource);
    let create_resp = http
        .post(&create_url)
        .header("Authorization", format!("Bearer {}", token_str))
        .header("Content-Type", "application/json")
        .json(&json!({
            "keyAlgorithm": "KEY_ALG_RSA_2048",
            "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE"
        }))
        .send().await.context("GCP createServiceAccountKey request")?;

    if !create_resp.status().is_success() {
        let status = create_resp.status();
        let body = create_resp.text().await.unwrap_or_default();
        anyhow::bail!("createServiceAccountKey failed ({}): {}", status, body);
    }

    let new_key: Value = create_resp.json().await.context("createServiceAccountKey response parse")?;
    let new_key_id = new_key["name"]
        .as_str()
        .and_then(|n| n.split('/').next_back())
        .context("no key name in createServiceAccountKey response")?
        .to_string();
    let private_key_data_b64 = new_key["privateKeyData"]
        .as_str()
        .context("no privateKeyData in createServiceAccountKey response")?;

    // privateKeyData is base64-encoded JSON key file
    let key_json_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        private_key_data_b64,
    ).context("base64 decode of privateKeyData")?;

    // 3. Ensure the Secret Manager secret exists (create if needed)
    let secret_resource = format!("projects/{}/secrets/{}", project, secret_name);
    let ensure_url = format!("https://secretmanager.googleapis.com/v1/{}", secret_resource);
    let ensure_resp = http
        .get(&ensure_url)
        .header("Authorization", format!("Bearer {}", token_str))
        .send().await.context("Secret Manager GET secret")?;

    if ensure_resp.status() == reqwest::StatusCode::NOT_FOUND {
        // Create the secret
        let create_secret_url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets?secretId={}",
            project, secret_name
        );
        let cs_resp = http
            .post(&create_secret_url)
            .header("Authorization", format!("Bearer {}", token_str))
            .header("Content-Type", "application/json")
            .json(&json!({ "replication": { "automatic": {} } }))
            .send().await.context("Secret Manager create secret")?;
        if !cs_resp.status().is_success() {
            let body = cs_resp.text().await.unwrap_or_default();
            anyhow::bail!("Secret Manager create secret failed: {}", body);
        }
    }

    // 4. Add new secret version
    let add_version_url = format!(
        "https://secretmanager.googleapis.com/v1/{}:addVersion",
        secret_resource
    );
    let payload_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &key_json_bytes,
    );
    let sv_resp = http
        .post(&add_version_url)
        .header("Authorization", format!("Bearer {}", token_str))
        .header("Content-Type", "application/json")
        .json(&json!({ "payload": { "data": payload_b64 } }))
        .send().await.context("Secret Manager addSecretVersion")?;

    if !sv_resp.status().is_success() {
        let status = sv_resp.status();
        let body = sv_resp.text().await.unwrap_or_default();
        anyhow::bail!("Secret Manager addSecretVersion failed ({}): {}", status, body);
    }

    // 5. Delete old key (retry for transient errors)
    if !old_key_id.is_empty() {
        let delete_url = format!(
            "https://iam.googleapis.com/v1/{}/keys/{}",
            sa_resource, old_key_id
        );
        let mut deleted = false;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
            let del_resp = http
                .delete(&delete_url)
                .header("Authorization", format!("Bearer {}", token_str))
                .send().await.context("GCP deleteServiceAccountKey")?;
            if del_resp.status().is_success() || del_resp.status() == reqwest::StatusCode::NOT_FOUND {
                deleted = true;
                break;
            }
            if attempt == 2 {
                let body = del_resp.text().await.unwrap_or_default();
                eprintln!("[remediation] Warning: deleteServiceAccountKey failed after 3 attempts: {}", body);
            }
        }
        let _ = deleted;
    }

    Ok(new_key_id)
}

/// Map a Cloud Storage bucket to the object the rules describe.
fn normalize_bucket(b: &Value) -> Value {
    let iam = b.get("iamConfiguration").cloned().unwrap_or(Value::Null);
    let mut out = json!({
        "name": b.get("name"),
        "location": b.get("location"),
        "storage_class": b.get("storageClass"),
        "uniform_bucket_level_access": iam
            .pointer("/uniformBucketLevelAccess/enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        // GCS omits `versioning` on a bucket where it was never turned on, and
        // object versioning is off by default — absent means disabled here.
        "versioning_enabled": b
            .pointer("/versioning/enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    });
    if let Some(pap) = iam.get("publicAccessPrevention") {
        out["public_access_prevention"] = pap.clone();
    }
    out
}

/// Map a GKE cluster to the object the rules describe.
///
/// `node_config.0.management.0.auto_upgrade` is an aggregate: GKE carries
/// auto-upgrade per node pool, the rule asks one question of the cluster, so it
/// holds only when every pool has it. A cluster with no pool at all answers
/// nothing rather than inventing a `true`.
fn normalize_cluster(c: &Value) -> Value {
    let mut out = json!({
        "name": c.get("name"),
        "location": c.get("location"),
        "status": c.get("status"),
        "logging_service": c.get("loggingService"),
        "monitoring_service": c.get("monitoringService"),
        "enable_legacy_abac": c.pointer("/legacyAbac/enabled").and_then(|v| v.as_bool()).unwrap_or(false),
        "network_policy": [{
            "enabled": c.pointer("/networkPolicy/enabled").and_then(|v| v.as_bool()).unwrap_or(false)
        }],
        "private_cluster_config": [{
            "enable_private_nodes": c
                .pointer("/privateClusterConfig/enablePrivateNodes")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        }],
        "master_authorized_networks_config": [{
            "cidr_blocks": c
                .pointer("/masterAuthorizedNetworksConfig/cidrBlocks")
                .cloned()
                .unwrap_or_else(|| Value::Array(vec![]))
        }],
    });

    if let Some(pools) = c.get("nodePools").and_then(|p| p.as_array()) {
        if !pools.is_empty() {
            let all_auto_upgrade = pools.iter().all(|p| {
                p.pointer("/management/autoUpgrade")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            });
            out["node_config"] = json!([{ "management": [{ "auto_upgrade": all_auto_upgrade }] }]);
        }
    }

    if let Some(psp) = c.pointer("/podSecurityPolicyConfig/enabled").and_then(|v| v.as_bool()) {
        out["pod_security_policy_config"] = json!([{ "enabled": psp }]);
    }

    out
}

/// Last path segment of a Compute self link (`.../zones/europe-west9-a` →
/// `europe-west9-a`). Compute answers scopes as full URLs; the rules and the
/// reports want the bare name.
fn short_name(link: Option<&Value>) -> Option<&str> {
    link.and_then(|l| l.as_str())
        .and_then(|l| l.rsplit('/').next())
}

/// Instance metadata keys worth carrying into a scan result.
///
/// Extend this list when a rule starts reading another key — a key that is not
/// here reads as an empty string and its rule fails on a resource that may
/// well be compliant.
const SECURITY_METADATA_KEYS: &[&str] = &[
    "block-project-ssh-keys",
    "disable-legacy-endpoints",
    "enable-oslogin",
    "enable-oslogin-2fa",
    "enable-oslogin-sk",
    "serial-port-enable",
    "serial-port-logging-enable",
];

/// Terraform flattens an instance's `metadata.items[]` key/value list into a
/// map, which is how the rules index it (`metadata.enable-oslogin`).
///
/// Only the security flags above are copied. The rest of a real instance's
/// metadata is both enormous and secret-bearing — a GKE node's `kube-env`
/// alone holds `TPM_BOOTSTRAP_KEY` and `KUBE_PROXY_TOKEN`, and `configure-sh`
/// added 60 KB on the one node of the test project — and a scan result is not
/// a place to copy credentials to.
///
/// A key the instance never set stays out of the map: the engine reads the
/// missing property as an empty string, and for `block-project-ssh-keys` and
/// `enable-oslogin` that is the right answer — not setting them is exactly
/// what CIS 4.3 and 4.4 flag.
fn metadata_map(metadata: Option<&Value>) -> Value {
    let mut map = serde_json::Map::new();
    if let Some(items) = metadata.and_then(|m| m.get("items")).and_then(|i| i.as_array()) {
        for item in items {
            match item.get("key").and_then(|k| k.as_str()) {
                Some(key) if SECURITY_METADATA_KEYS.contains(&key) => {
                    map.insert(
                        key.to_string(),
                        item.get("value").cloned().unwrap_or(Value::Null),
                    );
                }
                _ => {}
            }
        }
    }
    Value::Object(map)
}

/// Map a Compute instance to the object the rules describe.
///
/// Instance metadata only — GCP also applies project-wide metadata at boot, so
/// an instance can have OS Login on through the project while its own metadata
/// says nothing. The rules were written against `google_compute_instance`,
/// whose `metadata` is the instance's own, and merging the project's in would
/// answer a different question than the one asked.
fn normalize_instance(i: &Value) -> Value {
    let mut out = json!({
        "name": i.get("name"),
        "zone": short_name(i.get("zone")),
        "machine_type": short_name(i.get("machineType")),
        "status": i.get("status"),
        // proto3 omits false booleans on the wire: an instance that does not
        // mention canIpForward has IP forwarding off. Observed on a live
        // instance, which carries no `canIpForward` at all.
        "can_ip_forward": i.get("canIpForward").and_then(|v| v.as_bool()).unwrap_or(false),
        "deletion_protection": i.get("deletionProtection").and_then(|v| v.as_bool()).unwrap_or(false),
        // Either the legacy boolean or a confidential instance type (SEV,
        // SEV_SNP, TDX) — proto3 omits both when confidential computing is off.
        "confidential_computing": i.pointer("/confidentialInstanceConfig/enableConfidentialCompute").and_then(|v| v.as_bool()).unwrap_or(false)
            || i.pointer("/confidentialInstanceConfig/confidentialInstanceType").and_then(|v| v.as_str()).is_some_and(|t| !t.is_empty() && t != "CONFIDENTIAL_INSTANCE_TYPE_UNSPECIFIED"),
        "metadata": metadata_map(i.get("metadata")),
        // Same proto3 default: no shielded config, or a config that leaves a
        // flag out, means the feature is off — which is the finding CIS 4.6
        // is after.
        "shielded_instance_config": [{
            "enable_vtpm": i.pointer("/shieldedInstanceConfig/enableVtpm").and_then(|v| v.as_bool()).unwrap_or(false),
            "enable_secure_boot": i.pointer("/shieldedInstanceConfig/enableSecureBoot").and_then(|v| v.as_bool()).unwrap_or(false),
            "enable_integrity_monitoring": i.pointer("/shieldedInstanceConfig/enableIntegrityMonitoring").and_then(|v| v.as_bool()).unwrap_or(false),
        }],
    });

    // An instance with no service account attached has no `serviceAccounts` at
    // all, and the rules read `service_account.0.email` — leaving the field out
    // answers "no default service account here", which is true.
    if let Some(accounts) = i.get("serviceAccounts").and_then(|s| s.as_array()) {
        out["service_account"] = Value::Array(
            accounts
                .iter()
                .map(|sa| {
                    json!({
                        "email": sa.get("email"),
                        // An empty repeated field is omitted rather than sent
                        // as []; no scopes granted is what that means.
                        "scopes": sa.get("scopes").cloned().unwrap_or_else(|| json!([])),
                    })
                })
                .collect(),
        );
    }

    if let Some(nics) = i.get("networkInterfaces").and_then(|n| n.as_array()) {
        out["network_interface"] = Value::Array(
            nics.iter()
                .map(|nic| {
                    let mut out = json!({
                        "network": nic.get("network"),
                        "subnetwork": nic.get("subnetwork"),
                        "network_ip": nic.get("networkIP"),
                    });
                    // CIS 4.11 reads `network_interface.0.access_config EQUAL ""`,
                    // i.e. it treats the block's absence as "no public IP" —
                    // Terraform only emits the block for an interface that has
                    // an external address. An empty array here would read as a
                    // public IP the instance does not have, so the key is left
                    // out entirely when GCP sends no accessConfigs.
                    if let Some(configs) = nic.get("accessConfigs").and_then(|a| a.as_array()) {
                        if !configs.is_empty() {
                            out["access_config"] = Value::Array(
                                configs
                                    .iter()
                                    .map(|c| {
                                        json!({
                                            "nat_ip": c.get("natIP"),
                                            "network_tier": c.get("networkTier"),
                                        })
                                    })
                                    .collect(),
                            );
                        }
                    }
                    out
                })
                .collect(),
        );
    }

    out
}

/// Map a persistent disk to the object the rules describe.
///
/// Terraform's `disk_encryption_key.0.kms_key_self_link` is the API's
/// `diskEncryptionKey.kmsKeyName`, which really is a self link. A disk left on
/// Google-managed keys carries no `diskEncryptionKey` whatsoever (observed on
/// all five disks of the test project), and CIS 4.7 reads that absence as the
/// violation it is — nothing is filled in to soften it.
fn normalize_disk(d: &Value) -> Value {
    let mut out = json!({
        "name": d.get("name"),
        "zone": short_name(d.get("zone")),
        "region": short_name(d.get("region")),
        "type": short_name(d.get("type")),
        "size_gb": d.get("sizeGb"),
        "status": d.get("status"),
    });
    if let Some(key) = d.pointer("/diskEncryptionKey/kmsKeyName") {
        out["disk_encryption_key"] = json!([{ "kms_key_self_link": key }]);
    }
    // A customer-supplied key (CIS 4.7) leaves only its hash on the disk.
    out["csek"] = json!(d.pointer("/diskEncryptionKey/sha256").is_some());
    out
}

/// Map a subnetwork to the object the rules describe.
///
/// Turning flow logs off does not clear `logConfig`: a subnet that once had
/// them keeps `aggregationInterval` and `flowSampling` beside `enable: false`
/// (seen on a live subnet right after a disable). Terraform only carries a
/// `log_config` block while logging is on, and CIS 3.8 tests the block's
/// presence, so it is emitted only when `enable` is true — passing the stale
/// block through would answer "this subnet logs" for one that stopped.
fn normalize_subnetwork(s: &Value) -> Value {
    let mut out = json!({
        "name": s.get("name"),
        "region": short_name(s.get("region")),
        "network": s.get("network"),
        "ip_cidr_range": s.get("ipCidrRange"),
        "purpose": s.get("purpose"),
        "private_ip_google_access": s.get("privateIpGoogleAccess").and_then(|v| v.as_bool()).unwrap_or(false),
    });

    if s.pointer("/logConfig/enable").and_then(|v| v.as_bool()).unwrap_or(false) {
        let mut log_config = serde_json::Map::new();
        // GCP fills the interval in itself once logging is on (INTERVAL_5_SEC
        // by default, confirmed on a subnet enabled for the occasion), but an
        // interval it did not send is not one to invent.
        for (api, tf) in [
            ("aggregationInterval", "aggregation_interval"),
            ("flowSampling", "flow_sampling"),
            ("metadata", "metadata"),
        ] {
            if let Some(v) = s.pointer(&format!("/logConfig/{}", api)) {
                log_config.insert(tf.to_string(), v.clone());
            }
        }
        out["log_config"] = Value::Array(vec![Value::Object(log_config)]);
    }

    out
}

/// Map an SSL policy to the object the rules describe.
///
/// `minTlsVersion` is not optional: the API rejects a policy created without
/// it ("SslPolicy minimum TLS version needs to be specified"), so it is always
/// on the wire and never has to be defaulted.
fn normalize_ssl_policy(p: &Value) -> Value {
    json!({
        "name": p.get("name"),
        "profile": p.get("profile"),
        "min_tls_version": p.get("minTlsVersion"),
        "region": short_name(p.get("region")),
    })
}

/// Protocols that carry port numbers. A firewall entry naming one of these
/// without a `ports` list opens every port of it; ICMP, ESP and the rest have
/// no ports to open. `all` covers every protocol, TCP included.
fn protocol_has_ports(protocol: &str) -> bool {
    matches!(protocol, "tcp" | "udp" | "sctp" | "all" | "6" | "17" | "132")
}

/// Every port a firewall rule lets through, one JSON string per port.
///
/// `allowed_ports` has no counterpart in the Terraform schema — there the
/// ports stay as GCP writes them in `allow.0.ports`: a mix of single ports
/// ("3389") and ranges ("0-65535"). The engine's INCLUDE on an array is an
/// exact element match, so a range token can never answer "is 3389 reachable";
/// the range has to be enumerated, or the most dangerous rule of all — the one
/// that opens everything to the internet — would be the one CIS 3.7 never
/// matches. Ports are deduplicated across the rule's `allowed` entries, which
/// bounds the answer at the 65536 ports that exist.
/// Enumerating every port a firewall rule opens is the only way the engine can
/// answer "is 3389 reachable": `INCLUDE` on an array is exact element equality,
/// so a `"0-65535"` token never matches `"3389"`.
///
/// Enumerating a full range verbatim costs 65 536 strings per rule — measured
/// at 1.5 MB of JSON for the six rules of a default VPC, copied again into
/// every violation, webhook payload and saved record. A range that covers the
/// whole usable space is therefore reported as `allows_all_ports` instead, and
/// the rules ask that question separately. Anything narrower is enumerated, up
/// to a cap that is announced rather than silent.
const MAX_ENUMERATED_PORTS: usize = 8192;

struct AllowedPorts {
    ports: Vec<Value>,
    all: bool,
    truncated: bool,
}

fn expand_allowed_ports(allowed: &[Value]) -> AllowedPorts {
    let mut ports: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    let mut all = false;

    for entry in allowed {
        let protocol = entry
            .get("IPProtocol")
            .and_then(|p| p.as_str())
            .unwrap_or_default()
            .to_lowercase();
        match entry.get("ports").and_then(|p| p.as_array()) {
            Some(tokens) => {
                for token in tokens.iter().filter_map(|t| t.as_str()) {
                    match token.split_once('-') {
                        Some((low, high)) => {
                            if let (Ok(low), Ok(high)) =
                                (low.trim().parse::<u32>(), high.trim().parse::<u32>())
                            {
                                let high = high.min(65535);
                                // Port 0 is not assignable, so a range reaching
                                // from 0 or 1 to the top opens everything.
                                if low <= 1 && high >= 65535 {
                                    all = true;
                                } else {
                                    ports.extend(low..=high);
                                }
                            }
                        }
                        None => {
                            if let Ok(port) = token.trim().parse::<u32>() {
                                ports.insert(port);
                            }
                        }
                    }
                }
            }
            // A port-bearing protocol cited without `ports` means every port.
            None if protocol_has_ports(&protocol) => all = true,
            None => {}
        }
    }

    let truncated = ports.len() > MAX_ENUMERATED_PORTS;
    AllowedPorts {
        ports: ports
            .into_iter()
            .take(MAX_ENUMERATED_PORTS)
            .map(|p| Value::String(p.to_string()))
            .collect(),
        all,
        truncated,
    }
}

/// Map a VPC firewall rule to the object the rules describe.
fn normalize_firewall(f: &Value) -> Value {
    let allowed: Vec<Value> = f
        .get("allowed")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let expanded = expand_allowed_ports(&allowed);
    json!({
        "name": f.get("name"),
        "network": f.get("network"),
        "direction": f.get("direction"),
        "priority": f.get("priority"),
        "disabled": f.get("disabled").and_then(|v| v.as_bool()).unwrap_or(false),
        // An empty repeated field is omitted on the wire, and an EGRESS rule
        // ships destination ranges instead — in both cases no source is open.
        "source_ranges": f.get("sourceRanges").cloned().unwrap_or_else(|| json!([])),
        "destination_ranges": f.get("destinationRanges").cloned().unwrap_or_else(|| json!([])),
        "target_tags": f.get("targetTags").cloned().unwrap_or_else(|| json!([])),
        "allow": allowed.iter().map(|a| json!({
            "protocol": a.get("IPProtocol"),
            "ports": a.get("ports").cloned().unwrap_or_else(|| json!([])),
        })).collect::<Vec<_>>(),
        "allowed_ports": expanded.ports,
        "allows_all_ports": expanded.all,
        "allowed_ports_truncated": expanded.truncated,
    })
}

/// Map a log sink to the object the rules describe.
///
/// A sink created without a filter exports everything and carries no `filter`
/// at all; CIS 2.2 reads that absence as the finding. The two sinks Google
/// creates itself (`_Required`, `_Default`) both come with one.
fn normalize_log_sink(s: &Value) -> Value {
    let mut out = json!({
        "name": s.get("name"),
        "writer_identity": s.get("writerIdentity"),
        "disabled": s.get("disabled").and_then(|v| v.as_bool()).unwrap_or(false),
    });
    if let Some(destination) = s.get("destination") {
        out["destination"] = destination.clone();
        let d = destination.as_str().unwrap_or("");
        out["destination_kind"] = json!(d.split('.').next().unwrap_or(""));
    }
    if let Some(filter) = s.get("filter") {
        out["filter"] = filter.clone();
    }
    out
}

/// Map a BigQuery dataset (the `datasets.get` answer) to the object the rules
/// describe.
///
/// The ACL keeps the order BigQuery returns it in. CIS 7.1 as written only
/// looks at `access.0`, and reordering the entries to put a public grant where
/// the rule happens to look would be answering for the rule rather than
/// reporting what the API said.
fn normalize_dataset(d: &Value) -> Value {
    const ACCESS_FIELDS: &[(&str, &str)] = &[
        ("specialGroup", "special_group"),
        ("userByEmail", "user_by_email"),
        ("groupByEmail", "group_by_email"),
        ("iamMember", "iam_member"),
        ("domain", "domain"),
        ("role", "role"),
    ];

    let access: Vec<Value> = d
        .get("access")
        .and_then(|a| a.as_array())
        .map(|entries| {
            entries
                .iter()
                .map(|entry| {
                    let mut out = serde_json::Map::new();
                    for (api, tf) in ACCESS_FIELDS {
                        // An ACL entry names exactly one grantee kind; the
                        // others are absent, and absent is what "this is not a
                        // special group" looks like.
                        if let Some(v) = entry.get(api) {
                            out.insert(tf.to_string(), v.clone());
                        }
                    }
                    Value::Object(out)
                })
                .collect()
        })
        .unwrap_or_default();

    let mut out = json!({
        "name": d.pointer("/datasetReference/datasetId"),
        "dataset_id": d.pointer("/datasetReference/datasetId"),
        "project": d.pointer("/datasetReference/projectId"),
        "location": d.get("location"),
        "access": access,
    });

    // CMEK is opt-in and the block is absent without it, which is the finding
    // CIS 7.2 wants. `kms_key_name` is the API's `kmsKeyName` under
    // `defaultEncryptionConfiguration` (BigQuery's own discovery document; no
    // CMEK dataset could be created here to see it on the wire, since that
    // needs a KMS key and Cloud KMS is off on every reachable project).
    if let Some(key) = d.pointer("/defaultEncryptionConfiguration/kmsKeyName") {
        out["default_encryption_configuration"] = json!([{ "kms_key_name": key }]);
    }

    out
}

#[cfg(test)]
mod normalize_tests {
    use super::*;

    /// Payload shapes taken from a live project rather than from docs.
    #[test]
    fn normalizes_a_bucket() {
        let b = json!({
            "name": "rtk-cloud-backups-prd",
            "location": "EU",
            "storageClass": "STANDARD",
            "iamConfiguration": {
                "uniformBucketLevelAccess": { "enabled": true },
                "publicAccessPrevention": "enforced"
            }
        });
        let out = normalize_bucket(&b);
        assert_eq!(out["uniform_bucket_level_access"], json!(true));
        assert_eq!(out["public_access_prevention"], json!("enforced"));
        // No `versioning` block at all: GCS omits it when never enabled.
        assert_eq!(out["versioning_enabled"], json!(false));
    }

    #[test]
    fn a_bucket_without_public_access_prevention_does_not_get_an_invented_one() {
        let out = normalize_bucket(&json!({ "name": "b", "iamConfiguration": {} }));
        assert!(out.get("public_access_prevention").is_none());
    }

    /// The rules were written against Terraform's schema, which represents a
    /// nested block as a one-element list — hence `network_policy.0.enabled`.
    #[test]
    fn wraps_cluster_blocks_the_way_the_rules_index_them() {
        let c = json!({
            "name": "rtk-bench",
            "location": "europe-west9-a",
            "status": "RUNNING",
            "loggingService": "logging.googleapis.com/kubernetes",
            "monitoringService": "monitoring.googleapis.com/kubernetes",
            "legacyAbac": {},
            "networkPolicy": null,
            "privateClusterConfig": { "publicEndpoint": "34.155.119.190" },
            "masterAuthorizedNetworksConfig": {}
        });
        let out = normalize_cluster(&c);
        assert_eq!(out["network_policy"][0]["enabled"], json!(false));
        assert_eq!(out["private_cluster_config"][0]["enable_private_nodes"], json!(false));
        assert_eq!(out["master_authorized_networks_config"][0]["cidr_blocks"], json!([]));
        assert_eq!(out["enable_legacy_abac"], json!(false));
        assert_eq!(out["logging_service"], json!("logging.googleapis.com/kubernetes"));
    }

    /// Auto-upgrade is per node pool but the rule asks the cluster, so it only
    /// holds when every pool has it.
    #[test]
    fn node_auto_upgrade_holds_only_when_every_pool_has_it() {
        let with = |pools: Value| {
            let c = json!({ "name": "c", "nodePools": pools });
            normalize_cluster(&c)["node_config"][0]["management"][0]["auto_upgrade"].clone()
        };
        assert_eq!(with(json!([{ "management": { "autoUpgrade": true } }])), json!(true));
        assert_eq!(
            with(json!([
                { "management": { "autoUpgrade": true } },
                { "management": { "autoUpgrade": false } }
            ])),
            json!(false)
        );
        // A pool that does not say: GCP omits false booleans on the wire.
        assert_eq!(with(json!([{ "management": {} }])), json!(false));
    }

    #[test]
    fn a_cluster_without_node_pools_says_nothing_about_auto_upgrade() {
        let out = normalize_cluster(&json!({ "name": "c" }));
        assert!(out.get("node_config").is_none());
    }

    /// The GKE node of the test project, as `aggregated/instances` returned it
    /// (metadata trimmed to the keys that survive normalization plus one that
    /// must not).
    fn live_instance() -> Value {
        json!({
            "kind": "compute#instance",
            "name": "gke-rtk-bench-default-pool-fe776aea-vhbv",
            "machineType": "https://www.googleapis.com/compute/v1/projects/rtk-ai-labs-01/zones/europe-west9-a/machineTypes/e2-standard-4",
            "status": "RUNNING",
            "zone": "https://www.googleapis.com/compute/v1/projects/rtk-ai-labs-01/zones/europe-west9-a",
            "deletionProtection": false,
            "networkInterfaces": [{
                "network": "https://www.googleapis.com/compute/v1/projects/rtk-ai-labs-01/global/networks/default",
                "subnetwork": "https://www.googleapis.com/compute/v1/projects/rtk-ai-labs-01/regions/europe-west9/subnetworks/default",
                "networkIP": "10.200.0.10",
                "name": "nic0",
                "accessConfigs": [{
                    "kind": "compute#accessConfig",
                    "type": "ONE_TO_ONE_NAT",
                    "name": "external-nat",
                    "natIP": "34.155.221.100",
                    "networkTier": "PREMIUM"
                }]
            }],
            "metadata": {
                "kind": "compute#metadata",
                "fingerprint": "TXngDqPmoSk=",
                "items": [
                    { "key": "serial-port-logging-enable", "value": "true" },
                    { "key": "disable-legacy-endpoints", "value": "true" },
                    { "key": "kube-env", "value": "KUBE_PROXY_TOKEN: dGhpcyBpcyBhIHRva2Vu\nTPM_BOOTSTRAP_KEY: c2VjcmV0" }
                ]
            },
            "serviceAccounts": [{
                "email": "587907362788-compute@developer.gserviceaccount.com",
                "scopes": [
                    "https://www.googleapis.com/auth/devstorage.read_only",
                    "https://www.googleapis.com/auth/logging.write"
                ]
            }],
            "shieldedInstanceConfig": {
                "enableSecureBoot": false,
                "enableVtpm": true,
                "enableIntegrityMonitoring": true
            }
        })
    }

    #[test]
    fn normalizes_a_live_instance() {
        let out = normalize_instance(&live_instance());
        assert_eq!(out["name"], json!("gke-rtk-bench-default-pool-fe776aea-vhbv"));
        assert_eq!(out["zone"], json!("europe-west9-a"));
        assert_eq!(out["machine_type"], json!("e2-standard-4"));
        // The instance carries no `canIpForward` at all: proto3 drops the false.
        assert_eq!(out["can_ip_forward"], json!(false));
        assert_eq!(out["shielded_instance_config"][0]["enable_vtpm"], json!(true));
        assert_eq!(
            out["service_account"][0]["email"],
            json!("587907362788-compute@developer.gserviceaccount.com")
        );
        assert_eq!(
            out["service_account"][0]["scopes"][0],
            json!("https://www.googleapis.com/auth/devstorage.read_only")
        );
        assert_eq!(out["network_interface"][0]["access_config"][0]["nat_ip"], json!("34.155.221.100"));
    }

    /// CIS 4.3 and 4.4 read metadata keys this node never sets, and reading
    /// them as empty is the finding. What must not happen is the node's
    /// credential-bearing metadata riding along into the scan result.
    #[test]
    fn instance_metadata_keeps_the_security_flags_and_drops_the_secrets() {
        let out = normalize_instance(&live_instance());
        assert_eq!(out["metadata"]["serial-port-logging-enable"], json!("true"));
        assert_eq!(out["metadata"]["disable-legacy-endpoints"], json!("true"));
        assert!(out["metadata"].get("kube-env").is_none());
        assert!(out["metadata"].get("enable-oslogin").is_none());
        assert!(out["metadata"].get("block-project-ssh-keys").is_none());
    }

    /// CIS 4.11 reads `network_interface.0.access_config EQUAL ""`, so an
    /// instance with no external address must leave the key out — an empty
    /// array would read as a public IP it does not have.
    #[test]
    fn an_instance_without_an_external_address_has_no_access_config() {
        let mut instance = live_instance();
        instance["networkInterfaces"][0]
            .as_object_mut()
            .expect("nic is an object")
            .remove("accessConfigs");
        let out = normalize_instance(&instance);
        assert!(out["network_interface"][0].get("access_config").is_none());
    }

    /// A disk of the test project, all five of which came back without any
    /// `diskEncryptionKey`: Google-managed keys, which is what CIS 4.7 flags.
    #[test]
    fn a_google_managed_disk_says_nothing_about_a_kms_key() {
        let disk = json!({
            "kind": "compute#disk",
            "name": "pvc-41be48d0-5117-49bd-a5be-000a387599f0",
            "sizeGb": "8",
            "zone": "https://www.googleapis.com/compute/v1/projects/rtk-ai-labs-01/zones/europe-west1-b",
            "status": "READY",
            "type": "https://www.googleapis.com/compute/v1/projects/rtk-ai-labs-01/zones/europe-west1-b/diskTypes/pd-balanced",
            "enableConfidentialCompute": false
        });
        let out = normalize_disk(&disk);
        assert_eq!(out["name"], json!("pvc-41be48d0-5117-49bd-a5be-000a387599f0"));
        assert_eq!(out["zone"], json!("europe-west1-b"));
        assert_eq!(out["type"], json!("pd-balanced"));
        assert!(out.get("disk_encryption_key").is_none());
    }

    /// `kms_key_self_link` is Terraform's name for the API's `kmsKeyName`
    /// (Compute's discovery document, schema `CustomerEncryptionKey`), and the
    /// rule indexes it as a one-element list.
    #[test]
    fn a_cmek_disk_exposes_its_key_as_a_one_element_list() {
        let disk = json!({
            "name": "d",
            "diskEncryptionKey": {
                "kmsKeyName": "projects/rtk-ai-labs-01/locations/europe-west9/keyRings/r/cryptoKeys/k"
            }
        });
        let out = normalize_disk(&disk);
        assert_eq!(
            out["disk_encryption_key"][0]["kms_key_self_link"],
            json!("projects/rtk-ai-labs-01/locations/europe-west9/keyRings/r/cryptoKeys/k")
        );
    }

    /// A subnet that never had flow logs: no `logConfig` on the wire at all.
    #[test]
    fn a_subnet_without_flow_logs_has_no_log_config_block() {
        let subnet = json!({
            "kind": "compute#subnetwork",
            "name": "default",
            "network": "https://www.googleapis.com/compute/v1/projects/rtk-ai-labs-01/global/networks/default",
            "ipCidrRange": "10.128.0.0/20",
            "region": "https://www.googleapis.com/compute/v1/projects/rtk-ai-labs-01/regions/us-central1",
            "privateIpGoogleAccess": false,
            "purpose": "PRIVATE"
        });
        let out = normalize_subnetwork(&subnet);
        assert_eq!(out["region"], json!("us-central1"));
        assert_eq!(out["private_ip_google_access"], json!(false));
        assert!(out.get("log_config").is_none());
    }

    #[test]
    fn a_subnet_with_flow_logs_on_carries_its_aggregation_interval() {
        let subnet = json!({
            "name": "default",
            "region": "https://www.googleapis.com/compute/v1/projects/rtk-ai-labs-01/regions/africa-south1",
            "ipCidrRange": "10.218.0.0/20",
            "privateIpGoogleAccess": false,
            "enableFlowLogs": true,
            "logConfig": {
                "enable": true,
                "aggregationInterval": "INTERVAL_5_SEC",
                "flowSampling": 0.5,
                "metadata": "EXCLUDE_ALL_METADATA"
            }
        });
        let out = normalize_subnetwork(&subnet);
        assert_eq!(out["log_config"][0]["aggregation_interval"], json!("INTERVAL_5_SEC"));
        assert_eq!(out["log_config"][0]["metadata"], json!("EXCLUDE_ALL_METADATA"));
    }

    /// The same subnet read back right after flow logs were switched off:
    /// `logConfig` stays, interval and sampling included, with `enable: false`.
    /// Passing that block through would tell CIS 3.8 the subnet is logging.
    #[test]
    fn a_subnet_that_stopped_logging_drops_the_stale_log_config() {
        let subnet = json!({
            "name": "default",
            "region": "https://www.googleapis.com/compute/v1/projects/rtk-ai-labs-01/regions/africa-south1",
            "enableFlowLogs": false,
            "logConfig": {
                "enable": false,
                "aggregationInterval": "INTERVAL_5_SEC",
                "flowSampling": 0.5,
                "metadata": "EXCLUDE_ALL_METADATA"
            }
        });
        assert!(normalize_subnetwork(&subnet).get("log_config").is_none());
    }

    /// The policy created on the test project for the occasion, as
    /// `aggregated/sslPolicies` returned it.
    #[test]
    fn normalizes_an_ssl_policy() {
        let policy = json!({
            "kind": "compute#sslPolicy",
            "selfLink": "https://www.googleapis.com/compute/v1/projects/rtk-ai-labs-01/global/sslPolicies/kxn-probe-tmp",
            "name": "kxn-probe-tmp",
            "profile": "COMPATIBLE",
            "minTlsVersion": "TLS_1_0",
            "fingerprint": "UCiJtMU0f-Q="
        });
        let out = normalize_ssl_policy(&policy);
        assert_eq!(out["min_tls_version"], json!("TLS_1_0"));
        assert_eq!(out["profile"], json!("COMPATIBLE"));
    }

    /// `default-allow-rdp` of the test project's default VPC — the rule CIS 3.7
    /// exists for.
    #[test]
    fn a_firewall_opening_rdp_to_the_internet_names_the_port() {
        let firewall = json!({
            "kind": "compute#firewall",
            "name": "default-allow-rdp",
            "network": "https://www.googleapis.com/compute/v1/projects/rtk-ai-labs-01/global/networks/default",
            "priority": 65534,
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [{ "IPProtocol": "tcp", "ports": ["3389"] }],
            "direction": "INGRESS",
            "logConfig": { "enable": false },
            "disabled": false
        });
        let out = normalize_firewall(&firewall);
        assert_eq!(out["source_ranges"], json!(["0.0.0.0/0"]));
        assert_eq!(out["allowed_ports"], json!(["3389"]));
        assert_eq!(out["allow"][0]["protocol"], json!("tcp"));
    }

    /// `default-allow-internal`: a range token can only answer the rule once
    /// enumerated.
    #[test]
    fn a_port_range_is_enumerated() {
        let firewall = json!({
            "name": "default-allow-internal",
            "sourceRanges": ["10.128.0.0/9"],
            "allowed": [
                { "IPProtocol": "tcp", "ports": ["0-65535"] },
                { "IPProtocol": "udp", "ports": ["0-65535"] },
                { "IPProtocol": "icmp" }
            ],
            "direction": "INGRESS",
            "disabled": false
        });
        let out = normalize_firewall(&firewall);
        // A range spanning the whole space is a flag, not 65 536 strings: the
        // rules ask `allows_all_ports` rather than looking for one port in a
        // list that would weigh a quarter of a megabyte on its own.
        assert_eq!(out["allows_all_ports"], json!(true));
        assert_eq!(out["allowed_ports"], json!([]));
        assert_eq!(out["allowed_ports_truncated"], json!(false));
    }

    /// A range that is wide but does not reach the top is still enumerated —
    /// only a rule that opens everything gets the shorthand.
    #[test]
    fn a_narrow_range_is_still_enumerated() {
        let out = normalize_firewall(&json!({
            "name": "web",
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [{ "IPProtocol": "tcp", "ports": ["3380-3390"] }]
        }));
        assert_eq!(out["allows_all_ports"], json!(false));
        let ports = out["allowed_ports"].as_array().expect("ports are a list");
        assert_eq!(ports.len(), 11);
        assert!(ports.contains(&json!("3389")));
    }

    /// Past the cap the list is cut, and says so rather than pretending to be
    /// complete.
    #[test]
    fn an_oversized_enumeration_announces_its_truncation() {
        let out = normalize_firewall(&json!({
            "name": "wide",
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [{ "IPProtocol": "tcp", "ports": ["2-60000"] }]
        }));
        assert_eq!(out["allows_all_ports"], json!(false));
        assert_eq!(
            out["allowed_ports"].as_array().map(|p| p.len()),
            Some(MAX_ENUMERATED_PORTS)
        );
        assert_eq!(out["allowed_ports_truncated"], json!(true));
    }

    /// `gke-rtk-bench-d4b9d8bd-all`: TCP named with no ports, which the API's
    /// own documentation defines as every port — while ICMP and ESP have none.
    #[test]
    fn a_protocol_without_ports_means_every_port_for_tcp_and_none_for_icmp() {
        let tcp = normalize_firewall(&json!({
            "name": "gke-rtk-bench-d4b9d8bd-all",
            "sourceRanges": ["10.108.0.0/14"],
            "allowed": [{ "IPProtocol": "esp" }, { "IPProtocol": "tcp" }, { "IPProtocol": "icmp" }]
        }));
        assert_eq!(tcp["allows_all_ports"], json!(true));
        assert_eq!(tcp["allowed_ports"], json!([]));

        let icmp = normalize_firewall(&json!({
            "name": "default-allow-icmp",
            "sourceRanges": ["0.0.0.0/0"],
            "allowed": [{ "IPProtocol": "icmp" }]
        }));
        assert_eq!(icmp["allowed_ports"], json!([]));
        assert_eq!(icmp["allows_all_ports"], json!(false));
    }

    /// An EGRESS rule has no `sourceRanges` at all; the empty list is what the
    /// wire means, not a guess.
    #[test]
    fn a_firewall_without_source_ranges_answers_an_empty_list() {
        let out = normalize_firewall(&json!({ "name": "e", "direction": "EGRESS", "destinationRanges": ["0.0.0.0/0"] }));
        assert_eq!(out["source_ranges"], json!([]));
        assert_eq!(out["destination_ranges"], json!(["0.0.0.0/0"]));
    }

    /// `_Required`, one of the two sinks Google creates in every project.
    #[test]
    fn normalizes_a_log_sink() {
        let sink = json!({
            "name": "_Required",
            "destination": "logging.googleapis.com/projects/rtk-ai-labs-01/locations/global/buckets/_Required",
            "filter": "LOG_ID(\"cloudaudit.googleapis.com/activity\")",
            "resourceName": "projects/rtk-ai-labs-01/sinks/_Required"
        });
        let out = normalize_log_sink(&sink);
        assert_eq!(out["name"], json!("_Required"));
        assert_eq!(
            out["destination"],
            json!("logging.googleapis.com/projects/rtk-ai-labs-01/locations/global/buckets/_Required")
        );
        assert!(out["filter"].as_str().is_some_and(|f| f.contains("cloudaudit")));
        assert_eq!(out["disabled"], json!(false));
    }

    /// A sink exporting everything carries no `filter`, which is exactly what
    /// CIS 2.2 reports.
    #[test]
    fn a_sink_without_a_filter_does_not_get_an_invented_one() {
        let out = normalize_log_sink(&json!({ "name": "s", "destination": "storage.googleapis.com/b" }));
        assert!(out.get("filter").is_none());
    }

    /// The `datasets.get` answer for a dataset created on the test project —
    /// the listing endpoint carries none of this.
    #[test]
    fn normalizes_a_bigquery_dataset() {
        let dataset = json!({
            "kind": "bigquery#dataset",
            "id": "rtk-ai-labs-01:kxn_probe_tmp",
            "datasetReference": { "datasetId": "kxn_probe_tmp", "projectId": "rtk-ai-labs-01" },
            "access": [
                { "role": "WRITER", "specialGroup": "projectWriters" },
                { "role": "OWNER", "specialGroup": "projectOwners" },
                { "role": "OWNER", "userByEmail": "patrick@rtk-ai.app" },
                { "role": "READER", "specialGroup": "projectReaders" }
            ],
            "location": "EU",
            "type": "DEFAULT"
        });
        let out = normalize_dataset(&dataset);
        assert_eq!(out["name"], json!("kxn_probe_tmp"));
        assert_eq!(out["access"][0]["special_group"], json!("projectWriters"));
        assert_eq!(out["access"][0]["role"], json!("WRITER"));
        // An entry naming a user is not a special group, and says so by
        // carrying no `special_group` rather than an empty one.
        assert_eq!(out["access"][2]["user_by_email"], json!("patrick@rtk-ai.app"));
        assert!(out["access"][2].get("special_group").is_none());
        // No CMEK on this dataset, which is the finding CIS 7.2 is after.
        assert!(out.get("default_encryption_configuration").is_none());
    }

    #[test]
    fn a_cmek_dataset_exposes_its_key_as_a_one_element_list() {
        let dataset = json!({
            "datasetReference": { "datasetId": "d", "projectId": "p" },
            "defaultEncryptionConfiguration": {
                "kmsKeyName": "projects/p/locations/eu/keyRings/r/cryptoKeys/k"
            }
        });
        let out = normalize_dataset(&dataset);
        assert_eq!(
            out["default_encryption_configuration"][0]["kms_key_name"],
            json!("projects/p/locations/eu/keyRings/r/cryptoKeys/k")
        );
    }

    /// Every object served has a collector behind it.
    #[test]
    fn every_declared_resource_type_is_reachable() {
        for object in NATIVE_TYPES {
            assert!(
                matches!(
                    *object,
                    "api_keys"
                        | "logging_metric_alerts"
                        | "project"
                        | "assets"
                        | "kms_crypto_key"
                        | "org_policies"
                        | "project_iam_member"
                        | "secret_versions"
                        | "bigquery_dataset"
                        | "compute_disk"
                        | "compute_firewall"
                        | "compute_instance"
                        | "compute_ssl_policy"
                        | "compute_subnetwork"
                        | "container_cluster"
                        | "logging_project_sink"
                        | "metrics"
                        | "cloud_functions"
                        | "cloud_run_services"
                        | "cloud_sql_instances"
                        | "dns_zones"
                        | "iam_service_accounts"
                        | "networks"
                        | "pubsub_subscriptions"
                        | "pubsub_topics"
                        | "secrets"
                        | "service_account_keys"
                        | "storage_bucket"
                ),
                "{object} is declared but `gather` has no arm for it"
            );
        }
    }
}


/// Organization policy constraints read by `org_policies` — those CIS GCP
/// Foundations names, plus the ones that close its other findings at the root.
const ORG_POLICY_CONSTRAINTS: &[&str] = &[
    "iam.allowedPolicyMemberDomains",
    "iam.disableServiceAccountKeyCreation",
    "iam.automaticIamGrantsForDefaultServiceAccounts",
    "compute.skipDefaultNetworkCreation",
    "compute.requireOsLogin",
    "compute.disableSerialPortAccess",
    "compute.vmExternalIpAccess",
    "compute.requireShieldedVm",
    "sql.restrictPublicIp",
    "storage.uniformBucketLevelAccess",
    "storage.publicAccessPrevention",
];

/// A 403 that only says the API was never enabled on the project.
fn is_service_disabled(e: &ProviderError) -> bool {
    let msg = e.to_string();
    msg.contains("SERVICE_DISABLED") || msg.contains("accessNotConfigured")
}

fn age_days(ts: Option<&str>, now: &DateTime<Utc>) -> Option<i64> {
    ts.and_then(|t| t.parse::<DateTime<Utc>>().ok()).map(|t| (*now - t).num_days())
}

/// "7776000s" → 90.
fn duration_days(d: Option<&str>) -> Option<f64> {
    d.and_then(|d| d.strip_suffix('s'))
        .and_then(|s| s.parse::<f64>().ok())
        .map(|secs| (secs / 86_400.0 * 100.0).round() / 100.0)
}

/// One row per (role, member). `member_roles` is every role the same member
/// holds on the project, so separation-of-duties controls (CIS 1.8, 1.11) can
/// ask "does whoever holds this role also hold that one?" from a single row.
fn iam_members(policy: &Value) -> Vec<Value> {
    let bindings: Vec<&Value> = policy["bindings"].as_array().into_iter().flatten().collect();
    let mut roles_of: std::collections::HashMap<&str, Vec<&str>> = Default::default();
    for b in &bindings {
        let role = b["role"].as_str().unwrap_or("");
        for m in b["members"].as_array().into_iter().flatten() {
            let roles = roles_of.entry(m.as_str().unwrap_or("")).or_default();
            if !roles.contains(&role) {
                roles.push(role);
            }
        }
    }
    let mut out = Vec::new();
    for b in &bindings {
        for m in b["members"].as_array().into_iter().flatten() {
            let member = m.as_str().unwrap_or("");
            let (kind, id) = member.split_once(':').unwrap_or((member, ""));
            out.push(json!({
                "role": b["role"],
                "member": member,
                "member_type": kind,
                "member_id": id,
                "member_roles": roles_of.get(member).cloned().unwrap_or_default(),
                "condition": b["condition"]["title"],
            }));
        }
    }
    out
}

/// The `allServices` audit configuration of an IAM policy: its log types and
/// exempted members. A policy without one has no data-access logging.
fn all_services_audit(policy: &Value) -> (Vec<String>, Vec<String>) {
    let mut types = Vec::new();
    let mut exempted = Vec::new();
    for c in policy["auditConfigs"].as_array().into_iter().flatten() {
        if c["service"].as_str() != Some("allServices") {
            continue;
        }
        for l in c["auditLogConfigs"].as_array().into_iter().flatten() {
            if let Some(t) = l["logType"].as_str() {
                types.push(t.to_string());
            }
            for m in l["exemptedMembers"].as_array().into_iter().flatten() {
                if let Some(m) = m.as_str() {
                    exempted.push(m.to_string());
                }
            }
        }
    }
    (types, exempted)
}

/// Notification categories CIS 1.16 wants a contact for. `ALL` covers them.
const ESSENTIAL_CONTACT_CATEGORIES: &[&str] =
    &["LEGAL", "SECURITY", "SUSPENSION", "TECHNICAL", "TECHNICAL_INCIDENTS"];

/// CIS 2.4–2.11: the log filter each control prescribes, reduced to the
/// tokens that identify it. A metric matches when its filter — lower-cased,
/// whitespace removed — contains every token, so the parenthesization and
/// operator spacing of the benchmark text need not be copied byte for byte.
const METRIC_ALERT_CONTROLS: &[(&str, &str, &[&str])] = &[
    ("2.4", "project_ownership", &["cloudresourcemanager.googleapis.com", "projectownership", "projectownerinvitee", "roles/owner"]),
    ("2.5", "audit_configuration", &["setiampolicy", "auditconfigdeltas"]),
    ("2.6", "custom_role", &["iam_role", "google.iam.admin.v1.createrole", "google.iam.admin.v1.deleterole", "google.iam.admin.v1.updaterole"]),
    ("2.7", "vpc_firewall", &["gce_firewall_rule", "compute.firewalls.patch", "compute.firewalls.insert", "compute.firewalls.delete"]),
    ("2.8", "vpc_route", &["gce_route", "compute.routes.delete", "compute.routes.insert"]),
    ("2.9", "vpc_network", &["gce_network", "compute.networks.insert", "compute.networks.patch", "compute.networks.delete", "compute.networks.removepeering", "compute.networks.addpeering"]),
    ("2.10", "storage_iam", &["gcs_bucket", "storage.setiampermissions"]),
    ("2.11", "sql_configuration", &["cloudsql.instances.update"]),
];

fn metric_alert_rows(metrics: &[Value], policies: &[Value]) -> Vec<Value> {
    let squash = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase();
    let alerted = |metric: &str| {
        let needle = format!("logging.googleapis.com/user/{metric}");
        policies.iter().any(|p| {
            p["enabled"].as_bool().unwrap_or(true) && p["conditions"].to_string().contains(&needle)
        })
    };
    METRIC_ALERT_CONTROLS
        .iter()
        .map(|(control, category, tokens)| {
            let matching: Vec<&str> = metrics
                .iter()
                .filter(|m| {
                    let f = squash(m["filter"].as_str().unwrap_or(""));
                    tokens.iter().all(|t| f.contains(t))
                })
                .filter_map(|m| m["name"].as_str())
                .collect();
            let with_alert = matching.iter().find(|m| alerted(m));
            json!({
                "name": category,
                "control": control,
                "metric": with_alert.or(matching.first()).copied().unwrap_or(""),
                "metric_exists": !matching.is_empty(),
                "alert_enabled": with_alert.is_some(),
            })
        })
        .collect()
}

/// Environment variable names that look like they hold a credential.
fn secret_like_names(env: &Value) -> Vec<String> {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)(secret|passw(or)?d|passwd|token|api_?key|private_?key|credential)").unwrap()
    });
    env.as_object()
        .map(|m| m.keys().filter(|k| RE.is_match(k)).cloned().collect())
        .unwrap_or_default()
}

/// Cloud Functions with the names of their credential-looking environment
/// variables (CIS 1.17): runtime and build variables alike.
fn normalize_function(f: &Value) -> Value {
    let mut row = f.clone();
    let mut names = secret_like_names(&f["serviceConfig"]["environmentVariables"]);
    names.extend(secret_like_names(&f["buildConfig"]["environmentVariables"]));
    // 1st gen functions keep them at the top level.
    names.extend(secret_like_names(&f["environmentVariables"]));
    row["secret_like_env_vars"] = json!(names);
    row
}

/// A VPC network with what CIS 2.12 and 3.2 ask: whether a DNS policy logs
/// its queries, and whether it is a legacy (subnet-less) network.
fn normalize_network(n: &Value, dns_policies: &[Value]) -> Value {
    let mut row = n.clone();
    let name = n["name"].as_str().unwrap_or("");
    let suffix = format!("/global/networks/{name}");
    row["dns_logging"] = json!(dns_policies.iter().any(|p| {
        p["enableLogging"].as_bool().unwrap_or(false)
            && p["networks"].as_array().into_iter().flatten().any(|net| {
                net["networkUrl"].as_str().is_some_and(|u| u.ends_with(&suffix))
            })
    }));
    row["legacy"] = json!(n.get("IPv4Range").is_some());
    row
}

fn normalize_sql_instance(i: &Value) -> Value {
    let ip = &i["settings"]["ipConfiguration"];
    let ssl_mode = ip["sslMode"].as_str().unwrap_or("");
    let mut row = i.clone();
    row["ssl_enforced"] = json!(
        ip["requireSsl"].as_bool() == Some(true)
            || matches!(ssl_mode, "ENCRYPTED_ONLY" | "TRUSTED_CLIENT_CERTIFICATE_REQUIRED")
    );
    row["public_ip"] = json!(ip["ipv4Enabled"].as_bool().unwrap_or(false));
    row["authorized_networks"] = json!(ip["authorizedNetworks"]
        .as_array()
        .map(|a| a.iter().filter_map(|n| n["value"].as_str()).collect::<Vec<_>>())
        .unwrap_or_default());
    row["backups_enabled"] = json!(i["settings"]["backupConfiguration"]["enabled"].as_bool().unwrap_or(false));
    let version = i["databaseVersion"].as_str().unwrap_or("");
    row["engine"] = json!(if version.starts_with("MYSQL") {
        "mysql"
    } else if version.starts_with("POSTGRES") {
        "postgres"
    } else if version.starts_with("SQLSERVER") {
        "sqlserver"
    } else {
        ""
    });
    // Flags as a map, values lower-cased: `flags.log_connections EQUAL on`.
    // A flag left at its default is absent, and each CIS control says which
    // default is compliant.
    let mut flags = serde_json::Map::new();
    for f in i["settings"]["databaseFlags"].as_array().into_iter().flatten() {
        if let Some(name) = f["name"].as_str() {
            flags.insert(
                name.to_string(),
                json!(f["value"].as_str().unwrap_or("").to_lowercase()),
            );
        }
    }
    row["flags"] = Value::Object(flags);
    row
}

fn normalize_dns_zone(z: &Value) -> Value {
    let mut row = z.clone();
    row["visibility"] = json!(z["visibility"].as_str().unwrap_or("public"));
    row["dnssec_state"] = json!(z["dnssecConfig"]["state"].as_str().unwrap_or("off"));
    row["dnssec_algorithms"] = json!(z["dnssecConfig"]["defaultKeySpecs"]
        .as_array()
        .map(|a| a.iter().filter_map(|k| k["algorithm"].as_str()).collect::<Vec<_>>())
        .unwrap_or_default());
    let algorithms = |kind: &str| -> Vec<&str> {
        z["dnssecConfig"]["defaultKeySpecs"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|k| k["keyType"].as_str() == Some(kind))
            .filter_map(|k| k["algorithm"].as_str())
            .collect()
    };
    row["key_signing_algorithms"] = json!(algorithms("keySigning"));
    row["zone_signing_algorithms"] = json!(algorithms("zoneSigning"));
    row
}

fn normalize_kms_key(k: &Value) -> Value {
    let name = k["name"].as_str().unwrap_or("");
    // projects/P/locations/L/keyRings/R/cryptoKeys/K
    let parts: Vec<&str> = name.split('/').collect();
    json!({
        "name": parts.get(7).copied().unwrap_or(name),
        "key_ring": parts.get(5),
        "location": parts.get(3),
        "id": name,
        "purpose": k["purpose"],
        "rotation_period": k["rotationPeriod"],
        "rotation_period_days": duration_days(k["rotationPeriod"].as_str()),
        "next_rotation_time": k["nextRotationTime"],
        "protection_level": k["versionTemplate"]["protectionLevel"],
        "algorithm": k["versionTemplate"]["algorithm"],
        "primary_state": k["primary"]["state"],
        "create_time": k["createTime"],
    })
}

fn normalize_api_key(k: &Value, now: &DateTime<Utc>) -> Value {
    let r = &k["restrictions"];
    let app = ["browserKeyRestrictions", "serverKeyRestrictions", "androidKeyRestrictions", "iosKeyRestrictions"]
        .iter()
        .any(|f| !r[*f].is_null());
    let apis = r["apiTargets"].as_array().map(|a| !a.is_empty()).unwrap_or(false);
    json!({
        "name": k["displayName"].as_str().filter(|s| !s.is_empty()).or(k["uid"].as_str()),
        "id": k["name"],
        "create_time": k["createTime"],
        "age_days": age_days(k["createTime"].as_str(), now),
        "app_restricted": app,
        "api_restricted": apis,
        "api_targets": r["apiTargets"].as_array().map(|a| a.iter().filter_map(|t| t["service"].as_str()).collect::<Vec<_>>()).unwrap_or_default(),
    })
}

fn normalize_org_policy(constraint: &str, p: &Value) -> Value {
    let rules = p["spec"]["rules"].as_array().cloned().unwrap_or_default();
    let enforced = rules.iter().find_map(|r| r["enforce"].as_bool());
    let allow_all = rules.iter().any(|r| r["allowAll"].as_bool() == Some(true));
    let deny_all = rules.iter().any(|r| r["denyAll"].as_bool() == Some(true));
    let values = |key: &str| -> Vec<Value> {
        rules
            .iter()
            .filter_map(|r| r["values"][key].as_array())
            .flatten()
            .cloned()
            .collect()
    };
    json!({
        "constraint": constraint,
        "enforced": enforced,
        "allow_all": allow_all,
        "deny_all": deny_all,
        "allowed_values": values("allowedValues"),
        "denied_values": values("deniedValues"),
        // Restricted means a list constraint narrowed to some values, or a
        // boolean constraint turned on.
        "restricted": enforced == Some(true) || deny_all || !values("allowedValues").is_empty(),
    })
}

fn normalize_asset(a: &Value) -> Value {
    json!({
        "name": a["displayName"],
        "id": a["name"],
        "asset_type": a["assetType"],
        "service": a["assetType"].as_str().and_then(|t| t.split('/').next()),
        "location": a["location"],
        "state": a["state"],
        "labels": a["labels"],
        "create_time": a["createTime"],
        "update_time": a["updateTime"],
        "kms_keys": a["kmsKeys"],
        "parent": a["parentFullResourceName"],
    })
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn iam_policy_is_flattened_to_one_row_per_member() {
        let policy = json!({"bindings": [
            {"role": "roles/owner", "members": ["user:a@x.io", "serviceAccount:s@p.iam.gserviceaccount.com"]},
            {"role": "roles/viewer", "members": ["allUsers"]}
        ]});
        let rows = iam_members(&policy);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[1]["member_type"], "serviceAccount");
        assert_eq!(rows[2]["member"], "allUsers");
    }

    // Shape from a live Cloud SQL Postgres 18 instance.
    #[test]
    fn sql_ssl_mode_counts_as_enforcement() {
        let live = json!({"name": "db", "settings": {
            "ipConfiguration": {"authorizedNetworks": [], "sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
                                "ipv4Enabled": false, "requireSsl": false},
            "backupConfiguration": {"enabled": true}}});
        let r = normalize_sql_instance(&live);
        assert_eq!(r["ssl_enforced"], false);
        assert_eq!(r["public_ip"], false);
        assert_eq!(r["backups_enabled"], true);
        let mut enc = live.clone();
        enc["settings"]["ipConfiguration"]["sslMode"] = json!("ENCRYPTED_ONLY");
        enc["settings"]["ipConfiguration"]["authorizedNetworks"] = json!([{"value": "0.0.0.0/0"}]);
        let r = normalize_sql_instance(&enc);
        assert_eq!(r["ssl_enforced"], true);
        assert_eq!(r["authorized_networks"], json!(["0.0.0.0/0"]));
    }

    // Shapes from live getEffectivePolicy answers.
    #[test]
    fn org_policy_effective_values() {
        let list = normalize_org_policy("iam.allowedPolicyMemberDomains",
            &json!({"spec": {"rules": [{"allowAll": true}]}}));
        assert_eq!(list["restricted"], false);
        let boolean = normalize_org_policy("compute.requireOsLogin",
            &json!({"spec": {"rules": [{"enforce": false}]}}));
        assert_eq!(boolean["enforced"], false);
        assert_eq!(boolean["restricted"], false);
        let narrowed = normalize_org_policy("iam.allowedPolicyMemberDomains",
            &json!({"spec": {"rules": [{"values": {"allowedValues": ["C0abc"]}}]}}));
        assert_eq!(narrowed["restricted"], true);
    }

    #[test]
    fn kms_rotation_period_in_days() {
        let k = normalize_kms_key(&json!({
            "name": "projects/p/locations/europe-west1/keyRings/r/cryptoKeys/k",
            "purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776000s",
            "versionTemplate": {"protectionLevel": "SOFTWARE"}}));
        assert_eq!(k["name"], "k");
        assert_eq!(k["location"], "europe-west1");
        assert_eq!(k["rotation_period_days"], 90.0);
        let none = normalize_kms_key(&json!({"name": "projects/p/locations/l/keyRings/r/cryptoKeys/k"}));
        assert_eq!(none["rotation_period_days"], Value::Null);
    }

    #[test]
    fn service_disabled_is_recognized() {
        let e = ProviderError::Query("GET x (403 Forbidden): {\"reason\": \"SERVICE_DISABLED\"}".into());
        assert!(is_service_disabled(&e));
        assert!(!is_service_disabled(&ProviderError::Query("403 PERMISSION_DENIED".into())));
    }

    #[test]
    fn member_roles_lists_every_role_of_the_member() {
        let policy = json!({"bindings": [
            {"role": "roles/cloudkms.admin", "members": ["user:a@x.org"]},
            {"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter", "members": ["user:a@x.org", "user:b@x.org"]},
        ]});
        let rows = iam_members(&policy);
        let a = rows.iter().find(|r| r["member"] == "user:a@x.org").unwrap();
        assert_eq!(a["member_roles"], json!(["roles/cloudkms.admin", "roles/cloudkms.cryptoKeyEncrypterDecrypter"]));
        let b = rows.iter().find(|r| r["member"] == "user:b@x.org").unwrap();
        assert_eq!(b["member_roles"], json!(["roles/cloudkms.cryptoKeyEncrypterDecrypter"]));
    }

    #[test]
    fn audit_config_of_all_services() {
        let policy = json!({"auditConfigs": [
            {"service": "storage.googleapis.com", "auditLogConfigs": [{"logType": "ADMIN_READ"}]},
            {"service": "allServices", "auditLogConfigs": [
                {"logType": "DATA_READ", "exemptedMembers": ["user:x@y.org"]},
                {"logType": "DATA_WRITE"}
            ]}
        ]});
        let (types, exempted) = all_services_audit(&policy);
        assert_eq!(types, vec!["DATA_READ", "DATA_WRITE"]);
        assert_eq!(exempted, vec!["user:x@y.org"]);
        assert_eq!(all_services_audit(&json!({})), (vec![], vec![]));
    }

    #[test]
    fn a_cis_metric_needs_an_enabled_alert_to_count() {
        let metrics = vec![json!({
            "name": "fw-changes",
            "filter": "resource.type=\"gce_firewall_rule\" AND (protoPayload.methodName:\"compute.firewalls.patch\" OR protoPayload.methodName:\"compute.firewalls.insert\" OR protoPayload.methodName:\"compute.firewalls.delete\")"
        })];
        let alert = |enabled: bool| json!({"enabled": enabled, "conditions": [{"conditionThreshold": {
            "filter": "metric.type=\"logging.googleapis.com/user/fw-changes\" AND resource.type=\"global\""}}]});
        let row = |policies: &[Value]| metric_alert_rows(&metrics, policies).into_iter().find(|r| r["control"] == "2.7").unwrap();
        assert_eq!(row(&[]), json!({"name": "vpc_firewall", "control": "2.7", "metric": "fw-changes", "metric_exists": true, "alert_enabled": false}));
        assert_eq!(row(&[alert(false)])["alert_enabled"], false);
        assert_eq!(row(&[alert(true)])["alert_enabled"], true);
        // Every control is reported, matched or not.
        let all = metric_alert_rows(&[], &[]);
        assert_eq!(all.len(), 8);
        assert!(all.iter().all(|r| r["alert_enabled"] == false && r["metric"] == ""));
    }

    #[test]
    fn sql_flags_and_engine() {
        let row = normalize_sql_instance(&json!({
            "databaseVersion": "POSTGRES_15",
            "settings": {"databaseFlags": [
                {"name": "log_connections", "value": "On"},
                {"name": "cloudsql.enable_pgaudit", "value": "on"}
            ]}
        }));
        assert_eq!(row["engine"], "postgres");
        assert_eq!(row["flags"]["log_connections"], "on");
        assert_eq!(
            kxn_core::engine::property::get_sub_property(&row, "flags.cloudsql/.enable_pgaudit"),
            Some(&json!("on"))
        );
        assert_eq!(normalize_sql_instance(&json!({"databaseVersion": "SQLSERVER_2019_STANDARD"}))["engine"], "sqlserver");
    }

    #[test]
    fn network_dns_logging_and_legacy() {
        let policies = vec![json!({"enableLogging": true, "networks": [
            {"networkUrl": "https://www.googleapis.com/compute/v1/projects/p/global/networks/prod"}]})];
        let prod = normalize_network(&json!({"name": "prod"}), &policies);
        assert_eq!(prod["dns_logging"], true);
        assert_eq!(prod["legacy"], false);
        let old = normalize_network(&json!({"name": "old", "IPv4Range": "10.240.0.0/16"}), &policies);
        assert_eq!(old["dns_logging"], false);
        assert_eq!(old["legacy"], true);
    }

    #[test]
    fn function_env_vars_that_look_like_secrets() {
        let row = normalize_function(&json!({
            "serviceConfig": {"environmentVariables": {"DB_PASSWORD": "x", "LOG_LEVEL": "info", "STRIPE_API_KEY": "y"}},
            "buildConfig": {"environmentVariables": {"GITHUB_TOKEN": "z"}}
        }));
        assert_eq!(row["secret_like_env_vars"], json!(["DB_PASSWORD", "STRIPE_API_KEY", "GITHUB_TOKEN"]));
        assert_eq!(normalize_function(&json!({}))["secret_like_env_vars"], json!([]));
    }

    #[test]
    fn dnssec_key_kinds_are_told_apart() {
        let z = normalize_dns_zone(&json!({"dnssecConfig": {"state": "on", "defaultKeySpecs": [
            {"keyType": "keySigning", "algorithm": "rsasha256"},
            {"keyType": "zoneSigning", "algorithm": "rsasha1"}
        ]}}));
        assert_eq!(z["key_signing_algorithms"], json!(["rsasha256"]));
        assert_eq!(z["zone_signing_algorithms"], json!(["rsasha1"]));
    }
}
