use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Value};
use tracing::{debug, info};

const DEFAULT_NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const DEFAULT_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const DEFAULT_EPSS_URL: &str = "https://api.first.org/data/v1/epss";

const RESOURCE_TYPES: &[&str] = &["nvd_cves", "kev", "epss"];

pub struct CveFeedsProvider {
    config: Value,
    client: reqwest::Client,
}

impl CveFeedsProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| ProviderError::Connection(format!("HTTP client: {}", e)))?;
        Ok(Self { config, client })
    }

    fn nvd_url(&self) -> String {
        get_config_or_env(&self.config, "NVD_URL", Some("CVE"))
            .unwrap_or_else(|| DEFAULT_NVD_URL.to_string())
    }

    fn kev_url(&self) -> String {
        get_config_or_env(&self.config, "KEV_URL", Some("CVE"))
            .unwrap_or_else(|| DEFAULT_KEV_URL.to_string())
    }

    fn epss_url(&self) -> String {
        get_config_or_env(&self.config, "EPSS_URL", Some("CVE"))
            .unwrap_or_else(|| DEFAULT_EPSS_URL.to_string())
    }

    fn api_key(&self) -> Option<String> {
        get_config_or_env(&self.config, "API_KEY", Some("NVD"))
    }

    fn keywords(&self) -> Vec<String> {
        if let Some(Value::Array(arr)) = self.config.get("keywords") {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else if let Some(kw) = get_config_or_env(&self.config, "KEYWORDS", Some("CVE")) {
            kw.split(',').map(|s| s.trim().to_string()).collect()
        } else {
            vec![]
        }
    }

    fn cpe_name(&self) -> Option<String> {
        get_config_or_env(&self.config, "CPE_NAME", Some("CVE"))
    }

    fn severity(&self) -> Option<String> {
        get_config_or_env(&self.config, "SEVERITY", Some("CVE"))
    }

    fn days_back(&self) -> u32 {
        get_config_or_env(&self.config, "DAYS_BACK", Some("CVE"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(7)
    }

    fn max_results(&self) -> u32 {
        get_config_or_env(&self.config, "MAX_RESULTS", Some("CVE"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(100)
    }

    /// Fetch CVEs from NVD API v2.0
    async fn gather_nvd(&self) -> Result<Vec<Value>, ProviderError> {
        let base_url = self.nvd_url();
        let days = self.days_back();
        let now = chrono::Utc::now();
        let start = now - chrono::Duration::days(days as i64);

        let start_str = start.format("%Y-%m-%dT00:00:00.000").to_string();
        let end_str = now.format("%Y-%m-%dT23:59:59.999").to_string();

        let mut results = Vec::new();
        let keywords = self.keywords();

        // If no keywords, do a single date-range query
        let queries: Vec<Option<&str>> = if keywords.is_empty() {
            vec![None]
        } else {
            keywords.iter().map(|k| Some(k.as_str())).collect()
        };

        for keyword in &queries {
            let mut params = vec![
                ("pubStartDate", start_str.clone()),
                ("pubEndDate", end_str.clone()),
                (
                    "resultsPerPage",
                    self.max_results().to_string(),
                ),
            ];

            if let Some(kw) = keyword {
                params.push(("keywordSearch", kw.to_string()));
            }
            if let Some(cpe) = self.cpe_name() {
                params.push(("cpeName", cpe));
            }
            if let Some(sev) = self.severity() {
                params.push(("cvssV3Severity", sev.to_uppercase()));
            }

            let mut req = self.client.get(&base_url).query(&params);
            if let Some(key) = self.api_key() {
                req = req.header("apiKey", key);
            }

            debug!(url = %base_url, keyword = ?keyword, "Fetching NVD CVEs");

            let resp = req.send().await.map_err(|e| {
                ProviderError::Api(format!("NVD API request failed: {}", e))
            })?;

            if resp.status() == 403 {
                return Err(ProviderError::RateLimited {
                    retry_after_secs: 30,
                });
            }

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(ProviderError::Api(format!(
                    "NVD API {} — {}",
                    status, body
                )));
            }

            let data: Value = resp.json().await.map_err(|e| {
                ProviderError::Api(format!("NVD JSON parse error: {}", e))
            })?;

            let vulns = data
                .get("vulnerabilities")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            info!(count = vulns.len(), keyword = ?keyword, "NVD CVEs fetched");

            for vuln in vulns {
                if let Some(cve) = vuln.get("cve") {
                    results.push(normalize_nvd_cve(cve));
                }
            }
        }

        // Deduplicate by CVE ID
        results.sort_by(|a, b| {
            a.get("id")
                .and_then(|v| v.as_str())
                .cmp(&b.get("id").and_then(|v| v.as_str()))
        });
        results.dedup_by(|a, b| {
            a.get("id").and_then(|v| v.as_str())
                == b.get("id").and_then(|v| v.as_str())
        });

        Ok(results)
    }

    /// Fetch CISA Known Exploited Vulnerabilities catalog
    async fn gather_kev(&self) -> Result<Vec<Value>, ProviderError> {
        let url = self.kev_url();
        debug!(url = %url, "Fetching CISA KEV catalog");

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ProviderError::Api(format!("KEV fetch failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(ProviderError::Api(format!(
                "KEV API {}",
                resp.status()
            )));
        }

        let data: Value = resp.json().await.map_err(|e| {
            ProviderError::Api(format!("KEV JSON parse error: {}", e))
        })?;

        let vulns = data
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        info!(count = vulns.len(), "CISA KEV entries fetched");

        // Filter by days_back if configured
        let days = self.days_back();
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
        let cutoff_str = cutoff.format("%Y-%m-%d").to_string();

        let mut results: Vec<Value> = vulns
            .into_iter()
            .filter(|v| {
                v.get("dateAdded")
                    .and_then(|d| d.as_str())
                    .map(|d| d >= cutoff_str.as_str())
                    .unwrap_or(true)
            })
            .map(|v| normalize_kev(&v))
            .collect();

        // Filter by keywords if set
        let keywords = self.keywords();
        if !keywords.is_empty() {
            results.retain(|v| {
                let vendor = v
                    .get("vendor")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let product = v
                    .get("product")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let desc = v
                    .get("description")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                keywords.iter().any(|kw| {
                    let kw = kw.to_lowercase();
                    vendor.contains(&kw)
                        || product.contains(&kw)
                        || desc.contains(&kw)
                })
            });
        }

        Ok(results)
    }

    /// Fetch EPSS scores for a list of CVE IDs
    async fn gather_epss(&self) -> Result<Vec<Value>, ProviderError> {
        // EPSS needs CVE IDs — get them from config or fetch top scores
        let cve_ids: Vec<String> =
            if let Some(Value::Array(arr)) = self.config.get("cve_ids") {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            } else {
                // Fetch top EPSS scores (most likely to be exploited)
                vec![]
            };

        let url = self.epss_url();

        let resp = if cve_ids.is_empty() {
            // Top scores sorted by EPSS descending
            let limit = self.max_results().min(100);
            debug!("Fetching top {} EPSS scores", limit);
            self.client
                .get(&url)
                .query(&[
                    ("order", "!epss"),
                    ("limit", &limit.to_string()),
                ])
                .send()
                .await
        } else {
            // Specific CVE IDs
            let ids = cve_ids.join(",");
            debug!(count = cve_ids.len(), "Fetching EPSS for specific CVEs");
            self.client
                .get(&url)
                .query(&[("cve", &ids)])
                .send()
                .await
        };

        let resp = resp.map_err(|e| {
            ProviderError::Api(format!("EPSS fetch failed: {}", e))
        })?;

        if !resp.status().is_success() {
            return Err(ProviderError::Api(format!(
                "EPSS API {}",
                resp.status()
            )));
        }

        let data: Value = resp.json().await.map_err(|e| {
            ProviderError::Api(format!("EPSS JSON parse error: {}", e))
        })?;

        let entries = data
            .get("data")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        info!(count = entries.len(), "EPSS scores fetched");

        Ok(entries.into_iter().map(|e| normalize_epss(&e)).collect())
    }
}

#[async_trait::async_trait]
impl Provider for CveFeedsProvider {
    fn name(&self) -> &str {
        "cve"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(
        &self,
        resource_type: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        match resource_type {
            "nvd_cves" => self.gather_nvd().await,
            "kev" => self.gather_kev().await,
            "epss" => self.gather_epss().await,
            _ => Err(ProviderError::UnsupportedResourceType(
                resource_type.to_string(),
            )),
        }
    }
}

/// Normalize NVD CVE response into a flat JSON structure
fn normalize_nvd_cve(cve: &Value) -> Value {
    let id = cve
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let description = cve
        .get("descriptions")
        .and_then(|v| v.as_array())
        .and_then(|arr| {
            arr.iter().find(|d| {
                d.get("lang").and_then(|l| l.as_str()) == Some("en")
            })
        })
        .and_then(|d| d.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Extract CVSS v3.1 or v3.0 score
    let metrics = cve.get("metrics").unwrap_or(&Value::Null);
    let (cvss_version, cvss_score, cvss_severity, cvss_vector) =
        extract_cvss(metrics);

    // Extract CWE IDs
    let weaknesses: Vec<String> = cve
        .get("weaknesses")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|w| {
                    w.get("description")
                        .and_then(|d| d.as_array())
                        .and_then(|d| d.first())
                        .and_then(|d| d.get("value"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default();

    // Extract affected vendors/products from configurations
    let affected = extract_affected(cve);

    let published = cve
        .get("published")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let modified = cve
        .get("lastModified")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    json!({
        "id": id,
        "description": description,
        "published": published,
        "modified": modified,
        "cvss_version": cvss_version,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "weaknesses": weaknesses,
        "affected": affected,
        "source": "nvd",
        "kev_listed": false,
        "epss_score": null,
        "epss_percentile": null,
    })
}

fn extract_cvss(metrics: &Value) -> (&str, f64, String, String) {
    // Try CVSS v3.1 first, then v3.0, then v2.0
    for (key, version) in [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
    ] {
        if let Some(arr) = metrics.get(key).and_then(|v| v.as_array()) {
            if let Some(metric) = arr.first() {
                let cvss = metric.get("cvssData").unwrap_or(&Value::Null);
                let score = cvss
                    .get("baseScore")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let severity = cvss
                    .get("baseSeverity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN")
                    .to_uppercase();
                let vector = cvss
                    .get("vectorString")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                return (version, score, severity, vector);
            }
        }
    }

    // Fallback to v2
    if let Some(arr) = metrics
        .get("cvssMetricV2")
        .and_then(|v| v.as_array())
    {
        if let Some(metric) = arr.first() {
            let cvss = metric.get("cvssData").unwrap_or(&Value::Null);
            let score = cvss
                .get("baseScore")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let severity = if score >= 9.0 {
                "CRITICAL"
            } else if score >= 7.0 {
                "HIGH"
            } else if score >= 4.0 {
                "MEDIUM"
            } else {
                "LOW"
            }
            .to_string();
            let vector = cvss
                .get("vectorString")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            return ("2.0", score, severity, vector);
        }
    }

    ("none", 0.0, "UNKNOWN".to_string(), String::new())
}

fn extract_affected(cve: &Value) -> Vec<Value> {
    let mut affected = Vec::new();
    if let Some(configs) = cve.get("configurations").and_then(|v| v.as_array()) {
        for config in configs {
            if let Some(nodes) = config.get("nodes").and_then(|v| v.as_array())
            {
                for node in nodes {
                    if let Some(matches) =
                        node.get("cpeMatch").and_then(|v| v.as_array())
                    {
                        for m in matches {
                            let cpe = m
                                .get("criteria")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let parts: Vec<&str> = cpe.split(':').collect();
                            if parts.len() >= 5 {
                                affected.push(json!({
                                    "cpe": cpe,
                                    "vendor": parts[3],
                                    "product": parts[4],
                                    "version_start": m.get("versionStartIncluding").and_then(|v| v.as_str()).unwrap_or(""),
                                    "version_end": m.get("versionEndExcluding").and_then(|v| v.as_str()).unwrap_or(""),
                                    "vulnerable": m.get("vulnerable").and_then(|v| v.as_bool()).unwrap_or(true),
                                }));
                            }
                        }
                    }
                }
            }
        }
    }
    affected
}

fn normalize_kev(entry: &Value) -> Value {
    json!({
        "id": entry.get("cveID").and_then(|v| v.as_str()).unwrap_or(""),
        "vendor": entry.get("vendorProject").and_then(|v| v.as_str()).unwrap_or(""),
        "product": entry.get("product").and_then(|v| v.as_str()).unwrap_or(""),
        "description": entry.get("shortDescription").and_then(|v| v.as_str()).unwrap_or(""),
        "date_added": entry.get("dateAdded").and_then(|v| v.as_str()).unwrap_or(""),
        "due_date": entry.get("dueDate").and_then(|v| v.as_str()).unwrap_or(""),
        "required_action": entry.get("requiredAction").and_then(|v| v.as_str()).unwrap_or(""),
        "known_ransomware": entry.get("knownRansomwareCampaignUse").and_then(|v| v.as_str()).unwrap_or("Unknown"),
        "source": "cisa_kev",
        "kev_listed": true,
        "cvss_severity": "CRITICAL",
    })
}

fn normalize_epss(entry: &Value) -> Value {
    let epss = entry
        .get("epss")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f64>().ok())
        .or_else(|| entry.get("epss").and_then(|v| v.as_f64()))
        .unwrap_or(0.0);

    let percentile = entry
        .get("percentile")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f64>().ok())
        .or_else(|| entry.get("percentile").and_then(|v| v.as_f64()))
        .unwrap_or(0.0);

    json!({
        "id": entry.get("cve").and_then(|v| v.as_str()).unwrap_or(""),
        "epss_score": epss,
        "epss_percentile": percentile,
        "date": entry.get("date").and_then(|v| v.as_str()).unwrap_or(""),
        "source": "epss",
        "high_risk": epss >= 0.5,
    })
}
