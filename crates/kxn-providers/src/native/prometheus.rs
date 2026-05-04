//! Prometheus exposition format scraper.
//!
//! Scrapes any HTTP endpoint that serves the [Prometheus text-based
//! exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/)
//! (Traefik, node-exporter, blackbox-exporter, an application's own
//! `/metrics` endpoint, etc.) and turns each `name{labels} value` line
//! into a kxn metric record.
//!
//! Configuration:
//!
//! - `URL`               — full URL to scrape (e.g. `http://traefik:9100/metrics`)
//! - `BEARER_TOKEN`      — optional Authorization header value
//! - `INSECURE`          — skip TLS verification when set to `true`/`1`
//! - `INCLUDE_PREFIXES`  — comma-separated metric name prefixes to keep
//!   (everything else is dropped). Defaults to all metrics.
//! - `EXCLUDE_PREFIXES`  — comma-separated metric name prefixes to drop
//!   (applied after `INCLUDE_PREFIXES`). Useful to skip
//!   `go_*` / `process_*` runtime noise.
//!
//! The provider exposes a single resource type, `prometheus_metrics`,
//! whose items are flat `{metric_name: value}` maps consumed by the kxn
//! metrics flattener and stored in the `metrics` table.
//!
//! Labels are preserved by appending them to the metric name verbatim
//! (e.g. `traefik_requests_total{code="200",method="GET"}`), since the
//! shared `metrics` schema has no labels column. Downstream SQL can
//! filter with `metric_name LIKE 'traefik_requests_total{%code="200"%'`
//! or split with `regexp_match`.

use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Map, Value};

const RESOURCE_TYPES: &[&str] = &["prometheus_metrics"];

pub struct PrometheusProvider {
    url: String,
    bearer_token: Option<String>,
    include_prefixes: Vec<String>,
    exclude_prefixes: Vec<String>,
    client: reqwest::Client,
}

impl PrometheusProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let url = get_config_or_env(&config, "URL", Some("PROM"))
            .ok_or_else(|| ProviderError::InvalidConfig("PROM_URL not set".into()))?;

        let bearer_token = get_config_or_env(&config, "BEARER_TOKEN", Some("PROM"));

        let insecure = get_config_or_env(&config, "INSECURE", Some("PROM"))
            .map(|s| s == "true" || s == "1")
            .unwrap_or(false);

        let include_prefixes: Vec<String> = get_config_or_env(&config, "INCLUDE_PREFIXES", Some("PROM"))
            .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
            .unwrap_or_default();

        let exclude_prefixes: Vec<String> = get_config_or_env(&config, "EXCLUDE_PREFIXES", Some("PROM"))
            .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
            .unwrap_or_default();

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(insecure)
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("kxn-prometheus-scraper")
            .build()
            .map_err(|e| ProviderError::Connection(format!("HTTP client build failed: {}", e)))?;

        Ok(Self { url, bearer_token, include_prefixes, exclude_prefixes, client })
    }

    async fn scrape(&self) -> Result<String, ProviderError> {
        let mut req = self.client.get(&self.url);
        if let Some(token) = &self.bearer_token {
            req = req.bearer_auth(token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ProviderError::Connection(format!("scrape request failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(ProviderError::Connection(format!(
                "scrape returned status {}",
                resp.status()
            )));
        }
        resp.text()
            .await
            .map_err(|e| ProviderError::Connection(format!("scrape body read failed: {}", e)))
    }

    fn keep_metric(&self, name: &str) -> bool {
        if !self.include_prefixes.is_empty()
            && !self.include_prefixes.iter().any(|p| name.starts_with(p))
        {
            return false;
        }
        if self.exclude_prefixes.iter().any(|p| name.starts_with(p)) {
            return false;
        }
        true
    }
}

#[async_trait::async_trait]
impl Provider for PrometheusProvider {
    fn name(&self) -> &str {
        "prometheus"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        if resource_type != "prometheus_metrics" {
            return Err(ProviderError::NotFound(format!(
                "Unknown resource type '{}' for prometheus provider",
                resource_type
            )));
        }
        let body = self.scrape().await?;
        let parsed = parse_exposition(&body);

        // The kxn metrics flattener expects a Vec of objects whose keys
        // are metric names and values are numbers (or numeric strings).
        // Collapse all parsed series into a single object so a scrape
        // becomes one row per metric in the `metrics` table.
        let mut bag: Map<String, Value> = Map::new();
        for (name, value) in parsed {
            if !self.keep_metric(&name) {
                continue;
            }
            bag.insert(name, json!(value));
        }
        Ok(vec![Value::Object(bag)])
    }
}

/// Parse Prometheus text exposition format into `(metric_name_with_labels, value)` pairs.
///
/// Lines starting with `#` (HELP / TYPE) are ignored. Histogram and summary
/// children (`_bucket`, `_sum`, `_count`) are returned as-is so users can
/// reconstruct them downstream.
fn parse_exposition(body: &str) -> Vec<(String, f64)> {
    let mut out = Vec::new();
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Format: name{labels} value [timestamp]
        // We ignore the optional timestamp; the time column is set by kxn at insert.
        let (name_with_labels, value_part) = match split_metric_value(line) {
            Some(pair) => pair,
            None => continue,
        };
        let value: f64 = match value_part.split_whitespace().next().and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => continue,
        };
        out.push((name_with_labels.to_string(), value));
    }
    out
}

/// Split a `name{labels} value` line into the labelled name and the
/// remaining value+timestamp portion. Handles the `name value` no-labels
/// case as well.
fn split_metric_value(line: &str) -> Option<(&str, &str)> {
    if let Some(brace_close) = line.find('}') {
        // Labelled: split at the first whitespace AFTER '}'.
        let after = &line[brace_close + 1..];
        let space_pos = after.find(char::is_whitespace)?;
        let absolute = brace_close + 1 + space_pos;
        Some((line[..absolute].trim(), line[absolute..].trim()))
    } else {
        // Bare: split at the first whitespace.
        let space_pos = line.find(char::is_whitespace)?;
        Some((&line[..space_pos], line[space_pos..].trim()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_metric() {
        let p = parse_exposition("up 1\n");
        assert_eq!(p, vec![("up".into(), 1.0)]);
    }

    #[test]
    fn parse_labelled_metric() {
        let body = r#"
            traefik_requests_total{code="200",method="GET"} 42
            traefik_requests_total{code="500",method="POST"} 3.14
        "#;
        let p = parse_exposition(body);
        assert_eq!(p.len(), 2);
        assert!(p[0].0.contains("code=\"200\""));
        assert_eq!(p[0].1, 42.0);
        assert_eq!(p[1].1, 3.14);
    }

    #[test]
    fn skip_comments_and_blank_lines() {
        let body = "# HELP foo\n# TYPE foo counter\n\nfoo 7\n";
        let p = parse_exposition(body);
        assert_eq!(p, vec![("foo".into(), 7.0)]);
    }

    #[test]
    fn ignore_optional_timestamp_column() {
        // Prometheus exposition allows an optional integer timestamp after
        // the value — kxn ignores it, the row's `time` is set on insert.
        let p = parse_exposition("foo 1.5 1700000000000\n");
        assert_eq!(p, vec![("foo".into(), 1.5)]);
    }
}
