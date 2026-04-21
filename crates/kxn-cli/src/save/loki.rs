//! Grafana Loki save backend.
//!
//! Pushes scan results, metrics, and logs to a Loki instance via the HTTP
//! `/loki/api/v1/push` endpoint.
//!
//! URL format: `loki://host:3100` (http) or `loki+https://host:3100` (https).
//!
//! Optional auth via `LOKI_USER` + `LOKI_PASSWORD` env vars (Basic Auth) or
//! `LOKI_TOKEN` (Bearer token — e.g. Grafana Cloud).
//!
//! Tenant header via `LOKI_TENANT` env var (multi-tenant Loki, sent as
//! `X-Scope-OrgID`).

use anyhow::{Context, Result};
use kxn_rules::SaveConfig;

use super::{LogRecord, MetricRecord, ScanRecord};

/// Parse the Loki URL.
/// Accepts `loki://host:3100`, `loki+https://host:3100`, `http://host:3100`,
/// `https://host:3100`. Returns the HTTP(S) base URL (no trailing slash).
fn parse_url(url: &str) -> Result<String> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("loki+https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("loki+http://") {
        ("http", rest)
    } else if let Some(rest) = url.strip_prefix("loki://") {
        ("http", rest)
    } else if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        anyhow::bail!("loki url must start with loki://, loki+https://, http://, or https://");
    };
    let host = rest.trim_end_matches('/');
    Ok(format!("{}://{}", scheme, host))
}

/// Labels for a Loki stream (a flat JSON map: label name → value).
type StreamLabels = serde_json::Map<String, serde_json::Value>;
/// A single Loki log line: `(timestamp_ns, message)`.
type StreamValue = (String, String);
/// One Loki stream = labels + its list of values.
type LokiStream = (StreamLabels, Vec<StreamValue>);

/// Build the Loki push payload from a list of streams.
fn build_push_body(streams: Vec<LokiStream>) -> String {
    let streams_json: Vec<serde_json::Value> = streams
        .into_iter()
        .map(|(labels, values)| {
            let values_arr: Vec<Vec<String>> =
                values.into_iter().map(|(ts, line)| vec![ts, line]).collect();
            serde_json::json!({
                "stream": labels,
                "values": values_arr,
            })
        })
        .collect();
    serde_json::json!({ "streams": streams_json }).to_string()
}

fn ts_nanos(dt: &chrono::DateTime<chrono::Utc>) -> String {
    let secs = dt.timestamp() as i128;
    let nanos = dt.timestamp_subsec_nanos() as i128;
    (secs * 1_000_000_000 + nanos).to_string()
}

async fn post_push(base_url: &str, body: String) -> Result<()> {
    let url = format!("{}/loki/api/v1/push", base_url);
    let client = crate::alerts::shared_client();

    let mut req = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body);

    if let (Ok(user), Ok(pwd)) = (std::env::var("LOKI_USER"), std::env::var("LOKI_PASSWORD")) {
        req = req.basic_auth(user, Some(pwd));
    } else if let Ok(token) = std::env::var("LOKI_TOKEN") {
        req = req.bearer_auth(token);
    }

    if let Ok(tenant) = std::env::var("LOKI_TENANT") {
        req = req.header("X-Scope-OrgID", tenant);
    }

    let resp = req.send().await.context("loki push request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        tracing::warn!(url = %url, %status, body = %body, "loki push failed");
        anyhow::bail!("loki push failed: {} — {}", status, body);
    }

    tracing::debug!(url = %url, "loki push succeeded");
    Ok(())
}

/// Save scan results + metrics to Loki.
pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let base_url = parse_url(&config.url)?;

    let mut scan_values: Vec<(String, String)> = Vec::new();
    let mut metric_values: Vec<(String, String)> = Vec::new();

    for r in records {
        if config.only_errors && !r.error {
            continue;
        }
        let line = serde_json::json!({
            "target": r.target,
            "provider": r.provider,
            "rule_name": r.rule_name,
            "rule_description": r.rule_description,
            "level": r.level,
            "level_label": r.level_label,
            "error": r.error,
            "messages": r.messages,
            "compliance": r.compliance,
            "batch_id": r.batch_id,
            "origin": config.origin,
        })
        .to_string();
        scan_values.push((ts_nanos(&r.timestamp), line));
    }

    for m in metrics {
        let line = serde_json::json!({
            "target": m.target,
            "provider": m.provider,
            "resource_type": m.resource_type,
            "metric_name": m.metric_name,
            "value_num": m.value_num,
            "value_str": m.value_str,
            "origin": config.origin,
        })
        .to_string();
        metric_values.push((ts_nanos(&m.timestamp), line));
    }

    let mut streams = Vec::new();
    if !scan_values.is_empty() {
        let mut labels = serde_json::Map::new();
        labels.insert("app".into(), "kxn".into());
        labels.insert("kind".into(), "scan".into());
        labels.insert("origin".into(), config.origin.clone().into());
        streams.push((labels, scan_values));
    }
    if !metric_values.is_empty() {
        let mut labels = serde_json::Map::new();
        labels.insert("app".into(), "kxn".into());
        labels.insert("kind".into(), "metric".into());
        labels.insert("origin".into(), config.origin.clone().into());
        streams.push((labels, metric_values));
    }

    if streams.is_empty() {
        return Ok(());
    }

    let body = build_push_body(streams);
    post_push(&base_url, body).await
}

/// Save log records to Loki.
pub async fn save_logs(config: &SaveConfig, logs: &[LogRecord]) -> Result<()> {
    if logs.is_empty() {
        return Ok(());
    }
    let base_url = parse_url(&config.url)?;

    let mut values: Vec<(String, String)> = Vec::new();
    for log in logs {
        let line = serde_json::json!({
            "target": log.target,
            "source": log.source,
            "level": log.level,
            "message": log.message,
            "host": log.host,
            "unit": log.unit,
            "batch_id": log.batch_id,
            "origin": config.origin,
        })
        .to_string();
        values.push((ts_nanos(&log.collected_at), line));
    }

    let mut labels = serde_json::Map::new();
    labels.insert("app".into(), "kxn".into());
    labels.insert("kind".into(), "log".into());
    labels.insert("origin".into(), config.origin.clone().into());

    let body = build_push_body(vec![(labels, values)]);
    post_push(&base_url, body).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url_loki_scheme() {
        assert_eq!(parse_url("loki://host:3100").unwrap(), "http://host:3100");
        assert_eq!(parse_url("loki://host:3100/").unwrap(), "http://host:3100");
        assert_eq!(
            parse_url("loki+https://host:3100").unwrap(),
            "https://host:3100"
        );
        assert_eq!(
            parse_url("loki+http://host:3100").unwrap(),
            "http://host:3100"
        );
    }

    #[test]
    fn test_parse_url_http_passthrough() {
        assert_eq!(
            parse_url("http://loki.example.com").unwrap(),
            "http://loki.example.com"
        );
        assert_eq!(
            parse_url("https://loki.example.com:3100").unwrap(),
            "https://loki.example.com:3100"
        );
    }

    #[test]
    fn test_parse_url_rejects_unknown_scheme() {
        assert!(parse_url("ftp://x").is_err());
        assert!(parse_url("bogus").is_err());
    }

    #[test]
    fn test_ts_nanos_format() {
        // Epoch second 0 + 1 nanosecond.
        let dt = chrono::DateTime::from_timestamp(0, 1).unwrap();
        assert_eq!(ts_nanos(&dt), "1");
        // Epoch second 1 + 500 milliseconds.
        let dt = chrono::DateTime::from_timestamp(1, 500_000_000).unwrap();
        assert_eq!(ts_nanos(&dt), "1500000000");
    }

    #[test]
    fn test_build_push_body_single_stream() {
        let mut labels = serde_json::Map::new();
        labels.insert("app".into(), "kxn".into());
        let values = vec![("1234567890000000000".to_string(), "hello".to_string())];
        let body = build_push_body(vec![(labels, values)]);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["streams"][0]["stream"]["app"], "kxn");
        assert_eq!(v["streams"][0]["values"][0][0], "1234567890000000000");
        assert_eq!(v["streams"][0]["values"][0][1], "hello");
    }

    #[test]
    fn test_build_push_body_empty_streams() {
        let body = build_push_body(vec![]);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["streams"].as_array().unwrap().len(), 0);
    }
}
