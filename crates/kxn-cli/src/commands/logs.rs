use anyhow::Result;
use clap::Args;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use kxn_providers::{create_native_provider, parse_target_uri};
use kxn_rules::parse_config;

use crate::save::LogRecord;

#[derive(Args)]
pub struct LogsArgs {
    /// SSH target URI (e.g. ssh://root@host)
    #[arg()]
    pub target: Option<String>,

    /// Collection interval in seconds
    #[arg(short = 'n', long, default_value = "300")]
    pub interval: u64,

    /// Filter by log level (error, warning, info)
    #[arg(short, long = "level")]
    pub level: Vec<String>,

    /// Filter by source (journal, dmesg, auth)
    #[arg(short, long = "source")]
    pub source: Vec<String>,

    /// Filter by regex pattern on message
    #[arg(short, long)]
    pub pattern: Option<String>,

    /// Expose Prometheus metrics on this port
    #[arg(long)]
    pub metrics_port: Option<u16>,

    /// Webhook URLs for anomaly alerts
    #[arg(short, long)]
    pub webhook: Vec<String>,

    /// Alert when error count exceeds this threshold per collection
    #[arg(long, default_value = "50")]
    pub error_threshold: usize,

    /// Output format: text, json
    #[arg(short, long, default_value = "text")]
    pub output: String,

    /// Path to kxn.toml config file
    #[arg(long = "config-file")]
    pub config_file: Option<PathBuf>,
}

struct LogTarget {
    name: String,
    /// "ssh" or "kubernetes" — determines which provider + resource_type to
    /// gather. SSH targets call `gather("logs")` and read `entries`. K8s
    /// targets call `gather("pod_logs")` and unpack one entry per log line.
    ///
    /// TODO: refactor to a ProviderKind enum shared with kxn-providers so
    /// that exhaustiveness is checked at compile time. Deferred because
    /// parse_target_uri and all call sites would need to change together.
    provider_kind: String,
    provider_config: Value,
    interval: u64,
    webhooks: Vec<String>,
}

#[derive(Clone, Default, serde::Serialize)]
struct LogMetrics {
    target: String,
    total: usize,
    by_level: HashMap<String, usize>,
    by_source: HashMap<String, usize>,
    duration_ms: u128,
}

type SharedLogMetrics = Arc<RwLock<Vec<LogMetrics>>>;

pub async fn run(args: LogsArgs, global_config: Option<PathBuf>) -> Result<()> {
    let config_file = args.config_file.clone().or(global_config).or_else(|| {
        let default = PathBuf::from("kxn.toml");
        if default.exists() { Some(default) } else { None }
    });

    let scan_config = config_file
        .as_ref()
        .map(|p| parse_config(p).map_err(|e| anyhow::anyhow!("{}", e)))
        .transpose()?;

    let save_configs: Arc<Vec<kxn_rules::SaveConfig>> = Arc::new(
        scan_config
            .as_ref()
            .map(|c| c.save.clone())
            .unwrap_or_default(),
    );

    let targets = resolve_log_targets(&args, &scan_config)?;
    if targets.is_empty() {
        anyhow::bail!(
            "No log targets found. Use `kxn logs ssh://user@host`, \
             `kxn logs kubernetes://in-cluster`, or add ssh/kubernetes \
             [[targets]] to kxn.toml"
        );
    }

    let metrics: SharedLogMetrics = Arc::new(RwLock::new(Vec::new()));

    if let Some(port) = args.metrics_port {
        let m = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_log_metrics(port, m).await {
                error!(error = %e, "Metrics server error");
            }
        });
        info!(port, "Prometheus metrics exposed");
    }

    info!(
        targets = targets.len(),
        save = save_configs.len(),
        "kxn logs starting"
    );
    for t in &targets {
        info!(target = %t.name, interval = t.interval, "log target configured");
    }

    let filter = LogFilter {
        levels: args.level.clone(),
        sources: args.source.clone(),
        pattern: args.pattern.as_ref().map(|p| regex::Regex::new(p)).transpose()?,
    };
    let filter = Arc::new(filter);

    let mut handles = Vec::new();
    for target in targets {
        let metrics = metrics.clone();
        let output = args.output.clone();
        let error_threshold = args.error_threshold;
        let filter = filter.clone();
        let save_cfgs = save_configs.clone();

        handles.push(tokio::spawn(async move {
            run_log_loop(target, metrics, output, error_threshold, filter, save_cfgs).await
        }));
    }

    for h in handles {
        if let Err(e) = h.await? {
            error!(error = %e, "Log target task error");
        }
    }

    Ok(())
}

struct LogFilter {
    levels: Vec<String>,
    sources: Vec<String>,
    pattern: Option<regex::Regex>,
}

impl LogFilter {
    fn matches(&self, entry: &Value) -> bool {
        if !self.levels.is_empty() {
            if let Some(level) = entry.get("level").and_then(|v| v.as_str()) {
                if !self.levels.iter().any(|l| l.eq_ignore_ascii_case(level)) {
                    return false;
                }
            }
        }
        if !self.sources.is_empty() {
            if let Some(source) = entry.get("source").and_then(|v| v.as_str()) {
                if !self.sources.iter().any(|s| s.eq_ignore_ascii_case(source)) {
                    return false;
                }
            }
        }
        if let Some(ref re) = self.pattern {
            if let Some(msg) = entry.get("message").and_then(|v| v.as_str()) {
                if !re.is_match(msg) {
                    return false;
                }
            }
        }
        true
    }
}

fn resolve_log_targets(
    args: &LogsArgs,
    scan_config: &Option<kxn_rules::ScanConfig>,
) -> Result<Vec<LogTarget>> {
    // Single target from CLI
    if let Some(ref uri) = args.target {
        let (provider, config) =
            parse_target_uri(uri).map_err(|e| anyhow::anyhow!("{}", e))?;
        if provider != "ssh" && provider != "kubernetes" {
            anyhow::bail!(
                "kxn logs supports ssh:// and kubernetes:// targets, got '{}'",
                provider
            );
        }
        return Ok(vec![LogTarget {
            name: uri.clone(),
            provider_kind: provider,
            provider_config: config,
            interval: args.interval,
            webhooks: args.webhook.clone(),
        }]);
    }

    // Multi-target from kxn.toml
    let config = scan_config
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No target specified and no kxn.toml found"))?;

    let mut targets = Vec::new();
    for tc in &config.targets {
        let provider_kind = match &tc.provider {
            Some(p) if p == "ssh" || p == "kubernetes" => p.clone(),
            Some(_) => continue, // skip other providers
            None => {
                // Try to infer from URI
                if let Some(ref uri) = tc.uri {
                    if uri.starts_with("ssh://") {
                        "ssh".to_string()
                    } else if uri.starts_with("kubernetes://") {
                        "kubernetes".to_string()
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            }
        };

        let config_value = toml_table_to_json(&tc.config);

        targets.push(LogTarget {
            name: tc.name.clone(),
            provider_kind,
            provider_config: config_value,
            interval: tc.interval.unwrap_or(args.interval),
            webhooks: if tc.webhook.is_empty() {
                args.webhook.clone()
            } else {
                tc.webhook.clone()
            },
        });
    }

    Ok(targets)
}

fn toml_table_to_json(table: &toml::Table) -> Value {
    crate::utils::toml_table_to_json(table)
}

async fn run_log_loop(
    target: LogTarget,
    metrics: SharedLogMetrics,
    output: String,
    error_threshold: usize,
    filter: Arc<LogFilter>,
    save_configs: Arc<Vec<kxn_rules::SaveConfig>>,
) -> Result<()> {
    let client = crate::alerts::shared_client();
    let mut last_alert: Option<Instant> = None;
    let alert_dedup = Duration::from_secs(3600);
    let mut iteration = 0u64;

    loop {
        iteration += 1;
        let batch_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let start = Instant::now();

        // Gather logs — provider depends on target kind
        let provider = match create_native_provider(&target.provider_kind, target.provider_config.clone()) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    target = %target.name,
                    provider = %target.provider_kind,
                    error = %e,
                    "Provider connection error"
                );
                tokio::time::sleep(Duration::from_secs(target.interval)).await;
                continue;
            }
        };

        // TODO: provider_kind should be a ProviderKind enum rather than a plain String.
        // Refactoring is deferred because parse_target_uri (kxn-providers) and all call
        // sites would need to be updated together.
        let resource_type = match target.provider_kind.as_str() {
            "kubernetes" => "pod_logs",
            _ => "logs",
        };

        let gathered = match provider.gather(resource_type).await {
            Ok(items) => items,
            Err(e) => {
                warn!(
                    target = %target.name,
                    resource_type,
                    error = %e,
                    "Gather error"
                );
                tokio::time::sleep(Duration::from_secs(target.interval)).await;
                continue;
            }
        };

        // Owned entries. SSH targets have a top-level `entries` array of dicts;
        // K8s pod_logs has one item per pod with `logs: [<raw lines>]` — we
        // flatten each raw line into an entry with inferred level and source
        // labels so the filter + save/output pipeline treats them uniformly.
        let owned_entries: Vec<Value> = match target.provider_kind.as_str() {
            "kubernetes" => flatten_kubernetes_pod_logs(&gathered),
            _ => gathered
                .iter()
                .filter_map(|item| item.get("entries"))
                .filter_map(|e| e.as_array())
                .flat_map(|arr| arr.iter().cloned())
                .collect(),
        };
        let entries: Vec<&Value> = owned_entries
            .iter()
            .filter(|entry| filter.matches(entry))
            .collect();

        let duration_ms = start.elapsed().as_millis();

        // Build metrics
        let mut by_level: HashMap<String, usize> = HashMap::new();
        let mut by_source: HashMap<String, usize> = HashMap::new();
        for entry in &entries {
            if let Some(level) = entry.get("level").and_then(|v| v.as_str()) {
                *by_level.entry(level.to_string()).or_default() += 1;
            }
            if let Some(source) = entry.get("source").and_then(|v| v.as_str()) {
                *by_source.entry(source.to_string()).or_default() += 1;
            }
        }

        let log_metrics = LogMetrics {
            target: target.name.clone(),
            total: entries.len(),
            by_level: by_level.clone(),
            by_source: by_source.clone(),
            duration_ms,
        };

        // Update shared metrics
        {
            let mut m = metrics.write().await;
            m.retain(|lm| lm.target != target.name);
            m.push(log_metrics.clone());
        }

        // Output
        let error_count = by_level.get("error").copied().unwrap_or(0);
        let warning_count = by_level.get("warning").copied().unwrap_or(0);

        match output.as_str() {
            "json" => {
                let out = serde_json::json!({
                    "iteration": iteration,
                    "timestamp": now.to_rfc3339(),
                    "target": target.name,
                    "total": entries.len(),
                    "errors": error_count,
                    "warnings": warning_count,
                    "duration_ms": duration_ms,
                    "by_source": by_source,
                });
                println!("{}", serde_json::to_string(&out)?);
            }
            _ => {
                let status = if error_count > 0 { "WARN" } else { "OK" };
                info!(
                    target = %target.name,
                    iteration,
                    status,
                    total = entries.len(),
                    errors = error_count,
                    warnings = warning_count,
                    duration_ms,
                    "log collection cycle"
                );
            }
        }

        // Convert to LogRecords and save
        if !save_configs.is_empty() && !entries.is_empty() {
            let log_records: Vec<LogRecord> = entries
                .iter()
                .map(|entry| LogRecord {
                    target: target.name.clone(),
                    source: entry
                        .get("source")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    level: entry
                        .get("level")
                        .and_then(|v| v.as_str())
                        .unwrap_or("info")
                        .to_string(),
                    message: entry
                        .get("message")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    host: Some(target.name.clone()),
                    unit: entry
                        .get("unit")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    collected_at: now,
                    batch_id: batch_id.clone(),
                    tags: HashMap::new(),
                })
                .collect();

            if let Err(e) = crate::save::save_logs(&save_configs, &log_records).await {
                warn!(
                    target = %target.name,
                    error = %e,
                    "Failed to save log records"
                );
            }
        }

        // Anomaly detection: error spike
        if error_count >= error_threshold {
            let should_alert = match last_alert {
                Some(t) => Instant::now().duration_since(t) >= alert_dedup,
                None => true,
            };

            if should_alert && !target.webhooks.is_empty() {
                let payload = serde_json::json!({
                    "event": "kxn_log_anomaly",
                    "timestamp": now.to_rfc3339(),
                    "target": target.name,
                    "anomaly": "error_spike",
                    "error_count": error_count,
                    "threshold": error_threshold,
                    "total_logs": entries.len(),
                    "by_source": by_source,
                });

                for url in &target.webhooks {
                    let body = if url.contains("hooks.slack.com") {
                        serde_json::json!({
                            "text": format!(
                                "*[KXN LOG ALERT]* `{}` — {} errors detected (threshold: {})",
                                target.name, error_count, error_threshold
                            )
                        })
                    } else if url.contains("discord.com/api/webhooks") {
                        serde_json::json!({
                            "content": format!(
                                "🔴 **KXN LOG ALERT** `{}` — {} errors detected (threshold: {})",
                                target.name, error_count, error_threshold
                            )
                        })
                    } else {
                        payload.clone()
                    };
                    let _ = client.post(url).json(&body).send().await;
                }

                last_alert = Some(Instant::now());
            }
        }

        // Auth failure spike
        let auth_errors = entries
            .iter()
            .filter(|e| {
                e.get("source").and_then(|v| v.as_str()) == Some("auth")
                    && e.get("level").and_then(|v| v.as_str()) == Some("error")
            })
            .count();

        if auth_errors > 10 && !target.webhooks.is_empty() {
            let payload = serde_json::json!({
                "event": "kxn_log_anomaly",
                "timestamp": now.to_rfc3339(),
                "target": target.name,
                "anomaly": "auth_failure_spike",
                "auth_error_count": auth_errors,
            });
            for url in &target.webhooks {
                let _ = client.post(url).json(&payload).send().await;
            }
        }

        tokio::time::sleep(Duration::from_secs(target.interval)).await;
    }
}

async fn serve_log_metrics(port: u16, metrics: SharedLogMetrics) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    loop {
        let (mut socket, _) = listener.accept().await?;
        let m = metrics.read().await;

        let mut body = String::new();
        body.push_str("# HELP kxn_logs_total Total log entries collected\n");
        body.push_str("# TYPE kxn_logs_total gauge\n");
        for lm in m.iter() {
            for (level, count) in &lm.by_level {
                body.push_str(&format!(
                    "kxn_logs_total{{target=\"{}\",level=\"{}\"}} {}\n",
                    lm.target, level, count
                ));
            }
        }

        body.push_str("# HELP kxn_logs_by_source Log entries by source\n");
        body.push_str("# TYPE kxn_logs_by_source gauge\n");
        for lm in m.iter() {
            for (source, count) in &lm.by_source {
                body.push_str(&format!(
                    "kxn_logs_by_source{{target=\"{}\",source=\"{}\"}} {}\n",
                    lm.target, source, count
                ));
            }
        }

        body.push_str("# HELP kxn_logs_collection_duration_ms Collection duration\n");
        body.push_str("# TYPE kxn_logs_collection_duration_ms gauge\n");
        for lm in m.iter() {
            body.push_str(&format!(
                "kxn_logs_collection_duration_ms{{target=\"{}\"}} {}\n",
                lm.target, lm.duration_ms
            ));
        }

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let _ = socket.write_all(response.as_bytes()).await;
    }
}

/// Transform `pod_logs` gather output into entry dicts matching the SSH `logs`
/// entry shape (`{level, source, message, unit, timestamp?}`).
///
/// Input shape (one item per pod, produced by KubernetesProvider::gather_pod_logs):
///
/// ```json
/// [
///   {"pod":"web-1","namespace":"default","phase":"Running",
///    "error_lines":3,"logs":["2026-04-21T10:00:00.000Z ERROR x","WARN y","panic!"]}
/// ]
/// ```
///
/// Output: one entry per log line, with `source = "<ns>/<pod>"`, `unit = pod`,
/// `level` inferred from keyword matching, and `timestamp` if the line starts
/// with an RFC3339 timestamp (K8s `timestamps=true` format).
fn flatten_kubernetes_pod_logs(gathered: &[Value]) -> Vec<Value> {
    let mut out = Vec::new();
    for item in gathered {
        let pod = item.get("pod").and_then(|v| v.as_str()).unwrap_or("");
        let ns = item.get("namespace").and_then(|v| v.as_str()).unwrap_or("");
        let source = format!("{}/{}", ns, pod);
        let Some(lines) = item.get("logs").and_then(|v| v.as_array()) else {
            continue;
        };
        for line in lines {
            let Some(raw) = line.as_str() else { continue };
            let (timestamp_opt, msg) = parse_k8s_log_timestamp(raw);
            let level = infer_level(msg);
            let mut entry = serde_json::json!({
                "source": source,
                "unit": pod,
                "level": level,
                "message": msg,
            });
            if let (Some(ts), Some(obj)) = (timestamp_opt, entry.as_object_mut()) {
                obj.insert("timestamp".to_string(), serde_json::Value::String(ts));
            }
            out.push(entry);
        }
    }
    out
}

/// Try to split a K8s log line into `(Some(timestamp_rfc3339), rest)`.
///
/// K8s appends `?timestamps=true` to the log URL, which prepends each line
/// with an RFC3339 timestamp followed by a space:
///   `2024-01-15T10:30:00.123456789Z Some log message`
///
/// Returns `(None, original_line)` if no timestamp prefix is found, so the
/// caller can continue gracefully.
fn parse_k8s_log_timestamp(line: &str) -> (Option<String>, &str) {
    // The timestamp ends at the first space. A valid K8s timestamp contains
    // 'T' and ends with 'Z' (UTC) or a numeric offset.
    let Some(space_pos) = line.find(' ') else {
        return (None, line);
    };
    let candidate = &line[..space_pos];
    // Quick structural check: must contain 'T' and end with 'Z' or '+'/'-' offset
    let looks_like_ts = candidate.contains('T')
        && (candidate.ends_with('Z') || candidate.rfind(['+', '-']).map(|i| i > 10).unwrap_or(false));
    if !looks_like_ts {
        return (None, line);
    }
    // Validate by attempting to parse as RFC3339
    match chrono::DateTime::parse_from_rfc3339(candidate) {
        Ok(_) => (Some(candidate.to_string()), &line[space_pos + 1..]),
        Err(_) => (None, line),
    }
}

/// Infer a log level from a line content. Matches common keywords
/// case-insensitively — "error", "fatal", "panic", "exception" → error,
/// "warn" → warning, otherwise info.
fn infer_level(line: &str) -> &'static str {
    let lower = line.to_ascii_lowercase();
    if lower.contains("error")
        || lower.contains("fatal")
        || lower.contains("panic")
        || lower.contains("exception")
    {
        "error"
    } else if lower.contains("warn") {
        "warning"
    } else {
        "info"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_level() {
        assert_eq!(infer_level("ERROR: failed to connect"), "error");
        assert_eq!(infer_level("level=fatal something"), "error");
        assert_eq!(infer_level("thread panicked at line 42"), "error");
        assert_eq!(infer_level("uncaught exception"), "error");
        assert_eq!(infer_level("[WARN] disk almost full"), "warning");
        assert_eq!(infer_level("starting server on :8080"), "info");
    }

    #[test]
    fn test_parse_k8s_log_timestamp_valid() {
        let (ts, msg) = parse_k8s_log_timestamp("2024-01-15T10:30:00.123456789Z ERROR boom");
        assert_eq!(ts.as_deref(), Some("2024-01-15T10:30:00.123456789Z"));
        assert_eq!(msg, "ERROR boom");
    }

    #[test]
    fn test_parse_k8s_log_timestamp_no_ts() {
        let (ts, msg) = parse_k8s_log_timestamp("WARN no timestamp here");
        assert!(ts.is_none());
        assert_eq!(msg, "WARN no timestamp here");
    }

    #[test]
    fn test_parse_k8s_log_timestamp_no_space() {
        let (ts, msg) = parse_k8s_log_timestamp("nospace");
        assert!(ts.is_none());
        assert_eq!(msg, "nospace");
    }

    #[test]
    fn test_flatten_kubernetes_pod_logs_basic() {
        let gathered = vec![serde_json::json!({
            "pod": "web-1",
            "namespace": "default",
            "phase": "Running",
            "error_lines": 2,
            "logs": [
                "2026-04-21T10:00:00Z ERROR boom",
                "2026-04-21T10:00:01Z WARN slow",
                "2026-04-21T10:00:02Z info ok",
            ]
        })];
        let out = flatten_kubernetes_pod_logs(&gathered);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0]["source"], "default/web-1");
        assert_eq!(out[0]["unit"], "web-1");
        assert_eq!(out[0]["level"], "error");
        assert_eq!(out[0]["timestamp"], "2026-04-21T10:00:00Z");
        assert_eq!(out[0]["message"], "ERROR boom");
        assert_eq!(out[1]["level"], "warning");
        assert_eq!(out[2]["level"], "info");
    }

    #[test]
    fn test_flatten_kubernetes_pod_logs_no_timestamp() {
        // Lines without a timestamp prefix: timestamp field must be absent.
        let gathered = vec![serde_json::json!({
            "pod": "app","namespace": "prod",
            "logs": ["WARN no ts here"]
        })];
        let out = flatten_kubernetes_pod_logs(&gathered);
        assert_eq!(out.len(), 1);
        assert!(out[0].get("timestamp").is_none());
        assert_eq!(out[0]["message"], "WARN no ts here");
    }

    #[test]
    fn test_flatten_kubernetes_pod_logs_multiple_pods() {
        let gathered = vec![
            serde_json::json!({"pod":"a","namespace":"ns1","logs":["error x"]}),
            serde_json::json!({"pod":"b","namespace":"ns2","logs":["warn y","info z"]}),
        ];
        let out = flatten_kubernetes_pod_logs(&gathered);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0]["source"], "ns1/a");
        assert_eq!(out[1]["source"], "ns2/b");
        assert_eq!(out[2]["source"], "ns2/b");
    }

    #[test]
    fn test_flatten_kubernetes_pod_logs_missing_logs() {
        // Pod without `logs` field (e.g. phase=Pending, filter dropped it upstream)
        // must not produce entries or crash.
        let gathered = vec![serde_json::json!({"pod":"x","namespace":"default","phase":"Pending"})];
        let out = flatten_kubernetes_pod_logs(&gathered);
        assert!(out.is_empty());
    }

    #[test]
    fn test_flatten_kubernetes_pod_logs_non_string_line() {
        // Defensive: a non-string log entry should be silently skipped.
        let gathered = vec![serde_json::json!({
            "pod":"x","namespace":"ns","logs":[42, "real error"]
        })];
        let out = flatten_kubernetes_pod_logs(&gathered);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["message"], "real error");
    }
}
