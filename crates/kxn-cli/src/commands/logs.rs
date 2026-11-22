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
    /// Target URI: ssh://user@host, k8s://<context>[/<namespace>[/<pod>]]
    /// (the pod is a name prefix, e.g. k8s://prod/monitoring/kxn), or a database:
    /// postgresql://, mysql://, mongodb://, oracle://
    #[arg()]
    pub target: Option<String>,

    /// Keep printing new log lines
    #[arg(short = 'f', long)]
    pub follow: bool,

    /// Lines printed first (per container for Kubernetes targets)
    #[arg(long, default_value = "100")]
    pub tail: u32,

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

    /// Stream logs in real-time (only supported for `kubernetes://` targets).
    ///
    /// When set, kxn opens a long-lived watch on the cluster pods and tails
    /// each container's log via `/pods/{name}/log?follow=true`. Lines are
    /// batched and forwarded to the configured `[[save]]` backends (Postgres,
    /// Loki, Elasticsearch, etc.) — replacing the need for a separate log
    /// shipper such as Promtail or Alloy.
    #[arg(long)]
    pub stream: bool,

    /// Maximum number of lines buffered before flushing to save backends
    /// (only used in `--stream` mode).
    #[arg(long, default_value = "100")]
    pub stream_batch_lines: usize,

    /// Maximum buffering delay in milliseconds before flushing
    /// (only used in `--stream` mode).
    #[arg(long, default_value = "1000")]
    pub stream_batch_ms: u64,
}

/// Providers whose `logs` object (or `pod_logs` for Kubernetes) kxn logs can read.
const LOG_PROVIDERS: &[&str] = &["ssh", "kubernetes", "postgresql", "mysql", "mongodb", "oracle"];

/// The log provider a URI points to, if any.
fn log_provider_for_uri(uri: &str) -> Option<&'static str> {
    let scheme = uri.split("://").next()?;
    let provider = match scheme {
        "k8s" | "kubernetes" => "kubernetes",
        "postgres" => "postgresql",
        "mongodb+srv" => "mongodb",
        other => other,
    };
    LOG_PROVIDERS.iter().copied().find(|p| *p == provider)
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
    // `kxn logs k8s://ctx/ns/pod`: print the lines themselves, like
    // `kubectl logs`. The collection daemon (save backends, metrics,
    // --stream) keeps its behaviour.
    if let Some(uri) = &args.target {
        let (provider, config) = parse_target_uri(uri).map_err(|e| anyhow::anyhow!("{}", e))?;
        let daemon = args.stream || args.metrics_port.is_some() || !args.webhook.is_empty();
        let has_saves = {
            let file = args.config_file.clone().or(global_config.clone());
            file.and_then(|p| parse_config(&p).ok()).is_some_and(|c| !c.save.is_empty())
        };
        if !daemon && !has_saves {
            if provider == "kubernetes" {
                return view_kubernetes_logs(&args, config).await;
            }
            if LOG_PROVIDERS.contains(&provider.as_str()) {
                return view_provider_logs(&args, &provider, config).await;
            }
        }
    }
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

        if args.stream && target.provider_kind == "kubernetes" {
            let batch_lines = args.stream_batch_lines;
            let batch_ms = args.stream_batch_ms;
            handles.push(tokio::spawn(async move {
                run_k8s_log_stream(target, metrics, save_cfgs, batch_lines, batch_ms).await
            }));
        } else {
            handles.push(tokio::spawn(async move {
                run_log_loop(target, metrics, output, error_threshold, filter, save_cfgs).await
            }));
        }
    }

    for h in handles {
        if let Err(e) = h.await? {
            error!(error = %e, "Log target task error");
        }
    }

    Ok(())
}

/// Print a Kubernetes pod's (or namespace's) log lines, then follow them
/// with `-f`.
async fn view_kubernetes_logs(args: &LogsArgs, config: Value) -> Result<()> {
    use std::io::IsTerminal;
    let pod_prefix = config.get("K8S_POD").and_then(|v| v.as_str()).map(String::from);
    let provider = kxn_providers::native::kubernetes::KubernetesProvider::new(config)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let filter = LogFilter {
        levels: args.level.clone(),
        sources: args.source.clone(),
        pattern: args.pattern.as_ref().map(|p| regex::Regex::new(p)).transpose()?,
    };
    let color = std::io::stdout().is_terminal();
    let multi_pod = pod_prefix.is_none();
    let mut since: HashMap<String, String> = HashMap::new();
    let mut printed_any = false;

    loop {
        let lines = provider
            .pod_log_lines(pod_prefix.as_deref(), args.tail, &since)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        for (source, container, raw) in lines {
            let (ts, msg) = parse_k8s_log_timestamp(&raw);
            if let Some(ts) = &ts {
                since.insert(format!("{}/{}", source, container), ts.clone());
            }
            let level = infer_level(msg);
            let entry = serde_json::json!({ "source": source, "level": level, "message": msg });
            if !filter.matches(&entry) {
                continue;
            }
            printed_any = true;
            let time = ts.as_deref().and_then(|t| t.get(11..19)).unwrap_or("");
            let who = if multi_pod { format!("{} ", source) } else { String::new() };
            if color {
                let c = match level {
                    "error" => "\x1b[31m",
                    "warning" => "\x1b[33m",
                    _ => "\x1b[2m",
                };
                println!("\x1b[2m{}\x1b[0m {}{}{}\x1b[0m", time, who, c, msg);
            } else {
                println!("{} {}{}", time, who, msg);
            }
        }
        if !args.follow {
            if !printed_any {
                eprintln!("no matching log lines");
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Print the log entries of a server or database (`logs` object), then poll
/// for new ones with `-f`.
async fn view_provider_logs(args: &LogsArgs, provider_name: &str, config: Value) -> Result<()> {
    use std::io::IsTerminal;
    let provider = create_native_provider(provider_name, config).map_err(|e| anyhow::anyhow!("{}", e))?;
    let filter = LogFilter {
        levels: args.level.clone(),
        sources: args.source.clone(),
        pattern: args.pattern.as_ref().map(|p| regex::Regex::new(p)).transpose()?,
    };
    let color = std::io::stdout().is_terminal();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut printed_any = false;
    loop {
        let gathered = provider.gather("logs").await.map_err(|e| anyhow::anyhow!("{}", e))?;
        let entries: Vec<Value> = gathered
            .iter()
            .filter_map(|item| item.get("entries").and_then(|e| e.as_array()))
            .flat_map(|a| a.iter().cloned())
            .collect();
        // Filter first, then keep the last `--tail` of what matched.
        let matching: Vec<Value> = entries.into_iter().filter(|e| filter.matches(e)).collect();
        let skip = matching.len().saturating_sub(args.tail as usize);
        for entry in matching.into_iter().skip(skip) {
            let line = format_log_entry(&entry);
            if !seen.insert(line.clone()) {
                continue;
            }
            printed_any = true;
            let level = entry.get("level").and_then(|v| v.as_str()).unwrap_or("info");
            if color {
                let c = match level {
                    "error" | "fatal" | "critical" => "\x1b[31m",
                    "warning" | "warn" => "\x1b[33m",
                    _ => "",
                };
                println!("{}{}\x1b[0m", c, line);
            } else {
                println!("{}", line);
            }
        }
        if !args.follow {
            if !printed_any {
                eprintln!("no matching log lines");
                if provider_name == "postgresql" {
                    eprintln!(
                        "PostgreSQL logs are read from the server's log file: it needs logging_collector = on \
                         and a role allowed to read it (superuser or pg_read_server_files)"
                    );
                }
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// `timestamp source level message` for one entry of a `logs` object.
fn format_log_entry(entry: &Value) -> String {
    let text = |k: &str| -> String {
        match entry.get(k) {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => String::new(),
            Some(other) => other.to_string(),
        }
    };
    let mut parts: Vec<String> = Vec::new();
    for k in ["timestamp", "source", "level"] {
        let v = text(k);
        if !v.is_empty() {
            parts.push(v);
        }
    }
    let unit = text("unit");
    if !unit.is_empty() {
        parts.push(format!("{unit}:"));
    }
    parts.push(text("message").replace('\n', " "));
    parts.join(" ")
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
        if !LOG_PROVIDERS.contains(&provider.as_str()) {
            anyhow::bail!(
                "kxn logs reads ssh://, k8s://, postgresql://, mysql://, mongodb:// and oracle:// targets, got '{}'",
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
            Some(p) if LOG_PROVIDERS.contains(&p.as_str()) => p.clone(),
            Some(_) => continue, // skip other providers
            None => match tc.uri.as_deref().and_then(log_provider_for_uri) {
                Some(p) => p.to_string(),
                None => continue,
            },
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
    use std::sync::LazyLock;
    static ANSI: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").expect("ansi regex"));
    // The first level word standing on its own decides. Matching "error"
    // anywhere made `idx_scans_error` or `0 errors` an error line, and a
    // line tagged INFO that mentions an error later an error too.
    static LEVEL: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"(?i)\b(fatal|panic|panicked|crit|critical|emerg|alert|err|error|exception|warn|warning|info|notice|debug|trace)\b",
        )
        .expect("level regex")
    });
    let clean = ANSI.replace_all(line, "");
    match LEVEL
        .captures(&clean)
        .map(|c| c[1].to_ascii_lowercase())
        .as_deref()
    {
        Some("warn" | "warning") => "warning",
        Some("info" | "notice" | "debug" | "trace") | None => "info",
        Some(_) => "error",
    }
}

/// Stream Kubernetes pod logs in real-time and forward to save backends.
///
/// Replaces the per-interval `gather("pod_logs")` loop with a long-lived
/// pod watch + per-container log follow. Lines are batched (by count or
/// elapsed time) before each save call to keep insert throughput high.
async fn run_k8s_log_stream(
    target: LogTarget,
    metrics: SharedLogMetrics,
    save_configs: Arc<Vec<kxn_rules::SaveConfig>>,
    batch_lines: usize,
    batch_ms: u64,
) -> Result<()> {
    use kxn_providers::native::kubernetes_log_tail::{tail_pods, LogLine, TailConfig};
    use tokio::sync::mpsc;

    // Resolve TailConfig from the kubernetes provider config (same env-or-config
    // lookup that KubernetesProvider::new uses, so behavior matches the gather path).
    let cfg = &target.provider_config;
    let api_url = cfg
        .get("K8S_API_URL")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            std::env::var("K8S_API_URL")
                .ok()
                .or_else(|| std::env::var("KUBERNETES_SERVICE_HOST").ok().map(|h| {
                    let port = std::env::var("KUBERNETES_SERVICE_PORT")
                        .unwrap_or_else(|_| "443".into());
                    format!("https://{}:{}", h, port)
                }))
        })
        .unwrap_or_else(|| "https://kubernetes.default.svc".into());

    let token_file = cfg
        .get("K8S_TOKEN_FILE")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("K8S_TOKEN_FILE").ok())
        .unwrap_or_else(|| "/var/run/secrets/kubernetes.io/serviceaccount/token".into());
    let ca_file = cfg
        .get("K8S_CA_FILE")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("K8S_CA_FILE").ok())
        .unwrap_or_else(|| "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt".into());

    let token = cfg
        .get("K8S_TOKEN")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("K8S_TOKEN").ok())
        .or_else(|| std::fs::read_to_string(&token_file).ok());

    let insecure = cfg
        .get("K8S_INSECURE")
        .and_then(|v| v.as_str())
        .map(|s| s == "true" || s == "1")
        .or_else(|| std::env::var("K8S_INSECURE").ok().map(|s| s == "true" || s == "1"))
        .unwrap_or(false);

    let ca_pem = if insecure { None } else { std::fs::read(&ca_file).ok() };

    let namespace = cfg
        .get("K8S_NAMESPACE")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("K8S_NAMESPACE").ok());

    // Comma-separated namespace list. Typical setting on managed clusters
    // where CoreDNS / konnectivity-agent dominate volume:
    //   K8S_EXCLUDE_NAMESPACES=kube-system
    let exclude_namespaces: Vec<String> = cfg
        .get("K8S_EXCLUDE_NAMESPACES")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("K8S_EXCLUDE_NAMESPACES").ok())
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default();

    // Comma-separated regex list, e.g.
    //   K8S_EXCLUDE_POD_PATTERNS=^konnectivity-agent-,^coredns-
    let exclude_pod_patterns: Vec<regex::Regex> = cfg
        .get("K8S_EXCLUDE_POD_PATTERNS")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("K8S_EXCLUDE_POD_PATTERNS").ok())
        .map(|s| {
            s.split(',')
                .map(|p| p.trim())
                .filter(|p| !p.is_empty())
                .filter_map(|p| match regex::Regex::new(p) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        warn!(
                            pattern = %p,
                            error = %e,
                            "K8S_EXCLUDE_POD_PATTERNS: invalid regex, skipping"
                        );
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    if !exclude_namespaces.is_empty() || !exclude_pod_patterns.is_empty() {
        info!(
            exclude_namespaces = ?exclude_namespaces,
            exclude_pod_patterns = exclude_pod_patterns.len(),
            "k8s log tail exclusions active"
        );
    }

    let tail_cfg = TailConfig {
        api_url,
        token,
        ca_pem,
        namespace: namespace.clone(),
        insecure,
        exclude_namespaces,
        exclude_pod_patterns,
    };

    info!(
        target = %target.name,
        namespace = ?namespace,
        batch_lines,
        batch_ms,
        "kxn k8s log stream starting"
    );

    let (tx, mut rx) = mpsc::channel::<LogLine>(8192);

    // Spawn the pod-watcher / log-follower task. It runs until the channel is
    // closed (which happens when this function returns and `rx` is dropped).
    let target_name = target.name.clone();
    let watcher = tokio::spawn(async move {
        if let Err(e) = tail_pods(tail_cfg, tx).await {
            error!(target = %target_name, error = %e, "pod watch terminated");
        }
    });

    let batch_window = Duration::from_millis(batch_ms);
    let mut buffer: Vec<LogLine> = Vec::with_capacity(batch_lines);
    let mut total: usize = 0;
    let mut last_flush = Instant::now();

    loop {
        let timeout = batch_window.saturating_sub(last_flush.elapsed());
        let recv = tokio::time::timeout(timeout, rx.recv()).await;
        match recv {
            Ok(Some(line)) => {
                buffer.push(line);
                if buffer.len() >= batch_lines {
                    flush_stream_batch(&target.name, &mut buffer, &save_configs, &metrics, &mut total).await;
                    last_flush = Instant::now();
                }
            }
            Ok(None) => {
                // Sender dropped; flush remainder and exit.
                if !buffer.is_empty() {
                    flush_stream_batch(&target.name, &mut buffer, &save_configs, &metrics, &mut total).await;
                }
                break;
            }
            Err(_elapsed) => {
                if !buffer.is_empty() {
                    flush_stream_batch(&target.name, &mut buffer, &save_configs, &metrics, &mut total).await;
                }
                last_flush = Instant::now();
            }
        }
    }

    watcher.abort();
    Ok(())
}

async fn flush_stream_batch(
    target_name: &str,
    buffer: &mut Vec<kxn_providers::native::kubernetes_log_tail::LogLine>,
    save_configs: &[kxn_rules::SaveConfig],
    metrics: &SharedLogMetrics,
    total: &mut usize,
) {
    let batch_id = format!("stream-{}", chrono::Utc::now().format("%Y%m%dT%H%M%S%.3f"));
    let records: Vec<LogRecord> = buffer
        .drain(..)
        .map(|l| {
            let mut tags = HashMap::new();
            tags.insert("namespace".to_string(), l.namespace.clone());
            tags.insert("pod".to_string(), l.pod.clone());
            tags.insert("container".to_string(), l.container.clone());
            if let Some(node) = &l.node {
                tags.insert("node".to_string(), node.clone());
            }
            LogRecord {
                target: target_name.to_string(),
                source: "kubernetes".to_string(),
                level: infer_level_from_message(&l.message),
                message: l.message,
                host: l.node,
                unit: Some(format!("{}/{}/{}", l.namespace, l.pod, l.container)),
                collected_at: l.time,
                batch_id: batch_id.clone(),
                tags,
            }
        })
        .collect();

    *total += records.len();

    if !save_configs.is_empty() {
        if let Err(e) = crate::save::save_logs(save_configs, &records).await {
            warn!(target = %target_name, error = %e, "log save failed");
        }
    }

    {
        let mut m = metrics.write().await;
        m.retain(|lm| lm.target != target_name);
        m.push(LogMetrics {
            target: target_name.to_string(),
            total: *total,
            by_level: HashMap::new(),
            by_source: HashMap::new(),
            duration_ms: 0,
        });
    }
}

fn infer_level_from_message(msg: &str) -> String {
    infer_level(msg).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_log_entry() {
        let e = serde_json::json!({"timestamp": "2026-11-22T21:47:23Z", "source": "mongo_global",
            "level": "warning", "message": "Overriding max connections"});
        assert_eq!(format_log_entry(&e), "2026-11-22T21:47:23Z mongo_global warning Overriding max connections");
        let j = serde_json::json!({"source": "journal", "unit": "sshd", "message": "Accepted publickey"});
        assert_eq!(format_log_entry(&j), "journal sshd: Accepted publickey");
        let o = serde_json::json!({"source": "slow_op", "level": "warning", "message": {"op": "query"}});
        assert_eq!(format_log_entry(&o), "slow_op warning {\"op\":\"query\"}");
    }

    #[test]
    fn test_log_provider_for_uri() {
        assert_eq!(log_provider_for_uri("ssh://root@h"), Some("ssh"));
        assert_eq!(log_provider_for_uri("k8s://prod/ns"), Some("kubernetes"));
        assert_eq!(log_provider_for_uri("postgres://u@db/x"), Some("postgresql"));
        assert_eq!(log_provider_for_uri("mongodb+srv://c.example.net"), Some("mongodb"));
        assert_eq!(log_provider_for_uri("oracle://u@db:1521/ORCL"), Some("oracle"));
        assert_eq!(log_provider_for_uri("gcp://p"), None);
    }

    #[test]
    fn test_infer_level() {
        assert_eq!(infer_level("ERROR: failed to connect"), "error");
        assert_eq!(infer_level("level=fatal something"), "error");
        assert_eq!(infer_level("thread panicked at line 42"), "error");
        assert_eq!(infer_level("uncaught exception"), "error");
        assert_eq!(infer_level("[WARN] disk almost full"), "warning");
        assert_eq!(infer_level("starting server on :8080"), "info");
        // A level word must stand on its own, and the first one decides.
        assert_eq!(infer_level("NOTICE: relation \"idx_scans_error\" already exists"), "info");
        assert_eq!(infer_level("\x1b[32m INFO\x1b[0m tokio_postgres: query error retried"), "info");
        assert_eq!(infer_level("{\"level\":\"warn\",\"msg\":\"slow\"}"), "warning");
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
