use anyhow::Result;
use clap::Args;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

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
            "No SSH targets found. Use `kxn logs ssh://user@host` or add SSH [[targets]] to kxn.toml"
        );
    }

    let metrics: SharedLogMetrics = Arc::new(RwLock::new(Vec::new()));

    if let Some(port) = args.metrics_port {
        let m = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_log_metrics(port, m).await {
                eprintln!("Metrics server error: {}", e);
            }
        });
        eprintln!("Prometheus metrics at http://0.0.0.0:{}/metrics", port);
    }

    eprintln!(
        "kxn logs | {} target(s) | save={}",
        targets.len(),
        save_configs.len()
    );
    for t in &targets {
        eprintln!("  {} | interval={}s", t.name, t.interval);
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
            eprintln!("Target error: {}", e);
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
        if provider != "ssh" {
            anyhow::bail!(
                "kxn logs only supports SSH targets, got '{}'. Use ssh://user@host",
                provider
            );
        }
        return Ok(vec![LogTarget {
            name: uri.clone(),
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
        let _provider = match &tc.provider {
            Some(p) if p == "ssh" => p.clone(),
            Some(_) => continue, // skip non-SSH targets
            None => {
                // Try to infer from URI
                if let Some(ref uri) = tc.uri {
                    if uri.starts_with("ssh://") {
                        "ssh".to_string()
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

        // Gather logs via SSH
        let provider = match create_native_provider("ssh", target.provider_config.clone()) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[{}] {} SSH connection error: {}", timestamp(), target.name, e);
                tokio::time::sleep(Duration::from_secs(target.interval)).await;
                continue;
            }
        };

        let gathered = match provider.gather("logs").await {
            Ok(items) => items,
            Err(e) => {
                eprintln!("[{}] {} gather error: {}", timestamp(), target.name, e);
                tokio::time::sleep(Duration::from_secs(target.interval)).await;
                continue;
            }
        };

        // Extract entries from the summary object
        let entries: Vec<&Value> = gathered
            .iter()
            .filter_map(|item| item.get("entries"))
            .filter_map(|e| e.as_array())
            .flat_map(|arr| arr.iter())
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
                eprintln!(
                    "[{}] {} #{} {} | {} logs (err={} warn={}) | {}ms",
                    timestamp(),
                    target.name,
                    iteration,
                    status,
                    entries.len(),
                    error_count,
                    warning_count,
                    duration_ms,
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
                eprintln!("[{}] {} save error: {}", timestamp(), target.name, e);
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

fn timestamp() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}
