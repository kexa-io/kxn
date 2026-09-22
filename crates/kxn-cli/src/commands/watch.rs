use anyhow::{Context, Result};
use clap::Args;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use kxn_core::{check_rule, ConditionNode, Rule, SubResultScan};
use kxn_providers::{create_native_provider, native_provider_names};
use kxn_rules::{parse_config, parse_directory, resolve_rules, RuleFilter, RuleFile};

use super::extract_resources;

#[derive(Args)]
pub struct WatchArgs {
    /// Provider name (e.g. ssh, postgresql, mysql, mongodb, http)
    #[arg(short, long)]
    pub provider: Option<String>,

    /// Provider config JSON
    #[arg(long = "provider-config", default_value = "{}", id = "provider_config")]
    pub provider_config_json: String,

    /// Path to kxn.toml config file
    #[arg(long = "config-file")]
    pub config_file: Option<PathBuf>,

    /// Path to TOML rules directory
    #[arg(short = 'R', long = "rules")]
    pub rules: Option<PathBuf>,

    /// Scan interval in seconds
    #[arg(short = 'n', long, default_value = "60")]
    pub interval: u64,

    /// Webhook URL for alerts (POST JSON on new failures)
    #[arg(short, long)]
    pub webhook: Vec<String>,

    /// Minimum alert interval in seconds (dedup window)
    #[arg(long, default_value = "3600")]
    pub alert_interval: u64,

    /// Expose Prometheus metrics on this port (e.g. 9090)
    #[arg(long)]
    pub metrics_port: Option<u16>,

    /// Also expose per-container and per-node CPU/RAM gauges on the metrics
    /// endpoint (kxn_pod_cpu_millicores, kxn_pod_memory_mib,
    /// kxn_pod_*_request/limit_*, kxn_node_*). Kubernetes targets only.
    /// Off by default: adds 2–6 series per container.
    #[arg(long = "metrics-resources", requires = "metrics_port")]
    pub metrics_resources: bool,

    /// Output format: text, json, prometheus
    #[arg(short, long, default_value = "text")]
    pub output: String,

    /// Include rules matching glob patterns
    #[arg(short, long = "include")]
    pub include: Vec<String>,

    /// Exclude rules matching glob patterns
    #[arg(short = 'x', long = "exclude")]
    pub exclude: Vec<String>,

    /// Filter by tags
    #[arg(short, long = "tag")]
    pub tags: Vec<String>,

    /// Minimum severity level
    #[arg(short = 'l', long = "min-level")]
    pub min_level: Option<u8>,

    /// Show verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

/// Rich violation with full context for AI agent remediation
#[derive(Clone, serde::Serialize)]
pub struct Violation {
    pub rule: String,
    pub description: String,
    pub level: u8,
    pub level_label: String,
    pub object_type: String,
    pub object_content: Value,
    pub conditions: Value,
    pub messages: Vec<String>,
    pub provider: String,
    pub target: String,
    pub remediation_context: Value,
    /// Per-rule webhooks (from rule definition)
    pub rule_webhooks: Vec<String>,
    /// Compliance framework mappings
    pub compliance: Vec<kxn_core::ComplianceRef>,
    /// Remediation actions defined on the rule
    pub remediation_actions: Vec<kxn_core::RemediationAction>,
}

/// Alert dedup entry
struct AlertEntry {
    last_alerted: Instant,
}

/// Stable fingerprint of a violation's resource, so the dedup cache key
/// distinguishes *which* resource violated a rule, not just the rule
/// itself. Without this, two different resources violating the same rule
/// in the same scan (e.g. two different pods both tripping
/// `k8s-pod-high-restart-count`) collapse onto one cache entry — the
/// first insert makes the second look like a dedup hit and its alert is
/// silently dropped, even though it's a distinct, real violation.
fn resource_fingerprint(content: &Value) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    content.to_string().hash(&mut hasher);
    hasher.finish()
}

/// POST a webhook payload, logging (not swallowing) delivery failures.
/// This is the only alerting mechanism the tool has — a network blip or
/// a rate-limited endpoint used to drop the alert with zero trace of it
/// ever happening.
async fn post_webhook(client: &reqwest::Client, url: &str, body: &Value) {
    if let Err(e) = client.post(url).json(body).send().await {
        eprintln!("[{}] webhook delivery failed url={}: {}", timestamp(), url, e);
    }
}

/// Per-target scan summary
#[derive(Clone, Default, serde::Serialize)]
pub struct ScanSummary {
    pub target: String,
    pub provider: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub by_level: [usize; 4],
    pub violations: Vec<Violation>,
    pub duration_ms: u128,
}

/// Global metrics aggregating all targets
#[derive(Clone, Default)]
struct GlobalMetrics {
    summaries: Vec<ScanSummary>,
    /// Per-target resource gauge samples (`--metrics-resources`), keyed by
    /// target name then metric family, so the exposition can emit one
    /// HELP/TYPE header per family across all targets.
    resource_samples: HashMap<String, std::collections::BTreeMap<&'static str, Vec<String>>>,
}

type SharedMetrics = Arc<RwLock<GlobalMetrics>>;

pub async fn run(mut args: WatchArgs, global_config: Option<PathBuf>) -> Result<()> {
    // Merge global -c/--config with watch --config-file (global takes precedence)
    if args.config_file.is_none() {
        args.config_file = global_config;
    }
    // Try to load config file for multi-target mode
    let config_path = args.config_file.clone().or_else(|| {
        let default = PathBuf::from("kxn.toml");
        if default.exists() {
            Some(default)
        } else {
            None
        }
    });

    let mut scan_config = config_path
        .as_ref()
        .map(|p| parse_config(p).map_err(|e| anyhow::anyhow!("{}", e)))
        .transpose()?;

    // Resolve ${secret:...} placeholders in target URIs and config values
    if let Some(ref mut cfg) = scan_config {
        resolve_target_secrets(cfg).await?;
    }

    let targets = match resolve_targets(&args, &scan_config) {
        Ok(t) => t,
        Err(e) => {
            let error_msg = format!("{}", e);
            eprintln!("Configuration error: {}", error_msg);
            // Send webhook if configured
            if !args.webhook.is_empty() {
                let client = crate::alerts::shared_client();
                let payload = build_error_webhook_payload(
                    "global",
                    "config",
                    "config_error",
                    &error_msg,
                    0,
                );
                for url in &args.webhook {
                    post_webhook(client, url, &payload).await;
                }
            }
            return Err(e);
        }
    };
    if targets.is_empty() {
        let msg = "No targets configured. Use --provider or add [[targets]] to kxn.toml";
        if !args.webhook.is_empty() {
            let client = crate::alerts::shared_client();
            let payload = build_error_webhook_payload("global", "config", "config_error", msg, 0);
            for url in &args.webhook {
                post_webhook(client, url, &payload).await;
            }
        }
        anyhow::bail!("{}", msg);
    }

    let metrics: SharedMetrics = Arc::new(RwLock::new(GlobalMetrics::default()));

    // Start metrics server if requested
    if let Some(port) = args.metrics_port {
        let m = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_metrics(port, m).await {
                eprintln!("Metrics server error: {}", e);
            }
        });
        eprintln!("Prometheus metrics at http://0.0.0.0:{}/metrics", port);
    }

    let save_configs: Arc<Vec<kxn_rules::SaveConfig>> = Arc::new(
        scan_config
            .as_ref()
            .map(|c| c.save.clone())
            .unwrap_or_default(),
    );

    let total_webhooks = if args.webhook.is_empty() {
        targets.iter().map(|t| t.webhooks.len()).max().unwrap_or(0)
    } else {
        args.webhook.len()
    };
    eprintln!(
        "kxn watch | {} target(s) | webhooks={} | save={}",
        targets.len(),
        total_webhooks,
        save_configs.len()
    );
    for t in &targets {
        eprintln!(
            "  {} | provider={} | rules={} | interval={}s",
            t.name,
            t.provider,
            t.rule_count,
            t.interval
        );
    }

    // Spawn one task per target
    let mut handles = Vec::new();
    for target in targets {
        let metrics = metrics.clone();
        let opts = LoopOptions {
            output: args.output.clone(),
            verbose: args.verbose,
            resource_metrics: args.metrics_resources,
        };
        let alert_interval = args.alert_interval;
        let global_webhooks = args.webhook.clone();
        let save_cfgs = save_configs.clone();

        handles.push(tokio::spawn(async move {
            run_target_loop(
                target,
                metrics,
                opts,
                alert_interval,
                global_webhooks,
                save_cfgs,
            )
            .await
        }));
    }

    // Wait for all (they loop forever unless error)
    for h in handles {
        if let Err(e) = h.await? {
            eprintln!("Target error: {}", e);
        }
    }

    Ok(())
}

/// Resolved target ready for monitoring
struct ResolvedTarget {
    name: String,
    provider: String,
    provider_config: Value,
    files: Vec<(String, RuleFile)>,
    rule_count: usize,
    interval: u64,
    webhooks: Vec<String>,
}

/// Resolve `${secret:...}` and `${ENV_VAR}` placeholders in target URIs and config values.
async fn resolve_target_secrets(config: &mut kxn_rules::ScanConfig) -> Result<()> {
    use kxn_rules::secrets::{self, SecretRef};

    async fn resolve_one(secret_ref: &SecretRef) -> Result<String> {
        match secret_ref {
            SecretRef::EnvVar(name) => std::env::var(name)
                .map_err(|_| anyhow::anyhow!("env var ${{{name}}} not set")),
            SecretRef::Azure { vault, name } => {
                kxn_providers::secrets::azure_keyvault::get_secret(vault, name).await
            }
            SecretRef::Aws { secret_name, key } => {
                kxn_providers::secrets::aws_secrets::get_secret(secret_name, key).await
            }
            SecretRef::Vault { path, key } => {
                kxn_providers::secrets::hashicorp_vault::get_secret(path, key).await
            }
            SecretRef::Gcp { project, name } => {
                kxn_providers::secrets::gcp_secrets::get_secret(project, name).await
            }
        }
    }

    for target in &mut config.targets {
        // Resolve URI
        if let Some(uri) = &target.uri {
            let refs = secrets::extract_refs(uri);
            if !refs.is_empty() {
                let mut resolved = std::collections::HashMap::new();
                for (placeholder, secret_ref) in &refs {
                    resolved.insert(placeholder.clone(), resolve_one(secret_ref).await?);
                }
                target.uri = Some(secrets::interpolate(uri, &resolved));
            }
        }

        // Resolve config string values
        let keys: Vec<String> = target.config.keys().cloned().collect();
        for key in keys {
            if let Some(toml::Value::String(s)) = target.config.get(&key).cloned() {
                let refs = secrets::extract_refs(&s);
                if !refs.is_empty() {
                    let mut resolved = std::collections::HashMap::new();
                    for (placeholder, secret_ref) in &refs {
                        resolved.insert(placeholder.clone(), resolve_one(secret_ref).await?);
                    }
                    target.config.insert(key, toml::Value::String(secrets::interpolate(&s, &resolved)));
                }
            }
        }
    }
    Ok(())
}

fn resolve_targets(
    args: &WatchArgs,
    scan_config: &Option<kxn_rules::ScanConfig>,
) -> Result<Vec<ResolvedTarget>> {
    let native_names = native_provider_names();

    // If --provider is given, always use single-target CLI mode
    // Otherwise, check for [[targets]] in config file (daemon mode)
    let provider = args.provider.clone();

    if provider.is_none() {
        if let Some(ref config) = scan_config {
            if !config.targets.is_empty() {
                return resolve_config_targets(config, args, &native_names);
            }
        }
    }

    let provider = provider
        .ok_or_else(|| anyhow::anyhow!("--provider required (or add [[targets]] to kxn.toml)"))?;

    if !native_names.contains(&provider.as_str()) {
        anyhow::bail!(
            "Watch mode only supports native providers: {}",
            native_names.join(", ")
        );
    }

    let provider_config: Value =
        serde_json::from_str(&args.provider_config_json).context("Invalid config JSON")?;

    let files = load_rules_cli(args, scan_config)?;
    if files.is_empty() {
        anyhow::bail!("No rules match the filter criteria.");
    }

    let rule_count = files.iter().map(|(_, rf)| rf.rules.len()).sum();

    Ok(vec![ResolvedTarget {
        name: provider.clone(),
        provider: provider.clone(),
        provider_config,
        files,
        rule_count,
        interval: args.interval,
        webhooks: args.webhook.clone(),
    }])
}

fn resolve_config_targets(
    config: &kxn_rules::ScanConfig,
    args: &WatchArgs,
    native_names: &[&str],
) -> Result<Vec<ResolvedTarget>> {
    let base_dir = args
        .config_file
        .as_ref()
        .and_then(|p| p.parent())
        .unwrap_or(std::path::Path::new("."));

    // Load all rules from config
    let resolved = resolve_rules(config, base_dir, &[], &[], false, false)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let all_files = resolved.files;

    let mut targets = Vec::new();

    for tc in &config.targets {
        let provider = match &tc.provider {
            Some(p) => p.as_str(),
            None => {
                eprintln!(
                    "Warning: skipping target '{}' — no provider specified",
                    tc.name
                );
                continue;
            }
        };
        if !native_names.contains(&provider) {
            eprintln!(
                "Warning: skipping target '{}' — provider '{}' not supported in watch mode",
                tc.name, provider
            );
            continue;
        }

        // Convert toml::Table to serde_json::Value
        let config_value = toml_table_to_json(&tc.config);

        // Filter rules for this target
        let files = if tc.rules.is_empty() {
            all_files.clone()
        } else {
            filter_rules_for_target(&all_files, &tc.rules)
        };

        let rule_count = files.iter().map(|(_, rf)| rf.rules.len()).sum();

        let webhooks = if tc.webhook.is_empty() {
            args.webhook.clone()
        } else {
            tc.webhook.clone()
        };

        targets.push(ResolvedTarget {
            name: tc.name.clone(),
            provider: provider.to_string(),
            provider_config: config_value,
            files,
            rule_count,
            interval: tc.interval.unwrap_or(args.interval),
            webhooks,
        });
    }

    Ok(targets)
}

fn filter_rules_for_target(
    all_files: &[(String, RuleFile)],
    rule_names: &[String],
) -> Vec<(String, RuleFile)> {
    all_files
        .iter()
        .filter(|(name, _)| {
            rule_names.iter().any(|pattern| {
                if pattern.contains('*') {
                    glob_match(pattern, name)
                } else {
                    name == pattern || name.contains(pattern)
                }
            })
        })
        .cloned()
        .collect()
}

fn glob_match(pattern: &str, name: &str) -> bool {
    use std::sync::{LazyLock, Mutex};
    use std::collections::HashMap;
    static CACHE: LazyLock<Mutex<HashMap<String, regex::Regex>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let re = cache.entry(pattern.to_string()).or_insert_with(|| {
        let regex_str = pattern.replace('.', "\\.").replace('*', ".*");
        regex::Regex::new(&format!("^{}$", regex_str)).unwrap_or_else(|_| {
            regex::Regex::new("^$").unwrap()
        })
    });
    re.is_match(name)
}

fn toml_table_to_json(table: &toml::Table) -> Value {
    crate::utils::toml_table_to_json(table)
}

fn load_rules_cli(
    args: &WatchArgs,
    scan_config: &Option<kxn_rules::ScanConfig>,
) -> Result<Vec<(String, RuleFile)>> {
    let config_path = args.config_file.clone();

    let rules_dir = args
        .rules
        .clone()
        .unwrap_or_else(|| PathBuf::from("./rules"));

    // --rules flag always takes precedence over config file rules
    let (mut files, config_filter) = if args.rules.is_some() {
        let files = parse_directory(&rules_dir).map_err(|e| anyhow::anyhow!("{}", e))?;
        (files, None)
    } else if let Some(ref config) = scan_config {
        let base_dir = config_path
            .as_ref()
            .and_then(|p| p.parent())
            .unwrap_or(std::path::Path::new("."));
        let resolved = resolve_rules(config, base_dir, &[], &[], false, false)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        (resolved.files, Some(resolved.filter))
    } else {
        let files = parse_directory(&rules_dir).map_err(|e| anyhow::anyhow!("{}", e))?;
        (files, None)
    };

    if let Some(cf) = config_filter {
        if !cf.is_empty() {
            files = cf.apply(&files);
        }
    }

    let filter = RuleFilter {
        include: args.include.clone(),
        exclude: args.exclude.clone(),
        tags: args.tags.clone(),
        min_level: args.min_level,
        ..Default::default()
    };
    if !filter.is_empty() {
        files = filter.apply(&files);
    }

    Ok(files)
}

/// Per-target loop knobs that come straight from the CLI flags.
struct LoopOptions {
    output: String,
    verbose: bool,
    /// `--metrics-resources`: publish CPU/RAM gauges from gathered objects.
    resource_metrics: bool,
}

async fn run_target_loop(
    target: ResolvedTarget,
    metrics: SharedMetrics,
    opts: LoopOptions,
    alert_interval_secs: u64,
    global_webhooks: Vec<String>,
    save_configs: Arc<Vec<kxn_rules::SaveConfig>>,
) -> Result<()> {
    let LoopOptions { output, verbose, resource_metrics } = opts;
    let mut alert_cache: HashMap<String, AlertEntry> = HashMap::new();
    let alert_dedup = Duration::from_secs(alert_interval_secs);
    let client = crate::alerts::shared_client();
    let mut iteration = 0u64;
    let needed_types = needed_resource_types(&target.files);

    let target_webhooks = if target.webhooks.is_empty() {
        global_webhooks.clone()
    } else {
        target.webhooks.clone()
    };

    loop {
        iteration += 1;
        let batch_id = uuid::Uuid::new_v4().to_string();
        let now_ts = chrono::Utc::now();

        let gathered = match gather_needed(&target.provider, &target.provider_config, &needed_types).await {
            Ok(data) => data,
            Err(e) => {
                let error_msg = format!("{}", e);
                eprintln!("[{}] {} gather error: {}", timestamp(), target.name, error_msg);

                // Send error webhook
                let error_payload = build_error_webhook_payload(
                    &target.name,
                    &target.provider,
                    "gather_error",
                    &error_msg,
                    iteration,
                );
                for url in &target_webhooks {
                    post_webhook(client, url, &error_payload).await;
                }

                tokio::time::sleep(Duration::from_secs(target.interval)).await;
                continue;
            }
        };

        let summary = run_scan(&target.name, &target.provider, &target.files, &gathered);

        // Update global metrics
        {
            let mut m = metrics.write().await;
            m.summaries.retain(|s| s.target != target.name);
            m.summaries.push(summary.clone());
            if resource_metrics {
                m.resource_samples
                    .insert(target.name.clone(), render_resource_samples(&target.name, &gathered));
            }
        }

        // Output
        match output.as_str() {
            "json" => {
                let out = serde_json::json!({
                    "iteration": iteration,
                    "timestamp": now_ts.to_rfc3339(),
                    "target": target.name,
                    "provider": target.provider,
                    "total": summary.total,
                    "passed": summary.passed,
                    "failed": summary.failed,
                    "duration_ms": summary.duration_ms,
                    "violations": summary.violations,
                });
                println!("{}", serde_json::to_string(&out)?);
            }
            "prometheus" => {
                print_prometheus(&target.name, &target.provider, &summary);
            }
            _ => {
                let status = if summary.failed == 0 { "OK" } else { "FAIL" };
                eprintln!(
                    "[{}] {} #{} {} | {}/{} passed | {}ms",
                    timestamp(),
                    target.name,
                    iteration,
                    status,
                    summary.passed,
                    summary.total,
                    summary.duration_ms,
                );
                if verbose {
                    for v in &summary.violations {
                        eprintln!(
                            "  FAIL  {} [{}] {}",
                            v.rule, v.level_label, v.description
                        );
                        for msg in &v.messages {
                            eprintln!("        {}", msg);
                        }
                    }
                }
            }
        }

        // Save results + raw metrics to databases
        if !save_configs.is_empty() {
            let records = build_save_records(&summary, &batch_id, now_ts, &save_configs);
            let metrics = crate::save::flatten_gathered(
                &gathered,
                &target.name,
                &target.provider,
                now_ts,
            );
            if let Err(e) = crate::save::save_all(&save_configs, &records, &metrics).await {
                let error_msg = format!("{}", e);
                eprintln!("[{}] {} save error: {}", timestamp(), target.name, error_msg);
                let error_payload = build_error_webhook_payload(
                    &target.name,
                    &target.provider,
                    "save_error",
                    &error_msg,
                    iteration,
                );
                for url in &target_webhooks {
                    post_webhook(client, url, &error_payload).await;
                }
            }

            // Persist raw gathered objects on every cycle so dashboards see
            // every kind kxn discovers, not just those a rule fires against.
            let raw = crate::save::flatten_gathered_resources(
                &gathered,
                &target.name,
                &target.provider,
                &batch_id,
                now_ts,
            );
            if let Err(e) = crate::save::save_raw_resources(&save_configs, &raw).await {
                eprintln!(
                    "[{}] {} raw resource save error: {}",
                    timestamp(),
                    target.name,
                    e
                );
            }
        }

        // Send rich webhook alerts (global + per-rule)
        let now = Instant::now();
        for v in &summary.violations {
            let cache_key = format!(
                "{}:{}:{}",
                target.name,
                v.rule,
                resource_fingerprint(&v.object_content)
            );
            let should_alert = match alert_cache.get(&cache_key) {
                Some(entry) => now.duration_since(entry.last_alerted) >= alert_dedup,
                None => true,
            };

            if should_alert {
                let payload = build_webhook_payload(v, iteration);

                // Send to target-level webhooks
                for url in &target_webhooks {
                    let body = wrap_for_webhook(url, &payload, v);
                    post_webhook(client, url, &body).await;
                }
                // Send to per-rule webhooks
                for url in &v.rule_webhooks {
                    let body = wrap_for_webhook(url, &payload, v);
                    post_webhook(client, url, &body).await;
                }

                if !target_webhooks.is_empty() || !v.rule_webhooks.is_empty() {
                    alert_cache.insert(cache_key.clone(), AlertEntry { last_alerted: now });
                }

                // Execute remediation actions (if any defined on the rule)
                if !v.remediation_actions.is_empty() {
                    let ctx = crate::remediation::RemediationContext {
                        rule_name: v.rule.clone(),
                        rule_description: v.description.clone(),
                        level: v.level,
                        target: v.target.clone(),
                        provider: v.provider.clone(),
                        object_type: v.object_type.clone(),
                        object_content: v.object_content.clone(),
                        messages: v.messages.clone(),
                    };
                    let count = crate::remediation::execute_remediations(
                        &v.remediation_actions,
                        &ctx,
                        None,
                    ).await;
                    if count > 0 {
                        eprintln!(
                            "[{}] {} remediation: {}/{} actions executed for {}",
                            timestamp(), target.name, count, v.remediation_actions.len(), v.rule
                        );
                    }
                }
            }
        }

        // Clean resolved alerts
        let active: std::collections::HashSet<String> = summary
            .violations
            .iter()
            .map(|v| {
                format!(
                    "{}:{}:{}",
                    target.name,
                    v.rule,
                    resource_fingerprint(&v.object_content)
                )
            })
            .collect();
        alert_cache.retain(|k, _| active.contains(k));

        tokio::time::sleep(Duration::from_secs(target.interval)).await;
    }
}

fn build_save_records(
    summary: &ScanSummary,
    batch_id: &str,
    timestamp: chrono::DateTime<chrono::Utc>,
    save_configs: &[kxn_rules::SaveConfig],
) -> Vec<crate::save::ScanRecord> {
    // Collect tags from all save configs (merged)
    let mut tags = std::collections::HashMap::new();
    for cfg in save_configs {
        for (k, v) in &cfg.tags {
            tags.insert(k.clone(), v.to_string().trim_matches('"').to_string());
        }
    }

    summary
        .violations
        .iter()
        .map(|v| crate::save::ScanRecord {
            target: v.target.clone(),
            provider: v.provider.clone(),
            rule_name: v.rule.clone(),
            rule_description: v.description.clone(),
            level: v.level,
            level_label: v.level_label.clone(),
            object_type: v.object_type.clone(),
            object_content: v.object_content.clone(),
            error: true,
            messages: v.messages.clone(),
            conditions: v.conditions.clone(),
            compliance: v.compliance.clone(),
            batch_id: batch_id.to_string(),
            timestamp,
            tags: tags.clone(),
        })
        .collect()
}

/// Wrap payload for specific webhook providers (Discord, Slack, etc.)
fn wrap_for_webhook(url: &str, _raw_payload: &Value, v: &Violation) -> Value {
    if url.contains("discord.com/api/webhooks") {
        // Rich embed: each context piece (target, object type, namespace,
        // node, conditions, …) gets its own field so operators can scan the
        // alert at a glance. Drops the awkward "Pod: unknown" line for
        // cluster-scope violations where no resource identity exists.
        let (color, level_emoji) = match v.level {
            3 => (15158332u32, "🔴"), // red — fatal
            2 => (15105570u32, "🟠"), // dark orange — error
            1 => (15844367u32, "🟡"), // gold — warning
            _ => (3447003u32, "🔵"),  // blue — info
        };

        // Resource identity: K8s metadata.* first, flat fields next.
        // Rust probes (disk_usage, pod_resource, tls_certs…) emit flat objects
        // such as { kind, fs_kind, node, namespace, pod, pvc_name, used_pct, … }
        // — surface those identity hints so operators can locate the offender
        // without opening the dashboard.
        let resource_name = v
            .object_content
            .pointer("/metadata/name")
            .and_then(|n| n.as_str())
            .or_else(|| v.object_content.get("name").and_then(|n| n.as_str()))
            .or_else(|| v.object_content.get("pvc_name").and_then(|n| n.as_str()))
            .or_else(|| v.object_content.get("pod").and_then(|n| n.as_str()))
            .or_else(|| v.object_content.get("pod_name").and_then(|n| n.as_str()));
        let namespace = v
            .object_content
            .pointer("/metadata/namespace")
            .and_then(|n| n.as_str())
            .or_else(|| v.object_content.get("namespace").and_then(|n| n.as_str()));
        let node_name = v
            .object_content
            .pointer("/spec/nodeName")
            .and_then(|n| n.as_str())
            .or_else(|| v.object_content.get("node").and_then(|n| n.as_str()))
            .or_else(|| v.object_content.get("nodeName").and_then(|n| n.as_str()));
        let pvc_name = v.object_content.get("pvc_name").and_then(|n| n.as_str());
        let pod_name = v
            .object_content
            .get("pod")
            .or_else(|| v.object_content.get("pod_name"))
            .and_then(|n| n.as_str());
        let container_name = v
            .object_content
            .get("container")
            .or_else(|| v.object_content.get("container_name"))
            .and_then(|n| n.as_str());
        let kind_field = v.object_content.get("kind").and_then(|n| n.as_str());
        let fs_kind = v.object_content.get("fs_kind").and_then(|n| n.as_str());

        let mut fields: Vec<Value> = Vec::new();
        fields.push(serde_json::json!({
            "name": "Target", "value": format!("`{}`", v.target), "inline": true,
        }));
        fields.push(serde_json::json!({
            "name": "Object type", "value": format!("`{}`", v.object_type), "inline": true,
        }));
        fields.push(serde_json::json!({
            "name": "Severity", "value": v.level_label.to_uppercase(), "inline": true,
        }));
        if let Some(name) = resource_name {
            let display = match namespace {
                Some(ns) => format!("`{}/{}`", ns, name),
                None => format!("`{}`", name),
            };
            fields.push(serde_json::json!({
                "name": "Resource", "value": display, "inline": true,
            }));
        }
        if let Some(node) = node_name {
            fields.push(serde_json::json!({
                "name": "Node", "value": format!("`{}`", node), "inline": true,
            }));
        }
        // Surface PVC explicitly when present even if Resource was filled
        // from a sibling field — disk_usage rows for PVCs carry both `pod`
        // and `pvc_name` and operators want to see which volume is full.
        if let Some(pvc) = pvc_name {
            let already_in_resource = resource_name == Some(pvc);
            if !already_in_resource {
                fields.push(serde_json::json!({
                    "name": "PVC", "value": format!("`{}`", pvc), "inline": true,
                }));
            }
        }
        if let Some(pod) = pod_name {
            let already_in_resource = resource_name == Some(pod);
            if !already_in_resource {
                fields.push(serde_json::json!({
                    "name": "Pod", "value": format!("`{}`", pod), "inline": true,
                }));
            }
        }
        if let Some(container) = container_name {
            fields.push(serde_json::json!({
                "name": "Container", "value": format!("`{}`", container), "inline": true,
            }));
        }
        // For probes that emit a `kind` discriminator (e.g. disk_usage:
        // node/pvc, fs_kind: root/image) include a Scope field so the
        // alert is unambiguous: "Scope: node/root" vs "Scope: pvc".
        if let Some(kind) = kind_field {
            let scope = match fs_kind {
                Some(fs) => format!("`{}/{}`", kind, fs),
                None => format!("`{}`", kind),
            };
            fields.push(serde_json::json!({
                "name": "Scope", "value": scope, "inline": true,
            }));
        }
        if !v.messages.is_empty() {
            // Each message is `property OP threshold but got value` —
            // exactly the diff between expected and observed.
            let body = v
                .messages
                .iter()
                .map(|m| format!("• {}", m))
                .collect::<Vec<_>>()
                .join("\n");
            fields.push(serde_json::json!({
                "name": "Conditions failed", "value": body, "inline": false,
            }));
        }
        if !v.compliance.is_empty() {
            let refs = v
                .compliance
                .iter()
                .map(|c| format!("{} {}", c.framework, c.control))
                .collect::<Vec<_>>()
                .join(", ");
            fields.push(serde_json::json!({
                "name": "Compliance", "value": refs, "inline": false,
            }));
        }

        serde_json::json!({
            "embeds": [{
                "title": format!("{} {}", level_emoji, v.rule),
                "description": v.description,
                "color": color,
                "fields": fields,
                "footer": { "text": format!("kxn watch · {}", v.provider) },
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }]
        })
    } else if url.contains("hooks.slack.com") {
        // Slack expects {"text": "message"}
        let text = format!(
            "*[{}]* `{}` — {}\n{}",
            v.level_label.to_uppercase(),
            v.rule,
            v.description,
            v.messages.join("\n"),
        );
        serde_json::json!({ "text": text })
    } else {
        // Generic webhook: send raw JSON payload
        _raw_payload.clone()
    }
}

fn build_error_webhook_payload(
    target: &str,
    provider: &str,
    error_type: &str,
    message: &str,
    iteration: u64,
) -> Value {
    serde_json::json!({
        "event": "kxn_error",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "iteration": iteration,
        "error_type": error_type,
        "target": target,
        "provider": provider,
        "message": message,
        "severity": "critical",
    })
}

fn build_webhook_payload(v: &Violation, iteration: u64) -> Value {
    serde_json::json!({
        "event": "compliance_violation",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "iteration": iteration,

        // Rule context
        "rule": {
            "name": v.rule,
            "description": v.description,
            "level": v.level,
            "level_label": v.level_label,
            "object_type": v.object_type,
            "conditions": v.conditions,
        },

        // Compliance framework mappings
        "compliance": v.compliance.iter().map(|c| {
            let mut m = serde_json::json!({
                "framework": c.framework,
                "control": c.control,
            });
            if let Some(ref s) = c.section {
                m["section"] = Value::String(s.clone());
            }
            m
        }).collect::<Vec<_>>(),

        // What was checked
        "resource": {
            "provider": v.provider,
            "target": v.target,
            "object_type": v.object_type,
            "content": v.object_content,
        },

        // What failed
        "failure": {
            "messages": v.messages,
        },

        // Remediation hints
        "remediation": v.remediation_context,
    })
}

fn conditions_to_json(conditions: &[ConditionNode]) -> Value {
    serde_json::to_value(conditions).unwrap_or(Value::Null)
}

fn build_remediation(rule: &Rule, object_content: &Value) -> Value {
    let mut hints = Vec::new();

    for cond in &rule.conditions {
        match cond {
            ConditionNode::Leaf(leaf) => {
                let actual = object_content.get(&leaf.property);
                hints.push(serde_json::json!({
                    "property": leaf.property,
                    "expected_condition": format!("{:?}", leaf.condition),
                    "expected_value": leaf.value,
                    "actual_value": actual,
                }));
            }
            ConditionNode::Parent(parent) => {
                hints.push(serde_json::json!({
                    "type": "compound",
                    "operator": format!("{:?}", parent.operator),
                    "description": parent.description,
                }));
            }
        }
    }

    serde_json::json!({
        "action": format!("Fix {} on {}", rule.name, rule.object),
        "details": hints,
    })
}

async fn gather_all(provider: &str, config: &Value) -> Result<Value> {
    let p = create_native_provider(provider, config.clone())
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let gathered = p
        .gather_all()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let mut output = serde_json::Map::new();
    for (rt, resources) in gathered {
        output.insert(rt, Value::Array(resources));
    }

    Ok(Value::Object(output))
}

/// The `object` values referenced by a target's loaded rules — e.g. for a
/// kubernetes target with only `cluster_stats`/`pod_restarts` rules, this is
/// just those 2 names out of the provider's 68 available resource types.
fn needed_resource_types(files: &[(String, RuleFile)]) -> std::collections::HashSet<String> {
    files
        .iter()
        .flat_map(|(_, rf)| rf.rules.iter().map(|r| r.object.clone()))
        .filter(|o| !o.is_empty())
        .collect()
}

/// Like `gather_all`, but for the watch loop: fetches only the resource
/// types the target's own rules actually reference instead of every type
/// the provider supports. A provider with dozens of resource types (e.g.
/// kubernetes: 68) would otherwise pull and hold the entire cluster's state
/// in memory every cycle even when the loaded rules only look at a couple
/// of them. Falls back to a full gather if no rule `object` could be
/// determined, so behavior never regresses to "gathers nothing".
async fn gather_needed(
    provider: &str,
    config: &Value,
    needed: &std::collections::HashSet<String>,
) -> Result<Value> {
    if needed.is_empty() {
        return gather_all(provider, config).await;
    }

    let p = create_native_provider(provider, config.clone())
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let all_types = p
        .resource_types()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let mut output = serde_json::Map::new();
    for rt in all_types {
        if !needed.contains(&rt) {
            continue;
        }
        match p.gather(&rt).await {
            Ok(items) => {
                output.insert(rt, Value::Array(items));
            }
            Err(e) => {
                tracing::warn!(resource_type = %rt, error = %e, "Gather failed for resource type");
                output.insert(rt, Value::Array(vec![serde_json::json!({"error": e.to_string()})]));
            }
        }
    }

    Ok(Value::Object(output))
}

fn run_scan(
    target_name: &str,
    provider_name: &str,
    files: &[(String, RuleFile)],
    resources: &Value,
) -> ScanSummary {
    let start = Instant::now();
    let mut summary = ScanSummary {
        target: target_name.to_string(),
        provider: provider_name.to_string(),
        ..Default::default()
    };

    let resource_list = if resources.is_array() {
        resources.as_array().cloned().unwrap_or_default()
    } else {
        vec![resources.clone()]
    };

    for (_name, rf) in files {
        for rule in &rf.rules {
            for resource in &resource_list {
                let items = extract_resources(resource, &rule.object);
                // Skip rules for resources not present (tool/service not installed)
                if items.is_empty() && !rule.object.is_empty() {
                    continue;
                }
                let targets: Vec<&Value> = if items.is_empty() {
                    vec![resource]
                } else {
                    items
                };

                for target in targets {
                    // Skip resources that don't match apply_to filter
                    if !rule.matches_apply_to(target) {
                        continue;
                    }
                    summary.total += 1;
                    let sub_results = check_rule(&rule.conditions, target);
                    let errors: Vec<SubResultScan> =
                        sub_results.into_iter().filter(|r| !r.result).collect();

                    if errors.is_empty() {
                        summary.passed += 1;
                    } else {
                        summary.failed += 1;
                        let level_idx = std::cmp::min(rule.level as usize, 3);
                        summary.by_level[level_idx] += 1;

                        let messages: Vec<String> = errors
                            .iter()
                            .filter_map(|e| e.message.clone())
                            .collect();

                        let level_label = match rule.level as u8 {
                            0 => "info",
                            1 => "warning",
                            2 => "error",
                            _ => "fatal",
                        }
                        .to_string();

                        summary.violations.push(Violation {
                            rule: rule.name.clone(),
                            description: rule.description.clone(),
                            level: rule.level as u8,
                            level_label,
                            object_type: rule.object.clone(),
                            object_content: target.clone(),
                            conditions: conditions_to_json(&rule.conditions),
                            messages,
                            provider: provider_name.to_string(),
                            target: target_name.to_string(),
                            remediation_context: build_remediation(rule, target),
                            rule_webhooks: rule.webhook.clone(),
                            compliance: rule.compliance.clone(),
                            remediation_actions: rule.remediation.clone(),
                        });
                    }
                }
            }
        }
    }

    summary.duration_ms = start.elapsed().as_millis();
    summary
}

fn print_prometheus(target: &str, provider: &str, summary: &ScanSummary) {
    let labels = format!("provider=\"{}\",target=\"{}\"", provider, target);
    println!("# HELP kxn_rules_total Total rules evaluated");
    println!("# TYPE kxn_rules_total gauge");
    println!("kxn_rules_total{{{}}} {}", labels, summary.total);
    println!("# HELP kxn_rules_passed Rules that passed");
    println!("# TYPE kxn_rules_passed gauge");
    println!("kxn_rules_passed{{{}}} {}", labels, summary.passed);
    println!("# HELP kxn_rules_failed Rules that failed");
    println!("# TYPE kxn_rules_failed gauge");
    println!("kxn_rules_failed{{{}}} {}", labels, summary.failed);
    println!("# HELP kxn_scan_duration_ms Scan duration in milliseconds");
    println!("# TYPE kxn_scan_duration_ms gauge");
    println!(
        "kxn_scan_duration_ms{{{}}} {}",
        labels, summary.duration_ms
    );
    println!("# HELP kxn_violations_by_level Violations by severity level");
    println!("# TYPE kxn_violations_by_level gauge");
    for (i, label) in ["info", "warning", "error", "fatal"].iter().enumerate() {
        println!(
            "kxn_violations_by_level{{{},level=\"{}\"}} {}",
            labels, label, summary.by_level[i]
        );
    }
}

/// Full Prometheus text exposition: scan summaries for every target, then
/// the resource gauges collected with `--metrics-resources`, one HELP/TYPE
/// header per metric family.
fn render_exposition(m: &GlobalMetrics) -> String {
    let mut body = String::new();
    body.push_str("# HELP kxn_rules_total Total rules evaluated\n# TYPE kxn_rules_total gauge\n");
    for s in &m.summaries {
        body.push_str(&format!("kxn_rules_total{{{}}} {}\n", scan_labels(s), s.total));
    }
    body.push_str("# HELP kxn_rules_passed Rules that passed\n# TYPE kxn_rules_passed gauge\n");
    for s in &m.summaries {
        body.push_str(&format!("kxn_rules_passed{{{}}} {}\n", scan_labels(s), s.passed));
    }
    body.push_str("# HELP kxn_rules_failed Rules that failed\n# TYPE kxn_rules_failed gauge\n");
    for s in &m.summaries {
        body.push_str(&format!("kxn_rules_failed{{{}}} {}\n", scan_labels(s), s.failed));
    }
    body.push_str("# HELP kxn_scan_duration_ms Scan duration in milliseconds\n# TYPE kxn_scan_duration_ms gauge\n");
    for s in &m.summaries {
        body.push_str(&format!("kxn_scan_duration_ms{{{}}} {}\n", scan_labels(s), s.duration_ms));
    }
    body.push_str("# HELP kxn_violations_by_level Violations by severity level\n# TYPE kxn_violations_by_level gauge\n");
    for s in &m.summaries {
        for (i, level) in ["info", "warning", "error", "fatal"].iter().enumerate() {
            body.push_str(&format!(
                "kxn_violations_by_level{{{},level=\"{}\"}} {}\n",
                scan_labels(s),
                level,
                s.by_level[i]
            ));
        }
    }

    // Resource gauges: group samples of every target under one header.
    let mut families: std::collections::BTreeMap<&'static str, Vec<&String>> =
        std::collections::BTreeMap::new();
    for per_target in m.resource_samples.values() {
        for (family, lines) in per_target {
            families.entry(family).or_default().extend(lines.iter());
        }
    }
    for (family, lines) in families {
        let help = RESOURCE_FAMILIES
            .iter()
            .find(|(name, _)| *name == family)
            .map(|(_, h)| *h)
            .unwrap_or("");
        body.push_str(&format!("# HELP {family} {help}\n# TYPE {family} gauge\n"));
        for line in lines {
            body.push_str(line);
            body.push('\n');
        }
    }
    body
}

fn scan_labels(s: &ScanSummary) -> String {
    format!(
        "provider=\"{}\",target=\"{}\"",
        prom_escape(&s.provider),
        prom_escape(&s.target)
    )
}

/// Metric families emitted by `--metrics-resources`, with their HELP text.
const RESOURCE_FAMILIES: &[(&str, &str)] = &[
    ("kxn_pod_cpu_millicores", "Container CPU usage in millicores"),
    ("kxn_pod_memory_mib", "Container working-set memory in MiB"),
    ("kxn_pod_cpu_request_millicores", "Container CPU request in millicores (only when set)"),
    ("kxn_pod_cpu_limit_millicores", "Container CPU limit in millicores (only when set)"),
    ("kxn_pod_memory_request_mib", "Container memory request in MiB (only when set)"),
    ("kxn_pod_memory_limit_mib", "Container memory limit in MiB (only when set)"),
    ("kxn_node_cpu_millicores", "Node CPU usage in millicores"),
    ("kxn_node_memory_mib", "Node working-set memory in MiB"),
    ("kxn_node_cpu_allocatable_millicores", "Node allocatable CPU in millicores"),
    ("kxn_node_memory_allocatable_mib", "Node allocatable memory in MiB"),
];

/// Escape a label value per the Prometheus text format.
fn prom_escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// Build the per-container and per-node gauge samples for one target from
/// its gathered objects. Prefers `pod_efficiency` (usage + requests/limits),
/// falls back to `pod_resource` (usage only); nodes come from `node_metrics`.
/// Non-Kubernetes targets simply produce no samples.
fn render_resource_samples(
    target: &str,
    gathered: &Value,
) -> std::collections::BTreeMap<&'static str, Vec<String>> {
    let mut out: std::collections::BTreeMap<&'static str, Vec<String>> =
        std::collections::BTreeMap::new();
    let rows = |key: &str| -> Vec<&Value> {
        gathered
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter(|r| r.get("error").is_none()).collect())
            .unwrap_or_default()
    };
    let s = |row: &Value, key: &str| -> String {
        prom_escape(row.get(key).and_then(|v| v.as_str()).unwrap_or(""))
    };
    let f = |row: &Value, key: &str| -> Option<f64> { row.get(key).and_then(|v| v.as_f64()) };
    let tgt = prom_escape(target);

    let mut containers = rows("pod_efficiency");
    let (usage_cpu_key, usage_mem_key) = if containers.is_empty() {
        containers = rows("pod_resource");
        ("cpu_millicores", "memory_mib")
    } else {
        ("cpu_usage_millicores", "memory_usage_mib")
    };
    for row in containers {
        let labels = format!(
            "target=\"{}\",namespace=\"{}\",pod=\"{}\",container=\"{}\",node=\"{}\",workload_kind=\"{}\",workload=\"{}\"",
            tgt,
            s(row, "namespace"),
            s(row, "pod"),
            s(row, "container"),
            s(row, "node"),
            s(row, "owner_kind"),
            s(row, "owner_name"),
        );
        let pairs: [(&'static str, &str); 6] = [
            ("kxn_pod_cpu_millicores", usage_cpu_key),
            ("kxn_pod_memory_mib", usage_mem_key),
            ("kxn_pod_cpu_request_millicores", "cpu_request_millicores"),
            ("kxn_pod_cpu_limit_millicores", "cpu_limit_millicores"),
            ("kxn_pod_memory_request_mib", "memory_request_mib"),
            ("kxn_pod_memory_limit_mib", "memory_limit_mib"),
        ];
        for (family, key) in pairs {
            if let Some(v) = f(row, key) {
                out.entry(family).or_default().push(format!("{family}{{{labels}}} {v}"));
            }
        }
    }

    for row in rows("node_metrics") {
        let labels = format!("target=\"{}\",node=\"{}\"", tgt, s(row, "name"));
        let pairs: [(&'static str, &str); 4] = [
            ("kxn_node_cpu_millicores", "cpu_millicores"),
            ("kxn_node_memory_mib", "memory_mib"),
            ("kxn_node_cpu_allocatable_millicores", "allocatable_cpu_millicores"),
            ("kxn_node_memory_allocatable_mib", "allocatable_memory_mib"),
        ];
        for (family, key) in pairs {
            if let Some(v) = f(row, key) {
                out.entry(family).or_default().push(format!("{family}{{{labels}}} {v}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod resource_metrics_tests {
    use super::*;
    use serde_json::json;

    fn gathered() -> Value {
        json!({
            "pod_efficiency": [
                {"namespace": "app", "pod": "web-1", "container": "web", "node": "n1",
                 "owner_kind": "Deployment", "owner_name": "web",
                 "cpu_usage_millicores": 12.5, "memory_usage_mib": 200.0,
                 "cpu_request_millicores": 100.0, "memory_limit_mib": 512.0},
                {"error": "boom"}
            ],
            "node_metrics": [
                {"name": "n1", "cpu_millicores": 300.0, "memory_mib": 2048.0,
                 "allocatable_cpu_millicores": 4000.0, "allocatable_memory_mib": 8000.0}
            ]
        })
    }

    #[test]
    fn samples_from_pod_efficiency_and_nodes() {
        let out = render_resource_samples("k8s", &gathered());
        let cpu = &out["kxn_pod_cpu_millicores"];
        assert_eq!(cpu.len(), 1, "error rows are skipped");
        assert_eq!(
            cpu[0],
            "kxn_pod_cpu_millicores{target=\"k8s\",namespace=\"app\",pod=\"web-1\",container=\"web\",node=\"n1\",workload_kind=\"Deployment\",workload=\"web\"} 12.5"
        );
        assert!(out.contains_key("kxn_pod_cpu_request_millicores"));
        assert!(!out.contains_key("kxn_pod_cpu_limit_millicores"), "unset limit → no series");
        assert_eq!(out["kxn_node_memory_allocatable_mib"][0], "kxn_node_memory_allocatable_mib{target=\"k8s\",node=\"n1\"} 8000");
    }

    #[test]
    fn falls_back_to_pod_resource() {
        let g = json!({"pod_resource": [{"namespace": "a", "pod": "p", "container": "c", "cpu_millicores": 1.0, "memory_mib": 2.0}]});
        let out = render_resource_samples("t", &g);
        assert_eq!(out["kxn_pod_memory_mib"][0], "kxn_pod_memory_mib{target=\"t\",namespace=\"a\",pod=\"p\",container=\"c\",node=\"\",workload_kind=\"\",workload=\"\"} 2");
        assert!(render_resource_samples("t", &json!({"system_stats": []})).is_empty());
    }

    #[test]
    fn exposition_has_one_header_per_family_across_targets() {
        let mut m = GlobalMetrics::default();
        m.resource_samples.insert("a".into(), render_resource_samples("a", &gathered()));
        m.resource_samples.insert("b".into(), render_resource_samples("b", &gathered()));
        let body = render_exposition(&m);
        assert_eq!(body.matches("# TYPE kxn_pod_cpu_millicores gauge").count(), 1);
        assert_eq!(body.matches("kxn_pod_cpu_millicores{").count(), 2);
        assert!(body.starts_with("# HELP kxn_rules_total"));
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(prom_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}

async fn serve_metrics(port: u16, metrics: SharedMetrics) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    loop {
        let (mut socket, _) = listener.accept().await?;
        let m = metrics.read().await;

        let body = render_exposition(&m);

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

// --- Public API for monitor command ---

pub async fn gather_all_pub(provider: &str, config: &Value) -> Result<Value> {
    gather_all(provider, config).await
}

pub fn run_scan_pub(
    target_name: &str,
    provider_name: &str,
    files: &[(String, RuleFile)],
    resources: &Value,
) -> ScanSummary {
    run_scan(target_name, provider_name, files, resources)
}

pub fn build_generic_alert_payload(violations: &[Violation], target_uri: &str) -> Value {
    serde_json::json!({
        "event": "kxn_violation",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "target": target_uri,
        "violation_count": violations.len(),
        "violations": violations.iter().map(|v| {
            serde_json::json!({
                "rule": v.rule,
                "description": v.description,
                "level": v.level,
                "level_label": v.level_label,
                "messages": v.messages,
                "compliance": v.compliance.iter().map(|c| {
                    let mut m = serde_json::json!({
                        "framework": c.framework,
                        "control": c.control,
                    });
                    if let Some(ref s) = c.section {
                        m["section"] = Value::String(s.clone());
                    }
                    m
                }).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Regression test: two distinct resources violating the same rule
    /// must get distinct dedup keys, or the second's alert would be
    /// silently dropped as a false-positive dedup hit (see doc comment
    /// on `resource_fingerprint`).
    #[test]
    fn resource_fingerprint_distinguishes_different_resources() {
        let pod_a = json!({"namespace": "default", "pod": "app-1", "restart_count": 25});
        let pod_b = json!({"namespace": "default", "pod": "app-2", "restart_count": 30});
        assert_ne!(
            resource_fingerprint(&pod_a),
            resource_fingerprint(&pod_b)
        );
    }

    #[test]
    fn resource_fingerprint_stable_for_identical_content() {
        let a = json!({"namespace": "default", "pod": "app-1", "restart_count": 25});
        let b = json!({"namespace": "default", "pod": "app-1", "restart_count": 25});
        assert_eq!(resource_fingerprint(&a), resource_fingerprint(&b));
    }

    /// A target whose rules only reference 2 object types (out of a
    /// provider that may support dozens) must only request those 2 —
    /// this is what keeps `gather_needed` from pulling the whole
    /// provider's resource set into memory every scan.
    #[test]
    fn needed_resource_types_matches_only_referenced_objects() {
        let toml_src = r#"
            [[rules]]
            name = "r1"
            level = 1
            object = "cluster_stats"
            conditions = [{ property = "total_restarts", condition = "INF", value = 100 }]

            [[rules]]
            name = "r2"
            level = 3
            object = "pod_restarts"
            conditions = [{ property = "restart_count", condition = "SUP", value = 20 }]

            [[rules]]
            name = "r3 (dup object)"
            level = 1
            object = "cluster_stats"
            conditions = [{ property = "warning_events", condition = "INF", value = 50 }]
        "#;
        let rule_file: RuleFile = toml::from_str(toml_src).unwrap();
        let files = vec![("cluster-health.toml".to_string(), rule_file)];

        let needed = needed_resource_types(&files);

        assert_eq!(needed.len(), 2);
        assert!(needed.contains("cluster_stats"));
        assert!(needed.contains("pod_restarts"));
        // The other 66 kubernetes resource types (deployments, secrets,
        // Istio/ArgoCD CRDs, etc.) are correctly absent.
        assert!(!needed.contains("deployments"));
    }
}
