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

fn extract_resources(root: &Value, object: &str) -> Vec<Value> {
    if object.is_empty() {
        return vec![];
    }
    match root.get(object) {
        Some(Value::Array(arr)) => arr.clone(),
        Some(val) => vec![val.clone()],
        None => vec![],
    }
}

#[derive(Args)]
pub struct WatchArgs {
    /// Provider name (e.g. ssh, postgresql, mysql, mongodb, http)
    #[arg(short, long)]
    pub provider: Option<String>,

    /// Provider config JSON
    #[arg(short, long, default_value = "{}")]
    pub config: String,

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
}

type SharedMetrics = Arc<RwLock<GlobalMetrics>>;

pub async fn run(args: WatchArgs) -> Result<()> {
    // Try to load config file for multi-target mode
    let config_path = args.config_file.clone().or_else(|| {
        let default = PathBuf::from("kxn.toml");
        if default.exists() {
            Some(default)
        } else {
            None
        }
    });

    let scan_config = config_path
        .as_ref()
        .map(|p| parse_config(p).map_err(|e| anyhow::anyhow!("{}", e)))
        .transpose()?;

    let targets = match resolve_targets(&args, &scan_config) {
        Ok(t) => t,
        Err(e) => {
            let error_msg = format!("{}", e);
            eprintln!("Configuration error: {}", error_msg);
            // Send webhook if configured
            if !args.webhook.is_empty() {
                let client = reqwest::Client::new();
                let payload = build_error_webhook_payload(
                    "global",
                    "config",
                    "config_error",
                    &error_msg,
                    0,
                );
                for url in &args.webhook {
                    let _ = client.post(url).json(&payload).send().await;
                }
            }
            return Err(e);
        }
    };
    if targets.is_empty() {
        let msg = "No targets configured. Use --provider or add [[targets]] to kxn.toml";
        if !args.webhook.is_empty() {
            let client = reqwest::Client::new();
            let payload = build_error_webhook_payload("global", "config", "config_error", msg, 0);
            for url in &args.webhook {
                let _ = client.post(url).json(&payload).send().await;
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
        let output = args.output.clone();
        let verbose = args.verbose;
        let alert_interval = args.alert_interval;
        let global_webhooks = args.webhook.clone();
        let save_cfgs = save_configs.clone();

        handles.push(tokio::spawn(async move {
            run_target_loop(
                target,
                metrics,
                output,
                verbose,
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
        serde_json::from_str(&args.config).context("Invalid config JSON")?;

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
    let regex_str = pattern.replace('.', "\\.").replace('*', ".*");
    regex::Regex::new(&format!("^{}$", regex_str))
        .map(|r| r.is_match(name))
        .unwrap_or(false)
}

fn toml_table_to_json(table: &toml::Table) -> Value {
    let toml_value = toml::Value::Table(table.clone());
    // Convert via string serialization
    let json_str = serde_json::to_string(&toml_value).unwrap_or_else(|_| "{}".to_string());
    serde_json::from_str(&json_str).unwrap_or(Value::Object(serde_json::Map::new()))
}

fn load_rules_cli(
    args: &WatchArgs,
    scan_config: &Option<kxn_rules::ScanConfig>,
) -> Result<Vec<(String, RuleFile)>> {
    let config_path = args.config_file.clone().or_else(|| {
        if args.rules.is_some() {
            return None;
        }
        let default = PathBuf::from("kxn.toml");
        if default.exists() {
            Some(default)
        } else {
            None
        }
    });

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

async fn run_target_loop(
    target: ResolvedTarget,
    metrics: SharedMetrics,
    output: String,
    verbose: bool,
    alert_interval_secs: u64,
    global_webhooks: Vec<String>,
    save_configs: Arc<Vec<kxn_rules::SaveConfig>>,
) -> Result<()> {
    let mut alert_cache: HashMap<String, AlertEntry> = HashMap::new();
    let alert_dedup = Duration::from_secs(alert_interval_secs);
    let client = reqwest::Client::new();
    let mut iteration = 0u64;

    let target_webhooks = if target.webhooks.is_empty() {
        global_webhooks.clone()
    } else {
        target.webhooks.clone()
    };

    loop {
        iteration += 1;
        let batch_id = uuid::Uuid::new_v4().to_string();
        let now_ts = chrono::Utc::now();

        let gathered = match gather_all(&target.provider, &target.provider_config).await {
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
                    let _ = client.post(url).json(&error_payload).send().await;
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
                    let _ = client.post(url).json(&error_payload).send().await;
                }
            }
        }

        // Send rich webhook alerts (global + per-rule)
        let now = Instant::now();
        for v in &summary.violations {
            let cache_key = format!("{}:{}", target.name, v.rule);
            let should_alert = match alert_cache.get(&cache_key) {
                Some(entry) => now.duration_since(entry.last_alerted) >= alert_dedup,
                None => true,
            };

            if should_alert {
                let payload = build_webhook_payload(v, iteration);

                // Send to target-level webhooks
                for url in &target_webhooks {
                    let _ = client.post(url).json(&payload).send().await;
                }
                // Send to per-rule webhooks
                for url in &v.rule_webhooks {
                    let _ = client.post(url).json(&payload).send().await;
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
            .map(|v| format!("{}:{}", target.name, v.rule))
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
                let targets = if items.is_empty() {
                    vec![resource.clone()]
                } else {
                    items
                };

                for target in &targets {
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

async fn serve_metrics(port: u16, metrics: SharedMetrics) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    loop {
        let (mut socket, _) = listener.accept().await?;
        let m = metrics.read().await;

        let mut body = String::new();
        for s in &m.summaries {
            let labels = format!("provider=\"{}\",target=\"{}\"", s.provider, s.target);
            body.push_str(&format!(
                "kxn_rules_total{{{}}} {}\n",
                labels, s.total
            ));
            body.push_str(&format!(
                "kxn_rules_passed{{{}}} {}\n",
                labels, s.passed
            ));
            body.push_str(&format!(
                "kxn_rules_failed{{{}}} {}\n",
                labels, s.failed
            ));
            body.push_str(&format!(
                "kxn_scan_duration_ms{{{}}} {}\n",
                labels, s.duration_ms
            ));
            for (i, level) in ["info", "warning", "error", "fatal"].iter().enumerate() {
                body.push_str(&format!(
                    "kxn_violations_by_level{{{},level=\"{}\"}} {}\n",
                    labels, level, s.by_level[i]
                ));
            }
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
