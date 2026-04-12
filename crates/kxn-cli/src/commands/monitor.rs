use anyhow::Result;
use clap::Args;
use serde_json::Value;
use std::path::PathBuf;

use kxn_providers::parse_target_uri as do_parse_uri;
use kxn_rules::{parse_file, RuleFile, RuleFilter};

/// Parse a target URI into (provider, config JSON).
fn parse_target_uri(uri: &str) -> Result<(String, Value)> {
    do_parse_uri(uri).map_err(|e| anyhow::anyhow!("{}", e))
}

/// Select rules automatically for a provider.
///
/// Default: *-monitoring.toml files matching the provider
/// --compliance: adds *-cis.toml files matching the provider
fn auto_select_rules(
    provider: &str,
    _compliance: bool,
    rules_dir: &std::path::Path,
) -> Result<Vec<(String, RuleFile)>> {
    let pattern = rules_dir.join("**/*.toml");
    let pattern_str = pattern
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid rules path"))?;

    let mut selected = Vec::new();

    for entry in glob::glob(pattern_str).map_err(|e| anyhow::anyhow!("Glob error: {}", e))? {
        let path = entry.map_err(|e| anyhow::anyhow!("Glob error: {}", e))?;
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Parse file, skip on error (e.g. compliance-mapping.toml)
        let rf = match parse_file(&path) {
            Ok(rf) => rf,
            Err(_) => continue,
        };

        // Filter by provider metadata
        let matches_provider = rf
            .metadata
            .as_ref()
            .map(|m| m.provider.as_deref() == Some(provider))
            .unwrap_or(false);

        if !matches_provider {
            continue;
        }

        // Include all rules for the matching provider
        selected.push((name, rf));
    }

    Ok(selected)
}

#[derive(Args)]
pub struct QuickScanArgs {
    /// Target URI (e.g. postgresql://user:pass@host:5432)
    pub uri: String,

    /// Include compliance rules (CIS, SOC-2, PCI-DSS, etc.)
    pub compliance: bool,

    /// Alert URI (e.g. slack://hooks.slack.com/services/T00/B00/xxx)
    pub alerts: Vec<String>,

    /// Save URI (e.g. elasticsearch://host:9200/kxn, s3://bucket/prefix)
    pub saves: Vec<String>,

    /// Expose Prometheus metrics on this port
    pub metrics: Option<u16>,

    /// Path to rules directory
    pub rules_dir: Option<PathBuf>,

    /// Minimum severity level (0=info, 1=warning, 2=error, 3=fatal)
    pub min_level: Option<u8>,

    /// Output format: text, json, sarif
    pub output: String,

    /// Show verbose output
    pub verbose: bool,
}

#[derive(Args)]
pub struct MonitorArgs {
    /// Target URI (e.g. postgresql://user:pass@host:5432)
    pub uri: String,

    /// Include compliance rules (CIS, SOC-2, PCI-DSS, etc.)
    #[arg(long)]
    pub compliance: bool,

    /// Alert URI (e.g. slack://hooks.slack.com/services/T00/B00/xxx)
    #[arg(long = "alert")]
    pub alerts: Vec<String>,

    /// Save results to a backend (e.g. elasticsearch://host:9200/kxn, s3://bucket/prefix)
    #[arg(long = "save")]
    pub saves: Vec<String>,

    /// Scan interval in seconds (default: 60)
    #[arg(short = 'n', long, default_value = "60")]
    pub interval: u64,

    /// Minimum alert interval in seconds for dedup (default: 3600)
    #[arg(long, default_value = "3600")]
    pub alert_interval: u64,

    /// Expose Prometheus metrics on this port
    #[arg(long)]
    pub metrics: Option<u16>,

    /// Path to rules directory
    #[arg(short = 'R', long = "rules")]
    pub rules_dir: Option<PathBuf>,

    /// Minimum severity level (0=info, 1=warning, 2=error, 3=fatal)
    #[arg(short = 'l', long = "min-level")]
    pub min_level: Option<u8>,

    /// Output format: text, json, prometheus
    #[arg(short, long, default_value = "text")]
    pub output: String,

    /// Show verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

/// Find rules directory: CLI arg > ./rules > cache > next to exe
pub fn find_rules_dir(cli_dir: &Option<PathBuf>) -> PathBuf {
    if let Some(dir) = cli_dir {
        return dir.clone();
    }
    // 1. Local ./rules (user's project rules, always wins)
    let local = PathBuf::from("./rules");
    if local.exists() {
        return local;
    }
    // 2. Cached rules from `kxn rules pull` (~/.cache/kxn/rules)
    if let Some(cache_dir) = dirs::cache_dir() {
        let cached = cache_dir.join("kxn").join("rules");
        if cached.exists() {
            return cached;
        }
    }
    // 3. Next to executable
    if let Ok(exe) = std::env::current_exe() {
        let exe_rules = exe.parent().unwrap_or(exe.as_path()).join("rules");
        if exe_rules.exists() {
            return exe_rules;
        }
    }
    local
}

/// One-shot scan: `kxn <URI>`
pub async fn run_quick(args: QuickScanArgs) -> Result<()> {
    let (provider, config) = parse_target_uri(&args.uri)?;
    let rules_dir = find_rules_dir(&args.rules_dir);
    let mut files = auto_select_rules(&provider, args.compliance, &rules_dir)?;

    // Auto-download rules on first run
    if files.is_empty() {
        eprintln!("No rules found. Downloading community rules...");
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("kxn")
            .join("rules");
        if let Ok(count) = crate::commands::rules::auto_pull(&cache_dir).await {
            if count > 0 {
                files = auto_select_rules(&provider, false, &cache_dir)?;
            }
        }
    }
    if files.is_empty() {
        anyhow::bail!(
            "No rules found for provider '{}'. Run `kxn rules pull` to download community rules.",
            provider,
        );
    }

    // Apply min-level filter
    if args.min_level.is_some() {
        let filter = RuleFilter {
            min_level: args.min_level,
            ..Default::default()
        };
        files = filter.apply(&files);
    }

    let rule_count: usize = files.iter().map(|(_, rf)| rf.rules.len()).sum();
    let file_names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    eprintln!(
        "kxn | {} | {} rules ({} files) from {}",
        args.uri,
        rule_count,
        file_names.len(),
        rules_dir.display(),
    );

    // Parse alert URIs
    let alerts: Vec<(String, String)> = args
        .alerts
        .iter()
        .map(|u| crate::alerts::parse_alert_uri(u))
        .collect::<Result<_>>()?;

    // Gather
    let gathered = super::watch::gather_all_pub(&provider, &config).await?;

    // Scan
    let summary = super::watch::run_scan_pub("target", &provider, &files, &gathered);

    // Output
    print!("{}", crate::output::format_output(&summary, &args.output, &args.uri));

    // Save results to backends
    if !args.saves.is_empty() {
        let save_configs: Vec<kxn_rules::SaveConfig> = args
            .saves
            .iter()
            .map(|u| crate::save::parse_save_uri(u))
            .collect::<Result<_>>()?;
        let records = violations_to_records(&summary.violations, &provider);
        let metrics = crate::save::flatten_gathered(&gathered, "target", &provider, chrono::Utc::now());
        if let Err(e) = crate::save::save_all(&save_configs, &records, &metrics).await {
            eprintln!("Save error: {}", e);
        } else {
            eprintln!("Results saved to {} backend(s)", save_configs.len());
        }
    }

    // Send alerts if violations exist
    if !alerts.is_empty() && summary.failed > 0 {
        crate::alerts::send_alerts(&alerts, &summary.violations, &args.uri).await;
        eprintln!("Alerts sent to {} destination(s)", alerts.len());
    }

    if summary.failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// Daemon mode: `kxn monitor <URI>`
pub async fn run_monitor(args: MonitorArgs) -> Result<()> {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    let (provider, config) = parse_target_uri(&args.uri)?;
    let rules_dir = find_rules_dir(&args.rules_dir);
    let mut files = auto_select_rules(&provider, args.compliance, &rules_dir)?;

    // Auto-download rules on first run
    if files.is_empty() {
        eprintln!("No rules found. Downloading community rules...");
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("kxn")
            .join("rules");
        if let Ok(count) = crate::commands::rules::auto_pull(&cache_dir).await {
            if count > 0 {
                files = auto_select_rules(&provider, false, &cache_dir)?;
            }
        }
    }
    if files.is_empty() {
        anyhow::bail!(
            "No rules found for provider '{}'. Run `kxn rules pull` to download community rules.",
            provider,
        );
    }

    if args.min_level.is_some() {
        let filter = RuleFilter {
            min_level: args.min_level,
            ..Default::default()
        };
        files = filter.apply(&files);
    }

    let rule_count: usize = files.iter().map(|(_, rf)| rf.rules.len()).sum();
    let file_names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();

    let alerts: Vec<(String, String)> = args
        .alerts
        .iter()
        .map(|u| crate::alerts::parse_alert_uri(u))
        .collect::<Result<_>>()?;

    let save_configs: Vec<kxn_rules::SaveConfig> = args
        .saves
        .iter()
        .map(|u| crate::save::parse_save_uri(u))
        .collect::<Result<_>>()?;

    eprintln!(
        "kxn monitor | {} | {} rules from [{}] | interval={}s | alerts={} | save={}",
        args.uri,
        rule_count,
        file_names.join(", "),
        args.interval,
        alerts.len(),
        save_configs.len()
    );

    let alert_dedup = Duration::from_secs(args.alert_interval);
    let mut alert_cache: HashMap<String, Instant> = HashMap::new();
    let mut iteration = 0u64;

    loop {
        iteration += 1;

        let gathered = match super::watch::gather_all_pub(&provider, &config).await {
            Ok(data) => data,
            Err(e) => {
                eprintln!("[{}] gather error: {}", timestamp(), e);
                tokio::time::sleep(Duration::from_secs(args.interval)).await;
                continue;
            }
        };

        let summary = super::watch::run_scan_pub("target", &provider, &files, &gathered);

        // Output
        match args.output.as_str() {
            "json" => {
                let out = serde_json::json!({
                    "iteration": iteration,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "target": args.uri,
                    "provider": provider,
                    "total": summary.total,
                    "passed": summary.passed,
                    "failed": summary.failed,
                    "violations": summary.violations,
                });
                println!("{}", serde_json::to_string(&out)?);
            }
            _ => {
                let status = if summary.failed == 0 { "OK" } else { "FAIL" };
                eprintln!(
                    "[{}] #{} {} | {}/{} passed | {}ms",
                    timestamp(),
                    iteration,
                    status,
                    summary.passed,
                    summary.total,
                    summary.duration_ms,
                );
                if args.verbose {
                    for v in &summary.violations {
                        eprintln!("  FAIL  {} [{}] {}", v.rule, v.level_label, v.description);
                        for msg in &v.messages {
                            eprintln!("        {}", msg);
                        }
                    }
                }
            }
        }

        // Save results to backends
        if !save_configs.is_empty() {
            let records = violations_to_records(&summary.violations, &provider);
            let metrics = crate::save::flatten_gathered(&gathered, "target", &provider, chrono::Utc::now());
            if let Err(e) = crate::save::save_all(&save_configs, &records, &metrics).await {
                eprintln!("[{}] save error: {}", timestamp(), e);
            }
        }

        // Send alerts for new violations
        if !alerts.is_empty() {
            let now = Instant::now();
            let new_violations: Vec<_> = summary
                .violations
                .iter()
                .filter(|v| {
                    let key = v.rule.clone();
                    match alert_cache.get(&key) {
                        Some(last) => now.duration_since(*last) >= alert_dedup,
                        None => true,
                    }
                })
                .collect();

            if !new_violations.is_empty() {
                let owned: Vec<super::watch::Violation> = new_violations.iter().map(|v| (*v).clone()).collect();
                crate::alerts::send_alerts(&alerts, &owned, &args.uri).await;
                for v in &new_violations {
                    alert_cache.insert(v.rule.clone(), now);
                }
                eprintln!(
                    "[{}] {} alert(s) sent to {} destination(s)",
                    timestamp(),
                    new_violations.len(),
                    alerts.len()
                );
            }

            // Clean resolved alerts
            let active: std::collections::HashSet<String> =
                summary.violations.iter().map(|v| v.rule.clone()).collect();
            alert_cache.retain(|k, _| active.contains(k));
        }

        // Wait for next interval or graceful shutdown on Ctrl+C
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(args.interval)) => {}
            _ = tokio::signal::ctrl_c() => {
                eprintln!("[{}] Received Ctrl+C, shutting down gracefully", timestamp());
                break;
            }
        }
    }

    Ok(())
}

fn timestamp() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

/// Convert violations into ScanRecords for save backends
fn violations_to_records(
    violations: &[super::watch::Violation],
    provider: &str,
) -> Vec<crate::save::ScanRecord> {
    let batch_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    violations
        .iter()
        .map(|v| crate::save::ScanRecord {
            target: v.target.clone(),
            provider: provider.to_string(),
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
            batch_id: batch_id.clone(),
            timestamp: now,
            tags: std::collections::HashMap::new(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::parse_alert_uri;
    use serde_json::json;

    #[test]
    fn parse_target_uri_postgresql() {
        let (provider, config) = parse_target_uri("postgresql://admin:secret@db.example.com:5432/mydb").unwrap();
        assert_eq!(provider, "postgresql");
        assert_eq!(config["PG_HOST"], "db.example.com");
        assert_eq!(config["PG_PORT"], "5432");
        assert_eq!(config["PG_USER"], "admin");
        assert_eq!(config["PG_PASSWORD"], "secret");
    }

    #[test]
    fn parse_target_uri_mysql() {
        let (provider, config) = parse_target_uri("mysql://root:pass@localhost:3306/db").unwrap();
        assert_eq!(provider, "mysql");
        assert_eq!(config["MYSQL_HOST"], "localhost");
        assert_eq!(config["MYSQL_PORT"], "3306");
        assert_eq!(config["MYSQL_USER"], "root");
        assert_eq!(config["MYSQL_PASSWORD"], "pass");
    }

    #[test]
    fn parse_target_uri_mongodb() {
        let uri = "mongodb://user:pass@host:27017/mydb";
        let (provider, config) = parse_target_uri(uri).unwrap();
        assert_eq!(provider, "mongodb");
        assert_eq!(config["MONGODB_URI"], uri);
    }

    #[test]
    fn parse_target_uri_ssh() {
        let (provider, config) = parse_target_uri("ssh://deploy@server.io:2222").unwrap();
        assert_eq!(provider, "ssh");
        assert_eq!(config["SSH_HOST"], "server.io");
        assert_eq!(config["SSH_PORT"], "2222");
        assert_eq!(config["SSH_USER"], "deploy");
    }

    #[test]
    fn parse_target_uri_ssh_default_user() {
        let (provider, config) = parse_target_uri("ssh://myhost").unwrap();
        assert_eq!(provider, "ssh");
        assert_eq!(config["SSH_USER"], "root");
        assert_eq!(config["SSH_PORT"], "22");
    }

    #[test]
    fn parse_target_uri_http() {
        let uri = "https://api.example.com/health";
        let (provider, config) = parse_target_uri(uri).unwrap();
        assert_eq!(provider, "http");
        assert_eq!(config["URL"], uri);
    }

    #[test]
    fn parse_target_uri_grpc() {
        let (provider, config) = parse_target_uri("grpc://api.example.com:9090").unwrap();
        assert_eq!(provider, "grpc");
        assert_eq!(config["GRPC_HOST"], "api.example.com");
        assert_eq!(config["GRPC_PORT"], "9090");
    }

    #[test]
    fn parse_target_uri_unsupported_scheme() {
        let result = parse_target_uri("ftp://host/path");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Unsupported URI scheme"));
    }

    #[test]
    fn parse_target_uri_postgresql_missing_user() {
        let result = parse_target_uri("postgresql://localhost:5432/db");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("must include a user"));
    }

    #[test]
    fn parse_alert_uri_slack() {
        let (kind, url) = parse_alert_uri("slack://hooks.slack.com/services/T00/B00/xxx").unwrap();
        assert_eq!(kind, "slack");
        assert_eq!(url, "https://hooks.slack.com/services/T00/B00/xxx");
    }

    #[test]
    fn parse_alert_uri_discord() {
        let (kind, url) = parse_alert_uri("discord://discord.com/api/webhooks/123/abc").unwrap();
        assert_eq!(kind, "discord");
        assert_eq!(url, "https://discord.com/api/webhooks/123/abc");
    }

    #[test]
    fn parse_alert_uri_https() {
        let (kind, url) = parse_alert_uri("https://custom.example.com/hook").unwrap();
        assert_eq!(kind, "webhook");
        assert_eq!(url, "https://custom.example.com/hook");
    }

    #[test]
    fn parse_alert_uri_unsupported() {
        let result = parse_alert_uri("amqp://broker:5672");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported alert URI"));
    }

    #[test]
    fn auto_select_rules_monitoring_and_compliance() {
        let dir = tempfile::tempdir().unwrap();

        let monitoring_toml = r#"
[metadata]
provider = "ssh"
[[rules]]
name = "ssh-uptime"
description = "Check uptime"
level = 1
object = "system_info"
[[rules.conditions]]
property = "uptime"
condition = "SUP"
value = "0"
"#;
        std::fs::write(dir.path().join("ssh-monitoring.toml"), monitoring_toml).unwrap();

        let cis_toml = r#"
[metadata]
provider = "ssh"
[[rules]]
name = "ssh-cis-root"
description = "No root login"
level = 2
object = "sshd_config"
[[rules.conditions]]
property = "permitrootlogin"
condition = "EQUAL"
value = "no"
"#;
        std::fs::write(dir.path().join("ssh-cis.toml"), cis_toml).unwrap();

        let other_toml = r#"
[metadata]
provider = "mysql"
[[rules]]
name = "mysql-check"
description = "MySQL check"
level = 1
object = "config"
[[rules.conditions]]
property = "version"
condition = "SUP"
value = "5"
"#;
        std::fs::write(dir.path().join("mysql-monitoring.toml"), other_toml).unwrap();

        let result = auto_select_rules("ssh", false, dir.path()).unwrap();
        let names: Vec<&str> = result.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"ssh-monitoring"));
        assert!(!names.contains(&"ssh-cis"));
        assert!(!names.contains(&"mysql-monitoring"));

        let result_compliance = auto_select_rules("ssh", true, dir.path()).unwrap();
        let names: Vec<&str> = result_compliance.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"ssh-monitoring"));
        assert!(names.contains(&"ssh-cis"));
    }

    #[test]
    fn auto_select_rules_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = auto_select_rules("ssh", false, dir.path()).unwrap();
        assert!(result.is_empty());
    }

    fn make_violation(rule: &str, level: u8) -> super::super::watch::Violation {
        super::super::watch::Violation {
            rule: rule.to_string(),
            description: format!("{} desc", rule),
            level,
            level_label: match level {
                0 => "info",
                1 => "warning",
                2 => "error",
                _ => "fatal",
            }
            .to_string(),
            object_type: "test_obj".to_string(),
            object_content: json!({"key": "val"}),
            conditions: json!([]),
            messages: vec!["failed check".to_string()],
            provider: "ssh".to_string(),
            target: "target-1".to_string(),
            remediation_context: json!({}),
            rule_webhooks: vec![],
            compliance: vec![],
            remediation_actions: vec![],
        }
    }

    #[test]
    fn violations_to_records_basic() {
        let violations = vec![
            make_violation("rule-a", 2),
            make_violation("rule-b", 1),
        ];
        let records = violations_to_records(&violations, "ssh");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].rule_name, "rule-a");
        assert_eq!(records[0].provider, "ssh");
        assert_eq!(records[0].level, 2);
        assert!(records[0].error);
        assert_eq!(records[1].rule_name, "rule-b");
        assert_eq!(records[0].batch_id, records[1].batch_id);
    }

    #[test]
    fn violations_to_records_empty() {
        let records = violations_to_records(&[], "postgresql");
        assert!(records.is_empty());
    }

    #[test]
    fn find_rules_dir_with_explicit_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let result = find_rules_dir(&Some(path.clone()));
        assert_eq!(result, path);
    }

    #[test]
    fn find_rules_dir_none_fallback() {
        let result = find_rules_dir(&None);
        assert!(result.to_str().unwrap().contains("rules"));
    }
}
