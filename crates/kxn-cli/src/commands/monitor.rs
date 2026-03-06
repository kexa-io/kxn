use anyhow::{Context, Result};
use clap::Args;
use serde_json::Value;
use std::path::PathBuf;

use kxn_providers::native_provider_names;
use kxn_rules::{parse_file, RuleFile, RuleFilter};

/// Parse a target URI into (provider, config JSON).
///
/// Supported schemes:
///   postgresql://user:pass@host:5432/dbname
///   mysql://user:pass@host:3306/dbname
///   mongodb://user:pass@host:27017/dbname
///   ssh://user@host:22
///   http://host/path  |  https://host/path
///   grpc://host:443
fn parse_target_uri(uri: &str) -> Result<(String, Value)> {
    let parsed = url::Url::parse(uri).context("Invalid target URI")?;
    let scheme = parsed.scheme().to_lowercase();

    let (provider, config) = match scheme.as_str() {
        "postgresql" | "postgres" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(5432);
            let user = parsed.username();
            let password = parsed.password().unwrap_or("");
            if user.is_empty() {
                anyhow::bail!("PostgreSQL URI must include a user: postgresql://user:pass@host");
            }
            (
                "postgresql".to_string(),
                serde_json::json!({
                    "PG_HOST": host,
                    "PG_PORT": port.to_string(),
                    "PG_USER": user,
                    "PG_PASSWORD": password,
                }),
            )
        }
        "mysql" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(3306);
            let user = parsed.username();
            let password = parsed.password().unwrap_or("");
            if user.is_empty() {
                anyhow::bail!("MySQL URI must include a user: mysql://user:pass@host");
            }
            (
                "mysql".to_string(),
                serde_json::json!({
                    "MYSQL_HOST": host,
                    "MYSQL_PORT": port.to_string(),
                    "MYSQL_USER": user,
                    "MYSQL_PASSWORD": password,
                }),
            )
        }
        "mongodb" | "mongodb+srv" => {
            // Pass the full URI as-is for MongoDB driver
            (
                "mongodb".to_string(),
                serde_json::json!({
                    "MONGO_URI": uri,
                }),
            )
        }
        "ssh" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(22);
            let user = if parsed.username().is_empty() {
                "root"
            } else {
                parsed.username()
            };
            (
                "ssh".to_string(),
                serde_json::json!({
                    "SSH_HOST": host,
                    "SSH_PORT": port.to_string(),
                    "SSH_USER": user,
                }),
            )
        }
        "http" | "https" => (
            "http".to_string(),
            serde_json::json!({
                "URL": uri,
            }),
        ),
        "grpc" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(443);
            (
                "grpc".to_string(),
                serde_json::json!({
                    "GRPC_HOST": host,
                    "GRPC_PORT": port.to_string(),
                }),
            )
        }
        _ => anyhow::bail!(
            "Unsupported URI scheme '{}'. Supported: postgresql, mysql, mongodb, ssh, http, https, grpc",
            scheme
        ),
    };

    // Verify provider is available
    let native = native_provider_names();
    if !native.contains(&provider.as_str()) {
        anyhow::bail!("Provider '{}' is not available", provider);
    }

    Ok((provider, config))
}

/// Select rules automatically for a provider.
///
/// Default: *-monitoring.toml files matching the provider
/// --compliance: adds *-cis.toml files matching the provider
fn auto_select_rules(
    provider: &str,
    compliance: bool,
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

        let is_monitoring = name.contains("monitoring");
        let is_cis = name.contains("cis");
        let is_security = name.contains("security");

        // Always include monitoring rules
        if is_monitoring {
            selected.push((name, rf));
            continue;
        }
        // Include compliance/security only with --compliance
        if compliance && (is_cis || is_security) {
            selected.push((name, rf));
            continue;
        }
        // Include generic rules (no suffix pattern) always
        if !is_monitoring && !is_cis && !is_security {
            selected.push((name, rf));
        }
    }

    Ok(selected)
}

/// Format an alert payload for Slack
fn format_slack_payload(violations: &[super::watch::Violation], target_uri: &str) -> Value {
    if violations.is_empty() {
        return serde_json::json!({
            "text": format!("kxn | {} | ALL PASSED", target_uri),
        });
    }

    let mut blocks = Vec::new();

    // Header
    blocks.push(serde_json::json!({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": format!("kxn | {} violation(s)", violations.len()),
        }
    }));

    // Target info
    blocks.push(serde_json::json!({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": format!("*Target:* `{}`", target_uri),
        }
    }));

    for v in violations.iter().take(10) {
        let level_icon = match v.level {
            0 => "info",
            1 => "warning",
            2 => "error",
            _ => "fatal",
        };

        let mut text = format!(
            "*[{}] {}*\n{}",
            level_icon, v.rule, v.description
        );

        // Add compliance refs
        if !v.compliance.is_empty() {
            let refs: Vec<String> = v
                .compliance
                .iter()
                .map(|c| format!("{} {}", c.framework, c.control))
                .collect();
            text.push_str(&format!("\n_Compliance:_ {}", refs.join(", ")));
        }

        // Add failure messages
        if !v.messages.is_empty() {
            text.push_str(&format!("\n`{}`", v.messages.join("; ")));
        }

        blocks.push(serde_json::json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": text,
            }
        }));
    }

    if violations.len() > 10 {
        blocks.push(serde_json::json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!("_...and {} more violations_", violations.len() - 10),
            }
        }));
    }

    serde_json::json!({
        "blocks": blocks,
    })
}

/// Format an alert payload for Discord
fn format_discord_payload(violations: &[super::watch::Violation], target_uri: &str) -> Value {
    if violations.is_empty() {
        return serde_json::json!({
            "content": format!("**kxn** | `{}` | ALL PASSED", target_uri),
        });
    }

    let mut description = String::new();
    for v in violations.iter().take(10) {
        let level_icon = match v.level {
            0 => "ℹ️",
            1 => "⚠️",
            2 => "❌",
            _ => "🔴",
        };

        description.push_str(&format!("{} **{}**\n{}\n", level_icon, v.rule, v.description));

        if !v.compliance.is_empty() {
            let refs: Vec<String> = v
                .compliance
                .iter()
                .map(|c| format!("{} {}", c.framework, c.control))
                .collect();
            description.push_str(&format!("Compliance: {}\n", refs.join(", ")));
        }
        description.push('\n');
    }

    if violations.len() > 10 {
        description.push_str(&format!("...and {} more violations\n", violations.len() - 10));
    }

    serde_json::json!({
        "embeds": [{
            "title": format!("kxn | {} violation(s)", violations.len()),
            "description": description,
            "color": 15158332,
            "footer": {
                "text": format!("Target: {}", target_uri),
            }
        }]
    })
}

/// Parse an alert URI and return (type, url).
/// slack://hooks.slack.com/services/T00/B00/xxx → ("slack", "https://hooks.slack.com/services/T00/B00/xxx")
/// discord://discord.com/api/webhooks/123/abc  → ("discord", "https://discord.com/api/webhooks/123/abc")
/// https://custom.example.com/webhook          → ("webhook", "https://custom.example.com/webhook")
fn parse_alert_uri(uri: &str) -> Result<(String, String)> {
    if let Some(rest) = uri.strip_prefix("slack://") {
        Ok(("slack".to_string(), format!("https://{}", rest)))
    } else if let Some(rest) = uri.strip_prefix("discord://") {
        Ok(("discord".to_string(), format!("https://{}", rest)))
    } else if uri.starts_with("http://") || uri.starts_with("https://") {
        Ok(("webhook".to_string(), uri.to_string()))
    } else {
        anyhow::bail!(
            "Unsupported alert URI '{}'. Supported: slack://, discord://, http(s)://",
            uri
        );
    }
}

/// Send alerts to all configured alert URIs
async fn send_alerts(
    alerts: &[(String, String)],
    violations: &[super::watch::Violation],
    target_uri: &str,
) {
    let client = reqwest::Client::new();

    for (alert_type, url) in alerts {
        let payload = match alert_type.as_str() {
            "slack" => format_slack_payload(violations, target_uri),
            "discord" => format_discord_payload(violations, target_uri),
            _ => super::watch::build_generic_alert_payload(violations, target_uri),
        };

        if let Err(e) = client.post(url).json(&payload).send().await {
            eprintln!("Alert error ({}): {}", alert_type, e);
        }
    }
}

#[derive(Args)]
pub struct QuickScanArgs {
    /// Target URI (e.g. postgresql://user:pass@host:5432)
    pub uri: String,

    /// Include compliance rules (CIS, SOC-2, PCI-DSS, etc.)
    #[arg(long)]
    pub compliance: bool,

    /// Alert URI (e.g. slack://hooks.slack.com/services/T00/B00/xxx)
    #[arg(long = "alert")]
    pub alerts: Vec<String>,

    /// Expose Prometheus metrics on this port
    #[arg(long)]
    pub metrics: Option<u16>,

    /// Path to rules directory
    #[arg(short = 'R', long = "rules")]
    pub rules_dir: Option<PathBuf>,

    /// Minimum severity level (0=info, 1=warning, 2=error, 3=fatal)
    #[arg(short = 'l', long = "min-level")]
    pub min_level: Option<u8>,

    /// Output format: text, json, sarif
    #[arg(short, long, default_value = "text")]
    pub output: String,

    /// Show verbose output
    #[arg(short, long)]
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

/// Find rules directory: CLI arg > ./rules > bundled rules
fn find_rules_dir(cli_dir: &Option<PathBuf>) -> PathBuf {
    if let Some(dir) = cli_dir {
        return dir.clone();
    }
    let local = PathBuf::from("./rules");
    if local.exists() {
        return local;
    }
    // Fallback: next to executable
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

    if files.is_empty() {
        anyhow::bail!(
            "No rules found for provider '{}' in {:?}. Use --rules to specify a rules directory.",
            provider,
            rules_dir
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
        "kxn | {} | {} rules from [{}]",
        args.uri,
        rule_count,
        file_names.join(", ")
    );

    // Parse alert URIs
    let alerts: Vec<(String, String)> = args
        .alerts
        .iter()
        .map(|u| parse_alert_uri(u))
        .collect::<Result<_>>()?;

    // Gather
    let gathered = super::watch::gather_all_pub(&provider, &config).await?;

    // Scan
    let summary = super::watch::run_scan_pub("target", &provider, &files, &gathered);

    // Output
    match args.output.as_str() {
        "json" => {
            let out = serde_json::json!({
                "target": args.uri,
                "provider": provider,
                "total": summary.total,
                "passed": summary.passed,
                "failed": summary.failed,
                "violations": summary.violations,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        _ => {
            if summary.failed == 0 {
                println!(
                    "ALL PASSED | {}/{} rules | {}ms",
                    summary.passed, summary.total, summary.duration_ms
                );
            } else {
                println!(
                    "FAILED | {}/{} passed | {} violations | {}ms\n",
                    summary.passed, summary.total, summary.failed, summary.duration_ms
                );
                for v in &summary.violations {
                    let level_label = match v.level {
                        0 => "info",
                        1 => "warn",
                        2 => "ERROR",
                        _ => "FATAL",
                    };
                    println!("  [{}] {}", level_label, v.rule);
                    println!("        {}", v.description);
                    if !v.compliance.is_empty() {
                        let refs: Vec<String> = v
                            .compliance
                            .iter()
                            .map(|c| format!("{} {}", c.framework, c.control))
                            .collect();
                        println!("        Compliance: {}", refs.join(", "));
                    }
                    for msg in &v.messages {
                        println!("        {}", msg);
                    }
                    println!();
                }
            }
        }
    }

    // Send alerts if violations exist
    if !alerts.is_empty() && summary.failed > 0 {
        send_alerts(&alerts, &summary.violations, &args.uri).await;
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

    if files.is_empty() {
        anyhow::bail!(
            "No rules found for provider '{}' in {:?}. Use --rules to specify a rules directory.",
            provider,
            rules_dir
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
        .map(|u| parse_alert_uri(u))
        .collect::<Result<_>>()?;

    eprintln!(
        "kxn monitor | {} | {} rules from [{}] | interval={}s | alerts={}",
        args.uri,
        rule_count,
        file_names.join(", "),
        args.interval,
        alerts.len()
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
                send_alerts(&alerts, &owned, &args.uri).await;
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

        tokio::time::sleep(Duration::from_secs(args.interval)).await;
    }
}

fn timestamp() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}
