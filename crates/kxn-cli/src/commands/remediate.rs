use anyhow::Result;
use clap::Args;
use kxn_providers::{create_native_provider, parse_target_uri};
use kxn_rules::parse_directory;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::extract_resources;
use crate::table::{CYAN, GREEN, RESET};

fn spinner_start(msg: &str) -> (Arc<AtomicBool>, tokio::task::JoinHandle<()>) {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let m = msg.to_string();
    let handle = tokio::spawn(async move {
        let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let mut i = 0;
        while r.load(Ordering::Relaxed) {
            eprint!("\r{CYAN}{}{RESET} {m}", frames[i % frames.len()]);
            i += 1;
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        }
    });
    (running, handle)
}

fn spinner_stop((running, handle): (Arc<AtomicBool>, tokio::task::JoinHandle<()>), msg: &str) {
    running.store(false, Ordering::Relaxed);
    handle.abort();
    eprint!("\r\x1b[K{GREEN}✓{RESET} {msg}\n");
}

#[derive(Args)]
pub struct RemediateArgs {
    /// Target URI (e.g. ssh://root@server, postgresql://user:pass@host:5432)
    pub uri: String,

    /// Apply remediation for specific rule(s) — repeatable
    #[arg(short, long = "rule")]
    pub rules: Vec<String>,

    /// Apply all remediations matching this substring
    #[arg(long)]
    pub apply_filter: Option<String>,

    /// Rules directory
    #[arg(short = 'R', long = "rules-dir", default_value = "./rules")]
    pub rules_dir: PathBuf,

    /// Dry-run: show what would be done without executing
    #[arg(long)]
    pub dry_run: bool,

    /// Include compliance rules
    #[arg(long)]
    pub compliance: bool,
}

pub async fn run(args: RemediateArgs) -> Result<()> {
    let (provider_name, config) =
        parse_target_uri(&args.uri).map_err(|e| anyhow::anyhow!("{}", e))?;

    let provider = create_native_provider(&provider_name, config.clone())
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Load rules
    let files = parse_directory(&args.rules_dir)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if files.is_empty() {
        anyhow::bail!("No rules found in {}", args.rules_dir.display());
    }

    // Gather all resources with spinner
    let spinner = spinner_start(&format!("Scanning {}...", args.uri));
    let gathered = provider
        .gather_all()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let resources: Vec<serde_json::Value> = gathered
        .into_values()
        .flat_map(|items| items.into_iter())
        .collect();
    spinner_stop(spinner, &format!("Gathered {} resources", resources.len()));

    // Evaluate rules and collect violations with remediations (deduplicated by rule name)
    let mut violations = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();

    for (_name, rf) in &files {
        let rule_provider = rf.metadata.as_ref()
            .and_then(|m| m.provider.as_deref())
            .unwrap_or("");
        if !rule_provider.is_empty() && rule_provider != provider_name {
            continue;
        }
        for rule in &rf.rules {
            if rule.remediation.is_empty() || seen_rules.contains(&rule.name) {
                continue;
            }
            for resource in &resources {
                let items = extract_resources(resource, &rule.object);
                let targets: Vec<&serde_json::Value> = if items.is_empty() {
                    vec![resource]
                } else {
                    items
                };
                for target in targets {
                    let results = kxn_core::check_rule(&rule.conditions, target);
                    let failures: Vec<_> =
                        results.iter().filter(|r| !r.result).collect();
                    if !failures.is_empty() {
                        let messages: Vec<String> = failures
                            .iter()
                            .map(|r| r.message.clone().unwrap_or_default())
                            .collect();
                        violations.push((rule.clone(), target.clone(), messages));
                        seen_rules.insert(rule.name.clone());
                        break; // One violation per rule is enough for remediation
                    }
                }
                if seen_rules.contains(&rule.name) { break; }
            }
        }
    }

    if violations.is_empty() {
        println!("No remediable violations found.");
        return Ok(());
    }

    // List mode: no --rule or --apply-filter specified
    let apply_mode = !args.rules.is_empty() || args.apply_filter.is_some();

    if !apply_mode {
        let rows: Vec<crate::table::RemediateRow> = violations
            .iter()
            .enumerate()
            .map(|(i, (rule, _target, messages))| {
                let remediation = rule
                    .remediation
                    .iter()
                    .map(|a| crate::remediation::action_summary(a))
                    .collect::<Vec<_>>()
                    .join(" ; ");
                crate::table::RemediateRow {
                    num: i + 1,
                    level: rule.level as u8,
                    rule: rule.name.clone(),
                    description: rule.description.clone(),
                    remediation,
                    message: messages.first().cloned().unwrap_or_default(),
                }
            })
            .collect();
        crate::table::print_remediate_table(&rows);
        return Ok(());
    }

    // Apply mode: filter violations by selected rules (by number or name)
    let selected: Vec<_> = violations
        .iter()
        .enumerate()
        .filter(|(i, (rule, _, _))| {
            if !args.rules.is_empty() {
                args.rules.iter().any(|r| {
                    // Match by number (1-based)
                    if let Ok(n) = r.parse::<usize>() {
                        *i + 1 == n
                    } else {
                        // Match by exact name or substring
                        rule.name == *r || rule.name.contains(r.as_str())
                    }
                })
            } else if let Some(ref filter) = args.apply_filter {
                rule.name.contains(filter.as_str())
            } else {
                false
            }
        })
        .map(|(_, v)| v)
        .collect();

    if selected.is_empty() {
        println!("No violations match the selected rules.");
        return Ok(());
    }

    println!(
        "{} remediation(s) to apply{}:\n",
        selected.len(),
        if args.dry_run { " (DRY RUN)" } else { "" }
    );

    let mut applied = 0;
    for (rule, target, messages) in &selected {
        println!("  [{}] {}", rule.name, rule.description);
        for action in &rule.remediation {
            println!(
                "    -> {}",
                crate::remediation::action_summary(action)
            );
        }

        if args.dry_run {
            println!("    => SKIPPED (dry-run)\n");
            continue;
        }

        let ctx = crate::remediation::RemediationContext {
            rule_name: rule.name.clone(),
            rule_description: rule.description.clone(),
            level: rule.level as u8,
            target: args.uri.clone(),
            provider: provider_name.clone(),
            object_type: rule.object.clone(),
            object_content: (*target).clone(),
            messages: messages.clone(),
        };

        let count = crate::remediation::execute_remediations(
            &rule.remediation,
            &ctx,
        )
        .await;

        if count > 0 {
            println!("    => APPLIED ({}/{})\n", count, rule.remediation.len());
            applied += 1;
        } else {
            println!("    => FAILED\n");
        }
    }

    println!(
        "Done: {}/{} remediations applied.",
        applied,
        selected.len()
    );

    Ok(())
}
