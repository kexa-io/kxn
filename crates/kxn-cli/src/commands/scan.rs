use anyhow::{Context, Result};
use clap::Args;
use kxn_core::{ComplianceRef, Level, Rule};
use serde_json::Value;
use std::io::Read;
use std::path::PathBuf;

use kxn_core::{check_rule, ResultScan, ScanSummary};
use kxn_rules::{parse_config, parse_directory, resolve_rules, RuleFilter};

use super::extract_resources;

#[derive(Args)]
pub struct ScanArgs {
    /// Path to kxn.toml config file
    #[arg(short, long = "config")]
    pub config: Option<PathBuf>,

    /// Path to TOML rules directory (used when no config file)
    #[arg(short = 'R', long = "rules")]
    pub rules: Option<PathBuf>,

    /// JSON resources to check (reads from stdin if not provided)
    #[arg(short, long)]
    pub resource: Option<String>,

    /// Enable optional rule sets by name (can repeat)
    #[arg(long = "enable")]
    pub enable: Vec<String>,

    /// Disable optional rule sets by name (can repeat)
    #[arg(long = "disable")]
    pub disable: Vec<String>,

    /// Only run mandatory rules
    #[arg(long = "only-mandatory")]
    pub only_mandatory: bool,

    /// Run all rules (mandatory + all optional)
    #[arg(long = "all")]
    pub all: bool,

    /// Include rules matching glob patterns (can repeat)
    #[arg(short, long = "include")]
    pub include: Vec<String>,

    /// Exclude rules matching glob patterns (can repeat)
    #[arg(short = 'x', long = "exclude")]
    pub exclude: Vec<String>,

    /// Filter by tags (AND — rule must have all)
    #[arg(short, long = "tag")]
    pub tags: Vec<String>,

    /// Filter by tags (OR — rule must have any)
    #[arg(long = "any-tag")]
    pub any_tags: Vec<String>,

    /// Minimum severity level (0=info, 1=warning, 2=error, 3=fatal)
    #[arg(short = 'l', long = "min-level")]
    pub min_level: Option<u8>,

    /// Show verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Output results as JSON (ScanSummary)
    #[arg(long)]
    pub json: bool,

    /// Output format: text (default), json, sarif
    #[arg(long = "output", value_name = "FORMAT")]
    pub output_format: Option<String>,

    /// Write SARIF output to file (default: stdout)
    #[arg(long = "sarif-file")]
    pub sarif_file: Option<PathBuf>,
}

pub async fn run(args: ScanArgs) -> Result<()> {
    // Determine config path: explicit, auto-detect kxn.toml (only if --rules not passed), or none
    let config_path = args
        .config
        .clone()
        .or_else(|| {
            // Only auto-detect kxn.toml if --rules was not explicitly passed
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

    let rules_dir = args.rules.clone().unwrap_or_else(|| PathBuf::from("./rules"));

    // Validate rules path when explicitly provided
    if args.rules.is_some() && !rules_dir.exists() {
        anyhow::bail!(
            "Rules path '{}' does not exist",
            rules_dir.display()
        );
    }
    if args.rules.is_some() && !rules_dir.is_dir() {
        anyhow::bail!(
            "Rules path '{}' is not a directory. Use 'kxn check -R <file>' for single rule files",
            rules_dir.display()
        );
    }

    // Load rules: from config or from rules directory
    let (mut files, config_filter) = if let Some(ref cfg_path) = config_path {
        let config = parse_config(cfg_path)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let base_dir = cfg_path.parent().unwrap_or(std::path::Path::new("."));
        let resolved = resolve_rules(
            &config,
            base_dir,
            &args.enable,
            &args.disable,
            args.only_mandatory,
            args.all,
        )
        .map_err(|e| anyhow::anyhow!("{}", e))?;

        if args.verbose {
            let names: Vec<&str> = resolved.files.iter().map(|(n, _)| n.as_str()).collect();
            eprintln!("Config: {} | Rule sets: {}", cfg_path.display(), names.join(", "));
        }

        (resolved.files, Some(resolved.filter))
    } else {
        let files = parse_directory(&rules_dir)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        (files, None)
    };

    // Merge CLI filters with config filters
    let filter = RuleFilter {
        include: args.include,
        exclude: args.exclude,
        tags: args.tags,
        any_tags: args.any_tags,
        min_level: args.min_level.or(config_filter.as_ref().and_then(|f| f.min_level)),
    };

    // Apply config-level filters first
    if let Some(cf) = config_filter {
        if !cf.is_empty() {
            files = cf.apply(&files);
        }
    }

    // Apply CLI filters
    if !filter.is_empty() {
        files = filter.apply(&files);
    }

    if files.is_empty() {
        println!("No rules match the filter criteria.");
        return Ok(());
    }

    // Read resource(s)
    let json_str = match args.resource {
        Some(s) => s,
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("Failed to read stdin")?;
            buf
        }
    };

    if json_str.trim().is_empty() {
        anyhow::bail!(
            "No resource input. Provide JSON via --resource or stdin:\n  \
             kxn scan -R rules/ -r '{{\"key\": \"value\"}}'\n  \
             echo '{{\"key\": \"value\"}}' | kxn scan -R rules/"
        );
    }

    let resources: Vec<serde_json::Value> = if json_str.trim().starts_with('[') {
        serde_json::from_str(&json_str).context("Invalid JSON array")?
    } else {
        vec![serde_json::from_str(&json_str).context("Invalid JSON")?]
    };

    let output_fmt = args.output_format.as_deref()
        .unwrap_or(if args.json { "json" } else { "text" });
    let is_text = output_fmt == "text";

    let mut total_rules = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut results: Vec<ResultScan> = Vec::new();
    // For SARIF: track rule metadata per failure
    let mut sarif_rules: Vec<&Rule> = Vec::new();

    for (_name, rf) in &files {
        for rule in &rf.rules {
            for resource in &resources {
                let items = extract_resources(resource, &rule.object);
                // If the resource type doesn't exist in the gathered data,
                // skip this rule — the service/tool isn't installed.
                if items.is_empty() && !rule.object.is_empty() {
                    continue;
                }
                let targets: Vec<&Value> = if items.is_empty() {
                    vec![resource]
                } else {
                    items
                };

                for target in targets {
                    if !rule.matches_apply_to(target) {
                        continue;
                    }
                    total_rules += 1;
                    let sub_results = check_rule(&rule.conditions, target);
                    let errors: Vec<_> =
                        sub_results.iter().filter(|r| !r.result).cloned().collect();

                    if errors.is_empty() {
                        passed += 1;
                        if is_text && args.verbose {
                            println!("  PASS  {}", rule.name);
                        }
                    } else {
                        failed += 1;
                        if is_text {
                            let compliance_str = if rule.compliance.is_empty() {
                                String::new()
                            } else {
                                let refs: Vec<String> = rule.compliance.iter()
                                    .map(|c| format!("{} {}", c.framework, c.control))
                                    .collect();
                                format!(" ({})", refs.join(", "))
                            };
                            println!("  FAIL  {} [{}]{}", rule.name, rule.level, compliance_str);
                            for e in &errors {
                                if let Some(msg) = &e.message {
                                    println!("        {}", msg);
                                }
                            }
                        }
                        sarif_rules.push(rule);
                        results.push(ResultScan {
                            object_content: target.clone(),
                            rule_name: rule.name.clone(),
                            errors,
                            compliance: rule.compliance.clone(),
                        });
                    }
                }
            }
        }
    }

    let summary = ScanSummary {
        total_rules,
        passed,
        failed,
        results,
    };

    match output_fmt {
        "json" => {
            println!("{}", serde_json::to_string(&summary)
                .context("Failed to serialize scan results")?);
        }
        "sarif" => {
            let sarif = build_sarif(&summary, &sarif_rules);
            let sarif_str = serde_json::to_string_pretty(&sarif)
                .context("Failed to serialize SARIF output")?;
            if let Some(ref path) = args.sarif_file {
                std::fs::write(path, &sarif_str)
                    .with_context(|| format!("Failed to write SARIF to {}", path.display()))?;
                eprintln!("SARIF written to {}", path.display());
            } else {
                println!("{}", sarif_str);
            }
        }
        _ => {
            println!(
                "\nScan: {} rules, {} passed, {} failed",
                total_rules, passed, failed
            );
        }
    }

    if failed > 0 {
        anyhow::bail!("Scan failed: {} violation(s) found", failed);
    }
    Ok(())
}

fn level_to_sarif(level: Level) -> &'static str {
    match level {
        Level::Info => "note",
        Level::Warning => "warning",
        Level::Error | Level::Fatal => "error",
    }
}

fn compliance_to_tags(compliance: &[ComplianceRef]) -> Vec<String> {
    compliance.iter().map(|c| format!("{}/{}", c.framework, c.control)).collect()
}

fn build_sarif(summary: &ScanSummary, rules: &[&Rule]) -> Value {
    // Build unique rule descriptors
    let mut seen_rules = std::collections::HashMap::new();
    let mut rule_descriptors = Vec::new();

    for rule in rules {
        if seen_rules.contains_key(&rule.name) {
            continue;
        }
        let idx = rule_descriptors.len();
        seen_rules.insert(rule.name.clone(), idx);

        let mut tags = compliance_to_tags(&rule.compliance);
        tags.extend(rule.tags.iter().cloned());

        let mut descriptor = serde_json::json!({
            "id": rule.name,
            "shortDescription": { "text": rule.description },
            "properties": {
                "tags": tags,
            }
        });

        if !rule.compliance.is_empty() {
            let help_text = rule.compliance.iter()
                .map(|c| {
                    let mut s = format!("{} {}", c.framework, c.control);
                    if let Some(ref sec) = c.section {
                        s.push_str(&format!(" ({})", sec));
                    }
                    s
                })
                .collect::<Vec<_>>()
                .join(", ");
            descriptor["helpUri"] = Value::String(String::new());
            descriptor["help"] = serde_json::json!({
                "text": help_text,
            });
        }

        rule_descriptors.push(descriptor);
    }

    // Build results
    let sarif_results: Vec<Value> = summary.results.iter().zip(rules.iter()).map(|(result, rule)| {
        let rule_idx = seen_rules.get(&result.rule_name).copied().unwrap_or(0);
        let messages: Vec<String> = result.errors.iter()
            .filter_map(|e| e.message.clone())
            .collect();
        let message = if messages.is_empty() {
            format!("Rule '{}' failed", result.rule_name)
        } else {
            messages.join("; ")
        };

        serde_json::json!({
            "ruleId": result.rule_name,
            "ruleIndex": rule_idx,
            "level": level_to_sarif(rule.level),
            "message": { "text": message },
            "properties": {
                "compliance": result.compliance.iter().map(|c| {
                    serde_json::json!({
                        "framework": c.framework,
                        "control": c.control,
                    })
                }).collect::<Vec<_>>(),
            }
        })
    }).collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "kxn",
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/kexa-io/kxn",
                    "rules": rule_descriptors,
                }
            },
            "results": sarif_results,
            "invocations": [{
                "executionSuccessful": summary.failed == 0,
                "toolExecutionNotifications": [],
            }],
        }]
    })
}
