use anyhow::{Context, Result};
use clap::Args;
use serde_json::Value;
use std::io::Read;
use std::path::PathBuf;

use kxn_core::{check_rule, ResultScan};
use kxn_rules::{parse_directory, RuleFilter};

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
pub struct ScanArgs {
    /// Path to TOML rules directory
    #[arg(short = 'R', long = "rules", default_value = "./rules")]
    pub rules: PathBuf,

    /// JSON resources to check (reads from stdin if not provided)
    #[arg(short, long)]
    pub resource: Option<String>,

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
}

pub async fn run(args: ScanArgs) -> Result<()> {
    // Parse rules
    let all_files = parse_directory(&args.rules).map_err(|e| anyhow::anyhow!("{}", e))?;

    // Apply filters
    let filter = RuleFilter {
        include: args.include,
        exclude: args.exclude,
        tags: args.tags,
        any_tags: args.any_tags,
        min_level: args.min_level,
    };
    let files = if filter.is_empty() {
        all_files
    } else {
        filter.apply(&all_files)
    };

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

    let resources: Vec<serde_json::Value> = if json_str.trim().starts_with('[') {
        serde_json::from_str(&json_str).context("Invalid JSON array")?
    } else {
        vec![serde_json::from_str(&json_str).context("Invalid JSON")?]
    };

    let mut total_rules = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut results: Vec<ResultScan> = Vec::new();

    for (_name, rf) in &files {
        for rule in &rf.rules {
            for resource in &resources {
                let items = extract_resources(resource, &rule.object);
                let targets = if items.is_empty() {
                    vec![resource.clone()]
                } else {
                    items
                };

                for target in &targets {
                    total_rules += 1;
                    let sub_results = check_rule(&rule.conditions, target);
                    let errors: Vec<_> =
                        sub_results.iter().filter(|r| !r.result).cloned().collect();

                    if errors.is_empty() {
                        passed += 1;
                        if args.verbose {
                            println!("  PASS  {}", rule.name);
                        }
                    } else {
                        failed += 1;
                        println!("  FAIL  {} [{}]", rule.name, rule.level);
                        for e in &errors {
                            if let Some(msg) = &e.message {
                                println!("        {}", msg);
                            }
                        }
                        results.push(ResultScan {
                            object_content: target.clone(),
                            rule_name: rule.name.clone(),
                            errors,
                        });
                    }
                }
            }
        }
    }

    println!(
        "\nScan: {} rules, {} passed, {} failed",
        total_rules, passed, failed
    );

    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}
