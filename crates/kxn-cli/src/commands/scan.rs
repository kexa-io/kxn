use anyhow::{Context, Result};
use clap::Args;
use std::io::Read;
use std::path::PathBuf;

use kxn_core::{check_rule, ResultScan};
use kxn_rules::parse_directory;

#[derive(Args)]
pub struct ScanArgs {
    /// Path to TOML rules directory
    #[arg(short = 'R', long = "rules", default_value = "./rules")]
    pub rules: PathBuf,

    /// JSON resources to check (reads from stdin if not provided)
    #[arg(short, long)]
    pub resource: Option<String>,

    /// Show verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

pub async fn run(args: ScanArgs) -> Result<()> {
    // Parse rules
    let files = parse_directory(&args.rules).map_err(|e| anyhow::anyhow!("{}", e))?;

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
                total_rules += 1;
                let sub_results = check_rule(&rule.conditions, resource);
                let errors: Vec<_> = sub_results.iter().filter(|r| !r.result).cloned().collect();

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
                        object_content: resource.clone(),
                        rule_name: rule.name.clone(),
                        errors,
                    });
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
