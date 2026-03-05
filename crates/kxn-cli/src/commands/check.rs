use anyhow::{Context, Result};
use clap::Args;
use serde_json::Value;
use std::io::Read;
use std::path::PathBuf;

use kxn_core::check_rule;
use kxn_rules::parse_file;

/// Extract resources from JSON by object key.
/// If root is `{"request": [{...}, {...}]}` and object is "request",
/// returns the array items. If root is already an array, returns its items.
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
pub struct CheckArgs {
    /// Path to TOML rules file
    #[arg(short = 'R', long = "rules")]
    rules: PathBuf,

    /// JSON resource to check (reads from stdin if not provided)
    #[arg(short, long)]
    resource: Option<String>,
}

pub async fn run(args: CheckArgs) -> Result<()> {
    // Parse rules
    let rule_file =
        parse_file(&args.rules).map_err(|e| anyhow::anyhow!("Failed to parse rules: {}", e))?;

    // Read resource JSON
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
    let resource: serde_json::Value =
        serde_json::from_str(&json_str).context("Invalid JSON resource")?;

    // Evaluate each rule
    let mut all_passed = true;
    for rule in &rule_file.rules {
        // Extract resources matching rule.object from the JSON
        let resources = extract_resources(&resource, &rule.object);

        if resources.is_empty() {
            // No matching resources — evaluate against the root object
            let results = check_rule(&rule.conditions, &resource);
            let failures: Vec<_> = results.iter().filter(|r| !r.result).collect();
            if failures.is_empty() {
                println!("  PASS  {}", rule.name);
            } else {
                println!("  FAIL  {} [{}]", rule.name, rule.level);
                for f in &failures {
                    if let Some(msg) = &f.message {
                        println!("        {}", msg);
                    }
                }
                all_passed = false;
            }
        } else {
            for (i, res) in resources.iter().enumerate() {
                let results = check_rule(&rule.conditions, res);
                let failures: Vec<_> = results.iter().filter(|r| !r.result).collect();
                let label = if resources.len() > 1 {
                    format!("{}[{}]", rule.name, i)
                } else {
                    rule.name.clone()
                };
                if failures.is_empty() {
                    println!("  PASS  {}", label);
                } else {
                    println!("  FAIL  {} [{}]", label, rule.level);
                    for f in &failures {
                        if let Some(msg) = &f.message {
                            println!("        {}", msg);
                        }
                    }
                    all_passed = false;
                }
            }
        }
    }

    if all_passed {
        println!("\nAll rules passed.");
    } else {
        std::process::exit(1);
    }

    Ok(())
}
