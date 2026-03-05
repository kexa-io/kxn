use anyhow::{Context, Result};
use clap::Args;
use serde_json::Value;
use std::io::Read;
use std::path::PathBuf;

use kxn_core::{check_rule, ResultScan};
use kxn_rules::{parse_config, parse_directory, resolve_rules, RuleFilter};

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
