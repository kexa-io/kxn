use anyhow::{Context, Result};
use clap::Args;
use std::io::Read;
use std::path::PathBuf;

use kxn_rules::parse_file;


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

    // The shared scan loop — `kxn check` judges a JSON payload handed on the
    // command line, so there is no target provider to rule packs out and no
    // catalogue to tell a missing object from an uncollectable one.
    let files = vec![(String::new(), rule_file)];
    let resources = vec![resource];
    let mut all_passed = true;

    let totals = kxn_rules::scan(&files, &resources, &kxn_rules::ScanOptions::default(), |event| {
        match event {
            kxn_rules::Event::Pass { rule, .. } => println!("  PASS  {}", rule.name),
            kxn_rules::Event::Violation { rule, failures, .. } => {
                println!("  FAIL  {} [{}]", rule.name, rule.level);
                for f in &failures {
                    if let Some(msg) = &f.message {
                        println!("        {}", msg);
                    }
                }
                all_passed = false;
            }
            // A rule whose object is absent used to be judged against the whole
            // payload, which read every property as missing and invented
            // failures. Say so instead.
            kxn_rules::Event::NotEvaluated { rule, reason, .. } => {
                let what = reason.object().unwrap_or("-");
                println!("  SKIP  {}  (objet '{}' absent du document)", rule.name, what);
            }
        }
    });

    if all_passed {
        println!(
            "\nAll rules passed. ({} évaluées, {} non évaluées)",
            totals.evaluated(),
            totals.not_evaluated
        );
    } else {
        std::process::exit(1);
    }

    Ok(())
}
