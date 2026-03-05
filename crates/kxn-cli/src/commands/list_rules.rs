use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use kxn_rules::parse_directory;

#[derive(Args)]
pub struct ListRulesArgs {
    /// Path to rules directory
    #[arg(short = 'R', long = "rules", default_value = "./rules")]
    pub rules: PathBuf,

    /// Filter by provider
    #[arg(short, long)]
    pub provider: Option<String>,
}

pub fn run(args: ListRulesArgs) -> Result<()> {
    let files =
        parse_directory(&args.rules).map_err(|e| anyhow::anyhow!("{}", e))?;

    let mut total = 0;
    for (name, rf) in &files {
        println!("Rule set: {}", name);
        if let Some(meta) = &rf.metadata {
            if let Some(p) = &meta.provider {
                println!("  Provider: {}", p);
            }
        }
        for rule in &rf.rules {
            println!(
                "  [{}] {} — {}",
                rule.level, rule.name, rule.description
            );
            total += 1;
        }
    }
    println!("\n{} rules in {} file(s)", total, files.len());
    Ok(())
}
