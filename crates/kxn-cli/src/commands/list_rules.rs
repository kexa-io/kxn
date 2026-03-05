use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use kxn_rules::{parse_directory, RuleFilter};

#[derive(Args)]
pub struct ListRulesArgs {
    /// Path to rules directory
    #[arg(short = 'R', long = "rules", default_value = "./rules")]
    pub rules: PathBuf,

    /// Filter by provider
    #[arg(short, long)]
    pub provider: Option<String>,

    /// Include rules matching glob patterns
    #[arg(short, long = "include")]
    pub include: Vec<String>,

    /// Exclude rules matching glob patterns
    #[arg(short = 'x', long = "exclude")]
    pub exclude: Vec<String>,

    /// Filter by tags (AND)
    #[arg(short, long = "tag")]
    pub tags: Vec<String>,

    /// Filter by tags (OR)
    #[arg(long = "any-tag")]
    pub any_tags: Vec<String>,

    /// Minimum severity level
    #[arg(short = 'l', long = "min-level")]
    pub min_level: Option<u8>,
}

pub fn run(args: ListRulesArgs) -> Result<()> {
    let all_files = parse_directory(&args.rules).map_err(|e| anyhow::anyhow!("{}", e))?;

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

    let mut total = 0;
    for (name, rf) in &files {
        // Provider filter
        if let Some(ref p) = args.provider {
            if let Some(meta) = &rf.metadata {
                if let Some(mp) = &meta.provider {
                    if mp != p {
                        continue;
                    }
                }
            }
        }

        println!("Rule set: {}", name);
        if let Some(meta) = &rf.metadata {
            if let Some(p) = &meta.provider {
                println!("  Provider: {}", p);
            }
            if !meta.tags.is_empty() {
                println!("  Tags: {}", meta.tags.join(", "));
            }
        }
        for rule in &rf.rules {
            let tags = if rule.tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", rule.tags.join(", "))
            };
            println!(
                "  [{}] {} — {}{}",
                rule.level, rule.name, rule.description, tags
            );
            total += 1;
        }
    }
    println!("\n{} rules in {} file(s)", total, files.len());
    Ok(())
}
