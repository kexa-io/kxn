//! `kxn list-targets` command — display configured targets from kxn.toml.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::config;
use kxn_rules::secrets;

#[derive(Args)]
pub struct ListTargetsArgs {
    /// Path to kxn.toml config file
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,
}

pub fn run(args: ListTargetsArgs) -> Result<()> {
    let config_path = resolve_config_path(args.config)?;

    eprintln!("Loading config from: {}", config_path.display());
    let scan_config = config::load_config(&config_path)?;

    if scan_config.targets.is_empty() {
        println!("No targets configured in {}", config_path.display());
        return Ok(());
    }

    println!(
        "## {} target(s) from {}\n",
        scan_config.targets.len(),
        config_path.display()
    );

    for target in &scan_config.targets {
        let provider = target
            .provider
            .as_deref()
            .unwrap_or("(from URI)");

        let uri_display = target
            .uri
            .as_deref()
            .map(|u| secrets::redact(u))
            .unwrap_or_else(|| "(none)".to_string());

        println!("- **{}**", target.name);
        println!("  provider: {}", provider);
        println!("  uri: {}", uri_display);

        if !target.rules.is_empty() {
            println!("  rules: {}", target.rules.join(", "));
        }
        if let Some(interval) = target.interval {
            println!("  interval: {}s", interval);
        }
        println!();
    }

    Ok(())
}

/// Resolve config path from CLI arg or discovery.
fn resolve_config_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    config::discover_config()
        .ok_or_else(|| anyhow::anyhow!(
            "No kxn.toml found. Searched: ./kxn.toml, \
             ~/.config/kxn/kxn.toml, ~/.kxn.toml"
        ))
}
