use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

pub mod alerts;
mod commands;
pub mod config;
pub mod remediation;
mod save;

#[derive(Parser)]
#[command(name = "kxn", about = "Kexa Next Gen — Rust compliance scanner")]
#[command(version)]
struct Cli {
    /// Path to kxn.toml config file
    #[arg(short = 'c', long = "config", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize kxn: build, install, configure MCP for Claude Desktop & Code
    Init(commands::init::InitArgs),
    /// Check a JSON resource against TOML rules (zero infra)
    Check(commands::check::CheckArgs),
    /// Scan resources from providers against rules
    Scan(commands::scan::ScanArgs),
    /// Gather resources from a Terraform provider
    Gather(commands::gather::GatherArgs),
    /// List rules from TOML files
    ListRules(commands::list_rules::ListRulesArgs),
    /// List available providers
    ListProviders(commands::list_providers::ListProvidersArgs),
    /// Start MCP server (stdio)
    Serve(commands::serve::ServeArgs),
    /// Manage community rules from kxn-rules repository
    Rules(commands::rules::RulesArgs),
    /// Continuous compliance monitoring (gather + scan in a loop)
    Watch(commands::watch::WatchArgs),
    /// Continuous monitoring daemon with alerts (simple URI interface)
    Monitor(commands::monitor::MonitorArgs),
    /// List configured targets from kxn.toml
    ListTargets(commands::list_targets::ListTargetsArgs),
}

/// Check if a string looks like a target URI (has a scheme like postgresql://, ssh://, etc.)
fn looks_like_uri(s: &str) -> bool {
    let schemes = [
        "postgresql://",
        "postgres://",
        "mysql://",
        "mongodb://",
        "mongodb+srv://",
        "ssh://",
        "http://",
        "https://",
        "grpc://",
        "oracle://",
    ];
    schemes.iter().any(|scheme| s.starts_with(scheme))
}

/// Parse quick-scan args from raw args (when first arg is a URI)
fn parse_quick_args(args: Vec<String>) -> commands::monitor::QuickScanArgs {
    let uri = args[1].clone();
    let mut compliance = false;
    let mut alerts = Vec::new();
    let mut saves = Vec::new();
    let mut metrics = None;
    let mut rules_dir = None;
    let mut min_level = None;
    let mut output = "text".to_string();
    let mut verbose = false;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--compliance" => compliance = true,
            "--alert" => {
                i += 1;
                if i < args.len() {
                    alerts.push(args[i].clone());
                }
            }
            "--metrics" => {
                i += 1;
                if i < args.len() {
                    metrics = args[i].parse().ok();
                }
            }
            "-R" | "--rules" => {
                i += 1;
                if i < args.len() {
                    rules_dir = Some(PathBuf::from(&args[i]));
                }
            }
            "-l" | "--min-level" => {
                i += 1;
                if i < args.len() {
                    min_level = args[i].parse().ok();
                }
            }
            "-o" | "--output" => {
                i += 1;
                if i < args.len() {
                    output = args[i].clone();
                }
            }
            "--save" => {
                i += 1;
                if i < args.len() {
                    saves.push(args[i].clone());
                }
            }
            "-v" | "--verbose" => verbose = true,
            "--json" => output = "json".to_string(),
            _ => {}
        }
        i += 1;
    }

    commands::monitor::QuickScanArgs {
        uri,
        compliance,
        alerts,
        saves,
        metrics,
        rules_dir,
        min_level,
        output,
        verbose,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    // Quick scan: `kxn postgresql://user:pass@host:5432`
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.len() > 1 && looks_like_uri(&raw_args[1]) {
        let args = parse_quick_args(raw_args);
        return commands::monitor::run_quick(args).await;
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Init(args) => commands::init::run(args).await,
        Commands::Check(args) => commands::check::run(args).await,
        Commands::Scan(args) => commands::scan::run(args).await,
        Commands::Gather(args) => commands::gather::run(args).await,
        Commands::ListRules(args) => commands::list_rules::run(args),
        Commands::ListProviders(args) => commands::list_providers::run(args),
        Commands::Serve(args) => commands::serve::run(args).await,
        Commands::Rules(args) => commands::rules::run(args).await,
        Commands::Watch(args) => commands::watch::run(args).await,
        Commands::Monitor(args) => commands::monitor::run_monitor(args).await,
        Commands::ListTargets(args) => commands::list_targets::run(args),
    }
}
