use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;
mod save;

#[derive(Parser)]
#[command(name = "kxn", about = "Kexa Next Gen — Rust compliance scanner")]
#[command(version)]
struct Cli {
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

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
    }
}
