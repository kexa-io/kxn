use anyhow::Result;
use clap::Args;
use kxn_mcp::KxnServer;
use rmcp::ServiceExt;

use super::webhook;

#[derive(Args)]
pub struct ServeArgs {
    /// Start MCP server on stdio
    #[arg(long)]
    pub mcp: bool,

    /// Start webhook HTTP server
    #[arg(long)]
    pub webhook: bool,

    /// Rules directory
    #[arg(short = 'R', long = "rules", default_value = "./rules")]
    pub rules: String,

    /// Port for webhook server
    #[arg(long, default_value = "8080")]
    pub port: u16,

    /// Alert destinations (slack://, discord://, etc.)
    #[arg(long = "alert")]
    pub alerts: Vec<String>,

    /// Save backends (postgresql://, kafka://, etc.)
    #[arg(long = "save")]
    pub saves: Vec<String>,

    /// Include compliance/monitoring rules
    #[arg(long)]
    pub compliance: bool,

    /// Minimum severity level filter
    #[arg(short = 'l', long = "min-level")]
    pub min_level: Option<u8>,
}

pub async fn run(args: ServeArgs) -> Result<()> {
    if args.webhook {
        return run_webhook(args).await;
    }

    if !args.mcp {
        anyhow::bail!("Use --mcp or --webhook flag to start a server");
    }

    run_mcp(args).await
}

async fn run_mcp(args: ServeArgs) -> Result<()> {
    eprintln!("kxn MCP server starting on stdio...");

    let server = KxnServer::new(args.rules);
    let transport = rmcp::transport::io::stdio();

    let service = server
        .serve(transport)
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {}", e))?;

    service
        .waiting()
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {}", e))?;

    Ok(())
}

async fn run_webhook(args: ServeArgs) -> Result<()> {
    let webhook_args = webhook::WebhookArgs {
        port: args.port,
        alerts: args.alerts,
        saves: args.saves,
        rules: args.rules,
        compliance: args.compliance,
        min_level: args.min_level,
    };
    webhook::run_webhook(webhook_args).await
}
