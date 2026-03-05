use anyhow::Result;
use clap::Args;
use kxn_mcp::KxnServer;
use rmcp::ServiceExt;

#[derive(Args)]
pub struct ServeArgs {
    /// Start MCP server on stdio
    #[arg(long)]
    pub mcp: bool,

    /// Rules directory
    #[arg(short = 'R', long = "rules", default_value = "./rules")]
    pub rules: String,
}

pub async fn run(args: ServeArgs) -> Result<()> {
    if !args.mcp {
        anyhow::bail!("Use --mcp flag to start MCP server");
    }

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
