//! MCP server implementation using rmcp v0.1

use rmcp::model::*;
use rmcp::service::{RequestContext, RoleServer};
use rmcp::handler::server::ServerHandler;

use crate::tools;

#[derive(Clone)]
pub struct KxnServer {
    rules_dir: String,
}

impl KxnServer {
    pub fn new(rules_dir: String) -> Self {
        Self { rules_dir }
    }
}

impl ServerHandler for KxnServer {
    fn get_info(&self) -> InitializeResult {
        InitializeResult {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: None,
                }),
                ..Default::default()
            },
            server_info: Implementation {
                name: "kxn".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            instructions: Some("Kexa Next Gen — cloud compliance scanner supporting ALL Terraform providers (AWS, GCP, Azure, GitHub, etc.). Workflow: 1) Use kxn_provider_schema to discover available resource types (no credentials needed), 2) Use kxn_gather to query live resources (credentials via env vars like AWS_PROFILE, GOOGLE_APPLICATION_CREDENTIALS). For Terraform data sources, prefix the type with 'data.' (e.g. data.aws_s3_buckets). Use kxn_check_resource for zero-infra compliance checks.".into()),
        }
    }

    fn list_tools(
        &self,
        _request: PaginatedRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, rmcp::Error>> + Send + '_ {
        async { Ok(tools::list_tools()) }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, rmcp::Error>> + Send + '_ {
        let rules_dir = self.rules_dir.clone();
        async move { tools::call_tool(request, &rules_dir).await }
    }
}
