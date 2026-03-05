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
            instructions: Some("Kexa Next Gen (kxn) — multi-cloud compliance scanner & infrastructure monitor.\n\n\
                Providers: ssh, postgresql, mysql, mongodb, kubernetes, cloud_run, azure_webapp, http (native) + ALL Terraform providers (aws, google, azurerm, github, cloudflare, vault, etc.).\n\n\
                Workflow:\n\
                1) kxn_list_providers — see all available providers\n\
                2) kxn_list_resource_types — discover resource types for a native provider (e.g. ssh → system_stats, logs, db_stats)\n\
                3) kxn_provider_schema — discover Terraform provider types (no credentials needed)\n\
                4) kxn_gather — query live resources (credentials via config JSON or env vars)\n\
                5) kxn_scan — evaluate gathered resources against compliance rules\n\
                6) kxn_check_resource — check any JSON against conditions (zero infra)\n\
                7) kxn_list_rules — see all available compliance rules\n\n\
                Key resource types: system_stats (33 OS metrics), db_stats (DB monitoring), logs (error/warning logs), cluster_stats (K8s health).".into()),
        }
    }

    async fn list_tools(
        &self,
        _request: PaginatedRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::Error> {
        Ok(tools::list_tools())
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
