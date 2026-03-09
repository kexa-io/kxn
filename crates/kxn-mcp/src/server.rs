//! MCP server implementation using rmcp v0.1

use rmcp::model::*;
use rmcp::service::{RequestContext, RoleServer};
use rmcp::handler::server::ServerHandler;

use crate::tools;

#[derive(Clone)]
pub struct KxnServer {
    rules_dir: String,
    config_path: Option<String>,
}

impl KxnServer {
    pub fn new(rules_dir: String) -> Self {
        Self {
            rules_dir,
            config_path: None,
        }
    }

    pub fn with_config(mut self, config_path: Option<String>) -> Self {
        self.config_path = config_path;
        self
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
            instructions: Some("Kexa Next Gen (kxn) — multi-cloud compliance scanner & infrastructure monitor. 736+ rules, 14 providers.\n\n\
                Native providers: ssh, postgresql, mysql, mongodb, kubernetes, github, cloud_run, azure_webapp, http, grpc.\n\
                Terraform providers (via gRPC bridge): aws, google, azurerm, azuread, googleworkspace, cloudflare, vault, and 3000+ others.\n\n\
                Rule coverage: CIS (SSH, K8s API+master+node, AWS, Azure, GCP, O365, Google Workspace, Entra ID, PostgreSQL, MySQL, MongoDB, Oracle), \
                OWASP API Security Top 10, gRPC security, HTTP/HTTPS TLS, IAM (AWS, Azure, GCP), Grafana monitoring, system monitoring, database monitoring.\n\n\
                Workflow:\n\
                1) kxn_list_providers — see all available providers\n\
                2) kxn_list_resource_types — discover resource types for a native provider\n\
                3) kxn_provider_schema — discover Terraform provider types (no credentials needed)\n\
                4) kxn_gather — query live resources (credentials via config JSON or env vars)\n\
                5) kxn_scan — evaluate gathered resources against 736+ compliance rules\n\
                6) kxn_check_resource — check any JSON against conditions (zero infra)\n\
                7) kxn_list_rules — see all available compliance rules\n\
                8) kxn_list_targets — list configured targets from kxn.toml\n\n\
                Unique features: gRPC health check monitoring, OWASP API scanning, K8s node-level CIS via SSH, database CIS, SaaS compliance (O365/Google Workspace).".into()),
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
        let config_path = self.config_path.clone();
        async move { tools::call_tool(request, &rules_dir, config_path.as_deref()).await }
    }
}
