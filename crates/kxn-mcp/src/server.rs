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
            instructions: Some("Kexa Next Gen (kxn) — multi-cloud compliance scanner. 736+ rules, 14 providers.\n\n\
                IMPORTANT — When the user asks to scan a database or target (e.g. \"scan mon postgresql\", \"vérifie ma base mysql\", \"scan mes VMs\"):\n\
                → Use kxn_scan with the `target` parameter. This does EVERYTHING automatically: reads kxn.toml config, connects to the target, gathers all resources, filters rules, and scans.\n\
                → Example: kxn_scan(target: \"postgresql\") — no need to gather first, no need for URI or config.\n\
                → Use kxn_list_targets first if you need to see available target names.\n\n\
                Quick reference:\n\
                - kxn_scan(target: \"name\") — FULL auto scan of a configured target (gather + evaluate rules)\n\
                - kxn_list_targets — show all configured targets from kxn.toml\n\
                - kxn_gather(target: \"name\") — gather resources only (no rules evaluation)\n\
                - kxn_list_providers — see native + Terraform providers\n\
                - kxn_list_resource_types(provider) — discover resource types\n\
                - kxn_check_resource(resource, conditions) — check any JSON against conditions (zero infra)\n\
                - kxn_list_rules — see all 736+ compliance rules\n\
                - kxn_provider_schema(provider) — discover Terraform provider types\n\n\
                Providers: ssh, postgresql, mysql, mongodb, kubernetes, github, http, grpc + 3000+ via Terraform gRPC bridge.\n\
                Rules: CIS (SSH, K8s, AWS, Azure, GCP, databases), OWASP API Top 10, IAM, TLS, monitoring.".into()),
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
