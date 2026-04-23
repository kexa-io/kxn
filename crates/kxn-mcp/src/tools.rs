//! MCP tool definitions — 9 tools for Kexa compliance scanning

use rmcp::model::*;
use serde_json::json;
use std::path::Path;
use std::sync::Arc;

use kxn_core::check_rule;
use kxn_providers::{ProviderAddress, TerraformProvider, parse_target_uri, create_native_provider};
use kxn_rules::parse_directory;
use kxn_rules::secrets;

/// Resolve `${...}` placeholders in a string (env vars + cloud secrets).
async fn resolve_secrets(s: &str) -> String {
    let refs = secrets::extract_refs(s);
    if refs.is_empty() {
        return s.to_string();
    }
    let mut resolved = std::collections::HashMap::new();
    for (placeholder, secret_ref) in &refs {
        match secret_ref {
            secrets::SecretRef::EnvVar(name) => {
                if let Ok(val) = std::env::var(name) {
                    resolved.insert(placeholder.clone(), val);
                }
            }
            secrets::SecretRef::Gcp { project, name } => {
                if let Ok(val) = kxn_providers::secrets::gcp_secrets::get_secret(project, name).await {
                    resolved.insert(placeholder.clone(), val);
                }
            }
            secrets::SecretRef::Azure { vault, name } => {
                if let Ok(val) = kxn_providers::secrets::azure_keyvault::get_secret(vault, name).await {
                    resolved.insert(placeholder.clone(), val);
                }
            }
            secrets::SecretRef::Aws { secret_name, key } => {
                if let Ok(val) = kxn_providers::secrets::aws_secrets::get_secret(secret_name, key).await {
                    resolved.insert(placeholder.clone(), val);
                }
            }
            secrets::SecretRef::Vault { path, key } => {
                if let Ok(val) = kxn_providers::secrets::hashicorp_vault::get_secret(path, key).await {
                    resolved.insert(placeholder.clone(), val);
                }
            }
        }
    }
    secrets::interpolate(s, &resolved)
}

pub fn list_tools() -> ListToolsResult {
    ListToolsResult {
        tools: vec![
            tool_def(
                "kxn_list_providers",
                "List all available providers: native (ssh, postgresql, mysql, mongodb, oracle, kubernetes, github, http, grpc) and cached Terraform providers (aws, google, azurerm, azuread, googleworkspace, cloudflare, vault, etc.).",
                json!({"type":"object","properties":{"provider":{"type":"string","description":"Filter by provider name"}}})
            ),
            tool_def(
                "kxn_list_resource_types",
                "List available resource types for a native provider. Use this BEFORE kxn_gather to discover what can be gathered. Examples: ssh → sshd_config, system_stats, logs, kubelet_config, k8s_master_config; postgresql → databases, db_stats, settings; kubernetes → pods, deployments, nodes, cluster_stats; github → organization, repositories; grpc → health_check, connection, reflection, service_health; http → request.",
                json!({"type":"object","properties":{
                    "provider":{"type":"string","description":"Native provider name (ssh, postgresql, mysql, mongodb, kubernetes, github, http, grpc)"}
                },"required":["provider"]})
            ),
            tool_def(
                "kxn_list_rules",
                "Parse and list all compliance rules from TOML files (736+ rules). Covers: CIS benchmarks (SSH, K8s, AWS, Azure, GCP, O365, Google Workspace, Entra ID, PostgreSQL, MySQL, MongoDB, Oracle), OWASP API Security Top 10, gRPC security, HTTP/HTTPS TLS, Grafana monitoring, system monitoring, database monitoring.",
                json!({"type":"object","properties":{
                    "rulesDirectory":{"type":"string","description":"Path to rules directory (default: ./rules)"},
                    "provider":{"type":"string","description":"Filter rules by provider"}
                }})
            ),
            tool_def(
                "kxn_provider_schema",
                "Discover resource types and attributes of any Terraform provider. No credentials needed. Use this BEFORE kxn_gather to find available types for Terraform providers.",
                json!({"type":"object","properties":{
                    "provider":{"type":"string","description":"Provider address (e.g. hashicorp/aws, hashicorp/google, hashicorp/azurerm)"},
                    "filter":{"type":"string","description":"Substring filter on type names (e.g. s3, compute, virtual_machine)"},
                    "typeName":{"type":"string","description":"Specific type name to get its attributes (e.g. aws_s3_bucket)"},
                    "version":{"type":"string","description":"Provider version (default: latest)"}
                },"required":["provider"]})
            ),
            tool_def(
                "kxn_gather",
                "Gather live resources from any provider. Native: ssh (system_stats, logs, sshd_config, sysctl, users, services, os_info, file_permissions, kubelet_config, k8s_master_config), postgresql (databases, db_stats, logs, roles, settings, stat_activity, extensions), mysql (databases, db_stats, logs, users, grants, variables, status, processlist), mongodb (databases, db_stats, logs, users, serverStatus, currentOp, cmdLineOpts), kubernetes (26 types: pods with securityContext, deployments, services, nodes, namespaces, ingresses, events, cluster_stats, jobs, hpa, daemonsets, statefulsets, cronjobs, rbac, network_policies, PV/PVC, node_metrics, pod_metrics, pod_logs), github (organization, repositories, webhooks, actions_org_secrets, members, teams, dependabot_alerts, actions_permissions), grpc (health_check, connection, reflection, service_health), http (request). Also supports ALL Terraform providers (hashicorp/aws, hashicorp/google, azuread, googleworkspace, etc.).",
                json!({"type":"object","properties":{
                    "provider":{"type":"string","description":"Provider name: ssh, postgresql, mysql, mongodb, kubernetes, github, http, grpc (native) or hashicorp/aws, hashicorp/google, etc. (Terraform)"},
                    "resourceType":{"type":"string","description":"Resource type (e.g. system_stats, db_stats, pods, logs). For Terraform data sources, use 'data.' prefix"},
                    "config":{"type":"string","description":"Provider config JSON. Examples: {\"SSH_HOST\":\"10.0.0.1\",\"SSH_USER\":\"root\"} for ssh, {\"PG_HOST\":\"db\",\"PG_USER\":\"admin\"} for postgresql. For credentials, use 'target' parameter instead to keep secrets in kxn.toml."},
                    "target":{"type":"string","description":"Target name from kxn.toml (uses its provider and config, overrides provider/config params)"},
                    "version":{"type":"string","description":"Provider version (Terraform only, default: latest)"}
                },"required":["provider","resourceType"]})
            ),
            tool_def(
                "kxn_scan",
                "Run a full compliance scan: load 736+ rules, evaluate against resources. Returns violations with severity, compliance framework mapping (CIS, OWASP, PCI-DSS), and remediation. Covers: SSH CIS, K8s CIS (API+master+node), AWS/Azure/GCP CIS+IAM, O365, Google Workspace, Entra ID, PostgreSQL/MySQL/MongoDB/Oracle CIS, OWASP API Top 10, gRPC security, HTTP/HTTPS TLS, Grafana, system monitoring.",
                json!({"type":"object","properties":{
                    "rulesDirectory":{"type":"string","description":"Path to rules directory (default: ./rules)"},
                    "resource":{"type":"string","description":"JSON resource(s) to scan"},
                    "target":{"type":"string","description":"Target name from kxn.toml (uses its rules filter and config)"},
                    "verbose":{"type":"boolean","description":"Include resource content in violations"}
                }})
            ),
            tool_def(
                "kxn_check_resource",
                "Check any JSON resource against Kexa conditions — zero infrastructure required. Conditions: EQUAL, DIFFERENT, SUP, INF, SUP_OR_EQUAL, INF_OR_EQUAL, INCLUDE, REGEX, STARTS_WITH, ENDS_WITH, DATE_INF/SUP. Supports nested AND/OR/NAND/NOR operators.",
                json!({"type":"object","properties":{
                    "resource":{"type":"string","description":"JSON string of the resource to check"},
                    "conditions":{"type":"string","description":"JSON string of Kexa conditions array"}
                },"required":["resource","conditions"]})
            ),
            tool_def(
                "kxn_list_targets",
                "List configured scan targets from kxn.toml config file. Shows target name, provider, URI (with secrets redacted), associated rules, and scan interval.",
                json!({"type":"object","properties":{
                    "configPath":{"type":"string","description":"Path to kxn.toml config file (default: auto-discover)"}
                }})
            ),
            tool_def(
                "kxn_remediate",
                "Scan a target for compliance violations and remediate selected ones. TWO modes:\n\n1) **List mode** (no `rules` param): scans and returns all violations that have remediations available. Shows rule names, descriptions, and what the remediation would do. Use this first to let the user choose.\n\n2) **Apply mode** (`rules` param with list of rule names): executes ONLY the selected remediations. Shell commands are batched (one service restart at the end). SQL commands get one reload at the end.\n\nWorkflow: call once without `rules` to show options → user picks → call again with `rules` array.",
                json!({"type":"object","properties":{
                    "target":{"type":"string","description":"Target name from kxn.toml"},
                    "rulesDirectory":{"type":"string","description":"Path to rules directory (default: ./rules)"},
                    "rules":{"type":"array","items":{"type":"string"},"description":"List of exact rule names to remediate. Triggers apply mode."},
                    "applyFilter":{"type":"string","description":"Apply all remediations for rules matching this substring (e.g. 'ssh-cis-5.2' or 'protocol'). Triggers apply mode."},
                    "ruleFilter":{"type":"string","description":"Pre-filter: only consider violations matching this rule name substring (works in both list and apply modes)"}
                },"required":["target"]})
            ),
        ],
        next_cursor: None,
    }
}

fn tool_def(name: &str, description: &str, schema: serde_json::Value) -> Tool {
    let schema_map = match schema {
        serde_json::Value::Object(o) => Arc::new(o),
        _ => Arc::new(serde_json::Map::new()),
    };
    Tool {
        name: name.to_string().into(),
        description: description.to_string().into(),
        input_schema: schema_map,
    }
}

pub async fn call_tool(
    request: CallToolRequestParam,
    rules_dir: &str,
    config_path: Option<&str>,
) -> Result<CallToolResult, rmcp::Error> {
    let args = request.arguments.unwrap_or_default();
    let result = match request.name.as_ref() {
        "kxn_list_providers" => tool_list_providers(&args),
        "kxn_list_resource_types" => tool_list_resource_types(&args).await,
        "kxn_list_rules" => tool_list_rules(&args, rules_dir),
        "kxn_provider_schema" => tool_provider_schema(&args).await,
        "kxn_gather" => tool_gather(&args, config_path).await,
        "kxn_scan" => tool_scan(&args, rules_dir, config_path).await,
        "kxn_check_resource" => tool_check_resource(&args),
        "kxn_list_targets" => tool_list_targets(&args, config_path),
        "kxn_remediate" => tool_remediate(&args, rules_dir, config_path).await,
        other => Err(format!("Unknown tool: {}", other)),
    };

    match result {
        Ok(text) => Ok(CallToolResult::success(vec![Content::text(text)])),
        Err(err) => Ok(CallToolResult::error(vec![Content::text(err)])),
    }
}

fn get_str<'a>(args: &'a serde_json::Map<String, serde_json::Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|v| v.as_str())
}

/// Validate a rules directory path: reject path traversal and absolute paths.
fn validate_rules_dir(dir: &str) -> Result<(), String> {
    if dir.contains("..") {
        return Err("rulesDirectory must not contain '..' (path traversal)".into());
    }
    if Path::new(dir).is_absolute() {
        return Err("rulesDirectory must be a relative path".into());
    }
    Ok(())
}

fn tool_list_providers(
    args: &serde_json::Map<String, serde_json::Value>,
) -> Result<String, String> {
    let filter = get_str(args, "provider");

    let mut lines = vec!["## Native providers (built-in)".to_string()];
    for name in kxn_providers::native_provider_names() {
        if let Some(f) = filter {
            if !name.contains(f) {
                continue;
            }
        }
        lines.push(format!("- {} (native)", name));
    }

    let registry =
        kxn_providers::ProviderRegistry::new().map_err(|e| format!("{}", e))?;
    let cached = registry.list_cached().map_err(|e| format!("{}", e))?;

    if !cached.is_empty() {
        lines.push("\n## Cached Terraform providers".to_string());
        for (addr, version) in &cached {
            if let Some(f) = filter {
                if !addr.name.contains(f) && !addr.namespace.contains(f) {
                    continue;
                }
            }
            lines.push(format!("- {}/{} v{}", addr.namespace, addr.name, version));
        }
    }

    Ok(lines.join("\n"))
}

async fn tool_list_resource_types(
    args: &serde_json::Map<String, serde_json::Value>,
) -> Result<String, String> {
    let provider_name = get_str(args, "provider")
        .ok_or("Missing required parameter: provider")?;

    let native_names = kxn_providers::native_provider_names();

    if !native_names.contains(&provider_name) {
        return Err(format!(
            "Unknown native provider '{}'. Available: {}",
            provider_name,
            native_names.join(", ")
        ));
    }

    // For providers that need config to construct, we return a static list
    let types: Vec<&str> = match provider_name {
        "ssh" => vec!["sshd_config", "sysctl", "users", "services", "file_permissions", "os_info", "system_stats", "logs", "kubelet_config", "k8s_master_config"],
        "postgresql" => vec!["databases", "roles", "settings", "stat_activity", "extensions", "db_stats", "logs"],
        "mysql" => vec!["databases", "users", "grants", "variables", "status", "engines", "processlist", "db_stats", "logs"],
        "mongodb" => vec!["databases", "users", "serverStatus", "currentOp", "db_stats", "logs", "cmdLineOpts"],
        "kubernetes" | "k8s" => vec![
            "pods", "deployments", "services", "nodes", "namespaces", "ingresses",
            "configmaps", "secrets_metadata", "events", "cluster_stats",
            "rbac_cluster_roles", "rbac_cluster_role_bindings", "network_policies",
            "persistent_volumes", "persistent_volume_claims", "daemonsets", "statefulsets",
            "cronjobs", "service_accounts", "jobs", "hpa", "resource_quotas", "limit_ranges",
            "node_metrics", "pod_metrics", "pod_logs",
        ],
        "github" | "gh" => vec![
            "organization", "members", "outside_collaborators", "teams", "webhooks",
            "audit_log", "security_managers", "custom_roles",
            "repositories", "rulesets", "environments", "deploy_keys", "autolinks",
            "dependabot_alerts", "secret_scanning_alerts", "code_scanning_alerts",
            "actions_permissions", "actions_org_secrets", "actions_org_variables",
            "actions_runners", "actions_workflows",
            "packages", "copilot_usage", "codeowners", "community_metrics",
        ],
        "http" => vec!["request"],
        "grpc" => vec!["health_check", "connection", "reflection", "service_health"],
        "oracle" => vec!["users", "tables", "privileges", "sessions", "parameters", "views", "triggers", "db_stats", "logs"],
        _ => vec![],
    };

    let mut lines = vec![format!("## {} — {} resource types", provider_name, types.len())];
    for t in &types {
        let desc = match *t {
            "system_stats" => "CPU, memory, disk, swap, network, load, processes (33 metrics)",
            "db_stats" => "Internal DB monitoring: connections, cache hit ratio, locks, replication lag, queries",
            "logs" => "Error/warning logs from system journal, auth, DB logs",
            "sshd_config" => "SSH server configuration directives",
            "sysctl" => "Kernel parameters (sysctl -a)",
            "users" => "System or DB users",
            "services" => "Systemd services",
            "os_info" => "OS release, kernel, hostname",
            "pods" => "Kubernetes pods with container status and restarts",
            "deployments" => "Kubernetes deployments with replica counts",
            "nodes" => "Kubernetes nodes with capacity and conditions",
            "cluster_stats" => "Kubernetes cluster summary: pod/node/deployment counts, restarts, events",
            "events" => "Kubernetes warning events",
            "node_metrics" => "CPU/memory usage per node (requires metrics-server)",
            "pod_metrics" => "CPU/memory usage per container (requires metrics-server)",
            "pod_logs" => "Error/warning lines from pod logs (last 100 lines, max 50 pods)",
            "jobs" => "Batch job status and completion",
            "hpa" => "Horizontal Pod Autoscaler status and scaling",
            "resource_quotas" => "Namespace resource quotas",
            "limit_ranges" => "Namespace limit ranges",
            "rbac_cluster_roles" => "Cluster-wide RBAC roles",
            "rbac_cluster_role_bindings" => "Cluster-wide RBAC role bindings",
            "network_policies" => "Network policies per namespace",
            "persistent_volumes" => "Cluster persistent volumes",
            "persistent_volume_claims" => "Persistent volume claims",
            "daemonsets" => "DaemonSet status across nodes",
            "statefulsets" => "StatefulSet replica status",
            "cronjobs" => "CronJob schedules and last run",
            "service_accounts" => "Service accounts per namespace",
            "secrets_metadata" => "Secret names and types (no values)",
            "configmaps" => "ConfigMaps per namespace",
            "ingresses" => "Ingress rules and backends",
            "organization" => "GitHub org settings: 2FA, permissions, fork policy",
            "repositories" => "Repos with branch protection, vulnerability alerts, secret scanning",
            "webhooks" => "Org webhooks with SSL verification status",
            "actions_org_secrets" => "Org Actions secrets with visibility scope",
            "actions_org_variables" => "Org Actions variables",
            "actions_runners" => "Self-hosted Actions runners",
            "actions_workflows" => "Actions workflows across all repos",
            "members" => "Org members with roles and 2FA status",
            "outside_collaborators" => "External collaborators with repo access",
            "teams" => "Org teams with members and repo counts",
            "dependabot_alerts" => "Open Dependabot vulnerability alerts",
            "secret_scanning_alerts" => "Open secret scanning alerts across repos",
            "code_scanning_alerts" => "Open CodeQL/SAST alerts across repos",
            "actions_permissions" => "Org-level Actions permissions and policies",
            "audit_log" => "Org audit log events (last 100)",
            "security_managers" => "Teams with security manager role",
            "custom_roles" => "Custom repository roles",
            "rulesets" => "Org-level repository rulesets",
            "environments" => "Deployment environments with protection rules",
            "deploy_keys" => "Deploy keys across all repos",
            "autolinks" => "Autolink references across repos",
            "packages" => "Published packages (npm, docker, maven, etc.)",
            "copilot_usage" => "Copilot billing and seat usage",
            "codeowners" => "CODEOWNERS file presence per repo",
            "community_metrics" => "Community profile (README, LICENSE, CoC, etc.)",
            "settings" | "variables" | "parameters" => "Database configuration settings",
            "databases" => "Database list with tables, indexes, sizes",
            "http_response" => "HTTP response: status, headers, timing, TLS info",
            "request" => "HTTP response: status code, headers, timing, TLS, certificate",
            "kubelet_config" => "K8s worker node config: kubelet.yaml, process args, file permissions (CIS 4.x)",
            "k8s_master_config" => "K8s control plane config: apiserver, controller, scheduler, etcd args + file perms (CIS 1.x-2.x)",
            "cmdLineOpts" => "MongoDB startup config: security, TLS, audit, network settings",
            "health_check" => "gRPC health check: SERVING status, response time, gRPC status code",
            "connection" => "gRPC connection: connectivity, TLS status, connect time",
            "reflection" => "gRPC server reflection: service discovery, registered services",
            "service_health" => "gRPC per-service health: status of each registered service",
            _ => "",
        };
        if desc.is_empty() {
            lines.push(format!("- `{}`", t));
        } else {
            lines.push(format!("- `{}` — {}", t, desc));
        }
    }

    Ok(lines.join("\n"))
}

fn tool_list_rules(
    args: &serde_json::Map<String, serde_json::Value>,
    default_dir: &str,
) -> Result<String, String> {
    let dir = get_str(args, "rulesDirectory").unwrap_or(default_dir);
    if let Some(user_dir) = get_str(args, "rulesDirectory") {
        validate_rules_dir(user_dir)?;
    }

    let files = parse_directory(Path::new(dir))?;

    let mut lines = vec![format!("## Rules from `{}`", dir)];
    let mut total = 0;
    let mut by_level = [0u32; 4];

    for (name, rf) in &files {
        lines.push(format!("\n### {}", name));
        for rule in &rf.rules {
            let level_idx = rule.level as usize;
            if level_idx < 4 {
                by_level[level_idx] += 1;
            }
            lines.push(format!(
                "- [{}] **{}** — {}",
                rule.level, rule.name, rule.description
            ));
            total += 1;
        }
    }

    lines.insert(
        1,
        format!(
            "- **{}** rules, {} file(s). By level: info={}, warning={}, error={}, fatal={}",
            total,
            files.len(),
            by_level[0],
            by_level[1],
            by_level[2],
            by_level[3]
        ),
    );
    Ok(lines.join("\n"))
}

async fn tool_provider_schema(
    args: &serde_json::Map<String, serde_json::Value>,
) -> Result<String, String> {
    let provider_name = get_str(args, "provider").ok_or("Missing required parameter: provider")?;
    let filter = get_str(args, "filter");
    let type_name = get_str(args, "typeName");
    let version = get_str(args, "version");

    let address = ProviderAddress::parse(provider_name).map_err(|e| format!("{}", e))?;

    let provider = TerraformProvider::schema_only(address, version)
        .await
        .map_err(|e| format!("Failed to load provider schema: {}", e))?;

    // If a specific type is requested, return its attributes
    if let Some(tn) = type_name {
        let is_data = tn.starts_with("data.");
        let bare_name = if is_data { &tn[5..] } else { tn };

        let attrs = if is_data {
            provider.data_source_attributes(bare_name).await
        } else {
            provider.type_attributes(bare_name).await
        }
        .map_err(|e| format!("{}", e))?;

        let mut lines = vec![format!("## {} — {} attributes", tn, attrs.len())];
        for attr in &attrs {
            lines.push(format!("- {}", attr));
        }
        return Ok(lines.join("\n"));
    }

    // List all types, optionally filtered
    let resource_types = provider.resource_types();
    let data_source_types = provider.data_source_types();

    let matches_filter = |name: &str| -> bool {
        match filter {
            Some(f) => name.contains(f),
            None => true,
        }
    };

    let filtered_resources: Vec<&String> = resource_types.iter().filter(|t| matches_filter(t)).collect();
    let filtered_data: Vec<&String> = data_source_types.iter().filter(|t| matches_filter(t)).collect();

    let mut lines = vec![format!(
        "## {}/{} — types{}",
        provider_name,
        version.unwrap_or("latest"),
        filter.map(|f| format!(" matching \"{}\"", f)).unwrap_or_default()
    )];

    if !filtered_resources.is_empty() {
        lines.push(format!("\n### Resource types ({})", filtered_resources.len()));
        lines.push(filtered_resources.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(", "));
    }

    if !filtered_data.is_empty() {
        lines.push(format!(
            "\n### Data source types ({}) — use \"data.\" prefix to query",
            filtered_data.len()
        ));
        lines.push(
            filtered_data
                .iter()
                .map(|t| format!("data.{}", t))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }

    if filtered_resources.is_empty() && filtered_data.is_empty() {
        lines.push("\nNo types found matching the filter.".to_string());
    }

    Ok(lines.join("\n"))
}

async fn tool_gather(
    args: &serde_json::Map<String, serde_json::Value>,
    mcp_config_path: Option<&str>,
) -> Result<String, String> {
    // If target is specified, resolve provider + config from kxn.toml
    let (provider_name, resource_type, config, version_owned);
    if let Some(target_name) = get_str(args, "target") {
        let path = match mcp_config_path {
            Some(p) => std::path::PathBuf::from(p),
            None => discover_config()
                .ok_or("No kxn.toml found. Pass configPath or use --config on serve.")?,
        };
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
        let scan_config: kxn_rules::config::ScanConfig = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;
        let target = scan_config
            .targets
            .iter()
            .find(|t| t.name == target_name)
            .ok_or_else(|| format!("Target '{}' not found", target_name))?;
        let raw_uri = target
            .uri
            .as_deref()
            .ok_or_else(|| format!("Target '{}' has no URI", target_name))?;
        let uri = resolve_secrets(raw_uri).await;
        let (pname, pconfig) = parse_target_uri(&uri).map_err(|e| format!("{}", e))?;
        provider_name = pname;
        resource_type = get_str(args, "resourceType")
            .unwrap_or("__all__")
            .to_string();
        config = pconfig;
        version_owned = None;
    } else {
        provider_name = get_str(args, "provider")
            .ok_or("Missing required parameter: provider")?
            .to_string();
        resource_type = get_str(args, "resourceType")
            .ok_or("Missing required parameter: resourceType")?
            .to_string();
        let config_str = get_str(args, "config").unwrap_or("{}");
        config = serde_json::from_str(config_str)
            .map_err(|e| format!("Invalid config JSON: {}", e))?;
        version_owned = get_str(args, "version").map(|s| s.to_string());
    }
    let version = version_owned.as_deref();

    let native_names = kxn_providers::native_provider_names();

    if native_names.contains(&provider_name.as_str()) {
        // Native provider: gather all or specific type
        let provider =
            create_native_provider(&provider_name, config).map_err(|e| format!("{}", e))?;

        if resource_type == "__all__" {
            let all = provider.gather_all().await.map_err(|e| format!("{}", e))?;
            let mut merged = serde_json::Map::new();
            for (rt, items) in all {
                merged.insert(rt, serde_json::Value::Array(items));
            }
            return format_gather_output(&provider_name, "all", &serde_json::Value::Object(merged));
        }

        let resources = provider
            .gather(&resource_type)
            .await
            .map_err(|e| format!("{}", e))?;

        return format_gather_output(&provider_name, &resource_type, &serde_json::to_value(&resources).unwrap_or_default());
    }

    // Terraform provider path
    let address = ProviderAddress::parse(&provider_name).map_err(|e| format!("{}", e))?;

    let user_config = config.clone();
    let mut provider = TerraformProvider::new(address, config, version)
        .await
        .map_err(|e| format!("Failed to start Terraform provider: {}", e))?;

    let is_data_source = resource_type.starts_with("data.");
    let type_name = if is_data_source {
        &resource_type[5..]
    } else {
        &resource_type
    };

    let result = if is_data_source {
        let ds_config = provider
            .build_data_source_config(type_name, user_config)
            .await
            .map_err(|e| format!("{}", e))?;
        provider.read_data_source(type_name, ds_config).await
    } else {
        let state = serde_json::json!({});
        provider.read_resource(type_name, state).await
    };

    // Always stop the provider
    provider.stop().await.ok();

    match result {
        Ok(Some(value)) => format_gather_output(&provider_name, &resource_type, &value),
        Ok(None) => Ok(format!("## {} / {} — no data returned", provider_name, resource_type)),
        Err(e) => Err(format!("Gather failed: {}", e)),
    }
}

fn format_gather_output(provider_name: &str, resource_type: &str, value: &serde_json::Value) -> Result<String, String> {
    let count = match value {
        serde_json::Value::Array(arr) => arr.len().to_string(),
        serde_json::Value::Object(_) => "1".to_string(),
        _ => "?".to_string(),
    };

    let mut lines = vec![format!(
        "## {} / {} — {} resource(s)",
        provider_name, resource_type, count
    )];

    let json_str = serde_json::to_string_pretty(value)
        .map_err(|e| format!("JSON serialization error: {}", e))?;

    // Cap output at ~100KB for MCP
    let max_len = 100_000;
    if json_str.len() > max_len {
        lines.push(format!("```json\n{}...\n```", &json_str[..max_len]));
        lines.push(format!(
            "\n(output truncated: {} bytes total)",
            json_str.len()
        ));
    } else {
        lines.push(format!("```json\n{}\n```", json_str));
    }

    Ok(lines.join("\n"))
}

async fn tool_scan(
    args: &serde_json::Map<String, serde_json::Value>,
    default_dir: &str,
    config_path: Option<&str>,
) -> Result<String, String> {
    if let Some(user_dir) = get_str(args, "rulesDirectory") {
        validate_rules_dir(user_dir)?;
    }
    let dir = get_str(args, "rulesDirectory").unwrap_or(default_dir);
    let verbose = args
        .get("verbose")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let target_name = get_str(args, "target");

    // If target is specified, load config, gather resources, filter rules
    if let Some(tname) = target_name {
        return tool_scan_target(tname, dir, verbose, config_path).await;
    }

    // Fallback: scan provided resource JSON against all rules
    let resource_str = get_str(args, "resource").unwrap_or("{}");
    let resources: Vec<serde_json::Value> = if resource_str.trim().starts_with('[') {
        serde_json::from_str(resource_str).map_err(|e| format!("Invalid JSON array: {}", e))?
    } else {
        vec![serde_json::from_str(resource_str).map_err(|e| format!("Invalid JSON: {}", e))?]
    };

    let files = parse_directory(Path::new(dir))?;
    run_scan(&files, &resources, verbose, None)
}

/// Scan a target from kxn.toml: gather resources, filter rules, evaluate.
async fn tool_scan_target(
    target_name: &str,
    rules_dir: &str,
    verbose: bool,
    config_path: Option<&str>,
) -> Result<String, String> {
    // 1. Load config
    let path = match config_path {
        Some(p) => std::path::PathBuf::from(p),
        None => discover_config()
            .ok_or("No kxn.toml found. Pass configPath or use --config on serve.")?,
    };
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let config: kxn_rules::config::ScanConfig = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

    // 2. Find the target
    let target = config
        .targets
        .iter()
        .find(|t| t.name == target_name)
        .ok_or_else(|| format!("Target '{}' not found in {}", target_name, path.display()))?;

    // 3. Parse URI → provider + config (resolve ${ENV} vars)
    let raw_uri = target
        .uri
        .as_deref()
        .ok_or_else(|| format!("Target '{}' has no URI", target_name))?;
    let uri = resolve_secrets(raw_uri).await;
    let (provider_name, provider_config) =
        parse_target_uri(&uri).map_err(|e| format!("{}", e))?;

    // 4. Gather all resource types
    let provider =
        create_native_provider(&provider_name, provider_config).map_err(|e| format!("{}", e))?;
    let all_resources = provider
        .gather_all()
        .await
        .map_err(|e| format!("Gather failed for {}: {}", target_name, e))?;

    // Merge all gathered resources into a single JSON object
    let mut merged = serde_json::Map::new();
    for (rt, items) in &all_resources {
        merged.insert(rt.clone(), serde_json::Value::Array(items.clone()));
    }
    let resources = vec![serde_json::Value::Object(merged)];

    // 5. Load and filter rules by target's rule list
    let files = parse_directory(Path::new(rules_dir))?;
    let rule_filter: Vec<&str> = target.rules.iter().map(|s| s.as_str()).collect();

    run_scan(&files, &resources, verbose, Some(&rule_filter))
}

/// Run scan: evaluate rules against resources.
fn run_scan(
    files: &[(String, kxn_rules::RuleFile)],
    resources: &[serde_json::Value],
    verbose: bool,
    rule_filter: Option<&[&str]>,
) -> Result<String, String> {
    let mut total = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut violations = Vec::new();

    for (name, rf) in files {
        // Filter by rule set names from target config
        if let Some(filter) = rule_filter {
            let file_stem = name.trim_end_matches(".toml");
            if !filter.contains(&file_stem) {
                continue;
            }
        }

        for rule in &rf.rules {
            for resource in resources {
                let items = if rule.object.is_empty() {
                    vec![resource.clone()]
                } else {
                    match resource.get(&rule.object) {
                        Some(serde_json::Value::Array(arr)) => arr.clone(),
                        Some(val) => vec![val.clone()],
                        None => continue, // No matching data for this rule object
                    }
                };

                for target in &items {
                    total += 1;
                    let results = check_rule(&rule.conditions, target);
                    let errors: Vec<_> = results.iter().filter(|r| !r.result).collect();

                    if errors.is_empty() {
                        passed += 1;
                    } else {
                        failed += 1;
                        violations.push(format_violation(rule, &errors, verbose, target));
                    }
                }
            }
        }
    }

    let mut lines = vec![
        "## Scan results".to_string(),
        format!(
            "- **{}** rules, **{}** passed, **{}** failed",
            total, passed, failed
        ),
    ];

    if !violations.is_empty() {
        lines.push(format!("\n## Violations ({})", violations.len()));
        lines.extend(violations);
    } else {
        lines.push("\nNo violations found.".to_string());
    }

    Ok(lines.join("\n"))
}

fn format_violation(
    rule: &kxn_core::Rule,
    errors: &[&kxn_core::SubResultScan],
    verbose: bool,
    target: &serde_json::Value,
) -> String {
    let level_label = match rule.level {
        kxn_core::Level::Info => "INFO",
        kxn_core::Level::Warning => "WARNING",
        kxn_core::Level::Error => "ERROR",
        kxn_core::Level::Fatal => "FATAL",
    };
    let mut v = format!("### [{}] {}\n", level_label, rule.name);
    v.push_str(&format!("- {}\n", rule.description));

    if !rule.compliance.is_empty() {
        let refs: Vec<String> = rule
            .compliance
            .iter()
            .map(|c| {
                let mut s = format!("{} {}", c.framework, c.control);
                if let Some(ref sec) = c.section {
                    s.push_str(&format!(" ({})", sec));
                }
                s
            })
            .collect();
        v.push_str(&format!("- Compliance: {}\n", refs.join(", ")));
    }

    for e in errors {
        if let Some(msg) = &e.message {
            v.push_str(&format!("- {}\n", msg));
        }
    }

    if !rule.remediation.is_empty() {
        v.push_str("- **Remediation available:**\n");
        for action in &rule.remediation {
            match action {
                kxn_core::RemediationAction::Shell { command, .. } => {
                    v.push_str(&format!("  - Shell: `{}`\n", command));
                }
                kxn_core::RemediationAction::Webhook { url, .. } => {
                    v.push_str(&format!("  - Webhook: {}\n", url));
                }
                kxn_core::RemediationAction::Binary { path, args, .. } => {
                    v.push_str(&format!("  - Binary: {} {}\n", path, args.join(" ")));
                }
                kxn_core::RemediationAction::Lua { script, .. } => {
                    v.push_str(&format!("  - Lua script: {} (premium)\n", script));
                }
                kxn_core::RemediationAction::Sql { query, .. } => {
                    v.push_str(&format!("  - SQL: `{}`\n", query));
                }
                kxn_core::RemediationAction::RotateSpSecret { vault, secret_name } => {
                    v.push_str(&format!("  - Rotate SP secret → KV {}/{}\n", vault, secret_name));
                }
            }
        }
    }

    if verbose {
        v.push_str(&format!(
            "- Resource: `{}`\n",
            serde_json::to_string(target)
                .unwrap_or_default()
                .chars()
                .take(500)
                .collect::<String>()
        ));
    }
    v
}

fn tool_check_resource(
    args: &serde_json::Map<String, serde_json::Value>,
) -> Result<String, String> {
    let resource_str = get_str(args, "resource")
        .ok_or("Missing required parameter: resource")?;
    let conditions_str = get_str(args, "conditions")
        .ok_or("Missing required parameter: conditions")?;

    let resource: serde_json::Value =
        serde_json::from_str(resource_str).map_err(|e| format!("Invalid resource JSON: {}", e))?;
    let conditions: Vec<kxn_core::ConditionNode> = serde_json::from_str(conditions_str)
        .map_err(|e| format!("Invalid conditions JSON: {}", e))?;

    let results = check_rule(&conditions, &resource);
    let all_passed = results.iter().all(|r| r.result);
    let failures: Vec<_> = results.iter().filter(|r| !r.result).collect();

    let mut lines = vec![
        format!(
            "## Check result: {}",
            if all_passed { "PASSED" } else { "FAILED" }
        ),
        format!(
            "- {} condition(s) evaluated, {} failed",
            results.len(),
            failures.len()
        ),
        String::new(),
    ];

    for (i, r) in results.iter().enumerate() {
        lines.push(format!(
            "{} condition {}: {} -> got: {}",
            if r.result { "  PASS" } else { "  FAIL" },
            i + 1,
            r.message
                .as_deref()
                .unwrap_or(&format!("{:?}", r.condition)),
            serde_json::to_string(&r.value).unwrap_or_default()
        ));
    }

    Ok(lines.join("\n"))
}

fn tool_list_targets(
    args: &serde_json::Map<String, serde_json::Value>,
    default_config: Option<&str>,
) -> Result<String, String> {
    let config_path = get_str(args, "configPath")
        .or(default_config);

    let path = match config_path {
        Some(p) => std::path::PathBuf::from(p),
        None => discover_config()
            .ok_or("No kxn.toml found. Pass configPath or use --config on serve.")?,
    };

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let config: kxn_rules::config::ScanConfig = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

    if config.targets.is_empty() {
        return Ok(format!("No targets configured in {}", path.display()));
    }

    let mut lines = vec![format!(
        "## {} target(s) from `{}`",
        config.targets.len(),
        path.display()
    )];

    for target in &config.targets {
        let provider = target
            .provider
            .as_deref()
            .unwrap_or("(from URI)");
        let uri = target
            .uri
            .as_deref()
            .map(kxn_rules::secrets::redact)
            .unwrap_or_else(|| "(none)".to_string());

        lines.push(format!(
            "- **{}** | provider: {} | uri: {}",
            target.name, provider, uri
        ));

        if !target.rules.is_empty() {
            lines.push(format!("  rules: {}", target.rules.join(", ")));
        }
        if let Some(interval) = target.interval {
            lines.push(format!("  interval: {}s", interval));
        }
    }

    Ok(lines.join("\n"))
}

/// Remediate: scan target, find violations with remediations, execute selected ones.
async fn tool_remediate(
    args: &serde_json::Map<String, serde_json::Value>,
    default_dir: &str,
    config_path: Option<&str>,
) -> Result<String, String> {
    let target_name = get_str(args, "target")
        .ok_or("Missing required parameter: target")?;
    if let Some(user_dir) = get_str(args, "rulesDirectory") {
        validate_rules_dir(user_dir)?;
    }
    let dir = get_str(args, "rulesDirectory").unwrap_or(default_dir);
    let rule_filter = get_str(args, "ruleFilter");

    // If `rules` or `applyFilter` is provided → apply mode; otherwise list mode
    let selected_rules: Option<Vec<String>> = args.get("rules").and_then(|v| {
        v.as_array().map(|arr| {
            arr.iter().filter_map(|s| s.as_str().map(String::from)).collect()
        })
    });
    let apply_filter = get_str(args, "applyFilter");
    let apply_mode = selected_rules.is_some() || apply_filter.is_some();

    // 1. Load config and target
    let path = match config_path {
        Some(p) => std::path::PathBuf::from(p),
        None => discover_config()
            .ok_or("No kxn.toml found. Pass configPath or use --config on serve.")?,
    };
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let config: kxn_rules::config::ScanConfig = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse {}: {}", path.display(), e))?;

    let target = config
        .targets
        .iter()
        .find(|t| t.name == target_name)
        .ok_or_else(|| format!("Target '{}' not found", target_name))?;

    let raw_uri = target
        .uri
        .as_deref()
        .ok_or_else(|| format!("Target '{}' has no URI", target_name))?;
    let uri = resolve_secrets(raw_uri).await;
    let (provider_name, provider_config) =
        parse_target_uri(&uri).map_err(|e| format!("{}", e))?;

    // 2. Gather resources
    let provider =
        create_native_provider(&provider_name, provider_config).map_err(|e| format!("{}", e))?;
    let all_resources = provider
        .gather_all()
        .await
        .map_err(|e| format!("Gather failed: {}", e))?;

    let mut merged = serde_json::Map::new();
    for (rt, items) in &all_resources {
        merged.insert(rt.clone(), serde_json::Value::Array(items.clone()));
    }
    let resources = vec![serde_json::Value::Object(merged)];

    // 3. Load and filter rules
    let files = parse_directory(Path::new(dir))?;
    let target_rules: Vec<&str> = target.rules.iter().map(|s| s.as_str()).collect();

    // 4. Collect violations with remediations
    let mut lines = if apply_mode {
        vec![format!("## Applying remediations for target: {}", target_name)]
    } else {
        vec![format!("## Available remediations for target: {}", target_name),
             "Select rule names to remediate by calling kxn_remediate again with `rules` parameter.\n".to_string()]
    };
    let mut remediated = 0;
    let mut skipped = 0;
    let mut errors = Vec::new();

    // Collect shell commands to batch them (avoid multiple service restarts)
    let mut shell_batch: Vec<(String, String)> = Vec::new(); // (rule_name, command)
    let mut need_pg_reload = false;

    for (name, rf) in &files {
        let file_stem = name.trim_end_matches(".toml");
        if !target_rules.contains(&file_stem) {
            continue;
        }

        for rule in &rf.rules {
            if let Some(filter) = rule_filter {
                if !rule.name.contains(filter) {
                    continue;
                }
            }
            if rule.remediation.is_empty() {
                continue;
            }

            for resource in &resources {
                let items = if rule.object.is_empty() {
                    vec![resource.clone()]
                } else {
                    match resource.get(&rule.object) {
                        Some(serde_json::Value::Array(arr)) => arr.clone(),
                        Some(val) => vec![val.clone()],
                        None => continue,
                    }
                };

                for item in &items {
                    let results = check_rule(&rule.conditions, item);
                    let has_errors = results.iter().any(|r| !r.result);
                    if !has_errors {
                        continue;
                    }

                    // In apply mode, skip rules not matching selection
                    if apply_mode {
                        let in_rules = selected_rules.as_ref()
                            .is_some_and(|sel| sel.iter().any(|s| s == &rule.name));
                        let in_filter = apply_filter
                            .is_some_and(|f| rule.name.contains(f));
                        if !in_rules && !in_filter {
                            continue;
                        }
                    }

                    for action in &rule.remediation {
                        match action {
                            kxn_core::RemediationAction::Sql { query, reload } => {
                                if !apply_mode {
                                    lines.push(format!(
                                        "- `{}` — sql: `{}`",
                                        rule.name, query
                                    ));
                                    remediated += 1;
                                } else {
                                    match provider.execute_sql(query).await {
                                        Ok(msg) => {
                                            lines.push(format!(
                                                "- **{}**: {}",
                                                rule.name, msg
                                            ));
                                            if reload.unwrap_or(true)
                                                && provider_name == "postgresql"
                                            {
                                                need_pg_reload = true;
                                            }
                                            remediated += 1;
                                        }
                                        Err(e) => {
                                            errors.push(format!(
                                                "{}: {}",
                                                rule.name, e
                                            ));
                                            skipped += 1;
                                        }
                                    }
                                }
                            }
                            kxn_core::RemediationAction::Shell { command, .. } => {
                                if !apply_mode {
                                    lines.push(format!(
                                        "- `{}` — shell: `{}`",
                                        rule.name,
                                        if command.len() > 80 { &command[..80] } else { command }
                                    ));
                                    remediated += 1;
                                } else {
                                    // Collect shell commands, execute as batch later
                                    shell_batch.push((
                                        rule.name.clone(),
                                        command.clone(),
                                    ));
                                }
                            }
                            _ => {
                                skipped += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    // 5. Execute batched shell commands (strip service restarts, do one at the end)
    if !shell_batch.is_empty() {
        // Detect service restart commands to deduplicate
        let restart_patterns = [
            "systemctl restart sshd",
            "systemctl restart ssh",
            "systemctl reload nginx",
            "systemctl reload httpd",
            "systemctl reload apache2",
            "systemctl restart mongod",
            "systemctl restart docker",
        ];

        let mut restart_commands: Vec<String> = Vec::new();
        let mut config_commands: Vec<(String, String)> = Vec::new(); // (rule_name, config_only_cmd)

        for (rule_name, cmd) in &shell_batch {
            // Split the command: extract config changes vs service restarts
            let mut config_parts = Vec::new();
            let mut found_restart = None;

            for part in cmd.split("&&").map(|s| s.trim()) {
                let is_restart = restart_patterns
                    .iter()
                    .any(|p| part.contains(p));
                if is_restart {
                    if !restart_commands.contains(&part.to_string()) {
                        found_restart = Some(part.to_string());
                    }
                } else {
                    config_parts.push(part.to_string());
                }
            }

            if let Some(restart) = found_restart {
                if !restart_commands.contains(&restart) {
                    restart_commands.push(restart);
                }
            }

            if !config_parts.is_empty() {
                config_commands.push((
                    rule_name.clone(),
                    config_parts.join(" && "),
                ));
            }
        }

        // Execute config changes (only reached in apply mode)
        for (rule_name, cmd) in &config_commands {
            match provider.execute_shell(cmd).await {
                Ok(output) => {
                    let msg = if output.trim().is_empty() {
                        "OK".to_string()
                    } else {
                        output.trim().chars().take(200).collect()
                    };
                    lines.push(format!("- **{}**: {}", rule_name, msg));
                    remediated += 1;
                }
                Err(e) => {
                    errors.push(format!("{}: {}", rule_name, e));
                    skipped += 1;
                }
            }
        }

        // One single restart per service at the end
        if !restart_commands.is_empty() {
            for restart_cmd in &restart_commands {
                match provider.execute_shell(restart_cmd).await {
                    Ok(_) => {
                        lines.push(format!("- **service-reload**: `{}`", restart_cmd));
                    }
                    Err(e) => {
                        errors.push(format!("service restart: {}", e));
                    }
                }
            }
        }
    }

    // 6. Single pg_reload_conf() at the end for PostgreSQL
    if need_pg_reload && apply_mode {
        match provider.execute_sql("SELECT pg_reload_conf()").await {
            Ok(_) => {
                lines.push("- **pg-reload**: configuration reloaded".to_string());
            }
            Err(e) => {
                errors.push(format!("pg_reload_conf: {}", e));
            }
        }
    }

    if apply_mode {
        lines.insert(
            1,
            format!(
                "- {} applied, {} skipped, {} errors",
                remediated, skipped, errors.len()
            ),
        );
    } else {
        lines.insert(
            1,
            format!("- {} violation(s) with remediations available", remediated),
        );
    }

    if !errors.is_empty() {
        lines.push("\n### Errors".to_string());
        for e in &errors {
            lines.push(format!("- {}", e));
        }
    }

    if remediated == 0 && skipped == 0 {
        lines.push(
            "\nNo violations with remediations found. All rules passed or no remediation defined."
                .to_string(),
        );
    }

    Ok(lines.join("\n"))
}

/// Discover kxn.toml (same logic as kxn-cli config discovery).
fn discover_config() -> Option<std::path::PathBuf> {
    let candidates = vec![
        Some(std::path::PathBuf::from("kxn.toml")),
        dirs::config_dir().map(|d| d.join("kxn/kxn.toml")),
        dirs::home_dir().map(|d| d.join(".kxn.toml")),
    ];
    candidates.into_iter().flatten().find(|p| p.exists())
}
