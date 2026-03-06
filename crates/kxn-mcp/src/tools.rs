//! MCP tool definitions — 6 tools for Kexa compliance scanning

use rmcp::model::*;
use serde_json::json;
use std::path::Path;
use std::sync::Arc;

use kxn_core::check_rule;
use kxn_providers::{ProviderAddress, TerraformProvider};
use kxn_rules::parse_directory;

pub fn list_tools() -> ListToolsResult {
    ListToolsResult {
        tools: vec![
            tool_def(
                "kxn_list_providers",
                "List all available providers: native (ssh, postgresql, mysql, mongodb, oracle, kubernetes, cloud_run, azure_webapp, http) and cached Terraform providers (aws, google, azurerm, github, cloudflare, vault, etc.).",
                json!({"type":"object","properties":{"provider":{"type":"string","description":"Filter by provider name"}}})
            ),
            tool_def(
                "kxn_list_resource_types",
                "List available resource types for a native provider. Use this BEFORE kxn_gather to discover what can be gathered. Examples: ssh → sshd_config, system_stats, logs, os_info; postgresql → databases, db_stats, logs, settings; kubernetes → pods, deployments, nodes, cluster_stats.",
                json!({"type":"object","properties":{
                    "provider":{"type":"string","description":"Native provider name (ssh, postgresql, mysql, mongodb, kubernetes, cloud_run, azure_webapp, http)"}
                },"required":["provider"]})
            ),
            tool_def(
                "kxn_list_rules",
                "Parse and list all compliance rules from TOML files. Shows rule names, descriptions, severity levels. Rules cover: SSH CIS, DB monitoring (PostgreSQL, MySQL, MongoDB, Oracle), system monitoring, log monitoring, Kubernetes, HTTP security.",
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
                "Gather live resources from any provider. Native providers: ssh (system_stats, logs, sshd_config, sysctl, users, services, os_info, file_permissions), postgresql (databases, db_stats, logs, roles, settings, stat_activity, extensions), mysql (databases, db_stats, logs, users, grants, variables, status, processlist), mongodb (databases, db_stats, logs, users, serverStatus, currentOp), kubernetes (26 types: pods, deployments, services, nodes, namespaces, ingresses, events, cluster_stats, jobs, hpa, daemonsets, statefulsets, cronjobs, rbac, network_policies, PV/PVC, node_metrics, pod_metrics, pod_logs), cloud_run (services, revisions, jobs), azure_webapp (webapps, app_service_plans, webapp_config), http (http_response). Also supports ALL Terraform providers (hashicorp/aws, hashicorp/google, etc.) — prefix data sources with 'data.'.",
                json!({"type":"object","properties":{
                    "provider":{"type":"string","description":"Provider name: ssh, postgresql, mysql, mongodb, kubernetes, cloud_run, azure_webapp, http (native) or hashicorp/aws, hashicorp/google, etc. (Terraform)"},
                    "resourceType":{"type":"string","description":"Resource type (e.g. system_stats, db_stats, pods, logs). For Terraform data sources, use 'data.' prefix"},
                    "config":{"type":"string","description":"Provider config JSON. Examples: {\"SSH_HOST\":\"10.0.0.1\",\"SSH_USER\":\"root\"} for ssh, {\"PG_HOST\":\"db\",\"PG_USER\":\"admin\"} for postgresql, {\"K8S_API_URL\":\"https://...\",\"K8S_TOKEN\":\"...\"} for kubernetes"},
                    "version":{"type":"string","description":"Provider version (Terraform only, default: latest)"}
                },"required":["provider","resourceType"]})
            ),
            tool_def(
                "kxn_scan",
                "Run a full compliance scan: load rules, evaluate against resources. Returns violations with severity, compliance framework mapping (CIS, PCI-DSS, ISO27001), and remediation suggestions. Supports all rule files: ssh-cis, aws-cis, azure-cis, gcp-cis, kubernetes-cis, github-security, monitoring, db monitoring, http-security.",
                json!({"type":"object","properties":{
                    "rulesDirectory":{"type":"string","description":"Path to rules directory (default: ./rules)"},
                    "resource":{"type":"string","description":"JSON resource(s) to scan"},
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
) -> Result<CallToolResult, rmcp::Error> {
    let args = request.arguments.unwrap_or_default();
    let result = match request.name.as_ref() {
        "kxn_list_providers" => tool_list_providers(&args),
        "kxn_list_resource_types" => tool_list_resource_types(&args).await,
        "kxn_list_rules" => tool_list_rules(&args, rules_dir),
        "kxn_provider_schema" => tool_provider_schema(&args).await,
        "kxn_gather" => tool_gather(&args).await,
        "kxn_scan" => tool_scan(&args, rules_dir),
        "kxn_check_resource" => tool_check_resource(&args),
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
        "ssh" => vec!["sshd_config", "sysctl", "users", "services", "file_permissions", "os_info", "system_stats", "logs"],
        "postgresql" => vec!["databases", "roles", "settings", "stat_activity", "extensions", "db_stats", "logs"],
        "mysql" => vec!["databases", "users", "grants", "variables", "status", "engines", "processlist", "db_stats", "logs"],
        "mongodb" => vec!["databases", "users", "serverStatus", "currentOp", "db_stats", "logs"],
        "kubernetes" | "k8s" => vec![
            "pods", "deployments", "services", "nodes", "namespaces", "ingresses",
            "configmaps", "secrets_metadata", "events", "cluster_stats",
            "rbac_cluster_roles", "rbac_cluster_role_bindings", "network_policies",
            "persistent_volumes", "persistent_volume_claims", "daemonsets", "statefulsets",
            "cronjobs", "service_accounts", "jobs", "hpa", "resource_quotas", "limit_ranges",
            "node_metrics", "pod_metrics", "pod_logs",
        ],
        "cloud_run" | "cloudrun" => vec!["services", "revisions", "jobs"],
        "azure_webapp" | "azurewebapp" => vec!["webapps", "app_service_plans", "webapp_config"],
        "http" => vec!["http_response"],
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
            "settings" | "variables" | "parameters" => "Database configuration settings",
            "databases" => "Database list with tables, indexes, sizes",
            "http_response" => "HTTP response: status, headers, timing, TLS info",
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
) -> Result<String, String> {
    let provider_name = get_str(args, "provider").ok_or("Missing required parameter: provider")?;
    let resource_type =
        get_str(args, "resourceType").ok_or("Missing required parameter: resourceType")?;
    let config_str = get_str(args, "config").unwrap_or("{}");
    let version = get_str(args, "version");

    let config: serde_json::Value =
        serde_json::from_str(config_str).map_err(|e| format!("Invalid config JSON: {}", e))?;

    let native_names = kxn_providers::native_provider_names();

    if native_names.contains(&provider_name) {
        // Native provider path (unchanged)
        let provider =
            kxn_providers::create_native_provider(provider_name, config).map_err(|e| format!("{}", e))?;

        let resources = provider
            .gather(resource_type)
            .await
            .map_err(|e| format!("{}", e))?;

        return format_gather_output(provider_name, resource_type, &serde_json::to_value(&resources).unwrap_or_default());
    }

    // Terraform provider path
    let address = ProviderAddress::parse(provider_name).map_err(|e| format!("{}", e))?;

    let user_config = config.clone();
    let mut provider = TerraformProvider::new(address, config, version)
        .await
        .map_err(|e| format!("Failed to start Terraform provider: {}", e))?;

    let is_data_source = resource_type.starts_with("data.");
    let type_name = if is_data_source {
        &resource_type[5..]
    } else {
        resource_type
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
        Ok(Some(value)) => format_gather_output(provider_name, resource_type, &value),
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

fn tool_scan(
    args: &serde_json::Map<String, serde_json::Value>,
    default_dir: &str,
) -> Result<String, String> {
    let dir = get_str(args, "rulesDirectory").unwrap_or(default_dir);
    let resource_str = get_str(args, "resource").unwrap_or("{}");
    let verbose = args
        .get("verbose")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let resources: Vec<serde_json::Value> = if resource_str.trim().starts_with('[') {
        serde_json::from_str(resource_str).map_err(|e| format!("Invalid JSON array: {}", e))?
    } else {
        vec![serde_json::from_str(resource_str).map_err(|e| format!("Invalid JSON: {}", e))?]
    };

    let files = parse_directory(Path::new(dir))?;

    let mut total = 0;
    let mut passed = 0;
    let mut failed = 0;
    let mut violations = Vec::new();

    for (_name, rf) in &files {
        for rule in &rf.rules {
            for resource in &resources {
                // Extract sub-resources based on rule object
                let items = if rule.object.is_empty() {
                    vec![resource.clone()]
                } else {
                    match resource.get(&rule.object) {
                        Some(serde_json::Value::Array(arr)) => arr.clone(),
                        Some(val) => vec![val.clone()],
                        None => vec![resource.clone()],
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
                        let level_label = match rule.level {
                            kxn_core::Level::Info => "INFO",
                            kxn_core::Level::Warning => "WARNING",
                            kxn_core::Level::Error => "ERROR",
                            kxn_core::Level::Fatal => "FATAL",
                        };
                        let mut v = format!("### [{}] {}\n", level_label, rule.name);
                        v.push_str(&format!("- {}\n", rule.description));

                        // Compliance mapping
                        if !rule.compliance.is_empty() {
                            let refs: Vec<String> = rule.compliance.iter()
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

                        for e in &errors {
                            if let Some(msg) = &e.message {
                                v.push_str(&format!("- {}\n", msg));
                            }
                        }

                        // Remediation actions
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
                        violations.push(v);
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
