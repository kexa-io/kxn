//! Export kxn tools as OpenAI function calling schema.
//! This allows any AI agent to discover and use kxn capabilities.

use anyhow::Result;
use clap::Args;
use serde_json::json;

#[derive(Args)]
pub struct ToolsArgs {
    /// Output format: openai, anthropic, summary
    #[arg(short, long, default_value = "openai")]
    pub format: String,
}

pub fn run(args: ToolsArgs) -> Result<()> {
    match args.format.as_str() {
        "openai" => print_openai_schema(),
        "anthropic" => print_anthropic_schema(),
        _ => print_summary(),
    }
    Ok(())
}

fn tools() -> Vec<serde_json::Value> {
    vec![
        json!({
            "name": "kxn_scan",
            "description": "Scan infrastructure for compliance violations and vulnerabilities. Supports SSH servers, databases (PostgreSQL, MySQL, MongoDB), Kubernetes clusters, and cloud resources. Returns violations with severity, compliance mappings (CIS, NIST, PCI-DSS, SOC-2), and remediation steps.",
            "parameters": {
                "type": "object",
                "properties": {
                    "uri": {
                        "type": "string",
                        "description": "Target URI (e.g. ssh://root@server, postgresql://user:pass@host:5432, kubernetes://cluster)"
                    },
                    "output": {
                        "type": "string",
                        "enum": ["json", "csv", "toml", "minimal", "text"],
                        "description": "Output format (default: json)"
                    },
                    "compliance": {
                        "type": "boolean",
                        "description": "Include CIS/compliance rules"
                    }
                },
                "required": ["uri"]
            }
        }),
        json!({
            "name": "kxn_gather",
            "description": "Gather resources from a provider without evaluating rules. Returns raw resource data as JSON. Useful for inspection before scanning.",
            "parameters": {
                "type": "object",
                "properties": {
                    "provider": {
                        "type": "string",
                        "description": "Provider name (ssh, postgresql, mysql, mongodb, kubernetes, github, http, grpc, cve)"
                    },
                    "resource_type": {
                        "type": "string",
                        "description": "Resource type (e.g. system_stats, packages_cve, pods, db_stats)"
                    },
                    "config": {
                        "type": "object",
                        "description": "Provider config (e.g. {\"SSH_HOST\": \"server\", \"SSH_USER\": \"root\"})"
                    }
                },
                "required": ["provider", "resource_type"]
            }
        }),
        json!({
            "name": "kxn_check",
            "description": "Check arbitrary JSON data against compliance conditions. Zero infrastructure needed — pure logic evaluation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "resource": {
                        "type": "object",
                        "description": "JSON resource to check"
                    },
                    "conditions": {
                        "type": "array",
                        "description": "Conditions to evaluate (e.g. [{\"property\": \"port\", \"condition\": \"EQUAL\", \"value\": 443}])"
                    }
                },
                "required": ["resource", "conditions"]
            }
        }),
        json!({
            "name": "kxn_cve_lookup",
            "description": "Look up CVEs for installed packages using the local NVD/KEV/EPSS database. Returns CVE IDs, CVSS scores, severity, and exploitation status.",
            "parameters": {
                "type": "object",
                "properties": {
                    "uri": {
                        "type": "string",
                        "description": "SSH target URI (e.g. ssh://root@server)"
                    }
                },
                "required": ["uri"]
            }
        }),
        json!({
            "name": "kxn_remediate",
            "description": "List and apply remediations for compliance violations. Always list first, then apply selected rules after user confirmation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "uri": {
                        "type": "string",
                        "description": "Target URI"
                    },
                    "rules": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Rule names to remediate (omit to list all available)"
                    }
                },
                "required": ["uri"]
            }
        }),
    ]
}

fn print_openai_schema() {
    let schema: Vec<serde_json::Value> = tools()
        .into_iter()
        .map(|t| {
            json!({
                "type": "function",
                "function": t
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}

fn print_anthropic_schema() {
    let schema: Vec<serde_json::Value> = tools()
        .into_iter()
        .map(|t| {
            json!({
                "name": t["name"],
                "description": t["description"],
                "input_schema": t["parameters"]
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}

fn print_summary() {
    println!("kxn agent tools:\n");
    for t in tools() {
        println!(
            "  {} — {}",
            t["name"].as_str().unwrap_or(""),
            t["description"]
                .as_str()
                .unwrap_or("")
                .chars()
                .take(80)
                .collect::<String>()
        );
    }
    println!("\nExport schemas:");
    println!("  kxn tools -f openai     # OpenAI function calling format");
    println!("  kxn tools -f anthropic  # Anthropic tool use format");
}
