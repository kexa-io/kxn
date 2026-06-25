//! # Graph command
//!
//! Builds an infrastructure graph (`nodes` + `edges`) from a cloud provider by
//! combining a bulk resource inventory with per-resource detail lookups to
//! extract inter-object relations.
//!
//! Unlike `gather`, which returns a flat inventory, `graph` emits the edges
//! between resources (NIC attached to VM, NIC protected by NSG, NIC connected
//! to subnet, ...). Relation extraction is a provider capability; only the
//! `azurerm` provider is supported for now.

use anyhow::{anyhow, Context, Result};
use clap::Args;
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};

use kxn_providers::azure_arm;

/// Arguments for the `graph` command.
#[derive(Args)]
pub struct GraphArgs {
    /// Provider to build the graph from (currently only "azurerm").
    #[arg(short = 'p', long = "provider")]
    pub provider: String,

    /// Provider config JSON, e.g. '{"subscription_id":"..."}'.
    #[arg(short = 'C', long = "provider-config", default_value = "{}")]
    pub provider_config: String,

    /// Output format: json (default).
    #[arg(short = 'o', long = "output", default_value = "json")]
    pub output: String,

    /// Maximum number of concurrent detail (relation) lookups.
    #[arg(long = "concurrency", default_value_t = 16)]
    pub concurrency: usize,

    /// Show progress on stderr.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

/// Entry point for the `graph` command.
pub async fn run(args: GraphArgs) -> Result<()> {
    let provider = args.provider.to_lowercase();
    if !matches!(provider.as_str(), "azurerm" | "azure" | "hashicorp/azurerm") {
        return Err(anyhow!(
            "graph: only the azurerm provider is supported for now, got '{}'",
            args.provider
        ));
    }

    let cfg: Value =
        serde_json::from_str(&args.provider_config).context("invalid --provider-config JSON")?;
    let subscription_id = cfg
        .get("subscription_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("ARM_SUBSCRIPTION_ID").ok())
        .or_else(|| std::env::var("AZURE_SUBSCRIPTION_ID").ok())
        .ok_or_else(|| {
            anyhow!("graph: subscription_id required in --provider-config or ARM_SUBSCRIPTION_ID env var")
        })?;

    // 1. Bulk inventory: one paginated ARM call returns every resource summary.
    let resources = azure_arm::list_resources(&subscription_id)
        .await
        .context("listing azure resources")?;
    if args.verbose {
        eprintln!("graph: {} resources listed", resources.len());
    }

    // 2. Per-resource detail fetch (bounded concurrency) -> properties + edges.
    let built: Vec<(Value, Vec<azure_arm::ArmRelation>)> = stream::iter(resources)
        .map(|summary| async move {
            let id = summary
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            match azure_arm::fetch_resource(&id).await {
                Ok(detail) => {
                    let relations = azure_arm::extract_relations(&detail);
                    (build_node(&summary, Some(&detail)), relations)
                }
                Err(e) => {
                    if args.verbose {
                        eprintln!("graph: detail fetch failed for {}: {}", id, e);
                    }
                    // Keep the node from the summary; just no relations from it.
                    (build_node(&summary, None), Vec::new())
                }
            }
        })
        .buffer_unordered(args.concurrency.max(1))
        .collect()
        .await;

    // 3. Assemble nodes + deduplicated edges.
    // Index node ids (lowercased -> canonical) so edges can be resolved to real
    // graph nodes: references to sub-components (e.g. a NIC ipConfiguration) are
    // collapsed onto their parent node, and references to resources outside the
    // subscription (e.g. a marketplace image version) are dropped.
    let node_ids: std::collections::HashMap<String, String> = built
        .iter()
        .filter_map(|(n, _)| {
            n.get("id")
                .and_then(|v| v.as_str())
                .map(|s| (s.to_lowercase(), s.to_string()))
        })
        .collect();

    let nodes: Vec<Value> = built.iter().map(|(n, _)| n.clone()).collect();
    let mut edges = Vec::new();
    let mut edge_seen = std::collections::HashSet::new();

    for (node, relations) in &built {
        let source = node
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        for rel in relations {
            let Some(target) = resolve_node(&rel.target, &node_ids) else {
                continue;
            };
            if target.to_lowercase() == source.to_lowercase() {
                continue;
            }
            let key = (
                source.to_lowercase(),
                target.to_lowercase(),
                rel.kind.clone(),
            );
            if edge_seen.insert(key) {
                edges.push(json!({
                    "source": source,
                    "target": target,
                    "kind": rel.kind,
                }));
            }
        }
    }

    let graph = json!({ "nodes": nodes, "edges": edges });

    match args.output.as_str() {
        "json" => println!("{}", serde_json::to_string_pretty(&graph)?),
        other => return Err(anyhow!("graph: unsupported output format '{}'", other)),
    }

    if args.verbose {
        eprintln!("graph: {} nodes, {} edges", nodes.len(), edges.len());
    }
    Ok(())
}

/// Resolve a referenced ARM id to a graph node's canonical id.
///
/// Returns the exact node if the target is one, otherwise the longest node id
/// that is a parent of the target (so sub-component references collapse onto
/// their owning resource). Returns `None` when the target is not part of the
/// graph (e.g. a platform/marketplace resource), so the edge is dropped.
fn resolve_node(
    target: &str,
    node_ids: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let lower = target.to_lowercase();
    if let Some(canonical) = node_ids.get(&lower) {
        return Some(canonical.clone());
    }
    let mut best: Option<&String> = None;
    for (lid, canonical) in node_ids {
        if lower.starts_with(&format!("{}/", lid))
            && best.is_none_or(|b| canonical.len() > b.len())
        {
            best = Some(canonical);
        }
    }
    best.cloned()
}

/// Build a graph node from a resource summary, optionally enriched with the
/// detailed `properties` bag fetched from ARM.
fn build_node(summary: &Value, detail: Option<&Value>) -> Value {
    let id = summary.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let properties = detail
        .and_then(|d| d.get("properties").cloned())
        .unwrap_or_else(|| json!({}));

    json!({
        "id": id,
        "type": summary.get("type").cloned().unwrap_or(Value::Null),
        "name": summary.get("name").cloned().unwrap_or(Value::Null),
        "region": summary.get("location").cloned().unwrap_or(Value::Null),
        "resource_group": resource_group_from_id(id),
        "tags": summary.get("tags").cloned().unwrap_or_else(|| json!({})),
        "properties": properties,
    })
}

/// Extract the resource group name from an ARM resource id (case-insensitive
/// match on the `/resourceGroups/` segment), or `null` if absent.
fn resource_group_from_id(id: &str) -> Value {
    let lower = id.to_lowercase();
    if let Some(pos) = lower.find("/resourcegroups/") {
        let rest = &id[pos + "/resourceGroups/".len()..];
        if let Some(name) = rest.split('/').next() {
            if !name.is_empty() {
                return Value::String(name.to_string());
            }
        }
    }
    Value::Null
}
