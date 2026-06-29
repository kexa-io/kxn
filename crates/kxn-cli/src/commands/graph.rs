//! # Graph command
//!
//! Builds an infrastructure graph (`nodes` + `edges`) from a cloud provider by
//! combining a resource inventory with inter-object relation extraction.
//!
//! Unlike `gather`, which returns a flat inventory, `graph` emits the edges
//! between resources (NIC attached to VM, subnet connected to network, ...).
//! Supported providers: `azurerm` (ARM `{id}` references) and `gcp` (Compute
//! resource-URL references).

use anyhow::{anyhow, Context, Result};
use clap::Args;
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};

use kxn_providers::{aws_resources, azure_arm, gcp_compute};

/// A graph node plus the relations (target id, kind) discovered from it.
type BuiltNode = (Value, Vec<(String, String)>);

/// Arguments for the `graph` command.
#[derive(Args)]
pub struct GraphArgs {
    /// Provider to build the graph from: "azurerm" or "gcp".
    #[arg(short = 'p', long = "provider")]
    pub provider: String,

    /// Provider config JSON, e.g. '{"subscription_id":"..."}' (azure) or
    /// '{"project":"..."}' (gcp).
    #[arg(short = 'C', long = "provider-config", default_value = "{}")]
    pub provider_config: String,

    /// Output format: json (default).
    #[arg(short = 'o', long = "output", default_value = "json")]
    pub output: String,

    /// Maximum number of concurrent detail lookups (azure only).
    #[arg(long = "concurrency", default_value_t = 16)]
    pub concurrency: usize,

    /// JSON resources for the `aws` provider (file path, or stdin if omitted):
    /// an array of AWS Config configuration items or Cloud Control resources.
    #[arg(short = 'r', long = "resource")]
    pub resource: Option<std::path::PathBuf>,

    /// Show progress on stderr.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

/// Entry point for the `graph` command.
pub async fn run(args: GraphArgs) -> Result<()> {
    let cfg: Value =
        serde_json::from_str(&args.provider_config).context("invalid --provider-config JSON")?;

    let built = match args.provider.to_lowercase().as_str() {
        "azurerm" | "azure" | "hashicorp/azurerm" => build_azure(&cfg, &args).await?,
        "gcp" | "google" => build_gcp(&cfg, &args).await?,
        "aws" => build_aws(&args)?,
        other => {
            return Err(anyhow!(
                "graph: unsupported provider '{}' (expected azurerm, gcp or aws)",
                other
            ))
        }
    };

    assemble_and_print(built, &args.output, args.verbose)
}

/// Build the Azure graph: a flat inventory followed by a concurrent per-resource
/// detail fetch that yields the properties and the ARM id references.
async fn build_azure(cfg: &Value, args: &GraphArgs) -> Result<Vec<BuiltNode>> {
    let explicit = cfg
        .get("subscription_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("ARM_SUBSCRIPTION_ID").ok())
        .or_else(|| std::env::var("AZURE_SUBSCRIPTION_ID").ok());

    // Resolve which subscriptions to scan: the explicit one, or every
    // subscription the credential can access.
    let subscriptions: Vec<azure_arm::Subscription> = match explicit {
        Some(id) => {
            // Resolve the friendly name when possible, but don't fail the scan
            // if the credential cannot enumerate subscriptions.
            let name = azure_arm::list_subscriptions()
                .await
                .ok()
                .and_then(|subs| {
                    subs.into_iter()
                        .find(|s| s.subscription_id == id)
                        .map(|s| s.display_name)
                })
                .unwrap_or_else(|| id.clone());
            vec![azure_arm::Subscription {
                subscription_id: id,
                display_name: name,
            }]
        }
        None => {
            let subs = azure_arm::list_subscriptions()
                .await
                .context("listing azure subscriptions")?;
            if args.verbose {
                eprintln!("graph: scanning {} azure subscription(s)", subs.len());
            }
            subs
        }
    };

    let mut built: Vec<BuiltNode> = Vec::new();
    for sub in &subscriptions {
        // Emit a subscription container node so every subscription is visible,
        // even empty ones, and the hierarchy is grounded.
        built.push((
            json!({
                "id": format!("/subscriptions/{}", sub.subscription_id),
                "type": "Microsoft.Resources/subscriptions",
                "name": sub.display_name,
                "region": Value::Null,
                "resource_group": Value::Null,
                "tags": json!({}),
                "properties": json!({}),
            }),
            Vec::new(),
        ));
        match build_azure_subscription(&sub.subscription_id, args).await {
            Ok(nodes) => built.extend(nodes),
            Err(e) => {
                eprintln!(
                    "graph: subscription {} scan failed: {}",
                    sub.subscription_id, e
                );
            }
        }
    }

    Ok(built)
}

/// Scan a single subscription: list its resources, fetch each one's detail to
/// extract relations, and expand vnet subnets into nodes.
async fn build_azure_subscription(
    subscription_id: &str,
    args: &GraphArgs,
) -> Result<Vec<BuiltNode>> {
    let resources = azure_arm::list_resources(subscription_id)
        .await
        .context("listing azure resources")?;
    if args.verbose {
        eprintln!("graph: {} azure resources listed", resources.len());
    }

    let mut built: Vec<BuiltNode> = stream::iter(resources)
        .map(|summary| async move {
            let id = summary.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            match azure_arm::fetch_resource(&id).await {
                Ok(detail) => {
                    let rels = azure_arm::extract_relations(&detail)
                        .into_iter()
                        .map(|r| (r.target, r.kind))
                        .collect();
                    (build_node_azure(&summary, Some(&detail)), rels)
                }
                Err(e) => {
                    if args.verbose {
                        eprintln!("graph: detail fetch failed for {}: {}", id, e);
                    }
                    (build_node_azure(&summary, None), Vec::new())
                }
            }
        })
        .buffer_unordered(args.concurrency.max(1))
        .collect()
        .await;

    // Subnets live inside a vnet's `properties.subnets[]`, not as top-level ARM
    // resources. Promote them to first-class nodes so the vnet -> subnet -> NIC
    // network flow is visible, and so NIC subnet references resolve to the
    // subnet rather than collapsing onto the vnet.
    let mut subnet_nodes: Vec<BuiltNode> = Vec::new();
    for (node, rels) in built.iter_mut() {
        let is_vnet = node
            .get("type")
            .and_then(|v| v.as_str())
            .is_some_and(|t| t.eq_ignore_ascii_case("Microsoft.Network/virtualNetworks"));
        if !is_vnet {
            continue;
        }
        let region = node.get("region").cloned().unwrap_or(Value::Null);
        let Some(subnets) = node
            .pointer("/properties/subnets")
            .and_then(|v| v.as_array())
            .cloned()
        else {
            continue;
        };
        for sn in subnets {
            let Some(sid) = sn.get("id").and_then(|v| v.as_str()) else {
                continue;
            };
            rels.push((sid.to_string(), "contains".to_string()));
            let snode = json!({
                "id": sid,
                "type": "Microsoft.Network/virtualNetworks/subnets",
                "name": sn.get("name").cloned().unwrap_or(Value::Null),
                "region": region.clone(),
                "resource_group": resource_group_from_id(sid),
                "tags": json!({}),
                "properties": sn.get("properties").cloned().unwrap_or_else(|| json!({})),
            });
            let srels = azure_arm::extract_relations(&snode)
                .into_iter()
                .map(|r| (r.target, r.kind))
                .collect();
            subnet_nodes.push((snode, srels));
        }
    }
    if args.verbose {
        eprintln!("graph: expanded {} azure subnets into nodes", subnet_nodes.len());
    }
    built.extend(subnet_nodes);

    Ok(built)
}

/// Build the GCP graph: the Compute list endpoints already return full
/// resources, so each one yields its node and its URL references directly.
async fn build_gcp(cfg: &Value, args: &GraphArgs) -> Result<Vec<BuiltNode>> {
    let project = cfg
        .get("project")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| std::env::var("GOOGLE_CLOUD_PROJECT").ok())
        .or_else(|| std::env::var("GCP_PROJECT").ok())
        .ok_or_else(|| {
            anyhow!("graph: project required in --provider-config or GOOGLE_CLOUD_PROJECT env var")
        })?;

    // Prefer Cloud Asset Inventory (covers every service: Storage, IAM, Secret
    // Manager, GKE, SQL, ... not just Compute). Fall back to the Compute-only
    // collector if the Asset Inventory API is disabled or denied.
    match gcp_compute::list_assets(&project).await {
        Ok(assets) if !assets.is_empty() => {
            if args.verbose {
                eprintln!("graph: {} gcp assets listed (asset inventory)", assets.len());
            }
            let built = assets
                .into_iter()
                .map(|a| {
                    let data = a.pointer("/resource/data").cloned().unwrap_or_else(|| json!({}));
                    let rels = gcp_compute::extract_relations(&data)
                        .into_iter()
                        .map(|x| (x.target, x.kind))
                        .collect();
                    (build_node_gcp_asset(&a, &data), rels)
                })
                .collect();
            return Ok(built);
        }
        Ok(_) => {
            if args.verbose {
                eprintln!("graph: asset inventory empty, falling back to compute collector");
            }
        }
        Err(e) => {
            if args.verbose {
                eprintln!("graph: asset inventory unavailable ({e}), falling back to compute");
            }
        }
    }

    let resources = gcp_compute::list_resources(&project)
        .await
        .context("listing gcp compute resources")?;
    if args.verbose {
        eprintln!("graph: {} gcp resources listed (compute)", resources.len());
    }

    let built = resources
        .into_iter()
        .map(|r| {
            let rels = gcp_compute::extract_relations(&r)
                .into_iter()
                .map(|x| (x.target, x.kind))
                .collect();
            (build_node_gcp(&r), rels)
        })
        .collect();

    Ok(built)
}

/// Build a GCP graph node from a Cloud Asset Inventory asset. The id is the
/// canonical asset name (`//service/.../resource`), the type is the assetType
/// (e.g. `secretmanager.googleapis.com/Secret`), and properties come from
/// `resource.data`.
fn build_node_gcp_asset(asset: &Value, data: &Value) -> Value {
    let name = asset.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let asset_type = asset.get("assetType").and_then(|v| v.as_str()).unwrap_or("");
    // Prefer the resource selfLink as the id so cross-resource references (which
    // are selfLink URLs) resolve to edges; fall back to the asset name for
    // services without a selfLink (Secret Manager, IAM, ...).
    let id = data
        .get("selfLink")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    let display = data
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| asset.get("name").and_then(|v| v.as_str()))
        .map(|s| s.rsplit('/').next().unwrap_or(s).to_string());
    json!({
        "id": id,
        "type": asset_type,
        "name": display,
        "region": asset.pointer("/resource/location").and_then(|v| v.as_str()),
        "properties": data.clone(),
    })
}

/// Build the AWS graph from resources provided as JSON (file or stdin), rather
/// than from live signed API calls. Accepts a top-level array, or an object
/// wrapping the list under `configurationItems`, `resources` or `value`.
fn build_aws(args: &GraphArgs) -> Result<Vec<BuiltNode>> {
    let raw = match &args.resource {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?,
        None => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading resources from stdin")?;
            buf
        }
    };

    let parsed: Value = serde_json::from_str(&raw).context("parsing AWS resources JSON")?;
    let resources: Vec<Value> = match &parsed {
        Value::Array(arr) => arr.clone(),
        Value::Object(_) => ["configurationItems", "resources", "value"]
            .iter()
            .find_map(|k| parsed.get(*k).and_then(|v| v.as_array()).cloned())
            .unwrap_or_else(|| vec![parsed.clone()]),
        _ => return Err(anyhow!("graph: expected a JSON array or object of AWS resources")),
    };
    if args.verbose {
        eprintln!("graph: {} aws resources loaded", resources.len());
    }

    let built = resources
        .into_iter()
        .map(|r| {
            let rels = aws_resources::extract_relations(&r)
                .into_iter()
                .map(|x| (x.target, x.kind))
                .collect();
            (build_node_aws(&r), rels)
        })
        .collect();
    Ok(built)
}

/// Assemble nodes and deduplicated edges from the built nodes, resolving each
/// reference to a real graph node, and print the `{ nodes, edges }` document.
fn assemble_and_print(built: Vec<BuiltNode>, output: &str, verbose: bool) -> Result<()> {
    // Index node ids (lowercased -> canonical) so edges resolve to real nodes:
    // sub-component references collapse onto their parent; references outside
    // the inventory are dropped.
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
        let source = node.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        for (target_ref, kind) in relations {
            let Some(target) = resolve_node(target_ref, &node_ids) else {
                continue;
            };
            if target.to_lowercase() == source.to_lowercase() {
                continue;
            }
            let key = (source.to_lowercase(), target.to_lowercase(), kind.clone());
            if edge_seen.insert(key) {
                edges.push(json!({ "source": source, "target": target, "kind": kind }));
            }
        }
    }

    let graph = json!({ "nodes": nodes, "edges": edges });
    match output {
        "json" => println!("{}", serde_json::to_string_pretty(&graph)?),
        other => return Err(anyhow!("graph: unsupported output format '{}'", other)),
    }
    if verbose {
        eprintln!("graph: {} nodes, {} edges", nodes.len(), edges.len());
    }
    Ok(())
}

/// Resolve a referenced id/URL to a graph node's canonical id. Returns the exact
/// node, otherwise the longest node id that is a parent of the target (so
/// sub-component references collapse onto their owner), otherwise `None`.
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
        if lower.starts_with(&format!("{}/", lid)) && best.is_none_or(|b| canonical.len() > b.len())
        {
            best = Some(canonical);
        }
    }
    best.cloned()
}

/// Build an Azure graph node from a resource summary, optionally enriched with
/// the detailed `properties` bag fetched from ARM.
fn build_node_azure(summary: &Value, detail: Option<&Value>) -> Value {
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

/// Build a GCP graph node from a Compute resource. The `selfLink` URL is the
/// node id; the resource type comes from the `kind` field (e.g.
/// `compute#subnetwork`).
fn build_node_gcp(resource: &Value) -> Value {
    let id = resource.get("selfLink").and_then(|v| v.as_str()).unwrap_or("");
    let rtype = resource
        .get("kind")
        .and_then(|v| v.as_str())
        .map(|k| k.trim_start_matches("compute#").to_string());

    json!({
        "id": id,
        "type": rtype,
        "name": resource.get("name").cloned().unwrap_or(Value::Null),
        "region": location_from_self_link(id),
        "properties": resource.clone(),
    })
}

/// Build an AWS graph node from a Config configuration item or Cloud Control
/// resource. The id is the `resourceId`/`Identifier`/ARN; the type and region
/// come from the item metadata.
fn build_node_aws(resource: &Value) -> Value {
    let id = aws_resources::resource_id(resource).unwrap_or_default();
    let properties = resource
        .get("configuration")
        .or_else(|| resource.get("Properties"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    json!({
        "id": id,
        "type": aws_resources::resource_type(resource),
        "name": resource.get("resourceName").or_else(|| resource.get("name")).cloned().unwrap_or(Value::Null),
        "region": resource.get("awsRegion").or_else(|| resource.get("region")).cloned().unwrap_or(Value::Null),
        "properties": properties,
    })
}

/// Extract the resource group name from an ARM resource id, or `null`.
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

/// Extract the region or zone from a Compute selfLink (the segment after
/// `/regions/` or `/zones/`), or `null` for global resources.
fn location_from_self_link(self_link: &str) -> Value {
    for marker in ["/regions/", "/zones/"] {
        if let Some(pos) = self_link.find(marker) {
            let rest = &self_link[pos + marker.len()..];
            if let Some(name) = rest.split('/').next() {
                if !name.is_empty() {
                    return Value::String(name.to_string());
                }
            }
        }
    }
    Value::Null
}
