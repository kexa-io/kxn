//! # GCP Compute inventory and relations
//!
//! Lists Google Compute Engine resources for a project and extracts the
//! relations between them. GCP represents cross-resource references as resource
//! **URLs** (e.g. a subnetwork's `network` field, an instance's
//! `networkInterfaces[].subnetwork`). Those URLs are self-describing — they
//! encode the resource type — so, like the Azure ARM `{id}` walker, a generic
//! URL walker discovers every relation without per-type code.

use anyhow::{Context, Result};
use serde_json::Value;

/// Compute collections to inventory, with whether they are listed via the
/// `aggregated/*` endpoint (zonal/regional) or the `global/*` endpoint.
const COLLECTIONS: &[(&str, bool)] = &[
    ("networks", false),
    ("firewalls", false),
    ("backendServices", false),
    ("healthChecks", false),
    ("urlMaps", false),
    ("targetHttpProxies", false),
    ("targetHttpsProxies", false),
    ("subnetworks", true),
    ("instances", true),
    ("disks", true),
    ("addresses", true),
    ("routers", true),
    ("forwardingRules", true),
    ("targetPools", true),
    ("instanceGroups", true),
];

/// List Compute Engine resources for a project across the inventoried
/// collections. Each returned object keeps its native fields (including
/// `selfLink`, used as the node id, and the cross-reference URL fields).
/// Collections whose API is disabled or empty are skipped.
pub async fn list_resources(project: &str) -> Result<Vec<Value>> {
    let token = get_gcp_token().await?;
    let client = crate::http::shared_client();
    let mut out = Vec::new();

    for (collection, aggregated) in COLLECTIONS {
        let scope = if *aggregated { "aggregated" } else { "global" };
        let mut url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/{}/{}",
            project, scope, collection
        );

        // Each collection paginates independently via `pageToken`.
        loop {
            let resp = client
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
                .context("GCP Compute request failed")?;

            if !resp.status().is_success() {
                // A disabled API or a forbidden collection should not abort the
                // whole inventory — skip this collection.
                break;
            }

            let json: Value = resp.json().await.context("parse Compute response")?;
            collect_items(&json, aggregated, collection, &mut out);

            match json.get("nextPageToken").and_then(|v| v.as_str()) {
                Some(t) if !t.is_empty() => {
                    url = format!(
                        "https://compute.googleapis.com/compute/v1/projects/{}/{}/{}?pageToken={}",
                        project, scope, collection, t
                    );
                }
                _ => break,
            }
        }
    }

    Ok(out)
}

/// List ALL project resources via Cloud Asset Inventory (one API across every
/// service: Compute, Storage, IAM, Secret Manager, GKE, SQL, ...), far broader
/// than the Compute-only `list_resources`. Returns the raw asset objects
/// (`{ name, assetType, resource: { data, location, parent } }`); noisy types
/// (SecretVersion, enabled-Service entries) are filtered out.
pub async fn list_assets(project: &str) -> Result<Vec<Value>> {
    let token = get_gcp_token().await?;
    let client = crate::http::shared_client();

    let base = format!(
        "https://cloudasset.googleapis.com/v1/projects/{}/assets?contentType=RESOURCE&pageSize=500",
        project
    );
    let mut url = base.clone();
    let mut out = Vec::new();

    loop {
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .context("GCP Cloud Asset Inventory request failed")?;

        if !resp.status().is_success() {
            let s = resp.status();
            let t = resp.text().await.unwrap_or_default();
            anyhow::bail!("GCP Cloud Asset Inventory GET failed ({}): {}", s, t);
        }

        let json: Value = resp.json().await.context("parse asset inventory response")?;
        if let Some(arr) = json.get("assets").and_then(|v| v.as_array()) {
            for a in arr {
                if let Some(t) = a.get("assetType").and_then(|v| v.as_str()) {
                    if is_noise_asset_type(t) {
                        continue;
                    }
                }
                out.push(a.clone());
            }
        }

        match json.get("nextPageToken").and_then(|v| v.as_str()) {
            Some(t) if !t.is_empty() => url = format!("{}&pageToken={}", base, t),
            _ => break,
        }
    }

    Ok(out)
}

/// High-volume, low-value asset types that only add noise to the graph.
fn is_noise_asset_type(asset_type: &str) -> bool {
    matches!(
        asset_type,
        "secretmanager.googleapis.com/SecretVersion"
            | "serviceusage.googleapis.com/Service"
            | "cloudbilling.googleapis.com/ProjectBillingInfo"
    )
}

/// Pull resource objects out of a Compute list response. Aggregated responses
/// nest items per scope under `items.<scope>.<collection>`; global responses
/// put them directly under `items`.
fn collect_items(json: &Value, aggregated: &bool, collection: &str, out: &mut Vec<Value>) {
    if *aggregated {
        if let Some(scopes) = json.get("items").and_then(|v| v.as_object()) {
            for blk in scopes.values() {
                if let Some(arr) = blk.get(collection).and_then(|v| v.as_array()) {
                    out.extend(arr.iter().cloned());
                }
            }
        }
    } else if let Some(arr) = json.get("items").and_then(|v| v.as_array()) {
        out.extend(arr.iter().cloned());
    }
}

/// A directed relation discovered between two GCP resources.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GcpRelation {
    /// selfLink URL of the referenced resource (the edge target).
    pub target: String,
    /// Semantic kind, inferred from the referenced resource's type segment.
    pub kind: String,
}

/// Extract cross-resource relations from a Compute resource by collecting every
/// nested Compute resource URL and inferring the kind from its type segment.
/// References to the resource itself are skipped, as are duplicate pairs.
pub fn extract_relations(resource: &Value) -> Vec<GcpRelation> {
    let self_link = resource
        .get("selfLink")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    walk(resource, &self_link, &mut out, &mut seen);
    out
}

/// Recursively collect Compute resource URLs from any string value.
fn walk(
    node: &Value,
    self_link: &str,
    out: &mut Vec<GcpRelation>,
    seen: &mut std::collections::HashSet<String>,
) {
    match node {
        Value::String(s) if is_compute_url(s) => {
            let lower = s.to_lowercase();
            if lower != self_link && seen.insert(lower) {
                out.push(GcpRelation {
                    target: s.clone(),
                    kind: kind_from_url(s).to_string(),
                });
            }
        }
        Value::Array(arr) => {
            for v in arr {
                walk(v, self_link, out, seen);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                walk(v, self_link, out, seen);
            }
        }
        _ => {}
    }
}

/// True if the string is a Compute Engine resource URL. Compute selfLinks and
/// reference fields use the `www.googleapis.com/compute/...` form as well as the
/// `compute.googleapis.com/...` form, so match on the path rather than the host.
fn is_compute_url(s: &str) -> bool {
    s.starts_with("https://")
        && s.contains("/compute/")
        && s.contains("/projects/")
        && type_segment(s).is_some()
}

/// Extract the resource-type segment of a Compute URL (the path component just
/// before the trailing resource name), e.g. `.../global/networks/foo` -> `networks`.
fn type_segment(url: &str) -> Option<&str> {
    let path = url.split('?').next().unwrap_or(url);
    let mut it = path.rsplit('/');
    let _name = it.next()?; // trailing resource name
    let seg = it.next()?;
    if seg.is_empty() {
        None
    } else {
        Some(seg)
    }
}

/// Map a referenced Compute resource URL to a relation kind, based on its type
/// segment. Unknown types fall back to a neutral `references`.
fn kind_from_url(url: &str) -> &'static str {
    match type_segment(url).unwrap_or("").to_lowercase().as_str() {
        "networks" | "subnetworks" | "backendservices" | "targetpools"
        | "forwardingrules" | "urlmaps" | "targethttpproxies" | "targethttpsproxies" => {
            "connected_to"
        }
        "firewalls" | "firewallpolicies" | "securitypolicies" => "protected_by",
        "routers" | "routes" => "routed_by",
        "instances" => "attached_to",
        "instancegroups" | "instancegroupmanagers" => "member_of",
        "healthchecks" | "httphealthchecks" | "httpshealthchecks" => "monitored_by",
        "serviceaccounts" => "uses_identity",
        "disks" | "images" | "snapshots" | "addresses" | "disktypes" => "uses",
        _ => "references",
    }
}

/// Obtain a GCP OAuth access token. `GOOGLE_OAUTH_ACCESS_TOKEN` (e.g. from
/// `gcloud auth print-access-token`) is used directly when set; otherwise the
/// standard application-default credentials chain is used.
async fn get_gcp_token() -> Result<String> {
    if let Ok(token) = std::env::var("GOOGLE_OAUTH_ACCESS_TOKEN") {
        return Ok(token);
    }
    let provider = gcp_auth::provider()
        .await
        .context("GCP auth failed (set GOOGLE_OAUTH_ACCESS_TOKEN or configure ADC)")?;
    let token = provider
        .token(&["https://www.googleapis.com/auth/cloud-platform"])
        .await
        .context("GCP token request failed")?;
    Ok(token.as_str().to_string())
}
