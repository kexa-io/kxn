//! Every GCP resource type, with its full configuration, through Cloud Asset
//! Inventory.
//!
//! Each Cloud Asset type (`compute.googleapis.com/Instance`,
//! `sqladmin.googleapis.com/Instance`, …) is served as an object of the same
//! name. A row is the resource exactly as its own service's REST API returns
//! it — the `data` of the asset — so a rule reads the fields documented by
//! Google for that API, plus two blocks kxn adds:
//!
//! - `_asset`: `name`, `type`, `location`, `parent`, `project`, `update_time`
//! - `_iam`: the resource's own IAM policy — `bindings`, the flat `members`
//!   list, and `public` (true when `allUsers` or `allAuthenticatedUsers` hold
//!   any role on it)
//!
//! Cloud Asset rate-limits `ListAssets` per minute, so one request per type
//! would exhaust the quota long before six hundred types are read. The whole
//! project is listed once instead — resources, then IAM policies — and every
//! type is answered from that single pass.

use std::collections::HashMap;

use serde_json::{json, Map, Value};

pub(crate) use super::gcp_asset_types::ASSET_TYPES;

/// Group a `ListAssets` RESOURCE listing and its IAM_POLICY counterpart into
/// one row per resource, keyed by asset type.
///
/// `policies` is `None` when the IAM listing could not be read. Every `_iam`
/// is then `null` rather than an empty policy: a rule asking "is this public?"
/// must not be told "no" by a listing that never happened.
pub(crate) fn group_assets(
    resources: &[Value],
    policies: Option<&[Value]>,
    project: &str,
) -> HashMap<String, Vec<Value>> {
    let policy_by_name: HashMap<&str, &Value> = policies
        .unwrap_or_default()
        .iter()
        .filter_map(|p| Some((p["name"].as_str()?, &p["iamPolicy"])))
        .collect();

    let mut out: HashMap<String, Vec<Value>> = HashMap::new();
    for a in resources {
        let Some(asset_type) = a["assetType"].as_str() else { continue };
        let name = a["name"].as_str().unwrap_or("");
        let mut row = asset_row(a, policy_by_name.get(name).copied(), project);
        if policies.is_none() {
            row["_iam"] = Value::Null;
        }
        out.entry(asset_type.to_string()).or_default().push(row);
    }
    out
}

/// One resource: its API representation, plus `_asset` and `_iam`.
pub(crate) fn asset_row(a: &Value, policy: Option<&Value>, project: &str) -> Value {
    let resource = &a["resource"];
    let mut row = match &resource["data"] {
        Value::Object(m) => m.clone(),
        // A type whose data is not an object (none observed) keeps it whole.
        Value::Null => Map::new(),
        other => {
            let mut m = Map::new();
            m.insert("data".into(), other.clone());
            m
        }
    };
    row.insert(
        "_asset".into(),
        json!({
            "name": a["name"],
            "type": a["assetType"],
            "location": resource["location"],
            "parent": resource["parent"],
            "project": project,
            "update_time": a["updateTime"],
        }),
    );
    row.insert("_iam".into(), iam_block(policy));
    Value::Object(row)
}

/// The resource's own IAM policy, flattened for rules. A resource with no
/// policy of its own answers an empty one, never a missing block: "nobody is
/// granted anything here" is what the absence means.
fn iam_block(policy: Option<&Value>) -> Value {
    let mut bindings = Vec::new();
    let mut members: Vec<String> = Vec::new();
    if let Some(p) = policy {
        for b in p["bindings"].as_array().into_iter().flatten() {
            let ms: Vec<String> = b["members"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|m| m.as_str().map(String::from))
                .collect();
            bindings.push(json!({ "role": b["role"], "members": ms }));
            for m in ms {
                if !members.contains(&m) {
                    members.push(m);
                }
            }
        }
    }
    let public = members
        .iter()
        .any(|m| m == "allUsers" || m == "allAuthenticatedUsers");
    json!({ "bindings": bindings, "members": members, "public": public })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sql_asset() -> Value {
        json!({
            "name": "//cloudsql.googleapis.com/projects/p/instances/db",
            "assetType": "sqladmin.googleapis.com/Instance",
            "updateTime": "2026-11-01T00:00:00Z",
            "resource": {
                "location": "europe-west1",
                "parent": "//cloudresourcemanager.googleapis.com/projects/123",
                "data": {
                    "name": "db",
                    "databaseVersion": "POSTGRES_15",
                    "settings": { "databaseFlags": [{ "name": "log_connections", "value": "on" }] }
                }
            }
        })
    }

    #[test]
    fn a_row_is_the_api_resource_with_asset_and_iam_blocks() {
        let row = asset_row(&sql_asset(), None, "p");
        assert_eq!(row["databaseVersion"], "POSTGRES_15");
        assert_eq!(row["settings"]["databaseFlags"][0]["value"], "on");
        assert_eq!(row["_asset"]["type"], "sqladmin.googleapis.com/Instance");
        assert_eq!(row["_asset"]["location"], "europe-west1");
        assert_eq!(row["_asset"]["project"], "p");
        assert_eq!(row["_iam"]["public"], false);
        assert_eq!(row["_iam"]["members"], json!([]));
    }

    #[test]
    fn an_iam_policy_granting_all_users_makes_the_resource_public() {
        let policies = vec![json!({
            "name": "//cloudsql.googleapis.com/projects/p/instances/db",
            "iamPolicy": { "bindings": [
                { "role": "roles/viewer", "members": ["allUsers", "user:a@x.org"] },
                { "role": "roles/editor", "members": ["user:a@x.org"] }
            ]}
        })];
        let grouped = group_assets(&[sql_asset()], Some(&policies), "p");
        let row = &grouped["sqladmin.googleapis.com/Instance"][0];
        assert_eq!(row["_iam"]["public"], true);
        assert_eq!(row["_iam"]["members"], json!(["allUsers", "user:a@x.org"]));
        assert_eq!(row["_iam"]["bindings"][1]["role"], "roles/editor");
    }

    #[test]
    fn an_unreadable_iam_listing_leaves_iam_unknown_not_empty() {
        let grouped = group_assets(&[sql_asset()], None, "p");
        assert!(grouped["sqladmin.googleapis.com/Instance"][0]["_iam"].is_null());
    }

    #[test]
    fn asset_types_are_sorted_unique_and_well_formed() {
        let mut seen = std::collections::BTreeSet::new();
        for t in ASSET_TYPES {
            let (service, kind) = t.split_once('/').expect("service/Kind");
            assert!(service.ends_with(".googleapis.com"), "{t}");
            assert!(kind.chars().next().is_some_and(|c| c.is_ascii_uppercase()), "{t}");
            assert!(seen.insert(*t), "{t} listed twice");
        }
        assert!(ASSET_TYPES.windows(2).all(|w| w[0] < w[1]), "keep ASSET_TYPES sorted");
    }
}
