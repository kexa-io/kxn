//! Every Azure resource type, with its full ARM representation, through Azure
//! Resource Graph.
//!
//! Each type of [`ARG_TYPES`] is served as an object named after the
//! lower-cased ARM type (`microsoft.storage/storageaccounts`,
//! `microsoft.network/networksecuritygroups`, …). A row is the Resource Graph
//! record: `id`, `name`, `type`, `location`, `resourceGroup`,
//! `subscriptionId`, `tags`, `sku`, `kind`, `identity`, and the resource's
//! ARM `properties` — so a rule reads the field names of the Azure REST API
//! reference (`properties.minimumTlsVersion`, `properties.enableHttp2`).
//!
//! One query per table covers every type of the subscription, so the cost of a
//! scan does not grow with the number of types read.

use std::collections::HashMap;

use serde_json::Value;

pub(crate) use super::azure_arg_types::{ARG_TABLES, ARG_TYPES};

pub(crate) fn is_arg_type(t: &str) -> bool {
    ARG_TYPES.binary_search_by(|(ty, _)| (*ty).cmp(t)).is_ok()
}

/// The Resource Graph query for one table, restricted to what kxn serves.
pub(crate) fn table_query(table: &str) -> String {
    let filter = match table {
        // Built-in role definitions are the same in every tenant: only custom
        // ones say something about this subscription.
        "authorizationresources" => {
            "| where type !~ 'microsoft.authorization/roledefinitions' or properties.type =~ 'CustomRole'"
        }
        "policyresources" => {
            "| where type !in~ ('microsoft.authorization/policydefinitions', \
             'microsoft.authorization/policydefinitions/versions', \
             'microsoft.authorization/policysetdefinitions', \
             'microsoft.authorization/policysetdefinitions/versions', \
             'microsoft.policyinsights/policymetadata')"
        }
        "advisorresources" => "| where type !~ 'microsoft.advisor/metadata'",
        "securityresources" => "| where type !~ 'microsoft.security/cvedetails'",
        "resourcecontainers" => "| where type !~ 'microsoft.management/managementgroups'",
        _ => "",
    };
    format!("{table} {filter}").trim().to_string()
}

/// Group rows by lower-cased type, keeping only the types kxn declares.
pub(crate) fn group_rows(rows: Vec<Value>) -> HashMap<String, Vec<Value>> {
    let mut out: HashMap<String, Vec<Value>> = HashMap::new();
    for row in rows {
        let Some(t) = row.get("type").and_then(|t| t.as_str()).map(str::to_lowercase) else {
            continue;
        };
        if is_arg_type(&t) {
            out.entry(t).or_default().push(row);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn types_are_sorted_unique_lower_case_and_in_a_known_table() {
        assert!(ARG_TYPES.windows(2).all(|w| w[0].0 < w[1].0), "keep ARG_TYPES sorted and unique");
        for (t, table) in ARG_TYPES {
            assert_eq!(*t, t.to_lowercase());
            assert!(t.contains('/'), "{t}");
            assert!(ARG_TABLES.contains(table), "{t} in unknown table {table}");
        }
        assert!(is_arg_type("microsoft.storage/storageaccounts"));
        assert!(is_arg_type("microsoft.authorization/roleassignments"));
        assert!(!is_arg_type("microsoft.authorization/policydefinitions"));
    }

    #[test]
    fn rows_are_grouped_by_lower_cased_type_and_unknown_types_dropped() {
        let grouped = group_rows(vec![
            json!({"type": "Microsoft.Storage/storageAccounts", "name": "a"}),
            json!({"type": "microsoft.storage/storageaccounts", "name": "b"}),
            json!({"type": "microsoft.policyinsights/policymetadata", "name": "ref"}),
            json!({"name": "no type"}),
        ]);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped["microsoft.storage/storageaccounts"].len(), 2);
    }

    #[test]
    fn reference_tables_are_filtered_in_the_query() {
        assert!(table_query("policyresources").contains("policydefinitions"));
        assert!(table_query("authorizationresources").contains("CustomRole"));
        assert_eq!(table_query("resources"), "resources");
    }
}
