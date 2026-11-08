//! Collecting only what is going to be read.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use crate::error::ProviderError;
use crate::traits::Provider;

/// Gather a provider's resources, restricted to `wanted` when it is given.
///
/// `None` collects everything — what a caller wants when the result is going to
/// be persisted for dashboards rather than only evaluated. With a set, only the
/// resource types in it are fetched: a Kubernetes CIS scan reads twelve objects
/// out of seventy, and the fifty-eight others are where the minutes go.
///
/// A type that fails to collect is recorded as an error entry rather than
/// dropped, so the scan can tell "no such resource" from "could not look".
pub async fn gather_selected(
    provider: &dyn Provider,
    wanted: Option<&BTreeSet<String>>,
) -> Result<Value, ProviderError> {
    let types = provider.resource_types().await?;
    let mut output = Map::new();

    for rt in types {
        if let Some(wanted) = wanted {
            if !wanted.contains(&rt) {
                continue;
            }
        }
        match provider.gather(&rt).await {
            Ok(items) => {
                output.insert(rt, Value::Array(items));
            }
            Err(e) => {
                tracing::warn!(resource_type = %rt, error = %e, "Gather failed for resource type");
                output.insert(rt, Value::Array(vec![json!({ "error": e.to_string() })]));
            }
        }
    }

    Ok(Value::Object(output))
}
