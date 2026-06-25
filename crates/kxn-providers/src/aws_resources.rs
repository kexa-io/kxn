//! # AWS resource relations
//!
//! Extracts inter-object relations from AWS resources provided as JSON. Two
//! input shapes are supported:
//!
//! - **AWS Config** configuration items, which carry a native `relationships`
//!   array (e.g. an instance "Is associated with" a Vpc) — the richest source.
//! - **Cloud Control / CloudFormation**-style resources, whose reference
//!   properties follow the `<Resource>Id` / `<Resource>Ids` / `<Resource>Arn`
//!   naming convention mined from the CloudFormation resource schemas.
//!
//! Live collection (signed AWS API calls) is intentionally out of scope: the
//! resources are provided as JSON, so the relation logic is testable without
//! credentials and a future collector can feed this module.

use serde_json::Value;

/// A directed relation discovered between two AWS resources.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AwsRelation {
    /// Id (resourceId or ARN) of the referenced resource — the edge target.
    pub target: String,
    /// Semantic kind, inferred from the referenced resource's type.
    pub kind: String,
}

/// Node id of an AWS resource: the AWS Config `resourceId` or the Cloud Control
/// `Identifier`, falling back to an ARN.
pub fn resource_id(resource: &Value) -> Option<String> {
    for ptr in ["/resourceId", "/Identifier", "/arn", "/Arn"] {
        if let Some(s) = resource.pointer(ptr).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// AWS resource type, e.g. `AWS::EC2::Instance`.
pub fn resource_type(resource: &Value) -> Option<String> {
    for ptr in ["/resourceType", "/TypeName"] {
        if let Some(s) = resource.pointer(ptr).and_then(|v| v.as_str()) {
            return Some(s.to_string());
        }
    }
    None
}

/// Extract relations from an AWS resource: the AWS Config `relationships` array
/// when present, plus the convention-based reference properties in the body.
pub fn extract_relations(resource: &Value) -> Vec<AwsRelation> {
    let self_id = resource_id(resource).unwrap_or_default().to_lowercase();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // 1. AWS Config native relationships (target type is explicit).
    if let Some(rels) = resource.get("relationships").and_then(|v| v.as_array()) {
        for r in rels {
            let Some(target) = r
                .get("resourceId")
                .or_else(|| r.get("arn"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let type_hint = r
                .get("resourceType")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| r.get("relationshipName").and_then(|v| v.as_str()).unwrap_or(""));
            push(&mut out, &mut seen, &self_id, target, kind_from_aws_type(type_hint));
        }
    }

    // 2. Convention-based references in the resource body.
    let body = resource
        .get("configuration")
        .or_else(|| resource.get("Properties"))
        .unwrap_or(resource);
    walk_props(body, &mut out, &mut seen, &self_id);

    out
}

/// Recursively scan a resource body for reference properties named like
/// `<Resource>Id`, `<Resource>Ids` or `<Resource>Arn`.
fn walk_props(
    node: &Value,
    out: &mut Vec<AwsRelation>,
    seen: &mut std::collections::HashSet<String>,
    self_id: &str,
) {
    match node {
        Value::Object(map) => {
            for (key, value) in map {
                if let Some(target_type) = reference_target_type(key) {
                    let kind = kind_from_aws_type(target_type);
                    match value {
                        Value::String(s) => push(out, seen, self_id, s, kind),
                        Value::Array(arr) => {
                            for e in arr {
                                if let Some(s) = e.as_str() {
                                    push(out, seen, self_id, s, kind);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                walk_props(value, out, seen, self_id);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                walk_props(v, out, seen, self_id);
            }
        }
        _ => {}
    }
}

/// If a property name follows the AWS reference convention, return the target
/// resource type embedded in it (e.g. `SubnetId` -> `Subnet`,
/// `SecurityGroupIds` -> `SecurityGroup`). Self-id fields are excluded by the
/// caller via the self id, not here.
fn reference_target_type(key: &str) -> Option<&str> {
    for suffix in ["Ids", "Arns", "Id", "Arn"] {
        if let Some(base) = key.strip_suffix(suffix) {
            if !base.is_empty() && base.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                return Some(base);
            }
        }
    }
    None
}

/// Record a relation, skipping self-references and duplicates.
fn push(
    out: &mut Vec<AwsRelation>,
    seen: &mut std::collections::HashSet<String>,
    self_id: &str,
    target: &str,
    kind: &str,
) {
    let lower = target.to_lowercase();
    if lower == self_id || target.is_empty() {
        return;
    }
    if seen.insert(format!("{}|{}", lower, kind)) {
        out.push(AwsRelation {
            target: target.to_string(),
            kind: kind.to_string(),
        });
    }
}

/// Map an AWS resource type (or a `<Resource>` prefix / relationship name) to a
/// relation kind. Matches on whole words so `SecurityGroup` is not shadowed by
/// `Group`. Unknown types fall back to a neutral `references`.
fn kind_from_aws_type(hint: &str) -> &'static str {
    let h = hint.to_lowercase();
    let has = |w: &str| h.contains(w);
    if has("securitygroup") || has("networkacl") || has("firewall") || has("wafv2") {
        "protected_by"
    } else if has("routetable") {
        "routed_by"
    } else if has("vpc") || has("subnet") || has("internetgateway") || has("natgateway")
        || has("loadbalancer") || has("targetgroup") || has("networkinterface")
        || has("transitgateway") || has("vpcendpoint") || has("vpcpeering")
    {
        "connected_to"
    } else if has("instanceprofile") || has("iamrole") || has("role") {
        "uses_identity"
    } else if has("volume") || has("snapshot") || has("image") || has("ami")
        || has("kmskey") || has("key") || has("bucket") || has("eip") || has("address")
    {
        "uses"
    } else if has("instance") {
        "attached_to"
    } else if has("autoscalinggroup") || has("placementgroup") {
        "member_of"
    } else if has("loggroup") || has("alarm") || has("logs") {
        "monitored_by"
    } else {
        "references"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_aws_config_relationships() {
        // An EC2 instance configuration item with native Config relationships.
        let instance = json!({
            "resourceType": "AWS::EC2::Instance",
            "resourceId": "i-0123456789",
            "relationships": [
                { "resourceType": "AWS::EC2::Vpc", "resourceId": "vpc-aaa",
                  "relationshipName": "Is contained in Vpc" },
                { "resourceType": "AWS::EC2::Subnet", "resourceId": "subnet-bbb",
                  "relationshipName": "Is contained in Subnet" },
                { "resourceType": "AWS::EC2::SecurityGroup", "resourceId": "sg-ccc",
                  "relationshipName": "Is associated with SecurityGroup" }
            ]
        });
        let rels = extract_relations(&instance);
        let by_target: std::collections::HashMap<_, _> =
            rels.iter().map(|r| (r.target.as_str(), r.kind.as_str())).collect();
        assert_eq!(by_target.get("vpc-aaa"), Some(&"connected_to"));
        assert_eq!(by_target.get("subnet-bbb"), Some(&"connected_to"));
        assert_eq!(by_target.get("sg-ccc"), Some(&"protected_by"));
    }

    #[test]
    fn extracts_convention_based_references() {
        // A Cloud Control-style resource with `<Resource>Id(s)` properties.
        let nic = json!({
            "TypeName": "AWS::EC2::NetworkInterface",
            "Identifier": "eni-123",
            "Properties": {
                "VpcId": "vpc-aaa",
                "SubnetId": "subnet-bbb",
                "GroupSet": ["sg-ccc", "sg-ddd"],
                "SecurityGroupIds": ["sg-ccc"]
            }
        });
        let rels = extract_relations(&nic);
        // VpcId -> Vpc (connected_to), SubnetId -> Subnet (connected_to),
        // SecurityGroupIds -> SecurityGroup (protected_by).
        assert!(rels.iter().any(|r| r.target == "vpc-aaa" && r.kind == "connected_to"));
        assert!(rels.iter().any(|r| r.target == "subnet-bbb" && r.kind == "connected_to"));
        assert!(rels.iter().any(|r| r.target == "sg-ccc" && r.kind == "protected_by"));
    }

    #[test]
    fn skips_self_reference() {
        let r = json!({
            "resourceType": "AWS::EC2::Vpc",
            "resourceId": "vpc-aaa",
            "configuration": { "VpcId": "vpc-aaa" }
        });
        assert!(extract_relations(&r).is_empty());
    }
}
