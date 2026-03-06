use serde::Serialize;

use super::rule::{ComplianceRef, RulesCondition};

/// Result of evaluating a single condition
#[derive(Debug, Clone, Serialize)]
pub struct SubResultScan {
    pub value: serde_json::Value,
    pub result: bool,
    pub condition: Vec<RulesCondition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Result of evaluating all conditions of a rule against a single resource
#[derive(Debug, Clone, Serialize)]
pub struct ResultScan {
    pub object_content: serde_json::Value,
    pub rule_name: String,
    pub errors: Vec<SubResultScan>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compliance: Vec<ComplianceRef>,
}

/// Summary of a full scan across multiple rules and resources
#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub total_rules: usize,
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<ResultScan>,
}
