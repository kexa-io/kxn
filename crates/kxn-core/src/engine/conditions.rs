//! All 33 condition check functions, ported from Kexa analyse.service.ts
//!
//! Each function takes the condition value (expected) and actual value from the resource,
//! both as serde_json::Value, and returns a bool.

use chrono::{Duration, NaiveDate, Utc};
use regex::Regex;
use serde_json::Value;
use tracing::debug;

use crate::models::rule::{ConditionNode, RulesCondition};

use super::evaluator::check_rule;

// ─── Equality / Comparison ──────────────────────────────────────────────────

pub fn check_equal(expected: &Value, actual: &Value) -> bool {
    debug!("check_equal: {:?} == {:?}", actual, expected);
    if actual == expected {
        return true;
    }
    // Type coercion: compare as numbers if possible
    if let (Some(a), Some(e)) = (as_f64(actual), as_f64(expected)) {
        return a == e;
    }
    false
}

pub fn check_greater_than(expected: &Value, actual: &Value) -> bool {
    debug!("check_greater_than: {:?} > {:?}", actual, expected);
    match (as_f64(actual), as_f64(expected)) {
        (Some(a), Some(e)) => a > e,
        _ => {
            let a = actual.to_string();
            let e = expected.to_string();
            a > e
        }
    }
}

pub fn check_less_than(expected: &Value, actual: &Value) -> bool {
    debug!("check_less_than: {:?} < {:?}", actual, expected);
    match (as_f64(actual), as_f64(expected)) {
        (Some(a), Some(e)) => a < e,
        _ => {
            let a = actual.to_string();
            let e = expected.to_string();
            a < e
        }
    }
}

// ─── String operations ──────────────────────────────────────────────────────

pub fn check_include(expected: &Value, actual: &Value) -> bool {
    debug!("check_include: {:?} contains {:?}", actual, expected);
    match actual {
        Value::String(s) => {
            let needle = value_to_string(expected);
            s.contains(&needle)
        }
        Value::Array(arr) => arr.contains(expected),
        _ => false,
    }
}

pub fn check_include_not_sensitive(expected: &Value, actual: &Value) -> bool {
    debug!("check_include_ns: {:?} contains {:?}", actual, expected);
    match actual {
        Value::String(s) => {
            let needle = value_to_string(expected).to_lowercase();
            s.to_lowercase().contains(&needle)
        }
        _ => false,
    }
}

pub fn check_starts_with(expected: &Value, actual: &Value) -> bool {
    let actual_s = value_to_string(actual);
    let expected_s = value_to_string(expected);
    actual_s.starts_with(&expected_s)
}

pub fn check_ends_with(expected: &Value, actual: &Value) -> bool {
    let actual_s = value_to_string(actual);
    let expected_s = value_to_string(expected);
    actual_s.ends_with(&expected_s)
}

pub fn check_regex(expected: &Value, actual: &Value) -> bool {
    let pattern = value_to_string(expected);
    let hay = value_to_string(actual);
    match Regex::new(&pattern) {
        Ok(re) => re.is_match(&hay),
        Err(_) => false,
    }
}

// ─── IN / NOT_IN ────────────────────────────────────────────────────────────

pub fn check_in(expected: &Value, actual: &Value) -> bool {
    if let Value::Array(arr) = expected {
        arr.contains(actual)
    } else {
        false
    }
}

pub fn check_not_in(expected: &Value, actual: &Value) -> bool {
    if let Value::Array(arr) = expected {
        !arr.contains(actual)
    } else {
        true
    }
}

// ─── Array quantifiers (ALL / SOME / ONE) ───────────────────────────────────

pub fn check_all(conditions: &Value, actual: &Value) -> bool {
    let items = match actual {
        Value::Array(arr) => arr,
        _ => return false,
    };
    let conds = match parse_condition_nodes(conditions) {
        Some(c) => c,
        None => return false,
    };
    items.iter().all(|item| {
        let results = check_rule(&conds, item);
        results.iter().all(|r| r.result)
    })
}

pub fn check_some(conditions: &Value, actual: &Value) -> bool {
    let items = match actual {
        Value::Array(arr) => arr,
        _ => return false,
    };
    let conds = match parse_condition_nodes(conditions) {
        Some(c) => c,
        None => return false,
    };
    items.iter().any(|item| {
        let results = check_rule(&conds, item);
        results.iter().all(|r| r.result)
    })
}

pub fn check_one(conditions: &Value, actual: &Value) -> bool {
    let items = match actual {
        Value::Array(arr) => arr,
        _ => return false,
    };
    let conds = match parse_condition_nodes(conditions) {
        Some(c) => c,
        None => return false,
    };
    let matching = items
        .iter()
        .filter(|item| {
            let results = check_rule(&conds, item);
            results.iter().all(|r| r.result)
        })
        .count();
    matching == 1
}

fn parse_condition_nodes(value: &Value) -> Option<Vec<ConditionNode>> {
    serde_json::from_value(value.clone()).ok()
}

// ─── Interval ───────────────────────────────────────────────────────────────

pub fn check_interval(expected: &Value, actual: &Value) -> bool {
    let parts = value_to_string(expected);
    let parts: Vec<&str> = parts.split_whitespace().collect();
    if parts.len() != 2 {
        return false;
    }
    let actual_f = match as_f64(actual) {
        Some(v) => v,
        None => return false,
    };
    let low: f64 = parts[0].parse().unwrap_or(f64::MIN);
    let high: f64 = parts[1].parse().unwrap_or(f64::MAX);
    actual_f >= low && actual_f <= high
}

// ─── Date operations ───────────────────────────────────────────────────────

/// Generate a date by subtracting a differential from now.
/// Differential format: "seconds minutes hours days weeks months years"
/// Positional: "0 0 0 90" = 90 days ago.
fn generate_date(differential: &str) -> chrono::DateTime<Utc> {
    let parts: Vec<i64> = differential
        .split_whitespace()
        .filter_map(|p| p.parse().ok())
        .collect();
    let units = [1i64, 60, 3600, 86400, 604800, 2592000, 31536000]; // sec, min, hr, day, week, month(30d), year(365d)
    let total_seconds: i64 = parts
        .iter()
        .zip(units.iter())
        .map(|(v, u)| v * u)
        .sum();
    Utc::now() - Duration::seconds(total_seconds)
}

fn parse_date(value: &Value, format: Option<&str>) -> Option<chrono::DateTime<Utc>> {
    let s = value_to_string(value);
    if s.is_empty() {
        return None;
    }
    // Try ISO 8601 first
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&s) {
        return Some(dt.with_timezone(&Utc));
    }
    // Try common formats
    let formats = [
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%m-%Y",
        "%d/%m/%Y",
        "%m/%d/%Y",
    ];
    let all_formats = if let Some(f) = format {
        let mut v = vec![f];
        v.extend(formats.iter());
        v
    } else {
        formats.to_vec()
    };
    for fmt in all_formats {
        if let Ok(nd) = NaiveDate::parse_from_str(&s, fmt) {
            return Some(nd.and_hms_opt(0, 0, 0)?.and_utc());
        }
        if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(&s, fmt) {
            return Some(ndt.and_utc());
        }
    }
    None
}

pub fn check_equal_date(
    condition: &RulesCondition,
    actual: &Value,
) -> bool {
    let actual_dt = match parse_date(actual, condition.date.as_deref()) {
        Some(d) => d,
        None => return false,
    };
    let expected_dt = match parse_date(&condition.value, condition.date.as_deref()) {
        Some(d) => d,
        None => return false,
    };
    actual_dt.date_naive() == expected_dt.date_naive()
}

pub fn check_greater_than_date(
    condition: &RulesCondition,
    actual: &Value,
) -> bool {
    let actual_dt = match parse_date(actual, condition.date.as_deref()) {
        Some(d) => d,
        None => return false,
    };
    let dynamic_dt = generate_date(&value_to_string(&condition.value));
    actual_dt < dynamic_dt
}

pub fn check_greater_than_date_or_equal(
    condition: &RulesCondition,
    actual: &Value,
) -> bool {
    let actual_dt = match parse_date(actual, condition.date.as_deref()) {
        Some(d) => d,
        None => return false,
    };
    let dynamic_dt = generate_date(&value_to_string(&condition.value));
    actual_dt <= dynamic_dt
}

pub fn check_less_than_date(
    condition: &RulesCondition,
    actual: &Value,
) -> bool {
    let actual_dt = match parse_date(actual, condition.date.as_deref()) {
        Some(d) => d,
        None => return false,
    };
    let dynamic_dt = generate_date(&value_to_string(&condition.value));
    actual_dt > dynamic_dt
}

pub fn check_less_than_date_or_equal(
    condition: &RulesCondition,
    actual: &Value,
) -> bool {
    let actual_dt = match parse_date(actual, condition.date.as_deref()) {
        Some(d) => d,
        None => return false,
    };
    let dynamic_dt = generate_date(&value_to_string(&condition.value));
    actual_dt >= dynamic_dt
}

pub fn check_interval_date(
    condition: &RulesCondition,
    actual: &Value,
) -> bool {
    let actual_dt = match parse_date(actual, condition.date.as_deref()) {
        Some(d) => d,
        None => return false,
    };
    let parts = value_to_string(&condition.value);
    let parts: Vec<&str> = parts.split_whitespace().collect();
    if parts.len() != 2 {
        return false;
    }
    let dt1 = match parse_date(&Value::String(parts[0].to_string()), condition.date.as_deref()) {
        Some(d) => d,
        None => return false,
    };
    let dt2 = match parse_date(&Value::String(parts[1].to_string()), condition.date.as_deref()) {
        Some(d) => d,
        None => return false,
    };
    actual_dt >= dt1 && actual_dt <= dt2
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_check_equal() {
        assert!(check_equal(&json!("yes"), &json!("yes")));
        assert!(!check_equal(&json!("yes"), &json!("no")));
        assert!(check_equal(&json!(42), &json!(42)));
    }

    #[test]
    fn test_check_greater_than() {
        assert!(check_greater_than(&json!(5), &json!(10)));
        assert!(!check_greater_than(&json!(10), &json!(5)));
    }

    #[test]
    fn test_check_less_than() {
        assert!(check_less_than(&json!(10), &json!(5)));
        assert!(!check_less_than(&json!(5), &json!(10)));
    }

    #[test]
    fn test_check_include_string() {
        assert!(check_include(&json!("ell"), &json!("hello")));
        assert!(!check_include(&json!("xyz"), &json!("hello")));
    }

    #[test]
    fn test_check_include_array() {
        assert!(check_include(&json!("b"), &json!(["a", "b", "c"])));
        assert!(!check_include(&json!("d"), &json!(["a", "b", "c"])));
    }

    #[test]
    fn test_check_regex() {
        assert!(check_regex(&json!("^hello"), &json!("hello world")));
        assert!(!check_regex(&json!("^world"), &json!("hello world")));
    }

    #[test]
    fn test_check_in() {
        assert!(check_in(&json!(["a", "b", "c"]), &json!("b")));
        assert!(!check_in(&json!(["a", "b", "c"]), &json!("d")));
    }

    #[test]
    fn test_check_interval() {
        assert!(check_interval(&json!("1 10"), &json!(5)));
        assert!(!check_interval(&json!("1 10"), &json!(15)));
    }

    #[test]
    fn test_check_starts_with() {
        assert!(check_starts_with(&json!("hel"), &json!("hello")));
        assert!(!check_starts_with(&json!("wor"), &json!("hello")));
    }

    #[test]
    fn test_check_ends_with() {
        assert!(check_ends_with(&json!("llo"), &json!("hello")));
        assert!(!check_ends_with(&json!("hel"), &json!("hello")));
    }
}
