use serde_json::Value;

/// Split a property path on `delimiter`, using `ignore` as escape character.
/// Port of Kexa `splitProperty` from helpers/spliter.ts.
///
/// Example: "a.b/c.d" with delimiter='.' and ignore='/' → ["a", "b.d"]
///   - The '/' before 'c' means "don't split on the next delimiter"
pub fn split_property(prop: &str, delimiter: char, ignore: char) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut escape = false;

    for ch in prop.chars() {
        if ch == delimiter && !escape {
            result.push(current);
            current = String::new();
        } else if ch == ignore && !escape {
            escape = true;
        } else {
            if escape && ch != delimiter {
                current.push(ignore);
            }
            current.push(ch);
            escape = false;
        }
    }
    result.push(current);
    result
}

/// Navigate into a JSON value using dot-separated property path.
/// Supports '/' as escape for dots in property names.
/// Port of Kexa `getSubProperty` from analyse.service.ts.
/// Uses a thread-local cache to avoid re-splitting the same property paths.
pub fn get_sub_property<'a>(object: &'a Value, property: &str) -> Option<&'a Value> {
    if property == "." {
        return Some(object);
    }

    // A flat map whose keys contain the separator is resolved by its own name
    // before the path is split. `sysctl` publishes `net.ipv4.ip_forward` as a
    // single key, and splitting it looked for a nested `net` object that does
    // not exist — so eight CIS network rules read an empty string and fired on
    // every host, compliant or not, while the value sat right there.
    if let Value::Object(map) = object {
        if let Some(found) = map.get(property) {
            return Some(found);
        }
    }

    use std::cell::RefCell;
    use std::collections::HashMap;
    thread_local! {
        static SPLIT_CACHE: RefCell<HashMap<String, Vec<String>>> = RefCell::new(HashMap::new());
    }

    let parts = SPLIT_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() > 10_000 {
            cache.clear();
        }
        cache
            .entry(property.to_string())
            .or_insert_with(|| split_property(property, '.', '/'))
            .clone()
    });

    let mut current = object;
    for part in &parts {
        match current {
            Value::Object(map) => {
                current = map.get(part.as_str())?;
            }
            Value::Array(arr) => {
                let idx: usize = part.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `sysctl` publishes its settings as one flat map keyed by the dotted
    /// name. Splitting on the dot looked for a nested object and found
    /// nothing, so the rule read an empty string instead of the value.
    #[test]
    fn a_flat_key_containing_dots_resolves_to_itself() {
        let flat = json!({ "net.ipv4.ip_forward": "1", "abi.swp": "0" });
        assert_eq!(get_sub_property(&flat, "net.ipv4.ip_forward"), Some(&json!("1")));
    }

    /// Nesting still wins where it exists, and the literal lookup must not
    /// shadow it: both shapes appear in the same scan.
    #[test]
    fn nested_paths_still_traverse() {
        let nested = json!({ "a": { "b": { "c": 42 } } });
        assert_eq!(get_sub_property(&nested, "a.b.c"), Some(&json!(42)));
    }

    /// When a map holds both spellings, the exact key is the one the operator
    /// wrote and the one that answers.
    #[test]
    fn the_literal_key_is_preferred_over_the_split_path() {
        let both = json!({ "a.b": "flat", "a": { "b": "nested" } });
        assert_eq!(get_sub_property(&both, "a.b"), Some(&json!("flat")));
    }

    #[test]
    fn test_split_simple() {
        assert_eq!(split_property("a.b.c", '.', '/'), vec!["a", "b", "c"]);
    }

    #[test]
    fn test_split_with_escape() {
        // '/' before '.' escapes the dot → "b.c" stays as one token
        assert_eq!(split_property("a.b/.c.d", '.', '/'), vec!["a", "b.c", "d"]);
        // '/' before non-delimiter keeps both characters
        assert_eq!(split_property("a.b/c.d", '.', '/'), vec!["a", "b/c", "d"]);
    }

    #[test]
    fn test_split_no_delimiter() {
        assert_eq!(split_property("abc", '.', '/'), vec!["abc"]);
    }

    #[test]
    fn test_get_sub_property_simple() {
        let obj = json!({"a": {"b": "value"}});
        assert_eq!(get_sub_property(&obj, "a.b"), Some(&json!("value")));
    }

    #[test]
    fn test_get_sub_property_dot() {
        let obj = json!({"x": 1});
        assert_eq!(get_sub_property(&obj, "."), Some(&obj));
    }

    #[test]
    fn test_get_sub_property_array() {
        let obj = json!({"items": [10, 20, 30]});
        assert_eq!(get_sub_property(&obj, "items.1"), Some(&json!(20)));
    }

    #[test]
    fn test_get_sub_property_missing() {
        let obj = json!({"a": 1});
        assert_eq!(get_sub_property(&obj, "b"), None);
    }
}
