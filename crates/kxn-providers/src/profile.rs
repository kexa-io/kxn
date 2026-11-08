use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Deserialize)]
pub struct Profile {
    pub name: String,
    pub providers: HashMap<String, ProviderRef>,
    pub resource_types: HashMap<String, ResourceTypeDef>,
}

#[derive(Deserialize)]
pub struct ProviderRef {
    pub address: String,
    pub version: Option<String>,
}

#[derive(Deserialize)]
pub struct ResourceTypeDef {
    pub provider: String,
    pub data_source: String,
    #[serde(default)]
    pub extra: Value,
}

/// Search paths for profile JSON files, in priority order.
fn profile_search_paths(name: &str) -> Vec<PathBuf> {
    let filename = format!("{}.json", name);
    let mut paths = Vec::new();

    // 1. ./profiles/{name}.json (relative to cwd)
    paths.push(PathBuf::from("profiles").join(&filename));

    // 2. Next to the executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("profiles").join(&filename));
        }
    }

    paths
}

/// Load a provider profile by name.
/// Searches `profiles/{name}.json` relative to cwd, then next to the executable.
pub fn load_profile(name: &str) -> Option<Profile> {
    for path in profile_search_paths(name) {
        if let Ok(content) = std::fs::read_to_string(&path) {
            return serde_json::from_str(&content).ok();
        }
    }
    None
}


/// Directories searched for profile JSON files, in priority order.
pub fn profile_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("profiles")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            dirs.push(dir.join("profiles"));
        }
    }
    dirs
}

/// Every profile found on disk, as (name, profile). Used to build the catalogue
/// of objects the Terraform bridge can produce, alongside the native providers.
pub fn load_all_profiles() -> Vec<(String, Profile)> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for dir in profile_dirs() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let name = match path.file_stem().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            if !seen.insert(name.clone()) {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(profile) = serde_json::from_str::<Profile>(&content) {
                    out.push((name, profile));
                }
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Merge profile extra config into user config.
/// Keys from `extra` are added to `user_config` without overwriting existing keys.
pub fn merge_extra(user_config: &Value, extra: &Value) -> Value {
    match (user_config, extra) {
        (Value::Object(user), Value::Object(ext)) => {
            let mut merged = user.clone();
            for (k, v) in ext {
                if !merged.contains_key(k) {
                    merged.insert(k.clone(), v.clone());
                }
            }
            Value::Object(merged)
        }
        _ => user_config.clone(),
    }
}
