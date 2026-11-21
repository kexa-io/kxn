//! `kxn get` — the raw objects of any target, in json/jsonl/toml/toon/table.
//! `kxn top` — the metrics of a target, as a table.

use anyhow::{anyhow, Result};
use clap::Args;
use kxn_providers::{create_native_provider, parse_target_uri};
use serde_json::{Map, Value};

#[derive(Args, Clone)]
pub struct GetArgs {
    /// Target URI (k8s://ctx/ns, postgresql://…, gcp://project, aws://region, ssh://…)
    pub target: String,

    /// Object type (e.g. pods, storage_bucket, roles); omitted: list the types; `all`: every type
    pub resource_type: Option<String>,

    /// Output: json (default), jsonl, toml, toon, table
    #[arg(short, long, default_value = "json")]
    pub output: String,

    /// Keep objects whose name contains this text
    #[arg(long)]
    pub name: Option<String>,

    /// Set when one URI expands to several targets: jsonl lines carry it.
    #[arg(skip)]
    pub tag: Option<String>,
}

#[derive(Args, Clone)]
pub struct TopArgs {
    /// Target URI (k8s://ctx[/ns], postgresql://…, mysql://…, mongodb://…, ssh://…, prometheus://…)
    pub target: String,

    /// Output: table (default), json, jsonl, toml, toon
    #[arg(short, long, default_value = "table")]
    pub output: String,

    /// Set when one URI expands to several targets: jsonl lines carry it.
    #[arg(skip)]
    pub tag: Option<String>,
}

const FORMATS: &[&str] = &["json", "jsonl", "toml", "toon", "table"];

pub async fn run_get(args: GetArgs) -> Result<()> {
    let uris = crate::targets::expand(&args.target).await?;
    if uris.len() == 1 {
        return get_one(args).await;
    }
    for uri in uris {
        section(&format!("# {}\n", uri), &args.output)?;
        if let Err(e) = get_one(GetArgs { target: uri.clone(), tag: Some(uri.clone()), ..args.clone() }).await {
            eprintln!("  skipped: {}", crate::targets::short_error(&e));
        }
    }
    Ok(())
}

async fn get_one(args: GetArgs) -> Result<()> {
    check_format(&args.output)?;
    let (provider_name, config) = parse_target_uri(&args.target).map_err(|e| anyhow!("{}", e))?;
    let provider = create_native_provider(&provider_name, config).map_err(|e| anyhow!("{}", e))?;
    let types = provider.resource_types().await.map_err(|e| anyhow!("{}", e))?;

    let Some(rt) = args.resource_type.as_deref() else {
        println!("Object types for {} ({}):", args.target, provider_name);
        for t in &types {
            println!("  {}", t);
        }
        match provider_name.as_str() {
            "aws" => println!("  …and any CloudFormation type, e.g. AWS::Lambda::Function, AWS::EC2::Instance"),
            "azure" => println!("  …and any ARM type, e.g. Microsoft.Web/sites, Microsoft.Compute/virtualMachines"),
            _ => {}
        }
        println!("\nkxn get {} <type> [-o json|jsonl|toml|toon|table]", args.target);
        return Ok(());
    };

    let doc = if rt == "all" {
        let mut all = Map::new();
        for t in &types {
            match provider.gather(t).await {
                Ok(items) => {
                    all.insert(t.clone(), Value::Array(filter_name(items, args.name.as_deref())));
                }
                Err(e) => {
                    all.insert(t.clone(), serde_json::json!({ "error": e.to_string() }));
                }
            }
        }
        Value::Object(all)
    } else {
        // Cloud catalogs are open-ended: any CloudFormation type on AWS
        // (`AWS::Lambda::Function`), any ARM type on Azure (`Microsoft.Web/sites`).
        let open_type = (provider_name == "aws" && rt.starts_with("AWS::"))
            || (provider_name == "azure" && rt.contains('/'));
        if !open_type && !types.iter().any(|t| t == rt) {
            anyhow::bail!(
                "unknown object type '{}' for {} — available: {}",
                rt,
                provider_name,
                types.join(", ")
            );
        }
        let items = provider.gather(rt).await.map_err(|e| anyhow!("{}", e))?;
        Value::Array(filter_name(items, args.name.as_deref()))
    };
    let key = args.resource_type.as_deref().unwrap_or("objects");
    if args.output == "jsonl" {
        return emit(&jsonl(&doc, key, rt == "all", args.tag.as_deref())?);
    }
    emit(&render(&doc, key, &args.output)?)
}

/// The metric object types of each provider, in display order.
fn metric_types(provider: &str, config: &Value) -> Option<Vec<&'static str>> {
    Some(match provider {
        "kubernetes" => {
            if config.get("K8S_NAMESPACE").is_some() {
                vec!["pod_metrics"]
            } else {
                vec!["node_metrics", "pod_metrics"]
            }
        }
        "postgresql" | "mysql" | "mongodb" => vec!["db_stats"],
        "ssh" | "local" => vec!["system_stats"],
        "prometheus" => vec!["prometheus_metrics"],
        "gcp" | "aws" | "azure" => vec!["metrics"],
        "http" => vec!["request"],
        _ => return None,
    })
}

pub async fn run_top(args: TopArgs) -> Result<()> {
    let uris = crate::targets::expand(&args.target).await?;
    if uris.len() == 1 {
        return top_one(args).await;
    }
    for uri in uris {
        section(&format!("\n=== {} ===\n", uri), &args.output)?;
        if let Err(e) = top_one(TopArgs { target: uri.clone(), tag: Some(uri.clone()), ..args.clone() }).await {
            eprintln!("  skipped: {}", crate::targets::short_error(&e));
        }
    }
    Ok(())
}

async fn top_one(args: TopArgs) -> Result<()> {
    check_format(&args.output)?;
    let (provider_name, config) = parse_target_uri(&args.target).map_err(|e| anyhow!("{}", e))?;
    let types = metric_types(&provider_name, &config).ok_or_else(|| {
        anyhow!(
            "no metrics for {} yet — `kxn get {}` lists what can be read",
            provider_name,
            args.target
        )
    })?;
    let pod_prefix = config.get("K8S_POD").and_then(|v| v.as_str()).map(String::from);
    let provider = create_native_provider(&provider_name, config).map_err(|e| anyhow!("{}", e))?;
    for (i, t) in types.iter().enumerate() {
        let mut items = provider.gather(t).await.map_err(|e| anyhow!("{}: {}", t, e))?;
        if let Some(p) = &pod_prefix {
            items.retain(|o| o.get("pod").or_else(|| o.get("name")).and_then(|v| v.as_str()).is_some_and(|n| n.starts_with(p.as_str())));
        }
        if args.output == "table" {
            items = readable_metrics(t, items);
        }
        if args.output == "table" && types.len() > 1 {
            if i > 0 {
                emit("\n")?;
            }
            emit(&format!("# {}\n", t))?;
        }
        if args.output == "jsonl" {
            emit(&jsonl(&Value::Array(items), t, true, args.tag.as_deref())?)?;
        } else {
            emit(&render(&Value::Array(items), t, &args.output)?)?;
        }
    }
    Ok(())
}

/// Table view of metrics: the useful columns, rounded, busiest first.
fn readable_metrics(kind: &str, items: Vec<Value>) -> Vec<Value> {
    let num = |o: &Value, k: &str| o.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0);
    let round = |x: f64| (x * 10.0).round() / 10.0;
    let mut rows: Vec<(f64, Value)> = match kind {
        "node_metrics" => items
            .iter()
            .map(|o| {
                let cpu = num(o, "cpu_millicores");
                (cpu, serde_json::json!({
                    "node": o.get("name").cloned().unwrap_or_default(),
                    "cpu_m": round(cpu),
                    "cpu_%": round(num(o, "cpu_pct")),
                    "memory_mib": round(num(o, "memory_mib")),
                    "memory_%": round(num(o, "memory_pct")),
                }))
            })
            .collect(),
        "pod_metrics" => items
            .iter()
            .map(|o| {
                let containers = o.get("containers").and_then(|c| c.as_array()).cloned().unwrap_or_default();
                let cpu: f64 = containers.iter().map(|c| num(c, "cpu_millicores")).sum();
                let mem: f64 = containers.iter().map(|c| num(c, "memory_mib")).sum();
                (cpu, serde_json::json!({
                    "namespace": o.get("namespace").cloned().unwrap_or_default(),
                    "pod": o.get("name").cloned().unwrap_or_default(),
                    "cpu_m": round(cpu),
                    "memory_mib": round(mem),
                    "containers": containers.len(),
                }))
            })
            .collect(),
        // GCP Cloud Monitoring: one row per resource, biggest first.
        "metrics" => items
            .iter()
            .map(|o| {
                let size = num(o, "size_bytes") / 1_048_576.0;
                let mut row = serde_json::json!({
                    "resource": o.get("resource").cloned().unwrap_or_default(),
                    "kind": o.get("kind").cloned().unwrap_or_default(),
                });
                if o.get("size_bytes").is_some() {
                    row["size_mib"] = serde_json::json!(round(size));
                }
                if let Some(n) = o.get("objects") {
                    row["objects"] = n.clone();
                }
                if o.get("cpu_pct").is_some() {
                    row["cpu_%"] = serde_json::json!(round(num(o, "cpu_pct")));
                }
                (size + num(o, "cpu_pct"), row)
            })
            .collect(),
        // HTTP probe: what a status page shows.
        "request" => items
            .iter()
            .map(|o| {
                (0.0, serde_json::json!({
                    "url": o.get("url").cloned().unwrap_or_default(),
                    "code": o.get("code").cloned().unwrap_or_default(),
                    "response_ms": o.get("delays").cloned().unwrap_or_default(),
                    "cert_days_left": o.pointer("/certificate/days_remaining").cloned().unwrap_or_default(),
                    "http": o.get("http_version").cloned().unwrap_or_default(),
                    "status": o.get("status").cloned().unwrap_or_default(),
                }))
            })
            .collect(),
        _ => return items,
    };
    rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    rows.into_iter().map(|(_, v)| v).collect()
}

/// Write to stdout; a closed pipe (`| head`) ends the command quietly
/// instead of panicking.
fn emit(text: &str) -> Result<()> {
    use std::io::Write;
    match std::io::stdout().write_all(text.as_bytes()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(0),
        other => Ok(other?),
    }
}

/// A per-target heading: on stdout for a table, on stderr otherwise so the
/// machine formats stay parseable.
fn section(text: &str, format: &str) -> Result<()> {
    if format == "table" {
        emit(text)
    } else {
        eprint!("{}", text.trim_start());
        Ok(())
    }
}

/// One compact JSON object per line (JSON Lines): `grep`/`jq -c` friendly.
/// `with_type` adds `"type"` (`kxn get … all`, `kxn top`), `target` adds
/// `"target"` (a URI that expanded to several targets).
fn jsonl(doc: &Value, key: &str, with_type: bool, target: Option<&str>) -> Result<String> {
    let mut out = String::new();
    let mut line = |kind: &str, v: &Value| -> Result<()> {
        let mut v = v.clone();
        if let Value::Object(o) = &mut v {
            if with_type {
                o.entry("type").or_insert_with(|| Value::String(kind.to_string()));
            }
            if let Some(t) = target {
                o.entry("target").or_insert_with(|| Value::String(t.to_string()));
            }
        }
        out.push_str(&serde_json::to_string(&v)?);
        out.push('\n');
        Ok(())
    };
    match doc {
        Value::Array(items) => {
            for v in items {
                line(key, v)?;
            }
        }
        // `all`: one entry per object type.
        Value::Object(types) if with_type => {
            for (kind, items) in types {
                match items {
                    Value::Array(a) => {
                        for v in a {
                            line(kind, v)?;
                        }
                    }
                    other => line(kind, other)?,
                }
            }
        }
        other => line(key, other)?,
    }
    Ok(out)
}

fn check_format(f: &str) -> Result<()> {
    if FORMATS.contains(&f) {
        Ok(())
    } else {
        Err(anyhow!("unknown output '{}' — use {}", f, FORMATS.join(", ")))
    }
}

/// Keep objects one of whose usual name fields contains `needle`.
fn filter_name(items: Vec<Value>, needle: Option<&str>) -> Vec<Value> {
    let Some(needle) = needle else { return items };
    items
        .into_iter()
        .filter(|o| {
            ["name", "pod", "resource", "url", "id", "email", "key_id", "database", "datname", "usename", "user", "User"]
                .iter()
                .filter_map(|k| o.get(*k).and_then(|v| v.as_str()))
                .chain(o.pointer("/metadata/name").and_then(|v| v.as_str()))
                .any(|n| n.contains(needle))
        })
        .collect()
}

fn render(doc: &Value, key: &str, format: &str) -> Result<String> {
    Ok(match format {
        "json" => format!("{}\n", serde_json::to_string_pretty(doc)?),
        "toon" => format!("{}\n", toon::encode(doc, None)),
        "toml" => {
            let wrapped = match doc {
                Value::Object(_) => doc.clone(),
                other => serde_json::json!({ key: other }),
            };
            toml::to_string_pretty(&json_to_toml(&wrapped).unwrap_or(toml::Value::Table(Default::default())))?
        }
        _ => table(doc),
    })
}

/// TOML has no null: null values and empty objects are left out.
fn json_to_toml(v: &Value) -> Option<toml::Value> {
    Some(match v {
        Value::Null => return None,
        Value::Bool(b) => toml::Value::Boolean(*b),
        Value::Number(n) => match n.as_i64() {
            Some(i) => toml::Value::Integer(i),
            None => toml::Value::Float(n.as_f64().unwrap_or_default()),
        },
        Value::String(s) => toml::Value::String(s.clone()),
        Value::Array(a) => toml::Value::Array(a.iter().filter_map(json_to_toml).collect()),
        Value::Object(o) => toml::Value::Table(
            o.iter().filter_map(|(k, v)| json_to_toml(v).map(|t| (k.clone(), t))).collect(),
        ),
    })
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// One object: `key  value` lines. Several: a table of their scalar fields,
/// identifying columns first.
fn table(doc: &Value) -> String {
    let items: Vec<&Map<String, Value>> = match doc {
        Value::Array(a) => a.iter().filter_map(|v| v.as_object()).collect(),
        Value::Object(o) => vec![o],
        _ => vec![],
    };
    if items.is_empty() {
        return "(none found)\n".to_string();
    }
    if items.len() == 1 {
        let o = items[0];
        let width = o.keys().map(|k| k.len()).max().unwrap_or(0);
        // Multi-line text (a page body, a command's raw output) would break
        // the layout: `-o json` shows it.
        return o
            .iter()
            .filter_map(|(k, v)| scalar(v).filter(|s| !s.contains('\n')).map(|s| format!("{:width$}  {}\n", k, s)))
            .collect();
    }

    const FIRST: &[&str] = &[
        "namespace", "pod", "node", "name", "resource", "kind", "url", "datname", "database", "id", "email",
        "cpu_m", "cpu_%", "memory_mib", "memory_%", "size_mib", "objects",
        "code", "response_ms", "cert_days_left",
    ];
    let mut cols: Vec<String> = FIRST
        .iter()
        .filter(|c| items.iter().any(|o| o.get(**c).and_then(scalar).is_some()))
        .map(|c| c.to_string())
        .collect();
    for o in items.iter().take(20) {
        for (k, v) in o.iter() {
            if scalar(v).is_some() && !cols.contains(k) {
                cols.push(k.clone());
            }
        }
    }
    cols.truncate(8);

    let cell = |o: &Map<String, Value>, c: &str| {
        let mut s = o.get(c).and_then(scalar).unwrap_or_default();
        // Cloud names are full paths (`projects/p/locations/l/services/api`):
        // the table shows the last segment; json/toml/toon keep it whole.
        if c == "name" && s.matches('/').count() >= 2 {
            s = s.rsplit('/').next().unwrap_or_default().to_string();
        }
        if s.chars().count() > 40 {
            format!("{}…", s.chars().take(39).collect::<String>())
        } else {
            s
        }
    };
    let widths: Vec<usize> = cols
        .iter()
        .map(|c| items.iter().map(|o| cell(o, c).chars().count()).max().unwrap_or(0).max(c.len()))
        .collect();
    let line = |vals: Vec<String>| {
        vals.iter()
            .zip(&widths)
            .map(|(v, w)| format!("{:w$}", v, w = *w))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
            + "\n"
    };
    let mut out = line(cols.iter().map(|c| c.to_uppercase()).collect());
    for o in &items {
        out.push_str(&line(cols.iter().map(|c| cell(o, c)).collect()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn toml_drops_nulls_and_wraps_lists() {
        let doc = json!([{ "name": "a", "x": null, "n": 1 }]);
        let out = render(&doc, "pods", "toml").unwrap();
        assert!(out.contains("[[pods]]"), "{out}");
        assert!(out.contains("name = \"a\""), "{out}");
        assert!(!out.contains('x'), "{out}");
    }

    #[test]
    fn jsonl_writes_one_object_per_line() {
        let doc = json!({ "pods": [{ "name": "a" }, { "name": "b" }], "nodes": { "error": "denied" } });
        let out = jsonl(&doc, "all", true, Some("k8s://x")).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out}");
        for l in &lines {
            let v: Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["target"], "k8s://x");
        }
        assert!(out.contains(r#""name":"a""#) && out.contains(r#""type":"pods""#), "{out}");
        let plain = jsonl(&json!([{ "name": "a" }]), "pods", false, None).unwrap();
        assert_eq!(plain, "{\"name\":\"a\"}\n");
    }

    #[test]
    fn table_puts_identifying_columns_first() {
        let doc = json!([
            { "cpu": 5, "pod": "api-1", "namespace": "prod" },
            { "cpu": 9, "pod": "api-2", "namespace": "prod" }
        ]);
        let out = table(&doc);
        assert!(out.starts_with("NAMESPACE  POD    CPU"), "{out}");
    }

    #[test]
    fn table_shortens_cloud_resource_paths() {
        let out = table(&json!([
            { "name": "projects/p/locations/eu/services/api" },
            { "name": "projects/p/locations/eu/services/web" }
        ]));
        assert!(out.contains("\napi\n") && !out.contains("projects/"), "{out}");
    }

    #[test]
    fn single_object_is_listed_as_key_value() {
        let out = table(&json!([{ "connections_total": 3, "cache_hit_ratio": 99.5 }]));
        assert!(out.contains("connections_total  3"), "{out}");
    }

    #[test]
    fn name_filter_reads_usual_name_fields() {
        let items = vec![json!({ "metadata": { "name": "kxn-abc" } }), json!({ "name": "other" })];
        assert_eq!(filter_name(items, Some("kxn")).len(), 1);
    }
}
