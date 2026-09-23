//! `kxn recommend` — Kubernetes CPU/memory right-sizing.
//!
//! Joins observed container usage (history from a kxn save backend, or a
//! few live samples) with the current requests/limits and proposes new
//! requests per workload container, KRR-style: CPU request = p95 of usage,
//! memory request = max usage + headroom, memory limit = memory request,
//! CPU limit left untouched. Output is a table, JSON, TOON (token-efficient
//! JSON for LLM prompts) or a PDF — no dashboard required.

use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Duration;

use kxn_providers::{create_native_provider, parse_target_uri};

#[derive(Args)]
pub struct RecommendArgs {
    /// Target URI: kubernetes://in-cluster, kubernetes://prod?namespace=app,
    /// kubernetes://x?api_url=https://…&token=… (K8S_* env vars also apply)
    #[arg(default_value = "kubernetes://in-cluster")]
    pub target: String,

    /// Provider config JSON merged over the URI, e.g. '{"K8S_API_URL":"…","K8S_TOKEN":"…"}'
    #[arg(long = "provider-config", default_value = "{}")]
    pub provider_config: String,

    /// Restrict to one namespace
    #[arg(short = 'n', long)]
    pub namespace: Option<String>,

    /// History window read from the save backend (e.g. 14d, 48h, 2w)
    #[arg(long, default_value = "14d")]
    pub window: String,

    /// PostgreSQL URL (or env var name) holding kxn history — a `pod_resource`
    /// table (kxn-stack) or kxn's own `resources` table. Defaults to the first
    /// postgres [[save]] entry of kxn.toml; "none" forces live sampling.
    #[arg(long)]
    pub history: Option<String>,

    /// Live samples to take when no history is available (spaced by --every)
    #[arg(long, default_value = "1")]
    pub samples: u32,

    /// Delay between live samples (e.g. 30s, 2m)
    #[arg(long, default_value = "30s")]
    pub every: String,

    /// CPU request = this percentile of observed usage
    #[arg(long, default_value = "95")]
    pub cpu_percentile: f64,

    /// Memory request/limit = observed max + this headroom (%)
    #[arg(long, default_value = "15")]
    pub memory_headroom: f64,

    /// Only list workloads whose CPU or memory request would change by at
    /// least this % (0 lists everything)
    #[arg(long, default_value = "10")]
    pub min_change: f64,

    /// Output format: text, json, toon, pdf
    #[arg(short, long, default_value = "text")]
    pub format: String,

    /// Write the report to this file instead of stdout (pdf defaults to ./kxn-recommend.pdf)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

/// Rounding grain for recommendations.
const CPU_STEP_M: f64 = 5.0;
const CPU_MIN_M: f64 = 10.0;
const MEM_STEP_MIB: f64 = 8.0;
const MEM_MIN_MIB: f64 = 16.0;

/// Observed usage of one (namespace, pod, container).
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub cpu_samples: Vec<f64>,
    pub mem_samples: Vec<f64>,
    /// Pre-aggregated stats when the backend already did the math.
    pub cpu_pct: Option<f64>,
    pub cpu_max: Option<f64>,
    pub mem_max: Option<f64>,
    pub count: u64,
    pub source: &'static str,
}

impl Observed {
    fn cpu_percentile(&self, p: f64) -> f64 {
        self.cpu_pct.unwrap_or_else(|| percentile(&self.cpu_samples, p))
    }
    fn cpu_max(&self) -> f64 {
        self.cpu_max.unwrap_or_else(|| self.cpu_samples.iter().cloned().fold(0.0, f64::max))
    }
    fn mem_max(&self) -> f64 {
        self.mem_max.unwrap_or_else(|| self.mem_samples.iter().cloned().fold(0.0, f64::max))
    }
    fn samples(&self) -> u64 {
        if self.count > 0 { self.count } else { self.cpu_samples.len() as u64 }
    }
}

/// Current spec of one (namespace, pod, container) from `pod_efficiency`.
#[derive(Debug, Clone)]
pub struct Spec {
    pub owner_kind: String,
    pub owner_name: String,
    pub cpu_request: Option<f64>,
    pub cpu_limit: Option<f64>,
    pub mem_request: Option<f64>,
    pub mem_limit: Option<f64>,
}

pub type Key = (String, String, String);

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub cpu_percentile: f64,
    pub memory_headroom_pct: f64,
    pub min_change_pct: f64,
}

pub async fn run(args: RecommendArgs, global_config: Option<PathBuf>) -> Result<()> {
    let format = args.format.to_ascii_lowercase();
    if !["text", "json", "toon", "pdf"].contains(&format.as_str()) {
        anyhow::bail!("--format must be text, json, toon or pdf (got '{}')", format);
    }
    let window_secs = parse_duration(&args.window).context("--window")?;
    let every = Duration::from_secs(parse_duration(&args.every).context("--every")?);
    if !(50.0..=100.0).contains(&args.cpu_percentile) {
        anyhow::bail!("--cpu-percentile must be between 50 and 100");
    }

    // Provider: URI first, explicit JSON on top, namespace flag last.
    let (provider_name, mut config) = parse_target_uri(&args.target).map_err(|e| anyhow::anyhow!("{}", e))?;
    if provider_name != "kubernetes" {
        anyhow::bail!("kxn recommend only supports kubernetes:// targets (got {})", provider_name);
    }
    let extra: Value = serde_json::from_str(&args.provider_config).context("Invalid --provider-config JSON")?;
    if let (Some(base), Some(add)) = (config.as_object_mut(), extra.as_object()) {
        for (k, v) in add {
            base.insert(k.clone(), v.clone());
        }
    }
    if let Some(ns) = &args.namespace {
        config["K8S_NAMESPACE"] = Value::String(ns.clone());
    }
    let provider = create_native_provider("kubernetes", config).map_err(|e| anyhow::anyhow!("{}", e))?;

    // Live snapshot: gives the current requests/limits and one usage sample.
    let mut specs: BTreeMap<Key, Spec> = BTreeMap::new();
    let mut observed: BTreeMap<Key, Observed> = BTreeMap::new();
    let mut live_samples = 0u32;
    let rows = provider.gather("pod_efficiency").await.map_err(|e| anyhow::anyhow!("{}", e))?;
    ingest_live(&rows, &mut specs, &mut observed);
    live_samples += 1;

    // History from Postgres when available.
    let history_url = resolve_history_url(args.history.as_deref(), global_config.as_deref());
    let mut history_rows = 0usize;
    let mut history_source = None;
    if let Some(url) = &history_url {
        eprintln!("kxn recommend | history: {} | window {}", redact(url), args.window);
        match load_history(url, window_secs, args.namespace.as_deref(), args.cpu_percentile).await {
            Ok((rows, source)) => {
                history_rows = rows.len();
                history_source = Some(source);
                for (key, obs) in rows {
                    // Only containers still present get a recommendation.
                    if specs.contains_key(&key) {
                        observed.insert(key, obs);
                    }
                }
            }
            Err(e) => eprintln!("kxn recommend | history unavailable ({}), using live samples", e),
        }
    }

    // Extra live samples when we have no history for most containers.
    let covered = observed.values().filter(|o| o.source == "history").count();
    if covered == 0 && args.samples > 1 {
        eprintln!(
            "kxn recommend | no history — taking {} live samples every {}",
            args.samples, args.every
        );
        for _ in 1..args.samples {
            tokio::time::sleep(every).await;
            let rows = provider.gather("pod_efficiency").await.map_err(|e| anyhow::anyhow!("{}", e))?;
            ingest_live(&rows, &mut specs, &mut observed);
            live_samples += 1;
        }
    }

    let policy = Policy {
        cpu_percentile: args.cpu_percentile,
        memory_headroom_pct: args.memory_headroom,
        min_change_pct: args.min_change,
    };
    let report = build_report(&specs, &observed, policy);
    let meta = json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "target": args.target,
        "namespace": args.namespace,
        "window": args.window,
        "history": {
            "url": history_url.as_deref().map(redact),
            "source": history_source,
            "containers_with_history": covered,
            "rows": history_rows,
        },
        "live_samples": live_samples,
        "policy": {
            "cpu_request": format!("p{} of observed usage, rounded up to {}m, min {}m", args.cpu_percentile, CPU_STEP_M, CPU_MIN_M),
            "memory_request": format!("max observed + {}%, rounded up to {}Mi, min {}Mi", args.memory_headroom, MEM_STEP_MIB, MEM_MIN_MIB),
            "memory_limit": "= memory request (Guaranteed-style, prevents OOM without over-commit)",
            "cpu_limit": "unchanged (kxn does not recommend CPU limits)",
            "min_change_pct": args.min_change,
        },
    });
    let mut doc = report;
    doc["meta"] = meta;

    let bytes = match format.as_str() {
        "json" => serde_json::to_string_pretty(&doc)?.into_bytes(),
        "toon" => toon::encode(&doc, None).into_bytes(),
        "pdf" => crate::pdf::render(
            "kxn recommend - Kubernetes right-sizing",
            &format!(
                "{} | target {} | window {} | {} containers, {} workloads",
                doc["meta"]["generated_at"].as_str().unwrap_or(""),
                args.target,
                args.window,
                doc["summary"]["containers"],
                doc["summary"]["workloads"]
            ),
            &pdf_blocks(&doc),
        ),
        _ => render_text(&doc).into_bytes(),
    };

    let output = match (&args.output, format.as_str()) {
        (Some(p), _) => Some(p.clone()),
        (None, "pdf") => Some(PathBuf::from("kxn-recommend.pdf")),
        _ => None,
    };
    match output {
        Some(path) => {
            std::fs::write(&path, &bytes).with_context(|| format!("write {}", path.display()))?;
            eprintln!("kxn recommend | wrote {} ({} bytes)", path.display(), bytes.len());
        }
        None => {
            use std::io::Write;
            std::io::stdout().write_all(&bytes)?;
            if !bytes.ends_with(b"\n") {
                println!();
            }
        }
    }
    Ok(())
}

/// Fold one `pod_efficiency` gather into specs + one usage sample each.
pub fn ingest_live(rows: &[Value], specs: &mut BTreeMap<Key, Spec>, observed: &mut BTreeMap<Key, Observed>) {
    for r in rows {
        if r.get("error").is_some() {
            continue;
        }
        let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let f = |k: &str| r.get(k).and_then(|v| v.as_f64());
        let key: Key = (s("namespace"), s("pod"), s("container"));
        if key.0.is_empty() || key.1.is_empty() {
            continue;
        }
        let (owner_kind, owner_name) = match (r.get("owner_kind").and_then(|v| v.as_str()), r.get("owner_name").and_then(|v| v.as_str())) {
            (Some(k), Some(n)) if !k.is_empty() => (k.to_string(), n.to_string()),
            _ => ("Pod".to_string(), key.1.clone()),
        };
        specs.insert(
            key.clone(),
            Spec {
                owner_kind,
                owner_name,
                cpu_request: f("cpu_request_millicores"),
                cpu_limit: f("cpu_limit_millicores"),
                mem_request: f("memory_request_mib"),
                mem_limit: f("memory_limit_mib"),
            },
        );
        let obs = observed.entry(key).or_insert_with(|| Observed { source: "live", ..Default::default() });
        if obs.source == "live" {
            obs.cpu_samples.push(f("cpu_usage_millicores").unwrap_or(0.0));
            obs.mem_samples.push(f("memory_usage_mib").unwrap_or(0.0));
        }
    }
}

/// Pick the history URL: `--history`, else the first postgres `[[save]]`
/// of the config file (explicit `-c`, then discovery), else none.
fn resolve_history_url(flag: Option<&str>, config_path: Option<&std::path::Path>) -> Option<String> {
    match flag {
        Some("none") | Some("") => return None,
        Some(url) => return Some(crate::save::resolve_url(url)),
        None => {}
    }
    let path = config_path.map(|p| p.to_path_buf()).or_else(crate::config::discover_config)?;
    let cfg = crate::config::load_config(&path).ok()?;
    cfg.save
        .iter()
        .find(|s| matches!(s.backend.as_str(), "postgres" | "postgresql"))
        .map(|s| crate::save::resolve_url(&s.url))
}

/// Hide the password of a connection URL for logs.
fn redact(url: &str) -> String {
    match (url.find("://"), url.rfind('@')) {
        (Some(a), Some(b)) if b > a => {
            let creds = &url[a + 3..b];
            match creds.find(':') {
                Some(c) => format!("{}{}:***{}", &url[..a + 3], &creds[..c], &url[b..]),
                None => url.to_string(),
            }
        }
        _ => url.to_string(),
    }
}

/// Aggregated usage per container from Postgres. Tries the flat
/// `pod_resource` table (kxn-stack / collectors) first, then kxn's own
/// `resources` JSONB table fed by `kxn watch` + `[[save]]`.
async fn load_history(
    url: &str,
    window_secs: u64,
    namespace: Option<&str>,
    cpu_percentile: f64,
) -> Result<(Vec<(Key, Observed)>, &'static str)> {
    use tokio_postgres::NoTls;
    let (client, connection) = tokio_postgres::connect(url, NoTls).await.context("PostgreSQL connection failed")?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("PostgreSQL connection error: {}", e);
        }
    });
    let window = window_secs as f64;
    let pct = cpu_percentile / 100.0;

    let exists = |table: &'static str| {
        let client = &client;
        async move {
            client
                .query_one(&format!("SELECT to_regclass('public.{table}')::text"), &[])
                .await
                .ok()
                .and_then(|r| r.get::<_, Option<String>>(0))
                .is_some()
        }
    };
    let ns_filter = |col: &str| match namespace {
        Some(_) => format!("AND {col} = $3"),
        None => String::new(),
    };

    // Pick the coarsest tier that still covers the window with enough
    // points: raw rows up to 7 days, 5-minute buckets up to 90 days, 1-hour
    // buckets beyond. Missing tables fall back to the raw table.
    let mut tier = history_tier_for(window_secs);
    if tier != "pod_resource" && !exists(tier).await {
        tier = "pod_resource";
    }
    let flat_exists = exists("pod_resource").await;

    let (sql, source): (String, &'static str) = if tier != "pod_resource" {
        (
            format!(
                "SELECT namespace, pod, container, \
                        percentile_cont($2) WITHIN GROUP (ORDER BY cpu_millicores)::float8, \
                        max(COALESCE(cpu_max_millicores, cpu_millicores))::float8, \
                        max(COALESCE(memory_max_mib, memory_mib))::float8, sum(samples)::int8 \
                 FROM {tier} WHERE bucket > NOW() - make_interval(secs => $1) {} \
                 GROUP BY 1, 2, 3",
                ns_filter("namespace")
            ),
            tier,
        )
    } else if flat_exists {
        (
            format!(
                "SELECT namespace, pod, container, \
                        percentile_cont($2) WITHIN GROUP (ORDER BY cpu_millicores)::float8, \
                        max(COALESCE(cpu_max_millicores, cpu_millicores))::float8, \
                        max(COALESCE(memory_max_mib, memory_mib))::float8, sum(COALESCE(samples, 1))::int8 \
                 FROM pod_resource WHERE time > NOW() - make_interval(secs => $1) {} \
                 GROUP BY 1, 2, 3",
                ns_filter("namespace")
            ),
            "pod_resource",
        )
    } else {
        (
            format!(
                "SELECT r.content->>'namespace', r.content->>'pod', r.content->>'container', \
                        percentile_cont($2) WITHIN GROUP (ORDER BY COALESCE((r.content->>'cpu_millicores')::float8, (r.content->>'cpu_usage_millicores')::float8))::float8, \
                        max(COALESCE((r.content->>'cpu_millicores')::float8, (r.content->>'cpu_usage_millicores')::float8))::float8, \
                        max(COALESCE((r.content->>'memory_mib')::float8, (r.content->>'memory_usage_mib')::float8))::float8, \
                        count(*)::int8 \
                 FROM resources r JOIN provider_items pi ON pi.id = r.provider_item_id \
                 WHERE pi.name IN ('pod_resource', 'pod_efficiency') AND r.created_at > NOW() - make_interval(secs => $1) {} \
                 GROUP BY 1, 2, 3",
                ns_filter("r.content->>'namespace'")
            ),
            "resources",
        )
    };
    let rows = match namespace {
        Some(ns) => client.query(&sql, &[&window, &pct, &ns]).await?,
        None => client.query(&sql, &[&window, &pct]).await?,
    };
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let key: Key = (
            row.get::<_, Option<String>>(0).unwrap_or_default(),
            row.get::<_, Option<String>>(1).unwrap_or_default(),
            row.get::<_, Option<String>>(2).unwrap_or_default(),
        );
        out.push((
            key,
            Observed {
                cpu_pct: row.get::<_, Option<f64>>(3),
                cpu_max: row.get::<_, Option<f64>>(4),
                mem_max: row.get::<_, Option<f64>>(5),
                count: row.get::<_, i64>(6).max(0) as u64,
                source: "history",
                ..Default::default()
            },
        ));
    }
    Ok((out, source))
}

/// Group containers per workload, compute recommendations and totals.
pub fn build_report(specs: &BTreeMap<Key, Spec>, observed: &BTreeMap<Key, Observed>, policy: Policy) -> Value {
    // (namespace, kind, workload, container) → member pods
    let mut groups: BTreeMap<(String, String, String, String), Vec<&Key>> = BTreeMap::new();
    for (key, spec) in specs {
        groups
            .entry((key.0.clone(), spec.owner_kind.clone(), spec.owner_name.clone(), key.2.clone()))
            .or_default()
            .push(key);
    }

    let mut rows = Vec::new();
    let mut total_cpu_saving = 0.0;
    let mut total_mem_saving = 0.0;
    let mut total_cpu_increase = 0.0;
    let mut total_mem_increase = 0.0;
    let mut no_request = 0usize;
    let mut containers = 0usize;

    for ((ns, kind, workload, container), members) in groups {
        let spec = &specs[members[0]];
        let replicas = members.iter().map(|k| &k.1).collect::<BTreeSet<_>>().len();
        containers += members.len();

        // Merge observations of every replica.
        let mut cpu_p = 0.0f64;
        let mut cpu_max = 0.0f64;
        let mut mem_max = 0.0f64;
        let mut samples = 0u64;
        let mut sources = BTreeSet::new();
        for k in &members {
            if let Some(o) = observed.get(*k) {
                cpu_p = cpu_p.max(o.cpu_percentile(policy.cpu_percentile));
                cpu_max = cpu_max.max(o.cpu_max());
                mem_max = mem_max.max(o.mem_max());
                samples += o.samples();
                sources.insert(o.source);
            }
        }
        if samples == 0 {
            continue;
        }

        let cpu_rec = round_up(cpu_p, CPU_STEP_M).max(CPU_MIN_M);
        let mem_rec = round_up(mem_max * (1.0 + policy.memory_headroom_pct / 100.0), MEM_STEP_MIB).max(MEM_MIN_MIB);

        let cpu_change = spec.cpu_request.map(|r| cpu_rec - r);
        let mem_change = spec.mem_request.map(|r| mem_rec - r);
        if spec.cpu_request.is_none() || spec.mem_request.is_none() {
            no_request += 1;
        }

        let change_pct = |change: Option<f64>, current: Option<f64>| -> f64 {
            match (change, current) {
                (Some(c), Some(cur)) if cur > 0.0 => (c / cur * 100.0).abs(),
                (Some(_), _) => 100.0,
                (None, _) => 100.0, // no request today: always worth listing
            }
        };
        let biggest = change_pct(cpu_change, spec.cpu_request).max(change_pct(mem_change, spec.mem_request));
        let action = match (spec.cpu_request, spec.mem_request) {
            (None, _) | (_, None) => "set",
            _ if biggest < policy.min_change_pct => "keep",
            _ => {
                let cpu_down = cpu_change.unwrap_or(0.0) < 0.0;
                let mem_down = mem_change.unwrap_or(0.0) < 0.0;
                let cpu_up = cpu_change.unwrap_or(0.0) > 0.0;
                let mem_up = mem_change.unwrap_or(0.0) > 0.0;
                match (cpu_up || mem_up, cpu_down || mem_down) {
                    (true, true) => "rebalance",
                    (true, false) => "increase",
                    _ => "reduce",
                }
            }
        };
        if action == "keep" && policy.min_change_pct > 0.0 {
            continue;
        }

        // Cluster-level effect = per-replica change × replicas; negative
        // change (request shrinks) is a saving.
        let rep = replicas as f64;
        if let Some(c) = cpu_change {
            if c < 0.0 { total_cpu_saving += -c * rep } else { total_cpu_increase += c * rep }
        }
        if let Some(c) = mem_change {
            if c < 0.0 { total_mem_saving += -c * rep } else { total_mem_increase += c * rep }
        }

        rows.push(json!({
            "namespace": ns,
            "kind": kind,
            "workload": workload,
            "container": container,
            "replicas": replicas,
            "samples": samples,
            "source": sources.into_iter().collect::<Vec<_>>().join("+"),
            "action": action,
            "cpu_request_m": spec.cpu_request,
            "cpu_limit_m": spec.cpu_limit,
            "cpu_p_m": round1(cpu_p),
            "cpu_max_m": round1(cpu_max),
            "cpu_rec_request_m": cpu_rec,
            "cpu_change_m": cpu_change.map(round1),
            "mem_request_mib": spec.mem_request,
            "mem_limit_mib": spec.mem_limit,
            "mem_max_mib": round1(mem_max),
            "mem_rec_request_mib": mem_rec,
            "mem_rec_limit_mib": mem_rec,
            "mem_change_mib": mem_change.map(round1),
        }));
    }

    // Biggest cluster-level effect first (savings and increases alike).
    rows.sort_by(|a, b| {
        let w = |r: &Value| {
            let rep = r["replicas"].as_f64().unwrap_or(1.0);
            let cpu = r["cpu_change_m"].as_f64().unwrap_or(0.0).abs() * rep;
            let mem = r["mem_change_mib"].as_f64().unwrap_or(0.0).abs() * rep;
            cpu + mem / 4.0 // 1 millicore ~ 4 MiB for ordering only
        };
        w(b).partial_cmp(&w(a)).unwrap_or(std::cmp::Ordering::Equal)
    });

    let by_action = |name: &str| rows.iter().filter(|r| r["action"] == name).count();
    json!({
        "summary": {
            "containers": containers,
            "workloads": rows.len(),
            "reduce": by_action("reduce"),
            "increase": by_action("increase"),
            "rebalance": by_action("rebalance"),
            "set": by_action("set"),
            "without_request": no_request,
            "cpu_saving_m": round1(total_cpu_saving),
            "cpu_increase_m": round1(total_cpu_increase),
            "memory_saving_mib": round1(total_mem_saving),
            "memory_increase_mib": round1(total_mem_increase),
        },
        "recommendations": rows,
    })
}

fn render_text(doc: &Value) -> String {
    let s = &doc["summary"];
    let m = &doc["meta"];
    let mut out = String::new();
    out.push_str(&format!(
        "kxn recommend | {} | window {} | history: {} ({} containers) | live samples: {}\n",
        m["target"].as_str().unwrap_or(""),
        m["window"].as_str().unwrap_or(""),
        m["history"]["source"].as_str().unwrap_or("none"),
        m["history"]["containers_with_history"],
        m["live_samples"]
    ));
    out.push_str(&format!(
        "{} containers | {} workloads listed: {} reduce, {} increase, {} rebalance, {} set | without request: {}\n",
        s["containers"], s["workloads"], s["reduce"], s["increase"], s["rebalance"], s["set"], s["without_request"]
    ));
    out.push_str(&format!(
        "cluster effect: CPU -{}m / +{}m  |  memory -{}Mi / +{}Mi\n\n",
        s["cpu_saving_m"], s["cpu_increase_m"], s["memory_saving_mib"], s["memory_increase_mib"]
    ));
    for line in table_lines(doc) {
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str(&format!(
        "\npolicy: cpu request = {} | memory request = {} | memory limit {} | cpu limit {}\n",
        m["policy"]["cpu_request"].as_str().unwrap_or(""),
        m["policy"]["memory_request"].as_str().unwrap_or(""),
        m["policy"]["memory_limit"].as_str().unwrap_or(""),
        m["policy"]["cpu_limit"].as_str().unwrap_or("")
    ));
    out
}

/// Fixed-width table shared by the text and PDF renderers.
fn table_lines(doc: &Value) -> Vec<String> {
    let fmt_opt = |v: &Value| match v.as_f64() {
        Some(x) => format!("{:.0}", x),
        None => "-".to_string(),
    };
    let fmt_chg = |v: &Value| match v.as_f64() {
        Some(x) if x > 0.0 => format!("+{:.0}", x),
        Some(x) => format!("{:.0}", x),
        None => "-".to_string(),
    };
    let mut lines = vec![
        format!(
            "{:<10} {:<28} {:<16} {:>3} {:>7} {:<8} {:>7} {:>7} {:>7} {:>7} | {:>8} {:>8} {:>8} {:>8}",
            "ACTION", "WORKLOAD", "CONTAINER", "REP", "N", "SRC", "CPU req", "CPU p", "CPU rec", "CHG CPU", "MEM req", "MEM max", "MEM rec", "CHG MEM"
        ),
        "-".repeat(151),
    ];
    for r in doc["recommendations"].as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
        let workload = format!(
            "{}/{}",
            r["namespace"].as_str().unwrap_or(""),
            r["workload"].as_str().unwrap_or("")
        );
        lines.push(format!(
            "{:<10} {:<28} {:<16} {:>3} {:>7} {:<8} {:>7} {:>7} {:>7} {:>7} | {:>8} {:>8} {:>8} {:>8}",
            r["action"].as_str().unwrap_or(""),
            crate::table::trunc(&workload, 28),
            crate::table::trunc(r["container"].as_str().unwrap_or(""), 16),
            r["replicas"],
            r["samples"],
            r["source"].as_str().unwrap_or(""),
            fmt_opt(&r["cpu_request_m"]),
            fmt_opt(&r["cpu_p_m"]),
            fmt_opt(&r["cpu_rec_request_m"]),
            fmt_chg(&r["cpu_change_m"]),
            fmt_opt(&r["mem_request_mib"]),
            fmt_opt(&r["mem_max_mib"]),
            fmt_opt(&r["mem_rec_request_mib"]),
            fmt_chg(&r["mem_change_mib"]),
        ));
    }
    if lines.len() == 2 {
        lines.push("(no workload above the --min-change threshold)".to_string());
    }
    lines
}

fn pdf_blocks(doc: &Value) -> Vec<crate::pdf::Block> {
    use crate::pdf::Block;
    let s = &doc["summary"];
    let m = &doc["meta"];
    vec![
        Block::Heading("Summary".into()),
        Block::Para(format!(
            "{} containers observed, {} workload containers listed: {} to reduce, {} to increase, {} to rebalance, {} without a request to set. \
             Cluster effect if applied: CPU -{} m / +{} m, memory -{} MiB / +{} MiB.",
            s["containers"], s["workloads"], s["reduce"], s["increase"], s["rebalance"], s["set"],
            s["cpu_saving_m"], s["cpu_increase_m"], s["memory_saving_mib"], s["memory_increase_mib"]
        )),
        Block::Para(format!(
            "Data: history {} ({} containers, {} aggregated rows), {} live sample(s). Window {}.",
            m["history"]["source"].as_str().unwrap_or("none"),
            m["history"]["containers_with_history"],
            m["history"]["rows"],
            m["live_samples"],
            m["window"].as_str().unwrap_or("")
        )),
        Block::Heading("Recommendations".into()),
        Block::Para("CPU in millicores, memory in MiB. CHG = recommended request minus current request per replica (negative = saving). N = usage samples across replicas.".into()),
        Block::Mono(table_lines(doc)),
        Block::Heading("Policy".into()),
        Block::Para(format!("CPU request: {}.", m["policy"]["cpu_request"].as_str().unwrap_or(""))),
        Block::Para(format!("Memory request: {}. Memory limit: {}.", m["policy"]["memory_request"].as_str().unwrap_or(""), m["policy"]["memory_limit"].as_str().unwrap_or(""))),
        Block::Para(format!("CPU limit: {}. Workloads whose change is below {}% are hidden.", m["policy"]["cpu_limit"].as_str().unwrap_or(""), m["policy"]["min_change_pct"])),
        Block::Para("Apply with care: a single live sample only reflects the current minute; prefer a history window covering at least one full business cycle (7-14 days).".into()),
    ]
}

/// History table for a window: raw ≤ 7 d, 5-minute tier ≤ 90 d, else hourly.
pub fn history_tier_for(window_secs: u64) -> &'static str {
    match window_secs {
        s if s <= 7 * 86_400 => "pod_resource",
        s if s <= 90 * 86_400 => "pod_resource_5m",
        _ => "pod_resource_1h",
    }
}

/// Nearest-rank percentile on an unsorted sample list (0 when empty).
pub fn percentile(samples: &[f64], p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut v = samples.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let rank = ((p / 100.0) * v.len() as f64).ceil() as usize;
    v[rank.clamp(1, v.len()) - 1]
}

fn round_up(v: f64, step: f64) -> f64 {
    (v / step).ceil() * step
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// "30s", "5m", "48h", "14d", "2w" → seconds.
pub fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().with_context(|| format!("invalid duration '{}'", s))?;
    let mult = match unit.trim() {
        "" | "s" | "sec" | "secs" => 1,
        "m" | "min" | "mins" => 60,
        "h" | "hr" | "hrs" => 3_600,
        "d" | "day" | "days" => 86_400,
        "w" | "week" | "weeks" => 604_800,
        other => anyhow::bail!("invalid duration unit '{}' in '{}'", other, s),
    };
    Ok(n * mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy { cpu_percentile: 95.0, memory_headroom_pct: 15.0, min_change_pct: 10.0 }
    }

    fn row(ns: &str, pod: &str, owner: &str, cpu: f64, mem: f64, req: Option<(f64, f64)>) -> Value {
        let mut r = json!({
            "namespace": ns, "pod": pod, "container": "app", "owner_kind": "Deployment", "owner_name": owner,
            "cpu_usage_millicores": cpu, "memory_usage_mib": mem,
        });
        if let Some((c, m)) = req {
            r["cpu_request_millicores"] = json!(c);
            r["memory_request_mib"] = json!(m);
            r["memory_limit_mib"] = json!(m * 2.0);
        }
        r
    }

    #[test]
    fn percentile_nearest_rank() {
        assert_eq!(percentile(&[], 95.0), 0.0);
        assert_eq!(percentile(&[5.0, 1.0, 3.0, 2.0, 4.0], 50.0), 3.0);
        assert_eq!(percentile(&[5.0, 1.0, 3.0, 2.0, 4.0], 95.0), 5.0);
        assert_eq!(percentile(&[7.0], 99.0), 7.0);
    }

    #[test]
    fn tier_selection() {
        assert_eq!(history_tier_for(3 * 86_400), "pod_resource");
        assert_eq!(history_tier_for(7 * 86_400), "pod_resource");
        assert_eq!(history_tier_for(30 * 86_400), "pod_resource_5m");
        assert_eq!(history_tier_for(400 * 86_400), "pod_resource_1h");
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30s").unwrap(), 30);
        assert_eq!(parse_duration("14d").unwrap(), 14 * 86_400);
        assert_eq!(parse_duration("2w").unwrap(), 2 * 604_800);
        assert!(parse_duration("14x").is_err());
    }

    #[test]
    fn live_ingest_accumulates_samples_and_merges_replicas() {
        let mut specs = BTreeMap::new();
        let mut obs = BTreeMap::new();
        let s1 = vec![row("app", "web-a", "web", 100.0, 300.0, Some((1000.0, 1024.0))), row("app", "web-b", "web", 40.0, 280.0, Some((1000.0, 1024.0)))];
        let s2 = vec![row("app", "web-a", "web", 120.0, 310.0, Some((1000.0, 1024.0))), row("app", "web-b", "web", 30.0, 290.0, Some((1000.0, 1024.0)))];
        ingest_live(&s1, &mut specs, &mut obs);
        ingest_live(&s2, &mut specs, &mut obs);
        assert_eq!(specs.len(), 2);
        assert_eq!(obs[&("app".into(), "web-a".into(), "app".into())].cpu_samples, vec![100.0, 120.0]);

        let report = build_report(&specs, &obs, policy());
        let recs = report["recommendations"].as_array().unwrap();
        assert_eq!(recs.len(), 1, "two replicas collapse into one workload row");
        let r = &recs[0];
        assert_eq!(r["workload"], "web");
        assert_eq!(r["replicas"], 2);
        assert_eq!(r["samples"], 4);
        assert_eq!(r["action"], "reduce");
        assert_eq!(r["cpu_rec_request_m"], 120.0); // p95 of {100,120} per replica → max 120, already on a 5m grid
        assert_eq!(r["mem_rec_request_mib"], 360.0); // 310 × 1.15 = 356.5 → 360
        assert_eq!(r["cpu_change_m"], -880.0);
        assert_eq!(report["summary"]["cpu_saving_m"], 1760.0); // × 2 replicas
        assert_eq!(report["summary"]["memory_saving_mib"], 1328.0);
    }

    #[test]
    fn missing_requests_are_set_and_small_changes_hidden() {
        let mut specs = BTreeMap::new();
        let mut obs = BTreeMap::new();
        let rows = vec![
            row("a", "x-1", "x", 3.0, 20.0, None),
            row("a", "y-1", "y", 98.0, 100.0, Some((100.0, 120.0))),
            row("a", "z-1", "z", 2.0, 900.0, Some((100.0, 512.0))),
        ];
        ingest_live(&rows, &mut specs, &mut obs);
        let report = build_report(&specs, &obs, policy());
        let recs = report["recommendations"].as_array().unwrap();
        let by = |w: &str| recs.iter().find(|r| r["workload"] == w).cloned();
        let x = by("x").expect("x listed");
        assert_eq!(x["action"], "set");
        assert_eq!(x["cpu_rec_request_m"], 10.0, "floor at 10m");
        assert_eq!(x["mem_rec_request_mib"], 24.0);
        assert!(x["cpu_change_m"].is_null());
        assert!(by("y").is_none(), "98m→100m and 100Mi→120Mi are within 10%");
        let z = by("z").expect("z listed");
        assert_eq!(z["action"], "rebalance", "cpu down, memory up");
        assert_eq!(report["summary"]["without_request"], 1);
    }

    #[test]
    fn redacts_passwords() {
        assert_eq!(redact("postgresql://kxn:secret@db:5432/kxn"), "postgresql://kxn:***@db:5432/kxn");
        assert_eq!(redact("postgresql://db/kxn"), "postgresql://db/kxn");
    }

    #[test]
    fn text_and_pdf_render() {
        let mut specs = BTreeMap::new();
        let mut obs = BTreeMap::new();
        ingest_live(&[row("a", "x-1", "x", 300.0, 200.0, Some((1000.0, 1024.0)))], &mut specs, &mut obs);
        let mut doc = build_report(&specs, &obs, policy());
        doc["meta"] = json!({"target": "kubernetes://t", "window": "14d", "history": {"source": null, "containers_with_history": 0, "rows": 0}, "live_samples": 1, "policy": {"cpu_request": "p95", "memory_request": "max+15%", "memory_limit": "= request", "cpu_limit": "unchanged", "min_change_pct": 10}});
        let text = render_text(&doc);
        assert!(text.contains("reduce     a/x"));
        assert!(text.contains("-700"));
        let pdf = crate::pdf::render("t", "s", &pdf_blocks(&doc));
        assert!(pdf.starts_with(b"%PDF-1.4"));
        let toon = toon::encode(&doc, None);
        assert!(toon.contains("recommendations[1]"), "TOON tabular array header: {toon}");
    }
}
