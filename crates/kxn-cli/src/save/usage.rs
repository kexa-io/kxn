//! Usage rollups produced by the `kxn watch` usage sampler.
//!
//! The sampler reads container/node CPU & RAM every few seconds and, on
//! each flush, condenses the samples into one row per container/node with
//! the window average and maximum. Postgres backends get flat tables
//! (`pod_resource`, `node_resource` — the schema the kxn-stack dashboards
//! query) plus 5-minute and 1-hour tiers refreshed incrementally; every
//! other backend receives the rows through the generic metrics pipeline.

use anyhow::Result;
use chrono::{DateTime, Utc};
use kxn_rules::SaveConfig;
use serde_json::{json, Value};

/// One container over one flush window.
#[derive(Debug, Clone, PartialEq)]
pub struct PodUsageRollup {
    pub time: DateTime<Utc>,
    pub namespace: String,
    pub pod: String,
    pub container: String,
    pub node: Option<String>,
    pub cpu_avg: f64,
    pub cpu_max: f64,
    pub mem_avg: f64,
    pub mem_max: f64,
    pub samples: i32,
}

/// One node over one flush window.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeUsageRollup {
    pub time: DateTime<Utc>,
    pub node: String,
    pub cpu_avg: f64,
    pub cpu_max: f64,
    pub mem_avg: f64,
    pub mem_max: f64,
    pub alloc_cpu: Option<f64>,
    pub alloc_mem: Option<f64>,
    pub samples: i32,
}

/// (node, cpu samples, mem samples) buffered for one container.
type PodBuffer = (Option<String>, Vec<f64>, Vec<f64>);
/// (alloc cpu, alloc mem, cpu samples, mem samples) buffered for one node.
type NodeBuffer = (Option<f64>, Option<f64>, Vec<f64>, Vec<f64>);

/// Accumulates raw samples between two flushes.
#[derive(Debug, Default, Clone)]
pub struct UsageAccumulator {
    /// keyed by (namespace, pod, container)
    pods: std::collections::BTreeMap<(String, String, String), PodBuffer>,
    nodes: std::collections::BTreeMap<String, NodeBuffer>,
}

impl UsageAccumulator {
    pub fn is_empty(&self) -> bool {
        self.pods.is_empty() && self.nodes.is_empty()
    }

    pub fn push_container(&mut self, namespace: &str, pod: &str, container: &str, node: Option<&str>, cpu: f64, mem: f64) {
        let e = self
            .pods
            .entry((namespace.to_string(), pod.to_string(), container.to_string()))
            .or_insert_with(|| (None, Vec::new(), Vec::new()));
        if e.0.is_none() {
            e.0 = node.map(str::to_string);
        }
        e.1.push(cpu);
        e.2.push(mem);
    }

    pub fn push_node(&mut self, node: &str, alloc: Option<(f64, f64)>, cpu: f64, mem: f64) {
        let e = self
            .nodes
            .entry(node.to_string())
            .or_insert_with(|| (None, None, Vec::new(), Vec::new()));
        if let Some((c, m)) = alloc {
            e.0 = Some(c);
            e.1 = Some(m);
        }
        e.2.push(cpu);
        e.3.push(mem);
    }

    /// Drain into rollup rows stamped `time` (the flush instant).
    pub fn drain(&mut self, time: DateTime<Utc>) -> (Vec<PodUsageRollup>, Vec<NodeUsageRollup>) {
        let stats = |v: &[f64]| -> (f64, f64) {
            if v.is_empty() {
                return (0.0, 0.0);
            }
            let avg = v.iter().sum::<f64>() / v.len() as f64;
            let max = v.iter().cloned().fold(f64::MIN, f64::max);
            (round2(avg), round2(max))
        };
        let pods = std::mem::take(&mut self.pods)
            .into_iter()
            .map(|((namespace, pod, container), (node, cpu, mem))| {
                let (cpu_avg, cpu_max) = stats(&cpu);
                let (mem_avg, mem_max) = stats(&mem);
                PodUsageRollup { time, namespace, pod, container, node, cpu_avg, cpu_max, mem_avg, mem_max, samples: cpu.len() as i32 }
            })
            .collect();
        let nodes = std::mem::take(&mut self.nodes)
            .into_iter()
            .map(|(node, (alloc_cpu, alloc_mem, cpu, mem))| {
                let (cpu_avg, cpu_max) = stats(&cpu);
                let (mem_avg, mem_max) = stats(&mem);
                NodeUsageRollup { time, node, cpu_avg, cpu_max, mem_avg, mem_max, alloc_cpu, alloc_mem, samples: cpu.len() as i32 }
            })
            .collect();
        (pods, nodes)
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// Rollup rows as `pod_resource` / `node_metrics` objects, for the generic
/// metrics flattener used by non-Postgres backends and for tests.
pub fn rollups_as_gathered(pods: &[PodUsageRollup], nodes: &[NodeUsageRollup]) -> Value {
    json!({
        "pod_resource": pods.iter().map(|p| json!({
            "namespace": p.namespace, "pod": p.pod, "container": p.container, "node": p.node,
            "cpu_millicores": p.cpu_avg, "cpu_max_millicores": p.cpu_max,
            "memory_mib": p.mem_avg, "memory_max_mib": p.mem_max, "samples": p.samples,
        })).collect::<Vec<_>>(),
        "node_metrics": nodes.iter().map(|n| json!({
            "name": n.node, "cpu_millicores": n.cpu_avg, "cpu_max_millicores": n.cpu_max,
            "memory_mib": n.mem_avg, "memory_max_mib": n.mem_max,
            "allocatable_cpu_millicores": n.alloc_cpu, "allocatable_memory_mib": n.alloc_mem, "samples": n.samples,
        })).collect::<Vec<_>>(),
    })
}

/// Persist one flush to every configured backend.
pub async fn save_usage(
    configs: &[SaveConfig],
    pods: &[PodUsageRollup],
    nodes: &[NodeUsageRollup],
    target: &str,
    provider: &str,
    time: DateTime<Utc>,
) -> Result<()> {
    let mut errors = Vec::new();
    for cfg in configs {
        let res = match cfg.backend.as_str() {
            "postgres" | "postgresql" => super::postgres::save_usage_rollups(cfg, pods, nodes).await,
            _ => {
                let metrics = super::flatten_gathered(&rollups_as_gathered(pods, nodes), target, provider, time);
                super::save_all(std::slice::from_ref(cfg), &[], &metrics).await
            }
        };
        if let Err(e) = res {
            errors.push(format!("{}: {}", cfg.backend, e));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("{}", errors.join("; "))
    }
}

pub(crate) const USAGE_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS pod_resource (
    id BIGSERIAL PRIMARY KEY,
    time TIMESTAMPTZ NOT NULL,
    namespace VARCHAR(255) NOT NULL,
    pod VARCHAR(255) NOT NULL,
    container VARCHAR(255) NOT NULL,
    cpu_millicores DOUBLE PRECISION,
    memory_mib DOUBLE PRECISION
);
ALTER TABLE pod_resource ADD COLUMN IF NOT EXISTS cpu_max_millicores DOUBLE PRECISION;
ALTER TABLE pod_resource ADD COLUMN IF NOT EXISTS memory_max_mib DOUBLE PRECISION;
ALTER TABLE pod_resource ADD COLUMN IF NOT EXISTS samples INTEGER;
ALTER TABLE pod_resource ADD COLUMN IF NOT EXISTS node VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_pod_resource_time ON pod_resource(time);
CREATE INDEX IF NOT EXISTS idx_pod_resource_key ON pod_resource(namespace, pod, container, time);
CREATE TABLE IF NOT EXISTS node_resource (
    id BIGSERIAL PRIMARY KEY,
    time TIMESTAMPTZ NOT NULL,
    node VARCHAR(255) NOT NULL,
    cpu_millicores DOUBLE PRECISION,
    memory_mib DOUBLE PRECISION,
    cpu_max_millicores DOUBLE PRECISION,
    memory_max_mib DOUBLE PRECISION,
    allocatable_cpu_millicores DOUBLE PRECISION,
    allocatable_memory_mib DOUBLE PRECISION,
    samples INTEGER
);
CREATE INDEX IF NOT EXISTS idx_node_resource_time ON node_resource(time);
CREATE TABLE IF NOT EXISTS pod_resource_5m (
    bucket TIMESTAMPTZ NOT NULL,
    namespace VARCHAR(255) NOT NULL,
    pod VARCHAR(255) NOT NULL,
    container VARCHAR(255) NOT NULL,
    cpu_millicores DOUBLE PRECISION,
    cpu_max_millicores DOUBLE PRECISION,
    memory_mib DOUBLE PRECISION,
    memory_max_mib DOUBLE PRECISION,
    samples BIGINT,
    PRIMARY KEY (bucket, namespace, pod, container)
);
CREATE TABLE IF NOT EXISTS pod_resource_1h (LIKE pod_resource_5m INCLUDING ALL);
CREATE TABLE IF NOT EXISTS node_resource_5m (
    bucket TIMESTAMPTZ NOT NULL,
    node VARCHAR(255) NOT NULL,
    cpu_millicores DOUBLE PRECISION,
    cpu_max_millicores DOUBLE PRECISION,
    memory_mib DOUBLE PRECISION,
    memory_max_mib DOUBLE PRECISION,
    allocatable_cpu_millicores DOUBLE PRECISION,
    allocatable_memory_mib DOUBLE PRECISION,
    samples BIGINT,
    PRIMARY KEY (bucket, node)
);
CREATE TABLE IF NOT EXISTS node_resource_1h (LIKE node_resource_5m INCLUDING ALL);
"#;

/// SQL that (re)computes the `pod_resource_<tier>` buckets touched in the
/// last `lookback_secs` seconds from the raw table. Idempotent upsert, so
/// running it after every flush keeps the tier exact.
pub(crate) fn pod_tier_refresh_sql(tier: &str, bucket_secs: i64, lookback_secs: i64) -> String {
    format!(
        "INSERT INTO pod_resource_{tier} (bucket, namespace, pod, container, cpu_millicores, cpu_max_millicores, memory_mib, memory_max_mib, samples) \
         SELECT to_timestamp(floor(extract(epoch FROM time) / {b}) * {b}), namespace, pod, container, \
                avg(cpu_millicores), max(COALESCE(cpu_max_millicores, cpu_millicores)), \
                avg(memory_mib), max(COALESCE(memory_max_mib, memory_mib)), sum(COALESCE(samples, 1)) \
         FROM pod_resource WHERE time >= NOW() - make_interval(secs => {l}) \
         GROUP BY 1, 2, 3, 4 \
         ON CONFLICT (bucket, namespace, pod, container) DO UPDATE SET \
           cpu_millicores = EXCLUDED.cpu_millicores, cpu_max_millicores = EXCLUDED.cpu_max_millicores, \
           memory_mib = EXCLUDED.memory_mib, memory_max_mib = EXCLUDED.memory_max_mib, samples = EXCLUDED.samples",
        tier = tier,
        b = bucket_secs,
        l = lookback_secs
    )
}

pub(crate) fn node_tier_refresh_sql(tier: &str, bucket_secs: i64, lookback_secs: i64) -> String {
    format!(
        "INSERT INTO node_resource_{tier} (bucket, node, cpu_millicores, cpu_max_millicores, memory_mib, memory_max_mib, allocatable_cpu_millicores, allocatable_memory_mib, samples) \
         SELECT to_timestamp(floor(extract(epoch FROM time) / {b}) * {b}), node, \
                avg(cpu_millicores), max(COALESCE(cpu_max_millicores, cpu_millicores)), \
                avg(memory_mib), max(COALESCE(memory_max_mib, memory_mib)), \
                max(allocatable_cpu_millicores), max(allocatable_memory_mib), sum(COALESCE(samples, 1)) \
         FROM node_resource WHERE time >= NOW() - make_interval(secs => {l}) \
         GROUP BY 1, 2 \
         ON CONFLICT (bucket, node) DO UPDATE SET \
           cpu_millicores = EXCLUDED.cpu_millicores, cpu_max_millicores = EXCLUDED.cpu_max_millicores, \
           memory_mib = EXCLUDED.memory_mib, memory_max_mib = EXCLUDED.memory_max_mib, \
           allocatable_cpu_millicores = EXCLUDED.allocatable_cpu_millicores, allocatable_memory_mib = EXCLUDED.allocatable_memory_mib, \
           samples = EXCLUDED.samples",
        tier = tier,
        b = bucket_secs,
        l = lookback_secs
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulator_averages_and_maxes_then_drains() {
        let mut acc = UsageAccumulator::default();
        assert!(acc.is_empty());
        acc.push_container("a", "p", "c", Some("n1"), 10.0, 100.0);
        acc.push_container("a", "p", "c", None, 30.0, 120.0);
        acc.push_node("n1", Some((4000.0, 8000.0)), 500.0, 2000.0);
        acc.push_node("n1", None, 700.0, 2100.0);
        let t = Utc::now();
        let (pods, nodes) = acc.drain(t);
        assert!(acc.is_empty(), "drain empties the buffer");
        assert_eq!(pods.len(), 1);
        let p = &pods[0];
        assert_eq!((p.cpu_avg, p.cpu_max, p.mem_avg, p.mem_max, p.samples), (20.0, 30.0, 110.0, 120.0, 2));
        assert_eq!(p.node.as_deref(), Some("n1"));
        let n = &nodes[0];
        assert_eq!((n.cpu_avg, n.cpu_max, n.alloc_cpu, n.samples), (600.0, 700.0, Some(4000.0), 2));
        let g = rollups_as_gathered(&pods, &nodes);
        assert_eq!(g["pod_resource"][0]["cpu_max_millicores"], 30.0);
        assert_eq!(g["node_metrics"][0]["name"], "n1");
    }

    #[test]
    fn tier_sql_targets_the_right_table_and_bucket() {
        let sql = pod_tier_refresh_sql("5m", 300, 600);
        assert!(sql.starts_with("INSERT INTO pod_resource_5m"));
        assert!(sql.contains("/ 300) * 300"));
        assert!(sql.contains("make_interval(secs => 600)"));
        let sql = node_tier_refresh_sql("1h", 3600, 7200);
        assert!(sql.contains("node_resource_1h") && sql.contains("/ 3600) * 3600"));
    }
}
