mod postgres;
mod mysql;

/// Resolve a save URL: if it doesn't contain "://", treat it as an env var name.
pub(crate) fn resolve_url(url: &str) -> String {
    if !url.contains("://") {
        std::env::var(url).unwrap_or_else(|_| url.to_string())
    } else {
        url.to_string()
    }
}

/// Apply payload compression to an HTTP save-backend body.
///
/// Returns `(compressed_bytes, content_encoding_header_value)` when a
/// supported algorithm is configured, or `(original_bytes, None)` when
/// `compression` is `None` / unsupported.
///
/// Supported algorithms: `"gzip"` (RFC 1952, via flate2).
/// Unsupported values log a warning and fall through uncompressed so a typo
/// never breaks a scan pipeline silently.
pub(crate) fn compress_payload(
    body: impl Into<Vec<u8>>,
    compression: Option<&str>,
) -> (Vec<u8>, Option<&'static str>) {
    let body = body.into();
    match compression.map(str::to_ascii_lowercase).as_deref() {
        None | Some("") | Some("none") | Some("off") | Some("false") => (body, None),
        Some("gzip") | Some("gz") => {
            use std::io::Write;
            let mut enc =
                flate2::write::GzEncoder::new(Vec::with_capacity(body.len() / 2), flate2::Compression::default());
            if let Err(e) = enc.write_all(&body) {
                tracing::warn!("gzip compress_payload write_all failed, sending uncompressed: {}", e);
                return (body, None);
            }
            match enc.finish() {
                Ok(compressed) => (compressed, Some("gzip")),
                Err(e) => {
                    tracing::warn!("gzip compress_payload finish failed, sending uncompressed: {}", e);
                    (body, None)
                }
            }
        }
        Some(other) => {
            tracing::warn!(
                "unknown save compression '{}' — sending uncompressed payload",
                other
            );
            (body, None)
        }
    }
}
mod mongo;
mod cloud_storage;
mod elasticsearch;
mod eventhubs;
mod file;
mod influxdb;
mod kafka;
mod pubsub;
mod redis;
mod loki;
mod sns;
mod splunk_hec;

use anyhow::Result;
use kxn_rules::SaveConfig;
use serde::Serialize;
use serde_json::Value;

/// A scan result row to persist
#[derive(Debug, Clone, Serialize)]
pub struct ScanRecord {
    pub target: String,
    pub provider: String,
    pub rule_name: String,
    pub rule_description: String,
    pub level: u8,
    pub level_label: String,
    pub object_type: String,
    pub object_content: Value,
    pub error: bool,
    pub messages: Vec<String>,
    pub conditions: Value,
    pub compliance: Vec<kxn_core::ComplianceRef>,
    pub batch_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tags: std::collections::HashMap<String, String>,
}

/// A log entry collected from a remote target
#[derive(Debug, Clone, Serialize)]
pub struct LogRecord {
    pub target: String,
    pub source: String,
    pub level: String,
    pub message: String,
    pub host: Option<String>,
    pub unit: Option<String>,
    pub collected_at: chrono::DateTime<chrono::Utc>,
    pub batch_id: String,
    pub tags: std::collections::HashMap<String, String>,
}

/// A flat metric data point for time-series (Grafana)
#[derive(Debug, Clone, Serialize)]
pub struct MetricRecord {
    pub target: String,
    pub provider: String,
    pub resource_type: String,
    pub metric_name: String,
    pub value_num: Option<f64>,
    pub value_str: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Save scan records + raw metrics to all configured backends
pub async fn save_all(
    configs: &[SaveConfig],
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    for config in configs {
        let result = match config.backend.as_str() {
            "postgres" | "postgresql" => postgres::save(config, records, metrics).await,
            "mysql" | "mariadb" => mysql::save(config, records, metrics).await,
            "mongodb" | "mongo" => mongo::save(config, records, metrics).await,
            "s3" | "gcs" | "azure" | "cloud" => cloud_storage::save(config, records, metrics).await,
            "elasticsearch" | "opensearch" | "elastic" => elasticsearch::save(config, records, metrics).await,
            "file" | "jsonl" => file::save(config, records, metrics).await,
            "kafka" => kafka::save(config, records, metrics).await,
            "eventhubs" | "eventhub" => eventhubs::save(config, records, metrics).await,
            "sns" => sns::save(config, records, metrics).await,
            "pubsub" => pubsub::save(config, records, metrics).await,
            "redis" => redis::save(config, records, metrics).await,
            "splunkhec" | "splunk-hec" => splunk_hec::save(config, records, metrics).await,
            "loki" | "grafana-loki" => loki::save(config, records, metrics).await,
            "influxdb" | "influx" => influxdb::save(config, records, metrics).await,
            other => {
                tracing::warn!(backend = %other, "unknown save backend, skipping");
                continue;
            }
        };
        if let Err(e) = result {
            tracing::warn!(backend = %config.backend, error = %e, "save backend error");
        }
    }
    Ok(())
}

/// Save log records to all configured backends
pub async fn save_logs(
    configs: &[SaveConfig],
    logs: &[LogRecord],
) -> Result<()> {
    if logs.is_empty() {
        return Ok(());
    }
    for config in configs {
        let result = match config.backend.as_str() {
            "postgres" | "postgresql" => postgres::save_logs(config, logs).await,
            "elasticsearch" | "opensearch" | "elastic" => elasticsearch::save_logs(config, logs).await,
            "file" | "jsonl" => file::save_logs(config, logs).await,
            "kafka" => kafka::save_logs(config, logs).await,
            "splunkhec" | "splunk-hec" => splunk_hec::save_logs(config, logs).await,
            "loki" | "grafana-loki" => loki::save_logs(config, logs).await,
            _ => {
                tracing::debug!("Backend '{}' has no native log support, skipping", config.backend);
                continue;
            }
        };
        if let Err(e) = result {
            tracing::warn!(backend = %config.backend, error = %e, "save logs backend error");
        }
    }
    Ok(())
}

/// Parse a save URI into a SaveConfig.
///
/// Supported schemes:
///   postgresql://user:pass@host:5432/db
///   mongodb://user:pass@host:27017/db
///   mysql://user:pass@host:3306/db
///   elasticsearch://host:9200/index
///   opensearch://host:9200/index
///   s3://bucket/prefix
///   gs://bucket/prefix
///   az://container/prefix
///   file://./results.jsonl
pub fn parse_save_uri(uri: &str) -> Result<SaveConfig> {
    let (backend, url) = if uri.starts_with("postgresql://") || uri.starts_with("postgres://") {
        ("postgres".to_string(), uri.to_string())
    } else if uri.starts_with("mysql://") {
        ("mysql".to_string(), uri.to_string())
    } else if uri.starts_with("mongodb://") || uri.starts_with("mongodb+srv://") {
        ("mongodb".to_string(), uri.to_string())
    } else if uri.starts_with("elasticsearch://") {
        ("elasticsearch".to_string(), uri.to_string())
    } else if uri.starts_with("opensearch://") {
        ("opensearch".to_string(), uri.to_string())
    } else if uri.starts_with("s3://") {
        ("s3".to_string(), uri.to_string())
    } else if uri.starts_with("gs://") {
        ("gcs".to_string(), uri.to_string())
    } else if uri.starts_with("az://") {
        ("azure".to_string(), uri.to_string())
    } else if uri.starts_with("file://") {
        ("file".to_string(), uri.to_string())
    } else if uri.starts_with("kafka://") {
        ("kafka".to_string(), uri.to_string())
    } else if uri.starts_with("eventhubs://") || uri.starts_with("eventhub://") {
        ("eventhubs".to_string(), uri.to_string())
    } else if uri.starts_with("sns://") {
        ("sns".to_string(), uri.to_string())
    } else if uri.starts_with("pubsub://") {
        ("pubsub".to_string(), uri.to_string())
    } else if uri.starts_with("redis://") {
        ("redis".to_string(), uri.to_string())
    } else if uri.starts_with("splunkhec://") || uri.starts_with("splunk-hec://") {
        ("splunkhec".to_string(), uri.to_string())
    } else if uri.starts_with("influxdb://") {
        ("influxdb".to_string(), uri.to_string())
    } else {
        anyhow::bail!(
            "Unsupported save URI '{}'. Supported: postgresql://, mongodb://, mysql://, \
             elasticsearch://, opensearch://, s3://, gs://, az://, file://, kafka://, \
             eventhubs://, sns://, pubsub://, redis://, splunkhec://, influxdb://",
            uri
        );
    };

    Ok(SaveConfig {
        backend,
        url,
        origin: "kxn".to_string(),
        only_errors: false,
        tags: toml::Table::new(),
        compression: None,
    })
}

/// Resource types that produce useful numeric time-series metrics.
/// Config-style types (sysctl, sshd_config, users, services, file_permissions)
/// are saved as scan results (JSONB) but not as flat metrics.
const METRIC_RESOURCE_TYPES: &[&str] = &[
    "system_stats",
    "os_info",
    "pg_settings",
    "mysql_variables",
    "http_response",
    "db_stats",
    // Kubernetes provider time-series
    "cluster_stats",
    "node_metrics",
    "pod_metrics",
    // Kubernetes provider monitoring probes (write rows on every cycle so
    // dashboards have continuous data even when no rule fails).
    "tls_certs",
    "pod_resource",
    "k8s_jobs",
    "netpol_coverage",
    "disk_usage",
    "endpoints",
    "endpoint_slices",
    "replicasets",
    "leases",
    "csi_drivers",
    "csi_nodes",
    "volume_attachments",
    "certificate_signing_requests",
    "runtime_classes",
    "pod_restarts",
    "pod_status_phase",
    "container_oom_kills",
    // Prometheus exposition scrape (any /metrics endpoint: Traefik,
    // node-exporter, blackbox-exporter, custom apps, etc.)
    "prometheus_metrics",
];

/// Flatten gathered JSON into individual metric records for time-series
pub fn flatten_gathered(
    gathered: &Value,
    target: &str,
    provider: &str,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Vec<MetricRecord> {
    let mut metrics = Vec::new();

    let obj = match gathered.as_object() {
        Some(o) => o,
        None => return metrics,
    };

    for (resource_type, resources) in obj {
        // Only flatten resource types that produce useful time-series
        if !METRIC_RESOURCE_TYPES.contains(&resource_type.as_str()) {
            continue;
        }

        let items = match resources.as_array() {
            Some(arr) => arr.clone(),
            None => continue,
        };

        for item in &items {
            if item.get("error").is_some() {
                continue;
            }

            let item_obj = match item.as_object() {
                Some(o) => o,
                None => continue,
            };

            for (key, value) in item_obj {
                let (value_num, value_str) = extract_metric_value(value);
                metrics.push(MetricRecord {
                    target: target.to_string(),
                    provider: provider.to_string(),
                    resource_type: resource_type.clone(),
                    metric_name: key.clone(),
                    value_num,
                    value_str,
                    timestamp,
                });
            }
        }
    }

    metrics
}

fn extract_metric_value(value: &Value) -> (Option<f64>, Option<String>) {
    match value {
        Value::Number(n) => (n.as_f64(), None),
        Value::Bool(b) => (Some(if *b { 1.0 } else { 0.0 }), None),
        Value::String(s) => {
            // Try to parse as number
            if let Ok(n) = s.parse::<f64>() {
                (Some(n), Some(s.clone()))
            } else {
                (None, Some(s.clone()))
            }
        }
        _ => (None, Some(value.to_string())),
    }
}

#[cfg(test)]
mod compression_tests {
    use super::*;

    fn gunzip(data: &[u8]) -> Vec<u8> {
        use std::io::Read;
        let mut dec = flate2::read::GzDecoder::new(data);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).expect("gunzip");
        out
    }

    #[test]
    fn test_compress_none_passthrough() {
        let (out, enc) = compress_payload(b"hello".to_vec(), None);
        assert_eq!(out, b"hello");
        assert_eq!(enc, None);
    }

    #[test]
    fn test_compress_explicit_none_passthrough() {
        for s in ["none", "off", "false", "", "NONE"] {
            let (out, enc) = compress_payload(b"hello".to_vec(), Some(s));
            assert_eq!(out, b"hello", "for compression='{}'", s);
            assert_eq!(enc, None);
        }
    }

    #[test]
    fn test_compress_gzip_roundtrip() {
        // Large repetitive payload so compression is noticeable.
        let body = "kxn-scan-result-".repeat(500);
        let (out, enc) = compress_payload(body.as_bytes().to_vec(), Some("gzip"));
        assert_eq!(enc, Some("gzip"));
        assert!(
            out.len() < body.len() / 2,
            "gzip should compress repetitive payload significantly ({}→{})",
            body.len(),
            out.len()
        );
        assert_eq!(gunzip(&out), body.as_bytes());
    }

    #[test]
    fn test_compress_gzip_alias_gz() {
        let (out, enc) = compress_payload(b"x".to_vec(), Some("GZ"));
        assert_eq!(enc, Some("gzip"));
        assert_eq!(gunzip(&out), b"x");
    }

    #[test]
    fn test_compress_unknown_alg_passthrough() {
        let (out, enc) = compress_payload(b"hello".to_vec(), Some("xz"));
        assert_eq!(out, b"hello");
        assert_eq!(enc, None);
    }
}
