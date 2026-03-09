use anyhow::{Context, Result};
use kxn_rules::SaveConfig;

use super::{MetricRecord, ScanRecord};

/// Save scan results + metrics to InfluxDB v2.
///
/// URL format: influxdb://host:8086/bucket
/// Auth: INFLUXDB_TOKEN and INFLUXDB_ORG env vars
pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let (base_url, bucket) = parse_url(&config.url)?;
    let token = std::env::var("INFLUXDB_TOKEN")
        .context("INFLUXDB_TOKEN env var required for InfluxDB")?;
    let org = std::env::var("INFLUXDB_ORG")
        .context("INFLUXDB_ORG env var required for InfluxDB")?;
    let client = reqwest::Client::new();

    let mut lines = String::new();

    // Scan results as line protocol
    for r in records {
        if config.only_errors && !r.error {
            continue;
        }
        let ts_ns = r.timestamp.timestamp_nanos_opt().unwrap_or(0);
        // kxn_scan,provider=ssh,target=host,rule=rule-name level=2i,error=true
        lines.push_str(&format!(
            "kxn_scan,provider={},target={},rule={} level={}i,error={} {}\n",
            escape_tag(&r.provider),
            escape_tag(&r.target),
            escape_tag(&r.rule_name),
            r.level,
            r.error,
            ts_ns,
        ));
    }

    // Metrics as line protocol
    for m in metrics {
        let ts_ns = m.timestamp.timestamp_nanos_opt().unwrap_or(0);
        if let Some(val) = m.value_num {
            lines.push_str(&format!(
                "kxn_metric,provider={},target={},resource={} {}={} {}\n",
                escape_tag(&m.provider),
                escape_tag(&m.target),
                escape_tag(&m.resource_type),
                escape_field(&m.metric_name),
                val,
                ts_ns,
            ));
        }
    }

    if lines.is_empty() {
        return Ok(());
    }

    let url = format!(
        "{}/api/v2/write?org={}&bucket={}&precision=ns",
        base_url,
        urlencoding::encode(&org),
        urlencoding::encode(&bucket),
    );

    client
        .post(&url)
        .header("Authorization", format!("Token {}", token))
        .header("Content-Type", "text/plain")
        .body(lines)
        .send()
        .await?
        .error_for_status()
        .context("InfluxDB write error")?;

    Ok(())
}

fn parse_url(url: &str) -> Result<(String, String)> {
    let rest = url
        .strip_prefix("influxdb://")
        .context("Invalid InfluxDB URI")?;
    let (host_port, bucket) = rest
        .split_once('/')
        .unwrap_or((rest, "kxn"));
    let base = format!("http://{}", host_port);
    let bucket = if bucket.is_empty() { "kxn" } else { bucket };
    Ok((base, bucket.to_string()))
}

/// Escape tag values for InfluxDB line protocol.
fn escape_tag(s: &str) -> String {
    s.replace(' ', "\\ ")
        .replace(',', "\\,")
        .replace('=', "\\=")
}

/// Escape field keys for InfluxDB line protocol.
fn escape_field(s: &str) -> String {
    s.replace(' ', "_").replace(',', "_").replace('=', "_")
}
