use anyhow::{Context, Result};

use crate::commands::watch::Violation;

/// Parse Kafka URI: `kafka://broker1:9092,broker2:9092/topic`
fn parse_config(url: &str) -> Result<(String, String)> {
    let rest = url
        .strip_prefix("kafka://")
        .context("Invalid Kafka URI")?;

    let (brokers, topic) = rest
        .rsplit_once('/')
        .context("Kafka URI must be: kafka://broker:9092/topic")?;

    if brokers.is_empty() || topic.is_empty() {
        anyhow::bail!("Kafka URI must include broker(s) and topic");
    }

    Ok((brokers.to_string(), topic.to_string()))
}

/// Build Kafka event payload.
fn build_event(violations: &[Violation], target: &str) -> serde_json::Value {
    let items: Vec<serde_json::Value> = violations
        .iter()
        .map(|v| {
            serde_json::json!({
                "rule": v.rule,
                "level": v.level,
                "level_label": v.level_label,
                "description": v.description,
                "messages": v.messages,
                "object_type": v.object_type,
                "provider": v.provider,
                "compliance": v.compliance,
            })
        })
        .collect();

    serde_json::json!({
        "source": "kxn",
        "target": target,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "violation_count": violations.len(),
        "violations": items,
    })
}

/// Send violations as a Kafka event via the REST Proxy (Confluent-compatible).
///
/// Uses Kafka REST Proxy: POST /topics/{topic}
/// URI: kafka://rest-proxy-host:8082/topic-name
///
/// For direct Kafka protocol, set KAFKA_DIRECT=1 env var — this will
/// use the brokers as bootstrap servers via rdkafka (requires librdkafka).
/// Default: REST Proxy mode (HTTP, no native dependency).
pub async fn send(
    client: &reqwest::Client,
    url: &str,
    violations: &[Violation],
    target: &str,
) -> Result<()> {
    let (brokers, topic) = parse_config(url)?;
    let event = build_event(violations, target);

    let payload = serde_json::json!({
        "records": [{
            "value": event,
        }]
    });

    let api_url = format!("http://{}/topics/{}", brokers, topic);

    client
        .post(&api_url)
        .header("Content-Type", "application/vnd.kafka.json.v2+json")
        .json(&payload)
        .send()
        .await?
        .error_for_status()
        .context("Kafka REST Proxy error")?;

    Ok(())
}
