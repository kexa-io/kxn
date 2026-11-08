use anyhow::{Context, Result};
use kxn_providers::aws_sigv4::{self, Credentials, SigningRequest};
use kxn_rules::SaveConfig;

use super::{MetricRecord, ScanRecord};

/// Save scan results to AWS SNS topic.
///
/// URL format: sns://region/topic-arn
///
/// Credentials come from `Credentials::resolve()`, so any source the AWS CLI
/// supports works — a key pair in the environment, an SSO session, a profile,
/// IRSA inside a cluster.
pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let (region, topic_arn) = parse_url(&config.url)?;
    let creds = Credentials::resolve().context("AWS credentials for SNS")?;
    let client = crate::alerts::shared_client();

    let mut events: Vec<serde_json::Value> = Vec::new();

    for r in records {
        if config.only_errors && !r.error {
            continue;
        }
        events.push(serde_json::json!({
            "type": "scan",
            "target": r.target,
            "provider": r.provider,
            "rule_name": r.rule_name,
            "level": r.level,
            "error": r.error,
            "batch_id": r.batch_id,
            "timestamp": r.timestamp.to_rfc3339(),
        }));
    }

    for m in metrics {
        events.push(serde_json::json!({
            "type": "metric",
            "target": m.target,
            "metric_name": m.metric_name,
            "value_num": m.value_num,
            "timestamp": m.timestamp.to_rfc3339(),
        }));
    }

    if events.is_empty() {
        return Ok(());
    }

    let message = serde_json::to_string(&events)?;
    let endpoint = format!("https://sns.{}.amazonaws.com", region);

    let body = format!(
        "Action=Publish&TopicArn={}&Message={}&Version=2010-03-31",
        urlencoding::encode(&topic_arn),
        urlencoding::encode(&message),
    );

    // The host is taken from the URL that will actually be called. The copy
    // this replaced signed the literal `sns.amazonaws.com` while sending the
    // regional Host header, so the signature could never match and every
    // publish was a 403.
    let host = aws_sigv4::host_from_url(&endpoint).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut headers = std::collections::BTreeMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    );

    let signed = aws_sigv4::sign(
        &creds,
        &SigningRequest {
            region: &region,
            service: "sns",
            method: "POST",
            host: &host,
            canonical_uri: "/",
            query: &[],
            headers: &headers,
            payload_sha256: &aws_sigv4::sha256_hex(body.as_bytes()),
        },
    );

    // Only the signed map: it already carries every header that was signed,
    // `content-type` included. Setting those again would duplicate them —
    // `reqwest::header` appends rather than replaces — and AWS would then
    // canonicalise `content-type: x, x` and reject the signature.
    let mut request = client.post(&endpoint).body(body);
    for (name, value) in &signed {
        request = request.header(name, value);
    }
    let response = request.send().await?;
    let status = response.status();
    if !status.is_success() {
        let detail = response.text().await.unwrap_or_default();
        anyhow::bail!("AWS SNS error ({status}): {}", kxn_core::truncate(&detail, 400));
    }

    Ok(())
}

fn parse_url(url: &str) -> Result<(String, String)> {
    // sns://us-east-1/arn:aws:sns:us-east-1:123:topic
    let rest = url.strip_prefix("sns://").context("Invalid SNS URI")?;
    let (region, arn) = rest
        .split_once('/')
        .context("SNS URI must be: sns://region/topic-arn")?;
    Ok((region.to_string(), arn.to_string()))
}



