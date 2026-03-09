use anyhow::{Context, Result};
use kxn_rules::SaveConfig;

use super::{MetricRecord, ScanRecord};

/// Save scan results to AWS SNS topic.
///
/// URL format: sns://region/topic-arn
/// Auth: AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY env vars
pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let (region, topic_arn) = parse_url(&config.url)?;
    let access_key = std::env::var("AWS_ACCESS_KEY_ID")
        .context("AWS_ACCESS_KEY_ID required for SNS")?;
    let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
        .context("AWS_SECRET_ACCESS_KEY required for SNS")?;
    let client = reqwest::Client::new();

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
    let now = chrono::Utc::now();

    // AWS Signature V4 for SNS Publish
    let body = format!(
        "Action=Publish&TopicArn={}&Message={}&Version=2010-03-31",
        urlencoding::encode(&topic_arn),
        urlencoding::encode(&message),
    );

    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let credential_scope = format!("{}/{}/sns/aws4_request", date_stamp, region);

    let string_to_sign = build_string_to_sign(
        &amz_date, &credential_scope, &body,
    );
    let signature = sign_v4(&secret_key, &date_stamp, &region, "sns", &string_to_sign);

    let auth_header = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders=content-type;host;x-amz-date, Signature={}",
        access_key, credential_scope, signature
    );

    client
        .post(&endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("X-Amz-Date", &amz_date)
        .header("Host", format!("sns.{}.amazonaws.com", region))
        .header("Authorization", &auth_header)
        .body(body)
        .send()
        .await?
        .error_for_status()
        .context("AWS SNS error")?;

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

fn build_string_to_sign(amz_date: &str, scope: &str, body: &str) -> String {
    use sha2::{Digest, Sha256};
    let payload_hash = hex::encode(Sha256::digest(body.as_bytes()));
    let canonical = format!(
        "POST\n/\n\ncontent-type:application/x-www-form-urlencoded\nhost:sns.amazonaws.com\nx-amz-date:{}\n\ncontent-type;host;x-amz-date\n{}",
        amz_date, payload_hash
    );
    let canonical_hash = hex::encode(Sha256::digest(canonical.as_bytes()));
    format!("AWS4-HMAC-SHA256\n{}\n{}\n{}", amz_date, scope, canonical_hash)
}

fn sign_v4(secret: &str, date: &str, region: &str, service: &str, string_to_sign: &str) -> String {
    let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
