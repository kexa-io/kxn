use anyhow::{Context, Result};
use chrono::Utc;

/// Get a secret from AWS Secrets Manager via REST API with SigV4 signing.
///
/// Requires env vars: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
/// Optional: AWS_REGION (defaults to us-east-1)
pub async fn get_secret(secret_name: &str, key: &str) -> Result<String> {
    let access_key =
        std::env::var("AWS_ACCESS_KEY_ID").context("AWS_ACCESS_KEY_ID not set")?;
    let secret_key =
        std::env::var("AWS_SECRET_ACCESS_KEY").context("AWS_SECRET_ACCESS_KEY not set")?;
    let region =
        std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());

    let body = serde_json::json!({"SecretId": secret_name}).to_string();
    let resp_json = call_secrets_manager(
        &access_key,
        &secret_key,
        &region,
        &body,
    )
    .await?;

    parse_secret_value(&resp_json, secret_name, key)
}

/// Make a signed request to AWS Secrets Manager.
async fn call_secrets_manager(
    access_key: &str,
    secret_key: &str,
    region: &str,
    body: &str,
) -> Result<serde_json::Value> {
    let host = format!("secretsmanager.{}.amazonaws.com", region);
    let url = format!("https://{}", host);
    let now = Utc::now();
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let content_hash = sha256_hex(body.as_bytes());
    let auth_header = build_auth_header(
        access_key,
        secret_key,
        region,
        &host,
        &date_stamp,
        &amz_date,
        &content_hash,
        body,
    );

    let client = crate::http::shared_client();
    let resp = client
        .post(&url)
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("Host", &host)
        .header("X-Amz-Target", "secretsmanager.GetSecretValue")
        .header("x-amz-content-sha256", &content_hash)
        .header("x-amz-date", &amz_date)
        .header("Authorization", &auth_header)
        .body(body.to_string())
        .send()
        .await
        .context("AWS Secrets Manager request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("AWS Secrets Manager failed ({}): {}", status, text);
    }

    resp.json().await.context("invalid JSON from AWS")
}

/// Build the SigV4 Authorization header.
fn build_auth_header(
    access_key: &str,
    secret_key: &str,
    region: &str,
    host: &str,
    date_stamp: &str,
    amz_date: &str,
    content_hash: &str,
    body: &str,
) -> String {
    let signed_headers =
        "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target";
    let canonical_request = format!(
        "POST\n/\n\ncontent-type:application/x-amz-json-1.1\nhost:{}\n\
         x-amz-content-sha256:{}\nx-amz-date:{}\n\
         x-amz-target:secretsmanager.GetSecretValue\n\n{}\n{}",
        host, content_hash, amz_date, signed_headers,
        sha256_hex(body.as_bytes())
    );

    let scope = format!(
        "{}/{}/secretsmanager/aws4_request",
        date_stamp, region
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        scope,
        sha256_hex(canonical_request.as_bytes())
    );

    let signing_key =
        aws4_signing_key(secret_key, date_stamp, region, "secretsmanager");
    let signature = hmac_sha256_hex(&signing_key, string_to_sign.as_bytes());

    format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key, scope, signed_headers, signature
    )
}

/// Extract the requested key from the SecretString JSON.
fn parse_secret_value(
    resp: &serde_json::Value,
    secret_name: &str,
    key: &str,
) -> Result<String> {
    let secret_string = resp["SecretString"]
        .as_str()
        .context("no SecretString in AWS response")?;

    let secret_data: serde_json::Value = serde_json::from_str(secret_string)?;
    secret_data[key]
        .as_str()
        .map(|s| s.to_string())
        .with_context(|| {
            format!("key '{}' not found in secret '{}'", key, secret_name)
        })
}

// ── SigV4 helpers ──────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    hex::encode(hmac_sha256(key, data))
}

fn aws4_signing_key(
    secret: &str,
    date: &str,
    region: &str,
    service: &str,
) -> Vec<u8> {
    let k_date =
        hmac_sha256(format!("AWS4{}", secret).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}
