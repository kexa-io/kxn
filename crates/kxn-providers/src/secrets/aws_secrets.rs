use crate::aws_sigv4::{self, Credentials, SigningRequest};
use anyhow::{Context, Result};

/// Get a secret from AWS Secrets Manager via REST API with SigV4 signing.
///
/// Credentials come from `Credentials::resolve()`: a key pair in the
/// environment, an SSO session, a profile, or the role of the pod this runs in.
/// Optional: AWS_REGION (defaults to us-east-1).
pub async fn get_secret(secret_name: &str, key: &str) -> Result<String> {
    let creds = Credentials::resolve().context("AWS credentials for Secrets Manager")?;
    let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    let body = serde_json::json!({ "SecretId": secret_name }).to_string();
    let resp_json = call_secrets_manager(&creds, &region, &body).await?;
    parse_secret_value(&resp_json, secret_name, key)
}

/// Make a signed request to AWS Secrets Manager.
async fn call_secrets_manager(
    creds: &Credentials,
    region: &str,
    body: &str,
) -> Result<serde_json::Value> {
    let url = format!("https://secretsmanager.{}.amazonaws.com", region);
    let host = aws_sigv4::host_from_url(&url).map_err(|e| anyhow::anyhow!("{e}"))?;
    let content_hash = aws_sigv4::sha256_hex(body.as_bytes());

    let mut headers = std::collections::BTreeMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/x-amz-json-1.1".to_string(),
    );
    headers.insert(
        "x-amz-target".to_string(),
        "secretsmanager.GetSecretValue".to_string(),
    );
    headers.insert("x-amz-content-sha256".to_string(), content_hash.clone());

    let signed = aws_sigv4::sign(
        creds,
        &SigningRequest {
            region,
            service: "secretsmanager",
            method: "POST",
            host: &host,
            canonical_uri: "/",
            query: &[],
            headers: &headers,
            payload_sha256: &content_hash,
        },
    );

    // Only the signed map: it holds every header that was signed. Setting any
    // of them again would duplicate it — `reqwest::header` appends — and AWS
    // canonicalises the duplicate, so the signature would no longer match.
    let client = crate::http::shared_client();
    let mut request = client.post(&url).body(body.to_string());
    for (name, value) in &signed {
        request = request.header(name, value);
    }

    let resp = request
        .send()
        .await
        .context("AWS Secrets Manager request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        // The body of a Secrets Manager error names the secret but never its
        // value; it is safe to surface and is what tells an operator whether
        // the problem is the name, the permission or the region.
        anyhow::bail!("AWS Secrets Manager failed ({}): {}", status, kxn_core::truncate(&text, 400));
    }

    resp.json().await.context("invalid JSON from AWS")
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

#[cfg(test)]
mod tests {
    /// Reaches the real Secrets Manager endpoint, so it is ignored by default;
    /// run it with `cargo test -p kxn-providers -- --ignored aws_secrets` when
    /// credentials are available.
    ///
    /// It asks for a secret that does not exist. The point is *which* error
    /// comes back: `ResourceNotFoundException` means the request was
    /// authenticated and the signature accepted, while `SignatureDoesNotMatch`
    /// or an `InvalidSignature` means the signing is broken. A unit test on the
    /// published vector proves the algorithm; only this proves that what the
    /// code sends is what it signed.
    #[tokio::test]
    #[ignore = "requires AWS credentials and network"]
    async fn a_missing_secret_answers_not_found_and_not_a_signature_error() {
        let err = super::get_secret("kxn-no-such-secret-for-signing-check", "k")
            .await
            .expect_err("the secret does not exist");
        let msg = err.to_string();
        assert!(
            !msg.contains("SignatureDoesNotMatch") && !msg.contains("InvalidSignature"),
            "the signature was rejected: {msg}"
        );
        assert!(
            msg.contains("ResourceNotFoundException") || msg.contains("Secrets Manager can't find"),
            "unexpected failure: {msg}"
        );
    }
}
