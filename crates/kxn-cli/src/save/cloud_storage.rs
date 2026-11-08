use anyhow::{Context, Result};
use kxn_providers::aws_sigv4::{self, Credentials, SigningRequest};
use chrono::Utc;
use kxn_rules::SaveConfig;
use serde_json::json;

use super::{MetricRecord, ScanRecord};

/// Save scan results + metrics as JSON files to cloud storage (S3, GCS, Azure Blob).
///
/// URL format determines the backend:
///   s3://bucket/prefix          — AWS S3 (uses AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION)
///   gs://bucket/prefix          — Google Cloud Storage (uses GOOGLE_APPLICATION_CREDENTIALS or gcloud auth)
///   az://container/prefix       — Azure Blob Storage (uses AZURE_STORAGE_ACCOUNT, AZURE_STORAGE_KEY or AZURE_STORAGE_SAS)
///   https://account.blob.core.windows.net/container/prefix — Azure Blob (explicit)
pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let url = &config.url;
    let now = Utc::now();
    let date_prefix = now.format("%Y/%m/%d/%H%M%S").to_string();

    let scans_json = serde_json::to_vec_pretty(&json!({
        "origin": config.origin,
        "timestamp": now.to_rfc3339(),
        "tags": config.tags,
        "scans": records,
    }))?;

    let metrics_json = serde_json::to_vec_pretty(&json!({
        "origin": config.origin,
        "timestamp": now.to_rfc3339(),
        "tags": config.tags,
        "metrics": metrics,
    }))?;

    if url.starts_with("s3://") {
        let (bucket, prefix) = parse_s3_url(url)?;
        upload_s3(&bucket, &format!("{}/{}/scans.json", prefix, date_prefix), &scans_json).await?;
        if !metrics.is_empty() {
            upload_s3(&bucket, &format!("{}/{}/metrics.json", prefix, date_prefix), &metrics_json).await?;
        }
    } else if url.starts_with("gs://") {
        let (bucket, prefix) = parse_gs_url(url)?;
        upload_gcs(&bucket, &format!("{}/{}/scans.json", prefix, date_prefix), &scans_json).await?;
        if !metrics.is_empty() {
            upload_gcs(&bucket, &format!("{}/{}/metrics.json", prefix, date_prefix), &metrics_json).await?;
        }
    } else if url.starts_with("az://") || url.contains(".blob.core.windows.net") {
        let (account, container, prefix) = parse_azure_url(url)?;
        upload_azure(&account, &container, &format!("{}/{}/scans.json", prefix, date_prefix), &scans_json).await?;
        if !metrics.is_empty() {
            upload_azure(&account, &container, &format!("{}/{}/metrics.json", prefix, date_prefix), &metrics_json).await?;
        }
    } else {
        anyhow::bail!("Unknown cloud storage URL scheme: {}", url);
    }

    Ok(())
}

// ── S3 ──────────────────────────────────────────────────────────────

fn parse_s3_url(url: &str) -> Result<(String, String)> {
    let path = url.strip_prefix("s3://").context("invalid s3:// URL")?;
    let (bucket, prefix) = path.split_once('/').unwrap_or((path, "kxn"));
    Ok((bucket.to_string(), prefix.to_string()))
}

async fn upload_s3(bucket: &str, key: &str, body: &[u8]) -> Result<()> {
    let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".into());
    let creds = Credentials::resolve().context("AWS credentials for S3")?;

    // Support custom S3-compatible endpoints (RustFS, MinIO, etc.), which are
    // path-style: the bucket is part of the path, not of the host.
    let custom_endpoint = std::env::var("AWS_ENDPOINT_URL").ok();
    let (url, canonical_uri) = match &custom_endpoint {
        Some(endpoint) => {
            let endpoint = endpoint.trim_end_matches('/');
            url::Url::parse(endpoint).context("invalid AWS_ENDPOINT_URL")?;
            (
                format!("{}/{}/{}", endpoint, bucket, key),
                format!("/{}/{}", bucket, aws_sigv4::encode_uri_path(key)),
            )
        }
        None => (
            format!("https://{}.s3.{}.amazonaws.com/{}", bucket, region, key),
            format!("/{}", aws_sigv4::encode_uri_path(key)),
        ),
    };

    // From the URL that will be called, so a custom endpoint's port is part of
    // the signed host exactly as it is part of the sent one.
    let host = aws_sigv4::host_from_url(&url).map_err(|e| anyhow::anyhow!("{e}"))?;
    let content_hash = aws_sigv4::sha256_hex(body);

    let mut headers = std::collections::BTreeMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    // S3 requires this header, and requires it signed.
    headers.insert("x-amz-content-sha256".to_string(), content_hash.clone());

    let signed = aws_sigv4::sign(
        &creds,
        &SigningRequest {
            region: &region,
            service: "s3",
            method: "PUT",
            host: &host,
            canonical_uri: &canonical_uri,
            query: &[],
            headers: &headers,
            payload_sha256: &content_hash,
        },
    );

    // The signed map already holds every header to send. Setting any of them
    // again would duplicate it — `reqwest::header` appends — and AWS would
    // canonicalise the duplicate and reject the signature.
    let client = crate::alerts::shared_client();
    let mut request = client.put(&url).body(body.to_vec());
    for (name, value) in &signed {
        request = request.header(name, value);
    }

    let resp = request.send().await.context("S3 upload failed")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("S3 upload failed ({}): {}", status, kxn_core::truncate(&text, 400));
    }

    tracing::info!("Uploaded to s3://{}/{}", bucket, key);
    Ok(())
}





// ── GCS ─────────────────────────────────────────────────────────────

fn parse_gs_url(url: &str) -> Result<(String, String)> {
    let path = url.strip_prefix("gs://").context("invalid gs:// URL")?;
    let (bucket, prefix) = path.split_once('/').unwrap_or((path, "kxn"));
    Ok((bucket.to_string(), prefix.to_string()))
}

async fn upload_gcs(bucket: &str, object: &str, body: &[u8]) -> Result<()> {
    let auth_manager = gcp_auth::provider().await.context("GCP auth failed")?;
    let token = auth_manager
        .token(&["https://www.googleapis.com/auth/devstorage.read_write"])
        .await
        .context("GCP token failed")?;

    let url = format!(
        "https://storage.googleapis.com/upload/storage/v1/b/{}/o?uploadType=media&name={}",
        bucket,
        urlencoding::encode(object)
    );

    let client = crate::alerts::shared_client();
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .bearer_auth(token.as_str())
        .body(body.to_vec())
        .send()
        .await
        .context("GCS upload failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("GCS upload failed ({}): {}", status, text);
    }

    tracing::info!("Uploaded to gs://{}/{}", bucket, object);
    Ok(())
}

// ── Azure Blob ──────────────────────────────────────────────────────

fn parse_azure_url(url: &str) -> Result<(String, String, String)> {
    if let Some(path) = url.strip_prefix("az://") {
        // az://container/prefix — account from env
        let account = std::env::var("AZURE_STORAGE_ACCOUNT")
            .context("AZURE_STORAGE_ACCOUNT not set for az:// URL")?;
        let (container, prefix) = path.split_once('/').unwrap_or((path, "kxn"));
        Ok((account, container.to_string(), prefix.to_string()))
    } else {
        // https://account.blob.core.windows.net/container/prefix
        let parsed = url::Url::parse(url).context("invalid Azure URL")?;
        let host = parsed.host_str().context("no host in Azure URL")?;
        let account = host
            .strip_suffix(".blob.core.windows.net")
            .context("expected *.blob.core.windows.net")?
            .to_string();
        let mut segments: Vec<&str> = parsed.path_segments().map(|s| s.collect()).unwrap_or_default();
        let container = segments.first().context("no container in URL")?.to_string();
        segments.remove(0);
        let prefix = if segments.is_empty() { "kxn".to_string() } else { segments.join("/") };
        Ok((account, container, prefix))
    }
}

async fn upload_azure(account: &str, container: &str, blob: &str, body: &[u8]) -> Result<()> {
    // Support SAS token or shared key
    let sas = std::env::var("AZURE_STORAGE_SAS").ok();
    let shared_key = std::env::var("AZURE_STORAGE_KEY").ok();

    let base_url = format!(
        "https://{}.blob.core.windows.net/{}/{}",
        account, container, blob
    );

    let url = if let Some(sas) = &sas {
        let separator = if sas.starts_with('?') { "" } else { "?" };
        format!("{}{}{}", base_url, separator, sas)
    } else {
        base_url.clone()
    };

    let client = crate::alerts::shared_client();
    let mut req = client
        .put(&url)
        .header("Content-Type", "application/json")
        .header("x-ms-blob-type", "BlockBlob")
        .header("x-ms-version", "2024-11-04");

    if sas.is_none() {
        if let Some(key) = &shared_key {
            // Simplified shared key auth
            let now = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
            let string_to_sign = format!(
                "PUT\n\n\n{}\n\napplication/json\n\n\n\n\n\n\nx-ms-blob-type:BlockBlob\nx-ms-date:{}\nx-ms-version:2024-11-04\n/{}/{}/{}",
                body.len(), now, account, container, blob
            );
            let decoded_key = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                key,
            ).context("invalid Azure storage key")?;
            let signature = {
                use sha2::Sha256;
                use hmac::{Hmac, Mac};
                type HmacSha256 = Hmac<Sha256>;
                let mut mac = HmacSha256::new_from_slice(&decoded_key).expect("HMAC key");
                mac.update(string_to_sign.as_bytes());
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, mac.finalize().into_bytes())
            };
            let auth = format!("SharedKey {}:{}", account, signature);
            req = req
                .header("x-ms-date", &now)
                .header("Authorization", &auth);
        } else {
            anyhow::bail!("Azure Blob: set AZURE_STORAGE_SAS or AZURE_STORAGE_KEY");
        }
    }

    let resp = req.body(body.to_vec()).send().await.context("Azure upload failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Azure Blob upload failed ({}): {}", status, text);
    }

    tracing::info!("Uploaded to az://{}/{}", container, blob);
    Ok(())
}
