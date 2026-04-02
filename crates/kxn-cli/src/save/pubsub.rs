use anyhow::{Context, Result};
use kxn_rules::SaveConfig;

use super::{MetricRecord, ScanRecord};

/// Save scan results to Google Cloud Pub/Sub.
///
/// URL format: pubsub://project-id/topic-name
/// Auth: GOOGLE_APPLICATION_CREDENTIALS or gcloud default credentials
pub async fn save(
    config: &SaveConfig,
    records: &[ScanRecord],
    metrics: &[MetricRecord],
) -> Result<()> {
    let (project, topic) = parse_url(&config.url)?;
    let token = get_access_token().await?;
    let client = crate::alerts::shared_client();

    let mut messages = Vec::new();

    for r in records {
        if config.only_errors && !r.error {
            continue;
        }
        let data = serde_json::json!({
            "type": "scan",
            "target": r.target,
            "provider": r.provider,
            "rule_name": r.rule_name,
            "level": r.level,
            "level_label": r.level_label,
            "error": r.error,
            "messages": r.messages,
            "compliance": r.compliance,
            "batch_id": r.batch_id,
            "timestamp": r.timestamp.to_rfc3339(),
        });
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_string(&data)?,
        );
        messages.push(serde_json::json!({
            "data": encoded,
            "attributes": {
                "source": "kxn",
                "type": "scan",
                "provider": r.provider,
            }
        }));
    }

    for m in metrics {
        let data = serde_json::json!({
            "type": "metric",
            "target": m.target,
            "metric_name": m.metric_name,
            "value_num": m.value_num,
            "timestamp": m.timestamp.to_rfc3339(),
        });
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_string(&data)?,
        );
        messages.push(serde_json::json!({
            "data": encoded,
            "attributes": {
                "source": "kxn",
                "type": "metric",
            }
        }));
    }

    if messages.is_empty() {
        return Ok(());
    }

    let url = format!(
        "https://pubsub.googleapis.com/v1/projects/{}/topics/{}:publish",
        project, topic
    );

    client
        .post(&url)
        .bearer_auth(&token)
        .json(&serde_json::json!({ "messages": messages }))
        .send()
        .await?
        .error_for_status()
        .context("Google Pub/Sub error")?;

    Ok(())
}

fn parse_url(url: &str) -> Result<(String, String)> {
    let rest = url
        .strip_prefix("pubsub://")
        .context("Invalid Pub/Sub URI")?;
    let (project, topic) = rest
        .split_once('/')
        .context("Pub/Sub URI must be: pubsub://project-id/topic")?;
    if project.is_empty() || topic.is_empty() {
        anyhow::bail!("Pub/Sub URI must include project and topic");
    }
    Ok((project.to_string(), topic.to_string()))
}

async fn get_access_token() -> Result<String> {
    let provider = gcp_auth::provider()
        .await
        .context("GCP auth failed — set GOOGLE_APPLICATION_CREDENTIALS")?;
    let token = provider
        .token(&["https://www.googleapis.com/auth/pubsub"])
        .await
        .context("Failed to get GCP token")?;
    Ok(token.as_str().to_string())
}
