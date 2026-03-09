pub mod discord;
pub mod email;
pub mod jira;
pub mod kafka;
pub mod linear;
pub mod opsgenie;
pub mod pagerduty;
pub mod servicenow;
pub mod slack;
pub mod sms;
pub mod splunk;
pub mod teams;
pub mod zendesk;

use anyhow::Result;

use crate::commands::watch::Violation;

/// Parse an alert URI into (type, url/config).
///
/// Supported schemes:
///   slack://hooks.slack.com/...          -> Slack webhook
///   discord://discord.com/...           -> Discord webhook
///   teams://outlook.webhook.office.com  -> Teams webhook
///   email://user:pass@smtp:587/to@x.com -> SMTP email
///   sms://sid:token@twilio/+123         -> Twilio SMS
///   jira://user:token@host/PROJECT      -> Jira issue
///   pagerduty://routing-key             -> PagerDuty Events v2
///   opsgenie://api-key                  -> OpsGenie alert
///   servicenow://user:pass@instance     -> ServiceNow incident
///   linear://api-key/TEAM               -> Linear issue
///   http:// | https://                  -> generic webhook
pub fn parse_alert_uri(uri: &str) -> Result<(String, String)> {
    if let Some(rest) = uri.strip_prefix("slack://") {
        Ok(("slack".to_string(), format!("https://{}", rest)))
    } else if let Some(rest) = uri.strip_prefix("discord://") {
        Ok(("discord".to_string(), format!("https://{}", rest)))
    } else if let Some(rest) = uri.strip_prefix("teams://") {
        Ok(("teams".to_string(), format!("https://{}", rest)))
    } else if uri.starts_with("email://") {
        Ok(("email".to_string(), uri.to_string()))
    } else if uri.starts_with("sms://") {
        Ok(("sms".to_string(), uri.to_string()))
    } else if uri.starts_with("jira://") {
        Ok(("jira".to_string(), uri.to_string()))
    } else if uri.starts_with("pagerduty://") {
        Ok(("pagerduty".to_string(), uri.to_string()))
    } else if uri.starts_with("opsgenie://") {
        Ok(("opsgenie".to_string(), uri.to_string()))
    } else if uri.starts_with("servicenow://") {
        Ok(("servicenow".to_string(), uri.to_string()))
    } else if uri.starts_with("linear://") {
        Ok(("linear".to_string(), uri.to_string()))
    } else if uri.starts_with("splunk://") {
        Ok(("splunk".to_string(), uri.to_string()))
    } else if uri.starts_with("zendesk://") {
        Ok(("zendesk".to_string(), uri.to_string()))
    } else if uri.starts_with("kafka://") {
        Ok(("kafka".to_string(), uri.to_string()))
    } else if uri.starts_with("http://") || uri.starts_with("https://") {
        Ok(("webhook".to_string(), uri.to_string()))
    } else {
        anyhow::bail!(
            "Unsupported alert URI '{}'. Supported: slack://, discord://, teams://, \
             email://, sms://, jira://, pagerduty://, opsgenie://, servicenow://, \
             linear://, splunk://, zendesk://, kafka://, http(s)://",
            uri
        );
    }
}

/// Send alerts to all configured destinations.
pub async fn send_alerts(
    alerts: &[(String, String)],
    violations: &[Violation],
    target: &str,
) {
    let client = reqwest::Client::new();

    for (alert_type, url) in alerts {
        let result = match alert_type.as_str() {
            "slack" => slack::send(&client, url, violations, target).await,
            "discord" => discord::send(&client, url, violations, target).await,
            "teams" => teams::send(&client, url, violations, target).await,
            "email" => email::send(&client, url, violations, target).await,
            "sms" => sms::send(&client, url, violations, target).await,
            "jira" => jira::send(&client, url, violations, target).await,
            "pagerduty" => pagerduty::send(&client, url, violations, target).await,
            "opsgenie" => opsgenie::send(&client, url, violations, target).await,
            "servicenow" => servicenow::send(&client, url, violations, target).await,
            "linear" => linear::send(&client, url, violations, target).await,
            "splunk" => splunk::send(&client, url, violations, target).await,
            "zendesk" => zendesk::send(&client, url, violations, target).await,
            "kafka" => kafka::send(&client, url, violations, target).await,
            _ => send_generic_webhook(&client, url, violations, target).await,
        };

        if let Err(e) = result {
            eprintln!("Alert error ({}): {}", alert_type, e);
        }
    }
}

/// Send a generic webhook with the standard JSON payload.
async fn send_generic_webhook(
    client: &reqwest::Client,
    url: &str,
    violations: &[Violation],
    target: &str,
) -> Result<()> {
    let payload = crate::commands::watch::build_generic_alert_payload(violations, target);
    client
        .post(url)
        .json(&payload)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}
