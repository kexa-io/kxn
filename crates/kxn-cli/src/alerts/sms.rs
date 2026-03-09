use anyhow::{Context, Result};

use crate::commands::watch::Violation;

/// Parse a Twilio SMS URI.
///
/// Format: `sms://accountSid:authToken@twilio/+1234567890`
struct TwilioConfig {
    account_sid: String,
    auth_token: String,
    to_number: String,
}

fn parse_sms_uri(url: &str) -> Result<TwilioConfig> {
    let parsed = url::Url::parse(url).context("Invalid SMS URI")?;
    let account_sid = urlencoding::decode(parsed.username())
        .context("Invalid account SID encoding")?
        .to_string();
    let auth_token = urlencoding::decode(parsed.password().unwrap_or(""))
        .context("Invalid auth token encoding")?
        .to_string();
    let to_number = parsed.path().trim_start_matches('/').to_string();

    if account_sid.is_empty() || auth_token.is_empty() {
        anyhow::bail!("SMS URI must include accountSid:authToken");
    }
    if to_number.is_empty() {
        anyhow::bail!("SMS URI must include phone number in path: sms://sid:token@twilio/+123");
    }

    Ok(TwilioConfig {
        account_sid,
        auth_token,
        to_number,
    })
}

/// Build a concise SMS body (max 1600 chars for Twilio).
fn build_body(violations: &[Violation], target: &str) -> String {
    if violations.is_empty() {
        return format!("kxn | {} | ALL PASSED", target);
    }

    let header = format!("kxn | {} | {} violation(s): ", target, violations.len());
    let mut body = header;

    for v in violations {
        let entry = format!("{} ({}), ", v.rule, v.level_label);
        if body.len() + entry.len() > 1580 {
            body.push_str("...");
            break;
        }
        body.push_str(&entry);
    }

    // Trim trailing ", "
    if body.ends_with(", ") {
        body.truncate(body.len() - 2);
    }

    body
}

/// Send violations as SMS via the Twilio API.
pub async fn send(
    client: &reqwest::Client,
    url: &str,
    violations: &[Violation],
    target: &str,
) -> Result<()> {
    let cfg = parse_sms_uri(url)?;
    let body = build_body(violations, target);

    let api_url = format!(
        "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
        cfg.account_sid
    );

    // Twilio requires a From number; use the account's default
    let from = format!("+1{}", &cfg.account_sid[..10.min(cfg.account_sid.len())]);

    client
        .post(&api_url)
        .basic_auth(&cfg.account_sid, Some(&cfg.auth_token))
        .form(&[("To", &cfg.to_number), ("From", &from), ("Body", &body)])
        .send()
        .await?
        .error_for_status()
        .context("Twilio API error")?;

    Ok(())
}
