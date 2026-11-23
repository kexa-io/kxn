use anyhow::{Context, Result};

use crate::commands::watch::Violation;

/// Parse a Twilio SMS URI.
///
/// Format: `sms://accountSid:authToken@twilio/+1234567890?from=+15550001111`
/// or `…?messaging_service=MG…`. Twilio needs a sender it owns; the env vars
/// `TWILIO_FROM` and `TWILIO_MESSAGING_SERVICE_SID` are the fallback.
#[derive(Debug)]
struct TwilioConfig {
    account_sid: String,
    auth_token: String,
    to_number: String,
    sender: Sender,
}

#[derive(Debug, PartialEq)]
enum Sender {
    From(String),
    MessagingService(String),
}

/// A `+` in a query string decodes to a space: `?from=+1555…` arrives as
/// ` 1555…`. Phone numbers never contain spaces, so put the `+` back.
fn phone(value: &str) -> String {
    let v = value.trim();
    if value.starts_with(' ') && !v.is_empty() {
        format!("+{}", v)
    } else {
        v.to_string()
    }
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

    let query = |key: &str| {
        parsed
            .query_pairs()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.to_string())
            .filter(|v| !v.trim().is_empty())
    };
    // The sender used to be "+1" followed by the first ten characters of the
    // account SID, which is not a Twilio number: every send was rejected.
    let sender = if let Some(from) = query("from").or_else(|| std::env::var("TWILIO_FROM").ok()) {
        Sender::From(phone(&from))
    } else if let Some(ms) = query("messaging_service")
        .or_else(|| std::env::var("TWILIO_MESSAGING_SERVICE_SID").ok())
    {
        Sender::MessagingService(ms.trim().to_string())
    } else {
        anyhow::bail!(
            "SMS URI needs a sender Twilio owns: sms://sid:token@twilio/+123?from=%2B1555… \
             or ?messaging_service=MG… (or TWILIO_FROM / TWILIO_MESSAGING_SERVICE_SID)"
        );
    };

    Ok(TwilioConfig {
        account_sid,
        auth_token,
        to_number,
        sender,
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

    let sender = match &cfg.sender {
        Sender::From(n) => ("From", n),
        Sender::MessagingService(s) => ("MessagingServiceSid", s),
    };

    client
        .post(&api_url)
        .basic_auth(&cfg.account_sid, Some(&cfg.auth_token))
        .form(&[("To", &cfg.to_number), (sender.0, sender.1), ("Body", &body)])
        .send()
        .await?
        .error_for_status()
        .context("Twilio API error")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_from_query_keeps_the_plus() {
        let c = parse_sms_uri("sms://AC123:tok@twilio/+33600000000?from=+15550001111").unwrap();
        assert_eq!(c.sender, Sender::From("+15550001111".into()));
        let c = parse_sms_uri("sms://AC123:tok@twilio/+33600000000?from=%2B15550001111").unwrap();
        assert_eq!(c.sender, Sender::From("+15550001111".into()));
    }

    #[test]
    fn messaging_service_sender() {
        let c = parse_sms_uri("sms://AC123:tok@twilio/+33600000000?messaging_service=MG42").unwrap();
        assert_eq!(c.sender, Sender::MessagingService("MG42".into()));
    }

    #[test]
    fn missing_sender_is_an_error() {
        if std::env::var("TWILIO_FROM").is_err() && std::env::var("TWILIO_MESSAGING_SERVICE_SID").is_err() {
            let err = parse_sms_uri("sms://AC123:tok@twilio/+33600000000").unwrap_err();
            assert!(err.to_string().contains("sender"), "{err}");
        }
    }
}
