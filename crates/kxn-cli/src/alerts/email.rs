use anyhow::{Context, Result};

use crate::commands::watch::Violation;

/// Parse an email alert URI into SMTP config.
///
/// Format: `email://user:pass@smtp.host:port/recipient@email.com`
struct EmailConfig {
    smtp_host: String,
    smtp_port: u16,
    username: String,
    password: String,
    recipient: String,
}

fn parse_email_uri(url: &str) -> Result<EmailConfig> {
    let parsed = url::Url::parse(url).context("Invalid email URI")?;
    let host = parsed
        .host_str()
        .context("Missing SMTP host")?
        .to_string();
    let port = parsed.port().unwrap_or(587);
    let username = urlencoding::decode(parsed.username())
        .context("Invalid username encoding")?
        .to_string();
    let password = urlencoding::decode(parsed.password().unwrap_or(""))
        .context("Invalid password encoding")?
        .to_string();
    let recipient = parsed.path().trim_start_matches('/').to_string();

    if username.is_empty() {
        anyhow::bail!("Email URI must include user: email://user:pass@host:port/to@email.com");
    }
    if recipient.is_empty() || !recipient.contains('@') {
        anyhow::bail!("Email URI must include recipient in path: email://...host/to@email.com");
    }

    Ok(EmailConfig {
        smtp_host: host,
        smtp_port: port,
        username,
        password,
        recipient,
    })
}

/// Build an HTML email body with a violations table.
fn build_html(violations: &[Violation], target: &str) -> String {
    if violations.is_empty() {
        return format!(
            "<h2>kxn | {} | ALL PASSED</h2><p>No violations found.</p>",
            target
        );
    }

    let mut rows = String::new();
    for v in violations {
        let level = match v.level {
            0 => "info",
            1 => "warning",
            2 => "error",
            _ => "fatal",
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            level,
            v.rule,
            v.description,
            v.messages.join("; "),
        ));
    }

    format!(
        r#"<h2>kxn | {} violation(s) on {}</h2>
<table border="1" cellpadding="4" cellspacing="0">
<tr><th>Level</th><th>Rule</th><th>Description</th><th>Details</th></tr>
{rows}
</table>"#,
        violations.len(),
        target,
    )
}

/// Send violations via SMTP email.
///
/// Uses `lettre` with STARTTLS. URI format:
/// `email://user:pass@smtp.host:port/recipient@email.com`
pub async fn send(
    _client: &reqwest::Client,
    url: &str,
    violations: &[Violation],
    target: &str,
) -> Result<()> {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    let cfg = parse_email_uri(url)?;

    let subject = if violations.is_empty() {
        format!("kxn | {} | ALL PASSED", target)
    } else {
        format!("kxn | {} | {} violation(s)", target, violations.len())
    };

    let html = build_html(violations, target);

    let email = Message::builder()
        .from(
            format!("kxn <{}>", cfg.username)
                .parse()
                .context("Invalid sender address")?,
        )
        .to(cfg.recipient.parse().context("Invalid recipient address")?)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(html)
        .context("Failed to build email")?;

    let creds = Credentials::new(cfg.username, cfg.password);

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)
        .context("Failed to create SMTP transport")?
        .port(cfg.smtp_port)
        .credentials(creds)
        .build();

    mailer.send(email).await.context("Failed to send email")?;
    Ok(())
}
