use anyhow::Result;
use kxn_core::RemediationAction;
use serde_json::Value;
use std::process::Command;
use tracing::{info, warn};

/// Context passed to remediation actions via environment variables and JSON
#[derive(serde::Serialize)]
pub struct RemediationContext {
    pub rule_name: String,
    pub rule_description: String,
    pub level: u8,
    pub target: String,
    pub provider: String,
    pub object_type: String,
    pub object_content: Value,
    pub messages: Vec<String>,
}

/// Execute a list of remediation actions for a violation.
/// Returns the number of actions successfully executed.
pub async fn execute_remediations(
    actions: &[RemediationAction],
    ctx: &RemediationContext,
) -> usize {
    let mut success = 0;
    let ctx_json = serde_json::to_string(ctx).unwrap_or_default();

    for action in actions {
        match execute_one(action, &ctx_json).await {
            Ok(()) => {
                info!("Remediation executed for {}: {:?}", ctx.rule_name, action_label(action));
                success += 1;
            }
            Err(e) => {
                warn!("Remediation failed for {}: {} — {}", ctx.rule_name, action_label(action), e);
            }
        }
    }
    success
}

fn action_label(action: &RemediationAction) -> String {
    match action {
        RemediationAction::Webhook { url, .. } => format!("webhook:{}", url),
        RemediationAction::Shell { command, .. } => format!("shell:{}", truncate(command, 40)),
        RemediationAction::Binary { path, .. } => format!("binary:{}", path),
        RemediationAction::Lua { script, .. } => format!("lua:{}", truncate(script, 40)),
        RemediationAction::Sql { query, .. } => format!("sql:{}", truncate(query, 40)),
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() > max { &s[..max] } else { s }
}

async fn execute_one(action: &RemediationAction, ctx_json: &str) -> Result<()> {
    match action {
        RemediationAction::Webhook { url, method, headers } => {
            let client = crate::alerts::shared_client();
            let method_str = method.as_deref().unwrap_or("POST");
            let mut req = match method_str.to_uppercase().as_str() {
                "GET" => client.get(url),
                "PUT" => client.put(url),
                "PATCH" => client.patch(url),
                _ => client.post(url),
            };
            if let Some(hdrs) = headers {
                for (k, v) in hdrs {
                    req = req.header(k.as_str(), v.as_str());
                }
            }
            let resp = req
                .header("Content-Type", "application/json")
                .body(ctx_json.to_string())
                .send()
                .await?;
            if !resp.status().is_success() {
                anyhow::bail!("HTTP {}", resp.status());
            }
            Ok(())
        }
        RemediationAction::Shell { command, timeout } => {
            let timeout_secs = timeout.unwrap_or(30);
            let output = tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                tokio::task::spawn_blocking({
                    let cmd = command.clone();
                    let ctx = ctx_json.to_string();
                    move || {
                        Command::new("sh")
                            .arg("-c")
                            .arg(&cmd)
                            .env("KXN_CONTEXT", &ctx)
                            .output()
                    }
                }),
            )
            .await
            .map_err(|_| anyhow::anyhow!("timeout after {}s", timeout_secs))?
            .map_err(|e| anyhow::anyhow!("spawn error: {}", e))?
            .map_err(|e| anyhow::anyhow!("exec error: {}", e))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("exit code {}: {}", output.status, stderr.trim());
            }
            Ok(())
        }
        RemediationAction::Binary { path, args, timeout } => {
            let timeout_secs = timeout.unwrap_or(30);
            let output = tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                tokio::task::spawn_blocking({
                    let path = path.clone();
                    let args = args.clone();
                    let ctx = ctx_json.to_string();
                    move || {
                        Command::new(&path)
                            .args(&args)
                            .env("KXN_CONTEXT", &ctx)
                            .output()
                    }
                }),
            )
            .await
            .map_err(|_| anyhow::anyhow!("timeout after {}s", timeout_secs))?
            .map_err(|e| anyhow::anyhow!("spawn error: {}", e))?
            .map_err(|e| anyhow::anyhow!("exec error: {}", e))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("exit code {}: {}", output.status, stderr.trim());
            }
            Ok(())
        }
        RemediationAction::Lua { script, timeout: _ } => {
            // Lua support is a premium feature — log and skip for now
            warn!("Lua remediation requires kxn premium: {}", truncate(script, 60));
            anyhow::bail!("Lua remediation requires kxn premium license");
        }
        RemediationAction::Sql { query, .. } => {
            // SQL remediation is handled by MCP tool or requires provider context
            warn!("SQL remediation not supported in CLI mode: {}", truncate(query, 60));
            anyhow::bail!("SQL remediation requires MCP tool (kxn_remediate) with target context");
        }
    }
}
