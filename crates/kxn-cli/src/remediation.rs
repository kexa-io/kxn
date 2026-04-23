use anyhow::Result;
use kxn_core::RemediationAction;
use kxn_providers::Provider;
use serde_json::Value;
use std::process::Command;
use std::sync::Arc;
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
/// If `provider` is set and the action is Shell/SQL, runs on the remote target.
pub async fn execute_remediations(
    actions: &[RemediationAction],
    ctx: &RemediationContext,
    provider: Option<Arc<dyn Provider>>,
) -> usize {
    let mut success = 0;
    let mut last_error: Option<String> = None;
    let ctx_json = serde_json::to_string(ctx).unwrap_or_default();

    for action in actions {
        match execute_one(action, &ctx_json, provider.clone()).await {
            Ok(()) => {
                info!("Remediation executed for {}: {:?}", ctx.rule_name, action_label(action));
                success += 1;
            }
            Err(e) => {
                let msg = format!("{}", e);
                warn!("Remediation failed for {}: {} — {}", ctx.rule_name, action_label(action), msg);
                last_error = Some(msg);
            }
        }
    }
    if success == 0 {
        if let Some(err) = last_error {
            eprintln!("    error: {}", err);
        }
    }
    success
}

/// Human-readable summary of a remediation action (for CLI display).
pub fn action_summary(action: &RemediationAction) -> String {
    match action {
        RemediationAction::Webhook { url, method, .. } => {
            format!("{} {}", method.as_deref().unwrap_or("POST"), url)
        }
        RemediationAction::Shell { command, .. } => {
            format!("shell: {}", truncate(command, 80))
        }
        RemediationAction::Binary { path, args, .. } => {
            format!("exec: {} {}", path, args.join(" "))
        }
        RemediationAction::Lua { script, .. } => {
            format!("lua: {}", truncate(script, 80))
        }
        RemediationAction::Sql { query, .. } => {
            format!("sql: {}", truncate(query, 80))
        }
        RemediationAction::RotateSpSecret { vault, secret_name } => {
            format!("rotate SP secret → keyvault:{}/{}", vault, secret_name)
        }
        RemediationAction::RotateSAKey { project, secret } => {
            format!("rotate SA key → secretmanager:{}/{}", project, secret)
        }
    }
}

fn action_label(action: &RemediationAction) -> String {
    match action {
        RemediationAction::Webhook { url, .. } => format!("webhook:{}", url),
        RemediationAction::Shell { command, .. } => format!("shell:{}", truncate(command, 40)),
        RemediationAction::Binary { path, .. } => format!("binary:{}", path),
        RemediationAction::Lua { script, .. } => format!("lua:{}", truncate(script, 40)),
        RemediationAction::Sql { query, .. } => format!("sql:{}", truncate(query, 40)),
        RemediationAction::RotateSpSecret { vault, secret_name } => {
            format!("rotate-sp-secret:kv={}/{}", vault, secret_name)
        }
        RemediationAction::RotateSAKey { project, secret } => {
            format!("rotate-sa-key:sm={}/{}", project, secret)
        }
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() > max { &s[..max] } else { s }
}

async fn execute_one(
    action: &RemediationAction,
    ctx_json: &str,
    provider: Option<Arc<dyn Provider>>,
) -> Result<()> {
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

            // If a provider is available, execute on the remote target
            if let Some(p) = &provider {
                return match tokio::time::timeout(
                    std::time::Duration::from_secs(timeout_secs),
                    p.execute_shell(command),
                ).await {
                    Ok(Ok(_)) => Ok(()),
                    Ok(Err(e)) => Err(anyhow::anyhow!("{}", e)),
                    Err(_) => Err(anyhow::anyhow!("timeout after {}s", timeout_secs)),
                };
            }

            // Otherwise fall back to local execution
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
        RemediationAction::RotateSpSecret { vault, secret_name } => {
            let tenant_id = std::env::var("AZURE_TENANT_ID")
                .map_err(|_| anyhow::anyhow!("AZURE_TENANT_ID not set"))?;
            let client_id = std::env::var("AZURE_CLIENT_ID")
                .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_ID not set"))?;
            let client_secret_env = std::env::var("AZURE_CLIENT_SECRET")
                .map_err(|_| anyhow::anyhow!("AZURE_CLIENT_SECRET not set"))?;

            // Extract app_object_id and credential_id from context JSON
            let ctx: serde_json::Value = serde_json::from_str(ctx_json)
                .map_err(|e| anyhow::anyhow!("Invalid context JSON: {}", e))?;
            let obj = &ctx["object_content"];
            let app_object_id = obj["app_object_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("app_object_id not found in context"))?;
            let credential_id = obj["credential_id"]
                .as_str()
                .unwrap_or("");
            let display_name = obj["display_name"].as_str().unwrap_or("unknown");

            info!("Rotating SP secret for app_object_id={} → KV {}/{}", app_object_id, vault, secret_name);

            let new_secret = kxn_providers::rotate_sp_secret(
                &tenant_id,
                &client_id,
                &client_secret_env,
                app_object_id,
                credential_id,
                display_name,
                vault,
                secret_name,
            ).await?;

            eprintln!("    [rotate-sp-secret] New secret stored in KV {}/{} (hint: {}...)", vault, secret_name, &new_secret[..8.min(new_secret.len())]);
            Ok(())
        }
        RemediationAction::RotateSAKey { project, secret } => {
            let ctx: serde_json::Value = serde_json::from_str(ctx_json)
                .map_err(|e| anyhow::anyhow!("Invalid context JSON: {}", e))?;
            let obj = &ctx["object_content"];
            let email = obj["email"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("email not found in context"))?;
            let key_id = obj["key_id"].as_str().unwrap_or("");

            info!("Rotating SA key for {} → Secret Manager {}/{}", email, project, secret);

            let new_key_id = kxn_providers::rotate_sa_key(project, email, key_id, secret).await?;

            eprintln!("    [rotate-sa-key] New key stored in Secret Manager {}/{} (key: {}...)", project, secret, &new_key_id[..8.min(new_key_id.len())]);
            Ok(())
        }
    }
}
