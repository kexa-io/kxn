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
///
/// `provider` is the scanned target itself. A `shell` action is a fix *for that
/// target*, so it always goes through the provider — `ssh` runs it on the remote
/// host, `local` on this machine, any other provider refuses it. It is never run
/// on whatever machine kxn happens to run on: the shipped rules carry fixes like
/// `sed -i ... /etc/httpd/conf/httpd.conf && systemctl reload httpd`, which would
/// otherwise silently rewrite the monitoring host's own configuration.
pub async fn execute_remediations(
    actions: &[RemediationAction],
    ctx: &RemediationContext,
    provider: Arc<dyn Provider>,
) -> usize {
    let mut success = 0;
    let mut last_error: Option<String> = None;
    let ctx_json = serde_json::to_string(ctx).unwrap_or_default();

    for action in actions {
        match execute_one(action, &ctx_json, &provider).await {
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

use kxn_core::truncate;

async fn execute_one(
    action: &RemediationAction,
    ctx_json: &str,
    provider: &Arc<dyn Provider>,
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
            // Always on the target, through the provider: `ssh` executes it on
            // the remote host, `local` on this one, every other provider rejects
            // it rather than letting a target's fix land on the kxn host.
            let timeout_secs = timeout.unwrap_or(30);
            match tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                provider.execute_shell(command),
            )
            .await
            {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(anyhow::anyhow!("{}", e)),
                Err(_) => Err(anyhow::anyhow!("timeout after {}s", timeout_secs)),
            }
        }
        // Unlike `shell`, `binary` is an escape hatch that runs on the machine
        // kxn runs on — a local fixer script fed the violation via KXN_CONTEXT —
        // not on the target.
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

#[cfg(test)]
mod tests {
    use super::*;
    use kxn_providers::error::ProviderError;
    use std::sync::Mutex;

    /// Records what was asked of the target instead of touching anything.
    struct RecordingTarget {
        shell: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl Provider for RecordingTarget {
        fn name(&self) -> &str {
            "recording"
        }
        async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
            Ok(vec![])
        }
        async fn gather(&self, _rt: &str) -> Result<Vec<Value>, ProviderError> {
            Ok(vec![])
        }
        async fn execute_shell(&self, command: &str) -> Result<String, ProviderError> {
            self.shell.lock().unwrap().push(command.to_string());
            Ok(String::new())
        }
    }

    /// A target that cannot run shell commands (http, kubernetes, a database…):
    /// it keeps the trait's default `execute_shell`, which refuses.
    struct ShellLessTarget;

    #[async_trait::async_trait]
    impl Provider for ShellLessTarget {
        fn name(&self) -> &str {
            "shell-less"
        }
        async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
            Ok(vec![])
        }
        async fn gather(&self, _rt: &str) -> Result<Vec<Value>, ProviderError> {
            Ok(vec![])
        }
    }

    fn ctx() -> RemediationContext {
        RemediationContext {
            rule_name: "test-rule".into(),
            rule_description: String::new(),
            level: 2,
            target: "test-target".into(),
            provider: "test".into(),
            object_type: String::new(),
            object_content: Value::Null,
            messages: vec![],
        }
    }

    #[tokio::test]
    async fn shell_remediation_goes_to_the_target() {
        let target = Arc::new(RecordingTarget { shell: Mutex::new(vec![]) });
        let action = RemediationAction::Shell {
            command: "systemctl reload httpd".into(),
            timeout: Some(5),
        };
        let count = execute_remediations(&[action], &ctx(), target.clone()).await;
        assert_eq!(count, 1);
        assert_eq!(
            target.shell.lock().unwrap().as_slice(),
            ["systemctl reload httpd"]
        );
    }

    /// Regression guard: a rule's shell fix must never be executed on the host
    /// running kxn when the target cannot run it. `kxn watch` used to fall back
    /// to a local `sh -c`, so watching a remote Apache rewrote the monitoring
    /// host's own httpd.conf.
    #[tokio::test]
    async fn shell_remediation_never_falls_back_to_the_kxn_host() {
        let marker = std::env::temp_dir()
            .join(format!("kxn-remediation-guard-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);

        let target: Arc<dyn Provider> = Arc::new(ShellLessTarget);
        let action = RemediationAction::Shell {
            command: format!("touch '{}'", marker.display()),
            timeout: Some(5),
        };
        let count = execute_remediations(&[action], &ctx(), target).await;

        assert_eq!(count, 0, "an unsupported shell remediation must fail, not run");
        assert!(
            !marker.exists(),
            "shell remediation escaped to the kxn host: {}",
            marker.display()
        );
    }
}
