//! Local subprocess provider.
//!
//! Runs gather queries and remediation commands as direct subprocesses on
//! the host kxn is running on, instead of going through SSH. Solves the
//! self-sabotage case where `kxn remediate ssh://...` against localhost
//! kills its own connection when a rule does `systemctl restart sshd`.
//!
//! URI: `local://` (no host required).
//!
//! Resource types are a subset of the SSH provider's — we reuse its
//! parsers verbatim (same `cat /etc/ssh/sshd_config` style commands), so
//! existing rules work without modification.

use crate::error::ProviderError;
use crate::native::ssh::SshProvider;
use crate::traits::Provider;
use serde_json::Value;
use tokio::process::Command;
use tracing::debug;

const RESOURCE_TYPES: &[&str] = &[
    "sshd_config",
    "sysctl",
    "users",
    "services",
    "file_permissions",
    "os_info",
    "packages",
];

pub struct LocalProvider {
    shell: String,
}

impl LocalProvider {
    pub fn new(_config: Value) -> Result<Self, ProviderError> {
        Ok(Self {
            shell: std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string()),
        })
    }

    async fn exec(&self, cmd: &str) -> Result<String, ProviderError> {
        debug!(cmd, "local exec");
        let output = Command::new(&self.shell)
            .arg("-c")
            .arg(cmd)
            .output()
            .await
            .map_err(|e| ProviderError::Query(format!("local exec `{}`: {}", cmd, e)))?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

#[async_trait::async_trait]
impl Provider for LocalProvider {
    fn name(&self) -> &str {
        "local"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        let (cmd, parser): (&str, fn(&str) -> Vec<Value>) = match resource_type {
            "sshd_config" => (
                "sudo sshd -T 2>/dev/null || sshd -T 2>/dev/null || cat /etc/ssh/sshd_config",
                SshProvider::parse_sshd_config,
            ),
            "sysctl" => ("sysctl -a 2>/dev/null", SshProvider::parse_sysctl),
            "users" => ("cat /etc/passwd", SshProvider::parse_users),
            "services" => (
                "systemctl list-unit-files --type=service --no-pager --no-legend",
                SshProvider::parse_services,
            ),
            "file_permissions" => (
                "stat -c '%n %a %U %G' /etc/passwd /etc/shadow /etc/group /etc/gshadow \
                 /etc/ssh/sshd_config /etc/crontab 2>/dev/null",
                SshProvider::parse_file_permissions,
            ),
            "os_info" => (
                "echo \"$(uname -a)\n---SEP---\n$(cat /etc/os-release 2>/dev/null)\n---SEP---\n$(hostname)\n---SEP---\n$(uptime -s 2>/dev/null)\"",
                SshProvider::parse_os_info,
            ),
            "packages" => {
                let output = self.exec(
                    "apt list --upgradable 2>/dev/null | tail -n +2; \
                     echo '---SEP---'; \
                     yum check-update 2>/dev/null | awk 'NF==3{print $1,$2,$3}'; \
                     echo '---SEP---'; \
                     apk version -l '<' 2>/dev/null | tail -n +2"
                ).await?;
                return Ok(SshProvider::parse_packages(&output));
            }
            _ => {
                return Err(ProviderError::UnsupportedResourceType(
                    resource_type.to_string(),
                ))
            }
        };

        let output = self.exec(cmd).await?;
        Ok(parser(&output))
    }

    async fn execute_shell(&self, command: &str) -> Result<String, ProviderError> {
        self.exec(command).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn execute_shell_returns_stdout() {
        let p = LocalProvider::new(Value::Null).unwrap();
        let out = p.execute_shell("echo hello-local").await.unwrap();
        assert!(out.contains("hello-local"));
    }

    #[tokio::test]
    async fn unsupported_resource_type_errors_out() {
        let p = LocalProvider::new(Value::Null).unwrap();
        let err = p.gather("does-not-exist").await.unwrap_err();
        assert!(matches!(err, ProviderError::UnsupportedResourceType(_)));
    }
}
