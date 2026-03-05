use crate::config::{get_config_or_env, require_config};
use crate::error::ProviderError;
use crate::traits::Provider;
use async_ssh2_tokio::client::{AuthMethod, Client, ServerCheckMethod};
use serde_json::{json, Value};
use tokio::sync::OnceCell;
use tracing::debug;

const RESOURCE_TYPES: &[&str] = &[
    "sshd_config",
    "sysctl",
    "users",
    "services",
    "file_permissions",
    "os_info",
];

enum SshAuth {
    Password(String),
    Key(String),
}

pub struct SshProvider {
    host: String,
    user: String,
    auth: SshAuth,
    port: u16,
    client: OnceCell<Client>,
}

impl SshProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let host = require_config(&config, "SSH_HOST", Some("SSH"))?;
        let user = get_config_or_env(&config, "SSH_USER", Some("SSH"))
            .unwrap_or_else(|| "root".to_string());
        let port: u16 = get_config_or_env(&config, "SSH_PORT", Some("SSH"))
            .and_then(|p| p.parse().ok())
            .unwrap_or(22);

        let auth =
            if let Some(password) = get_config_or_env(&config, "SSH_PASSWORD", Some("SSH")) {
                SshAuth::Password(password)
            } else if let Some(key) = get_config_or_env(&config, "SSH_KEY", Some("SSH")) {
                SshAuth::Key(key)
            } else if let Some(key_path) = get_config_or_env(&config, "SSH_KEY_PATH", Some("SSH"))
                .or_else(|| get_config_or_env(&config, "SSH_PRIVATE_KEY", Some("SSH")))
            {
                let key = std::fs::read_to_string(&key_path).map_err(|e| {
                    ProviderError::InvalidConfig(format!(
                        "Cannot read SSH key file {}: {}",
                        key_path, e
                    ))
                })?;
                SshAuth::Key(key)
            } else {
                return Err(ProviderError::InvalidConfig(
                    "SSH requires SSH_PASSWORD, SSH_KEY, or SSH_KEY_PATH".to_string(),
                ));
            };

        Ok(Self {
            host,
            user,
            auth,
            port,
            client: OnceCell::new(),
        })
    }

    async fn get_client(&self) -> Result<&Client, ProviderError> {
        self.client
            .get_or_try_init(|| async {
                let auth_method = match &self.auth {
                    SshAuth::Password(p) => AuthMethod::with_password(p),
                    SshAuth::Key(k) => AuthMethod::with_key(k, None),
                };

                Client::connect(
                    (self.host.as_str(), self.port),
                    self.user.as_str(),
                    auth_method,
                    ServerCheckMethod::NoCheck,
                )
                .await
                .map_err(|e| {
                    ProviderError::Connection(format!(
                        "SSH {}@{}:{} — {}",
                        self.user, self.host, self.port, e
                    ))
                })
            })
            .await
    }

    async fn exec(&self, cmd: &str) -> Result<String, ProviderError> {
        debug!(cmd, "SSH exec");
        let client = self.get_client().await?;
        let result = client
            .execute(cmd)
            .await
            .map_err(|e| ProviderError::Query(format!("SSH exec `{}`: {}", cmd, e)))?;
        Ok(result.stdout)
    }

    fn parse_sshd_config(output: &str) -> Vec<Value> {
        let mut map = serde_json::Map::new();
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once(char::is_whitespace) {
                map.insert(
                    key.trim().to_lowercase(),
                    Value::String(value.trim().to_string()),
                );
            }
        }
        vec![Value::Object(map)]
    }

    fn parse_sysctl(output: &str) -> Vec<Value> {
        let mut map = serde_json::Map::new();
        for line in output.lines() {
            if let Some((key, value)) = line.split_once(" = ") {
                map.insert(
                    key.trim().to_string(),
                    Value::String(value.trim().to_string()),
                );
            }
        }
        vec![Value::Object(map)]
    }

    fn parse_users(output: &str) -> Vec<Value> {
        let mut users = Vec::new();
        for line in output.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 7 {
                users.push(json!({
                    "username": parts[0],
                    "uid": parts[2].parse::<i64>().unwrap_or(-1),
                    "gid": parts[3].parse::<i64>().unwrap_or(-1),
                    "home": parts[5],
                    "shell": parts[6],
                }));
            }
        }
        users
    }

    fn parse_services(output: &str) -> Vec<Value> {
        let mut services = Vec::new();
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                services.push(json!({
                    "name": parts[0],
                    "state": parts[1],
                }));
            }
        }
        services
    }

    fn parse_file_permissions(output: &str) -> Vec<Value> {
        let mut files = Vec::new();
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                files.push(json!({
                    "path": parts[0],
                    "mode": parts[1],
                    "owner": parts[2],
                    "group": parts[3],
                }));
            }
        }
        files
    }

    fn parse_os_info(output: &str) -> Vec<Value> {
        let sections: Vec<&str> = output.split("---SEP---").collect();
        let uname = sections.first().map(|s| s.trim()).unwrap_or("");
        let os_release = sections.get(1).map(|s| s.trim()).unwrap_or("");
        let hostname = sections.get(2).map(|s| s.trim()).unwrap_or("");
        let uptime = sections.get(3).map(|s| s.trim()).unwrap_or("");

        let mut info = json!({
            "kernel": uname,
            "hostname": hostname,
            "uptime_since": uptime,
        });

        for line in os_release.lines() {
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_lowercase();
                let value = value.trim().trim_matches('"');
                info[key] = Value::String(value.to_string());
            }
        }

        vec![info]
    }
}

#[async_trait::async_trait]
impl Provider for SshProvider {
    fn name(&self) -> &str {
        "ssh"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        let (cmd, parser): (&str, fn(&str) -> Vec<Value>) = match resource_type {
            "sshd_config" => (
                "sshd -T 2>/dev/null || cat /etc/ssh/sshd_config",
                Self::parse_sshd_config,
            ),
            "sysctl" => ("sysctl -a 2>/dev/null", Self::parse_sysctl),
            "users" => ("cat /etc/passwd", Self::parse_users),
            "services" => (
                "systemctl list-unit-files --type=service --no-pager --no-legend",
                Self::parse_services,
            ),
            "file_permissions" => (
                "stat -c '%n %a %U %G' /etc/passwd /etc/shadow /etc/group /etc/gshadow \
                 /etc/ssh/sshd_config /etc/crontab 2>/dev/null",
                Self::parse_file_permissions,
            ),
            "os_info" => (
                "echo \"$(uname -a)\n---SEP---\n$(cat /etc/os-release 2>/dev/null)\n---SEP---\n$(hostname)\n---SEP---\n$(uptime -s 2>/dev/null)\"",
                Self::parse_os_info,
            ),
            _ => {
                return Err(ProviderError::UnsupportedResourceType(
                    resource_type.to_string(),
                ))
            }
        };

        let output = self.exec(cmd).await?;
        Ok(parser(&output))
    }
}
