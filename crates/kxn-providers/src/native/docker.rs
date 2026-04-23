use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Value};
use std::os::unix::fs::MetadataExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::debug;

const RESOURCE_TYPES: &[&str] = &[
    "docker_containers",
    "docker_config",
    "docker_host",
    "docker_images",
];

pub struct DockerProvider {
    socket_path: String,
}

impl DockerProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let socket_path = get_config_or_env(&config, "DOCKER_SOCKET", Some("DOCKER"))
            .unwrap_or_else(|| "/var/run/docker.sock".to_string());
        Ok(Self { socket_path })
    }

    async fn api_get(&self, path: &str) -> Result<Value, ProviderError> {
        debug!(path, "Docker API GET");
        let mut stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            ProviderError::Connection(format!(
                "Cannot connect to Docker socket {}: {}",
                self.socket_path, e
            ))
        })?;

        let request = format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            path
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| ProviderError::Query(e.to_string()))?;

        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| ProviderError::Query(e.to_string()))?;

        let response = String::from_utf8_lossy(&buf);
        let body_start = response.find("\r\n\r\n").ok_or_else(|| {
            ProviderError::Query("Invalid HTTP response from Docker".to_string())
        })?;
        let body = &response[body_start + 4..];

        // Handle chunked transfer encoding (skip chunk size lines)
        let body = if response.contains("Transfer-Encoding: chunked")
            || response.contains("transfer-encoding: chunked")
        {
            Self::decode_chunked(body)
        } else {
            body.to_string()
        };

        serde_json::from_str(&body)
            .map_err(|e| ProviderError::Query(format!("Docker JSON parse error on {path}: {e}")))
    }

    fn decode_chunked(body: &str) -> String {
        let mut result = String::new();
        let mut lines = body.lines().peekable();
        while let Some(size_line) = lines.next() {
            let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
            if size == 0 {
                break;
            }
            let mut chunk = String::new();
            let mut remaining = size;
            for line in lines.by_ref() {
                if remaining == 0 {
                    break;
                }
                chunk.push_str(line);
                chunk.push('\n');
                remaining = remaining.saturating_sub(line.len() + 1);
            }
            result.push_str(chunk.trim_end_matches('\n'));
        }
        result
    }

    fn read_daemon_json() -> Value {
        std::fs::read_to_string("/etc/docker/daemon.json")
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(json!({}))
    }

    fn file_mode_str(mode: u32) -> String {
        format!("{:o}", mode & 0o777)
    }

    async fn gather_containers(&self) -> Result<Vec<Value>, ProviderError> {
        let list = self
            .api_get("/v1.41/containers/json?all=true")
            .await?;
        let ids: Vec<String> = list
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|c| c["Id"].as_str().map(|s| s.to_string()))
            .collect();

        let mut containers = Vec::new();
        for id in ids {
            let c = match self
                .api_get(&format!("/v1.41/containers/{}/json", id))
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(container_id = %id, error = %e, "Docker inspect failed");
                    continue;
                }
            };

            let name = c["Name"]
                .as_str()
                .unwrap_or("")
                .trim_start_matches('/')
                .to_string();
            let state = c["State"]["Status"].as_str().unwrap_or("").to_string();
            let running = c["State"]["Running"].as_bool().unwrap_or(false);

            let labels = c["Config"]["Labels"].as_object();
            let label = |key: &str| -> String {
                labels
                    .and_then(|l| l.get(key))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };

            let security_opt = c["HostConfig"]["SecurityOpt"]
                .as_array()
                .map(|a| {
                    a.iter().any(|s| {
                        s.as_str()
                            .map(|s| s.contains("no-new-privileges"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            let hc = &c["Config"]["Healthcheck"];
            let healthcheck = !hc.is_null() && hc.is_object();

            containers.push(json!({
                "name": name,
                "state": state,
                "running": running,
                "image": c["Config"]["Image"].as_str().unwrap_or(""),
                "workdir": label("com.docker.compose.project.working_dir"),
                "service": label("com.docker.compose.service"),
                "project": label("com.docker.compose.project"),
                "privileged": c["HostConfig"]["Privileged"].as_bool().unwrap_or(false),
                "pid_mode": c["HostConfig"]["PidMode"].as_str().unwrap_or(""),
                "ipc_mode": c["HostConfig"]["IpcMode"].as_str().unwrap_or(""),
                "network_mode": c["HostConfig"]["NetworkMode"].as_str().unwrap_or(""),
                "memory_limit": c["HostConfig"]["Memory"].as_i64().unwrap_or(0),
                "cpu_shares": c["HostConfig"]["CpuShares"].as_i64().unwrap_or(0),
                "healthcheck": healthcheck,
                "read_only_rootfs": c["HostConfig"]["ReadonlyRootfs"].as_bool().unwrap_or(false),
                "user": c["Config"]["User"].as_str().unwrap_or(""),
                "mounts": c["Mounts"],
                "restart_policy_name": c["HostConfig"]["RestartPolicy"]["Name"].as_str().unwrap_or(""),
                "restart_policy_max_retry": c["HostConfig"]["RestartPolicy"]["MaximumRetryCount"].as_i64().unwrap_or(0),
                "no-new-privileges": security_opt,
            }));
        }
        Ok(containers)
    }

    async fn gather_config(&self) -> Result<Vec<Value>, ProviderError> {
        let d = Self::read_daemon_json();

        let insecure = match &d["insecure-registries"] {
            Value::Array(a) => {
                if a.is_empty() {
                    json!([])
                } else {
                    json!(a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(","))
                }
            }
            Value::String(s) => json!(s),
            Value::Null => json!(""),
            other => other.clone(),
        };

        Ok(vec![json!({
            "insecure-registries": insecure,
            "tls": d["tls"].as_bool().unwrap_or(false),
            "tlsverify": d["tlsverify"].as_bool().unwrap_or(false),
            "userland-proxy": d["userland-proxy"].as_bool().unwrap_or(true),
            "live-restore": d["live-restore"].as_bool().unwrap_or(false),
            "experimental": d["experimental"].as_bool().unwrap_or(false),
            "log-driver": d["log-driver"].as_str().unwrap_or("json-file"),
            "icc": d["icc"].as_bool().unwrap_or(true),
            "userns-remap": d["userns-remap"].as_str().unwrap_or(""),
            "seccomp-profile": d["seccomp-profile"].as_str().unwrap_or(""),
            "no-new-privileges": d["no-new-privileges"].as_bool().unwrap_or(false),
            "default-ulimits": d["default-ulimits"].clone(),
        })])
    }

    async fn gather_host(&self) -> Result<Vec<Value>, ProviderError> {
        let info = self.api_get("/v1.41/info").await?;

        let sock_meta = std::fs::metadata("/var/run/docker.sock").ok();
        let sock_perms = sock_meta
            .as_ref()
            .map(|m| Self::file_mode_str(m.mode()))
            .unwrap_or_default();
        let sock_owner = sock_meta
            .as_ref()
            .map(|m| m.uid().to_string())
            .unwrap_or_default();

        let audit_docker = std::fs::read_to_string("/etc/audit/rules.d/docker.rules")
            .map(|s| s.contains("dockerd"))
            .unwrap_or(false);

        let content_trust = std::env::var("DOCKER_CONTENT_TRUST")
            .unwrap_or_default();

        let version_major = info["ServerVersion"]
            .as_str()
            .and_then(|v| v.split('.').next())
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);

        // host_port_min from /proc/sys/net/ipv4/ip_local_port_range
        let host_port_min = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
            .ok()
            .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse::<i64>().ok()))
            .unwrap_or(0);

        let d = Self::read_daemon_json();
        Ok(vec![json!({
            "docker_version_major": version_major,
            "docker_sock_permissions": sock_perms,
            "docker_sock_owner": sock_owner,
            "audit_docker_daemon": audit_docker,
            "docker_content_trust": content_trust,
            "host_port_min": host_port_min,
            "tls": d["tls"].as_bool().unwrap_or(false),
            "tlsverify": d["tlsverify"].as_bool().unwrap_or(false),
        })])
    }

    async fn gather_images(&self) -> Result<Vec<Value>, ProviderError> {
        let list = self.api_get("/v1.41/images/json").await?;
        Ok(list
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|img| {
                let tags = img["RepoTags"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
                    .unwrap_or_default();
                json!({
                    "id": img["Id"].as_str().unwrap_or("").get(7..).unwrap_or(""),
                    "tags": tags,
                    "size": img["Size"].as_i64().unwrap_or(0),
                    "created": img["Created"].as_i64().unwrap_or(0),
                    "installed_packages": [],
                    "healthcheck": "",
                })
            })
            .collect())
    }
}

#[async_trait::async_trait]
impl Provider for DockerProvider {
    fn name(&self) -> &str {
        "docker"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        match resource_type {
            "docker_containers" => self.gather_containers().await,
            "docker_config" => self.gather_config().await,
            "docker_host" => self.gather_host().await,
            "docker_images" => self.gather_images().await,
            _ => Err(ProviderError::UnsupportedResourceType(
                resource_type.to_string(),
            )),
        }
    }
}
