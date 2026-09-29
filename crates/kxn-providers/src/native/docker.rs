use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Value};
use std::os::unix::fs::MetadataExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::debug;

pub(crate) const RESOURCE_TYPES: &[&str] = &[
    "docker_containers",
    "docker_config",
    "docker_host",
    "docker_host_files",
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

    /// Is this machine the daemon's own host?
    ///
    /// `/proc/sys/net/ipv4/ip_local_port_range` exists on every Linux host
    /// running dockerd and nowhere else, so its absence means the daemon lives
    /// behind a socket proxy, a VM or a TCP endpoint — and none of the local
    /// files describe it.
    fn on_the_daemon_host() -> bool {
        std::fs::metadata("/proc/sys/net/ipv4/ip_local_port_range").is_ok()
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

    /// The daemon's configuration, as `/etc/docker/daemon.json` states it.
    ///
    /// Served only on the daemon's own host. Elsewhere the file is absent and
    /// every value below would be the documented default — which reads as a
    /// measurement and is not one: on a Mac talking to a Linux VM it reported
    /// inter-container communication enabled, no user namespace remapping and
    /// no seccomp profile, none of which had been looked at.
    async fn gather_config(&self) -> Result<Vec<Value>, ProviderError> {
        if !Self::on_the_daemon_host() {
            tracing::debug!(
                "Docker: not the daemon's host, so /etc/docker/daemon.json does not describe it; \
                 docker_config is not served"
            );
            return Ok(Vec::new());
        }
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

    /// What the Docker API itself can answer about the daemon.
    ///
    /// Everything derived from the host filesystem moved to
    /// `docker_host_files`: this function used to read `/var/run/docker.sock`,
    /// `/etc/docker/daemon.json`, `/etc/audit/rules.d/docker.rules` and
    /// `/proc/sys/...` and substitute `false`, `0` or `""` when they could not
    /// be read — which is every time the daemon is not on this machine. On a
    /// Mac talking to a Linux VM that invented six violations in a row: no
    /// audit rules, no TLS, world-readable socket, privileged port range. None
    /// of it was measured; all of it was the default for "file not found".
    async fn gather_host(&self) -> Result<Vec<Value>, ProviderError> {
        let info = self.api_get("/v1.41/info").await?;
        let version_major = info["ServerVersion"]
            .as_str()
            .and_then(|v| v.split('.').next())
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);

        Ok(vec![json!({
            "docker_version_major": version_major,
        })])
    }

    /// Host-filesystem configuration of the daemon, served only when this
    /// machine really is the daemon's host.
    ///
    /// The test is `/proc/sys/net/ipv4/ip_local_port_range`: it exists on every
    /// Linux host running dockerd and nowhere else, so its absence means the
    /// daemon is behind a socket proxy, a VM or a TCP endpoint and none of
    /// these files describe it. The object is then not served at all, and the
    /// rules report that they could not be evaluated instead of failing.
    async fn gather_host_files(&self) -> Result<Vec<Value>, ProviderError> {
        let port_range = match std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range") {
            Ok(s) if Self::on_the_daemon_host() => s,
            _ => {
                tracing::debug!(
                    "Docker: this machine is not the daemon's host, so its host-level \
                     configuration cannot be read; docker_host_files is not served"
                );
                return Ok(Vec::new());
            }
        };
        let host_port_min = port_range
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<i64>().ok());

        let mut out = serde_json::Map::new();
        let mut set = |key: &str, value: Option<Value>| {
            if let Some(value) = value {
                out.insert(key.to_string(), value);
            }
        };

        // The socket path the provider actually talks to, not a fixed one.
        let sock_meta = std::fs::metadata(&self.socket_path).ok();
        set(
            "docker_sock_permissions",
            sock_meta.as_ref().map(|m| json!(Self::file_mode_str(m.mode()))),
        );
        set(
            "docker_sock_owner",
            sock_meta.as_ref().map(|m| json!(m.uid().to_string())),
        );
        set("host_port_min", host_port_min.map(|v| json!(v)));
        // CIS 1.2 and 1.3: ownership of the daemon's state directory and the
        // mode of its configuration file. Both are absent when the path does
        // not exist, which is an answer the rules can read as "not found"
        // rather than one substituted for them.
        set(
            "var_lib_docker_owner",
            std::fs::metadata("/var/lib/docker")
                .ok()
                .map(|m| json!(format!("{}:{}", m.uid(), m.gid()))),
        );
        set(
            "daemon_json_permissions",
            std::fs::metadata("/etc/docker/daemon.json")
                .ok()
                .map(|m| json!(Self::file_mode_str(m.mode()))),
        );
        set(
            "audit_docker_daemon",
            std::fs::read_to_string("/etc/audit/rules.d/docker.rules")
                .ok()
                .map(|s| json!(s.contains("dockerd"))),
        );

        // `daemon.json` is optional: absent means the daemon runs on its
        // defaults, which is an answer. Unreadable is not, and `read_to_string`
        // cannot tell the two apart here — so a missing file is taken as the
        // documented defaults, both of which are off.
        let daemon = Self::read_daemon_json();
        set("tls", Some(json!(daemon["tls"].as_bool().unwrap_or(false))));
        set(
            "tlsverify",
            Some(json!(daemon["tlsverify"].as_bool().unwrap_or(false))),
        );

        // DOCKER_CONTENT_TRUST is read from this process's environment, which
        // only describes the daemon when they share a host.
        set(
            "docker_content_trust",
            std::env::var("DOCKER_CONTENT_TRUST").ok().map(Value::String),
        );

        Ok(vec![Value::Object(out)])
    }

    /// Images, with the parts of their configuration the rules judge.
    ///
    /// `/images/json` does not carry the image config, so this inspects each
    /// image. The previous version listed them and wrote `"healthcheck": ""`
    /// and `"installed_packages": []` as literals — not measurements, constants
    /// — so CIS 4.2 and 4.3 failed for every image on every host, forever, and
    /// the finding said nothing about the image.
    async fn gather_images(&self) -> Result<Vec<Value>, ProviderError> {
        let list = self.api_get("/v1.41/images/json").await?;
        let ids: Vec<String> = list
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|img| img["Id"].as_str().map(String::from))
            .collect();

        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let detail = match self.api_get(&format!("/v1.41/images/{id}/json")).await {
                Ok(d) => d,
                Err(e) => {
                    // A layer removed between the listing and the inspection is
                    // ordinary; judging the image on what the listing knew is
                    // not, so it is left out.
                    tracing::debug!(image = %id, error = %e, "Docker: image inspect failed, skipping");
                    continue;
                }
            };
            // Untagged images are dangling layers left behind by a rebuild:
            // `docker images` hides them for the same reason, and judging them
            // added six findings about nothing deployable. They are pruned, not
            // audited.
            let tags = detail["RepoTags"].as_array().cloned().unwrap_or_default();
            if tags.iter().all(|t| t.as_str().unwrap_or("").is_empty()) {
                continue;
            }

            let config = &detail["Config"];
            let mut image = serde_json::Map::new();
            image.insert(
                "id".into(),
                json!(id.strip_prefix("sha256:").unwrap_or(&id)),
            );
            image.insert("tags".into(), Value::Array(tags));
            image.insert("size".into(), json!(detail["Size"].as_i64().unwrap_or(0)));
            image.insert("created".into(), detail["Created"].clone());
            // Absent in the config means the image runs as root, which is
            // exactly what CIS 4.1 asks about — an empty string is the answer,
            // not a missing one.
            image.insert(
                "user".into(),
                json!(config["User"].as_str().unwrap_or("")),
            );
            // Docker returns `null` for an image with no HEALTHCHECK; the rule
            // compares to the empty string, so the absence is spelled that way.
            image.insert(
                "healthcheck".into(),
                match config["Healthcheck"]["Test"].as_array() {
                    Some(test) if !test.is_empty() => json!(test
                        .iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")),
                    _ => json!(""),
                },
            );
            out.push(Value::Object(image));
        }
        Ok(out)
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
            "docker_host_files" => self.gather_host_files().await,
            "docker_images" => self.gather_images().await,
            _ => Err(ProviderError::UnsupportedResourceType(
                resource_type.to_string(),
            )),
        }
    }
}
