use crate::config::{get_config_or_env, require_config};
use crate::cve_db::CveDb;
use crate::error::ProviderError;
use crate::traits::Provider;
use async_ssh2_tokio::client::{AuthMethod, Client, ServerCheckMethod};
use serde_json::{json, Value};
use tokio::sync::OnceCell;
use tracing::{debug, info};

const RESOURCE_TYPES: &[&str] = &[
    "sshd_config",
    "sysctl",
    "users",
    "services",
    "file_permissions",
    "os_info",
    "system_stats",
    "packages",
    "packages_cve",
    "logs",
    "kubelet_config",
    "k8s_master_config",
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
    insecure: bool,
    client: OnceCell<Client>,
    cve_exclude_packages: Vec<String>,
    cve_exclude_patterns: Vec<String>,
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

        let insecure = get_config_or_env(&config, "SSH_INSECURE", Some("SSH"))
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let parse_list = |key: &str| -> Vec<String> {
            get_config_or_env(&config, key, Some("SSH"))
                .map(|s| s.split(',').map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty()).collect())
                .unwrap_or_default()
        };

        Ok(Self {
            host,
            user,
            auth,
            port,
            insecure,
            client: OnceCell::new(),
            cve_exclude_packages: parse_list("CVE_EXCLUDE_PACKAGES"),
            cve_exclude_patterns: parse_list("CVE_EXCLUDE_PATTERNS"),
        })
    }

    async fn get_client(&self) -> Result<&Client, ProviderError> {
        self.client
            .get_or_try_init(|| async {
                let auth_method = match &self.auth {
                    SshAuth::Password(p) => AuthMethod::with_password(p),
                    SshAuth::Key(k) => AuthMethod::with_key(k, None),
                };

                let check = if self.insecure {
                    tracing::warn!(host = %self.host, "SSH_INSECURE=true — skipping host key verification");
                    ServerCheckMethod::NoCheck
                } else {
                    ServerCheckMethod::DefaultKnownHostsFile
                };

                Client::connect(
                    (self.host.as_str(), self.port),
                    self.user.as_str(),
                    auth_method,
                    check,
                )
                .await
                .map_err(|e| {
                    ProviderError::Connection(format!(
                        "SSH {}@{}:{} — {}. If host key is not in known_hosts, add it with ssh-keyscan or set SSH_INSECURE=true.",
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
        // OpenSSH >=7.6 removed Protocol from `sshd -T` output (only v2 supported)
        if !map.contains_key("protocol") {
            map.insert("protocol".to_string(), Value::String("2".to_string()));
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

    fn parse_system_stats(output: &str) -> Vec<Value> {
        let sections: Vec<&str> = output.split("---SEP---").collect();

        // Parse CPU from /proc/stat (two samples, 1s apart)
        let cpu1 = sections.first().map(|s| s.trim()).unwrap_or("");
        let cpu2 = sections.get(1).map(|s| s.trim()).unwrap_or("");
        let cpu_percent = Self::calc_cpu_percent(cpu1, cpu2);

        // Parse memory from /proc/meminfo
        let meminfo = sections.get(2).map(|s| s.trim()).unwrap_or("");
        let (mem_total_mb, mem_used_mb, mem_percent) = Self::parse_meminfo(meminfo);

        // Parse swap from /proc/meminfo
        let (swap_total_mb, swap_used_mb, swap_percent) = Self::parse_swap(meminfo);

        // Parse disk from df
        let disk_info = sections.get(3).map(|s| s.trim()).unwrap_or("");
        let (disk_total_gb, disk_used_gb, disk_percent) = Self::parse_disk(disk_info);

        // Parse load average
        let loadavg = sections.get(4).map(|s| s.trim()).unwrap_or("");
        let load_parts: Vec<f64> = loadavg
            .split_whitespace()
            .take(3)
            .filter_map(|s| s.parse().ok())
            .collect();

        // Parse process count
        let nproc = sections
            .get(5)
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0);

        // Parse uptime seconds
        let uptime_secs = sections
            .get(6)
            .and_then(|s| s.trim().split('.').next())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        // Parse network from /proc/net/dev
        let net_dev = sections.get(7).map(|s| s.trim()).unwrap_or("");
        let (net_rx_bytes, net_tx_bytes, net_rx_packets, net_tx_packets, net_rx_errors, net_tx_errors) =
            Self::parse_net_dev(net_dev);

        // Parse disk I/O from /proc/diskstats
        let diskstats = sections.get(8).map(|s| s.trim()).unwrap_or("");
        let (disk_reads, disk_writes, disk_read_bytes, disk_write_bytes) =
            Self::parse_diskstats(diskstats);

        // Parse open files from /proc/sys/fs/file-nr
        let file_nr = sections.get(9).map(|s| s.trim()).unwrap_or("");
        let (open_files, max_files) = Self::parse_file_nr(file_nr);

        // Parse TCP connections from ss -s
        let ss_out = sections.get(10).map(|s| s.trim()).unwrap_or("");
        let (tcp_established, tcp_total) = Self::parse_tcp_stats(ss_out);

        // Parse vmstat (page in/out, swap in/out)
        let vmstat = sections.get(11).map(|s| s.trim()).unwrap_or("");
        let (pgpgin, pgpgout, pswpin, pswpout) = Self::parse_vmstat(vmstat);

        vec![json!({
            "cpu_percent": cpu_percent,
            "memory_total_mb": mem_total_mb,
            "memory_used_mb": mem_used_mb,
            "memory_percent": mem_percent,
            "swap_total_mb": swap_total_mb,
            "swap_used_mb": swap_used_mb,
            "swap_percent": swap_percent,
            "disk_total_gb": disk_total_gb,
            "disk_used_gb": disk_used_gb,
            "disk_percent": disk_percent,
            "load_1m": load_parts.first().copied().unwrap_or(0.0),
            "load_5m": load_parts.get(1).copied().unwrap_or(0.0),
            "load_15m": load_parts.get(2).copied().unwrap_or(0.0),
            "process_count": nproc,
            "uptime_seconds": uptime_secs,
            "net_rx_bytes": net_rx_bytes,
            "net_tx_bytes": net_tx_bytes,
            "net_rx_packets": net_rx_packets,
            "net_tx_packets": net_tx_packets,
            "net_rx_errors": net_rx_errors,
            "net_tx_errors": net_tx_errors,
            "disk_reads": disk_reads,
            "disk_writes": disk_writes,
            "disk_read_bytes": disk_read_bytes,
            "disk_write_bytes": disk_write_bytes,
            "open_files": open_files,
            "max_files": max_files,
            "tcp_established": tcp_established,
            "tcp_total": tcp_total,
            "pgpgin": pgpgin,
            "pgpgout": pgpgout,
            "pswpin": pswpin,
            "pswpout": pswpout,
        })]
    }

    fn calc_cpu_percent(sample1: &str, sample2: &str) -> f64 {
        let parse_cpu = |line: &str| -> Option<(i64, i64)> {
            let parts: Vec<i64> = line
                .split_whitespace()
                .skip(1) // skip "cpu"
                .filter_map(|s| s.parse().ok())
                .collect();
            if parts.len() >= 4 {
                let idle = parts[3];
                let total: i64 = parts.iter().sum();
                Some((idle, total))
            } else {
                None
            }
        };
        let (idle1, total1) = parse_cpu(sample1).unwrap_or((0, 1));
        let (idle2, total2) = parse_cpu(sample2).unwrap_or((0, 1));
        let delta_total = (total2 - total1) as f64;
        let delta_idle = (idle2 - idle1) as f64;
        if delta_total > 0.0 {
            ((delta_total - delta_idle) / delta_total * 100.0 * 10.0).round() / 10.0
        } else {
            0.0
        }
    }

    fn parse_meminfo(output: &str) -> (i64, i64, f64) {
        let mut total_kb = 0i64;
        let mut available_kb = 0i64;
        for line in output.lines() {
            if let Some(val) = line.strip_prefix("MemTotal:") {
                total_kb = val.split_whitespace().next()
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
            } else if let Some(val) = line.strip_prefix("MemAvailable:") {
                available_kb = val.split_whitespace().next()
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
            }
        }
        let total_mb = total_kb / 1024;
        let used_mb = (total_kb - available_kb) / 1024;
        let percent = if total_kb > 0 {
            ((used_mb as f64 / total_mb as f64) * 100.0 * 10.0).round() / 10.0
        } else {
            0.0
        };
        (total_mb, used_mb, percent)
    }

    fn parse_disk(output: &str) -> (i64, i64, f64) {
        // df output: Filesystem 1K-blocks Used Available Use% Mounted
        for line in output.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 && parts.last() == Some(&"/") {
                let total_kb: i64 = parts[1].parse().unwrap_or(0);
                let used_kb: i64 = parts[2].parse().unwrap_or(0);
                let total_gb = total_kb / 1_048_576;
                let used_gb = used_kb / 1_048_576;
                let percent = if total_kb > 0 {
                    (used_kb as f64 / total_kb as f64 * 100.0 * 10.0).round() / 10.0
                } else {
                    0.0
                };
                return (total_gb, used_gb, percent);
            }
        }
        (0, 0, 0.0)
    }

    fn parse_swap(meminfo: &str) -> (i64, i64, f64) {
        let mut total_kb = 0i64;
        let mut free_kb = 0i64;
        for line in meminfo.lines() {
            if let Some(val) = line.strip_prefix("SwapTotal:") {
                total_kb = val.split_whitespace().next()
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
            } else if let Some(val) = line.strip_prefix("SwapFree:") {
                free_kb = val.split_whitespace().next()
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
            }
        }
        let total_mb = total_kb / 1024;
        let used_mb = (total_kb - free_kb) / 1024;
        let percent = if total_kb > 0 {
            ((used_mb as f64 / total_mb as f64) * 100.0 * 10.0).round() / 10.0
        } else {
            0.0
        };
        (total_mb, used_mb, percent)
    }

    /// Parse /proc/net/dev — sum all non-lo interfaces
    fn parse_net_dev(output: &str) -> (i64, i64, i64, i64, i64, i64) {
        let (mut rx_bytes, mut tx_bytes) = (0i64, 0i64);
        let (mut rx_packets, mut tx_packets) = (0i64, 0i64);
        let (mut rx_errors, mut tx_errors) = (0i64, 0i64);
        for line in output.lines() {
            let line = line.trim();
            if !line.contains(':') || line.starts_with("Inter") || line.starts_with("face") {
                continue;
            }
            if let Some((iface, stats)) = line.split_once(':') {
                if iface.trim() == "lo" {
                    continue;
                }
                let parts: Vec<i64> = stats.split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if parts.len() >= 10 {
                    rx_bytes += parts[0];
                    rx_packets += parts[1];
                    rx_errors += parts[2];
                    tx_bytes += parts[8];
                    tx_packets += parts[9];
                    tx_errors += parts[10];
                }
            }
        }
        (rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors)
    }

    /// Parse /proc/diskstats — sum all sd*/vd*/nvme* devices (skip partitions)
    fn parse_diskstats(output: &str) -> (i64, i64, i64, i64) {
        let (mut reads, mut writes) = (0i64, 0i64);
        let (mut read_sectors, mut write_sectors) = (0i64, 0i64);
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 14 {
                continue;
            }
            let name = parts[2];
            // Only whole devices, not partitions (sda not sda1, vda not vda1)
            let is_device = (name.starts_with("sd") || name.starts_with("vd") || name.starts_with("xvd"))
                && name.len() == 3;
            let is_nvme = name.starts_with("nvme") && name.ends_with("n1") && !name.contains('p');
            if !is_device && !is_nvme {
                continue;
            }
            reads += parts[3].parse::<i64>().unwrap_or(0);
            read_sectors += parts[5].parse::<i64>().unwrap_or(0);
            writes += parts[7].parse::<i64>().unwrap_or(0);
            write_sectors += parts[9].parse::<i64>().unwrap_or(0);
        }
        // Sectors are typically 512 bytes
        (reads, writes, read_sectors * 512, write_sectors * 512)
    }

    /// Parse /proc/sys/fs/file-nr: allocated  free  max
    fn parse_file_nr(output: &str) -> (i64, i64) {
        let parts: Vec<i64> = output.split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect();
        let open = parts.first().copied().unwrap_or(0);
        let max = parts.get(2).copied().unwrap_or(0);
        (open, max)
    }

    /// Parse `ss -s` output for TCP stats
    fn parse_tcp_stats(output: &str) -> (i64, i64) {
        let mut established = 0i64;
        let mut total = 0i64;
        for line in output.lines() {
            let line = line.trim();
            if line.starts_with("TCP:") {
                // TCP: 5 (estab 2, closed 1, orphaned 0, timewait 0)
                // Extract total from first number
                for word in line.split_whitespace() {
                    if let Ok(n) = word.parse::<i64>() {
                        total = n;
                        break;
                    }
                }
                // Extract estab
                if let Some(pos) = line.find("estab") {
                    let after = &line[pos + 5..];
                    for ch in after.chars() {
                        if ch.is_ascii_digit() {
                            let num_str: String = after.chars()
                                .skip(after.find(ch).unwrap_or(0))
                                .take_while(|c| c.is_ascii_digit())
                                .collect();
                            established = num_str.parse().unwrap_or(0);
                            break;
                        }
                    }
                }
            }
        }
        // Fallback: parse /proc/net/sockstat format
        if total == 0 {
            for line in output.lines() {
                if line.starts_with("TCP:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for (i, p) in parts.iter().enumerate() {
                        if *p == "inuse" {
                            total = parts.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0);
                        }
                    }
                }
            }
        }
        (established, total)
    }

    /// Parse vmstat lines: pgpgin, pgpgout, pswpin, pswpout
    fn parse_vmstat(output: &str) -> (i64, i64, i64, i64) {
        let mut pgpgin = 0i64;
        let mut pgpgout = 0i64;
        let mut pswpin = 0i64;
        let mut pswpout = 0i64;
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                let val = parts[1].parse::<i64>().unwrap_or(0);
                match parts[0] {
                    "pgpgin" => pgpgin = val,
                    "pgpgout" => pgpgout = val,
                    "pswpin" => pswpin = val,
                    "pswpout" => pswpout = val,
                    _ => {}
                }
            }
        }
        (pgpgin, pgpgout, pswpin, pswpout)
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

    /// Gather installed packages and enrich with CVEs from local SQLite DB.
    async fn gather_packages_cve(&self) -> Result<Vec<Value>, ProviderError> {
        let output = self
            .exec(
                "dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null; \
                 echo '---SEP---'; \
                 rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null; \
                 echo '---SEP---'; \
                 apk list -I 2>/dev/null",
            )
            .await?;

        let mut packages = Self::parse_installed_packages(&output);

        // Apply CVE exclusions (per-target via kxn.toml config):
        //   CVE_EXCLUDE_PACKAGES = "git,tar"       — exact name match
        //   CVE_EXCLUDE_PATTERNS = "python3-*,libssl-*"  — prefix/glob match
        if !self.cve_exclude_packages.is_empty() {
            let set: std::collections::HashSet<String> = self.cve_exclude_packages
                .iter().map(|s| s.to_lowercase()).collect();
            packages.retain(|(name, _, _)| !set.contains(&name.to_lowercase()));
        }
        if !self.cve_exclude_patterns.is_empty() {
            let prefixes: Vec<String> = self.cve_exclude_patterns
                .iter().map(|s| s.trim_end_matches('*').to_lowercase()).collect();
            packages.retain(|(name, _, _)| {
                let lower = name.to_lowercase();
                !prefixes.iter().any(|p| lower.starts_with(p))
            });
        }

        // Deduplicate packages (same name+version listed twice by dpkg)
        let mut seen: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        packages.retain(|(name, version, _)| seen.insert((name.clone(), version.clone())));

        let db: CveDb = match CveDb::open_readonly() {
            Some(db) => db,
            None => {
                info!("No CVE database found — run 'kxn cve-update' first");
                return Ok(packages
                    .into_iter()
                    .map(|(name, version, manager)| {
                        json!({"name": name, "version": version, "manager": manager,
                               "cve_count": 0, "cves": [], "max_cvss": 0.0,
                               "max_severity": "NONE", "kev_listed": false})
                    })
                    .collect());
            }
        };

        let mut results = Vec::new();
        for (name, version, manager) in &packages {
            let product = normalize_package_name(name);
            let cves: Vec<Value> = db.lookup_product("*", &product).unwrap_or_default();
            let cve_count = cves.len();
            let max_cvss: f64 = cves
                .iter()
                .filter_map(|c: &Value| c.get("cvss_score").and_then(|v| v.as_f64()))
                .fold(0.0_f64, f64::max);
            let kev: bool = cves.iter().any(|c: &Value| {
                c.get("kev_listed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            });
            let top_cves: Vec<Value> = cves.into_iter().take(10).collect();
            results.push(json!({
                "name": name, "version": version, "manager": manager,
                "cve_count": cve_count, "cves": top_cves,
                "max_cvss": max_cvss,
                "max_severity": severity_from_score(max_cvss),
                "kev_listed": kev,
            }));
        }

        // Only return packages with CVEs, sorted by severity
        results.sort_by(|a, b| {
            b.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0)
                .partial_cmp(
                    &a.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0),
                )
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(results
            .into_iter()
            .filter(|r| {
                r.get("cve_count").and_then(|v| v.as_u64()).unwrap_or(0) > 0
            })
            .collect())
    }

    fn parse_installed_packages(output: &str) -> Vec<(String, String, String)> {
        let sections: Vec<&str> = output.split("---SEP---").collect();
        let mut pkgs = Vec::new();
        // dpkg
        if let Some(s) = sections.first() {
            for line in s.lines() {
                let line = line.trim();
                if line.is_empty() { continue; }
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                if parts.len() == 2 {
                    pkgs.push((parts[0].into(), parts[1].into(), "dpkg".into()));
                }
            }
        }
        // rpm
        if let Some(s) = sections.get(1) {
            for line in s.lines() {
                let line = line.trim();
                if line.is_empty() { continue; }
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                if parts.len() == 2 {
                    pkgs.push((parts[0].into(), parts[1].into(), "rpm".into()));
                }
            }
        }
        // apk
        if let Some(s) = sections.get(2) {
            for line in s.lines() {
                let line = line.trim();
                if line.is_empty() { continue; }
                if let Some(nv) = line.split_whitespace().next() {
                    if let Some(i) = nv.rfind('-') {
                        pkgs.push((nv[..i].into(), nv[i + 1..].into(), "apk".into()));
                    }
                }
            }
        }
        pkgs
    }

    fn parse_packages(output: &str) -> Vec<Value> {
        let sections: Vec<&str> = output.split("---SEP---").collect();
        let mut upgradable = Vec::new();

        // apt: "package/suite version_new arch [upgradable from: version_old]"
        if let Some(apt) = sections.first() {
            for line in apt.trim().lines() {
                let line = line.trim();
                if line.is_empty() { continue; }
                // e.g. "libssl3t64/noble-updates 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]"
                let parts: Vec<&str> = line.splitn(2, '/').collect();
                let name = parts.first().unwrap_or(&"").to_string();
                let current = line
                    .split("upgradable from: ")
                    .nth(1)
                    .map(|s| s.trim_end_matches(']').trim())
                    .unwrap_or("");
                let available = line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("");
                if !name.is_empty() {
                    upgradable.push(serde_json::json!({
                        "name": name,
                        "current_version": current,
                        "available_version": available,
                        "manager": "apt",
                    }));
                }
            }
        }

        // yum: "package.arch  version  repo"
        if let Some(yum) = sections.get(1) {
            for line in yum.trim().lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let name_arch = parts[0];
                    let name = name_arch.rsplit('.').nth(1).unwrap_or(name_arch);
                    upgradable.push(serde_json::json!({
                        "name": name,
                        "current_version": "",
                        "available_version": parts[1],
                        "manager": "yum",
                    }));
                }
            }
        }

        // apk: "package-version < available"
        if let Some(apk) = sections.get(2) {
            for line in apk.trim().lines() {
                let parts: Vec<&str> = line.split('<').collect();
                if parts.len() == 2 {
                    let name = parts[0].trim().to_string();
                    let available = parts[1].trim().to_string();
                    upgradable.push(serde_json::json!({
                        "name": name,
                        "current_version": "",
                        "available_version": available,
                        "manager": "apk",
                    }));
                }
            }
        }

        let count = upgradable.len();
        vec![serde_json::json!({
            "upgradable_count": count,
            "packages": upgradable,
        })]
    }

    fn parse_logs(output: &str) -> Vec<Value> {
        let sections: Vec<&str> = output.split("---SEP---").collect();
        let mut logs = Vec::new();

        // Section 0: journalctl errors/critical
        if let Some(section) = sections.first() {
            for line in section.trim().lines() {
                if let Some(entry) = Self::parse_journal_line(line, "error") {
                    logs.push(entry);
                }
            }
        }

        // Section 1: journalctl warnings
        if let Some(section) = sections.get(1) {
            for line in section.trim().lines() {
                if let Some(entry) = Self::parse_journal_line(line, "warning") {
                    logs.push(entry);
                }
            }
        }

        // Section 2: dmesg errors/warnings
        if let Some(section) = sections.get(2) {
            for line in section.trim().lines() {
                if line.is_empty() {
                    continue;
                }
                logs.push(json!({
                    "source": "dmesg",
                    "level": "warning",
                    "message": line.trim(),
                }));
            }
        }

        // Section 3: auth.log / sshd
        if let Some(section) = sections.get(3) {
            for line in section.trim().lines() {
                if line.is_empty() {
                    continue;
                }
                let level = if line.contains("Failed") || line.contains("error") || line.contains("Invalid") {
                    "error"
                } else {
                    "info"
                };
                logs.push(json!({
                    "source": "auth",
                    "level": level,
                    "message": line.trim(),
                }));
            }
        }

        // Aggregate: count by source and level for rule evaluation
        let total = logs.len();
        let error_count = logs.iter().filter(|l| l["level"] == "error").count();
        let warning_count = logs.iter().filter(|l| l["level"] == "warning").count();
        let auth_errors = logs.iter().filter(|l| l["source"] == "auth" && l["level"] == "error").count();
        let dmesg_count = logs.iter().filter(|l| l["source"] == "dmesg").count();

        // Return both summary (for rules) and entries (for detail)
        let summary = json!({
            "total_entries": total,
            "error_count": error_count,
            "warning_count": warning_count,
            "auth_error_count": auth_errors,
            "dmesg_count": dmesg_count,
            "entries": logs,
        });

        vec![summary]
    }

    fn parse_kubelet_config(output: &str) -> Vec<Value> {
        let sections: Vec<&str> = output.split("---SEP---").collect();
        let mut config = serde_json::Map::new();

        // Section 0: kubelet config.yaml (YAML key: value format)
        if let Some(section) = sections.first() {
            for line in section.trim().lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((key, value)) = line.split_once(':') {
                    let key = key.trim().to_string();
                    let value = value.trim().to_string();
                    if !value.is_empty() {
                        config.insert(key, Value::String(value));
                    }
                }
            }
        }

        // Section 1: kubelet process arguments
        if let Some(section) = sections.get(1) {
            for arg in section.split_whitespace() {
                if let Some(stripped) = arg.strip_prefix("--") {
                    if let Some((key, value)) = stripped.split_once('=') {
                        config.insert(
                            format!("arg_{}", key.replace('-', "_")),
                            Value::String(value.to_string()),
                        );
                    } else {
                        config.insert(
                            format!("arg_{}", stripped.replace('-', "_")),
                            Value::String("true".to_string()),
                        );
                    }
                }
            }
        }

        // Section 2: kubelet file permissions
        if let Some(section) = sections.get(2) {
            let mut files = serde_json::Map::new();
            for line in section.trim().lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let path = parts[0];
                    let short = path.rsplit('/').next().unwrap_or(path);
                    files.insert(
                        format!("{}_mode", short.replace('.', "_")),
                        Value::String(parts[1].to_string()),
                    );
                    files.insert(
                        format!("{}_owner", short.replace('.', "_")),
                        Value::String(parts[2].to_string()),
                    );
                }
            }
            config.extend(files);
        }

        // Section 3: kubelet version
        if let Some(section) = sections.get(3) {
            let version = section.trim();
            if !version.is_empty() {
                config.insert("kubelet_version".to_string(), Value::String(version.to_string()));
            }
        }

        // If kubelet is not installed (no version, no config file, no process args beyond defaults),
        // return empty list so rules don't evaluate on missing data.
        let has_kubelet = config.contains_key("kubelet_version")
            || config.keys().any(|k| k.ends_with("_mode") || k.ends_with("_owner"))
            || config.keys().filter(|k| k.starts_with("arg_")).count() > 2;

        if !has_kubelet {
            return vec![];
        }

        vec![Value::Object(config)]
    }

    fn parse_k8s_master_config(output: &str) -> Vec<Value> {
        let sections: Vec<&str> = output.split("---SEP---").collect();
        let mut config = serde_json::Map::new();

        // Section 0: kube-apiserver process arguments
        if let Some(section) = sections.first() {
            for arg in section.split_whitespace() {
                if let Some(stripped) = arg.strip_prefix("--") {
                    if let Some((key, value)) = stripped.split_once('=') {
                        config.insert(
                            format!("apiserver_{}", key.replace('-', "_")),
                            Value::String(value.to_string()),
                        );
                    } else {
                        config.insert(
                            format!("apiserver_{}", stripped.replace('-', "_")),
                            Value::String("true".to_string()),
                        );
                    }
                }
            }
        }

        // Section 1: kube-controller-manager process arguments
        if let Some(section) = sections.get(1) {
            for arg in section.split_whitespace() {
                if let Some(stripped) = arg.strip_prefix("--") {
                    if let Some((key, value)) = stripped.split_once('=') {
                        config.insert(
                            format!("controller_{}", key.replace('-', "_")),
                            Value::String(value.to_string()),
                        );
                    } else {
                        config.insert(
                            format!("controller_{}", stripped.replace('-', "_")),
                            Value::String("true".to_string()),
                        );
                    }
                }
            }
        }

        // Section 2: kube-scheduler process arguments
        if let Some(section) = sections.get(2) {
            for arg in section.split_whitespace() {
                if let Some(stripped) = arg.strip_prefix("--") {
                    if let Some((key, value)) = stripped.split_once('=') {
                        config.insert(
                            format!("scheduler_{}", key.replace('-', "_")),
                            Value::String(value.to_string()),
                        );
                    } else {
                        config.insert(
                            format!("scheduler_{}", stripped.replace('-', "_")),
                            Value::String("true".to_string()),
                        );
                    }
                }
            }
        }

        // Section 3: etcd process arguments
        if let Some(section) = sections.get(3) {
            for arg in section.split_whitespace() {
                if let Some(stripped) = arg.strip_prefix("--") {
                    if let Some((key, value)) = stripped.split_once('=') {
                        config.insert(
                            format!("etcd_{}", key.replace('-', "_")),
                            Value::String(value.to_string()),
                        );
                    } else {
                        config.insert(
                            format!("etcd_{}", stripped.replace('-', "_")),
                            Value::String("true".to_string()),
                        );
                    }
                }
            }
        }

        // Section 4: control plane file permissions
        if let Some(section) = sections.get(4) {
            for line in section.trim().lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 {
                    let path = parts[0];
                    let short = path.rsplit('/').next().unwrap_or(path);
                    config.insert(
                        format!("{}_mode", short.replace(['.', '-'], "_")),
                        Value::String(parts[1].to_string()),
                    );
                    config.insert(
                        format!("{}_owner", short.replace(['.', '-'], "_")),
                        Value::String(parts[2].to_string()),
                    );
                }
            }
        }

        // If K8s control plane is not installed, return empty.
        let has_k8s = config.keys().any(|k| {
            k.starts_with("apiserver_") && k != "apiserver_version"
                || k.starts_with("etcd_")
                || k.ends_with(".yaml_mode")
                || k.ends_with("_yaml_mode")
        });

        if !has_k8s {
            return vec![];
        }

        vec![Value::Object(config)]
    }

    fn parse_journal_line(line: &str, default_level: &str) -> Option<Value> {
        let line = line.trim();
        if line.is_empty() || line.starts_with("--") || line.starts_with("Hint:") || line.starts_with("No entries") {
            return None;
        }
        // journalctl short-iso: "2025-01-01T12:00:00+0000 hostname unit[pid]: message"
        let parts: Vec<&str> = line.splitn(4, ' ').collect();
        if parts.len() >= 4 {
            Some(json!({
                "source": "journal",
                "level": default_level,
                "timestamp": parts[0],
                "host": parts[1],
                "unit": parts[2].trim_end_matches(':'),
                "message": parts[3..].join(" "),
            }))
        } else {
            Some(json!({
                "source": "journal",
                "level": default_level,
                "message": line,
            }))
        }
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
                "sudo sshd -T 2>/dev/null || sshd -T 2>/dev/null || cat /etc/ssh/sshd_config",
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
            "packages" => {
                let output = self.exec(
                    "apt list --upgradable 2>/dev/null | tail -n +2; \
                     echo '---SEP---'; \
                     yum check-update 2>/dev/null | awk 'NF==3{print $1,$2,$3}'; \
                     echo '---SEP---'; \
                     apk version -l '<' 2>/dev/null | tail -n +2"
                ).await?;
                return Ok(Self::parse_packages(&output));
            }
            "packages_cve" => {
                return self.gather_packages_cve().await;
            }
            "logs" => {
                let output = self.exec(
                    "journalctl --no-pager -n 200 --output=short-iso -p err..emerg 2>/dev/null; \
                     echo '---SEP---'; \
                     journalctl --no-pager -n 100 --output=short-iso -p warning 2>/dev/null; \
                     echo '---SEP---'; \
                     dmesg --level=err,warn -T 2>/dev/null | tail -100; \
                     echo '---SEP---'; \
                     tail -200 /var/log/auth.log 2>/dev/null || journalctl -u sshd --no-pager -n 200 --output=short-iso 2>/dev/null"
                ).await?;
                return Ok(Self::parse_logs(&output));
            }
            "kubelet_config" => {
                let output = self.exec(
                    "cat /var/lib/kubelet/config.yaml 2>/dev/null || cat /etc/kubernetes/kubelet.conf 2>/dev/null; \
                     echo '---SEP---'; \
                     ps aux | grep '[k]ubelet' | sed 's/.*kubelet//' 2>/dev/null; \
                     echo '---SEP---'; \
                     stat -c '%n %a %U %G' \
                       /var/lib/kubelet/config.yaml \
                       /etc/kubernetes/kubelet.conf \
                       /etc/kubernetes/pki/ca.crt \
                       /var/lib/kubelet/pki/ \
                       2>/dev/null; \
                     echo '---SEP---'; \
                     kubelet --version 2>/dev/null | awk '{print $2}'"
                ).await?;
                return Ok(Self::parse_kubelet_config(&output));
            }
            "k8s_master_config" => {
                let output = self.exec(
                    "ps aux | grep '[k]ube-apiserver' | sed 's/.*kube-apiserver//' 2>/dev/null; \
                     echo '---SEP---'; \
                     ps aux | grep '[k]ube-controller-manager' | sed 's/.*kube-controller-manager//' 2>/dev/null; \
                     echo '---SEP---'; \
                     ps aux | grep '[k]ube-scheduler' | sed 's/.*kube-scheduler//' 2>/dev/null; \
                     echo '---SEP---'; \
                     ps aux | grep '[e]tcd' | grep -v 'kube' | sed 's/.*etcd//' 2>/dev/null; \
                     echo '---SEP---'; \
                     stat -c '%n %a %U %G' \
                       /etc/kubernetes/manifests/kube-apiserver.yaml \
                       /etc/kubernetes/manifests/kube-controller-manager.yaml \
                       /etc/kubernetes/manifests/kube-scheduler.yaml \
                       /etc/kubernetes/manifests/etcd.yaml \
                       /etc/kubernetes/admin.conf \
                       /etc/kubernetes/scheduler.conf \
                       /etc/kubernetes/controller-manager.conf \
                       /etc/kubernetes/pki/ \
                       /var/lib/etcd/ \
                       2>/dev/null"
                ).await?;
                return Ok(Self::parse_k8s_master_config(&output));
            }
            "system_stats" => {
                let output = self.exec(
                    "C1=$(head -1 /proc/stat); sleep 1; C2=$(head -1 /proc/stat); \
                     echo \"$C1\"; echo '---SEP---'; echo \"$C2\"; echo '---SEP---'; \
                     cat /proc/meminfo; echo '---SEP---'; \
                     df -k /; echo '---SEP---'; \
                     cat /proc/loadavg; echo '---SEP---'; \
                     ls -d /proc/[0-9]* 2>/dev/null | wc -l; echo '---SEP---'; \
                     cut -d' ' -f1 /proc/uptime; echo '---SEP---'; \
                     cat /proc/net/dev; echo '---SEP---'; \
                     cat /proc/diskstats; echo '---SEP---'; \
                     cat /proc/sys/fs/file-nr; echo '---SEP---'; \
                     ss -s 2>/dev/null || cat /proc/net/sockstat; echo '---SEP---'; \
                     cat /proc/vmstat 2>/dev/null | grep -E '^(pgpgin|pgpgout|pswpin|pswpout)'"
                ).await?;
                return Ok(Self::parse_system_stats(&output));
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

    #[test]
    fn test_parse_packages_apt() {
        let output = "libssl3t64/noble-updates 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]\n\
                       openssh-server/noble-updates 1:9.6p1-3ubuntu13.5 amd64 [upgradable from: 1:9.6p1-3ubuntu13.4]\n\
                       curl/noble-updates 8.5.0-2ubuntu10.6 amd64 [upgradable from: 8.5.0-2ubuntu10.4]\n\
                       ---SEP---\n\
                       ---SEP---\n";
        let result = SshProvider::parse_packages(output);
        assert_eq!(result.len(), 1);
        let pkg = &result[0];
        assert_eq!(pkg["upgradable_count"], 3);
        let packages = pkg["packages"].as_array().unwrap();
        assert_eq!(packages[0]["name"], "libssl3t64");
        assert_eq!(packages[0]["available_version"], "3.0.13-0ubuntu3.5");
        assert_eq!(packages[0]["current_version"], "3.0.13-0ubuntu3.4");
        assert_eq!(packages[0]["manager"], "apt");
        assert_eq!(packages[1]["name"], "openssh-server");
    }

    #[test]
    fn test_parse_packages_empty() {
        let output = "---SEP---\n---SEP---\n";
        let result = SshProvider::parse_packages(output);
        assert_eq!(result[0]["upgradable_count"], 0);
        assert!(result[0]["packages"].as_array().unwrap().is_empty());
    }
}

/// Map distro package names to CVE product names.
/// Use EXACT match (not prefix) to avoid false positives like
/// python3-certifi matching python3 → inheriting python's CVEs.
fn normalize_package_name(pkg: &str) -> String {
    let mappings: &[(&str, &str)] = &[
        // Exact package names → CVE product names
        ("openssl", "openssl"), ("libssl3t64", "openssl"), ("libssl3", "openssl"),
        ("libssl-dev", "openssl"), ("openssl-provider-legacy", "openssl"),
        ("openssh-server", "openssh"), ("openssh-client", "openssh"),
        ("openssh-sftp-server", "openssh"), ("openssh", "openssh"),
        ("nginx", "nginx"), ("nginx-common", "nginx"), ("nginx-core", "nginx"),
        ("apache2", "http_server"), ("httpd", "http_server"),
        ("curl", "curl"),
        ("libcurl4", "curl"), ("libcurl3", "curl"),
        ("libcurl4t64", "curl"), ("libcurl3t64", "curl"),
        ("libcurl3-gnutls", "curl"), ("libcurl3t64-gnutls", "curl"),
        ("libcurl4-gnutls-dev", "curl"),
        ("wget", "wget"),
        ("bind9", "bind"), ("bind9-host", "bind"), ("bind9-libs", "bind"),
        ("bind9-dnsutils", "bind"),
        ("postgresql", "postgresql"), ("postgresql-17", "postgresql"),
        ("postgresql-client", "postgresql"), ("libpq5", "postgresql"),
        ("libpq-dev", "postgresql"),
        ("mysql-server", "mysql"), ("mysql-client", "mysql"),
        ("mariadb-server", "mariadb"), ("mariadb-client", "mariadb"),
        ("redis", "redis"), ("redis-server", "redis"),
        ("mongodb", "mongodb"),
        ("docker.io", "docker"), ("docker-ce", "docker"), ("docker", "docker"),
        ("containerd", "containerd"), ("containerd.io", "containerd"), ("runc", "runc"),
        ("sudo", "sudo"), ("git", "git"), ("git-man", "git"),
        ("python3", "python"), ("python3-minimal", "python"),
        ("python2", "python"),
        ("nodejs", "node.js"), ("php", "php"),
        ("openjdk-17-jdk", "jdk"), ("openjdk-17-jre", "jdk"), ("openjdk", "jdk"),
        ("ruby", "ruby"),
        ("vim", "vim"), ("vim-common", "vim"), ("vim-tiny", "vim"),
        ("samba", "samba"), ("samba-common", "samba"),
        ("postfix", "postfix"), ("dovecot", "dovecot"),
        ("squid", "squid"), ("haproxy", "haproxy"),
        ("systemd", "systemd"), ("systemd-sysv", "systemd"),
        ("systemd-timesyncd", "systemd"),
        ("libc6", "glibc"), ("glibc", "glibc"),
        ("zlib1g", "zlib"), ("zlib1g-dev", "zlib"),
        ("libxml2", "libxml2"), ("libxml2-dev", "libxml2"),
        ("sqlite3", "sqlite"), ("libsqlite3-0", "sqlite"),
        ("tar", "tar"), ("gnupg", "gnupg"),
        ("libssh2-1t64", "libssh2"), ("libssh2-1", "libssh2"),
    ];
    let lower = pkg.to_lowercase();
    for (name, product) in mappings {
        if lower == *name {
            return product.to_string();
        }
    }
    // No mapping — return as-is (exact match against CVE DB)
    lower
}

fn severity_from_score(score: f64) -> &'static str {
    if score >= 9.0 { "CRITICAL" }
    else if score >= 7.0 { "HIGH" }
    else if score >= 4.0 { "MEDIUM" }
    else if score > 0.0 { "LOW" }
    else { "NONE" }
}
