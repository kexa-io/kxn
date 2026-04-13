//! Local SQLite CVE database — synced from NVD, CISA KEV, and EPSS public feeds.
//!
//! Usage:
//!   let db = CveDb::open_or_create()?;
//!   db.sync_kev(&client).await?;
//!   db.sync_epss(&client).await?;
//!   db.sync_nvd(&client, None).await?;   // full sync first time
//!   let cves = db.lookup_package("openssl", "3.0.2", "Debian:12")?;

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::path::PathBuf;
use tracing::{debug, info, warn};

const SCHEMA_VERSION: u32 = 1;

pub struct CveDb {
    conn: Connection,
}

impl CveDb {
    /// Open (or create) the CVE database at ~/.cache/kxn/cve.sqlite
    pub fn open_or_create() -> Result<Self, String> {
        let path = db_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create cache dir: {}", e))?;
        }
        let conn = Connection::open(&path)
            .map_err(|e| format!("Cannot open CVE DB: {}", e))?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| format!("PRAGMA: {}", e))?;

        let db = Self { conn };
        db.ensure_schema()?;
        Ok(db)
    }

    /// Open read-only (for scans). Returns None if DB doesn't exist yet.
    pub fn open_readonly() -> Option<Self> {
        let path = db_path();
        if !path.exists() {
            return None;
        }
        let conn = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .ok()?;
        Some(Self { conn })
    }

    fn ensure_schema(&self) -> Result<(), String> {
        self.conn
            .execute_batch(
                "
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cves (
                id          TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                cvss_score  REAL NOT NULL DEFAULT 0.0,
                cvss_vector TEXT NOT NULL DEFAULT '',
                severity    TEXT NOT NULL DEFAULT 'UNKNOWN',
                published   TEXT NOT NULL DEFAULT '',
                modified    TEXT NOT NULL DEFAULT '',
                weaknesses  TEXT NOT NULL DEFAULT '[]',
                source      TEXT NOT NULL DEFAULT 'nvd'
            );

            CREATE TABLE IF NOT EXISTS affected (
                cve_id        TEXT NOT NULL,
                vendor        TEXT NOT NULL DEFAULT '',
                product       TEXT NOT NULL DEFAULT '',
                version_start TEXT NOT NULL DEFAULT '',
                version_end   TEXT NOT NULL DEFAULT '',
                cpe           TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (cve_id) REFERENCES cves(id)
            );
            CREATE INDEX IF NOT EXISTS idx_affected_vendor_product
                ON affected(vendor, product);
            CREATE INDEX IF NOT EXISTS idx_affected_cve
                ON affected(cve_id);

            CREATE TABLE IF NOT EXISTS kev (
                cve_id          TEXT PRIMARY KEY,
                vendor          TEXT NOT NULL DEFAULT '',
                product         TEXT NOT NULL DEFAULT '',
                date_added      TEXT NOT NULL DEFAULT '',
                due_date        TEXT NOT NULL DEFAULT '',
                required_action TEXT NOT NULL DEFAULT '',
                ransomware      TEXT NOT NULL DEFAULT 'Unknown',
                description     TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS epss (
                cve_id     TEXT PRIMARY KEY,
                score      REAL NOT NULL DEFAULT 0.0,
                percentile REAL NOT NULL DEFAULT 0.0,
                date       TEXT NOT NULL DEFAULT ''
            );

            -- Distro security advisories (Debian/Ubuntu/RHEL)
            -- Indicates if a CVE is fixed/open/ignored in a specific distro release
            CREATE TABLE IF NOT EXISTS distro_fixes (
                distro        TEXT NOT NULL,
                release       TEXT NOT NULL,
                package       TEXT NOT NULL,
                cve_id        TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'open',
                fixed_version TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (distro, release, package, cve_id)
            );
            CREATE INDEX IF NOT EXISTS idx_distro_fixes_lookup
                ON distro_fixes(distro, release, package);
            ",
            )
            .map_err(|e| format!("Schema creation failed: {}", e))?;

        // Set schema version
        self.conn
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?1)",
                params![SCHEMA_VERSION.to_string()],
            )
            .map_err(|e| format!("Meta: {}", e))?;

        Ok(())
    }

    /// Sync CISA KEV catalog (full replace, small dataset ~1200 entries)
    pub async fn sync_kev(&self, client: &reqwest::Client) -> Result<usize, String> {
        let url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
        info!("Syncing CISA KEV from {}", url);

        let data: Value = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("KEV fetch: {}", e))?
            .json()
            .await
            .map_err(|e| format!("KEV parse: {}", e))?;

        let vulns = data
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .ok_or("KEV: missing vulnerabilities array")?;

        self.conn
            .execute("DELETE FROM kev", [])
            .map_err(|e| format!("KEV clear: {}", e))?;

        let mut count = 0;
        for v in vulns {
            let cve_id = v.get("cveID").and_then(|v| v.as_str()).unwrap_or("");
            if cve_id.is_empty() {
                continue;
            }
            self.conn
                .execute(
                    "INSERT OR REPLACE INTO kev (cve_id, vendor, product, date_added, due_date, required_action, ransomware, description) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        cve_id,
                        v.get("vendorProject").and_then(|v| v.as_str()).unwrap_or(""),
                        v.get("product").and_then(|v| v.as_str()).unwrap_or(""),
                        v.get("dateAdded").and_then(|v| v.as_str()).unwrap_or(""),
                        v.get("dueDate").and_then(|v| v.as_str()).unwrap_or(""),
                        v.get("requiredAction").and_then(|v| v.as_str()).unwrap_or(""),
                        v.get("knownRansomwareCampaignUse").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                        v.get("shortDescription").and_then(|v| v.as_str()).unwrap_or(""),
                    ],
                )
                .map_err(|e| format!("KEV insert: {}", e))?;
            count += 1;
        }

        self.set_meta("kev_last_sync", &chrono::Utc::now().to_rfc3339())?;
        info!(count, "CISA KEV synced");
        Ok(count)
    }

    /// Sync EPSS scores (top 5000 by score — most likely to be exploited)
    pub async fn sync_epss(&self, client: &reqwest::Client) -> Result<usize, String> {
        let url = "https://api.first.org/data/v1/epss?order=!epss&limit=5000";
        info!("Syncing EPSS top scores from {}", url);

        let data: Value = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("EPSS fetch: {}", e))?
            .json()
            .await
            .map_err(|e| format!("EPSS parse: {}", e))?;

        let entries = data
            .get("data")
            .and_then(|v| v.as_array())
            .ok_or("EPSS: missing data array")?;

        self.conn
            .execute("DELETE FROM epss", [])
            .map_err(|e| format!("EPSS clear: {}", e))?;

        let mut count = 0;
        for e in entries {
            let cve_id = e.get("cve").and_then(|v| v.as_str()).unwrap_or("");
            if cve_id.is_empty() {
                continue;
            }
            let score = parse_f64(e.get("epss"));
            let percentile = parse_f64(e.get("percentile"));
            let date = e
                .get("date")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            self.conn
                .execute(
                    "INSERT OR REPLACE INTO epss (cve_id, score, percentile, date) VALUES (?1, ?2, ?3, ?4)",
                    params![cve_id, score, percentile, date],
                )
                .map_err(|e| format!("EPSS insert: {}", e))?;
            count += 1;
        }

        self.set_meta("epss_last_sync", &chrono::Utc::now().to_rfc3339())?;
        info!(count, "EPSS scores synced");
        Ok(count)
    }

    /// Sync Debian security tracker. Covers all Debian releases.
    /// Format: {"package": {"CVE-XXXX-YYYY": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "..."}}}}}
    pub async fn sync_debian_tracker(&self, client: &reqwest::Client) -> Result<usize, String> {
        let url = "https://security-tracker.debian.org/tracker/data/json";
        info!("Syncing Debian security tracker from {}", url);

        let resp = client
            .get(url)
            .header("User-Agent", "kxn")
            .send()
            .await
            .map_err(|e| format!("Debian fetch: {}", e))?;

        let bytes = resp.bytes().await
            .map_err(|e| format!("Debian body: {}", e))?;

        // Size limit (protect against malicious/huge responses)
        if bytes.len() > 200 * 1024 * 1024 {
            return Err("Debian tracker response too large (>200MB)".into());
        }

        let data: Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Debian parse: {}", e))?;

        let pkgs = data.as_object()
            .ok_or("Debian tracker: root not an object")?;

        // Clear existing Debian data
        self.conn
            .execute("DELETE FROM distro_fixes WHERE distro = 'debian'", [])
            .map_err(|e| format!("Debian clear: {}", e))?;

        let tx = self.conn.unchecked_transaction()
            .map_err(|e| format!("Debian tx: {}", e))?;

        let mut count = 0;
        for (package, cves) in pkgs {
            let cves = match cves.as_object() {
                Some(c) => c,
                None => continue,
            };
            for (cve_id, details) in cves {
                if !cve_id.starts_with("CVE-") {
                    continue;
                }
                let releases = match details.get("releases").and_then(|r| r.as_object()) {
                    Some(r) => r,
                    None => continue,
                };
                for (release, info) in releases {
                    let status = info.get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("open");
                    let fixed_version = info.get("fixed_version")
                        .and_then(|s| s.as_str())
                        .unwrap_or("");

                    tx.execute(
                        "INSERT OR REPLACE INTO distro_fixes \
                         (distro, release, package, cve_id, status, fixed_version) \
                         VALUES ('debian', ?1, ?2, ?3, ?4, ?5)",
                        params![release, package, cve_id, status, fixed_version],
                    ).map_err(|e| format!("Debian insert: {}", e))?;
                    count += 1;
                }
            }
        }

        tx.commit().map_err(|e| format!("Debian commit: {}", e))?;
        self.set_meta("debian_last_sync", &chrono::Utc::now().to_rfc3339())?;
        info!(count, "Debian security tracker synced");
        Ok(count)
    }

    /// Sync Ubuntu security data via OVAL XML feed (authoritative Canonical source).
    /// Fetches per-release OVAL XML from security-metadata.canonical.com.
    pub async fn sync_ubuntu_tracker(&self, client: &reqwest::Client) -> Result<usize, String> {
        info!("Syncing Ubuntu OVAL");

        self.conn
            .execute("DELETE FROM distro_fixes WHERE distro = 'ubuntu'", [])
            .map_err(|e| format!("Ubuntu clear: {}", e))?;

        let releases = ["bionic", "focal", "jammy", "noble"];
        let mut total_count = 0;

        for release in &releases {
            let url = format!(
                "https://security-metadata.canonical.com/oval/com.ubuntu.{}.cve.oval.xml.bz2",
                release
            );
            let resp = match client.get(&url).header("User-Agent", "kxn").send().await {
                Ok(r) => r,
                Err(_) => continue,
            };
            if !resp.status().is_success() { continue; }
            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(_) => continue,
            };

            // Decompress bz2
            use std::io::Read;
            let mut decoder = bzip2::read::BzDecoder::new(&bytes[..]);
            let mut xml = String::new();
            if decoder.read_to_string(&mut xml).is_err() {
                continue;
            }

            let count = Self::parse_ubuntu_oval(&self.conn, release, &xml)?;
            info!(release = %release, count, "Ubuntu OVAL release parsed");
            total_count += count;
        }

        self.set_meta("ubuntu_last_sync", &chrono::Utc::now().to_rfc3339())?;
        info!(count = total_count, "Ubuntu OVAL synced");
        Ok(total_count)
    }

    /// Parse Ubuntu OVAL XML (regex-based, pragmatic).
    /// Extract: test_id → object_ref+state_ref, object_id → package (from comment),
    /// state_id → fixed_version (from <evr>), and definitions → CVEs + test refs.
    fn parse_ubuntu_oval(
        conn: &rusqlite::Connection,
        release: &str,
        xml: &str,
    ) -> Result<usize, String> {
        use regex::Regex;
        use std::collections::HashMap;

        // Object id → package name (extracted from comment "The 'pkgname' package binaries")
        let re_object = Regex::new(
            r#"dpkginfo_object\s+id="([^"]+)"[^>]*comment="The '([^']+)' package"#,
        ).map_err(|e| format!("regex: {}", e))?;
        let mut objects: HashMap<String, String> = HashMap::new();
        for cap in re_object.captures_iter(xml) {
            objects.insert(cap[1].to_string(), cap[2].to_string());
        }

        // State id → fixed_version (from <evr>0:VERSION</evr>)
        let re_state = Regex::new(
            r#"dpkginfo_state\s+id="([^"]+)"[^>]*>\s*<[^>]*:evr[^>]*>([^<]+)</"#,
        ).map_err(|e| format!("regex: {}", e))?;
        let mut states: HashMap<String, String> = HashMap::new();
        for cap in re_state.captures_iter(xml) {
            // Strip epoch (0:) prefix
            let ver = cap[2].trim().to_string();
            let ver = if let Some(idx) = ver.find(':') {
                ver[idx+1..].to_string()
            } else {
                ver
            };
            states.insert(cap[1].to_string(), ver);
        }

        // Test id → (object_ref, state_ref). State may be absent.
        // Match <linux-def:dpkginfo_test id="..."> ... <linux-def:object object_ref="..."/> ... [<linux-def:state state_ref="..."/>] ... </linux-def:dpkginfo_test>
        let re_test = Regex::new(
            r#"(?s)dpkginfo_test\s+id="([^"]+)"[^>]*>(.*?)</[^>]*:dpkginfo_test>"#,
        ).map_err(|e| format!("regex: {}", e))?;
        let re_obj_ref = Regex::new(r#"object_ref="([^"]+)""#).unwrap();
        let re_ste_ref = Regex::new(r#"state_ref="([^"]+)""#).unwrap();
        let mut tests: HashMap<String, (String, String)> = HashMap::new();
        for cap in re_test.captures_iter(xml) {
            let test_id = cap[1].to_string();
            let body = &cap[2];
            let obj_ref = re_obj_ref.captures(body)
                .map(|c| c[1].to_string()).unwrap_or_default();
            let ste_ref = re_ste_ref.captures(body)
                .map(|c| c[1].to_string()).unwrap_or_default();
            tests.insert(test_id, (obj_ref, ste_ref));
        }

        // Definitions: extract CVE references + test refs
        let re_definition = Regex::new(
            r#"(?s)<definition\s+class="vulnerability"[^>]*>(.*?)</definition>"#,
        ).map_err(|e| format!("regex: {}", e))?;
        let re_cve = Regex::new(
            r#"<reference\s+source="CVE"\s+ref_id="(CVE-[^"]+)""#,
        ).unwrap();
        let re_criterion = Regex::new(r#"test_ref="([^"]+)""#).unwrap();

        let tx = conn.unchecked_transaction()
            .map_err(|e| format!("Ubuntu tx: {}", e))?;

        let mut count = 0;
        for def_cap in re_definition.captures_iter(xml) {
            let body = &def_cap[1];
            let cves: Vec<String> = re_cve.captures_iter(body)
                .map(|c| c[1].to_string()).collect();
            if cves.is_empty() { continue; }
            let test_refs: Vec<String> = re_criterion.captures_iter(body)
                .map(|c| c[1].to_string()).collect();

            for cve_id in &cves {
                for test_id in &test_refs {
                    let (obj_ref, ste_ref) = match tests.get(test_id) {
                        Some(t) => t,
                        None => continue,
                    };
                    let pkg = match objects.get(obj_ref) {
                        Some(p) => p, None => continue,
                    };
                    // State may be absent (test just checks if package exists) → skip those
                    let ver = match states.get(ste_ref) {
                        Some(v) => v.as_str(), None => continue,
                    };
                    tx.execute(
                        "INSERT OR REPLACE INTO distro_fixes \
                         (distro, release, package, cve_id, status, fixed_version) \
                         VALUES ('ubuntu', ?1, ?2, ?3, 'resolved', ?4)",
                        params![release, pkg, cve_id, ver],
                    ).map_err(|e| format!("Ubuntu insert: {}", e))?;
                    count += 1;
                }
            }
        }

        tx.commit().map_err(|e| format!("Ubuntu commit: {}", e))?;
        Ok(count)
    }

    /// Sync Alpine Linux security database.
    /// Source: https://secdb.alpinelinux.org/{release}/{repo}.json for each release/repo.
    pub async fn sync_alpine_tracker(&self, client: &reqwest::Client) -> Result<usize, String> {
        info!("Syncing Alpine secdb");

        self.conn
            .execute("DELETE FROM distro_fixes WHERE distro = 'alpine'", [])
            .map_err(|e| format!("Alpine clear: {}", e))?;

        // Current supported Alpine releases (could be fetched dynamically)
        let releases = ["v3.18", "v3.19", "v3.20", "v3.21", "edge"];
        let repos = ["main", "community"];

        let tx = self.conn.unchecked_transaction()
            .map_err(|e| format!("Alpine tx: {}", e))?;

        let mut count = 0;
        for release in &releases {
            for repo in &repos {
                let url = format!("https://secdb.alpinelinux.org/{}/{}.json", release, repo);
                let resp = match client.get(&url).header("User-Agent", "kxn").send().await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if !resp.status().is_success() { continue; }
                let data: Value = match resp.json().await {
                    Ok(d) => d,
                    Err(_) => continue,
                };

                let packages = data.get("packages").and_then(|p| p.as_array());
                let packages = match packages { Some(p) => p, None => continue };

                for pkg_entry in packages {
                    let pkg = match pkg_entry.get("pkg") { Some(p) => p, None => continue };
                    let name = match pkg.get("name").and_then(|n| n.as_str()) {
                        Some(n) => n, None => continue,
                    };
                    let secfixes = match pkg.get("secfixes").and_then(|s| s.as_object()) {
                        Some(s) => s, None => continue,
                    };
                    for (fixed_version, cves) in secfixes {
                        let cves_arr = match cves.as_array() { Some(c) => c, None => continue };
                        for cve_val in cves_arr {
                            let cve_id = match cve_val.as_str() { Some(s) => s, None => continue };
                            if !cve_id.starts_with("CVE-") { continue; }
                            tx.execute(
                                "INSERT OR REPLACE INTO distro_fixes \
                                 (distro, release, package, cve_id, status, fixed_version) \
                                 VALUES ('alpine', ?1, ?2, ?3, 'resolved', ?4)",
                                params![release.trim_start_matches('v'), name, cve_id, fixed_version],
                            ).map_err(|e| format!("Alpine insert: {}", e))?;
                            count += 1;
                        }
                    }
                }
            }
        }

        tx.commit().map_err(|e| format!("Alpine commit: {}", e))?;
        self.set_meta("alpine_last_sync", &chrono::Utc::now().to_rfc3339())?;
        info!(count, "Alpine secdb synced");
        Ok(count)
    }

    /// Check if a CVE is fixed in the given distro/release/package/version combo.
    /// Returns true if fixed (should skip), false if still vulnerable.
    pub fn is_cve_fixed(
        &self,
        distro: &str,
        release: &str,
        package: &str,
        current_version: &str,
        cve_id: &str,
    ) -> bool {
        let row: Result<(String, String), _> = self.conn.query_row(
            "SELECT status, fixed_version FROM distro_fixes \
             WHERE distro = ?1 AND release = ?2 AND package = ?3 AND cve_id = ?4",
            params![distro, release, package, cve_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );
        match row {
            Ok((status, fixed_version)) => {
                // Status variants: resolved, open, undetermined, not_affected, ignored
                match status.as_str() {
                    "resolved" => {
                        !fixed_version.is_empty()
                            && compare_deb_versions(current_version, &fixed_version) != std::cmp::Ordering::Less
                    }
                    "not_affected" | "ignored" => true,
                    _ => false,
                }
            }
            Err(_) => false, // no entry → use is_cve_applicable check instead
        }
    }

    /// Check if a CVE is tracked by Debian for ANY package in this release.
    /// If YES but not for our package → the CVE is for a different product/version → not applicable to us.
    /// If NO anywhere → we can't tell, return false (assume vulnerable).
    pub fn is_cve_applicable(
        &self,
        distro: &str,
        release: &str,
        cve_id: &str,
    ) -> bool {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM distro_fixes \
             WHERE distro = ?1 AND release = ?2 AND cve_id = ?3",
            params![distro, release, cve_id],
            |row| row.get(0),
        ).unwrap_or(0);
        count > 0
    }

    /// Sync NVD CVEs. If last_modified is None, fetches last 120 days.
    /// Pass last sync date for delta updates.
    pub async fn sync_nvd(
        &self,
        client: &reqwest::Client,
        api_key: Option<&str>,
    ) -> Result<usize, String> {
        let last_sync = self.get_meta("nvd_last_sync")?;
        // NVD API wants exactly: YYYY-MM-DDTHH:MM:SS.mmm (no timezone suffix)
        let nvd_fmt = "%Y-%m-%dT%H:%M:%S%.3f";
        let start = if let Some(ref ts) = last_sync {
            // Parse saved RFC3339 and reformat for NVD
            chrono::DateTime::parse_from_rfc3339(ts)
                .map(|dt| dt.format(nvd_fmt).to_string())
                .unwrap_or_else(|_| ts.clone())
        } else {
            let d = chrono::Utc::now() - chrono::Duration::days(120);
            d.format(nvd_fmt).to_string()
        };
        let end = chrono::Utc::now().format(nvd_fmt).to_string();

        info!(start = %start, "Syncing NVD CVEs");

        let mut total = 0;
        let mut start_index = 0;
        let page_size = 2000;
        let mut rate_limit_retries = 0u32;
        const MAX_RATE_LIMIT_RETRIES: u32 = 3;

        loop {
            let mut req = client
                .get("https://services.nvd.nist.gov/rest/json/cves/2.0")
                .query(&[
                    ("lastModStartDate", start.as_str()),
                    ("lastModEndDate", end.as_str()),
                    ("resultsPerPage", &page_size.to_string()),
                    ("startIndex", &start_index.to_string()),
                ]);

            if let Some(key) = api_key {
                req = req.header("apiKey", key);
            }

            let resp = req
                .send()
                .await
                .map_err(|e| format!("NVD fetch: {}", e))?;

            if resp.status().as_u16() == 403 {
                rate_limit_retries += 1;
                if rate_limit_retries > MAX_RATE_LIMIT_RETRIES {
                    return Err(format!(
                        "NVD rate limited {} times, giving up (try again later or use an API key)",
                        MAX_RATE_LIMIT_RETRIES
                    ));
                }
                warn!(attempt = rate_limit_retries, max = MAX_RATE_LIMIT_RETRIES, "NVD rate limited, waiting 30s");
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            }
            // Reset on successful request
            rate_limit_retries = 0;

            if !resp.status().is_success() {
                return Err(format!("NVD API {}", resp.status()));
            }

            let data: Value = resp
                .json()
                .await
                .map_err(|e| format!("NVD parse: {}", e))?;

            let total_results = data
                .get("totalResults")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let vulns = data
                .get("vulnerabilities")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            let page_count = vulns.len();
            debug!(page_count, start_index, total_results, "NVD page fetched");

            for vuln in &vulns {
                if let Some(cve) = vuln.get("cve") {
                    self.upsert_nvd_cve(cve)?;
                }
            }

            total += page_count;
            start_index += page_size;

            if start_index as u64 >= total_results || page_count == 0 {
                break;
            }

            // NVD rate limit: 5 requests per 30s without key, 50 with key
            let delay = if api_key.is_some() { 1 } else { 6 };
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }

        self.set_meta("nvd_last_sync", &end)?;
        info!(total, "NVD CVEs synced");
        Ok(total)
    }

    fn upsert_nvd_cve(&self, cve: &Value) -> Result<(), String> {
        let id = cve.get("id").and_then(|v| v.as_str()).unwrap_or("");
        if id.is_empty() {
            return Ok(());
        }

        let desc = cve
            .get("descriptions")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en"))
            })
            .and_then(|d| d.get("value"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let metrics = cve.get("metrics").unwrap_or(&Value::Null);
        let (cvss_score, severity, vector) = extract_best_cvss(metrics);

        let published = cve
            .get("published")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let modified = cve
            .get("lastModified")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let weaknesses: Vec<String> = cve
            .get("weaknesses")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|w| {
                        w.get("description")
                            .and_then(|d| d.as_array())
                            .and_then(|d| d.first())
                            .and_then(|d| d.get("value"))
                            .and_then(|v| v.as_str())
                            .map(String::from)
                    })
                    .collect()
            })
            .unwrap_or_default();

        self.conn
            .execute(
                "INSERT OR REPLACE INTO cves (id, description, cvss_score, cvss_vector, severity, published, modified, weaknesses) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![id, desc, cvss_score, vector, severity, published, modified, serde_json::to_string(&weaknesses).unwrap_or_default()],
            )
            .map_err(|e| format!("CVE upsert: {}", e))?;

        // Upsert affected products
        self.conn
            .execute("DELETE FROM affected WHERE cve_id = ?1", params![id])
            .map_err(|e| format!("Affected delete: {}", e))?;

        if let Some(configs) = cve.get("configurations").and_then(|v| v.as_array()) {
            for config in configs {
                if let Some(nodes) = config.get("nodes").and_then(|v| v.as_array()) {
                    for node in nodes {
                        if let Some(matches) =
                            node.get("cpeMatch").and_then(|v| v.as_array())
                        {
                            for m in matches {
                                let cpe = m
                                    .get("criteria")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let parts: Vec<&str> = cpe.split(':').collect();
                                if parts.len() >= 5 {
                                    let _ = self.conn.execute(
                                        "INSERT INTO affected (cve_id, vendor, product, version_start, version_end, cpe) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                        params![
                                            id,
                                            parts[3],
                                            parts[4],
                                            m.get("versionStartIncluding").and_then(|v| v.as_str()).unwrap_or(""),
                                            m.get("versionEndExcluding").and_then(|v| v.as_str()).unwrap_or(""),
                                            cpe,
                                        ],
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Lookup CVEs for a package by vendor/product name.
    /// Returns enriched JSON objects ready for rule evaluation.
    pub fn lookup_product(
        &self,
        vendor: &str,
        product: &str,
    ) -> Result<Vec<Value>, String> {
        let vendor_lower = vendor.to_lowercase();
        let product_lower = product.to_lowercase();

        // Single query with LEFT JOINs — no N+1
        let query = if vendor == "*" {
            "SELECT DISTINCT c.id, c.description, c.cvss_score, c.cvss_vector, c.severity,
                    c.published, c.modified, c.weaknesses,
                    CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as kev_listed,
                    COALESCE(e.score, 0.0) as epss_score,
                    COALESCE(e.percentile, 0.0) as epss_percentile
             FROM cves c
             JOIN affected a ON c.id = a.cve_id
             LEFT JOIN kev k ON c.id = k.cve_id
             LEFT JOIN epss e ON c.id = e.cve_id
             WHERE LOWER(a.product) = ?1
             ORDER BY c.cvss_score DESC
             LIMIT 50"
        } else {
            "SELECT DISTINCT c.id, c.description, c.cvss_score, c.cvss_vector, c.severity,
                    c.published, c.modified, c.weaknesses,
                    CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as kev_listed,
                    COALESCE(e.score, 0.0) as epss_score,
                    COALESCE(e.percentile, 0.0) as epss_percentile
             FROM cves c
             JOIN affected a ON c.id = a.cve_id
             LEFT JOIN kev k ON c.id = k.cve_id
             LEFT JOIN epss e ON c.id = e.cve_id
             WHERE LOWER(a.vendor) = ?1 AND LOWER(a.product) = ?2
             ORDER BY c.cvss_score DESC
             LIMIT 50"
        };

        let mut stmt = self.conn.prepare(query)
            .map_err(|e| format!("Query prepare: {}", e))?;

        type Row = (String, String, f64, String, String, String, String, String, i32, f64, f64);
        let mapper = |row: &rusqlite::Row| -> rusqlite::Result<Row> {
            Ok((
                row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?,
                row.get(8)?, row.get(9)?, row.get(10)?,
            ))
        };

        let rows: Vec<Row> = if vendor == "*" {
            stmt.query_map(params![product_lower], mapper)
                .map_err(|e| format!("Query: {}", e))?
                .filter_map(|r| r.ok())
                .collect()
        } else {
            stmt.query_map(params![vendor_lower, product_lower], mapper)
                .map_err(|e| format!("Query: {}", e))?
                .filter_map(|r| r.ok())
                .collect()
        };

        let mut results = Vec::new();
        for (id, desc, score, vector, severity, published, modified, weaknesses, kev_flag, epss_score, epss_percentile) in rows {
            let kev = kev_flag != 0;

            results.push(json!({
                "id": id,
                "description": desc,
                "cvss_score": score,
                "cvss_vector": vector,
                "severity": severity,
                "published": published,
                "modified": modified,
                "weaknesses": serde_json::from_str::<Value>(&weaknesses).unwrap_or(json!([])),
                "kev_listed": kev,
                "epss_score": epss_score,
                "epss_percentile": epss_percentile,
                "vendor": vendor,
                "product": product,
                "source": "local_db",
            }));
        }

        Ok(results)
    }

    /// Lookup CVEs by searching vendor OR product name (fuzzy)
    pub fn search(&self, keyword: &str) -> Result<Vec<Value>, String> {
        let kw = format!("%{}%", keyword.to_lowercase());

        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT c.id, c.description, c.cvss_score, c.severity, c.published
             FROM cves c
             JOIN affected a ON c.id = a.cve_id
             WHERE LOWER(a.vendor) LIKE ?1 OR LOWER(a.product) LIKE ?1
             ORDER BY c.cvss_score DESC
             LIMIT 100"
        ).map_err(|e| format!("Search prepare: {}", e))?;

        let rows = stmt
            .query_map(params![kw], |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "description": row.get::<_, String>(1)?,
                    "cvss_score": row.get::<_, f64>(2)?,
                    "severity": row.get::<_, String>(3)?,
                    "published": row.get::<_, String>(4)?,
                }))
            })
            .map_err(|e| format!("Search: {}", e))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Search collect: {}", e))
    }

    /// Get DB stats
    pub fn stats(&self) -> Result<Value, String> {
        let cve_count: u32 = self
            .conn
            .query_row("SELECT COUNT(*) FROM cves", [], |r| r.get(0))
            .map_err(|e| format!("Stats: {}", e))?;
        let kev_count: u32 = self
            .conn
            .query_row("SELECT COUNT(*) FROM kev", [], |r| r.get(0))
            .map_err(|e| format!("Stats: {}", e))?;
        let epss_count: u32 = self
            .conn
            .query_row("SELECT COUNT(*) FROM epss", [], |r| r.get(0))
            .map_err(|e| format!("Stats: {}", e))?;
        let affected_count: u32 = self
            .conn
            .query_row("SELECT COUNT(*) FROM affected", [], |r| r.get(0))
            .map_err(|e| format!("Stats: {}", e))?;

        let nvd_sync = self.get_meta("nvd_last_sync")?.unwrap_or_default();
        let kev_sync = self.get_meta("kev_last_sync")?.unwrap_or_default();
        let epss_sync = self.get_meta("epss_last_sync")?.unwrap_or_default();

        Ok(json!({
            "cves": cve_count,
            "affected_entries": affected_count,
            "kev_entries": kev_count,
            "epss_entries": epss_count,
            "nvd_last_sync": nvd_sync,
            "kev_last_sync": kev_sync,
            "epss_last_sync": epss_sync,
            "db_path": db_path().to_string_lossy(),
        }))
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(|e| format!("Meta set: {}", e))?;
        Ok(())
    }

    fn get_meta(&self, key: &str) -> Result<Option<String>, String> {
        match self.conn.query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![key],
            |row| row.get(0),
        ) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Meta get: {}", e)),
        }
    }
}

fn db_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("kxn")
        .join("cve.sqlite")
}

fn extract_best_cvss(metrics: &Value) -> (f64, String, String) {
    for key in ["cvssMetricV31", "cvssMetricV30"] {
        if let Some(arr) = metrics.get(key).and_then(|v| v.as_array()) {
            if let Some(m) = arr.first() {
                let cvss = m.get("cvssData").unwrap_or(&Value::Null);
                let score = cvss.get("baseScore").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let severity = cvss
                    .get("baseSeverity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN")
                    .to_uppercase();
                let vector = cvss
                    .get("vectorString")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                return (score, severity, vector);
            }
        }
    }
    (0.0, "UNKNOWN".to_string(), String::new())
}

fn parse_f64(v: Option<&Value>) -> f64 {
    v.and_then(|v| {
        v.as_f64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })
    .unwrap_or(0.0)
}

/// Simplified Debian-style version comparison.
/// Compares versions like "1.2.3-4" or "3.5.4-1~deb13u2".
/// Not 100% dpkg-compatible but handles the common cases.
pub fn compare_deb_versions(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    // Strip epoch (N:)
    let strip_epoch = |s: &str| -> String {
        if let Some(idx) = s.find(':') {
            s[idx+1..].to_string()
        } else {
            s.to_string()
        }
    };
    let a = strip_epoch(a);
    let b = strip_epoch(b);

    // Split into chunks of digits and non-digits
    fn tokenize(s: &str) -> Vec<(bool, String)> {
        let mut tokens = Vec::new();
        let mut current = String::new();
        let mut is_digit = s.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false);
        for c in s.chars() {
            let d = c.is_ascii_digit();
            if d == is_digit {
                current.push(c);
            } else {
                if !current.is_empty() {
                    tokens.push((is_digit, current.clone()));
                }
                current.clear();
                current.push(c);
                is_digit = d;
            }
        }
        if !current.is_empty() {
            tokens.push((is_digit, current));
        }
        tokens
    }

    let ta = tokenize(&a);
    let tb = tokenize(&b);

    for i in 0..ta.len().max(tb.len()) {
        let (da, sa) = ta.get(i).map(|(d, s)| (*d, s.as_str())).unwrap_or((false, ""));
        let (db, sb) = tb.get(i).map(|(d, s)| (*d, s.as_str())).unwrap_or((false, ""));

        if da && db {
            // Both numeric
            let na: u64 = sa.parse().unwrap_or(0);
            let nb: u64 = sb.parse().unwrap_or(0);
            match na.cmp(&nb) {
                Ordering::Equal => continue,
                o => return o,
            }
        } else {
            match sa.cmp(sb) {
                Ordering::Equal => continue,
                o => return o,
            }
        }
    }
    Ordering::Equal
}
