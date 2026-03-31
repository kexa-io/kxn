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
                warn!("NVD rate limited, waiting 30s");
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            }

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

        // When vendor is "*", search by product only
        let query = if vendor == "*" {
            "SELECT DISTINCT c.id, c.description, c.cvss_score, c.cvss_vector, c.severity, c.published, c.modified, c.weaknesses
             FROM cves c
             JOIN affected a ON c.id = a.cve_id
             WHERE LOWER(a.product) = ?1
             ORDER BY c.cvss_score DESC
             LIMIT 50"
        } else {
            "SELECT DISTINCT c.id, c.description, c.cvss_score, c.cvss_vector, c.severity, c.published, c.modified, c.weaknesses
             FROM cves c
             JOIN affected a ON c.id = a.cve_id
             WHERE LOWER(a.vendor) = ?1 AND LOWER(a.product) = ?2
             ORDER BY c.cvss_score DESC
             LIMIT 50"
        };

        let mut stmt = self.conn.prepare(query)
            .map_err(|e| format!("Query prepare: {}", e))?;

        type Row = (String, String, f64, String, String, String, String, String);
        let mapper = |row: &rusqlite::Row| -> rusqlite::Result<Row> {
            Ok((
                row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?,
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
        for (id, desc, score, vector, severity, published, modified, weaknesses) in rows {

            // Enrich with KEV
            let kev = self.is_kev(&id)?;

            // Enrich with EPSS
            let (epss_score, epss_percentile) = self.get_epss(&id)?;

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

    fn is_kev(&self, cve_id: &str) -> Result<bool, String> {
        let count: u32 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM kev WHERE cve_id = ?1",
                params![cve_id],
                |row| row.get(0),
            )
            .map_err(|e| format!("KEV check: {}", e))?;
        Ok(count > 0)
    }

    fn get_epss(&self, cve_id: &str) -> Result<(f64, f64), String> {
        match self.conn.query_row(
            "SELECT score, percentile FROM epss WHERE cve_id = ?1",
            params![cve_id],
            |row| Ok((row.get::<_, f64>(0)?, row.get::<_, f64>(1)?)),
        ) {
            Ok(r) => Ok(r),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok((0.0, 0.0)),
            Err(e) => Err(format!("EPSS get: {}", e)),
        }
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
