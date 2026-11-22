use crate::config::{get_config_or_env, require_config};
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Value};

pub(crate) const RESOURCE_TYPES: &[&str] = &[
    "users",
    "profiles",
    "grantees",
    "instance",
    "tables",
    "privileges",
    "sessions",
    "parameters",
    "views",
    "triggers",
    "db_stats",
    "system_metrics",
    "logs",
    "tablespaces",
    "datafiles",
    "redo_logs",
    "indexes",
    "jobs",
    "rman_backups",
];

pub struct OracleProvider {
    host: String,
    port: u16,
    user: String,
    password: String,
    service_name: String,
}

impl OracleProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let host = require_config(&config, "ORACLE_HOST", Some("ORACLE"))?;
        let user = require_config(&config, "ORACLE_USER", Some("ORACLE"))?;
        let password = require_config(&config, "ORACLE_PASSWORD", Some("ORACLE"))?;
        let service_name = require_config(&config, "ORACLE_SERVICE_NAME", Some("ORACLE"))?;
        let port: u16 = get_config_or_env(&config, "ORACLE_PORT", Some("ORACLE"))
            .and_then(|p| p.parse().ok())
            .unwrap_or(1521);

        Ok(Self {
            host,
            port,
            user,
            password,
            service_name,
        })
    }

    fn connect_string(&self) -> String {
        format!(
            "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={})(PORT={}))(CONNECT_DATA=(SERVICE_NAME={})))",
            self.host, self.port, self.service_name
        )
    }

    async fn query_to_json(
        &self,
        session: &sibyl::Session<'_>,
        sql: &str,
        col_names: &[&str],
    ) -> Result<Vec<Value>, ProviderError> {
        let stmt = session
            .prepare(sql)
            .await
            .map_err(|e| ProviderError::Query(format!("{}: {}", sql, e)))?;

        let rows = stmt
            .query(())
            .await
            .map_err(|e| ProviderError::Query(format!("{}: {}", sql, e)))?;

        let mut results = Vec::new();
        while let Some(row) = rows.next().await
            .map_err(|e| ProviderError::Query(format!("{}: {}", sql, e)))?
        {
            let mut map = serde_json::Map::new();
            for (i, name) in col_names.iter().enumerate() {
                let val: Value = if let Ok(Some(n)) = row.get::<Option<f64>, usize>(i) {
                    json!(n)
                } else if let Ok(Some(n)) = row.get::<Option<i64>, usize>(i) {
                    json!(n)
                } else if let Ok(Some(s)) = row.get::<Option<String>, usize>(i) {
                    Value::String(s)
                } else {
                    Value::Null
                };
                map.insert(name.to_string(), val);
            }
            results.push(Value::Object(map));
        }

        Ok(results)
    }

    async fn query_single_value(
        &self,
        session: &sibyl::Session<'_>,
        sql: &str,
    ) -> Result<Option<f64>, ProviderError> {
        let stmt = session
            .prepare(sql)
            .await
            .map_err(|e| ProviderError::Query(format!("{}: {}", sql, e)))?;
        let rows = stmt
            .query(())
            .await
            .map_err(|e| ProviderError::Query(format!("{}: {}", sql, e)))?;
        if let Some(row) = rows.next().await
            .map_err(|e| ProviderError::Query(format!("{}: {}", sql, e)))?
        {
            // Try f64 first (Oracle NUMBER type)
            if let Ok(Some(n)) = row.get::<Option<f64>, usize>(0) {
                return Ok(Some(n));
            }
            // Then try i64
            if let Ok(Some(n)) = row.get::<Option<i64>, usize>(0) {
                return Ok(Some(n as f64));
            }
            // Finally try String and parse
            if let Ok(Some(s)) = row.get::<Option<String>, usize>(0) {
                return Ok(s.parse::<f64>().ok());
            }
        }
        Ok(None)
    }

    /// One object per grantee (user or role) that Oracle does not maintain,
    /// with the system privileges and roles granted to it (CIS section 6).
    async fn gather_grantees(&self, session: &sibyl::Session<'_>) -> Result<Vec<Value>, ProviderError> {
        const NOT_MAINTAINED: &str = "GRANTEE NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED = 'Y') \
             AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED = 'Y')";
        let sys = self
            .query_to_json(
                session,
                &format!("SELECT GRANTEE, PRIVILEGE, ADMIN_OPTION FROM DBA_SYS_PRIVS WHERE {NOT_MAINTAINED}"),
                &["grantee", "privilege", "admin_option"],
            )
            .await?;
        let roles = self
            .query_to_json(
                session,
                &format!("SELECT GRANTEE, GRANTED_ROLE, ADMIN_OPTION FROM DBA_ROLE_PRIVS WHERE {NOT_MAINTAINED}"),
                &["grantee", "granted_role", "admin_option"],
            )
            .await?;
        Ok(grantee_rows(&sys, &roles))
    }

    /// Instance-wide facts for CIS controls that are not parameters:
    /// version, patches, database links, password file, unified auditing and
    /// object grants on sensitive dictionary tables, directories and Java.
    async fn gather_instance(&self, session: &sibyl::Session<'_>) -> Result<Vec<Value>, ProviderError> {
        let mut o = serde_json::Map::new();
        let first_str = |rows: Vec<Value>, col: &str| -> Option<String> {
            rows.first().and_then(|r| r.get(col)).and_then(|v| v.as_str()).map(String::from)
        };
        if let Ok(rows) = self.query_to_json(session, "SELECT VERSION_FULL FROM V$INSTANCE", &["version"]).await {
            if let Some(v) = first_str(rows, "version") {
                let major = v.split('.').next().and_then(|m| m.parse::<u64>().ok()).unwrap_or(0);
                o.insert("version".into(), json!(v));
                o.insert("version_major".into(), json!(major));
            }
        }
        let not_maintained = "NOT IN (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED = 'Y') \
             AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED = 'Y')";
        let counts: Vec<(&str, String)> = vec![
            ("public_db_links", "SELECT COUNT(*) FROM DBA_DB_LINKS WHERE OWNER = 'PUBLIC'".into()),
            ("xs_users", "SELECT COUNT(*) FROM DBA_XS_USERS".into()),
            ("old_db_link_passwords", "SELECT COUNT(*) FROM SYS.LINK$ WHERE PASSWORD IS NOT NULL".into()),
            ("sensitive_table_grants", format!(
                "SELECT COUNT(*) FROM DBA_TAB_PRIVS WHERE OWNER = 'SYS' AND TABLE_NAME IN \
                 ('AUD$','USER$','USER_HISTORY$','LINK$','CDB_LOCAL_ADMINAUTH$','DEFAULT_PWD$','ENC$','HISTGRM$','HIST_HEAD$','PDB_SYNC$','SCHEDULER$_CREDENTIAL','SOURCE$','STATS$','XS$VERIFIERS','UNIFIED_AUDIT_TRAIL') \
                 AND GRANTEE {not_maintained}")),
            ("column_grants", format!("SELECT COUNT(*) FROM DBA_COL_PRIVS WHERE GRANTEE {not_maintained}")),
            ("proxy_users", "SELECT COUNT(*) FROM PROXY_USERS".into()),
            ("custom_java_grants", format!("SELECT COUNT(*) FROM DBA_JAVA_POLICY WHERE GRANTEE {not_maintained}")),
            ("directory_grants", format!(
                "SELECT COUNT(*) FROM DBA_TAB_PRIVS WHERE TYPE = 'DIRECTORY' AND GRANTEE {not_maintained}")),
            ("external_tables", "SELECT COUNT(*) FROM DBA_EXTERNAL_TABLES WHERE OWNER NOT IN \
                 (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED = 'Y')".into()),
            ("external_tables_preprocessor", "SELECT COUNT(*) FROM DBA_EXTERNAL_TABLES \
                 WHERE UPPER(ACCESS_PARAMETERS) LIKE '%PREPROCESSOR%' AND OWNER NOT IN \
                 (SELECT USERNAME FROM DBA_USERS WHERE ORACLE_MAINTAINED = 'Y')".into()),
            ("nondefault_underscore_parameters", "SELECT COUNT(*) FROM V$SYSTEM_PARAMETER \
                 WHERE NAME LIKE '\\_%' ESCAPE '\\' AND ISDEFAULT = 'FALSE'".into()),
        ];
        for (key, sql) in &counts {
            if let Ok(Some(n)) = self.query_single_value(session, sql).await {
                o.insert((*key).into(), json!(n as u64));
            }
        }
        // DBA_JAVA_POLICY exists only where the JVM is installed; without it
        // there is no Java grant to make.
        o.entry("custom_java_grants").or_insert(json!(0));
        if let Ok(rows) = self.query_to_json(session, "SELECT FORMAT FROM V$PASSWORDFILE_INFO", &["format"]).await {
            if let Some(f) = first_str(rows, "format") {
                o.insert("password_file_format".into(), json!(f));
            }
        }
        // Actions covered by an enabled unified audit policy, for every user.
        if let Ok(rows) = self
            .query_to_json(
                session,
                "SELECT DISTINCT p.AUDIT_OPTION FROM AUDIT_UNIFIED_POLICIES p \
                 JOIN AUDIT_UNIFIED_ENABLED_POLICIES e ON e.POLICY_NAME = p.POLICY_NAME \
                 WHERE e.ENTITY_NAME = 'ALL USERS' AND e.SUCCESS = 'YES' AND e.FAILURE = 'YES'",
                &["option"],
            )
            .await
        {
            let mut opts: Vec<String> = rows
                .iter()
                .filter_map(|r| r.get("option").and_then(|v| v.as_str()).map(String::from))
                .collect();
            opts.sort();
            o.insert("audited_actions".into(), json!(opts));
        }
        Ok(vec![Value::Object(o)])
    }

    async fn gather_db_stats(
        &self,
        session: &sibyl::Session<'_>,
    ) -> Result<Vec<Value>, ProviderError> {
        let mut stats = serde_json::Map::new();

        // Sessions
        let session_rows = self
            .query_to_json(
                session,
                "SELECT \
                 COUNT(*) as total_sessions, \
                 SUM(CASE WHEN STATUS='ACTIVE' THEN 1 ELSE 0 END) as active_sessions, \
                 SUM(CASE WHEN STATUS='INACTIVE' THEN 1 ELSE 0 END) as inactive_sessions \
                 FROM V$SESSION WHERE USERNAME IS NOT NULL",
                &["total_sessions", "active_sessions", "inactive_sessions"],
            )
            .await?;
        if let Some(row) = session_rows.first() {
            for (k, v) in row.as_object().into_iter().flatten() {
                stats.insert(k.clone(), v.clone());
            }
        }

        // Max processes (connection limit)
        if let Ok(Some(v)) = self
            .query_single_value(session, "SELECT VALUE FROM V$SYSTEM_PARAMETER WHERE NAME='processes'")
            .await
        {
            stats.insert("max_processes".into(), json!(v));
        }

        // SGA stats
        let sga_rows = self
            .query_to_json(
                session,
                "SELECT NAME, BYTES FROM V$SGASTAT WHERE POOL IS NULL OR POOL='shared pool'",
                &["name", "bytes"],
            )
            .await
            .unwrap_or_default();
        let mut sga_total: f64 = 0.0;
        for row in &sga_rows {
            if let Some(bytes) = row.get("bytes").and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))) {
                sga_total += bytes;
            }
        }
        stats.insert("sga_total_bytes".into(), json!(sga_total));

        // Buffer cache hit ratio
        let cache_sql = "SELECT ROUND((1 - (phy.value / (cur.value + con.value))) * 100, 2) \
            FROM V$SYSSTAT phy, V$SYSSTAT cur, V$SYSSTAT con \
            WHERE phy.NAME = 'physical reads' AND cur.NAME = 'db block gets' AND con.NAME = 'consistent gets' \
            AND (cur.value + con.value) > 0";
        if let Ok(Some(v)) = self.query_single_value(session, cache_sql).await {
            stats.insert("buffer_cache_hit_ratio".into(), json!(v));
        }

        // Library cache hit ratio
        let lib_sql = "SELECT ROUND(SUM(PINS - RELOADS) / SUM(PINS) * 100, 2) FROM V$LIBRARYCACHE WHERE PINS > 0";
        if let Ok(Some(v)) = self.query_single_value(session, lib_sql).await {
            stats.insert("library_cache_hit_ratio".into(), json!(v));
        }

        // Tablespace usage
        let tbs_rows = self
            .query_to_json(
                session,
                "SELECT TABLESPACE_NAME, USED_PERCENT FROM DBA_TABLESPACE_USAGE_METRICS",
                &["tablespace_name", "used_percent"],
            )
            .await
            .unwrap_or_default();
        let mut max_tbs_pct: f64 = 0.0;
        for row in &tbs_rows {
            if let Some(pct) = row.get("used_percent").and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))) {
                if pct > max_tbs_pct {
                    max_tbs_pct = pct;
                }
            }
        }
        stats.insert("tablespace_max_used_percent".into(), json!(max_tbs_pct));
        stats.insert("tablespace_count".into(), json!(tbs_rows.len()));

        // Waits / performance
        let wait_sql = "SELECT METRIC_NAME, VALUE FROM V$SYSMETRIC WHERE GROUP_ID = 2 AND METRIC_NAME IN (\
            'Database Wait Time Ratio','Database CPU Time Ratio',\
            'Executions Per Sec','Hard Parse Count Per Sec',\
            'Logical Reads Per Sec','Physical Reads Per Sec',\
            'Physical Writes Per Sec','User Commits Per Sec',\
            'User Rollbacks Per Sec','Current Logons Count',\
            'SQL Service Response Time','User Calls Per Sec')";
        let wait_rows = self
            .query_to_json(session, wait_sql, &["metric_name", "value"])
            .await
            .unwrap_or_default();
        for row in &wait_rows {
            if let (Some(name), Some(val)) = (
                row.get("metric_name").and_then(|v| v.as_str()),
                row.get("value"),
            ) {
                let key = name
                    .to_lowercase()
                    .replace(' ', "_")
                    .replace("per_sec", "per_s");
                let num = val.as_f64().or_else(|| val.as_str().and_then(|s| s.parse().ok()));
                if let Some(n) = num {
                    stats.insert(key, json!(n));
                }
            }
        }

        // Redo log switches per hour
        let redo_sql = "SELECT COUNT(*) FROM V$LOG_HISTORY WHERE FIRST_TIME > SYSDATE - 1/24";
        if let Ok(Some(v)) = self.query_single_value(session, redo_sql).await {
            stats.insert("redo_log_switches_last_hour".into(), json!(v));
        }

        // Long-running queries (> 5 min)
        let long_sql = "SELECT COUNT(*) FROM V$SESSION WHERE STATUS='ACTIVE' AND USERNAME IS NOT NULL \
            AND LAST_CALL_ET > 300";
        if let Ok(Some(v)) = self.query_single_value(session, long_sql).await {
            stats.insert("long_running_queries".into(), json!(v));
        }

        // Database size
        let size_sql = "SELECT SUM(BYTES) FROM DBA_DATA_FILES";
        if let Ok(Some(v)) = self.query_single_value(session, size_sql).await {
            stats.insert("total_size_bytes".into(), json!(v));
        }

        // Temp usage
        let temp_sql = "SELECT NVL(SUM(BLOCKS * 8192), 0) FROM V$SORT_USAGE";
        if let Ok(Some(v)) = self.query_single_value(session, temp_sql).await {
            stats.insert("temp_usage_bytes".into(), json!(v));
        }

        Ok(vec![Value::Object(stats)])
    }

    async fn gather_logs(
        &self,
        session: &sibyl::Session<'_>,
    ) -> Result<Vec<Value>, ProviderError> {
        let mut entries = Vec::new();

        // Alert log recent entries via V$DIAG_ALERT_EXT (12c+)
        let alert_rows = self
            .query_to_json(
                session,
                "SELECT ORIGINATING_TIMESTAMP, MESSAGE_TEXT, MESSAGE_TYPE, MESSAGE_LEVEL, COMPONENT_ID \
                 FROM V$DIAG_ALERT_EXT \
                 WHERE ORIGINATING_TIMESTAMP > SYSDATE - 1 \
                 AND MESSAGE_LEVEL <= 16 \
                 ORDER BY ORIGINATING_TIMESTAMP DESC \
                 FETCH FIRST 200 ROWS ONLY",
                &["timestamp", "message", "type", "level", "component"],
            )
            .await
            .unwrap_or_default();
        for row in &alert_rows {
            let level_num = row.get("level")
                .and_then(|v| v.as_str().and_then(|s| s.parse::<i64>().ok()).or_else(|| v.as_i64()))
                .unwrap_or(16);
            let level = if level_num <= 1 { "fatal" }
                else if level_num <= 8 { "error" }
                else if level_num <= 12 { "warning" }
                else { "info" };
            entries.push(json!({
                "source": "alert_log",
                "level": level,
                "timestamp": row.get("timestamp"),
                "component": row.get("component"),
                "message": row.get("message"),
            }));
        }

        // ORA- errors from V$SESSION with recent SQL errors
        let err_rows = self
            .query_to_json(
                session,
                "SELECT s.SID, s.USERNAME, s.PROGRAM, s.SQL_ID, \
                 (SELECT SQL_TEXT FROM V$SQL WHERE SQL_ID = s.SQL_ID AND ROWNUM = 1) as SQL_TEXT \
                 FROM V$SESSION s \
                 WHERE s.USERNAME IS NOT NULL AND s.STATUS = 'ACTIVE' \
                   AND s.SID <> SYS_CONTEXT('USERENV', 'SID') AND s.SQL_ID IS NOT NULL",
                &["sid", "username", "program", "sql_id", "sql_text"],
            )
            .await
            .unwrap_or_default();
        for row in &err_rows {
            entries.push(json!({
                "source": "active_session",
                "level": "info",
                "user": row.get("username"),
                "program": row.get("program"),
                "message": row.get("sql_text"),
            }));
        }

        let error_count = entries.iter().filter(|e| e["level"] == "error" || e["level"] == "fatal").count();
        let warning_count = entries.iter().filter(|e| e["level"] == "warning").count();

        let summary = json!({
            "total_entries": entries.len(),
            "error_count": error_count,
            "warning_count": warning_count,
            "entries": entries,
        });

        Ok(vec![summary])
    }

    async fn gather_tablespaces(
        &self,
        session: &sibyl::Session<'_>,
    ) -> Result<Vec<Value>, ProviderError> {
        let sql = "SELECT ts.TABLESPACE_NAME, ts.STATUS, ts.CONTENTS, \
            ts.LOGGING, ts.BIGFILE, ts.BLOCK_SIZE, ts.ALLOCATION_TYPE, \
            ts.SEGMENT_SPACE_MANAGEMENT, \
            NVL(df.TOTAL_BYTES, 0) as TOTAL_BYTES, \
            NVL(df.TOTAL_BYTES - fs.FREE_BYTES, 0) as USED_BYTES, \
            NVL(fs.FREE_BYTES, 0) as FREE_BYTES, \
            ROUND(NVL((df.TOTAL_BYTES - fs.FREE_BYTES) / df.TOTAL_BYTES * 100, 0), 2) as USED_PERCENT \
            FROM DBA_TABLESPACES ts \
            LEFT JOIN (SELECT TABLESPACE_NAME, SUM(BYTES) as TOTAL_BYTES \
              FROM DBA_DATA_FILES GROUP BY TABLESPACE_NAME) df \
              ON ts.TABLESPACE_NAME = df.TABLESPACE_NAME \
            LEFT JOIN (SELECT TABLESPACE_NAME, SUM(BYTES) as FREE_BYTES \
              FROM DBA_FREE_SPACE GROUP BY TABLESPACE_NAME) fs \
              ON ts.TABLESPACE_NAME = fs.TABLESPACE_NAME";
        let cols = &[
            "tablespace_name", "status", "contents", "logging", "bigfile",
            "block_size", "allocation_type", "segment_space_management",
            "total_bytes", "used_bytes", "free_bytes", "used_percent",
        ];
        self.query_to_json(session, sql, cols).await
    }

    async fn gather_datafiles(
        &self,
        session: &sibyl::Session<'_>,
    ) -> Result<Vec<Value>, ProviderError> {
        let sql = "SELECT FILE_NAME, FILE_ID, TABLESPACE_NAME, BYTES as SIZE_BYTES, \
            STATUS, AUTOEXTENSIBLE, MAXBYTES as MAX_BYTES, INCREMENT_BY, \
            ROUND(BYTES/1024/1024, 2) as SIZE_MB \
            FROM DBA_DATA_FILES ORDER BY TABLESPACE_NAME, FILE_NAME";
        let cols = &[
            "file_name", "file_id", "tablespace_name", "size_bytes",
            "status", "autoextensible", "max_bytes", "increment_by", "size_mb",
        ];
        self.query_to_json(session, sql, cols).await
    }

    async fn gather_redo_logs(
        &self,
        session: &sibyl::Session<'_>,
    ) -> Result<Vec<Value>, ProviderError> {
        let sql = "SELECT l.GROUP#, l.THREAD#, l.SEQUENCE#, l.BYTES as SIZE_BYTES, \
            l.MEMBERS, l.STATUS, l.ARCHIVED, \
            ROUND(l.BYTES/1024/1024, 2) as SIZE_MB \
            FROM V$LOG l ORDER BY l.GROUP#";
        let cols = &[
            "group_number", "thread_number", "sequence_number", "size_bytes",
            "members", "status", "archived", "size_mb",
        ];
        self.query_to_json(session, sql, cols).await
    }

    async fn gather_indexes(
        &self,
        session: &sibyl::Session<'_>,
    ) -> Result<Vec<Value>, ProviderError> {
        let sql = "SELECT OWNER, INDEX_NAME, TABLE_OWNER, TABLE_NAME, \
            INDEX_TYPE, UNIQUENESS, STATUS, TABLESPACE_NAME, \
            NUM_ROWS, DISTINCT_KEYS, LEAF_BLOCKS, BLEVEL, LAST_ANALYZED \
            FROM ALL_INDEXES \
            WHERE OWNER NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP','XDB', \
              'CTXSYS','MDSYS','ORDSYS','WMSYS','APEX_040200','APEX_PUBLIC_USER') \
            ORDER BY NUM_ROWS DESC NULLS LAST \
            FETCH FIRST 200 ROWS ONLY";
        let cols = &[
            "owner", "index_name", "table_owner", "table_name", "index_type",
            "uniqueness", "status", "tablespace_name", "num_rows",
            "distinct_keys", "leaf_blocks", "blevel", "last_analyzed",
        ];
        self.query_to_json(session, sql, cols).await
    }

    async fn gather_jobs(
        &self,
        session: &sibyl::Session<'_>,
    ) -> Result<Vec<Value>, ProviderError> {
        let sql = "SELECT OWNER, JOB_NAME, JOB_TYPE, STATE, ENABLED, \
            LAST_START_DATE, NEXT_RUN_DATE, RUN_COUNT, FAILURE_COUNT, RETRY_COUNT \
            FROM ALL_SCHEDULER_JOBS \
            WHERE OWNER NOT IN ('SYS','SYSTEM','ORACLE_OCM','EXFSYS') \
            ORDER BY LAST_START_DATE DESC NULLS LAST \
            FETCH FIRST 100 ROWS ONLY";
        let cols = &[
            "owner", "job_name", "job_type", "state", "enabled",
            "last_start_date", "next_run_date", "run_count",
            "failure_count", "retry_count",
        ];
        self.query_to_json(session, sql, cols).await
    }

    async fn gather_rman_backups(
        &self,
        session: &sibyl::Session<'_>,
    ) -> Result<Vec<Value>, ProviderError> {
        let sql = "SELECT RECID, SESSION_KEY, INPUT_TYPE, STATUS, \
            START_TIME, END_TIME, ELAPSED_SECONDS, \
            INPUT_BYTES, OUTPUT_BYTES, COMPRESSION_RATIO \
            FROM V$RMAN_BACKUP_JOB_DETAILS \
            ORDER BY START_TIME DESC \
            FETCH FIRST 50 ROWS ONLY";
        let cols = &[
            "recid", "session_key", "input_type", "status",
            "start_time", "end_time", "elapsed_seconds",
            "input_bytes", "output_bytes", "compression_ratio",
        ];
        match self.query_to_json(session, sql, cols).await {
            Ok(rows) => Ok(rows),
            Err(e) => {
                tracing::warn!("RMAN backup query failed (no permission?): {}", e);
                Ok(Vec::new())
            }
        }
    }
}

#[async_trait::async_trait]
impl Provider for OracleProvider {
    fn name(&self) -> &str {
        "oracle"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        let oracle = sibyl::env()
            .map_err(|e| ProviderError::Connection(format!("Oracle env: {}", e)))?;

        let session = oracle
            .connect(&self.connect_string(), &self.user, &self.password)
            .await
            .map_err(|e| ProviderError::Connection(format!("Oracle connect: {}", e)))?;

        match resource_type {
            "users" => {
                // DBA_USERS alone carries every column below. Joining it to
                // ALL_USERS added nothing and broke the query outright: both
                // views define CREATED, and `USING (USERNAME)` disambiguates
                // only the join column, so Oracle answered ORA-00918 and the
                // object every CIS user rule reads was never collected.
                let mut users = self.query_to_json(
                    &session,
                    "SELECT USERNAME, ACCOUNT_STATUS, CREATED, EXPIRY_DATE, DEFAULT_TABLESPACE, PROFILE, \
                     NVL(PASSWORD_VERSIONS, ' '), ORACLE_MAINTAINED, AUTHENTICATION_TYPE FROM DBA_USERS",
                    &["username", "account_status", "created", "expiry_date", "default_tablespace", "profile",
                      "password_versions", "oracle_maintained", "authentication_type"],
                ).await?;
                // CIS 4.1: open accounts still using a default password.
                let defpwd: std::collections::HashSet<String> = self
                    .query_to_json(&session, "SELECT USERNAME FROM DBA_USERS_WITH_DEFPWD", &["username"])
                    .await
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|r| r.get("username").and_then(|v| v.as_str()).map(String::from))
                    .collect();
                for u in users.iter_mut() {
                    let name = u.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let open = u.get("account_status").and_then(|v| v.as_str()).is_some_and(|s| s == "OPEN");
                    let versions = u.get("password_versions").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    if let Some(o) = u.as_object_mut() {
                        o.insert("default_password".into(), json!(open && defpwd.contains(&name)));
                        o.insert(
                            "old_password_versions".into(),
                            json!(versions.contains("10G") || versions.contains("11G")),
                        );
                        o.insert("password_versions".into(), json!(versions.trim()));
                    }
                }
                Ok(users)
            }
            // Password policy lives in DBA_PROFILES, not in the init
            // parameters: CIS 3.1 to 3.4 read `failed_login_attempts`,
            // `password_life_time`, `password_reuse_max` and
            // `password_lock_time` as if they were parameters, so they were
            // scored against a `parameters` object that never contains them.
            // One row per profile, resource limits pivoted onto it.
            "profiles" => {
                let rows = self
                    .query_to_json(
                        &session,
                        "SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES \
                         WHERE RESOURCE_TYPE = 'PASSWORD'",
                        &["profile", "resource_name", "limit"],
                    )
                    .await?;
                let mut by_profile: std::collections::BTreeMap<String, serde_json::Map<String, Value>> =
                    std::collections::BTreeMap::new();
                for row in &rows {
                    let (Some(profile), Some(resource), Some(limit)) = (
                        row.get("profile").and_then(|v| v.as_str()),
                        row.get("resource_name").and_then(|v| v.as_str()),
                        row.get("limit").and_then(|v| v.as_str()),
                    ) else {
                        continue;
                    };
                    by_profile
                        .entry(profile.to_string())
                        .or_default()
                        .insert(resource.to_lowercase(), Value::String(limit.to_string()));
                }
                let defaults = by_profile.get("DEFAULT").cloned().unwrap_or_default();
                Ok(by_profile
                    .into_iter()
                    .map(|(name, mut limits)| {
                        resolve_profile_limits(&mut limits, &defaults);
                        limits.insert("profile".into(), Value::String(name));
                        Value::Object(limits)
                    })
                    .collect())
            }
            // V$SYSMETRIC metrics, on their own object because the view can be
            // empty — it is on Oracle Free, which collects none of it — and the
            // six rules reading these would otherwise be scored against a
            // `db_stats` that never carries them. No rows, no object, no
            // verdict.
            //
            // Written against the documented metric names and NOT verified
            // against a populated instance: this container reports zero rows in
            // V$SYSMETRIC, so only the empty path is proven here.
            "system_metrics" => {
                let rows = self
                    .query_to_json(
                        &session,
                        "SELECT METRIC_NAME, VALUE FROM V$SYSMETRIC WHERE GROUP_ID = 2",
                        &["metric_name", "value"],
                    )
                    .await?;
                let wanted = [
                    ("Database Wait Time Ratio", "database_wait_time_ratio"),
                    ("Database CPU Time Ratio", "database_cpu_time_ratio"),
                    ("Physical Reads Per Sec", "physical_reads_per_s"),
                    ("Hard Parse Count Per Sec", "hard_parse_count_per_s"),
                    ("SQL Service Response Time", "sql_service_response_time"),
                    ("User Rollbacks Per Sec", "user_rollbacks_per_s"),
                ];
                let mut flat = serde_json::Map::new();
                for row in &rows {
                    let Some(name) = row.get("metric_name").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    if let Some((_, key)) = wanted.iter().find(|(oracle, _)| *oracle == name) {
                        if let Some(value) = row.get("value") {
                            flat.insert((*key).to_string(), value.clone());
                        }
                    }
                }
                // Every field or none: a partial object would have the engine
                // read the rest as empty strings and fail their rules.
                if flat.len() != wanted.len() {
                    tracing::debug!(
                        found = flat.len(),
                        "Oracle: V$SYSMETRIC does not report the full metric set; system_metrics is not served"
                    );
                    return Ok(Vec::new());
                }
                Ok(vec![Value::Object(flat)])
            }
            "tables" => {
                self.query_to_json(
                    &session,
                    "SELECT OWNER, TABLE_NAME, TABLESPACE_NAME, NUM_ROWS, STATUS, LOGGING FROM ALL_TABLES WHERE OWNER NOT IN (SELECT USERNAME FROM ALL_USERS WHERE ORACLE_MAINTAINED = 'Y')",
                    &["owner", "table_name", "tablespace_name", "num_rows", "status", "logging"],
                ).await
            }
            "privileges" => {
                // USER_SYS_PRIVS has no GRANTEE column — the USER_ views omit
                // it because the grantee is implicitly the connected user — so
                // this answered ORA-00904 and collected nothing. DBA_SYS_PRIVS
                // has it and covers the whole instance, which is what an audit
                // wants; the USER_ view is the fallback for an account without
                // the DBA role, where the connected user is the grantee.
                match self
                    .query_to_json(
                        &session,
                        // Grantees Oracle ships — users *and* roles, both
                        // flagged ORACLE_MAINTAINED — are excluded: on a stock
                        // 23ai they held all 58 grants carrying ADMIN OPTION,
                        // and a control meant to catch an unexpected holder
                        // reported SYS, SCHEDULER_ADMIN and AQ_ADMINISTRATOR_ROLE.
                        "SELECT GRANTEE, PRIVILEGE, ADMIN_OPTION FROM DBA_SYS_PRIVS \
                         WHERE GRANTEE NOT IN (SELECT USERNAME FROM ALL_USERS WHERE ORACLE_MAINTAINED = 'Y') \
                           AND GRANTEE NOT IN (SELECT ROLE FROM DBA_ROLES WHERE ORACLE_MAINTAINED = 'Y')",
                        &["grantee", "privilege", "admin_option"],
                    )
                    .await
                {
                    Ok(rows) => Ok(rows),
                    Err(e) => {
                        tracing::debug!(error = %e, "Oracle: DBA_SYS_PRIVS unreadable, falling back to the connected user's own privileges");
                        self.query_to_json(
                            &session,
                            "SELECT USER AS GRANTEE, PRIVILEGE, ADMIN_OPTION FROM USER_SYS_PRIVS",
                            &["grantee", "privilege", "admin_option"],
                        )
                        .await
                    }
                }
            }
            "sessions" => {
                self.query_to_json(
                    &session,
                    "SELECT SID, SERIAL#, USERNAME, STATUS, OSUSER, MACHINE, PROGRAM, LOGON_TIME FROM V$SESSION WHERE USERNAME IS NOT NULL",
                    &["sid", "serial", "username", "status", "osuser", "machine", "program", "logon_time"],
                ).await
            }
            "parameters" => {
                // Pivot parameters into a single flat object: {"param_name": "value", ...}
                //
                // Unset parameters are kept, as the empty string they are.
                // `WHERE VALUE IS NOT NULL` dropped them, and several controls
                // ask exactly whether a parameter is empty — `remote_listener`,
                // `log_archive_dest_1`, `db_recovery_file_dest`. Absent, they
                // were read as an empty string through the missing-property
                // path, so the verdict was accidental: right for the rules
                // wanting a value, wrong for the ones wanting none.
                let rows = self.query_to_json(
                    &session,
                    "SELECT NAME, NVL(VALUE, ' ') AS VALUE FROM V$SYSTEM_PARAMETER",
                    &["name", "value"],
                ).await?;
                let mut flat = serde_json::Map::new();
                for row in &rows {
                    if let Some(name) = row.get("name").and_then(|v| v.as_str()) {
                        let value = row
                            .get("value")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        flat.insert(name.to_string(), Value::String(value));
                    }
                }
                Ok(vec![Value::Object(flat)])
            }
            // Oracle-shipped schemas are excluded by the flag Oracle itself
            // sets, not by a hand-kept list. The four names that list held —
            // SYS, SYSTEM, OUTLN, DBSNMP — miss everything a modern release
            // adds: on a stock 23ai the remaining 28 internal schemas (DVSYS,
            // LBACSYS, GSMADMIN_INTERNAL, XDB, VECSYS…) owned every object,
            // and the "views in application schemas should be read-only" rule
            // reported 219 dictionary views on a database with no application
            // in it at all.
            "views" => {
                self.query_to_json(
                    &session,
                    "SELECT OWNER, VIEW_NAME, TEXT_LENGTH, READ_ONLY FROM ALL_VIEWS WHERE OWNER NOT IN (SELECT USERNAME FROM ALL_USERS WHERE ORACLE_MAINTAINED = 'Y')",
                    &["owner", "view_name", "text_length", "read_only"],
                ).await
            }
            "triggers" => {
                self.query_to_json(
                    &session,
                    "SELECT OWNER, TRIGGER_NAME, TRIGGER_TYPE, TRIGGERING_EVENT, TABLE_NAME, STATUS FROM ALL_TRIGGERS WHERE OWNER NOT IN (SELECT USERNAME FROM ALL_USERS WHERE ORACLE_MAINTAINED = 'Y')",
                    &["owner", "trigger_name", "trigger_type", "triggering_event", "table_name", "status"],
                ).await
            }
            "grantees" => self.gather_grantees(&session).await,
            "instance" => self.gather_instance(&session).await,
            "db_stats" => self.gather_db_stats(&session).await,
            "logs" => self.gather_logs(&session).await,
            "tablespaces" => self.gather_tablespaces(&session).await,
            "datafiles" => self.gather_datafiles(&session).await,
            "redo_logs" => self.gather_redo_logs(&session).await,
            "indexes" => self.gather_indexes(&session).await,
            "jobs" => self.gather_jobs(&session).await,
            "rman_backups" => self.gather_rman_backups(&session).await,
            _ => Err(ProviderError::UnsupportedResourceType(
                resource_type.to_string(),
            )),
        }
    }
}

/// Large stand-in for UNLIMITED so numeric comparisons fail as they should.
const UNLIMITED: f64 = 1.0e9;

/// Numeric value of a profile limit: UNLIMITED is huge, a fraction stays a
/// fraction (PASSWORD_LOCK_TIME 1/1440 is one minute).
fn limit_number(limit: &str) -> Option<f64> {
    let l = limit.trim();
    if l.eq_ignore_ascii_case("UNLIMITED") {
        return Some(UNLIMITED);
    }
    if let Some((a, b)) = l.split_once('/') {
        let (a, b) = (a.trim().parse::<f64>().ok()?, b.trim().parse::<f64>().ok()?);
        return (b != 0.0).then(|| a / b);
    }
    l.parse::<f64>().ok()
}

/// Replace DEFAULT with the DEFAULT profile's value, and add a `<limit>_n`
/// number for every numeric limit plus `life_plus_grace_n` (CIS 3.3).
fn resolve_profile_limits(
    limits: &mut serde_json::Map<String, Value>,
    defaults: &serde_json::Map<String, Value>,
) {
    let keys: Vec<String> = limits.keys().cloned().collect();
    for k in keys {
        if limits.get(&k).and_then(|v| v.as_str()) == Some("DEFAULT") {
            if let Some(d) = defaults.get(&k) {
                limits.insert(k.clone(), d.clone());
            }
        }
        if let Some(n) = limits.get(&k).and_then(|v| v.as_str()).and_then(limit_number) {
            limits.insert(format!("{k}_n"), json!(n));
        }
    }
    let n = |k: &str| limits.get(k).and_then(|v| v.as_f64());
    if let (Some(life), Some(grace)) = (n("password_life_time_n"), n("password_grace_time_n")) {
        limits.insert("life_plus_grace_n".into(), json!((life + grace).min(UNLIMITED)));
    }
}

/// Group DBA_SYS_PRIVS and DBA_ROLE_PRIVS rows by grantee.
fn grantee_rows(sys: &[Value], roles: &[Value]) -> Vec<Value> {
    let mut by: std::collections::BTreeMap<String, (Vec<String>, Vec<String>, u64)> =
        std::collections::BTreeMap::new();
    let s = |r: &Value, k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    for r in sys {
        let e = by.entry(s(r, "grantee")).or_default();
        e.0.push(s(r, "privilege"));
        if s(r, "admin_option") == "YES" {
            e.2 += 1;
        }
    }
    for r in roles {
        let e = by.entry(s(r, "grantee")).or_default();
        e.1.push(s(r, "granted_role"));
        if s(r, "admin_option") == "YES" {
            e.2 += 1;
        }
    }
    by.into_iter()
        .filter(|(g, _)| !g.is_empty())
        .map(|(grantee, (mut privs, mut roles, admin))| {
            privs.sort();
            roles.sort();
            let any = privs.iter().filter(|p| p.contains(" ANY ") || p.ends_with(" ANY")).count();
            json!({
                "grantee": grantee,
                "sys_privileges": privs,
                "roles": roles,
                "any_privilege_count": any,
                "admin_option_count": admin,
            })
        })
        .collect()
}

#[cfg(test)]
mod cis_tests {
    use super::*;

    #[test]
    fn profile_limits_resolve_defaults_and_numbers() {
        let defaults: serde_json::Map<String, Value> = serde_json::from_value(json!({
            "failed_login_attempts": "10", "password_life_time": "180", "password_grace_time": "7",
            "password_lock_time": "1", "password_reuse_max": "UNLIMITED"})).unwrap();
        let mut app: serde_json::Map<String, Value> = serde_json::from_value(json!({
            "failed_login_attempts": "DEFAULT", "password_life_time": "UNLIMITED",
            "password_grace_time": "DEFAULT", "password_lock_time": "1/1440", "password_reuse_max": "DEFAULT"})).unwrap();
        resolve_profile_limits(&mut app, &defaults);
        assert_eq!(app["failed_login_attempts"], "10");
        assert_eq!(app["failed_login_attempts_n"], 10.0);
        assert_eq!(app["password_reuse_max"], "UNLIMITED");
        assert!(app["life_plus_grace_n"].as_f64().unwrap() >= UNLIMITED);
        assert!((app["password_lock_time_n"].as_f64().unwrap() - 1.0 / 1440.0).abs() < 1e-9);
    }

    #[test]
    fn grantees_group_privileges_and_roles() {
        let sys = vec![
            json!({"grantee": "APP", "privilege": "SELECT ANY TABLE", "admin_option": "NO"}),
            json!({"grantee": "APP", "privilege": "CREATE SESSION", "admin_option": "YES"}),
        ];
        let roles = vec![json!({"grantee": "APP", "granted_role": "DBA", "admin_option": "NO"}),
                         json!({"grantee": "RPT", "granted_role": "SELECT_CATALOG_ROLE", "admin_option": "NO"})];
        let rows = grantee_rows(&sys, &roles);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["grantee"], "APP");
        assert_eq!(rows[0]["any_privilege_count"], 1);
        assert_eq!(rows[0]["admin_option_count"], 1);
        assert_eq!(rows[0]["roles"], json!(["DBA"]));
        assert_eq!(rows[1]["sys_privileges"], json!([]));
    }
}
