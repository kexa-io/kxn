use crate::config::{get_config_or_env, require_config};
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Value};

const RESOURCE_TYPES: &[&str] = &[
    "users",
    "tables",
    "privileges",
    "sessions",
    "parameters",
    "views",
    "triggers",
    "db_stats",
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
                 WHERE s.USERNAME IS NOT NULL AND s.STATUS = 'ACTIVE'",
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
                self.query_to_json(
                    &session,
                    "SELECT USERNAME, ACCOUNT_STATUS, CREATED, EXPIRY_DATE, DEFAULT_TABLESPACE, PROFILE FROM ALL_USERS JOIN DBA_USERS USING (USERNAME)",
                    &["username", "account_status", "created", "expiry_date", "default_tablespace", "profile"],
                ).await
            }
            "tables" => {
                self.query_to_json(
                    &session,
                    "SELECT OWNER, TABLE_NAME, TABLESPACE_NAME, NUM_ROWS, STATUS, LOGGING FROM ALL_TABLES WHERE OWNER NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP')",
                    &["owner", "table_name", "tablespace_name", "num_rows", "status", "logging"],
                ).await
            }
            "privileges" => {
                self.query_to_json(
                    &session,
                    "SELECT GRANTEE, PRIVILEGE, ADMIN_OPTION FROM USER_SYS_PRIVS",
                    &["grantee", "privilege", "admin_option"],
                ).await
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
                let rows = self.query_to_json(
                    &session,
                    "SELECT NAME, VALUE FROM V$SYSTEM_PARAMETER WHERE VALUE IS NOT NULL",
                    &["name", "value"],
                ).await?;
                let mut flat = serde_json::Map::new();
                for row in &rows {
                    if let (Some(name), Some(value)) = (
                        row.get("name").and_then(|v| v.as_str()),
                        row.get("value").and_then(|v| v.as_str()),
                    ) {
                        flat.insert(name.to_string(), Value::String(value.to_string()));
                    }
                }
                Ok(vec![Value::Object(flat)])
            }
            "views" => {
                self.query_to_json(
                    &session,
                    "SELECT OWNER, VIEW_NAME, TEXT_LENGTH, READ_ONLY FROM ALL_VIEWS WHERE OWNER NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP')",
                    &["owner", "view_name", "text_length", "read_only"],
                ).await
            }
            "triggers" => {
                self.query_to_json(
                    &session,
                    "SELECT OWNER, TRIGGER_NAME, TRIGGER_TYPE, TRIGGERING_EVENT, TABLE_NAME, STATUS FROM ALL_TRIGGERS WHERE OWNER NOT IN ('SYS','SYSTEM','OUTLN','DBSNMP')",
                    &["owner", "trigger_name", "trigger_type", "triggering_event", "table_name", "status"],
                ).await
            }
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
