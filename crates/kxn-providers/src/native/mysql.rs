use crate::config::{get_config_or_env, require_config};
use crate::error::ProviderError;
use crate::traits::Provider;
use mysql_async::prelude::*;
use mysql_async::{Conn, Opts, OptsBuilder, Row};
use serde_json::{json, Value};

pub(crate) const RESOURCE_TYPES: &[&str] = &[
    "databases",
    "users",
    "grants",
    "variables",
    "status",
    "engines",
    "processlist",
    "db_stats",
    "logs",
    "replication",
    "table_stats",
    "indexes",
    "innodb_status",
    "schema_sizes",
];

pub struct MySqlProvider {
    opts: Opts,
    /// Options without TLS, kept for the `prefer` fallback: mysql_async has no
    /// "encrypt if the server offers it" mode, so it is done here by trying
    /// once and falling back.
    plaintext_opts: Opts,
    ssl_mode: crate::db_tls::DbSslMode,
}

impl MySqlProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let host = require_config(&config, "MYSQL_HOST", Some("MYSQL"))?;
        let user = require_config(&config, "MYSQL_USER", Some("MYSQL"))?;
        let password = get_config_or_env(&config, "MYSQL_PASSWORD", Some("MYSQL")).unwrap_or_default();
        let port: u16 = get_config_or_env(&config, "MYSQL_PORT", Some("MYSQL"))
            .and_then(|p| p.parse().ok())
            .unwrap_or(3306);

        let ssl_mode = crate::db_tls::ssl_mode(&config, "MYSQL")?;
        let base = OptsBuilder::default()
            .ip_or_hostname(host)
            .user(Some(user))
            .pass(Some(password))
            .tcp_port(port);

        let plaintext_opts = Opts::from(base.clone());
        let opts = match ssl_mode {
            crate::db_tls::DbSslMode::Disable => plaintext_opts.clone(),
            _ => {
                let mut ssl = mysql_async::SslOpts::default()
                    // `prefer` and `require` encrypt without authenticating the
                    // server, as they do in libpq: demanding a trusted chain
                    // there would refuse the self-signed certificates most
                    // internal databases carry, and the modes that do verify
                    // exist for exactly that.
                    .with_danger_accept_invalid_certs(!ssl_mode.verifies_certificate())
                    .with_danger_skip_domain_validation(!ssl_mode.verifies_hostname());
                if let Some(path) = crate::db_tls::ssl_root_cert(&config, "MYSQL") {
                    ssl = ssl.with_root_certs(vec![std::path::PathBuf::from(path).into()]);
                }
                Opts::from(base.ssl_opts(Some(ssl)))
            }
        };

        Ok(Self {
            opts,
            plaintext_opts,
            ssl_mode,
        })
    }

    async fn connect(&self) -> Result<Conn, ProviderError> {
        match Conn::new(self.opts.clone()).await {
            Ok(conn) => Ok(conn),
            // `prefer` must never break a connection that would have worked
            // without TLS — that is what separates it from `require`, and it is
            // why it can be the default.
            Err(e) if self.ssl_mode == crate::db_tls::DbSslMode::Prefer => {
                tracing::debug!(error = %e, "MySQL: TLS refused, falling back to a plaintext connection");
                Conn::new(self.plaintext_opts.clone())
                    .await
                    .map_err(|e| ProviderError::Connection(format!("MySQL: {}", e)))
            }
            Err(e) => Err(ProviderError::Connection(format!("MySQL: {}", e))),
        }
    }

    async fn query_param(&self, conn: &mut Conn, sql: &str, param: &str) -> Result<Vec<Value>, ProviderError> {
        let rows: Vec<Row> = conn
            .exec(sql, (param,))
            .await
            .map_err(|e| ProviderError::Query(format!("{}: {}", sql, e)))?;
        Ok(rows.iter().map(row_to_json).collect())
    }

    async fn query_to_json(&self, conn: &mut Conn, sql: &str) -> Result<Vec<Value>, ProviderError> {
        let rows: Vec<Row> = conn
            .query(sql)
            .await
            .map_err(|e| ProviderError::Query(format!("{}: {}", sql, e)))?;

        Ok(rows.iter().map(row_to_json).collect())
    }

    /// Execute SQL statements (for remediation).
    pub async fn execute_sql(&self, sql: &str) -> Result<String, ProviderError> {
        let mut conn = self.connect().await?;
        let statements: Vec<&str> = sql.split(';').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        let mut results = Vec::new();
        for stmt in &statements {
            conn.query_drop(*stmt)
                .await
                .map_err(|e| ProviderError::Query(format!("{}: {}", stmt, e)))?;
            results.push(format!("OK: {}", stmt));
        }
        Ok(results.join("\n"))
    }

    async fn gather_databases(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        let db_rows: Vec<Row> = conn
            .query("SHOW DATABASES")
            .await
            .map_err(|e| ProviderError::Query(format!("SHOW DATABASES: {}", e)))?;

        let mut databases = Vec::new();
        for row in &db_rows {
            let db_name: String = row.get(0).unwrap_or_default();
            let mut db_info = json!({ "name": db_name });

            // Get tables for each database (parameterized)
            if let Ok(tables) = self.query_param(conn,
                "SELECT TABLE_NAME, TABLE_TYPE, ENGINE, TABLE_ROWS, DATA_LENGTH, TABLE_COLLATION \
                 FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?", &db_name).await {
                db_info["tables"] = json!(tables);
            }

            // Get columns (parameterized)
            if let Ok(columns) = self.query_param(conn,
                "SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, EXTRA, COLUMN_DEFAULT \
                 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ?", &db_name).await {
                db_info["columns"] = json!(columns);
            }

            // Get indexes (parameterized)
            if let Ok(indexes) = self.query_param(conn,
                "SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, COLUMN_NAME, INDEX_TYPE \
                 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ?", &db_name).await {
                db_info["indexes"] = json!(indexes);
            }

            databases.push(db_info);
        }

        Ok(databases)
    }

    async fn gather_users(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        // `authentication_string` holds the password hash and is deliberately not
        // selected: copying credential material into a scan artefact is a leak
        // in itself. CIS 6.2 only needs to know whether the hash is empty, so
        // the server answers that as a boolean. The socket plugins legitimately
        // have no hash — authentication happens at the OS level — and must not
        // be reported as passwordless accounts.
        let mut rows = self.query_to_json(conn, "SELECT (authentication_string = '' AND plugin NOT IN ('auth_socket', 'unix_socket')) AS has_empty_password, User, Host, Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv, Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Create_user_priv, Event_priv, Trigger_priv, account_locked, password_expired, plugin FROM mysql.user").await?;
        // MySQL answers a boolean expression with a tinyint. The engine compares
        // strictly, so `0` would never equal `false` and the rule could not be
        // written in terms a reader understands.
        // MySQL answers a boolean expression with a tinyint, and the text
        // protocol hands it over as the bytes `0` or `1` — so the value arrives
        // as a string, not a number. The engine compares strictly: `"0"` is
        // neither `0` nor `false`, and the rule matched no account at all,
        // compliant or not.
        for row in &mut rows {
            let flag = match row.get("has_empty_password") {
                Some(Value::Number(n)) => n.as_i64().map(|n| n != 0),
                Some(Value::String(s)) => Some(s != "0" && !s.is_empty()),
                Some(Value::Bool(b)) => Some(*b),
                _ => None,
            };
            if let Some(flag) = flag {
                row["has_empty_password"] = Value::Bool(flag);
            }
        }
        Ok(rows)
    }

    async fn gather_grants(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        let users: Vec<Row> = conn
            .query("SELECT User, Host FROM mysql.user")
            .await
            .map_err(|e| ProviderError::Query(format!("SELECT users: {}", e)))?;

        let mut results = Vec::new();
        for row in &users {
            let user: String = row.get(0).unwrap_or_default();
            let host: String = row.get(1).unwrap_or_default();
            let grant_sql = format!("SHOW GRANTS FOR '{}'@'{}'", user.replace('\'', "''"), host.replace('\'', "''"));

            let mut grant_entry = json!({ "user": user, "host": host, "grants": [] });

            if let Ok(grant_rows) = self.query_to_json(conn, &grant_sql).await {
                grant_entry["grants"] = json!(grant_rows);
            }
            results.push(grant_entry);
        }

        Ok(results)
    }

    async fn gather_variables(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        let rows: Vec<Row> = conn
            .query("SHOW GLOBAL VARIABLES")
            .await
            .map_err(|e| ProviderError::Query(format!("SHOW GLOBAL VARIABLES: {}", e)))?;

        // Return as a single object with key=variable_name, value=variable_value
        let mut vars = serde_json::Map::new();
        for row in &rows {
            let name: String = row.get(0).unwrap_or_default();
            let value: String = row.get(1).unwrap_or_default();
            vars.insert(name, Value::String(value));
        }
        Ok(vec![Value::Object(vars)])
    }

    async fn gather_status(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        let rows: Vec<Row> = conn
            .query("SHOW GLOBAL STATUS")
            .await
            .map_err(|e| ProviderError::Query(format!("SHOW GLOBAL STATUS: {}", e)))?;

        let mut status = serde_json::Map::new();
        for row in &rows {
            let name: String = row.get(0).unwrap_or_default();
            let value: String = row.get(1).unwrap_or_default();
            status.insert(name, Value::String(value));
        }
        Ok(vec![Value::Object(status)])
    }

    async fn gather_engines(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        self.query_to_json(conn, "SHOW ENGINES").await
    }

    async fn gather_processlist(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        self.query_to_json(conn, "SHOW FULL PROCESSLIST").await
    }

    async fn gather_db_stats(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        let rows: Vec<Row> = conn
            .query("SHOW GLOBAL STATUS")
            .await
            .map_err(|e| ProviderError::Query(format!("SHOW GLOBAL STATUS: {}", e)))?;

        let mut status_map = std::collections::HashMap::new();
        for row in &rows {
            let name: String = row.get(0).unwrap_or_default();
            let value: String = row.get(1).unwrap_or_default();
            status_map.insert(name, value);
        }

        let get_f64 = |key: &str| -> f64 {
            status_map
                .get(key)
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.0)
        };

        let mut stats = serde_json::Map::new();

        // Connections
        stats.insert("connections_current".into(), json!(get_f64("Threads_connected")));
        stats.insert("connections_running".into(), json!(get_f64("Threads_running")));
        stats.insert("connections_max_used".into(), json!(get_f64("Max_used_connections")));
        stats.insert("connections_aborted".into(), json!(get_f64("Aborted_connects")));
        stats.insert("connections_total".into(), json!(get_f64("Connections")));

        // Queries
        stats.insert("queries_total".into(), json!(get_f64("Queries")));
        stats.insert("questions_total".into(), json!(get_f64("Questions")));
        stats.insert("slow_queries".into(), json!(get_f64("Slow_queries")));
        stats.insert("select_full_join".into(), json!(get_f64("Select_full_join")));

        // InnoDB buffer pool
        let pool_size = get_f64("Innodb_buffer_pool_pages_total");
        let pool_free = get_f64("Innodb_buffer_pool_pages_free");
        let pool_dirty = get_f64("Innodb_buffer_pool_pages_dirty");
        stats.insert("innodb_buffer_pool_pages_total".into(), json!(pool_size));
        stats.insert("innodb_buffer_pool_pages_free".into(), json!(pool_free));
        stats.insert("innodb_buffer_pool_pages_dirty".into(), json!(pool_dirty));
        let read_requests = get_f64("Innodb_buffer_pool_read_requests");
        let disk_reads = get_f64("Innodb_buffer_pool_reads");
        if read_requests > 0.0 {
            let ratio = ((read_requests - disk_reads) / read_requests * 100.0 * 100.0).round() / 100.0;
            stats.insert("innodb_buffer_pool_hit_ratio".into(), json!(ratio));
        } else {
            stats.insert("innodb_buffer_pool_hit_ratio".into(), json!(100.0));
        }
        stats.insert("innodb_buffer_pool_read_requests".into(), json!(get_f64("Innodb_buffer_pool_read_requests")));
        stats.insert("innodb_buffer_pool_reads".into(), json!(get_f64("Innodb_buffer_pool_reads")));

        // InnoDB row operations
        stats.insert("innodb_rows_read".into(), json!(get_f64("Innodb_rows_read")));
        stats.insert("innodb_rows_inserted".into(), json!(get_f64("Innodb_rows_inserted")));
        stats.insert("innodb_rows_updated".into(), json!(get_f64("Innodb_rows_updated")));
        stats.insert("innodb_rows_deleted".into(), json!(get_f64("Innodb_rows_deleted")));
        stats.insert("innodb_deadlocks".into(), json!(get_f64("Innodb_deadlocks")));

        // Table locks
        stats.insert("table_locks_waited".into(), json!(get_f64("Table_locks_waited")));
        stats.insert("table_locks_immediate".into(), json!(get_f64("Table_locks_immediate")));

        // Temp tables
        stats.insert("created_tmp_tables".into(), json!(get_f64("Created_tmp_tables")));
        stats.insert("created_tmp_disk_tables".into(), json!(get_f64("Created_tmp_disk_tables")));

        // Bytes in/out
        stats.insert("bytes_received".into(), json!(get_f64("Bytes_received")));
        stats.insert("bytes_sent".into(), json!(get_f64("Bytes_sent")));

        // Open tables / files
        stats.insert("open_tables".into(), json!(get_f64("Open_tables")));
        stats.insert("open_files".into(), json!(get_f64("Open_files")));

        // Handler stats
        stats.insert("handler_read_first".into(), json!(get_f64("Handler_read_first")));
        stats.insert("handler_read_key".into(), json!(get_f64("Handler_read_key")));
        stats.insert("handler_read_rnd_next".into(), json!(get_f64("Handler_read_rnd_next")));

        // Replication (if slave)
        let slave_rows = self.query_to_json(conn, "SHOW SLAVE STATUS").await.unwrap_or_default();
        if let Some(slave) = slave_rows.first() {
            if let Some(lag) = slave.get("Seconds_Behind_Master") {
                stats.insert("replication_lag_seconds".into(), lag.clone());
            }
            if let Some(io) = slave.get("Slave_IO_Running") {
                stats.insert(
                    "replication_io_running".into(),
                    json!(if io.as_str() == Some("Yes") { 1 } else { 0 }),
                );
            }
            if let Some(sql) = slave.get("Slave_SQL_Running") {
                stats.insert(
                    "replication_sql_running".into(),
                    json!(if sql.as_str() == Some("Yes") { 1 } else { 0 }),
                );
            }
        }

        // Uptime
        stats.insert("uptime_seconds".into(), json!(get_f64("Uptime")));

        Ok(vec![Value::Object(stats)])
    }

    async fn gather_replication(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        // Try modern SHOW REPLICA STATUS first, fall back to SHOW SLAVE STATUS
        let rows = match self.query_to_json(conn, "SHOW REPLICA STATUS").await {
            Ok(r) => r,
            Err(_) => self.query_to_json(conn, "SHOW SLAVE STATUS").await.unwrap_or_default(),
        };
        // A server that is not a replica has no replication to judge, so it gets
        // no object rather than a placeholder. The `{"replication_configured":
        // false}` this replaces carried none of the fields the rules read, and
        // the engine reads a missing property as an empty string — so every
        // standalone server was reported as having a stopped IO thread, a
        // stopped SQL thread and unbounded lag. Four violations, invented.
        Ok(rows)
    }

    async fn gather_table_stats(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        let sql = "\
            SELECT TABLE_SCHEMA, TABLE_NAME, ENGINE, TABLE_ROWS, DATA_LENGTH, \
                   INDEX_LENGTH, DATA_FREE, \
                   ROUND(DATA_FREE / (DATA_LENGTH + INDEX_LENGTH + 1) * 100, 2) as fragmentation_percent, \
                   (DATA_LENGTH + INDEX_LENGTH) as total_size_bytes, \
                   TABLE_COLLATION, CREATE_TIME, UPDATE_TIME \
            FROM information_schema.TABLES \
            WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys') \
              AND TABLE_TYPE = 'BASE TABLE' \
            ORDER BY DATA_FREE DESC LIMIT 100";
        self.query_to_json(conn, sql).await
    }

    async fn gather_indexes(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        let stats = self.gather_index_statistics(conn).await;
        let usage = self.gather_index_usage(conn).await;
        let mut results = Vec::new();
        results.extend(stats);
        results.extend(usage);
        Ok(results)
    }

    async fn gather_index_statistics(&self, conn: &mut Conn) -> Vec<Value> {
        let sql = "\
            SELECT TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, NON_UNIQUE, \
                   SEQ_IN_INDEX, COLUMN_NAME, CARDINALITY, INDEX_TYPE, NULLABLE \
            FROM information_schema.STATISTICS \
            WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys') \
            ORDER BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX";
        let rows = self.query_to_json(conn, sql).await.unwrap_or_else(|e| {
            tracing::warn!("Failed to gather index statistics: {}", e);
            Vec::new()
        });
        rows.into_iter()
            .map(|mut v| { v["source"] = json!("statistics"); v })
            .collect()
    }

    async fn gather_index_usage(&self, conn: &mut Conn) -> Vec<Value> {
        let sql = "\
            SELECT object_schema, object_name, index_name, \
                   count_star as usage_count \
            FROM performance_schema.table_io_waits_summary_by_index_usage \
            WHERE index_name IS NOT NULL AND count_star = 0 \
              AND object_schema NOT IN ('mysql','performance_schema','sys')";
        let rows = self.query_to_json(conn, sql).await.unwrap_or_else(|e| {
            tracing::warn!("Failed to gather index usage from performance_schema: {}", e);
            Vec::new()
        });
        rows.into_iter()
            .map(|mut v| { v["source"] = json!("usage"); v })
            .collect()
    }

    async fn gather_innodb_status(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        let rows = self.query_to_json(conn, "SHOW ENGINE INNODB STATUS").await
            .unwrap_or_default();
        let raw = rows
            .first()
            .and_then(|r| r.get("Status").or_else(|| r.get("STATUS")))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        Ok(vec![parse_innodb_status(raw)])
    }

    async fn gather_schema_sizes(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        let sql = "\
            SELECT TABLE_SCHEMA as schema_name, \
                   COUNT(*) as table_count, \
                   SUM(DATA_LENGTH) as data_bytes, \
                   SUM(INDEX_LENGTH) as index_bytes, \
                   SUM(DATA_LENGTH + INDEX_LENGTH) as total_bytes, \
                   SUM(DATA_FREE) as free_bytes \
            FROM information_schema.TABLES \
            WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys') \
            GROUP BY TABLE_SCHEMA \
            ORDER BY total_bytes DESC";
        // The fragmentation rule is written as a percentage, which the byte
        // totals alone cannot answer; `table_stats` already publishes
        // `fragmentation_percent` for the same reason. Computed by the server so
        // the rule reads the ratio rather than re-deriving it.
        let mut rows = self.query_to_json(conn, sql).await?;
        for row in &mut rows {
            let num = |key: &str| -> Option<f64> {
                match row.get(key) {
                    Some(Value::Number(n)) => n.as_f64(),
                    Some(Value::String(s)) => s.parse().ok(),
                    _ => None,
                }
            };
            if let (Some(total), Some(free)) = (num("total_bytes"), num("free_bytes")) {
                if total > 0.0 {
                    row["free_ratio_percent"] = json!((free / total * 100.0).round());
                }
            }
        }
        Ok(rows)
    }

    async fn gather_logs(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        let mut entries = Vec::new();

        // Error log via SHOW WARNINGS (last session warnings)
        let warnings: Vec<Row> = conn
            .query("SHOW WARNINGS")
            .await
            .unwrap_or_default();
        for row in &warnings {
            let level: String = row.get(0).unwrap_or_default();
            let _code: i64 = row.get::<Option<i64>, _>(1).flatten().unwrap_or(0);
            let message: String = row.get(2).unwrap_or_default();
            entries.push(json!({
                "source": "warnings",
                "level": level.to_lowercase(),
                "message": message,
            }));
        }

        // SHOW ERRORS
        let errors: Vec<Row> = conn
            .query("SHOW ERRORS")
            .await
            .unwrap_or_default();
        for row in &errors {
            let level: String = row.get(0).unwrap_or_default();
            let _code: i64 = row.get::<Option<i64>, _>(1).flatten().unwrap_or(0);
            let message: String = row.get(2).unwrap_or_default();
            entries.push(json!({
                "source": "errors",
                "level": level.to_lowercase(),
                "message": message,
            }));
        }

        // Slow query log (if log_output=TABLE)
        let slow_rows = self
            .query_to_json(
                conn,
                "SELECT start_time, user_host, query_time, lock_time, rows_sent, rows_examined, sql_text \
                 FROM mysql.slow_log ORDER BY start_time DESC LIMIT 100",
            )
            .await
            .unwrap_or_default();
        for row in &slow_rows {
            entries.push(json!({
                "source": "slow_query",
                "level": "warning",
                "timestamp": row.get("start_time"),
                "user": row.get("user_host"),
                "query_time": row.get("query_time"),
                "lock_time": row.get("lock_time"),
                "rows_examined": row.get("rows_examined"),
                "message": row.get("sql_text"),
            }));
        }

        // General log recent entries (if log_output=TABLE)
        let general_rows = self
            .query_to_json(
                conn,
                "SELECT event_time, user_host, command_type, argument \
                 FROM mysql.general_log \
                 WHERE command_type IN ('Connect', 'Quit', 'Error') \
                 ORDER BY event_time DESC LIMIT 100",
            )
            .await
            .unwrap_or_default();
        for row in &general_rows {
            let level = match row.get("command_type").and_then(|v| v.as_str()) {
                Some("Error") => "error",
                _ => "info",
            };
            entries.push(json!({
                "source": "general_log",
                "level": level,
                "timestamp": row.get("event_time"),
                "user": row.get("user_host"),
                "message": row.get("argument"),
            }));
        }

        // Current long-running queries from processlist
        let proc_rows = self
            .query_to_json(
                conn,
                "SELECT ID, USER, HOST, DB, COMMAND, TIME, STATE, INFO \
                 FROM information_schema.PROCESSLIST \
                 WHERE COMMAND != 'Sleep' AND TIME > 60 AND INFO IS NOT NULL \
                 ORDER BY TIME DESC LIMIT 50",
            )
            .await
            .unwrap_or_default();
        for row in &proc_rows {
            entries.push(json!({
                "source": "processlist",
                "level": "warning",
                "message": format!("Long query ({}s): {}",
                    row.get("TIME").and_then(|v| v.as_str()).unwrap_or("?"),
                    row.get("INFO").and_then(|v| v.as_str()).unwrap_or("?")
                ),
                "user": row.get("USER"),
                "duration_seconds": row.get("TIME"),
            }));
        }

        let error_count = entries.iter().filter(|e| e["level"] == "error").count();
        let warning_count = entries.iter().filter(|e| e["level"] == "warning").count();
        let slow_count = entries.iter().filter(|e| e["source"] == "slow_query").count();

        let summary = json!({
            "total_entries": entries.len(),
            "error_count": error_count,
            "warning_count": warning_count,
            "slow_query_count": slow_count,
            "entries": entries,
        });

        Ok(vec![summary])
    }
}

#[async_trait::async_trait]
impl Provider for MySqlProvider {
    fn name(&self) -> &str {
        "mysql"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        let mut conn = self.connect().await?;
        let result = match resource_type {
            "databases" => self.gather_databases(&mut conn).await,
            "users" => self.gather_users(&mut conn).await,
            "grants" => self.gather_grants(&mut conn).await,
            "variables" => self.gather_variables(&mut conn).await,
            "status" => self.gather_status(&mut conn).await,
            "engines" => self.gather_engines(&mut conn).await,
            "processlist" => self.gather_processlist(&mut conn).await,
            "db_stats" => self.gather_db_stats(&mut conn).await,
            "logs" => self.gather_logs(&mut conn).await,
            "replication" => self.gather_replication(&mut conn).await,
            "table_stats" => self.gather_table_stats(&mut conn).await,
            "indexes" => self.gather_indexes(&mut conn).await,
            "innodb_status" => self.gather_innodb_status(&mut conn).await,
            "schema_sizes" => self.gather_schema_sizes(&mut conn).await,
            _ => {
                return Err(ProviderError::UnsupportedResourceType(
                    resource_type.to_string(),
                ))
            }
        };
        conn.disconnect().await.ok();
        result
    }

    async fn execute_sql(&self, sql: &str) -> Result<String, ProviderError> {
        MySqlProvider::execute_sql(self, sql).await
    }
}

fn extract_innodb_metric(text: &str, re: &regex::Regex) -> Option<i64> {
    re.captures(text)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse().ok())
}

fn parse_innodb_status(raw: &str) -> Value {
    use std::sync::LazyLock;
    static RE_HISTORY: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"History list length\s+(\d+)").unwrap());
    static RE_BP_TOTAL: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"Buffer pool size\s+(\d+)").unwrap());
    static RE_BP_FREE: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"Free buffers\s+(\d+)").unwrap());
    static RE_BP_DIRTY: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"Modified db pages\s+(\d+)").unwrap());
    static RE_INSERTS: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(\d+) inserts").unwrap());
    static RE_UPDATES: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(\d+) updates").unwrap());
    static RE_DELETES: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(\d+) deletes").unwrap());
    static RE_READS: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r"(\d+) reads").unwrap());

    let history_list_length = extract_innodb_metric(raw, &RE_HISTORY).unwrap_or(0);
    let bp_total = extract_innodb_metric(raw, &RE_BP_TOTAL).unwrap_or(0);
    let bp_free = extract_innodb_metric(raw, &RE_BP_FREE).unwrap_or(0);
    let bp_dirty = extract_innodb_metric(raw, &RE_BP_DIRTY).unwrap_or(0);
    let rows_inserted = extract_innodb_metric(raw, &RE_INSERTS).unwrap_or(0);
    let rows_updated = extract_innodb_metric(raw, &RE_UPDATES).unwrap_or(0);
    let rows_deleted = extract_innodb_metric(raw, &RE_DELETES).unwrap_or(0);
    let rows_read = extract_innodb_metric(raw, &RE_READS).unwrap_or(0);
    let deadlocks = if raw.contains("LATEST DETECTED DEADLOCK") { 1 } else { 0 };

    json!({
        "buffer_pool_pages_total": bp_total,
        "buffer_pool_pages_free": bp_free,
        "buffer_pool_pages_dirty": bp_dirty,
        "rows_inserted": rows_inserted,
        "rows_updated": rows_updated,
        "rows_deleted": rows_deleted,
        "rows_read": rows_read,
        "history_list_length": history_list_length,
        "deadlocks_detected": deadlocks,
        "raw_status": raw,
    })
}

/// Turn a result row into JSON without ever asking a column for a type it does
/// not hold.
///
/// The previous shape tried `Option<String>`, then `Option<i64>`, then
/// `Option<f64>`, expecting each failed attempt to answer `None`.
/// `mysql_async::Row::get` panics instead, so the very first attempt aborted the
/// process on any integer column — `kxn mysql://...` crashed on a real server
/// before printing a single verdict. Matching the wire value cannot fail.
fn row_to_json(row: &Row) -> Value {
    let columns = row.columns_ref();
    let mut map = serde_json::Map::new();
    for (i, col) in columns.iter().enumerate() {
        let name = col.name_str().to_string();
        let val = match row.as_ref(i) {
            None | Some(mysql_async::Value::NULL) => Value::Null,
            // MySQL hands back strings, and anything it does not have a native
            // type for, as bytes.
            Some(mysql_async::Value::Bytes(b)) => {
                Value::String(String::from_utf8_lossy(b).to_string())
            }
            Some(mysql_async::Value::Int(n)) => json!(n),
            Some(mysql_async::Value::UInt(n)) => json!(n),
            Some(mysql_async::Value::Float(f)) => json!(f),
            Some(mysql_async::Value::Double(f)) => json!(f),
            // Dates and times as the server would render them, so rules can
            // compare them as strings rather than against a debug format.
            Some(value @ (mysql_async::Value::Date(..) | mysql_async::Value::Time(..))) => {
                Value::String(value.as_sql(true).trim_matches('\'').to_string())
            }
        };
        map.insert(name, val);
    }
    Value::Object(map)
}

#[cfg(test)]
mod tls_tests {
    use super::*;
    use crate::db_tls::DbSslMode;

    /// The default must encrypt. The provider used to build its options with
    /// no `ssl_opts` at all, so every scan of every MySQL server — credentials
    /// included — crossed the network in the clear with no way to ask for
    /// anything else.
    #[test]
    fn the_default_is_not_cleartext() {
        let p = MySqlProvider::new(json!({ "MYSQL_HOST": "db", "MYSQL_USER": "u" })).expect("provider");
        assert_eq!(p.ssl_mode, DbSslMode::Prefer);
        assert!(p.opts.ssl_opts().is_some(), "prefer must offer TLS");
        // And the fallback the mode promises is actually available.
        assert!(p.plaintext_opts.ssl_opts().is_none());
    }

    #[test]
    fn disable_really_disables() {
        let p = MySqlProvider::new(json!({
            "MYSQL_HOST": "db", "MYSQL_USER": "u", "SSLMODE": "disable"
        }))
        .expect("provider");
        assert!(p.opts.ssl_opts().is_none());
    }

    /// Only the `verify-` modes authenticate the server; `require` encrypts
    /// without checking who it is talking to, as it does in libpq.
    #[test]
    fn only_the_verify_modes_validate_the_certificate() {
        let lax = MySqlProvider::new(json!({
            "MYSQL_HOST": "db", "MYSQL_USER": "u", "SSLMODE": "require"
        }))
        .expect("provider");
        let ssl = lax.opts.ssl_opts().expect("tls");
        assert!(ssl.accept_invalid_certs());
        assert!(ssl.skip_domain_validation());

        let strict = MySqlProvider::new(json!({
            "MYSQL_HOST": "db", "MYSQL_USER": "u", "SSLMODE": "verify-full"
        }))
        .expect("provider");
        let ssl = strict.opts.ssl_opts().expect("tls");
        assert!(!ssl.accept_invalid_certs());
        assert!(!ssl.skip_domain_validation());
    }

    #[test]
    fn an_unknown_mode_refuses_the_provider() {
        assert!(MySqlProvider::new(json!({
            "MYSQL_HOST": "db", "MYSQL_USER": "u", "SSLMODE": "requrie"
        }))
        .is_err());
    }
}
