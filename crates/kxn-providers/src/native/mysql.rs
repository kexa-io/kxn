use crate::config::{get_config_or_env, require_config};
use crate::error::ProviderError;
use crate::traits::Provider;
use mysql_async::prelude::*;
use mysql_async::{Conn, Opts, OptsBuilder, Row};
use serde_json::{json, Value};

const RESOURCE_TYPES: &[&str] = &[
    "databases",
    "users",
    "grants",
    "variables",
    "status",
    "engines",
    "processlist",
    "db_stats",
    "logs",
];

pub struct MySqlProvider {
    opts: Opts,
}

impl MySqlProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let host = require_config(&config, "MYSQL_HOST", Some("MYSQL"))?;
        let user = require_config(&config, "MYSQL_USER", Some("MYSQL"))?;
        let password = get_config_or_env(&config, "MYSQL_PASSWORD", Some("MYSQL")).unwrap_or_default();
        let port: u16 = get_config_or_env(&config, "MYSQL_PORT", Some("MYSQL"))
            .and_then(|p| p.parse().ok())
            .unwrap_or(3306);

        let opts = OptsBuilder::default()
            .ip_or_hostname(host)
            .user(Some(user))
            .pass(Some(password))
            .tcp_port(port);

        Ok(Self {
            opts: Opts::from(opts),
        })
    }

    async fn connect(&self) -> Result<Conn, ProviderError> {
        Conn::new(self.opts.clone())
            .await
            .map_err(|e| ProviderError::Connection(format!("MySQL: {}", e)))
    }

    async fn query_to_json(&self, conn: &mut Conn, sql: &str) -> Result<Vec<Value>, ProviderError> {
        let rows: Vec<Row> = conn
            .query(sql)
            .await
            .map_err(|e| ProviderError::Query(format!("{}: {}", sql, e)))?;

        Ok(rows.iter().map(row_to_json).collect())
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

            // Get tables for each database
            let tables_sql = format!(
                "SELECT TABLE_NAME, TABLE_TYPE, ENGINE, TABLE_ROWS, DATA_LENGTH, TABLE_COLLATION \
                 FROM information_schema.TABLES WHERE TABLE_SCHEMA = '{}'",
                db_name.replace('\'', "''")
            );
            if let Ok(tables) = self.query_to_json(conn, &tables_sql).await {
                db_info["tables"] = json!(tables);
            }

            // Get columns
            let cols_sql = format!(
                "SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY, EXTRA, COLUMN_DEFAULT \
                 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '{}'",
                db_name.replace('\'', "''")
            );
            if let Ok(columns) = self.query_to_json(conn, &cols_sql).await {
                db_info["columns"] = json!(columns);
            }

            // Get indexes
            let idx_sql = format!(
                "SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, COLUMN_NAME, INDEX_TYPE \
                 FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = '{}'",
                db_name.replace('\'', "''")
            );
            if let Ok(indexes) = self.query_to_json(conn, &idx_sql).await {
                db_info["indexes"] = json!(indexes);
            }

            databases.push(db_info);
        }

        Ok(databases)
    }

    async fn gather_users(&self, conn: &mut Conn) -> Result<Vec<Value>, ProviderError> {
        self.query_to_json(conn, "SELECT * FROM mysql.user").await
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
            _ => {
                return Err(ProviderError::UnsupportedResourceType(
                    resource_type.to_string(),
                ))
            }
        };
        conn.disconnect().await.ok();
        result
    }
}

fn row_to_json(row: &Row) -> Value {
    let columns = row.columns_ref();
    let mut map = serde_json::Map::new();
    for (i, col) in columns.iter().enumerate() {
        let name = col.name_str().to_string();
        let val: Value = if let Some(s) = row.get::<Option<String>, _>(i).flatten() {
            Value::String(s)
        } else if let Some(n) = row.get::<Option<i64>, _>(i).flatten() {
            json!(n)
        } else if let Some(f) = row.get::<Option<f64>, _>(i).flatten() {
            json!(f)
        } else if let Some(b) = row.get::<Option<Vec<u8>>, _>(i).flatten() {
            Value::String(String::from_utf8_lossy(&b).to_string())
        } else {
            Value::Null
        };
        map.insert(name, val);
    }
    Value::Object(map)
}
