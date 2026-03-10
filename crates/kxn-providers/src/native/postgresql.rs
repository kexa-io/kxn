use crate::config::{get_config_or_env, require_config};
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Value};
use tokio_postgres::{Client, Column, NoTls, Row};

const RESOURCE_TYPES: &[&str] = &[
    "databases",
    "roles",
    "settings",
    "stat_activity",
    "extensions",
    "db_stats",
    "logs",
    "replication",
    "table_stats",
    "indexes",
    "locks",
    "tablespaces",
];

pub struct PostgresqlProvider {
    host: String,
    user: String,
    password: String,
    port: u16,
}

impl PostgresqlProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let host = require_config(&config, "PG_HOST", Some("PG"))?;
        let user = require_config(&config, "PG_USER", Some("PG"))?;
        let password = get_config_or_env(&config, "PG_PASSWORD", Some("PG")).unwrap_or_default();
        let port: u16 = get_config_or_env(&config, "PG_PORT", Some("PG"))
            .and_then(|p| p.parse().ok())
            .unwrap_or(5432);

        Ok(Self {
            host,
            user,
            password,
            port,
        })
    }

    async fn connect(&self, dbname: &str) -> Result<Client, ProviderError> {
        let connstr = format!(
            "host={} user={} password={} port={} dbname={}",
            self.host, self.user, self.password, self.port, dbname
        );
        let (client, connection) = tokio_postgres::connect(&connstr, NoTls)
            .await
            .map_err(|e| ProviderError::Connection(format!("PostgreSQL: {}", e)))?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::error!("PostgreSQL connection error: {}", e);
            }
        });

        Ok(client)
    }

    async fn query_to_json(
        &self,
        client: &Client,
        sql: &str,
    ) -> Result<Vec<Value>, ProviderError> {
        let rows = client
            .query(sql, &[])
            .await
            .map_err(|e| ProviderError::Query(format!("{}: {}", sql, e)))?;

        Ok(rows.iter().map(row_to_json).collect())
    }

    /// Execute a SQL statement (for remediation). Returns affected rows or result.
    pub async fn execute_sql(&self, sql: &str) -> Result<String, ProviderError> {
        let client = self.connect("postgres").await?;
        // Split on semicolons for multi-statement support
        let statements: Vec<&str> = sql.split(';').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        let mut results = Vec::new();
        for stmt in &statements {
            client
                .execute(*stmt, &[])
                .await
                .map_err(|e| ProviderError::Query(format!("{}: {}", stmt, e)))?;
            results.push(format!("OK: {}", stmt));
        }
        Ok(results.join("\n"))
    }

    async fn gather_databases(&self) -> Result<Vec<Value>, ProviderError> {
        let client = self.connect("postgres").await?;

        let db_rows = client
            .query(
                "SELECT datname FROM pg_database WHERE datistemplate = false",
                &[],
            )
            .await
            .map_err(|e| ProviderError::Query(format!("pg_database: {}", e)))?;

        let mut databases = Vec::new();

        for db_row in &db_rows {
            let db_name: String = db_row.get(0);
            let mut db_info = json!({ "name": db_name });

            // Connect to each DB for detailed info
            if let Ok(db_client) = self.connect(&db_name).await {
                // Tables
                let tables_sql = "SELECT schemaname, tablename, tableowner, hasindexes, hasrules, hastriggers \
                    FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema')";
                if let Ok(tables) = self.query_to_json(&db_client, tables_sql).await {
                    db_info["tables"] = json!(tables);
                }

                // Columns
                let cols_sql = "SELECT table_schema, table_name, column_name, data_type, is_nullable, column_default \
                    FROM information_schema.columns WHERE table_schema NOT IN ('pg_catalog', 'information_schema')";
                if let Ok(columns) = self.query_to_json(&db_client, cols_sql).await {
                    db_info["columns"] = json!(columns);
                }

                // Indexes
                let idx_sql = "SELECT schemaname, tablename, indexname, indexdef \
                    FROM pg_indexes WHERE schemaname NOT IN ('pg_catalog', 'information_schema')";
                if let Ok(indexes) = self.query_to_json(&db_client, idx_sql).await {
                    db_info["indexes"] = json!(indexes);
                }

                // Views
                let views_sql = "SELECT schemaname, viewname, viewowner, definition \
                    FROM pg_views WHERE schemaname NOT IN ('pg_catalog', 'information_schema')";
                if let Ok(views) = self.query_to_json(&db_client, views_sql).await {
                    db_info["views"] = json!(views);
                }

                // Functions
                let funcs_sql = "SELECT n.nspname as schema, p.proname as name, \
                    pg_get_function_arguments(p.oid) as arguments, \
                    pg_get_function_result(p.oid) as return_type \
                    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
                    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')";
                if let Ok(functions) = self.query_to_json(&db_client, funcs_sql).await {
                    db_info["functions"] = json!(functions);
                }

                // Triggers
                let triggers_sql = "SELECT trigger_schema, trigger_name, event_manipulation, \
                    event_object_table, action_statement, action_timing \
                    FROM information_schema.triggers WHERE trigger_schema NOT IN ('pg_catalog', 'information_schema')";
                if let Ok(triggers) = self.query_to_json(&db_client, triggers_sql).await {
                    db_info["triggers"] = json!(triggers);
                }
            }

            databases.push(db_info);
        }

        Ok(databases)
    }

    async fn gather_roles(&self) -> Result<Vec<Value>, ProviderError> {
        let client = self.connect("postgres").await?;
        self.query_to_json(
            &client,
            "SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, \
             rolcanlogin, rolreplication, rolconnlimit, rolvaliduntil, rolbypassrls \
             FROM pg_roles",
        )
        .await
    }

    async fn gather_settings(&self) -> Result<Vec<Value>, ProviderError> {
        let client = self.connect("postgres").await?;
        let rows = client
            .query("SELECT name, setting FROM pg_settings", &[])
            .await
            .map_err(|e| ProviderError::Query(format!("pg_settings: {}", e)))?;

        // Return as a single flat object {name: setting, ...} for easy rule evaluation
        let mut map = serde_json::Map::new();
        for row in &rows {
            let name: String = row.get(0);
            let setting: String = row.get(1);
            map.insert(name, Value::String(setting));
        }
        Ok(vec![Value::Object(map)])
    }

    async fn gather_stat_activity(&self) -> Result<Vec<Value>, ProviderError> {
        let client = self.connect("postgres").await?;
        self.query_to_json(
            &client,
            "SELECT datname, pid, usename, application_name, client_addr, \
             backend_start, state, query \
             FROM pg_stat_activity",
        )
        .await
    }

    async fn gather_extensions(&self) -> Result<Vec<Value>, ProviderError> {
        let client = self.connect("postgres").await?;
        self.query_to_json(
            &client,
            "SELECT extname, extversion, extrelocatable \
             FROM pg_extension",
        )
        .await
    }

    async fn gather_db_stats(&self) -> Result<Vec<Value>, ProviderError> {
        let client = self.connect("postgres").await?;
        let mut stats = serde_json::Map::new();

        // Connection counts
        let rows = self
            .query_to_json(
                &client,
                "SELECT count(*) as total, \
                 count(*) FILTER (WHERE state = 'active') as active, \
                 count(*) FILTER (WHERE state = 'idle') as idle, \
                 count(*) FILTER (WHERE state = 'idle in transaction') as idle_in_transaction, \
                 count(*) FILTER (WHERE wait_event_type IS NOT NULL) as waiting \
                 FROM pg_stat_activity WHERE backend_type = 'client backend'",
            )
            .await?;
        if let Some(row) = rows.first() {
            for (k, v) in row.as_object().into_iter().flatten() {
                stats.insert(format!("connections_{}", k), v.clone());
            }
        }

        // Max connections
        let max_rows = self
            .query_to_json(&client, "SELECT setting::int as max_connections FROM pg_settings WHERE name = 'max_connections'")
            .await?;
        if let Some(row) = max_rows.first() {
            if let Some(v) = row.get("max_connections") {
                stats.insert("connections_max".into(), v.clone());
            }
        }

        // Database-level stats (aggregated)
        let db_rows = self
            .query_to_json(
                &client,
                "SELECT sum(xact_commit)::bigint as transactions_committed, \
                 sum(xact_rollback)::bigint as transactions_rolled_back, \
                 sum(blks_read)::bigint as blocks_read, \
                 sum(blks_hit)::bigint as blocks_hit, \
                 sum(tup_returned)::bigint as tuples_returned, \
                 sum(tup_fetched)::bigint as tuples_fetched, \
                 sum(tup_inserted)::bigint as tuples_inserted, \
                 sum(tup_updated)::bigint as tuples_updated, \
                 sum(tup_deleted)::bigint as tuples_deleted, \
                 sum(conflicts)::bigint as conflicts, \
                 sum(deadlocks)::bigint as deadlocks, \
                 sum(temp_files)::bigint as temp_files, \
                 sum(temp_bytes)::bigint as temp_bytes \
                 FROM pg_stat_database",
            )
            .await?;
        if let Some(row) = db_rows.first() {
            for (k, v) in row.as_object().into_iter().flatten() {
                stats.insert(k.clone(), v.clone());
            }
        }

        // Cache hit ratio
        let cache_rows = self
            .query_to_json(
                &client,
                "SELECT CASE WHEN (sum(blks_hit) + sum(blks_read)) = 0 THEN 0.0 \
                 ELSE round(sum(blks_hit)::numeric / (sum(blks_hit) + sum(blks_read)) * 100, 2)::float8 END as cache_hit_ratio \
                 FROM pg_stat_database",
            )
            .await?;
        if let Some(row) = cache_rows.first() {
            if let Some(v) = row.get("cache_hit_ratio") {
                stats.insert("cache_hit_ratio".into(), v.clone());
            }
        }

        // BGWriter/Checkpointer stats (PG17+ moved to pg_stat_checkpointer)
        let bgw_sql = "SELECT checkpoints_timed, checkpoints_req, \
             buffers_checkpoint, buffers_clean, buffers_backend, buffers_alloc \
             FROM pg_stat_bgwriter";
        let ckpt_sql = "SELECT num_timed as checkpoints_timed, num_requested as checkpoints_req, \
             buffers_written as buffers_checkpoint \
             FROM pg_stat_checkpointer";
        let bgw_rows = match self.query_to_json(&client, bgw_sql).await {
            Ok(rows) => rows,
            Err(_) => self.query_to_json(&client, ckpt_sql).await.unwrap_or_default(),
        };
        if let Some(row) = bgw_rows.first() {
            for (k, v) in row.as_object().into_iter().flatten() {
                stats.insert(k.clone(), v.clone());
            }
        }

        // Replication lag (if replica)
        let lag_rows = self
            .query_to_json(
                &client,
                "SELECT CASE WHEN pg_is_in_recovery() \
                 THEN EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()))::float \
                 ELSE 0 END as replication_lag_seconds",
            )
            .await?;
        if let Some(row) = lag_rows.first() {
            if let Some(v) = row.get("replication_lag_seconds") {
                stats.insert("replication_lag_seconds".into(), v.clone());
            }
        }

        // Database size
        let size_rows = self
            .query_to_json(
                &client,
                "SELECT sum(pg_database_size(datname))::bigint as total_size_bytes \
                 FROM pg_database WHERE datistemplate = false",
            )
            .await?;
        if let Some(row) = size_rows.first() {
            if let Some(v) = row.get("total_size_bytes") {
                stats.insert("total_size_bytes".into(), v.clone());
            }
        }

        // Long-running queries count
        let long_rows = self
            .query_to_json(
                &client,
                "SELECT count(*) as long_running_queries \
                 FROM pg_stat_activity \
                 WHERE state = 'active' AND query_start < now() - interval '5 minutes'",
            )
            .await?;
        if let Some(row) = long_rows.first() {
            if let Some(v) = row.get("long_running_queries") {
                stats.insert("long_running_queries".into(), v.clone());
            }
        }

        // Table bloat estimate (dead tuples)
        let dead_rows = self
            .query_to_json(
                &client,
                "SELECT COALESCE(sum(n_dead_tup), 0)::bigint as dead_tuples, \
                 COALESCE(sum(n_live_tup), 0)::bigint as live_tuples \
                 FROM pg_stat_user_tables",
            )
            .await?;
        if let Some(row) = dead_rows.first() {
            for (k, v) in row.as_object().into_iter().flatten() {
                stats.insert(k.clone(), v.clone());
            }
        }

        Ok(vec![Value::Object(stats)])
    }

    async fn gather_replication(&self) -> Result<Vec<Value>, ProviderError> {
        let client = self.connect("postgres").await?;

        let slots = self
            .query_to_json(
                &client,
                "SELECT slot_name, plugin, slot_type, active, \
                 restart_lsn, confirmed_flush_lsn \
                 FROM pg_replication_slots",
            )
            .await
            .unwrap_or_default();

        let replicas = self
            .query_to_json(
                &client,
                "SELECT client_addr, state, sent_lsn, write_lsn, \
                 flush_lsn, replay_lsn, sync_state \
                 FROM pg_stat_replication",
            )
            .await
            .unwrap_or_default();

        let active_count = slots
            .iter()
            .filter(|s| s.get("active") == Some(&json!(true)))
            .count();

        Ok(vec![json!({
            "slots": slots,
            "replicas": replicas,
            "slot_count": slots.len(),
            "active_slot_count": active_count,
            "replica_count": replicas.len(),
        })])
    }

    async fn gather_table_stats(&self) -> Result<Vec<Value>, ProviderError> {
        let client = self.connect("postgres").await?;
        self.query_to_json(
            &client,
            "SELECT schemaname, relname, n_live_tup, n_dead_tup, \
             CASE WHEN n_live_tup > 0 \
               THEN round(100.0 * n_dead_tup / (n_live_tup + n_dead_tup), 2) \
               ELSE 0 END as dead_ratio, \
             last_vacuum, last_autovacuum, last_analyze, last_autoanalyze, \
             vacuum_count, autovacuum_count, seq_scan, idx_scan, \
             pg_total_relation_size(\
               quote_ident(schemaname) || '.' || quote_ident(relname)\
             ) as total_bytes \
             FROM pg_stat_user_tables \
             ORDER BY n_dead_tup DESC LIMIT 100",
        )
        .await
    }

    async fn gather_indexes(&self) -> Result<Vec<Value>, ProviderError> {
        let client = self.connect("postgres").await?;
        self.query_to_json(
            &client,
            "SELECT schemaname, relname as table_name, \
             indexrelname as index_name, \
             idx_scan, idx_tup_read, idx_tup_fetch, \
             pg_relation_size(\
               quote_ident(schemaname) || '.' || quote_ident(indexrelname)\
             ) as index_size_bytes \
             FROM pg_stat_user_indexes \
             ORDER BY idx_scan ASC LIMIT 100",
        )
        .await
    }

    async fn gather_locks(&self) -> Result<Vec<Value>, ProviderError> {
        let client = self.connect("postgres").await?;
        self.query_to_json(
            &client,
            "SELECT locktype, mode, granted, \
             COALESCE(relation::regclass::text, 'N/A') as relation, \
             pid, \
             EXTRACT(EPOCH FROM (now() - a.query_start))::int \
               as duration_seconds \
             FROM pg_locks l \
             LEFT JOIN pg_stat_activity a USING (pid) \
             WHERE NOT l.granted \
                OR a.wait_event_type = 'Lock' \
             ORDER BY duration_seconds DESC NULLS LAST \
             LIMIT 50",
        )
        .await
    }

    async fn gather_tablespaces(&self) -> Result<Vec<Value>, ProviderError> {
        let client = self.connect("postgres").await?;
        self.query_to_json(
            &client,
            "SELECT spcname as name, \
             pg_tablespace_size(spcname) as size_bytes, \
             spcoptions \
             FROM pg_tablespace",
        )
        .await
    }

    async fn gather_logs(&self) -> Result<Vec<Value>, ProviderError> {
        let client = self.connect("postgres").await?;
        let mut entries = Vec::new();

        // Recent errors from pg_stat_activity (currently stuck/errored queries)
        let err_rows = self
            .query_to_json(
                &client,
                "SELECT datname, usename, application_name, client_addr, \
                 state, wait_event_type, wait_event, query, \
                 query_start, state_change, backend_start \
                 FROM pg_stat_activity \
                 WHERE state = 'active' AND query NOT LIKE '%pg_stat_activity%' \
                 ORDER BY query_start ASC LIMIT 50",
            )
            .await
            .unwrap_or_default();
        for row in &err_rows {
            entries.push(json!({
                "source": "pg_stat_activity",
                "level": "info",
                "message": row.get("query").unwrap_or(&Value::Null),
                "user": row.get("usename").unwrap_or(&Value::Null),
                "database": row.get("datname").unwrap_or(&Value::Null),
                "state": row.get("state").unwrap_or(&Value::Null),
                "started": row.get("query_start").unwrap_or(&Value::Null),
            }));
        }

        // Try to read CSV log if logging_collector is on
        let logfile_rows = self
            .query_to_json(
                &client,
                "SELECT pg_current_logfile() as logfile",
            )
            .await
            .unwrap_or_default();
        let logfile = logfile_rows
            .first()
            .and_then(|r| r.get("logfile"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if !logfile.is_empty() {
            // Read last 50KB of log
            let sql = format!(
                "SELECT pg_read_file('{}', greatest(pg_stat_file('{}').size - 51200, 0), 51200) as content",
                logfile.replace('\'', "''"),
                logfile.replace('\'', "''")
            );
            if let Ok(rows) = self.query_to_json(&client, &sql).await {
                if let Some(content) = rows.first().and_then(|r| r.get("content")).and_then(|v| v.as_str()) {
                    for line in content.lines() {
                        if line.is_empty() {
                            continue;
                        }
                        let level = if line.contains("ERROR") {
                            "error"
                        } else if line.contains("WARNING") {
                            "warning"
                        } else if line.contains("FATAL") || line.contains("PANIC") {
                            "fatal"
                        } else {
                            continue; // skip LOG/INFO lines
                        };
                        entries.push(json!({
                            "source": "pg_log",
                            "level": level,
                            "message": line.trim(),
                        }));
                    }
                }
            }
        }

        // Recent deadlocks/errors from pg_stat_database_conflicts
        let conflict_rows = self
            .query_to_json(
                &client,
                "SELECT datname, confl_tablespace, confl_lock, confl_snapshot, \
                 confl_bufferpin, confl_deadlock \
                 FROM pg_stat_database_conflicts \
                 WHERE confl_deadlock > 0 OR confl_lock > 0",
            )
            .await
            .unwrap_or_default();
        for row in &conflict_rows {
            entries.push(json!({
                "source": "pg_conflicts",
                "level": "error",
                "message": format!("Conflicts in {}: deadlocks={}, locks={}",
                    row.get("datname").and_then(|v| v.as_str()).unwrap_or("?"),
                    row.get("confl_deadlock").unwrap_or(&json!(0)),
                    row.get("confl_lock").unwrap_or(&json!(0)),
                ),
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
}

#[async_trait::async_trait]
impl Provider for PostgresqlProvider {
    fn name(&self) -> &str {
        "postgresql"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        match resource_type {
            "databases" => self.gather_databases().await,
            "roles" => self.gather_roles().await,
            "settings" => self.gather_settings().await,
            "stat_activity" => self.gather_stat_activity().await,
            "extensions" => self.gather_extensions().await,
            "db_stats" => self.gather_db_stats().await,
            "logs" => self.gather_logs().await,
            "replication" => self.gather_replication().await,
            "table_stats" => self.gather_table_stats().await,
            "indexes" => self.gather_indexes().await,
            "locks" => self.gather_locks().await,
            "tablespaces" => self.gather_tablespaces().await,
            _ => Err(ProviderError::UnsupportedResourceType(
                resource_type.to_string(),
            )),
        }
    }

    async fn execute_sql(&self, sql: &str) -> Result<String, ProviderError> {
        PostgresqlProvider::execute_sql(self, sql).await
    }
}

/// Convert a tokio-postgres Row to a serde_json::Value.
fn row_to_json(row: &Row) -> Value {
    let columns = row.columns();
    let mut map = serde_json::Map::new();

    for (i, col) in columns.iter().enumerate() {
        let name = col.name().to_string();
        let val = column_to_json(row, i, col);
        map.insert(name, val);
    }

    Value::Object(map)
}

fn column_to_json(row: &Row, idx: usize, col: &Column) -> Value {
    use tokio_postgres::types::Type;

    match *col.type_() {
        Type::BOOL => row
            .try_get::<_, Option<bool>>(idx)
            .unwrap_or(None)
            .map_or(Value::Null, |v| json!(v)),
        Type::INT2 => row
            .try_get::<_, Option<i16>>(idx)
            .unwrap_or(None)
            .map_or(Value::Null, |v| json!(v)),
        Type::INT4 => row
            .try_get::<_, Option<i32>>(idx)
            .unwrap_or(None)
            .map_or(Value::Null, |v| json!(v)),
        Type::INT8 => row
            .try_get::<_, Option<i64>>(idx)
            .unwrap_or(None)
            .map_or(Value::Null, |v| json!(v)),
        Type::FLOAT4 => row
            .try_get::<_, Option<f32>>(idx)
            .unwrap_or(None)
            .map_or(Value::Null, |v| json!(v)),
        Type::FLOAT8 => row
            .try_get::<_, Option<f64>>(idx)
            .unwrap_or(None)
            .map_or(Value::Null, |v| json!(v)),
        Type::OID => row
            .try_get::<_, Option<u32>>(idx)
            .unwrap_or(None)
            .map_or(Value::Null, |v| json!(v)),
        Type::INET => row
            .try_get::<_, Option<std::net::IpAddr>>(idx)
            .unwrap_or(None)
            .map_or(Value::Null, |v| json!(v.to_string())),
        Type::TIMESTAMPTZ => row
            .try_get::<_, Option<chrono::DateTime<chrono::Utc>>>(idx)
            .unwrap_or(None)
            .map_or(Value::Null, |v| json!(v.to_rfc3339())),
        Type::TIMESTAMP => row
            .try_get::<_, Option<chrono::NaiveDateTime>>(idx)
            .unwrap_or(None)
            .map_or(Value::Null, |v| json!(v.to_string())),
        _ => {
            // Fallback: try as String
            row.try_get::<_, Option<String>>(idx)
                .unwrap_or(None)
                .map_or(Value::Null, Value::String)
        }
    }
}
