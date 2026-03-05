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

        Ok(rows.iter().map(|row| row_to_json(row)).collect())
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
        self.query_to_json(
            &client,
            "SELECT name, setting, unit, category, short_desc, source, boot_val, reset_val \
             FROM pg_settings",
        )
        .await
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
            _ => Err(ProviderError::UnsupportedResourceType(
                resource_type.to_string(),
            )),
        }
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
                .map_or(Value::Null, |v| Value::String(v))
        }
    }
}
