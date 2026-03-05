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
