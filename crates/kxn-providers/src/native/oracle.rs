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
                let val: Value = match row.get::<String>(i) {
                    Ok(Some(s)) => Value::String(s),
                    _ => match row.get::<i64>(i) {
                        Ok(Some(n)) => json!(n),
                        _ => Value::Null,
                    },
                };
                map.insert(name.to_string(), val);
            }
            results.push(Value::Object(map));
        }

        Ok(results)
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
                self.query_to_json(
                    &session,
                    "SELECT NAME, VALUE, DISPLAY_VALUE, DESCRIPTION, ISDEFAULT FROM V$SYSTEM_PARAMETER",
                    &["name", "value", "display_value", "description", "isdefault"],
                ).await
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
            _ => Err(ProviderError::UnsupportedResourceType(
                resource_type.to_string(),
            )),
        }
    }
}
