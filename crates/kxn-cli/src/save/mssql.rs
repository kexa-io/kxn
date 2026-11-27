//! Microsoft SQL Server (and Azure SQL) save backend: scan results, metrics
//! and logs, through the `tiberius` driver (TLS by the system OpenSSL, as
//! for PostgreSQL).
//!
//! URI: `mssql://user:password@host[:1433][/database][?trust_server_certificate=true]`,
//! also accepted as `sqlserver://`. The database defaults to `kxn` and must
//! exist; kxn creates its three tables in the `dbo` schema on first use.
//! The connection is encrypted and the server certificate is verified.
//! `trust_server_certificate=true` accepts a self-signed certificate (the
//! default of a SQL Server container); `encrypt=false` turns TLS off.
//! The `retention` windows of the `[[save]]` block delete older rows after
//! each write, as the PostgreSQL backend does.

use anyhow::{bail, Context, Result};
use kxn_rules::SaveConfig;
use tiberius::{AuthMethod, Client, Config, EncryptionLevel, ToSql};
use tokio::net::TcpStream;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

use super::{resolve_url, LogRecord, MetricRecord, ScanRecord};

type Conn = Client<Compat<TcpStream>>;

/// SQL Server accepts at most 2100 parameters per statement.
const MAX_PARAMS: usize = 2000;

#[derive(Debug, PartialEq)]
struct Endpoint {
    host: String,
    port: u16,
    user: String,
    password: String,
    database: String,
    encrypt: bool,
    trust_cert: bool,
}

fn parse_uri(uri: &str) -> Result<Endpoint> {
    let rest = uri
        .strip_prefix("mssql://")
        .or_else(|| uri.strip_prefix("sqlserver://"))
        .with_context(|| format!("not an mssql:// URI: {uri}"))?;
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (auth, hostpart) = rest
        .rsplit_once('@')
        .context("mssql:// URI needs user:password@host (SQL Server authentication)")?;
    let (user, password) = auth.split_once(':').unwrap_or((auth, ""));
    let (hostport, database) = match hostpart.split_once('/') {
        Some((h, d)) if !d.trim_end_matches('/').is_empty() => (h, d.trim_end_matches('/')),
        Some((h, _)) => (h, "kxn"),
        None => (hostpart, "kxn"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().with_context(|| format!("invalid port in {uri}"))?),
        None => (hostport, 1433),
    };
    if host.is_empty() || user.is_empty() {
        bail!("mssql:// URI needs a user and a host: {uri}");
    }
    let mut encrypt = true;
    let mut trust_cert = false;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, "true"));
        let on = matches!(v.to_ascii_lowercase().as_str(), "true" | "yes" | "1" | "on");
        match k.to_ascii_lowercase().as_str() {
            "encrypt" => encrypt = on,
            "trust_server_certificate" | "trustservercertificate" => trust_cert = on,
            other => bail!("unknown mssql:// option '{other}' (encrypt, trust_server_certificate)"),
        }
    }
    Ok(Endpoint {
        host: host.to_string(),
        port,
        user: pct_decode(user),
        password: pct_decode(password),
        database: pct_decode(database),
        encrypt,
        trust_cert,
    })
}

/// Decode `%XX` escapes, so a password can hold `@`, `:` or `/`.
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn connect(config: &SaveConfig) -> Result<Conn> {
    let ep = parse_uri(&resolve_url(&config.url))?;
    let mut cfg = Config::new();
    cfg.host(&ep.host);
    cfg.port(ep.port);
    cfg.database(&ep.database);
    cfg.authentication(AuthMethod::sql_server(&ep.user, &ep.password));
    cfg.encryption(if ep.encrypt { EncryptionLevel::Required } else { EncryptionLevel::NotSupported });
    if ep.trust_cert {
        cfg.trust_cert();
    }
    let tcp = TcpStream::connect(cfg.get_addr())
        .await
        .with_context(|| format!("SQL Server connection to {}:{} failed", ep.host, ep.port))?;
    tcp.set_nodelay(true)?;
    Client::connect(cfg, tcp.compat_write()).await.map_err(|e| {
        let hint = if ep.encrypt && !ep.trust_cert {
            " (a self-signed server certificate needs ?trust_server_certificate=true)"
        } else {
            ""
        };
        anyhow::anyhow!("SQL Server TLS handshake or login to {} failed: {e}{hint}", ep.host)
    })
}

const CREATE_SCANS: &str = "IF OBJECT_ID(N'dbo.scans', N'U') IS NULL CREATE TABLE dbo.scans (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    created_at DATETIME2(3) NOT NULL,
    target NVARCHAR(255) NOT NULL,
    provider NVARCHAR(255) NOT NULL,
    rule_name NVARCHAR(255) NOT NULL,
    rule_description NVARCHAR(MAX),
    level INT NOT NULL,
    level_label NVARCHAR(32),
    object_type NVARCHAR(255),
    object_content NVARCHAR(MAX),
    error BIT NOT NULL,
    messages NVARCHAR(MAX),
    conditions NVARCHAR(MAX),
    compliance NVARCHAR(MAX),
    batch_id NVARCHAR(255),
    origin NVARCHAR(255),
    tags NVARCHAR(MAX),
    INDEX idx_scans_created (created_at),
    INDEX idx_scans_target (target, created_at)
)";

const CREATE_METRICS: &str = "IF OBJECT_ID(N'dbo.metrics', N'U') IS NULL CREATE TABLE dbo.metrics (
    time DATETIME2(3) NOT NULL,
    target NVARCHAR(255) NOT NULL,
    provider NVARCHAR(255) NOT NULL,
    resource_type NVARCHAR(255) NOT NULL,
    metric_name NVARCHAR(255) NOT NULL,
    value_num FLOAT,
    value_str NVARCHAR(MAX),
    INDEX idx_metrics_time CLUSTERED (time),
    INDEX idx_metrics_name (target, resource_type, metric_name)
)";

const CREATE_LOGS: &str = "IF OBJECT_ID(N'dbo.logs', N'U') IS NULL CREATE TABLE dbo.logs (
    id BIGINT IDENTITY(1,1) PRIMARY KEY NONCLUSTERED,
    time DATETIME2(6) NOT NULL,
    target NVARCHAR(255) NOT NULL,
    source NVARCHAR(64) NOT NULL,
    level NVARCHAR(32) NOT NULL,
    message NVARCHAR(MAX) NOT NULL,
    host NVARCHAR(255),
    unit NVARCHAR(255),
    batch_id NVARCHAR(255),
    tags NVARCHAR(MAX),
    INDEX idx_logs_time CLUSTERED (time),
    INDEX idx_logs_target_level (target, level)
)";

/// Insert `rows` (each of `columns.len()` values) with multi-row `INSERT`s that
/// stay under SQL Server's parameter limit, inside one transaction.
async fn insert_rows(
    conn: &mut Conn,
    table: &str,
    columns: &[&str],
    rows: &[Vec<Box<dyn ToSql + Send + Sync>>],
) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let per_stmt = (MAX_PARAMS / columns.len()).clamp(1, 1000);
    conn.simple_query("BEGIN TRANSACTION").await?.into_results().await?;
    for chunk in rows.chunks(per_stmt) {
        let mut sql = format!("INSERT INTO dbo.{table} ({}) VALUES ", columns.join(", "));
        let mut n = 0;
        for (i, _) in chunk.iter().enumerate() {
            if i > 0 {
                sql.push_str(", ");
            }
            sql.push('(');
            for c in 0..columns.len() {
                if c > 0 {
                    sql.push_str(", ");
                }
                n += 1;
                sql.push_str(&format!("@P{n}"));
            }
            sql.push(')');
        }
        let params: Vec<&dyn ToSql> = chunk.iter().flatten().map(|b| b.as_ref() as &dyn ToSql).collect();
        if let Err(e) = conn.execute(sql, &params).await {
            let _ = conn.simple_query("ROLLBACK TRANSACTION").await;
            return Err(e).with_context(|| format!("SQL Server insert into {table} failed"));
        }
    }
    conn.simple_query("COMMIT TRANSACTION").await?.into_results().await?;
    Ok(())
}

/// Delete rows of `table` older than its retention window, as the
/// PostgreSQL backend does. A failure is logged, never returned.
async fn prune(conn: &mut Conn, config: &SaveConfig, table: &str, time_col: &str) {
    let secs = match config.retention.window_secs(table) {
        Ok(Some(secs)) if secs > 0 => secs,
        Ok(_) => return,
        Err(e) => {
            tracing::warn!(table, error = %e, "invalid retention value, skipping prune");
            return;
        }
    };
    let cutoff = chrono::Utc::now() - chrono::Duration::seconds(secs);
    let sql = format!("DELETE FROM dbo.{table} WHERE {time_col} < @P1");
    if let Err(e) = conn.execute(sql, &[&cutoff as &dyn ToSql]).await {
        tracing::warn!(table, error = %e, "retention prune failed");
    }
}

type Row = Vec<Box<dyn ToSql + Send + Sync>>;

pub async fn save(config: &SaveConfig, records: &[ScanRecord], metrics: &[MetricRecord]) -> Result<()> {
    let mut conn = connect(config).await?;

    let records: Vec<&ScanRecord> = records.iter().filter(|r| !config.only_errors || r.error).collect();
    if !records.is_empty() {
        conn.simple_query(CREATE_SCANS).await?.into_results().await.context("Failed to create scans table")?;
        let mut rows: Vec<Row> = Vec::with_capacity(records.len());
        for r in records {
            let mut tags: serde_json::Map<String, serde_json::Value> = config
                .tags
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()))))
                .collect();
            tags.extend(r.tags.iter().map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone()))));
            rows.push(vec![
                Box::new(r.timestamp),
                Box::new(r.target.clone()),
                Box::new(r.provider.clone()),
                Box::new(r.rule_name.clone()),
                Box::new(r.rule_description.clone()),
                Box::new(r.level as i32),
                Box::new(r.level_label.clone()),
                Box::new(r.object_type.clone()),
                Box::new(serde_json::to_string(&r.object_content)?),
                Box::new(r.error),
                Box::new(serde_json::to_string(&r.messages)?),
                Box::new(serde_json::to_string(&r.conditions)?),
                Box::new(serde_json::to_string(&r.compliance)?),
                Box::new(r.batch_id.clone()),
                Box::new(config.origin.clone()),
                Box::new(serde_json::Value::Object(tags).to_string()),
            ]);
        }
        insert_rows(
            &mut conn,
            "scans",
            &["created_at", "target", "provider", "rule_name", "rule_description", "level", "level_label",
              "object_type", "object_content", "error", "messages", "conditions", "compliance", "batch_id",
              "origin", "tags"],
            &rows,
        )
        .await?;
        prune(&mut conn, config, "scans", "created_at").await;
    }

    if !metrics.is_empty() {
        conn.simple_query(CREATE_METRICS).await?.into_results().await.context("Failed to create metrics table")?;
        let rows: Vec<Row> = metrics
            .iter()
            .map(|m| -> Row {
                vec![
                    Box::new(m.timestamp),
                    Box::new(m.target.clone()),
                    Box::new(m.provider.clone()),
                    Box::new(m.resource_type.clone()),
                    Box::new(m.metric_name.clone()),
                    Box::new(m.value_num),
                    Box::new(m.value_str.clone()),
                ]
            })
            .collect();
        insert_rows(
            &mut conn,
            "metrics",
            &["time", "target", "provider", "resource_type", "metric_name", "value_num", "value_str"],
            &rows,
        )
        .await?;
        prune(&mut conn, config, "metrics", "time").await;
    }
    Ok(())
}

pub async fn save_logs(config: &SaveConfig, logs: &[LogRecord]) -> Result<()> {
    if logs.is_empty() {
        return Ok(());
    }
    let mut conn = connect(config).await?;
    conn.simple_query(CREATE_LOGS).await?.into_results().await.context("Failed to create logs table")?;
    let mut rows: Vec<Row> = Vec::with_capacity(logs.len());
    for l in logs {
        rows.push(vec![
            Box::new(l.collected_at),
            Box::new(l.target.clone()),
            Box::new(l.source.clone()),
            Box::new(l.level.clone()),
            Box::new(l.message.clone()),
            Box::new(l.host.clone()),
            Box::new(l.unit.clone()),
            Box::new(l.batch_id.clone()),
            Box::new(serde_json::to_string(&l.tags)?),
        ]);
    }
    insert_rows(
        &mut conn,
        "logs",
        &["time", "target", "source", "level", "message", "host", "unit", "batch_id", "tags"],
        &rows,
    )
    .await?;
    prune(&mut conn, config, "logs", "time").await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_uri() {
        let ep = parse_uri("mssql://kxn:p%40ss@db.example:14330/audit?trust_server_certificate=true").unwrap();
        assert_eq!(
            ep,
            Endpoint {
                host: "db.example".into(),
                port: 14330,
                user: "kxn".into(),
                password: "p@ss".into(),
                database: "audit".into(),
                encrypt: true,
                trust_cert: true,
            }
        );
    }

    #[test]
    fn defaults_port_database_and_tls() {
        let ep = parse_uri("sqlserver://sa:x@mssql.kxn.svc").unwrap();
        assert_eq!((ep.port, ep.database.as_str(), ep.encrypt, ep.trust_cert), (1433, "kxn", true, false));
        assert!(!parse_uri("mssql://sa:x@h/?encrypt=false").unwrap().encrypt);
    }

    #[test]
    fn rejects_bad_uris() {
        assert!(parse_uri("mssql://host/db").is_err(), "no credentials");
        assert!(parse_uri("mssql://sa:x@h:port").is_err());
        assert!(parse_uri("mssql://sa:x@h/?tls=1").is_err(), "unknown option");
    }
}
