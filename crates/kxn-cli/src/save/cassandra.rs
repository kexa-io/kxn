//! Cassandra (and ScyllaDB) save backend: scan results, metrics and logs.
//!
//! URI: `cassandra://[user:password@]host[:9042][/keyspace]`; the keyspace
//! defaults to `kxn`. kxn creates the keyspace when it is missing, with
//! `SimpleStrategy` and a replication factor of 1: on a multi-node cluster,
//! create it yourself first with the replication you need.
//!
//! Every table is partitioned by target and UTC day, so a partition never
//! grows past one day of one target, and clustered by time, newest first.
//! The `retention` windows of the `[[save]]` block become a TTL on each row,
//! so Cassandra drops old rows itself.

use anyhow::{bail, Context, Result};
use kxn_rules::SaveConfig;
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use scylla::statement::batch::{Batch, BatchType};
use scylla::statement::prepared::PreparedStatement;
use scylla::value::{CqlDate, CqlTimestamp};
use scylla::SerializeRow;
use std::collections::HashMap;
use uuid::Uuid;

use super::{resolve_url, LogRecord, MetricRecord, ScanRecord};

/// Rows sent per unlogged batch. Every row of a batch may land in another
/// partition, so batches stay small.
const BATCH_ROWS: usize = 50;

#[derive(Debug, PartialEq)]
struct Endpoint {
    node: String,
    user: Option<String>,
    password: Option<String>,
    keyspace: String,
}

fn parse_uri(uri: &str) -> Result<Endpoint> {
    // Errors quote the URI: never with its password.
    let shown = kxn_rules::secrets::redact(uri);
    let rest = uri
        .strip_prefix("cassandra://")
        .or_else(|| uri.strip_prefix("scylla://"))
        .with_context(|| format!("not a cassandra:// URI: {shown}"))?;
    let rest = rest.split('?').next().unwrap_or(rest);
    let (auth, hostpart) = match rest.rsplit_once('@') {
        Some((a, h)) => (Some(a), h),
        None => (None, rest),
    };
    let (hostport, keyspace) = match hostpart.split_once('/') {
        Some((h, k)) if !k.is_empty() => (h, k.trim_end_matches('/')),
        Some((h, _)) => (h, "kxn"),
        None => (hostpart, "kxn"),
    };
    if hostport.is_empty() {
        bail!("cassandra:// URI has no host: {shown}");
    }
    if !keyspace.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!("invalid Cassandra keyspace name '{keyspace}': letters, digits and _ only");
    }
    let node = if hostport.starts_with('[') || hostport.rsplit_once(':').is_some_and(|(_, p)| p.parse::<u16>().is_ok()) {
        hostport.to_string()
    } else {
        format!("{hostport}:9042")
    };
    let (user, password) = match auth {
        Some(a) => match a.split_once(':') {
            Some((u, p)) => (Some(pct_decode(u)), Some(pct_decode(p))),
            None => (Some(pct_decode(a)), None),
        },
        None => (None, None),
    };
    Ok(Endpoint { node, user, password, keyspace: keyspace.to_string() })
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

async fn connect(config: &SaveConfig) -> Result<(Session, String)> {
    let ep = parse_uri(&resolve_url(&config.url))?;
    let mut builder = SessionBuilder::new().known_node(&ep.node);
    if let Some(user) = &ep.user {
        builder = builder.user(user.clone(), ep.password.clone().unwrap_or_default());
    }
    let session = builder
        .build()
        .await
        .with_context(|| format!("Cassandra connection to {} failed", ep.node))?;
    let ks = ep.keyspace;
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {ks} WITH replication = \
                 {{'class': 'SimpleStrategy', 'replication_factor': 1}}"
            ),
            &[],
        )
        .await
        .with_context(|| format!("Failed to create keyspace {ks}"))?;
    Ok((session, ks))
}

async fn create_table(session: &Session, cql: String) -> Result<()> {
    session
        .query_unpaged(cql.clone(), &[])
        .await
        .with_context(|| format!("Failed to create table: {cql}"))?;
    Ok(())
}

fn scans_table(ks: &str) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {ks}.scans (\
         target text, day date, time timestamp, id uuid, \
         provider text, rule_name text, rule_description text, level int, level_label text, \
         object_type text, object_content text, error boolean, messages list<text>, \
         conditions text, compliance text, batch_id text, origin text, tags map<text, text>, \
         PRIMARY KEY ((target, day), time, id)) WITH CLUSTERING ORDER BY (time DESC, id ASC)"
    )
}

fn metrics_table(ks: &str) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {ks}.metrics (\
         target text, day date, time timestamp, id uuid, \
         provider text, resource_type text, metric_name text, value_num double, value_str text, \
         PRIMARY KEY ((target, day), time, id)) WITH CLUSTERING ORDER BY (time DESC, id ASC)"
    )
}

fn logs_table(ks: &str) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {ks}.logs (\
         target text, day date, time timestamp, id uuid, \
         source text, level text, message text, host text, unit text, \
         batch_id text, tags map<text, text>, \
         PRIMARY KEY ((target, day), time, id)) WITH CLUSTERING ORDER BY (time DESC, id ASC)"
    )
}

#[derive(SerializeRow)]
struct ScanRow {
    target: String,
    day: CqlDate,
    time: CqlTimestamp,
    id: Uuid,
    provider: String,
    rule_name: String,
    rule_description: String,
    level: i32,
    level_label: String,
    object_type: String,
    object_content: String,
    error: bool,
    messages: Vec<String>,
    conditions: String,
    compliance: String,
    batch_id: String,
    origin: String,
    tags: HashMap<String, String>,
}

#[derive(SerializeRow)]
struct MetricRow {
    target: String,
    day: CqlDate,
    time: CqlTimestamp,
    id: Uuid,
    provider: String,
    resource_type: String,
    metric_name: String,
    value_num: Option<f64>,
    value_str: Option<String>,
}

#[derive(SerializeRow)]
struct LogRow {
    target: String,
    day: CqlDate,
    time: CqlTimestamp,
    id: Uuid,
    source: String,
    level: String,
    message: String,
    host: Option<String>,
    unit: Option<String>,
    batch_id: String,
    tags: HashMap<String, String>,
}

/// `USING TTL n` for a table with a retention window, empty otherwise.
fn ttl_clause(config: &SaveConfig, table: &str) -> String {
    match config.retention.window_secs(table) {
        Ok(Some(secs)) if secs > 0 => format!(" USING TTL {}", secs.min(i32::MAX as i64)),
        Ok(_) => String::new(),
        Err(e) => {
            tracing::warn!(table, error = %e, "invalid retention value, rows kept without TTL");
            String::new()
        }
    }
}

fn ts(t: &chrono::DateTime<chrono::Utc>) -> CqlTimestamp {
    CqlTimestamp(t.timestamp_millis())
}

/// The UTC day of `t` as a CQL `date`: days since 1970-01-01, offset by 2^31.
fn day(t: &chrono::DateTime<chrono::Utc>) -> CqlDate {
    let days = t.timestamp().div_euclid(86_400);
    CqlDate(((1_i64 << 31) + days) as u32)
}

/// Send `rows` through `stmt` in unlogged batches of [`BATCH_ROWS`].
async fn insert_rows<V: scylla::serialize::row::SerializeRow>(
    session: &Session,
    stmt: &PreparedStatement,
    rows: Vec<V>,
) -> Result<()> {
    let mut rows = rows.into_iter().peekable();
    while rows.peek().is_some() {
        let chunk: Vec<V> = rows.by_ref().take(BATCH_ROWS).collect();
        let mut batch = Batch::new(BatchType::Unlogged);
        for _ in 0..chunk.len() {
            batch.append_statement(stmt.clone());
        }
        session.batch(&batch, chunk).await.context("Cassandra batch insert failed")?;
    }
    Ok(())
}

pub async fn save(config: &SaveConfig, records: &[ScanRecord], metrics: &[MetricRecord]) -> Result<()> {
    let (session, ks) = connect(config).await?;

    let records: Vec<&ScanRecord> = records.iter().filter(|r| !config.only_errors || r.error).collect();
    if !records.is_empty() {
        create_table(&session, scans_table(&ks)).await?;
        let stmt = session
            .prepare(format!(
                "INSERT INTO {ks}.scans (target, day, time, id, provider, rule_name, rule_description, \
                 level, level_label, object_type, object_content, error, messages, conditions, \
                 compliance, batch_id, origin, tags) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?){}",
                ttl_clause(config, "scans")
            ))
            .await
            .context("Failed to prepare scans insert")?;
        let mut rows = Vec::with_capacity(records.len());
        for r in records {
            let mut tags: HashMap<String, String> = config
                .tags
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())))
                .collect();
            tags.extend(r.tags.iter().map(|(k, v)| (k.clone(), v.clone())));
            rows.push(ScanRow {
                target: r.target.clone(),
                day: day(&r.timestamp),
                time: ts(&r.timestamp),
                id: Uuid::new_v4(),
                provider: r.provider.clone(),
                rule_name: r.rule_name.clone(),
                rule_description: r.rule_description.clone(),
                level: r.level as i32,
                level_label: r.level_label.clone(),
                object_type: r.object_type.clone(),
                object_content: serde_json::to_string(&r.object_content)?,
                error: r.error,
                messages: r.messages.clone(),
                conditions: serde_json::to_string(&r.conditions)?,
                compliance: serde_json::to_string(&r.compliance)?,
                batch_id: r.batch_id.clone(),
                origin: config.origin.clone(),
                tags,
            });
        }
        insert_rows(&session, &stmt, rows).await?;
    }

    if !metrics.is_empty() {
        create_table(&session, metrics_table(&ks)).await?;
        let stmt = session
            .prepare(format!(
                "INSERT INTO {ks}.metrics (target, day, time, id, provider, resource_type, metric_name, \
                 value_num, value_str) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?){}",
                ttl_clause(config, "metrics")
            ))
            .await
            .context("Failed to prepare metrics insert")?;
        let rows: Vec<_> = metrics
            .iter()
            .map(|m| MetricRow {
                target: m.target.clone(),
                day: day(&m.timestamp),
                time: ts(&m.timestamp),
                id: Uuid::new_v4(),
                provider: m.provider.clone(),
                resource_type: m.resource_type.clone(),
                metric_name: m.metric_name.clone(),
                value_num: m.value_num,
                value_str: m.value_str.clone(),
            })
            .collect();
        insert_rows(&session, &stmt, rows).await?;
    }
    Ok(())
}

pub async fn save_logs(config: &SaveConfig, logs: &[LogRecord]) -> Result<()> {
    if logs.is_empty() {
        return Ok(());
    }
    let (session, ks) = connect(config).await?;
    create_table(&session, logs_table(&ks)).await?;
    let stmt = session
        .prepare(format!(
            "INSERT INTO {ks}.logs (target, day, time, id, source, level, message, host, unit, \
             batch_id, tags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?){}",
            ttl_clause(config, "logs")
        ))
        .await
        .context("Failed to prepare logs insert")?;
    let rows: Vec<_> = logs
        .iter()
        .map(|l| LogRow {
            target: l.target.clone(),
            day: day(&l.collected_at),
            time: ts(&l.collected_at),
            id: Uuid::new_v4(),
            source: l.source.clone(),
            level: l.level.clone(),
            message: l.message.clone(),
            host: l.host.clone(),
            unit: l.unit.clone(),
            batch_id: l.batch_id.clone(),
            tags: l.tags.clone(),
        })
        .collect();
    insert_rows(&session, &stmt, rows).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_uri() {
        let ep = parse_uri("cassandra://kxn:p%40ss@db.example:9142/audit").unwrap();
        assert_eq!(
            ep,
            Endpoint {
                node: "db.example:9142".into(),
                user: Some("kxn".into()),
                password: Some("p@ss".into()),
                keyspace: "audit".into(),
            }
        );
    }

    #[test]
    fn defaults_port_and_keyspace() {
        let ep = parse_uri("cassandra://cassandra.kxn.svc").unwrap();
        assert_eq!(ep.node, "cassandra.kxn.svc:9042");
        assert_eq!(ep.keyspace, "kxn");
        assert_eq!(ep.user, None);
        assert_eq!(parse_uri("scylla://h/").unwrap().keyspace, "kxn");
    }

    #[test]
    fn rejects_unsafe_keyspace() {
        assert!(parse_uri("cassandra://h/kxn;DROP").is_err());
        assert!(parse_uri("cassandra:///kxn").is_err());
    }

    #[test]
    fn errors_never_quote_the_password() {
        let msg = format!("{:#}", parse_uri("cassandra://kxn:S3cr3t-pw@/kxn").unwrap_err());
        assert!(!msg.contains("S3cr3t-pw"), "{msg}");
    }

    #[test]
    fn day_is_the_utc_date() {
        use chrono::TimeZone;
        let epoch = chrono::Utc.with_ymd_and_hms(1970, 1, 1, 23, 59, 59).unwrap();
        assert_eq!(day(&epoch).0, 1 << 31);
        let t = chrono::Utc.with_ymd_and_hms(2026, 11, 27, 0, 0, 1).unwrap();
        assert_eq!(day(&t).0 as i64 - (1 << 31), 20_784);
    }

    #[test]
    fn ttl_from_retention() {
        let mut cfg: SaveConfig = toml::from_str("type = \"cassandra\"\nurl = \"cassandra://h\"").unwrap();
        // logs and metrics default to 7 days, scans are kept
        assert_eq!(ttl_clause(&cfg, "logs"), " USING TTL 604800");
        assert_eq!(ttl_clause(&cfg, "scans"), "");
        cfg.retention.logs = Some("2d".into());
        assert_eq!(ttl_clause(&cfg, "logs"), " USING TTL 172800");
        cfg.retention.logs = Some("0".into());
        assert_eq!(ttl_clause(&cfg, "logs"), "");
    }
}
