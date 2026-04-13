use crate::config::require_config;
use crate::error::ProviderError;
use crate::traits::Provider;
use mongodb::bson::{doc, Document};
use mongodb::Client;
use serde_json::{json, Value};
use tracing::warn;

const RESOURCE_TYPES: &[&str] = &[
    "databases", "users", "serverStatus", "currentOp", "db_stats", "logs", "cmdLineOpts",
    "replication", "collection_stats", "indexes", "sharding", "profiling",
];

pub struct MongodbProvider {
    uri: String,
}

impl MongodbProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let uri = require_config(&config, "MONGODB_URI", Some("MONGODB"))?;
        Ok(Self { uri })
    }

    async fn client(&self) -> Result<Client, ProviderError> {
        Client::with_uri_str(&self.uri)
            .await
            .map_err(|e| ProviderError::Connection(format!("MongoDB: {}", e)))
    }

    async fn gather_databases(&self, client: &Client) -> Result<Vec<Value>, ProviderError> {
        let db_list = client
            .list_databases()
            .await
            .map_err(|e| ProviderError::Query(format!("listDatabases: {}", e)))?;

        let mut databases = Vec::new();

        for db_spec in &db_list {
            let db_name = &db_spec.name;
            let db = client.database(db_name);
            let mut db_info = json!({
                "name": db_name,
                "sizeOnDisk": db_spec.size_on_disk,
            });

            // Collections
            if let Ok(coll_names) = db.list_collection_names().await {
                let mut collections = Vec::new();
                for coll_name in &coll_names {
                    let mut coll_info = json!({ "name": coll_name });

                    // Indexes
                    let coll = db.collection::<Document>(coll_name);
                    if let Ok(mut cursor) = coll.list_indexes().await {
                        let mut indexes = Vec::new();
                        while cursor.advance().await.unwrap_or(false) {
                            if let Ok(idx) = cursor.deserialize_current() {
                                indexes.push(json!({
                                    "name": idx.options.and_then(|o| o.name),
                                    "keys": format!("{}", idx.keys),
                                }));
                            }
                        }
                        coll_info["indexes"] = json!(indexes);
                    }

                    collections.push(coll_info);
                }
                db_info["collections"] = json!(collections);
            }

            // DB stats
            if let Ok(stats) = db
                .run_command(doc! { "dbStats": 1 })
                .await
            {
                db_info["stats"] = bson_doc_to_json(&stats);
            }

            databases.push(db_info);
        }

        Ok(databases)
    }

    async fn gather_users(&self, client: &Client) -> Result<Vec<Value>, ProviderError> {
        let admin_db = client.database("admin");
        let result = admin_db
            .run_command(doc! { "usersInfo": 1 })
            .await
            .map_err(|e| ProviderError::Query(format!("usersInfo: {}", e)))?;

        let users = result
            .get_array("users")
            .map_err(|e| ProviderError::Query(format!("usersInfo parse: {}", e)))?;

        Ok(users.iter().map(bson_to_json).collect())
    }

    async fn gather_server_status(&self, client: &Client) -> Result<Vec<Value>, ProviderError> {
        let admin_db = client.database("admin");
        let status = admin_db
            .run_command(doc! { "serverStatus": 1 })
            .await
            .map_err(|e| ProviderError::Query(format!("serverStatus: {}", e)))?;

        Ok(vec![bson_doc_to_json(&status)])
    }

    async fn gather_current_op(&self, client: &Client) -> Result<Vec<Value>, ProviderError> {
        let admin_db = client.database("admin");
        let result = admin_db
            .run_command(doc! { "currentOp": 1 })
            .await
            .map_err(|e| ProviderError::Query(format!("currentOp: {}", e)))?;

        let empty = vec![];
        let inprog = result.get_array("inprog").unwrap_or(&empty);

        Ok(inprog.iter().map(bson_to_json).collect())
    }

    async fn gather_db_stats(&self, client: &Client) -> Result<Vec<Value>, ProviderError> {
        let admin_db = client.database("admin");
        let status = admin_db
            .run_command(doc! { "serverStatus": 1 })
            .await
            .map_err(|e| ProviderError::Query(format!("serverStatus: {}", e)))?;

        let mut stats = serde_json::Map::new();

        // Helper to extract nested int/float from BSON
        let get_num = |doc: &Document, key: &str| -> Option<f64> {
            doc.get(key).and_then(|v| match v {
                mongodb::bson::Bson::Int32(n) => Some(*n as f64),
                mongodb::bson::Bson::Int64(n) => Some(*n as f64),
                mongodb::bson::Bson::Double(f) => Some(*f),
                _ => None,
            })
        };

        // Connections
        if let Ok(conn_doc) = status.get_document("connections") {
            if let Some(v) = get_num(conn_doc, "current") {
                stats.insert("connections_current".into(), json!(v));
            }
            if let Some(v) = get_num(conn_doc, "available") {
                stats.insert("connections_available".into(), json!(v));
            }
            if let Some(v) = get_num(conn_doc, "totalCreated") {
                stats.insert("connections_total_created".into(), json!(v));
            }
        }

        // Opcounters
        if let Ok(ops) = status.get_document("opcounters") {
            for key in &["insert", "query", "update", "delete", "getmore", "command"] {
                if let Some(v) = get_num(ops, key) {
                    stats.insert(format!("opcounters_{}", key), json!(v));
                }
            }
        }

        // Memory
        if let Ok(mem) = status.get_document("mem") {
            if let Some(v) = get_num(mem, "resident") {
                stats.insert("memory_resident_mb".into(), json!(v));
            }
            if let Some(v) = get_num(mem, "virtual") {
                stats.insert("memory_virtual_mb".into(), json!(v));
            }
        }

        // Network
        if let Ok(net) = status.get_document("network") {
            if let Some(v) = get_num(net, "bytesIn") {
                stats.insert("network_bytes_in".into(), json!(v));
            }
            if let Some(v) = get_num(net, "bytesOut") {
                stats.insert("network_bytes_out".into(), json!(v));
            }
            if let Some(v) = get_num(net, "numRequests") {
                stats.insert("network_requests".into(), json!(v));
            }
        }

        // WiredTiger cache
        if let Ok(wt) = status.get_document("wiredTiger") {
            if let Ok(cache) = wt.get_document("cache") {
                if let Some(v) = get_num(cache, "bytes currently in the cache") {
                    stats.insert("wt_cache_bytes_current".into(), json!(v));
                }
                if let Some(v) = get_num(cache, "maximum bytes configured") {
                    stats.insert("wt_cache_bytes_max".into(), json!(v));
                }
                if let Some(v) = get_num(cache, "tracked dirty bytes in the cache") {
                    stats.insert("wt_cache_dirty_bytes".into(), json!(v));
                }
                if let Some(v) = get_num(cache, "pages read into cache") {
                    stats.insert("wt_cache_pages_read".into(), json!(v));
                }
                if let Some(v) = get_num(cache, "pages written from cache") {
                    stats.insert("wt_cache_pages_written".into(), json!(v));
                }
            }
        }

        // Global lock
        if let Ok(gl) = status.get_document("globalLock") {
            if let Some(v) = get_num(gl, "activeClients") {
                stats.insert("globallock_active_clients".into(), json!(v));
            } else if let Ok(ac) = gl.get_document("activeClients") {
                if let Some(v) = get_num(ac, "total") {
                    stats.insert("globallock_active_clients".into(), json!(v));
                }
            }
            if let Ok(cq) = gl.get_document("currentQueue") {
                if let Some(v) = get_num(cq, "total") {
                    stats.insert("globallock_queue_total".into(), json!(v));
                }
            }
        }

        // Cursors
        if let Ok(metrics) = status.get_document("metrics") {
            if let Ok(cursor) = metrics.get_document("cursor") {
                if let Ok(open) = cursor.get_document("open") {
                    if let Some(v) = get_num(open, "total") {
                        stats.insert("cursors_open".into(), json!(v));
                    }
                }
                if let Some(v) = get_num(cursor, "timedOut") {
                    stats.insert("cursors_timed_out".into(), json!(v));
                }
            }
        }

        // Uptime
        if let Some(v) = get_num(&status, "uptimeMillis") {
            stats.insert("uptime_seconds".into(), json!(v / 1000.0));
        }

        // Replication (if replica set)
        if let Ok(repl) = status.get_document("repl") {
            let is_primary = repl.get_bool("ismaster").unwrap_or(false)
                || repl.get_bool("isWritablePrimary").unwrap_or(false);
            stats.insert("replication_is_primary".into(), json!(if is_primary { 1 } else { 0 }));
        } else {
            // Standalone — no replication
            stats.insert("replication_is_primary".into(), json!(0));
        }

        // Total data size across all databases
        let db_list = client.list_databases().await.unwrap_or_default();
        let total_size: u64 = db_list.iter().map(|d| d.size_on_disk).sum();
        stats.insert("total_size_bytes".into(), json!(total_size));

        Ok(vec![Value::Object(stats)])
    }

    async fn gather_cmd_line_opts(&self, client: &Client) -> Result<Vec<Value>, ProviderError> {
        let admin_db = client.database("admin");
        let result = admin_db
            .run_command(doc! { "getCmdLineOpts": 1 })
            .await
            .map_err(|e| ProviderError::Query(format!("getCmdLineOpts: {}", e)))?;

        let parsed = bson_doc_to_json(&result);

        // Flatten key security-relevant settings for easy rule evaluation
        let mut flat = serde_json::Map::new();

        // security.authorization
        if let Some(auth) = parsed.pointer("/parsed/security/authorization") {
            flat.insert("security_authorization".into(), auth.clone());
        }
        // security.keyFile
        if let Some(v) = parsed.pointer("/parsed/security/keyFile") {
            flat.insert("security_keyFile".into(), v.clone());
        }
        // net.bindIp
        if let Some(v) = parsed.pointer("/parsed/net/bindIp") {
            flat.insert("net_bindIp".into(), v.clone());
        }
        // net.tls.mode
        if let Some(v) = parsed.pointer("/parsed/net/tls/mode") {
            flat.insert("net_tls_mode".into(), v.clone());
        }
        // net.tls.certificateKeyFile
        if let Some(v) = parsed.pointer("/parsed/net/tls/certificateKeyFile") {
            flat.insert("net_tls_certificateKeyFile".into(), v.clone());
        }
        // net.tls.CAFile
        if let Some(v) = parsed.pointer("/parsed/net/tls/CAFile") {
            flat.insert("net_tls_CAFile".into(), v.clone());
        }
        // auditLog.destination
        if let Some(v) = parsed.pointer("/parsed/auditLog/destination") {
            flat.insert("auditLog_destination".into(), v.clone());
        }
        // auditLog.format
        if let Some(v) = parsed.pointer("/parsed/auditLog/format") {
            flat.insert("auditLog_format".into(), v.clone());
        }
        // net.port
        if let Some(v) = parsed.pointer("/parsed/net/port") {
            flat.insert("net_port".into(), v.clone());
        }
        // setParameter.authenticationMechanisms
        if let Some(v) = parsed.pointer("/parsed/setParameter/authenticationMechanisms") {
            flat.insert("authenticationMechanisms".into(), v.clone());
        }
        // storage.journal.enabled
        if let Some(v) = parsed.pointer("/parsed/storage/journal/enabled") {
            flat.insert("storage_journal_enabled".into(), v.clone());
        }
        // storage.engine
        if let Some(v) = parsed.pointer("/parsed/storage/engine") {
            flat.insert("storage_engine".into(), v.clone());
        }
        // storage.directoryPerDB
        if let Some(v) = parsed.pointer("/parsed/storage/directoryPerDB") {
            flat.insert("storage_directoryPerDB".into(), v.clone());
        }

        // Include raw parsed for advanced rules
        flat.insert("raw".into(), parsed);

        Ok(vec![Value::Object(flat)])
    }

    async fn non_system_dbs(&self, client: &Client) -> Vec<String> {
        let db_list = client.list_databases().await.unwrap_or_default();
        db_list
            .into_iter()
            .map(|d| d.name)
            .filter(|n| n != "admin" && n != "local" && n != "config")
            .collect()
    }

    async fn gather_replication(&self, client: &Client) -> Result<Vec<Value>, ProviderError> {
        let admin_db = client.database("admin");
        let result = match admin_db.run_command(doc! { "replSetGetStatus": 1 }).await {
            Ok(r) => r,
            Err(_) => return Ok(vec![json!({"replication_configured": false})]),
        };
        Ok(vec![parse_repl_status(&result)])
    }

    async fn gather_collection_stats(&self, client: &Client) -> Result<Vec<Value>, ProviderError> {
        let dbs = self.non_system_dbs(client).await;
        let mut all_stats = Vec::new();
        for db_name in &dbs {
            let db = client.database(db_name);
            let colls = match db.list_collection_names().await {
                Ok(c) => c,
                Err(e) => { warn!("list_collection_names({}): {}", db_name, e); continue; }
            };
            for coll_name in &colls {
                if all_stats.len() >= 200 { return Ok(all_stats); }
                if let Ok(stats) = db.run_command(doc! { "collStats": coll_name.as_str() }).await {
                    all_stats.push(extract_coll_stats(db_name, coll_name, &stats));
                }
            }
        }
        Ok(all_stats)
    }

    async fn gather_indexes(&self, client: &Client) -> Result<Vec<Value>, ProviderError> {
        let dbs = self.non_system_dbs(client).await;
        let mut all_indexes = Vec::new();
        for db_name in &dbs {
            let db = client.database(db_name);
            let colls = match db.list_collection_names().await {
                Ok(c) => c,
                Err(e) => { warn!("list_collection_names({}): {}", db_name, e); continue; }
            };
            for coll_name in &colls {
                if all_indexes.len() >= 500 { return Ok(all_indexes); }
                let coll = db.collection::<Document>(coll_name);
                let index_sizes = get_index_sizes(&db, coll_name).await;
                collect_indexes(&coll, db_name, coll_name, &index_sizes, &mut all_indexes).await;
            }
        }
        Ok(all_indexes)
    }

    async fn gather_sharding(&self, client: &Client) -> Result<Vec<Value>, ProviderError> {
        let admin = client.database("admin");
        let shards_result = match admin.run_command(doc! { "listShards": 1 }).await {
            Ok(r) => r,
            Err(_) => return Ok(vec![json!({"sharding_enabled": false})]),
        };
        let config = client.database("config");
        let balancer = config.run_command(doc! { "balancerStatus": 1 }).await.ok();
        Ok(vec![parse_sharding(&shards_result, balancer.as_ref())])
    }

    async fn gather_profiling(&self, client: &Client) -> Result<Vec<Value>, ProviderError> {
        let dbs = self.non_system_dbs(client).await;
        let mut results = Vec::new();
        for db_name in &dbs {
            let db = client.database(db_name);
            if let Ok(r) = db.run_command(doc! { "profile": -1 }).await {
                results.push(parse_profile(db_name, &r));
            }
        }
        Ok(results)
    }

    async fn gather_logs(&self, client: &Client) -> Result<Vec<Value>, ProviderError> {
        let admin_db = client.database("admin");
        let mut entries = Vec::new();

        // getLog global — recent log entries
        for log_type in &["global", "startupWarnings"] {
            let cmd = doc! { "getLog": *log_type };
            if let Ok(result) = admin_db.run_command(cmd).await {
                let empty = vec![];
                let log_lines = result.get_array("log").unwrap_or(&empty);
                for line in log_lines {
                    if let Some(s) = line.as_str() {
                        // MongoDB structured log is JSON
                        if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                            let severity = parsed.get("s").and_then(|v| v.as_str()).unwrap_or("I");
                            let level = match severity {
                                "F" => "fatal",
                                "E" => "error",
                                "W" => "warning",
                                _ => continue, // skip I/D for summary
                            };
                            entries.push(json!({
                                "source": format!("mongo_{}", log_type),
                                "level": level,
                                "timestamp": parsed.get("t").and_then(|t| t.get("$date")),
                                "component": parsed.get("c"),
                                "context": parsed.get("ctx"),
                                "message": parsed.get("msg"),
                                "attributes": parsed.get("attr"),
                            }));
                        } else {
                            // Unstructured log line
                            let level = if s.contains("ERROR") || s.contains(" E ") {
                                "error"
                            } else if s.contains("WARNING") || s.contains(" W ") {
                                "warning"
                            } else {
                                continue;
                            };
                            entries.push(json!({
                                "source": format!("mongo_{}", log_type),
                                "level": level,
                                "message": s,
                            }));
                        }
                    }
                }
            }
        }

        // Current slow operations (> 1s)
        let cmd = doc! { "currentOp": 1, "secs_running": { "$gt": 1 } };
        if let Ok(result) = admin_db.run_command(cmd).await {
            let empty = vec![];
            let ops = result.get_array("inprog").unwrap_or(&empty);
            for op in ops {
                entries.push(json!({
                    "source": "slow_op",
                    "level": "warning",
                    "message": bson_to_json(op),
                }));
            }
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
impl Provider for MongodbProvider {
    fn name(&self) -> &str {
        "mongodb"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        let client = self.client().await?;
        match resource_type {
            "databases" => self.gather_databases(&client).await,
            "users" => self.gather_users(&client).await,
            "serverStatus" => self.gather_server_status(&client).await,
            "currentOp" => self.gather_current_op(&client).await,
            "db_stats" => self.gather_db_stats(&client).await,
            "logs" => self.gather_logs(&client).await,
            "cmdLineOpts" => self.gather_cmd_line_opts(&client).await,
            "replication" => self.gather_replication(&client).await,
            "collection_stats" => self.gather_collection_stats(&client).await,
            "indexes" => self.gather_indexes(&client).await,
            "sharding" => self.gather_sharding(&client).await,
            "profiling" => self.gather_profiling(&client).await,
            _ => Err(ProviderError::UnsupportedResourceType(
                resource_type.to_string(),
            )),
        }
    }
}

fn bson_to_json(bson: &mongodb::bson::Bson) -> Value {
    match bson {
        mongodb::bson::Bson::Document(doc) => bson_doc_to_json(doc),
        mongodb::bson::Bson::Array(arr) => {
            Value::Array(arr.iter().map(bson_to_json).collect())
        }
        mongodb::bson::Bson::String(s) => Value::String(s.clone()),
        mongodb::bson::Bson::Int32(n) => json!(n),
        mongodb::bson::Bson::Int64(n) => json!(n),
        mongodb::bson::Bson::Double(f) => json!(f),
        mongodb::bson::Bson::Boolean(b) => json!(b),
        mongodb::bson::Bson::Null => Value::Null,
        mongodb::bson::Bson::ObjectId(oid) => json!(oid.to_hex()),
        mongodb::bson::Bson::DateTime(dt) => json!(dt.to_string()),
        mongodb::bson::Bson::Timestamp(ts) => json!({ "t": ts.time, "i": ts.increment }),
        other => json!(other.to_string()),
    }
}

fn bson_doc_to_json(doc: &Document) -> Value {
    let mut map = serde_json::Map::new();
    for (k, v) in doc {
        map.insert(k.clone(), bson_to_json(v));
    }
    Value::Object(map)
}

fn bson_get_num(doc: &Document, key: &str) -> Option<f64> {
    doc.get(key).and_then(|v| match v {
        mongodb::bson::Bson::Int32(n) => Some(*n as f64),
        mongodb::bson::Bson::Int64(n) => Some(*n as f64),
        mongodb::bson::Bson::Double(f) => Some(*f),
        _ => None,
    })
}

fn parse_repl_status(result: &Document) -> Value {
    let set_name = result.get_str("set").unwrap_or("");
    let my_state = bson_get_num(result, "myState").unwrap_or(0.0) as i64;
    let term = bson_get_num(result, "term").unwrap_or(0.0) as i64;
    let hb_interval = bson_get_num(result, "heartbeatIntervalMillis").unwrap_or(2000.0) as i64;

    let empty = vec![];
    let members_bson = result.get_array("members").unwrap_or(&empty);
    let mut members = Vec::new();
    let (mut healthy, mut primary, mut secondary) = (0u32, 0u32, 0u32);

    for m in members_bson {
        if let Some(doc) = m.as_document() {
            let state_str = doc.get_str("stateStr").unwrap_or("UNKNOWN");
            let health = bson_get_num(doc, "health").unwrap_or(0.0) as i32;
            if health == 1 { healthy += 1; }
            if state_str == "PRIMARY" { primary += 1; }
            if state_str == "SECONDARY" { secondary += 1; }
            members.push(parse_repl_member(doc, state_str, health));
        }
    }

    let member_count = members.len() as u32;
    json!({
        "replication_configured": true,
        "set_name": set_name,
        "my_state": my_state,
        "term": term,
        "heartbeat_interval_millis": hb_interval,
        "members": members,
        "member_count": member_count,
        "healthy_count": healthy,
        "primary_count": primary,
        "secondary_count": secondary,
    })
}

fn parse_repl_member(doc: &Document, state_str: &str, health: i32) -> Value {
    let name = doc.get_str("name").unwrap_or("");
    let uptime = bson_get_num(doc, "uptime").unwrap_or(0.0) as i64;
    let optime_date = doc
        .get_document("optime")
        .ok()
        .and_then(|o| o.get("ts"))
        .map(bson_to_json)
        .unwrap_or(Value::Null);
    let last_hb = doc
        .get("lastHeartbeat")
        .map(bson_to_json)
        .unwrap_or(Value::Null);

    json!({
        "name": name,
        "state_str": state_str,
        "health": health,
        "uptime": uptime,
        "optime_date": optime_date,
        "last_heartbeat": last_hb,
    })
}

fn extract_coll_stats(db_name: &str, coll_name: &str, stats: &Document) -> Value {
    let ns = format!("{}.{}", db_name, coll_name);
    let count = bson_get_num(stats, "count").unwrap_or(0.0) as i64;
    let size = bson_get_num(stats, "size").unwrap_or(0.0) as i64;
    let avg_obj = bson_get_num(stats, "avgObjSize").unwrap_or(0.0) as i64;
    let storage = bson_get_num(stats, "storageSize").unwrap_or(0.0) as i64;
    let idx_size = bson_get_num(stats, "totalIndexSize").unwrap_or(0.0) as i64;
    let nindexes = bson_get_num(stats, "nindexes").unwrap_or(0.0) as i64;
    let capped = stats.get_bool("capped").unwrap_or(false);

    let frag = stats
        .get_document("wiredTiger")
        .ok()
        .and_then(|wt| wt.get_document("block-manager").ok())
        .and_then(|bm| bson_get_num(bm, "file bytes available for reuse"))
        .unwrap_or(0.0) as i64;

    json!({
        "ns": ns,
        "count": count,
        "size": size,
        "avg_obj_size": avg_obj,
        "storage_size": storage,
        "total_index_size": idx_size,
        "nindexes": nindexes,
        "capped": capped,
        "fragmentation_bytes": frag,
    })
}

async fn get_index_sizes(
    db: &mongodb::Database,
    coll_name: &str,
) -> std::collections::HashMap<String, i64> {
    let mut sizes = std::collections::HashMap::new();
    if let Ok(stats) = db.run_command(doc! { "collStats": coll_name }).await {
        if let Ok(idx_sizes) = stats.get_document("indexSizes") {
            for (k, v) in idx_sizes {
                let val = match v {
                    mongodb::bson::Bson::Int32(n) => *n as i64,
                    mongodb::bson::Bson::Int64(n) => *n,
                    mongodb::bson::Bson::Double(f) => *f as i64,
                    _ => 0,
                };
                sizes.insert(k.clone(), val);
            }
        }
    }
    sizes
}

async fn collect_indexes(
    coll: &mongodb::Collection<Document>,
    db_name: &str,
    coll_name: &str,
    index_sizes: &std::collections::HashMap<String, i64>,
    out: &mut Vec<Value>,
) {
    let mut cursor = match coll.list_indexes().await {
        Ok(c) => c,
        Err(_) => return,
    };
    let ns = format!("{}.{}", db_name, coll_name);
    while cursor.advance().await.unwrap_or(false) {
        if out.len() >= 500 { return; }
        if let Ok(idx) = cursor.deserialize_current() {
            let name = idx.options.as_ref().and_then(|o| o.name.clone()).unwrap_or_default();
            let key_str = format!("{}", idx.keys);
            let unique = idx.options.as_ref().and_then(|o| o.unique).unwrap_or(false);
            let sparse = idx.options.as_ref().and_then(|o| o.sparse).unwrap_or(false);
            let ttl = idx.options.as_ref().and_then(|o| o.expire_after.map(|d| d.as_secs()));
            let size = index_sizes.get(&name).copied().unwrap_or(0);

            out.push(json!({
                "ns": ns,
                "name": name,
                "key": key_str,
                "unique": unique,
                "sparse": sparse,
                "ttl": ttl,
                "size_bytes": size,
            }));
        }
    }
}

fn parse_sharding(shards_result: &Document, balancer: Option<&Document>) -> Value {
    let empty = vec![];
    let shards_arr = shards_result.get_array("shards").unwrap_or(&empty);
    let shard_count = shards_arr.len();
    let shards: Vec<Value> = shards_arr.iter().map(bson_to_json).collect();

    let balancer_running = balancer
        .and_then(|b| b.get_bool("inBalancerRound").ok())
        .unwrap_or(false);
    let chunks_balanced = balancer
        .map(|b| b.get_bool("ok").unwrap_or(false))
        .unwrap_or(false);

    json!({
        "sharding_enabled": shard_count > 0,
        "shard_count": shard_count,
        "shards": shards,
        "balancer_running": balancer_running,
        "chunks_balanced": chunks_balanced,
    })
}

fn parse_profile(db_name: &str, result: &Document) -> Value {
    let level = bson_get_num(result, "was").unwrap_or(0.0) as i32;
    let slowms = bson_get_num(result, "slowms").unwrap_or(100.0) as i64;
    json!({
        "database": db_name,
        "profiling_level": level,
        "slowms": slowms,
    })
}
