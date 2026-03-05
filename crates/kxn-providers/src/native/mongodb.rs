use crate::config::require_config;
use crate::error::ProviderError;
use crate::traits::Provider;
use mongodb::bson::{doc, Document};
use mongodb::Client;
use serde_json::{json, Value};

const RESOURCE_TYPES: &[&str] = &["databases", "users", "serverStatus", "currentOp", "db_stats", "logs"];

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
