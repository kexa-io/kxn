use crate::config::require_config;
use crate::error::ProviderError;
use crate::traits::Provider;
use mongodb::bson::{doc, Document};
use mongodb::Client;
use serde_json::{json, Value};

const RESOURCE_TYPES: &[&str] = &["databases", "users", "serverStatus", "currentOp"];

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
