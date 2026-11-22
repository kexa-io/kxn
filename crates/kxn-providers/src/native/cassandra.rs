//! Apache Cassandra (4.0 and later) through CQL.
//!
//! `cassandra://user:password@host:9042`. Everything is read from system
//! tables, so the account needs no more than SELECT on `system_auth`,
//! `system_schema`, `system` and `system_views` (a superuser has it):
//!
//! - `settings`: the running configuration, from `system_views.settings`
//!   (cassandra.yaml with defaults applied), one flat object. Dotted names
//!   (`client_encryption_options.enabled` on 5.0) are also served with `_`.
//! - `roles`: one per role, from `system_auth.roles` (the password hash is
//!   never read), with its permissions from `system_auth.role_permissions`.
//! - `keyspaces`: replication strategy and factor per keyspace.
//! - `clients`: connected clients and whether they use TLS.
//! - `node`: release, cluster, data center, peers.
//! - `db_stats`: connections and thread-pool backlog, for `kxn top`.

use crate::config::{get_config_or_env, require_config};
use crate::error::ProviderError;
use crate::traits::Provider;
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use scylla::errors::TranslationError;
use scylla::policies::address_translator::{AddressTranslator, UntranslatedPeer};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

pub(crate) const RESOURCE_TYPES: &[&str] = &["settings", "roles", "keyspaces", "clients", "node", "db_stats"];

/// Keyspaces Cassandra creates for itself.
const SYSTEM_KEYSPACES: &[&str] = &[
    "system",
    "system_auth",
    "system_schema",
    "system_distributed",
    "system_traces",
    "system_views",
    "system_virtual_schema",
    "system_cluster_metadata",
];

pub struct CassandraProvider {
    host: String,
    port: u16,
    user: Option<String>,
    password: Option<String>,
}

impl CassandraProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let host = require_config(&config, "CASSANDRA_HOST", Some("CASSANDRA"))?;
        let port = get_config_or_env(&config, "CASSANDRA_PORT", Some("CASSANDRA"))
            .and_then(|p| p.parse().ok())
            .unwrap_or(9042);
        let user = get_config_or_env(&config, "CASSANDRA_USER", Some("CASSANDRA")).filter(|u| !u.is_empty());
        let password = get_config_or_env(&config, "CASSANDRA_PASSWORD", Some("CASSANDRA"));
        Ok(Self { host, port, user, password })
    }

    async fn session(&self) -> Result<Session, ProviderError> {
        let endpoint = format!("{}:{}", self.host, self.port);
        // Audit the node named in the URI, not whichever node the driver
        // would route to: the configuration (system_views.settings) is per
        // node, and the other nodes may not be reachable from here (a
        // port-forward, a network policy).
        let addrs: Vec<SocketAddr> = endpoint
            .to_socket_addrs()
            .map_err(|e| ProviderError::Connection(format!("Cassandra: {endpoint}: {e}")))?
            .collect();
        let target = *addrs
            .first()
            .ok_or_else(|| ProviderError::Connection(format!("Cassandra: {endpoint} resolves to no address")))?;
        let mut builder = SessionBuilder::new()
            .known_node(&endpoint)
            .address_translator(Arc::new(ToNode(target)));
        if let Some(user) = &self.user {
            builder = builder.user(user.clone(), self.password.clone().unwrap_or_default());
        }
        builder
            .build()
            .await
            .map_err(|e| ProviderError::Connection(format!("Cassandra: {e}")))
    }

    /// Run a query whose rows are (text, text) pairs.
    async fn pairs(&self, s: &Session, cql: &str) -> Result<Vec<(String, Option<String>)>, ProviderError> {
        let result = s
            .query_unpaged(cql, &[])
            .await
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?
            .into_rows_result()
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?;
        let rows = result
            .rows::<(String, Option<String>)>()
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?;
        rows.map(|r| r.map_err(|e| ProviderError::Query(format!("{cql}: {e}")))).collect()
    }

    async fn gather_settings(&self, s: &Session) -> Result<Vec<Value>, ProviderError> {
        let pairs = self.pairs(s, "SELECT name, value FROM system_views.settings").await?;
        Ok(vec![Value::Object(settings_map(&pairs))])
    }

    async fn gather_roles(&self, s: &Session) -> Result<Vec<Value>, ProviderError> {
        let cql = "SELECT role, can_login, is_superuser, member_of FROM system_auth.roles";
        let result = s
            .query_unpaged(cql, &[])
            .await
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?
            .into_rows_result()
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?;
        let mut roles = Vec::new();
        for r in result
            .rows::<(String, Option<bool>, Option<bool>, Option<Vec<String>>)>()
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?
        {
            let (role, can_login, is_superuser, member_of) =
                r.map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?;
            roles.push((role, can_login.unwrap_or(false), is_superuser.unwrap_or(false), member_of.unwrap_or_default()));
        }
        let cql = "SELECT role, resource, permissions FROM system_auth.role_permissions";
        let mut perms: Vec<(String, String, Vec<String>)> = Vec::new();
        if let Ok(res) = s.query_unpaged(cql, &[]).await {
            if let Ok(rows) = res.into_rows_result() {
                if let Ok(iter) = rows.rows::<(String, String, Option<Vec<String>>)>() {
                    for (role, resource, p) in iter.flatten() {
                        perms.push((role, resource, p.unwrap_or_default()));
                    }
                }
            }
        }
        Ok(role_rows(&roles, &perms))
    }

    async fn gather_keyspaces(&self, s: &Session) -> Result<Vec<Value>, ProviderError> {
        let cql = "SELECT keyspace_name, durable_writes, replication FROM system_schema.keyspaces";
        let result = s
            .query_unpaged(cql, &[])
            .await
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?
            .into_rows_result()
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?;
        let mut out = Vec::new();
        for r in result
            .rows::<(String, Option<bool>, Option<HashMap<String, String>>)>()
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?
        {
            let (name, durable, replication) = r.map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?;
            out.push(keyspace_row(&name, durable.unwrap_or(true), &replication.unwrap_or_default()));
        }
        Ok(out)
    }

    async fn gather_clients(&self, s: &Session) -> Result<Vec<Value>, ProviderError> {
        let cql = "SELECT address, port, username, ssl_enabled, protocol_version, driver_name FROM system_views.clients";
        let result = s
            .query_unpaged(cql, &[])
            .await
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?
            .into_rows_result()
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?;
        let mut out = Vec::new();
        for r in result
            .rows::<(std::net::IpAddr, i32, Option<String>, Option<bool>, Option<i32>, Option<String>)>()
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?
        {
            let (address, port, username, ssl, proto, driver) =
                r.map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?;
            out.push(json!({
                "address": address.to_string(),
                "port": port,
                "username": username.unwrap_or_default(),
                "ssl_enabled": ssl.unwrap_or(false),
                "protocol_version": proto,
                "driver_name": driver.unwrap_or_default(),
            }));
        }
        Ok(out)
    }

    async fn gather_node(&self, s: &Session) -> Result<Vec<Value>, ProviderError> {
        let cql = "SELECT release_version, cluster_name, data_center, rack FROM system.local";
        let result = s
            .query_unpaged(cql, &[])
            .await
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?
            .into_rows_result()
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?;
        let (release, cluster, dc, rack) = result
            .first_row::<(Option<String>, Option<String>, Option<String>, Option<String>)>()
            .map_err(|e| ProviderError::Query(format!("{cql}: {e}")))?;
        let release = release.unwrap_or_default();
        let major = release.split('.').next().and_then(|m| m.parse::<u64>().ok()).unwrap_or(0);
        let peers = s
            .query_unpaged("SELECT peer FROM system.peers_v2", &[])
            .await
            .ok()
            .and_then(|r| r.into_rows_result().ok())
            .map(|r| r.rows_num())
            .unwrap_or(0);
        // CIS 1.2 and 1.5/3.4: the JVM version and the OS account running it.
        let props: HashMap<String, String> = self
            .pairs(s, "SELECT name, value FROM system_views.system_properties")
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k, v.unwrap_or_default()))
            .collect();
        let java = props.get("java.version").cloned().unwrap_or_default();
        let java_major = java
            .split(['.', '-', '+'])
            .next()
            .and_then(|m| m.parse::<u64>().ok())
            .map(|m| if m == 1 { 8 } else { m })
            .unwrap_or(0);
        Ok(vec![json!({
            "java_version": java,
            "java_major": java_major,
            "process_user": props.get("user.name").cloned().unwrap_or_default(),
            "release_version": release,
            "version_major": major,
            "cluster_name": cluster.unwrap_or_default(),
            "data_center": dc.unwrap_or_default(),
            "rack": rack.unwrap_or_default(),
            "peers": peers,
            "nodes": peers + 1,
        })])
    }

    async fn gather_db_stats(&self, s: &Session) -> Result<Vec<Value>, ProviderError> {
        let mut stats = serde_json::Map::new();
        if let Ok(clients) = self.gather_clients(s).await {
            stats.insert("connections".into(), json!(clients.len()));
            let tls = clients.iter().filter(|c| c["ssl_enabled"] == true).count();
            stats.insert("connections_tls".into(), json!(tls));
            stats.insert("connections_without_tls".into(), json!(clients.len() - tls));
        }
        let cql = "SELECT name, active_tasks, pending_tasks, blocked_tasks, completed_tasks FROM system_views.thread_pools";
        if let Ok(res) = s.query_unpaged(cql, &[]).await {
            if let Ok(rows) = res.into_rows_result() {
                if let Ok(iter) = rows.rows::<(String, Option<i32>, Option<i32>, Option<i64>, Option<i64>)>() {
                    let (mut active, mut pending, mut blocked) = (0i64, 0i64, 0i64);
                    for (name, a, p, b, _) in iter.flatten() {
                        active += a.unwrap_or(0) as i64;
                        pending += p.unwrap_or(0) as i64;
                        blocked += b.unwrap_or(0);
                        if name == "MutationStage" || name == "ReadStage" {
                            stats.insert(format!("{}_pending", name.to_lowercase()), json!(p.unwrap_or(0)));
                        }
                    }
                    stats.insert("thread_pool_active".into(), json!(active));
                    stats.insert("thread_pool_pending".into(), json!(pending));
                    stats.insert("thread_pool_blocked_total".into(), json!(blocked));
                }
            }
        }
        Ok(vec![Value::Object(stats)])
    }
}

#[async_trait::async_trait]
impl Provider for CassandraProvider {
    fn name(&self) -> &str {
        "cassandra"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        let s = self.session().await?;
        match resource_type {
            "settings" => self.gather_settings(&s).await,
            "roles" => self.gather_roles(&s).await,
            "keyspaces" => self.gather_keyspaces(&s).await,
            "clients" => self.gather_clients(&s).await,
            "node" => self.gather_node(&s).await,
            "db_stats" => self.gather_db_stats(&s).await,
            _ => Err(ProviderError::UnsupportedResourceType(resource_type.to_string())),
        }
    }
}

/// Send every connection to the node the URI names, whatever address the
/// cluster advertises for its nodes: kxn audits that node, and the others may
/// not be reachable from here.
struct ToNode(SocketAddr);

#[async_trait::async_trait]
impl AddressTranslator for ToNode {
    async fn translate_address(&self, _peer: &UntranslatedPeer) -> Result<SocketAddr, TranslationError> {
        Ok(self.0)
    }
}

/// `system_views.settings` rows as one object; dotted names also served with `_`.
fn settings_map(pairs: &[(String, Option<String>)]) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    for (name, value) in pairs {
        let v = Value::String(value.clone().unwrap_or_default());
        if name.contains('.') {
            map.insert(name.replace('.', "_"), v.clone());
        }
        map.insert(name.clone(), v);
    }
    map
}

/// One object per role: login/superuser flags, roles it belongs to, and its
/// permissions grouped by resource (`data` is every keyspace).
fn role_rows(
    roles: &[(String, bool, bool, Vec<String>)],
    perms: &[(String, String, Vec<String>)],
) -> Vec<Value> {
    roles
        .iter()
        .map(|(role, can_login, is_superuser, member_of)| {
            let mut by_resource: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (r, resource, p) in perms {
                if r == role {
                    let mut p = p.clone();
                    p.sort();
                    by_resource.insert(resource.clone(), p);
                }
            }
            let all_keyspaces = by_resource.get("data").cloned().unwrap_or_default();
            json!({
                "role": role,
                "can_login": can_login,
                "is_superuser": is_superuser,
                "member_of": member_of,
                "is_default_cassandra": role == "cassandra",
                "permissions": by_resource,
                "all_keyspaces_permissions": all_keyspaces,
                "has_all_keyspaces_access": !all_keyspaces.is_empty(),
            })
        })
        .collect()
}

/// A keyspace with its replication class and factor (the smallest per-DC
/// factor for NetworkTopologyStrategy).
fn keyspace_row(name: &str, durable: bool, replication: &HashMap<String, String>) -> Value {
    let class = replication.get("class").cloned().unwrap_or_default();
    let short = class.rsplit('.').next().unwrap_or("").to_string();
    let factors: Vec<u64> = replication
        .iter()
        .filter(|(k, _)| k.as_str() != "class")
        .filter_map(|(_, v)| v.parse::<u64>().ok())
        .collect();
    json!({
        "keyspace": name,
        "is_system": SYSTEM_KEYSPACES.contains(&name),
        "durable_writes": durable,
        "replication_class": short,
        "replication_factor": factors.iter().min().copied().unwrap_or(0),
        "datacenters": factors.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_get_underscore_aliases() {
        let m = settings_map(&[
            ("client_encryption_options.enabled".into(), Some("false".into())),
            ("authenticator".into(), Some("PasswordAuthenticator".into())),
            ("cdc_raw_directory".into(), None),
        ]);
        assert_eq!(m["client_encryption_options_enabled"], "false");
        assert_eq!(m["client_encryption_options.enabled"], "false");
        assert_eq!(m["authenticator"], "PasswordAuthenticator");
        assert_eq!(m["cdc_raw_directory"], "");
    }

    #[test]
    fn roles_group_permissions() {
        let roles = vec![
            ("cassandra".to_string(), true, true, vec![]),
            ("app".to_string(), true, false, vec!["readers".to_string()]),
        ];
        let perms = vec![
            ("app".to_string(), "data/shop".to_string(), vec!["SELECT".to_string(), "MODIFY".to_string()]),
            ("app".to_string(), "data".to_string(), vec!["SELECT".to_string()]),
        ];
        let rows = role_rows(&roles, &perms);
        assert_eq!(rows[0]["is_default_cassandra"], true);
        assert_eq!(rows[1]["permissions"]["data/shop"], json!(["MODIFY", "SELECT"]));
        assert_eq!(rows[1]["has_all_keyspaces_access"], true);
    }

    #[test]
    fn keyspace_replication() {
        let mut r = HashMap::new();
        r.insert("class".into(), "org.apache.cassandra.locator.NetworkTopologyStrategy".into());
        r.insert("dc1".into(), "3".into());
        r.insert("dc2".into(), "2".into());
        let k = keyspace_row("shop", true, &r);
        assert_eq!(k["replication_class"], "NetworkTopologyStrategy");
        assert_eq!(k["replication_factor"], 2);
        assert_eq!(k["datacenters"], 2);
        assert_eq!(keyspace_row("system_auth", true, &HashMap::new())["is_system"], true);
    }
}
