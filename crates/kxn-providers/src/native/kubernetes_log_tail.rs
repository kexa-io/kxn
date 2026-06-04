//! Real-time Kubernetes pod log streaming.
//!
//! Watches the cluster for pod lifecycle events and maintains a long-lived
//! `/pods/{name}/log?follow=true` connection per container. Each log line
//! is decoded, timestamped, and forwarded to a [`tokio::sync::mpsc::Sender`]
//! for downstream batching and storage.
//!
//! Designed as a drop-in replacement for log shippers (Promtail, Alloy,
//! Fluent Bit) when paired with `kxn logs` save backends (Postgres, Loki,
//! Elasticsearch, etc.).

use crate::error::ProviderError;
use chrono::{DateTime, Utc};
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use tracing::{debug, error, info, warn};

/// Last-emitted timestamp per (pod uid, container name). Used to resume
/// `?follow=true` reconnects with `&sinceTime=...` so the apiserver does
/// not replay log lines we have already forwarded — root cause of the
/// CronJob duplication bug (#125 final fix; the v0.44.0 abort-on-
/// Completed change is the symptomatic band-aid).
///
/// State lives only in memory: if the kxn-logs pod restarts the cursor
/// is lost and one full replay can occur on the next connect — accepted
/// trade-off given the operational rarity vs. the SQLite/PVC complexity.
type LogCursors = Arc<Mutex<HashMap<(String, String), DateTime<Utc>>>>;

/// One log line emitted by a pod container.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub time: DateTime<Utc>,
    pub namespace: String,
    pub pod: String,
    pub container: String,
    pub node: Option<String>,
    pub message: String,
}

/// Tail configuration.
#[derive(Debug, Clone, Default)]
pub struct TailConfig {
    /// Kubernetes API base URL (e.g. `https://kubernetes.default.svc`).
    pub api_url: String,
    /// Bearer token for the Kubernetes API.
    pub token: Option<String>,
    /// PEM-encoded CA bundle (typically the cluster CA at
    /// `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`).
    /// When `None`, TLS verification is skipped.
    pub ca_pem: Option<Vec<u8>>,
    /// Namespace to watch. `None` means all namespaces.
    pub namespace: Option<String>,
    /// Skip TLS verification (overrides `ca_pem`).
    pub insecure: bool,
    /// Namespaces to skip entirely — no follower is spawned and no
    /// log line from a pod in one of these namespaces is forwarded.
    /// Typical use: silence `kube-system` on managed clusters where
    /// CoreDNS / konnectivity-agent dominate the log budget without
    /// providing operator value.
    pub exclude_namespaces: Vec<String>,
    /// Skip pods whose name matches any of these regexes. Applied
    /// after `exclude_namespaces` and in addition to it, so callers
    /// can exclude a single noisy DaemonSet (e.g. `^coredns-`)
    /// without dropping the whole namespace.
    pub exclude_pod_patterns: Vec<Regex>,
}

/// Watch pods in the cluster and stream their logs to `tx`.
///
/// This function returns once the watcher task and all per-pod followers
/// have terminated. Cancel by dropping the receiver — the `tx` send will
/// fail and the inner tasks will exit cleanly.
pub async fn tail_pods(
    config: TailConfig,
    tx: mpsc::Sender<LogLine>,
) -> Result<(), ProviderError> {
    let client = build_client(&config)?;
    let followers: Arc<Mutex<HashMap<String, Vec<JoinHandle<()>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let cursors: LogCursors = Arc::new(Mutex::new(HashMap::new()));

    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);

    loop {
        match watch_loop(&client, &config, &tx, followers.clone(), cursors.clone()).await {
            Ok(()) => {
                // Watch endpoint closed cleanly (e.g. resource version too old);
                // reconnect immediately.
                debug!("pod watch closed, reconnecting");
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                error!(error = %e, "pod watch error, retrying in {:?}", backoff);
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff * 2, max_backoff);
            }
        }
        if tx.is_closed() {
            info!("log receiver dropped, stopping pod watch");
            break;
        }
    }
    Ok(())
}

fn build_client(config: &TailConfig) -> Result<reqwest::Client, ProviderError> {
    // Streaming endpoints (`watch=true`, `follow=true`) hold the connection
    // open indefinitely, so we deliberately do NOT call `.timeout()` here —
    // the default `None` means no overall timeout. Per-read backpressure is
    // handled by the bounded mpsc channel in `tail_pods`.
    let mut builder = reqwest::Client::builder()
        .pool_idle_timeout(None)
        .danger_accept_invalid_certs(config.insecure);

    if !config.insecure {
        if let Some(ca_pem) = &config.ca_pem {
            let cert = reqwest::Certificate::from_pem(ca_pem).map_err(|e| {
                ProviderError::InvalidConfig(format!("invalid CA bundle: {}", e))
            })?;
            builder = builder.add_root_certificate(cert);
        }
    }

    builder
        .build()
        .map_err(|e| ProviderError::Connection(format!("failed to build HTTP client: {}", e)))
}

async fn watch_loop(
    client: &reqwest::Client,
    config: &TailConfig,
    tx: &mpsc::Sender<LogLine>,
    followers: Arc<Mutex<HashMap<String, Vec<JoinHandle<()>>>>>,
    cursors: LogCursors,
) -> Result<(), ProviderError> {
    let path = match &config.namespace {
        Some(ns) => format!("/api/v1/namespaces/{}/pods", ns),
        None => "/api/v1/pods".to_string(),
    };
    // resourceVersion=0 makes the apiserver replay the current state as
    // synthetic ADDED events before continuing to stream live changes —
    // otherwise we would only see events for pods that change after we
    // connect, missing every pod that was already running.
    let url = format!(
        "{}{}?watch=true&resourceVersion=0&allowWatchBookmarks=true",
        config.api_url, path
    );

    let mut req = client.get(&url);
    if let Some(token) = &config.token {
        req = req.bearer_auth(token);
    }

    debug!(url = %url, "opening pod watch");
    let resp = req
        .send()
        .await
        .map_err(|e| ProviderError::Connection(format!("watch request failed: {}", e)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(ProviderError::Connection(format!(
            "watch returned {}: {}",
            status, body
        )));
    }
    info!("pod watch connected, streaming events");

    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::with_capacity(8192);

    while let Some(chunk) = stream.next().await {
        let bytes = chunk
            .map_err(|e| ProviderError::Connection(format!("watch stream error: {}", e)))?;
        buf.extend_from_slice(&bytes);

        // Watch events are newline-delimited JSON.
        while let Some(nl) = buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buf.drain(..=nl).collect();
            let line_str = String::from_utf8_lossy(&line[..line.len().saturating_sub(1)]);
            if line_str.trim().is_empty() {
                continue;
            }
            debug!(bytes = line.len(), "watch event received");
            handle_event(client, config, tx, &line_str, followers.clone(), cursors.clone()).await;
        }
    }
    Ok(())
}

async fn handle_event(
    client: &reqwest::Client,
    config: &TailConfig,
    tx: &mpsc::Sender<LogLine>,
    raw: &str,
    followers: Arc<Mutex<HashMap<String, Vec<JoinHandle<()>>>>>,
    cursors: LogCursors,
) {
    let event: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "ignoring malformed watch event");
            return;
        }
    };

    let event_type = event["type"].as_str().unwrap_or("");
    let object = &event["object"];
    let uid = match object["metadata"]["uid"].as_str() {
        Some(u) => u.to_string(),
        None => return,
    };
    let namespace = object["metadata"]["namespace"].as_str().unwrap_or("default").to_string();
    let pod_name = match object["metadata"]["name"].as_str() {
        Some(n) => n.to_string(),
        None => return,
    };
    let node = object["spec"]["nodeName"].as_str().map(|s| s.to_string());

    // Drop the event entirely if the pod is in an excluded namespace or
    // matches an excluded name regex. Cheaper than starting a follower
    // and then silently dropping its output downstream.
    if config.exclude_namespaces.iter().any(|ns| ns == &namespace) {
        return;
    }
    if config
        .exclude_pod_patterns
        .iter()
        .any(|r| r.is_match(&pod_name))
    {
        return;
    }

    match event_type {
        "ADDED" | "MODIFIED" => {
            // Only follow once per pod uid; follow only when the pod is running.
            let phase = object["status"]["phase"].as_str().unwrap_or("");
            if phase != "Running" {
                // Pod has reached a terminal state (Succeeded/Failed) or has
                // not started yet (Pending). Abort any existing follower so
                // we don't re-stream the pod's complete history every time
                // the `?follow=true` connection retries against a non-Running
                // pod — which is what caused short-lived CronJob pods'
                // ~8-line output to land in the logs table thousands of
                // times per run (kexa-io/kxn#125). Followers are re-spawned
                // if the same uid ever flips back to Running, which happens
                // for paused/resumed StatefulSets but not for terminated
                // Jobs.
                let mut map = followers.lock().await;
                if let Some(handles) = map.remove(&uid) {
                    for h in handles {
                        h.abort();
                    }
                }
                return;
            }
            let mut map = followers.lock().await;
            if map.contains_key(&uid) {
                return;
            }

            let mut handles = Vec::new();
            let containers = object["spec"]["containers"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            for c in containers {
                let container_name = match c["name"].as_str() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let client_clone = client.clone();
                let config_clone = config.clone();
                let tx_clone = tx.clone();
                let ns = namespace.clone();
                let pod = pod_name.clone();
                let node_clone = node.clone();
                let uid_clone = uid.clone();
                let cursors_clone = cursors.clone();
                debug!(
                    namespace = %namespace,
                    pod = %pod_name,
                    container = %container_name,
                    "starting log follower"
                );
                let handle = tokio::spawn(async move {
                    follow_container(
                        client_clone,
                        config_clone,
                        tx_clone,
                        ns,
                        pod,
                        container_name,
                        node_clone,
                        uid_clone,
                        cursors_clone,
                    )
                    .await;
                });
                handles.push(handle);
            }
            map.insert(uid, handles);
        }
        "DELETED" => {
            let mut map = followers.lock().await;
            if let Some(handles) = map.remove(&uid) {
                for h in handles {
                    h.abort();
                }
            }
            // The pod uid will not be re-used by the apiserver, so its
            // cursor entries are dead weight. Drop them so the HashMap
            // does not grow unbounded across the kxn-logs uptime.
            let mut cur = cursors.lock().await;
            cur.retain(|(pod_uid, _), _| pod_uid != &uid);
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn follow_container(
    client: reqwest::Client,
    config: TailConfig,
    tx: mpsc::Sender<LogLine>,
    namespace: String,
    pod: String,
    container: String,
    node: Option<String>,
    pod_uid: String,
    cursors: LogCursors,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);

    loop {
        if tx.is_closed() {
            return;
        }
        match follow_once(
            &client,
            &config,
            &tx,
            &namespace,
            &pod,
            &container,
            node.as_deref(),
            &pod_uid,
            &cursors,
        )
        .await
        {
            Ok(()) => {
                // Connection closed cleanly (pod terminated or rotated logs); retry.
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                debug!(
                    namespace = %namespace,
                    pod = %pod,
                    container = %container,
                    error = %e,
                    "log follow error, retrying in {:?}",
                    backoff
                );
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff * 2, max_backoff);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn follow_once(
    client: &reqwest::Client,
    config: &TailConfig,
    tx: &mpsc::Sender<LogLine>,
    namespace: &str,
    pod: &str,
    container: &str,
    node: Option<&str>,
    pod_uid: &str,
    cursors: &LogCursors,
) -> Result<(), ProviderError> {
    // Resume from the last timestamp we successfully forwarded for
    // this (pod uid, container). The kubelet treats `sinceTime` as
    // inclusive, so we already nudged the cursor by +1ns when we
    // stored it — see the `tx.send` branch below — and the apiserver
    // will skip the line we already shipped.
    let since_time = {
        let cur = cursors.lock().await;
        cur.get(&(pod_uid.to_string(), container.to_string())).copied()
    };
    let since_query = match since_time {
        Some(ts) => format!("&sinceTime={}", urlencode(&ts.to_rfc3339())),
        None => String::new(),
    };
    let url = format!(
        "{}/api/v1/namespaces/{}/pods/{}/log?container={}&follow=true&timestamps=true{}",
        config.api_url, namespace, pod, container, since_query
    );

    let mut req = client.get(&url);
    if let Some(token) = &config.token {
        req = req.bearer_auth(token);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| ProviderError::Connection(format!("log follow request failed: {}", e)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(ProviderError::Connection(format!(
            "log follow returned {} for {}/{}/{}: {}",
            status, namespace, pod, container, body
        )));
    }

    // Convert the bytes stream into an AsyncRead so we can use BufReader.lines().
    let stream = resp.bytes_stream().map(|res| res.map_err(std::io::Error::other));
    let reader = tokio_util::io::StreamReader::new(stream);
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| ProviderError::Connection(format!("log read error: {}", e)))?
    {
        let (ts, msg) = split_timestamp(&line);
        let line_time = ts.unwrap_or_else(Utc::now);
        let line_record = LogLine {
            time: line_time,
            namespace: namespace.to_string(),
            pod: pod.to_string(),
            container: container.to_string(),
            node: node.map(|n| n.to_string()),
            message: msg.to_string(),
        };
        if tx.send(line_record).await.is_err() {
            return Ok(());
        }
        // Bump the cursor by 1ns so the next sinceTime query skips the
        // line we just shipped (the K8s API treats sinceTime as
        // inclusive). One ns is below the kubelet timestamp resolution,
        // so we never accidentally skip a later line.
        if let Some(next) = line_time.checked_add_signed(chrono::Duration::nanoseconds(1)) {
            let mut cur = cursors.lock().await;
            cur.insert((pod_uid.to_string(), container.to_string()), next);
        }
    }
    Ok(())
}

/// Minimal percent-encoder for the few characters that may appear in an
/// RFC 3339 timestamp and confuse the apiserver query parser (`+`, `:`).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(ch),
            other => {
                let mut buf = [0u8; 4];
                for b in other.encode_utf8(&mut buf).as_bytes() {
                    out.push_str(&format!("%{:02X}", b));
                }
            }
        }
    }
    out
}

/// Split a kubelet-formatted log line `"2026-05-04T05:23:39.462010842Z message"`
/// into its RFC3339 timestamp and the remaining message.
fn split_timestamp(line: &str) -> (Option<DateTime<Utc>>, &str) {
    if let Some((ts_str, rest)) = line.split_once(' ') {
        if let Ok(ts) = ts_str.parse::<DateTime<Utc>>() {
            return (Some(ts), rest);
        }
    }
    (None, line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_timestamp_parses_kubelet_format() {
        let (ts, msg) = split_timestamp("2026-05-04T05:23:39.462010842Z hello world");
        assert!(ts.is_some());
        assert_eq!(msg, "hello world");
    }

    #[test]
    fn split_timestamp_handles_missing_prefix() {
        let (ts, msg) = split_timestamp("plain log line");
        assert!(ts.is_none());
        assert_eq!(msg, "plain log line");
    }

    #[test]
    fn urlencode_escapes_rfc3339_colon_and_plus() {
        assert_eq!(
            urlencode("2026-06-04T08:30:00+02:00"),
            "2026-06-04T08%3A30%3A00%2B02%3A00"
        );
    }

    #[test]
    fn urlencode_passes_through_safe_chars() {
        assert_eq!(urlencode("2026-06-04T08-30-00.000Z"), "2026-06-04T08-30-00.000Z");
    }
}
