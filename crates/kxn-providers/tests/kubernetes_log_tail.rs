//! End-to-end integration tests for the kxn-logs pod-log streamer.
//!
//! Each test spins up a tiny mock kube apiserver on an ephemeral port,
//! runs [`tail_pods`] against it, drives a pod lifecycle through the
//! mock, and asserts the line stream the watcher emits matches what a
//! correct collector would forward.
//!
//! The harness exists primarily to lock in the dedup contract:
//! `?follow=true` reconnects honour `sinceTime` so a flaky network or
//! a phase transition does not double-ship lines (kexa-io/kxn#125).

use axum::extract::{Path, Query};
use axum::routing::get;
use axum::Router;
use kxn_providers::native::kubernetes_log_tail::{tail_pods, LogLine, TailConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// Spawn a localhost server that serves only the two endpoints the
/// log tail watcher hits — the pod watch stream and the per-container
/// log stream. Returns the base URL (`http://127.0.0.1:PORT`).
async fn spawn_mock_apiserver(state: Arc<MockState>) -> String {
    let app = Router::new()
        .route("/api/v1/pods", get(watch_pods))
        .route(
            "/api/v1/namespaces/{namespace}/pods/{pod}/log",
            get(read_log),
        )
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{}", addr)
}

#[derive(Default)]
struct MockState {
    /// How many times the apiserver has handed back a Running pod in
    /// the watch stream — bumped on every connection so reconnects
    /// rebuild the same view. We exit the connection after one ADDED
    /// event so the watcher's reconnect logic exercises naturally.
    watch_connects: AtomicUsize,
    /// How many times the `/log` endpoint has been hit. Read by the
    /// test to drive a reconnect.
    log_connects: AtomicUsize,
}

#[derive(serde::Deserialize)]
struct LogQuery {
    container: Option<String>,
    #[serde(rename = "sinceTime")]
    since_time: Option<String>,
    #[serde(rename = "follow")]
    _follow: Option<String>,
    #[serde(rename = "timestamps")]
    _timestamps: Option<String>,
}

async fn watch_pods(
    axum::extract::State(state): axum::extract::State<Arc<MockState>>,
) -> axum::response::Response {
    state.watch_connects.fetch_add(1, Ordering::SeqCst);
    // Single ADDED event with one running pod; then keep the connection
    // open for a short while so the watcher believes the stream is live.
    let event = serde_json::json!({
        "type": "ADDED",
        "object": {
            "metadata": {
                "uid": "pod-uid-1",
                "namespace": "default",
                "name": "my-pod"
            },
            "spec": {
                "nodeName": "node-1",
                "containers": [{"name": "app"}]
            },
            "status": {"phase": "Running"}
        }
    });
    // Just emit the synthetic ADDED event and close. The watcher will
    // reconnect, but the dedup invariant `if map.contains_key(&uid)`
    // ensures the same pod follower is not spawned twice — exactly
    // what we want, since the test only cares about the follower's
    // own log-stream reconnect behaviour.
    let body = format!("{}\n", event);
    axum::response::Response::builder()
        .status(200)
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn read_log(
    Path(params): Path<HashMap<String, String>>,
    Query(q): Query<LogQuery>,
    axum::extract::State(state): axum::extract::State<Arc<MockState>>,
) -> axum::response::Response {
    let _ = params;
    let _ = q.container;
    let connect_idx = state.log_connects.fetch_add(1, Ordering::SeqCst);

    // Five fixed lines spanning one second each so the watcher's
    // sinceTime nudge has a kubelet-resolution timestamp to land on.
    let all = vec![
        "2026-06-04T08:00:00.000000000Z line A",
        "2026-06-04T08:00:01.000000000Z line B",
        "2026-06-04T08:00:02.000000000Z line C",
        "2026-06-04T08:00:03.000000000Z line D",
        "2026-06-04T08:00:04.000000000Z line E",
    ];

    // If `sinceTime` was sent, only return lines strictly later than
    // it. The kxn-logs watcher bumps the cursor by 1 ns past the last
    // forwarded line so the apiserver should return ZERO replay lines
    // when called back-to-back after a clean drain.
    let since: Option<chrono::DateTime<chrono::Utc>> = q
        .since_time
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&chrono::Utc)));

    let filtered: Vec<&str> = all
        .into_iter()
        .filter(|line| match since {
            None => true,
            Some(t) => {
                let stamp = line.split_once(' ').and_then(|(ts, _)| {
                    chrono::DateTime::parse_from_rfc3339(ts).ok().map(|d| d.with_timezone(&chrono::Utc))
                });
                stamp.map(|s| s >= t).unwrap_or(true)
            }
        })
        .collect();

    let _ = connect_idx;
    let body = if filtered.is_empty() {
        String::new()
    } else {
        format!("{}\n", filtered.join("\n"))
    };
    axum::response::Response::builder()
        .status(200)
        .body(axum::body::Body::from(body))
        .unwrap()
}

/// The dedup contract: when the watcher reconnects, it should send
/// `sinceTime` so the apiserver does not replay lines we already
/// shipped. With five lines on the first connect and a reconnect
/// triggered before any new lines exist, the second connect must
/// yield zero additional forwarded lines.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn log_tail_does_not_duplicate_across_reconnect() {
    let state = Arc::new(MockState::default());
    let base = spawn_mock_apiserver(state.clone()).await;

    let tail_cfg = TailConfig {
        api_url: base,
        token: None,
        ca_pem: None,
        namespace: None,
        insecure: true,
        exclude_namespaces: vec![],
        exclude_pod_patterns: vec![],
    };
    let (tx, mut rx) = mpsc::channel::<LogLine>(64);

    let handle = tokio::spawn(async move {
        tail_pods(tail_cfg, tx).await.ok();
    });

    // Drain the first batch of five lines.
    let mut lines: Vec<LogLine> = Vec::new();
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while lines.len() < 5 {
        let now = tokio::time::Instant::now();
        if now >= drain_deadline {
            break;
        }
        let remaining = drain_deadline - now;
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(line)) => lines.push(line),
            _ => break,
        }
    }
    assert_eq!(lines.len(), 5, "first connect should yield 5 lines");

    // The follow_container retry loop will reconnect on its own once
    // the first response body completes. Give it a beat and assert
    // nothing else lands — the apiserver replied with zero lines
    // because sinceTime filtered them all out.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let extra = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
    assert!(extra.is_err(), "reconnect should not duplicate lines");

    // At least two log-endpoint hits prove the reconnect actually
    // happened, otherwise the dedup assertion would be vacuous.
    let connects = state.log_connects.load(Ordering::SeqCst);
    assert!(
        connects >= 2,
        "expected the watcher to reconnect at least once, got {} connects",
        connects
    );

    handle.abort();
}
