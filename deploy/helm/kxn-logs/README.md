# kxn-logs

Centralized **Kubernetes pod log collection** with [kxn](https://github.com/kexa-io/kxn) — polls pod logs through the Kubernetes API, keeps the error/warning lines and forwards them to Loki. **No fluent-bit, no promtail, no DaemonSet.**

## TL;DR

```bash
helm install kxn-logs ./deploy/helm/kxn-logs \
  --namespace observability --create-namespace \
  --set loki.url=loki.monitoring.svc.cluster.local:3100 \
  --set loki.origin=prod-eu-west
```

## What it does

- Runs a single pod with `kxn logs kubernetes://in-cluster --config-file /etc/kxn/kxn.toml --interval <collection.intervalSeconds>` (1 replica is enough).
- Every interval, reads the last 100 lines of each `Running` / `Failed` pod (first 50 pods) through `/api/v1/namespaces/<ns>/pods/<pod>/log`, and keeps the lines containing `error`, `warn`, `fatal`, `panic` or `exception` (up to 20 per pod).
- Classifies each kept line as `error` (`error`/`fatal`/`panic`/`exception`) or `warning` (`warn`); its source is `<namespace>/<pod>`.
- Filters by level (`collection.levels`, exact match, default `[error]`), source (`collection.sources`) and regex (`collection.pattern`).
- Pushes the kept lines to Loki through a `[[save]] type = "loki"` block, as a stream labelled `{app="kxn", kind="log", origin="<loki.origin>"}`. The line is JSON with `target`, `source`, `level`, `message`, `host`, `unit`, `batch_id`, `origin`.
- Exposes `/metrics` (`kxn_logs_total{target,level}`, `kxn_logs_by_source{target,source}`, `kxn_logs_collection_duration_ms`), with an optional `ServiceMonitor`.

## Prerequisites

- Kubernetes 1.24+
- A Loki endpoint reachable from the cluster.
- RBAC: cluster-wide `get/list/watch` on `pods`, `pods/log`, `namespaces` (created by default — set `rbac.create=false` if you bring your own ServiceAccount).

## Values

| Key | Default | Description |
|---|---|---|
| `image.repository` | `kexa/kxn` | Container image. |
| `image.tag` | `""` (Chart appVersion, `v0.57.1`) | Image tag. |
| `loki.enabled` | `true` | Write the `[[save]] type = "loki"` block. |
| `loki.url` | `loki.monitoring.svc.cluster.local:3100` | Loki endpoint: `host:port` (plain HTTP), `loki://host:port`, `loki+https://host`, or `http(s)://host`. |
| `loki.authSecretName` | `""` | Pre-existing Secret with basic-auth credentials (exposed as `LOKI_USER` / `LOKI_PASSWORD`). Empty = no auth. |
| `loki.authUsernameKey` | `username` | Key of the username in that Secret. |
| `loki.authPasswordKey` | `password` | Key of the password in that Secret. |
| `loki.origin` | `kxn-logs` | Value of the `origin` stream label — set one per cluster when several clusters push to the same Loki. |
| `collection.intervalSeconds` | `60` | Collection interval (`--interval`). |
| `collection.levels` | `[error]` | Levels kept (`--level`, exact match, not a minimum): `error`, `warning`, `info`. Empty list = all. |
| `collection.sources` | `[]` | Sources kept (`--source`, exact `<namespace>/<pod>`). Empty = all. |
| `collection.pattern` | `""` | Regex the message must match (`--pattern`, e.g. `Failed password`). |
| `metrics.enabled` | `true` | Expose Prometheus `/metrics` (`--metrics-port`) and a `<fullname>-metrics` Service. |
| `metrics.port` | `9090` | Metrics port. |
| `metrics.serviceMonitor.enabled` | `false` | Create a ServiceMonitor (requires Prometheus Operator). |
| `k8sInsecureTls` | `false` | Skip Kubernetes API CA verification (`K8S_INSECURE=true`, not recommended). |
| `extraArgs` | `[]` | Extra flags appended to `kxn logs`. |
| `extraEnv` | `[]` | Extra environment variables. |
| `resources` | requests `50m` / `64Mi`, limits `200m` / `256Mi` | Container resources. |

See [`values.yaml`](values.yaml) for the full list (security contexts, ServiceAccount, scheduling).

To keep warnings as well as errors:

```bash
helm upgrade --install kxn-logs ./deploy/helm/kxn-logs \
  --namespace observability \
  --set 'collection.levels={error,warning}'
```

## Loki with basic-auth

Create a Secret first, then point the chart at it:

```bash
kubectl -n observability create secret generic kxn-loki-auth \
  --from-literal=username=<user> --from-literal=password=<pass>

helm install kxn-logs ./deploy/helm/kxn-logs \
  --namespace observability \
  --set loki.url=loki+https://loki.example.com \
  --set loki.authSecretName=kxn-loki-auth
```

The chart exposes the two keys to the container as `LOKI_USER` / `LOKI_PASSWORD`, which the kxn Loki backend sends as HTTP Basic auth. For a Bearer token (Grafana Cloud) or a tenant header, pass `LOKI_TOKEN` or `LOKI_TENANT` through `extraEnv`.

## Verifying it works

```bash
# Watch the pod
kubectl -n observability logs -l app.kubernetes.io/name=kxn-logs -f

# Scrape metrics
kubectl -n observability port-forward svc/kxn-logs-metrics 9090:9090
curl http://localhost:9090/metrics

# Query Loki for kxn-pushed log lines
logcli query '{app="kxn", kind="log", origin="kxn-logs"}' --limit=20
```

## Uninstall

```bash
helm uninstall kxn-logs -n observability
```

## Related

- [`kxn` CLI](https://github.com/kexa-io/kxn) — the underlying Rust binary.
- [`kxn-monitor`](../kxn-monitor/) — continuous compliance scans and alerts.
- [`kxn-pod-monitor.yaml`](../../kubernetes/kxn-pod-monitor.yaml) — raw manifest variant (Discord alerts on pod state).
