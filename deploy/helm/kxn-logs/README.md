# kxn-logs

Centralized **Kubernetes pod log collection** with [kxn](https://github.com/kexa-io/kxn) — tails error/warn/fatal/panic/exception lines from every pod via the Kubernetes API and forwards them to a Loki sink (or any other kxn save backend). **No fluent-bit, no promtail, no DaemonSet.**

## TL;DR

```bash
helm install kxn-logs ./deploy/helm/kxn-logs \
  --namespace observability --create-namespace \
  --set loki.url=loki.monitoring.svc.cluster.local:3100 \
  --set loki.labels.cluster=prod-eu-west
```

## What it does

- Runs a single `kxn monitor kubernetes://in-cluster` pod (1 replica is enough).
- Polls every pod's `/api/v1/.../log` endpoint via the Kubernetes API.
- Filters lines by level (`error` by default), source, regex pattern.
- Pushes filtered lines to Loki using the `loki://` save backend bundled in the kxn binary.
- Exposes a `/metrics` endpoint with `kxn_rules_total`, `kxn_rules_passed/failed`, `kxn_scan_duration_ms`, `kxn_violations_by_level`.
- Optional `ServiceMonitor` for Prometheus Operator scraping.

## Prerequisites

- Kubernetes 1.24+
- A reachable Loki endpoint inside the cluster (or accessible from it).
- RBAC: cluster-wide `get/list/watch` on `pods`, `pods/log`, `namespaces`, `nodes`, `events` (created by default — disable with `rbac.create=false` if you bring your own).

## Common settings

| Key | Default | Description |
|---|---|---|
| `image.repository` | `kexa/kxn` | Container image. |
| `image.tag` | `""` (Chart appVersion) | Image tag. |
| `loki.url` | `loki.monitoring.svc.cluster.local:3100` | Target Loki endpoint. |
| `loki.authSecretName` | `""` | Pre-existing secret with `username` / `password` keys (basic-auth). |
| `loki.labels.cluster` | `""` | Static label — set this for multi-cluster Loki setups. |
| `collection.intervalSeconds` | `60` | How often kxn polls each pod. |
| `collection.level` | `error` | Minimum level kept. |
| `collection.pattern` | `""` | Optional regex pattern (e.g. `Failed password`). |
| `metrics.enabled` | `true` | Expose Prometheus `/metrics`. |
| `metrics.serviceMonitor.enabled` | `false` | Create a ServiceMonitor (requires Prometheus Operator). |
| `k8sInsecureTls` | `false` | Skip API CA verification (not recommended). |
| `resources.requests.cpu` | `50m` | |
| `resources.requests.memory` | `64Mi` | |

See [`values.yaml`](values.yaml) for the full list.

## Loki with basic-auth

Create a secret first, then point the chart at it:

```bash
kubectl -n observability create secret generic kxn-loki-auth \
  --from-literal=username=<user> --from-literal=password=<pass>

helm install kxn-logs ./deploy/helm/kxn-logs \
  --namespace observability \
  --set loki.url=loki.example.com:3100 \
  --set loki.authSecretName=kxn-loki-auth
```

The chart wires `LOKI_USERNAME` / `LOKI_PASSWORD` env vars into the container and injects them into the `loki://` URL.

## Verifying it works

```bash
# Watch the pod
kubectl -n observability logs -l app.kubernetes.io/name=kxn-logs -f

# Scrape metrics
kubectl -n observability port-forward svc/kxn-logs-metrics 9090:9090
curl http://localhost:9090/metrics

# Query Loki for kxn-pushed streams
logcli query '{job="kxn"}' --limit=20
```

## Uninstall

```bash
helm uninstall kxn-logs -n observability
```

## Related

- [`kxn` CLI](https://github.com/kexa-io/kxn) — the underlying Rust binary.
- [`kxn watch`](https://github.com/kexa-io/kxn/tree/main/docs) — continuous compliance scans.
- [`kxn-pod-monitor.yaml`](../../kubernetes/kxn-pod-monitor.yaml) — raw manifest variant (Discord alerts on pod state).
