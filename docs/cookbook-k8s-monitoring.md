# Cookbook — full Kubernetes monitoring with kxn in 10 minutes

Wire up **continuous compliance scans + centralized pod logs + 20 ready-made Grafana dashboards** on any Kubernetes cluster, using the same setup we run in production.

## What you get

| Layer | Tool | What it does |
|---|---|---|
| **Compliance** | `kxn-monitor` Helm chart | Scans the cluster every 30 s, alerts Discord/Slack on new failures, emits Prometheus metrics. |
| **Logs** | `kxn-logs` Helm chart | Polls pod logs via the K8s API, keeps the error lines (configurable) and pushes them to Loki. **No fluent-bit, no promtail.** |
| **Dashboards** | 20 Grafana dashboards (PostgreSQL) | Cluster overview, compliance, pods, namespaces, postgres, security, errors, traefik, … read from the tables kxn saves to PostgreSQL. `kxn-backups`, `kxn-certs`, `kxn-disks`, `kxn-netpolicies` and `kxn-traefik-deep` read tables kxn does not fill and stay empty. |
| **Alerts** | Discord / Slack webhook | One message per violating resource, with `<namespace>/<pod>` named in it; the same violation is not re-sent within `webhooks.alertIntervalSeconds`. Any other URL (Teams included) receives kxn's raw JSON payload; the chart has no value for the `[alerts]` table that formats Teams, PagerDuty and others. |

## Prerequisites

- A Kubernetes cluster (≥ 1.24).
- `kubectl` and `helm` 3.x.
- A reachable **Loki** endpoint for the `kxn-logs` chart (we'll install one if needed — see below).
- A **Grafana** with a **PostgreSQL** datasource (uid `kxn-pg`) on the database kxn saves to — the dashboards are SQL dashboards, not Prometheus/Loki ones. Prometheus is optional (for the `/metrics` endpoints).
- A **Discord or Slack** incoming webhook URL.

If you don't already have Grafana + Loki, see [§ "Quick observability stack"](#quick-observability-stack) below. For an all-in-one install (PostgreSQL + Grafana + dashboards already wired), use the [`kxn-stack` chart](../deploy/helm/kxn-stack/README.md) instead.

## 1 · Install `kxn-monitor` (compliance + alerts)

```bash
git clone https://github.com/kexa-io/kxn
cd kxn

# Webhook secret — pick whatever sink you use
kubectl create namespace monitoring
kubectl -n monitoring create secret generic kxn-webhooks \
  --from-literal=discord='https://discord.com/api/webhooks/...'

helm install kxn-monitor ./deploy/helm/kxn-monitor \
  --namespace monitoring \
  --set webhooks.secretName=kxn-webhooks \
  --set webhooks.secretKey=discord
```

By default this ships an inline starter rule set (`pod-not-failed`, `k8s-nodes-not-ready`). To use the full production rule set, copy [`deploy/examples/rules/cluster-health.toml`](../deploy/examples/rules/cluster-health.toml) and pass it via `customRules.files`:

```bash
helm upgrade --install kxn-monitor ./deploy/helm/kxn-monitor \
  --namespace monitoring \
  --set webhooks.secretName=kxn-webhooks \
  --set webhooks.secretKey=discord \
  --set-file customRules.files."cluster-health\.toml"=deploy/examples/rules/cluster-health.toml
```

**Verify**:

```bash
kubectl -n monitoring logs -l app.kubernetes.io/name=kxn-monitor -f
# Expected: "kxn watch | 1 target(s) | webhooks=1 | save=0"
#           "[<timestamp>] k8s #1 OK | 6/6 passed | 4ms"   (FAIL when a rule fails)
```

A failed pod will now hit your Discord with an embed like:

```
🔴 pod-not-failed
Pod must not be in Failed state
Target: k8s   Object type: pods   Severity: FATAL
Resource: my-app/worker-7c4d8b9f9-xkj2l   Node: <node>
Conditions failed: • phase DIFFERENT Failed but got Failed
```

## 2 · Install `kxn-logs` (centralized pod logs → Loki)

```bash
helm install kxn-logs ./deploy/helm/kxn-logs \
  --namespace monitoring \
  --set loki.url=loki.monitoring.svc.cluster.local:3100 \
  --set loki.origin=my-cluster
```

By default only `error` lines are kept; add warnings with `--set 'collection.levels={error,warning}'`. See the [chart README](../deploy/helm/kxn-logs/README.md) for the other values.

If your Loki has basic auth, create a secret first:

```bash
kubectl -n monitoring create secret generic kxn-loki-auth \
  --from-literal=username=<user> --from-literal=password=<pass>

helm upgrade --install kxn-logs ./deploy/helm/kxn-logs \
  --namespace monitoring \
  --set loki.url=loki.example.com:3100 \
  --set loki.authSecretName=kxn-loki-auth
```

**Verify**:

```bash
# Pod is alive
kubectl -n monitoring logs -l app.kubernetes.io/name=kxn-logs -f
# Logs are flowing
logcli query '{app="kxn", kind="log"}' --limit=10
```

## 3 · Import the 20 Grafana dashboards

The dashboards query PostgreSQL through a datasource with uid **`kxn-pg`**, so they show data only once `kxn-monitor` saves to PostgreSQL — set `save.enabled=true` together with a PostgreSQL target (see [§ 5](#5--optional--also-scan-a-postgresql-backend)) or `save.customUrl`. The log dashboards (`kxn-errors`, `kxn-cloud-logs`, `kxn-pod-logs`, …) read the `logs` table, which `kxn-logs` (Loki only) does not fill; the [`kxn-stack` chart](../deploy/helm/kxn-stack/README.md) streams logs into PostgreSQL. See [`deploy/examples/grafana/README.md`](../deploy/examples/grafana/README.md) for the table each dashboard reads.

If your Grafana runs the standard sidecar (kube-prometheus-stack ships it on by default):

```bash
for f in deploy/examples/grafana/kxn-*.json; do
  name=$(basename "$f" .json)
  kubectl -n monitoring create configmap "$name-dashboard" \
    --from-file="$name.json=$f" \
    --dry-run=client -o yaml \
    | kubectl label --local -f- grafana_dashboard=1 -o yaml \
    | kubectl apply -f -
done
```

The Grafana sidecar discovers `grafana_dashboard=1` ConfigMaps and loads them within ~30 s, into the sidecar's default folder. To get a `kxn` folder, add a folder annotation to the ConfigMaps (e.g. `grafana_folder=kxn`, with the sidecar's `folderAnnotation` set to that key).

If your Grafana uses **file provisioning** instead, mount the JSONs into `/var/lib/grafana/dashboards/kxn/` and add a provisioning file (see [`deploy/examples/grafana/README.md`](../deploy/examples/grafana/README.md)).

## 4 · End-to-end smoke test

```bash
# 1. Trigger a compliance violation: spawn a pod that fails immediately
kubectl run failpod --image=busybox --restart=Never -- /bin/false

# 2. Watch the alert hit Discord (the *first* alert is immediate; repeats of
#    the same violation are deduplicated for 3600 s by default)
# 3. With save enabled, the "Pods failed" counter of the "kxn-cluster" dashboard
#    goes up, and the pod is listed in "kxn-compliance" under pod-not-failed

# Cleanup
kubectl delete pod failpod
```

## 5 · Optional — also scan a PostgreSQL backend

If you run a Postgres app (or use kxn's own save backend), add it as a second target without redeploying anything:

```bash
kubectl -n monitoring create secret generic kxn-pg-creds \
  --from-literal=password='<pg-password>'

helm upgrade --install kxn-monitor ./deploy/helm/kxn-monitor \
  --namespace monitoring \
  --reuse-values \
  --set targets.postgresql.enabled=true \
  --set targets.postgresql.host=db.app.svc.cluster.local \
  --set targets.postgresql.user=app \
  --set targets.postgresql.database=app \
  --set targets.postgresql.passwordSecret.name=kxn-pg-creds \
  --set save.enabled=true \
  --set-file customRules.files."postgres-app-rules\.toml"=deploy/examples/rules/postgres-app-rules.toml
```

With `save.enabled=true`, results are saved to that same database (the URL is built from the target), and the `kxn-postgres` Grafana dashboard will start displaying connection counts, cache hit ratio, slow queries, etc. Point `save.customUrl` elsewhere to keep kxn's tables out of the application database.

## Optional — CPU/RAM every 10 s (or 5 s, 1 s)

`targets.kubernetes.usageIntervalSeconds` (default `10`) runs a dedicated sampler next to the 30 s compliance scan: kubelet stats every 10 s, CPU/RAM rules evaluated on each sample, rollups (avg + max per container and node) flushed to Postgres every `usageFlushSeconds` into `pod_resource` / `node_resource` and their 5-minute / 1-hour tiers. The `kxn-top-consumers` and `kxn-tenants` dashboards read `pod_resource`, and `kxn recommend` reads all of them, so no external collector is needed. Set it to `5` or `1` only if your kubelets run with a lower `--housekeeping-interval`; otherwise consecutive samples are identical.

## Optional — CPU/RAM gauges in Prometheus

`kxn-monitor` exposes scan metrics on `:9090/metrics`. Set `metrics.resourceMetrics=true` to also publish per-container and per-node gauges straight from the probes (`kxn_pod_cpu_millicores`, `kxn_pod_memory_mib`, `kxn_pod_cpu_request_millicores`, `kxn_pod_memory_limit_mib`, `kxn_node_cpu_millicores`, `kxn_node_memory_allocatable_mib`, …), labelled by `namespace`, `pod`, `container`, `node`, `workload_kind`, `workload`. Useful when you already run Prometheus/Alertmanager and want PromQL on the same numbers kxn alerts on, e.g.:

```promql
# containers above 90 % of their memory limit
kxn_pod_memory_mib / kxn_pod_memory_limit_mib > 0.9
# idle CPU requests (request ≥ 250m, usage < 10 %)
kxn_pod_cpu_request_millicores >= 250 and kxn_pod_cpu_millicores / kxn_pod_cpu_request_millicores < 0.1
```

Budget 2–6 series per container; keep it off on very large clusters or scope the target with `K8S_NAMESPACE`.

## Optional — right-sizing report

Once `kxn-monitor` saves to Postgres (the usage sampler fills `pod_resource`), `kxn recommend` turns that history into per-workload request recommendations without any dashboard: see [kubernetes-right-sizing.md](kubernetes-right-sizing.md).

## Tuning checklist

- **Alert noise too high?** Set `builtInRules.minLevel` to `2` (info and warning rules are no longer evaluated, so they never alert) and keep `webhooks.alertIntervalSeconds` at `3600` (the default: one alert per ongoing incident per hour).
- **Scan too aggressive?** Raise `targets.kubernetes.intervalSeconds` from `30` to `120`.
- **Custom rule with no `name`/`namespace` field?** The alert body falls back to the rule name — to get the offending object identified, ensure the rule's `object` is a per-resource type (e.g. `pods`) rather than `cluster_stats`.
- **Multi-cluster Loki?** Set `loki.origin=<name>` on each `kxn-logs` install and filter with `{app="kxn", kind="log", origin="<name>"}`.

## Quick observability stack

If you don't already run Grafana + Loki, the fastest path (you still need a PostgreSQL for the dashboards — or use the `kxn-stack` chart, which bundles one):

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

# Prometheus + Grafana
helm install kube-prom-stack prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace

# Loki (single-binary, fine for getting started)
helm install loki grafana/loki \
  --namespace monitoring \
  --set loki.auth_enabled=false \
  --set deploymentMode=SingleBinary \
  --set 'loki.commonConfig.replication_factor=1' \
  --set 'loki.storage.type=filesystem' \
  --set singleBinary.replicas=1
```

Then back to step 1.

## Read-only watch with Prometheus metrics

For an audit-only install (no writes to the cluster), use `deploy/kubernetes/kxn-watch-readonly.yaml`. It creates a ServiceAccount bound to the built-in `view` ClusterRole, pulls the rules with an initContainer, runs `kxn watch -R` with metrics on port 9090, and pins the image tag. The metric names are listed in [metrics.md](metrics.md).

## Related

- [`kxn-monitor` Helm chart](../deploy/helm/kxn-monitor/) — compliance + alerts.
- [`kxn-logs` Helm chart](../deploy/helm/kxn-logs/) — log forwarding.
- [Example rules](../deploy/examples/rules/) — production-ready TOML.
- [Grafana dashboards](../deploy/examples/grafana/) — 20 ready-to-import JSONs (PostgreSQL datasource `kxn-pg`).
- [Provider docs](providers.md) — full list of what kxn can scan.
