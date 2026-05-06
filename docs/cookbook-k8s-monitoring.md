# Cookbook — full Kubernetes monitoring with kxn in 10 minutes

Wire up **continuous compliance scans + centralized pod logs + 19 ready-made Grafana dashboards** on any Kubernetes cluster, using the same setup we run in production.

## What you get

| Layer | Tool | What it does |
|---|---|---|
| **Compliance** | `kxn-monitor` Helm chart | Scans the cluster every 30 s, alerts Discord/Slack on new failures, emits Prometheus metrics. |
| **Logs** | `kxn-logs` Helm chart | Tails error/warn/fatal/panic lines from every pod via the K8s API and pushes them to Loki. **No fluent-bit, no promtail.** |
| **Dashboards** | 19 Grafana dashboards | Cluster overview, compliance, pods, namespaces, postgres, security, CVE, errors, traefik, certs, disks, … |
| **Alerts** | Discord / Slack / Teams webhook | Consolidated, deduplicated, with `<namespace>/<pod>` named in the message. |

## Prerequisites

- A Kubernetes cluster (≥ 1.24).
- `kubectl` and `helm` 3.x.
- A reachable **Loki** endpoint (we'll install one if needed — see below).
- A reachable **Prometheus** + **Grafana** (kube-prometheus-stack works out of the box).
- A **Discord/Slack/Teams** incoming webhook URL.

If you don't already have Prometheus + Grafana + Loki, see [§ "Quick observability stack"](#quick-observability-stack) below.

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

By default this ships an inline starter rule set (`pod-not-failed`, `nodes-not-ready`). To use the full production rule set, copy [`deploy/examples/rules/cluster-health.toml`](../deploy/examples/rules/cluster-health.toml) and pass it via `customRules.files`:

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
#           "k8s #1 PASS | 6/6 passed | 4ms"
```

A failed pod will now hit your Discord with a message like:

```
ERROR pod-not-failed
Pod must not be in Failed state — pod name is included in the alert
`my-app/worker-7c4d8b9f9-xkj2l`
```

## 2 · Install `kxn-logs` (centralized pod logs → Loki)

```bash
helm install kxn-logs ./deploy/helm/kxn-logs \
  --namespace monitoring \
  --set loki.url=loki.monitoring.svc.cluster.local:3100 \
  --set loki.labels.cluster=$(kubectl config current-context)
```

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
logcli query '{job="kxn"} |= "error"' --limit=10
```

## 3 · Import the 19 Grafana dashboards

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

The Grafana sidecar discovers `grafana_dashboard=1` ConfigMaps and loads them within ~30 s. Browse to your Grafana → folder `kxn` → enjoy.

If your Grafana uses **file provisioning** instead, mount the JSONs into `/var/lib/grafana/dashboards/kxn/` and add a provisioning file (see [`deploy/examples/grafana/README.md`](../deploy/examples/grafana/README.md)).

## 4 · End-to-end smoke test

```bash
# 1. Trigger a compliance violation: spawn a pod that fails immediately
kubectl run failpod --image=busybox --restart=Never -- /bin/false

# 2. Watch the alert hit Discord (60 s default dedup, but the *first* alert
#    is immediate)
# 3. Open the Grafana "kxn-cluster" dashboard — pod count panel ticks up
# 4. Open "kxn-errors" — failpod's stderr appears in the Loki stream

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
  --set-file customRules.files."postgres-app-rules\.toml"=deploy/examples/rules/postgres-app-rules.toml
```

The `kxn-postgres` Grafana dashboard will start displaying connection counts, cache hit ratio, slow queries, etc.

## Tuning checklist

- **Alert noise too high?** Bump `webhooks.minLevel` to `2` (drop info+warn) and `webhooks.alertIntervalSeconds` to `3600` (one alert per ongoing incident per hour).
- **Scan too aggressive?** Raise `targets.kubernetes.intervalSeconds` from `30` to `120`.
- **Custom rule with no `name`/`namespace` field?** The alert body falls back to the rule name — to get the offending object identified, ensure the rule's `object` is a per-resource type (e.g. `pods`) rather than `cluster_stats`.
- **Multi-cluster Loki?** Set `loki.labels.cluster=<name>` on each `kxn-logs` install; the Grafana variables will resolve them.

## Quick observability stack

If you don't already run Prometheus + Grafana + Loki, the fastest path:

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

## Related

- [`kxn-monitor` Helm chart](../deploy/helm/kxn-monitor/) — compliance + alerts.
- [`kxn-logs` Helm chart](../deploy/helm/kxn-logs/) — log forwarding.
- [Example rules](../deploy/examples/rules/) — production-ready TOML.
- [Grafana dashboards](../deploy/examples/grafana/) — 19 ready-to-import JSONs.
- [Provider docs](providers.md) — full list of what kxn can scan.
