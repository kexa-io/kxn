# kxn-monitor

Continuous Kubernetes compliance monitoring with [kxn](https://github.com/kexa-io/kxn) — runs `kxn watch` against your in-cluster ServiceAccount, evaluates TOML rules every N seconds, exposes Prometheus metrics, and pushes consolidated alerts to **Discord / Slack / Teams / generic webhook** on new failures.

## TL;DR

```bash
# 1. Namespace + webhook secret (Discord / Slack / Teams / generic — pick what you use)
kubectl create namespace monitoring
kubectl -n monitoring create secret generic kxn-webhooks \
  --from-literal=discord='https://discord.com/api/webhooks/...'

# 2. Install
helm install kxn-monitor oci://registry-1.docker.io/kexa/kxn-monitor \
  --namespace monitoring \
  --set webhooks.secretName=kxn-webhooks \
  --set webhooks.secretKey=discord
```

## What it does

- Runs **one pod** with a read-only `ServiceAccount`.
- Calls `kxn watch` against the in-cluster Kubernetes API on a 30 s loop (configurable).
- Evaluates the TOML rules you ship in `customRules.files` (the `kexa/kxn` image does not bundle rule packs).
- Pushes a **consolidated alert** to the webhook URL on every new failure (with a configurable dedup window — default 1 h).
- Exposes a Prometheus `/metrics` endpoint with `kxn_rules_total`, `kxn_rules_passed/failed`, `kxn_scan_duration_ms`, `kxn_violations_by_level`.
- Optionally adds a `ServiceMonitor` for Prometheus Operator (kube-prometheus-stack).

## Common settings

| Key | Default | Description |
|---|---|---|
| `webhooks.secretName` | `kxn-webhooks` | Pre-existing secret with the webhook URL. |
| `webhooks.secretKey` | `discord` | Key inside the secret holding the URL. |
| `webhooks.alertIntervalSeconds` | `3600` | Dedup window — alerts more frequent than this for the same violation are suppressed. |
| `builtInRules.minLevel` | `0` | Global severity floor written to `[rules] min_level` (`0=info`, `1=warn`, `2=error`, `3=fatal`). Rules below it are not evaluated, so they never alert. |
| `builtInRules.include` | `[]` | Rule-name globs written to `[rules] include` (e.g. `["k8s-*"]`). Only matching rules are kept. |
| `builtInRules.exclude` | `[]` | Rule-name globs written to `[rules] exclude` (e.g. `["k8s-pod-no-limits"]`). |
| `targets.kubernetes.intervalSeconds` | `30` | How often to scan the cluster. |
| `targets.postgresql.enabled` | `false` | Set to `true` to also scan a PostgreSQL DB (e.g. your kxn save backend). |
| `customRules.files` | (sample inline) | Replace with your own TOML rule files. Examples in [`deploy/examples/rules/`](../../examples/rules/). |
| `metrics.enabled` | `true` | Expose Prometheus `/metrics`. |
| `metrics.resourceMetrics` | `false` | Also publish per-container / per-node CPU & RAM gauges (`--metrics-resources`). |
| `metrics.serviceMonitor.enabled` | `false` | Create a ServiceMonitor (requires Prometheus Operator). |
| `save.enabled` | `false` | Write a `[[save]]` block (needed by the PostgreSQL-backed Grafana dashboards). |

See [`values.yaml`](values.yaml) for the full list.

## Multiple webhooks

`kxn watch` accepts repeated `--webhook` flags, so you can add destinations via `extraArgs`:

```yaml
webhooks:
  secretName: kxn-webhooks
  secretKey: discord
extraArgs:
  - "--webhook"
  - "$(SLACK_URL)"
extraEnv:
  - name: SLACK_URL
    valueFrom:
      secretKeyRef:
        name: kxn-webhooks
        key: slack
```

## Adding a PostgreSQL target

If you also use a Postgres for your application, add it as a second target so the same scan loop checks DB compliance and pushes alerts to the same webhook:

```bash
kubectl -n monitoring create secret generic kxn-postgres-creds --from-literal=password='<pg-pass>'

helm upgrade --install kxn-monitor oci://registry-1.docker.io/kexa/kxn-monitor \
  --namespace monitoring \
  --set targets.postgresql.enabled=true \
  --set targets.postgresql.host=db.app.svc.cluster.local \
  --set targets.postgresql.user=kxn \
  --set targets.postgresql.database=kxn \
  --set targets.postgresql.passwordSecret.name=kxn-postgres-creds
```

## Verifying it works

```bash
# pod is running
kubectl -n monitoring logs -l app.kubernetes.io/name=kxn-monitor -f

# metrics scraped
kubectl -n monitoring port-forward svc/kxn-monitor-metrics 9090:9090
curl http://localhost:9090/metrics | head -20

# trigger an alert: create a pod that fails, watch your Discord
kubectl run failpod --image=busybox --restart=Never -- /bin/false
```

## Uninstall

```bash
helm uninstall kxn-monitor -n monitoring
```

## Related

- [`kxn-logs`](../kxn-logs/) — sister chart for log forwarding to Loki.
- [`examples/rules/`](../../examples/rules/) — production-ready TOML rules.
- [`examples/grafana/`](../../examples/grafana/) — 20 Grafana dashboards, reading the PostgreSQL tables this chart writes when `save.enabled=true` (and Loki for the log dashboards).
