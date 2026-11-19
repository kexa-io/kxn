# kxn-stack

**One Helm command, full kxn observability stack** on a blank Kubernetes cluster.

Bundles:

- **kxn-monitor** (sub-chart) — continuous compliance scan + Discord/Slack/Teams alerts
- **Grafana** (sub-chart, `grafana/grafana`) — with the 19 kxn dashboards pre-imported into the `kxn` folder
- **PostgreSQL** — kxn save backend, a standalone StatefulSet managed by this chart (not the Bitnami chart), schema applied by a post-install Job
- **kxn-logs** — a Deployment running `kxn logs kubernetes://in-cluster --stream`, writing pod log lines to the same backend

The storage backend is selected with `backend.type` (default `postgres`). `loki` deploys a single-binary Loki StatefulSet instead of PostgreSQL, `mongo` a MongoDB one. Prometheus is **not** included; the 19 dashboards are SQL dashboards and need `backend.type=postgres`.

The templates hard-code `kxn-stack-*` resource names (PostgreSQL service, secrets, ServiceAccount), so install the release as **`kxn-stack`**.

## TL;DR

```bash
git clone https://github.com/kexa-io/kxn
cd kxn/deploy/helm/kxn-stack

# Pull the chart dependencies (kxn-monitor / grafana)
helm dependency update

# Install — everything in the `kxn` namespace
helm install kxn-stack . \
  --namespace kxn --create-namespace \
  --set webhooks.discord=https://discord.com/api/webhooks/...
```

That's it. ~2 min later you have:

- Grafana on `kxn-stack-grafana` (admin / `kxn-admin`) with 19 dashboards loaded and a PostgreSQL datasource (uid `kxn-pg`).
- Postgres on `kxn-stack-postgresql:5432` storing every scan, violation, metric and log line.
- A `kxn-monitor` Pod scanning the cluster every 30 s (and the stack's own PostgreSQL every 60 s) and pinging your Discord on new failures.
- A `kxn-stack-kxn-logs` Pod streaming every pod's logs through the K8s API into the `logs` table.

## Picking your alert sink

Set whichever combination of webhooks you use; only `discord` is wired into `kxn-monitor` by default. Override `kxn-monitor.webhooks.secretKey` to switch:

```bash
helm install kxn-stack . \
  --namespace kxn --create-namespace \
  --set webhooks.slack=https://hooks.slack.com/services/... \
  --set kxn-monitor.webhooks.secretKey=slack
```

## Disable components you already run

| Key | Default | Effect |
|---|---|---|
| `grafana.enabled` | `true` | `false` skips Grafana **and** the dashboard / datasource ConfigMaps. |
| `logs.enabled` | `true` | `false` skips the log streamer Deployment. |
| `kxn-monitor.enabled` | `true` | `false` skips the compliance scanner. |
| `postgresql.enabled` | `true` | `false` skips the bundled PostgreSQL (with `backend.type=postgres`). |
| `kxn-monitor.metrics.serviceMonitor.enabled` | `false` | Create a ServiceMonitor if you run the Prometheus Operator. |

If you already run Grafana:

```bash
helm install kxn-stack . \
  --namespace kxn --create-namespace \
  --set webhooks.discord=... \
  --set grafana.enabled=false \
  --set kxn-monitor.metrics.serviceMonitor.enabled=true
```

Then add a PostgreSQL datasource with uid `kxn-pg` pointing at `kxn-stack-postgresql.kxn.svc:5432` (database `kxn`, user `kxn`, password from the `kxn-stack-postgresql` Secret) and import the JSON files from [`files/dashboards/`](files/dashboards/) (see [`deploy/examples/grafana`](../../examples/grafana/README.md)).

## Storage requirements

| Volume | Default size | Where |
|---|---|---|
| Postgres (scans, violations, resources, logs) — `backend.type=postgres` | 10 GiB (`postgresql.persistence.size`) | `data-kxn-stack-postgresql-0` PVC |
| Loki — only with `backend.type=loki` | 10 GiB (`loki.persistence.size`) | `data-kxn-stack-loki-0` PVC |
| Grafana (dashboards/state) | 5 GiB (`grafana.persistence.size`) | `kxn-stack-grafana` PVC |

## Smoke test

```bash
# Trigger a fatal violation
kubectl run failpod --image=busybox --restart=Never -- /bin/false

# Wait ~30 s, watch the alert hit Discord:
#   FATAL pod-not-failed
#   `default/failpod`

# Cleanup the smoke test
kubectl delete pod failpod
```

## Production hardening

- Change `grafana.adminPassword` (or feed it from an existing secret).
- Set your own Postgres passwords ahead of install (`postgresql.auth.password`, `postgresql.auth.postgresPassword`) — the defaults are public demo values.
- Front Grafana with an ingress + OAuth2 proxy, **don't expose port 3000 to the internet**.
- Set `kxn-monitor.builtInRules.minLevel` to `2` to stop evaluating (and alerting on) info and warning rules.
- Increase resources (`postgresql.resources`, `kxn-monitor.resources`, `logs.resources`) for clusters > 50 nodes.

## Uninstall

```bash
helm uninstall kxn-stack -n kxn
kubectl delete namespace kxn  # also drops the PVCs (data loss!)
```

If you want to keep the data: `kubectl -n kxn get pvc` and back them up before deleting the namespace.

## Related

- [`kxn-monitor`](../kxn-monitor/) — standalone chart for compliance + alerts.
- [`kxn-logs`](../kxn-logs/) — standalone chart for log forwarding.
- [Cookbook](../../docs/cookbook-k8s-monitoring.md) — manual install variant with explanations.
