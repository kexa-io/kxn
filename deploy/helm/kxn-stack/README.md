# kxn-stack

**One Helm command, full kxn observability stack** on a blank Kubernetes cluster.

Bundles:

- **PostgreSQL** — kxn save backend (Bitnami chart)
- **Grafana** — with the 19 kxn dashboards pre-imported into the `kxn` folder
- **Loki** — log aggregation (single-binary mode, persistent)
- **kube-prometheus-stack** — Prometheus + ServiceMonitor controller
- **kxn-monitor** — continuous compliance scan + Discord/Slack/Teams alerts
- **kxn-logs** — centralized pod log forwarding into Loki

## TL;DR

```bash
git clone https://github.com/kexa-io/kxn
cd kxn/deploy/helm/kxn-stack

# Pull the chart dependencies (postgres / grafana / loki / prometheus)
helm dependency update

# Install — everything in the `kxn` namespace
helm install kxn-stack . \
  --namespace kxn --create-namespace \
  --set webhooks.discord=https://discord.com/api/webhooks/...
```

That's it. ~2 min later you have:

- Grafana on `kxn-stack-grafana` (admin / `kxn-admin`) with 19 dashboards loaded.
- Postgres on `kxn-stack-postgresql:5432` storing every scan + violation.
- Loki on `kxn-stack-loki-gateway:80` receiving error/warn/fatal pod log lines.
- A `kxn-monitor` Pod scanning the cluster every 30 s and pinging your Discord on new failures.
- A `kxn-logs` Pod tailing every pod's logs through the K8s API.

## Picking your alert sink

Set whichever combination of webhooks you use; only `discord` is wired into `kxn-monitor` by default. Override `kxn-monitor.webhooks.secretKey` to switch:

```bash
helm install kxn-stack . \
  --namespace kxn --create-namespace \
  --set webhooks.slack=https://hooks.slack.com/services/... \
  --set kxn-monitor.webhooks.secretKey=slack
```

## Disable components you already run

If you already have Loki / Prometheus / Grafana in your cluster, turn the bundled ones off:

```bash
helm install kxn-stack . \
  --namespace kxn --create-namespace \
  --set webhooks.discord=... \
  --set loki.enabled=false \
  --set prometheus.enabled=false \
  --set grafana.enabled=false \
  --set kxn-logs.loki.url=loki.observability.svc:3100 \
  --set kxn-monitor.metrics.serviceMonitor.enabled=true
```

The 19 dashboard ConfigMaps are still emitted with the `grafana_dashboard=1` label — your existing Grafana sidecar will pick them up.

## Storage requirements

| Volume | Default size | Where |
|---|---|---|
| Postgres (scans, violations, resources) | 10 GiB | `kxn-stack-postgresql-0` PVC |
| Loki (pod log streams) | 10 GiB | `kxn-stack-loki-0` PVC |
| Grafana (dashboards/state) | 5 GiB | `kxn-stack-grafana` PVC |

## Smoke test

```bash
# Trigger a fatal violation
kubectl run failpod --image=busybox --restart=Never -- /bin/false

# Wait ~30 s, watch the alert hit Discord:
#   ERROR pod-not-failed
#   `default/failpod`

# Cleanup the smoke test
kubectl delete pod failpod
```

## Production hardening

- Change `grafana.adminPassword` (or feed it from an existing secret).
- Pin Postgres password ahead of install (`postgresql.auth.password`).
- Front Grafana with an ingress + OAuth2 proxy, **don't expose port 3000 to the internet**.
- Bump `kxn-monitor.webhooks.minLevel` to `2` to drop info+warning from your alert channel.
- Increase resources (`postgresql.primary.resources`, `prometheus.prometheus.prometheusSpec.resources`) for clusters > 50 nodes.

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
