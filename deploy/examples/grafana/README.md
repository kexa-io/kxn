# Grafana dashboards for kxn

19 ready-to-import Grafana dashboards built around the metrics that kxn exposes (`kxn watch --metrics-port`) and the logs it pushes to Loki (`kxn monitor --save loki://...`).

These are the same dashboards that power our own production monitoring — anonymized for the public repo. Drop the JSON files into Grafana and you're done.

## What's in here

| Dashboard | Purpose |
|---|---|
| **kxn-cluster** | High-level cluster overview: nodes, pods, deployments health, restart spikes |
| **kxn-compliance** | CIS / custom rule pass-rates, top failing rules, severity breakdown |
| **kxn-k8s-pods** | Per-pod CPU/memory/restarts, OOMKills, top consumers |
| **kxn-k8s-system** | kube-system + control-plane signals |
| **kxn-namespaces** | Resource consumption per namespace, drift detection |
| **kxn-tenants** | Multi-tenant view (resources, quotas, denials) |
| **kxn-top-consumers** | Hot pods/nodes by CPU, memory, network, disk |
| **kxn-postgres** | PostgreSQL health: connections, cache hit ratio, slow queries |
| **kxn-disks** | Filesystem usage, PVC saturation, I/O throughput |
| **kxn-certs** | TLS certificate inventory and expiry windows |
| **kxn-netpolicies** | NetworkPolicy coverage, missing-NetPol namespaces |
| **kxn-security** | Privileged pods, root containers, host-path mounts, RBAC wildcards |
| **kxn-errors** | Cluster-wide error rate from Loki streams pushed by `kxn logs` |
| **kxn-cloud-logs** | Centralized log explorer (Loki) — filtered by severity |
| **kxn-backups** | Backup CronJob success/failure tracking |
| **kxn-ingress** | Ingress traffic, status codes, latency |
| **kxn-traefik** | Traefik request rate, top routes, error budget |
| **kxn-traefik-deep** | Per-route latency percentiles, retries, circuit-breaker state |
| **kxn-traefik-live** | Real-time request stream (1s refresh) |

## Prerequisites

- A Grafana 10.x+ instance.
- A **Prometheus** datasource scraping kxn's `/metrics` endpoint (set up via `kxn watch --metrics-port 9090` or the `kxn-monitor` Helm chart with `metrics.serviceMonitor.enabled=true`).
- A **Loki** datasource if you want the log-based panels (`kxn-errors`, `kxn-cloud-logs`) — see the `kxn-logs` Helm chart for log forwarding.

## Import options

### A. Manual via the Grafana UI

`Dashboards` → `New` → `Import` → paste each JSON file. Pick your Prometheus / Loki datasource when prompted.

### B. Sidecar (kube-prometheus-stack / Bitnami Grafana)

If your Grafana runs with the Kubernetes sidecar enabled (`grafana.sidecar.dashboards.enabled=true`), drop each dashboard into a labeled `ConfigMap`:

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

The sidecar will pick them up automatically.

### C. Provisioning (file-based)

Mount the JSON files into `/var/lib/grafana/dashboards/kxn/` and add a provisioning file:

```yaml
# /etc/grafana/provisioning/dashboards/kxn.yaml
apiVersion: 1
providers:
  - name: kxn
    folder: kxn
    type: file
    options:
      path: /var/lib/grafana/dashboards/kxn
```

## Datasource UIDs

The dashboards reference datasources by **type** (Prometheus / Loki) without a hardcoded UID — Grafana resolves to the default of each type at import time. If you have multiple Prometheus or Loki datasources, edit each panel's `datasource` field after import.

## Customizing

- The dashboards expect the standard kxn metrics names: `kxn_rules_total`, `kxn_rules_passed`, `kxn_rules_failed`, `kxn_scan_duration_ms`, `kxn_violations_by_level`. If you override `--metrics-namespace`, search-and-replace the prefix.
- Loki labels expected: `job="kxn"`, optional `cluster=<name>`. Set them via `kxn-logs` chart's `loki.labels`.
- Variables (cluster, namespace, …) default to `All` — set sensible filters once and `Save as default`.
