# Grafana dashboards for kxn

20 ready-to-import Grafana dashboards built on the **PostgreSQL** tables that kxn writes with a postgres save backend (`[[save]] type = "postgres"`, `--save postgresql://...`, or `save.enabled=true` in the `kxn-monitor` chart): `scans`, `rules`, `metrics`, `logs`, `pod_resource` (+ `_5m` / `_1h` tiers).

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
| **kxn-errors** | Cluster-wide error rate from the `logs` table written by `kxn logs` |
| **kxn-cloud-logs** | Centralized log explorer (`logs` table) — filtered by severity |
| **kxn-pod-logs** | Pod logs explorer (`logs` table) |
| **kxn-backups** | Backup CronJob success/failure tracking |
| **kxn-ingress** | Ingress traffic, status codes, latency |
| **kxn-traefik** | Traefik request rate, top routes, error budget |
| **kxn-traefik-deep** | Per-route latency percentiles, retries, circuit-breaker state |
| **kxn-traefik-live** | Real-time request stream (1s refresh) |

## Prerequisites

- A Grafana 10.x+ instance.
- A **PostgreSQL** datasource with uid **`kxn-pg`**, pointing at the database kxn saves to. Every panel references this uid.
- kxn saving to that database: `kxn watch` with a `[[save]] type = "postgres"` block (the `kxn-monitor` chart with `save.enabled=true`, or the `kxn-stack` chart which wires all of this up). The log dashboards (`kxn-errors`, `kxn-cloud-logs`, `kxn-pod-logs`, `kxn-traefik-live`, and the log panels of `kxn-k8s-pods`, `kxn-namespaces`, `kxn-tenants`) need `kxn logs` saving to the same database — the `kxn-logs` chart writes to Loki only, so it does not feed them.
- `kxn-backups`, `kxn-certs`, `kxn-disks`, `kxn-netpolicies` and `kxn-traefik-deep` read dedicated tables (`k8s_jobs`, `tls_certs`, `disk_usage`, `netpol_coverage`, `request_geo`) that the `kxn-stack` schema creates but kxn 0.57.1 does not fill itself; they stay empty unless you populate those tables.

## Import options

### A. Manual via the Grafana UI

`Dashboards` → `New` → `Import` → paste each JSON file. The panels use the datasource uid `kxn-pg`, so create that PostgreSQL datasource first.

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

Every panel references a PostgreSQL datasource by the hardcoded uid `kxn-pg`. Provision your datasource with that uid (the `kxn-stack` chart does), or search-and-replace `"uid": "kxn-pg"` in the JSON files before import.

```yaml
# /etc/grafana/provisioning/datasources/kxn.yaml
apiVersion: 1
datasources:
  - name: kxn-pg
    type: grafana-postgresql-datasource
    uid: kxn-pg
    url: postgres.example.svc:5432
    user: kxn
    jsonData:
      database: kxn
      sslmode: require
    secureJsonData:
      password: ${KXN_PG_PASSWORD}
```

## Customizing

- The queries read the tables kxn creates on first write (`scans`, `rules`, `metrics`, `logs`, `pod_resource`, ...). The `origin` / `target` columns come from the `[[save]] origin` and `[[targets]] name` of your kxn config.
- Variables (cluster, namespace, …) default to `All` — set sensible filters once and `Save as default`.
