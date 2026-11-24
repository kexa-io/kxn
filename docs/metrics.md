# Prometheus metrics

`kxn watch --metrics-port <port>` serves Prometheus scan metrics at `http://<bind>:<port>/metrics`.
The address comes from `--metrics-bind` (default `0.0.0.0`, all interfaces); on anything other than
`127.0.0.1` / `localhost` / `::1`, set a token (see [Authentication](#authentication)) — kxn prints a
warning if you don't. `kxn monitor` does not open a metrics port.

`kxn logs --metrics-port <port>` serves log-collection metrics instead (see [Log collection metrics](#log-collection-metrics-kxn-logs)).

Series appear after the first completed scan of each target.

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `kxn_rules_total` | gauge | `provider`, `target` | Rule evaluations in the last scan |
| `kxn_rules_passed` | gauge | `provider`, `target` | Rule evaluations that passed in the last scan |
| `kxn_rules_failed` | gauge | `provider`, `target` | Rule evaluations that failed in the last scan |
| `kxn_scan_duration_ms` | gauge | `provider`, `target` | Duration of the last scan, in milliseconds |
| `kxn_violations_by_level` | gauge | `provider`, `target`, `level` | Violations in the last scan, per level: `info`, `warning`, `error`, `fatal` |

A rule is evaluated once per resource it applies to, so these counts are rule ×
resource evaluations, not rules: a rule checked against 40 users adds 40 to
`kxn_rules_total`. Rules that could not be evaluated (object not collected, pack
for another provider) are not counted. All values describe the most recent
scan, not a running total. Use `kxn_rules_failed > 0` for alerting, and
`100 * kxn_rules_passed / kxn_rules_total` for a compliance rate. Save backends
receive the same four counts as metric records (`resource_type = "kxn_scan"`,
see [Alerting and saving](alerting-and-saving.md#what-gets-saved)).

## Resource gauges (`--metrics-resources`)

With `--metrics-resources`, `watch` also exposes per-container and per-node CPU and memory gauges.
This flag requires `--metrics-port` and applies to Kubernetes targets. Pod gauges carry the labels `target`, `namespace`, `pod`, `container`, `node`, `workload_kind` and `workload`; node gauges carry `target` and `node`.

| Metric | Meaning |
|--------|---------|
| `kxn_pod_cpu_millicores` | Container CPU usage in millicores |
| `kxn_pod_memory_mib` | Container working-set memory in MiB |
| `kxn_pod_cpu_request_millicores` | Container CPU request (only when set) |
| `kxn_pod_cpu_limit_millicores` | Container CPU limit (only when set) |
| `kxn_pod_memory_request_mib` | Container memory request (only when set) |
| `kxn_pod_memory_limit_mib` | Container memory limit (only when set) |
| `kxn_node_cpu_millicores` | Node CPU usage in millicores |
| `kxn_node_memory_mib` | Node working-set memory in MiB |
| `kxn_node_cpu_allocatable_millicores` | Node allocatable CPU in millicores |
| `kxn_node_memory_allocatable_mib` | Node allocatable memory in MiB |

Usage values come from metrics-server, or from the kubelet when metrics-server is not available.

## Log collection metrics (`kxn logs`)

`kxn logs --metrics-port <port>` exposes, per target:

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `kxn_logs_total` | gauge | `target`, `level` | Log entries collected, per level |
| `kxn_logs_by_source` | gauge | `target`, `source` | Log entries collected, per source |
| `kxn_logs_collection_duration_ms` | gauge | `target` | Duration of the last collection, in milliseconds |

This endpoint always listens on `0.0.0.0` and has no token option: restrict it with a NetworkPolicy or firewall.

## Authentication

This section applies to `kxn watch`. Without a token, `/metrics` is open to anyone who can reach the port. The metrics also expose target names, and with `--metrics-resources` the pods, containers and nodes of the cluster.

Set a token with `--metrics-token <token>` or the `KXN_METRICS_TOKEN` environment variable. Prefer the environment variable, so the token does not appear in the process list. Requests then need `Authorization: Bearer <token>`, and other requests get `401`.

## Scrape config

```yaml
scrape_configs:
  - job_name: kxn
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/kxn-metrics-token
    static_configs:
      - targets: ["kxn-watch.monitoring.svc:9090"]
```
