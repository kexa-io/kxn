# Prometheus metrics

`kxn watch --metrics-port <port>` serves Prometheus metrics at `http://0.0.0.0:<port>/metrics`.
This is the only supported way to expose metrics. `kxn monitor` does not open a metrics port.

Series appear after the first completed scan of each target.

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `kxn_rules_total` | gauge | `provider`, `target` | Rules evaluated in the last scan |
| `kxn_rules_passed` | gauge | `provider`, `target` | Rules that passed in the last scan |
| `kxn_rules_failed` | gauge | `provider`, `target` | Rules that failed in the last scan |
| `kxn_scan_duration_ms` | gauge | `provider`, `target` | Duration of the last scan, in milliseconds |
| `kxn_violations_by_level` | gauge | `provider`, `target`, `level` | Violations in the last scan, per level: `info`, `warning`, `error`, `fatal` |

All values describe the most recent scan, not a running total. Use `kxn_rules_failed > 0` for alerting.

## Resource gauges (`--metrics-resources`)

With `--metrics-resources`, `watch` also exposes per-container and per-node CPU and memory gauges.
This flag requires `--metrics-port`. Pod labels identify the pod and container, and node labels identify the node.

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

## Scrape config

```yaml
scrape_configs:
  - job_name: kxn
    static_configs:
      - targets: ["kxn-watch.monitoring.svc:9090"]
```
