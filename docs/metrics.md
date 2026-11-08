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

## Scrape config

```yaml
scrape_configs:
  - job_name: kxn
    static_configs:
      - targets: ["kxn-watch.monitoring.svc:9090"]
```
