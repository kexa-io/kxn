# Example rules

Two ready-to-use TOML rule files we run against our own production cluster, anonymized for the public repo.

| File | Provider | Purpose |
|---|---|---|
| `cluster-health.toml` | `kubernetes` | Failed pods (named in the alert), pending backlog, not-ready nodes, unavailable deployments, restart spikes, warning-event bursts. |
| `postgres-app-rules.toml` | `postgresql` | Cache hit ratio, connection saturation, database size growth. |

## Use them with `kxn watch`

Reference both files from a single `kxn.toml` config. The webhook URL receives **only one consolidated payload per scan cycle** thanks to `--alert-interval`.

```toml
# kxn.toml
[rules]
min_level = 0  # set to 2 to drop info+warning from webhooks (only error/fatal)

[[rules.mandatory]]
name = "cluster-health"
path = "/etc/kxn/rules/cluster-health.toml"

[[rules.mandatory]]
name = "postgres-app"
path = "/etc/kxn/rules/postgres-app-rules.toml"

[[targets]]
name = "k8s"
provider = "kubernetes"
interval = 30  # scan every 30s

[[targets]]
name = "pg"
provider = "postgresql"
config = { PG_HOST = "<your-postgres-host>.<your-ns>.svc", PG_USER = "<user>", PG_PORT = "5432", PG_DATABASE = "<db>" }
interval = 60

[[save]]
type = "postgres"
url = "KXN_PG_URL"
origin = "kxn-collector"
```

Run it:

```bash
kxn watch -c kxn.toml --webhook "$DISCORD_WEBHOOK" --alert-interval 60 --metrics-port 9090
```

## Tuning guidance

| Field | Default here | When to change |
|---|---|---|
| `value = 50` (cache hit ratio) | tolerant | Bump to 70 once you have headroom — < 70 % is the textbook warning. |
| `value = 80` (active_connections) | for `max_connections=100` | Match your `max_connections` × 0.8. |
| `value = 30000` (db size) | 30 GiB | Match your PVC × 0.6 or your retention SLO. |
| `value = 100` (total_restarts) | 9-node cluster | Multiply by `nodes / 9`. |
| `value = 50` (warning_events) | quiet cluster | Raise to your background noise floor. |
| `value = 4` (pods_pending) | tolerant | Drop to 1 if you want to page on the first scheduling stall. |

## Related

- [`kxn-monitor` Helm chart](../../helm/kxn-monitor/) — runs the watch loop in-cluster with these rules.
- [`kxn-logs` Helm chart](../../helm/kxn-logs/) — log forwarding to Loki.
- [Grafana dashboards](../grafana/) — visualize the metrics emitted by `kxn watch`.
