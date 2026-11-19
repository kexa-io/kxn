# Quickstart — kxn metrics and logs in PostgreSQL + Grafana

kxn writes everything it sees (failing rules, the object that failed, numeric metrics, pod logs) to PostgreSQL. Grafana reads those tables with plain SQL. This page gets you there fast, then explains when to add Prometheus.

- [1. Kubernetes in 5 minutes: the `kxn-stack` chart](#1-kubernetes-in-5-minutes-the-kxn-stack-chart)
- [2. Without Kubernetes: your own PostgreSQL + Grafana](#2-without-kubernetes-your-own-postgresql--grafana)
- [3. Kubernetes pod logs](#3-kubernetes-pod-logs)
- [4. Why PostgreSQL, and when Prometheus](#4-why-postgresql-and-when-prometheus)
- [5. Troubleshooting](#5-troubleshooting)

## 1. Kubernetes in 5 minutes: the `kxn-stack` chart

[`deploy/helm/kxn-stack`](../deploy/helm/kxn-stack/README.md) installs, in one release:

| Component | What it runs |
|---|---|
| PostgreSQL | StatefulSet `kxn-stack-postgresql` (`postgres:18-alpine`), schema applied by a post-install Job |
| kxn-monitor | `kxn watch` on the in-cluster API every 30 s (target `k8s`) and on the stack's PostgreSQL every 60 s (target `kxn-pg`), saving to PostgreSQL |
| kxn-logs | `kxn logs kubernetes://in-cluster --stream`, writing every pod log line to the `logs` table |
| Grafana | `kxn-stack-grafana`, PostgreSQL datasource uid `kxn-pg`, 19 dashboards in the `kxn` folder |

Two constraints come from the templates:

- **Release name must be `kxn-stack`**: Service, Secret and ServiceAccount names are hard-coded (`kxn-stack-postgresql`, `kxn-stack-kxn-monitor`, …).
- **Namespace must be `kxn`**: the Grafana sidecars only look for dashboard and datasource ConfigMaps in `kxn` (`grafana.sidecar.dashboards.searchNamespace` / `grafana.sidecar.datasources.searchNamespace`). Use another namespace only if you override both.

```bash
git clone https://github.com/kexa-io/kxn
cd kxn/deploy/helm/kxn-stack

helm install kxn-stack . \
  --namespace kxn --create-namespace \
  --set postgresql.auth.password='change-me' \
  --set postgresql.auth.postgresPassword='change-me-too' \
  --set grafana.adminPassword='change-me-as-well' \
  --set webhooks.discord='https://discord.com/api/webhooks/...'   # optional
```

The sub-charts are already vendored in `charts/`, so no `helm dependency update` is needed (on this version it fails: `Chart.yaml` pins `kxn-monitor` 0.1.0, while `../kxn-monitor` is 0.1.1). The image is `kexa/kxn:v0.58.0`.

Useful values (all in [`values.yaml`](../deploy/helm/kxn-stack/values.yaml)):

| Key | Default | Notes |
|---|---|---|
| `postgresql.auth.password` / `postgresql.auth.postgresPassword` | public demo values | Set them before the first install: initdb uses them once. |
| `postgresql.persistence.size` | `10Gi` | |
| `grafana.adminPassword` | `kxn-admin` | |
| `webhooks.discord` / `slack` / `teams` / `generic` | `""` | Only the key named by `kxn-monitor.webhooks.secretKey` (default `discord`) is used. |
| `kxn-monitor.targets.kubernetes.intervalSeconds` | `30` | Scan interval of the cluster target. |
| `kxn-monitor.targets.postgresql.intervalSeconds` | `60` | Scan interval of the stack's own PostgreSQL. |
| `kxn-monitor.builtInRules.minLevel` | `0` | `2` = only evaluate error and fatal rules. |
| `kxn-monitor.customRules.files` | 2 rule files | The rules the monitor evaluates (the image ships no rule packs). |
| `logs.enabled` | `true` | The pod-log streamer. |
| `kxn-monitor.metrics.serviceMonitor.enabled` | `false` | Prometheus Operator ServiceMonitor (see [§ 4](#4-why-postgresql-and-when-prometheus)). |

Check and open Grafana:

```bash
kubectl -n kxn get pods          # postgresql-0, kxn-monitor, kxn-logs, grafana: Running
kubectl -n kxn port-forward svc/kxn-stack-grafana 3000:80
# http://localhost:3000 — admin / the grafana.adminPassword you set
```

Dashboards to open first (folder `kxn`):

| Dashboard | Reads | Shows |
|---|---|---|
| **Your cluster — Compliance** (`kxn-compliance`) | `scans`, `rules` | Failing rules of the last cycle, per target and severity |
| **Your cluster — Security findings** (`kxn-security`) | `scans`, `rules` | Findings by level, category, target |
| **Your cluster — Cluster** (`kxn-cluster`) | `metrics` (`cluster_stats`), `scans` | Nodes ready, pods running/pending/failed, restarts |
| **Your cluster — Errors & Noisy Pods** (`kxn-errors`) | `logs` | Error/warning rate, noisiest pods, top error messages |
| **Your cluster — Logs** (`kxn-cloud-logs`) | `logs` | Lines per namespace, recent lines |

A panel only has data when the rules in `kxn-monitor.customRules.files` make kxn gather the resource type behind it: `kxn watch` fetches only the types its rules reference. The default rules cover `pods`, `cluster_stats` and `db_stats`, so for example the CPU/memory panels of `kxn-cluster` (`node_metrics`) and the `kxn-k8s-pods` dashboard (`pod_metrics`) stay empty until you add rules on those objects. `kxn-backups`, `kxn-certs`, `kxn-disks`, `kxn-netpolicies` and `kxn-traefik-deep` read tables that kxn 0.57.1 does not fill (see the [dashboards README](../deploy/examples/grafana/README.md)).

Quick test: `kubectl run failpod --image=busybox --restart=Never -- /bin/false`, wait ~30 s, and `pod-not-failed` appears in `kxn-compliance` (and in Discord if set). `kubectl delete pod failpod` afterwards.

## 2. Without Kubernetes: your own PostgreSQL + Grafana

Any PostgreSQL works. kxn creates its tables on the first write, so the user in the URL needs `CREATE` on the database. For a local test:

```bash
docker network create kxn
docker run -d --name kxn-pg --network kxn -p 5432:5432 \
  -e POSTGRES_USER=kxn -e POSTGRES_PASSWORD=kxn -e POSTGRES_DB=kxn \
  postgres:18-alpine
```

### kxn.toml

```toml
[[targets]]
name = "web-01"
uri = "ssh://monitor@web-01.example.com"        # key from SSH_KEY_PATH or ~/.ssh/id_ed25519|id_rsa|id_ecdsa
rules = ["ssh-cis", "ssh-monitoring"]           # ssh-monitoring gathers system_stats (CPU, RAM, disk, load)
interval = 60

[[targets]]
name = "app-db"
uri = "postgresql://kxn_monitor:${PG_MONITOR_PASSWORD}@db.example.com:5432/postgres"
rules = ["postgresql-cis", "postgresql-monitoring"]   # postgresql-monitoring gathers db_stats
interval = 60

[[targets]]
name = "website"
uri = "https://example.com"
rules = ["http-security"]
interval = 300

[[targets]]
name = "cluster"
provider = "kubernetes"
rules = ["kubernetes-cis"]                      # includes cluster_stats rules
interval = 60

[[save]]
type = "postgres"
url = "KXN_PG_URL"                              # no "://": read from this environment variable
origin = "my-laptop"
retention = { scans = "30d", resources = "7d", metrics = "7d", logs = "48h" }
```

Notes, all from the code:

- `rules` match rule-set names (file stems). A name without `*` matches every set whose name *contains* it, so `"kubernetes"` would also pull `kubernetes-master-cis` (an SSH pack): name the sets you want.
- Rules are read from `./rules`, else `~/.cache/kxn/rules`. Fill the cache with `kxn rules pull`, or pass `-R <dir>`.
- **Kubernetes outside the cluster**: the provider does not read `~/.kube/config`. It uses `K8S_API_URL`, `K8S_TOKEN` (or `K8S_TOKEN_FILE`) and `K8S_CA_FILE` (or `K8S_INSECURE=true`), and falls back to the in-cluster ServiceAccount. The token needs read access to the objects your rules use.
- **The save backend connects without TLS.** Use `?sslmode=disable` (or no `sslmode`); `sslmode=require` fails. Unlike targets, the database name in the save URL is used.
- `retention` (postgres only) prunes rows after each save. `logs` and `metrics` default to `7d`; `scans` and `resources` are kept forever unless set; `"0"` disables pruning. Units: `s`, `m`, `h`, `d`, `w`. `KXN_RETENTION_LOGS` / `_METRICS` / `_SCANS` / `_RESOURCES` override the TOML.

### Run

```bash
kxn rules pull
export KXN_PG_URL='postgresql://kxn:kxn@localhost:5432/kxn?sslmode=disable'
export PG_MONITOR_PASSWORD='...'
export K8S_API_URL='https://my-cluster.example.com:6443' K8S_TOKEN='...' K8S_CA_FILE=./ca.crt

kxn watch -c kxn.toml
```

Each target scans on its own `interval` (default 60 s, `-n` on the command line). To run it as a systemd service: `sudo kxn watch install` (writes `/etc/kxn/kxn.toml`).

### What lands in PostgreSQL

| Table | Written by | Columns |
|---|---|---|
| `scans` | `kxn watch`, every cycle | `id`, `created_at`, `error`, `messages` (JSONB), `conditions` (JSONB), `resource_id`, `rule_id`, `batch_id`, `target` |
| `rules` | upserted with scans | `id`, `name`, `description`, `level` (0 info, 1 warning, 2 error, 3 fatal), `provider_id`, `provider_item_id` |
| `resources` | every cycle: each gathered object, and the object of each violation | `id`, `content` (JSONB), `created_at`, `origin_id`, `provider_item_id` |
| `metrics` | every cycle, for numeric resource types (`system_stats`, `db_stats`, `cluster_stats`, `node_metrics`, …) | `time`, `target`, `provider`, `resource_type`, `metric_name`, `value_num`, `value_str` |
| `logs` | `kxn logs` | `id`, `time`, `target`, `source`, `level`, `message`, `host`, `unit`, `batch_id`, `tags` (JSONB) |
| `providers`, `provider_items`, `origins`, `tags` | lookup tables | |

`kxn watch` saves **failing** results only (`error = true`): a rule that passes leaves no row. Each cycle writes the still-failing rows again with a new `batch_id`.

### Grafana

Datasource provisioning — the uid **must** be `kxn-pg`, every dashboard panel references it:

```yaml
# grafana/provisioning/datasources/kxn.yaml
apiVersion: 1
datasources:
  - name: kxn-pg
    type: grafana-postgresql-datasource
    uid: kxn-pg
    url: kxn-pg:5432              # host:port as seen from Grafana
    user: kxn
    access: proxy
    jsonData:
      database: kxn
      sslmode: disable
    secureJsonData:
      password: ${KXN_PG_PASSWORD}
```

Dashboard provisioning:

```yaml
# grafana/provisioning/dashboards/kxn.yaml
apiVersion: 1
providers:
  - name: kxn
    folder: kxn
    type: file
    options:
      path: /var/lib/grafana/dashboards/kxn
```

Run Grafana next to the PostgreSQL container above (from the repository root):

```bash
docker run -d --name grafana --network kxn -p 3000:3000 \
  -e KXN_PG_PASSWORD=kxn \
  -v "$PWD/grafana/provisioning:/etc/grafana/provisioning" \
  -v "$PWD/deploy/examples/grafana:/var/lib/grafana/dashboards/kxn:ro" \
  grafana/grafana:11.6.0
```

With an existing Grafana, add the datasource with uid `kxn-pg` and import the JSON files from [`deploy/examples/grafana`](../deploy/examples/grafana/README.md) (UI import, sidecar ConfigMaps, or the provider file above).

### Example queries

Paste into a Grafana panel (datasource `kxn-pg`, format *Time series*). Use a bucket at least as long as the scan `interval`, otherwise the series has holes (see [§ 5](#5-troubleshooting)).

Violations per severity over time. Each cycle re-writes the failing rows, so the inner query averages per cycle (`batch_id` = one cycle of one target) before summing the targets:

```sql
SELECT time, metric, SUM(per_cycle) AS value
FROM (
  SELECT
    $__timeGroupAlias(s.created_at, '5m'),
    s.target,
    CASE r.level WHEN 3 THEN 'fatal' WHEN 2 THEN 'error' WHEN 1 THEN 'warning' ELSE 'info' END AS metric,
    COUNT(*)::float / COUNT(DISTINCT s.batch_id) AS per_cycle
  FROM scans s
  JOIN rules r ON r.id = s.rule_id
  WHERE $__timeFilter(s.created_at) AND s.error
  GROUP BY 1, 2, 3
) t
GROUP BY 1, 2
ORDER BY 1
```

One metric per target over time (here CPU from `ssh-monitoring`; for PostgreSQL use `resource_type = 'db_stats'` and e.g. `cache_hit_ratio`, `connections_active`, `total_size_bytes`):

```sql
SELECT
  $__timeGroupAlias(time, '5m'),
  target AS metric,
  AVG(value_num) AS value
FROM metrics
WHERE $__timeFilter(time)
  AND resource_type = 'system_stats'
  AND metric_name = 'cpu_percent'
GROUP BY 1, 2
ORDER BY 1
```

Current violations with the offending object (format *Table*):

```sql
SELECT s.created_at, s.target, r.name AS rule, r.level, s.messages, res.content
FROM scans s
JOIN rules r     ON r.id = s.rule_id
JOIN resources res ON res.id = s.resource_id
WHERE s.batch_id IN (
  SELECT DISTINCT ON (target) batch_id FROM scans ORDER BY target, created_at DESC
)
ORDER BY r.level DESC, s.target
```

To list the metric names a target produces: `SELECT DISTINCT resource_type, metric_name FROM metrics WHERE target = 'web-01';`

## 3. Kubernetes pod logs

`kxn logs` reads pod logs through the Kubernetes API (no agent on the nodes) and writes them to every `[[save]]` backend of the config file that supports logs (`postgres`, `loki`, `elasticsearch`, `file`, `kafka`, `splunkhec`). With a URI on the command line, the `[[targets]]` of the file are ignored; only its `[[save]]` blocks are used.

**Stream mode** (what `kxn-stack` runs) — every line of every container, near real time:

```bash
kxn logs kubernetes://in-cluster --stream -c kxn.toml
# batching: --stream-batch-lines 100 (default) --stream-batch-ms 1000 (default)
# skip noisy namespaces: kubernetes://in-cluster?exclude_namespaces=kube-system
```

Rows: `target = 'kubernetes://in-cluster'`, `source = 'kubernetes'`, `unit = '<ns>/<pod>/<container>'`, `host = <node>`, `tags = {namespace, pod, container, node}`, `level` inferred from the message (`error` / `warning` / `info`). `--level`, `--source` and `--pattern` are **not** applied in stream mode.

**Poll mode** — every `--interval` seconds (default 300), only lines containing error/warn/fatal:

```bash
kxn logs kubernetes://in-cluster -c kxn.toml --interval 60 --level error --pattern 'timeout|refused'
```

Poll mode reads the last 100 lines of at most 50 Running/Failed pods, keeps up to 20 error/warn/fatal lines per pod, and stamps them with the collection time (a line still in the tail is saved again on the next poll). `--level` matches the inferred level (`error`, `warning`, `info`, case-insensitive), `--source` matches `<namespace>/<pod>`, `--pattern` is a regex on the message. Rows have `source = '<ns>/<pod>'`, `unit = <pod>` and empty `tags`.

**Dashboards**: `kxn-errors`, `kxn-cloud-logs`, `kxn-namespaces` and the log panels of `kxn-k8s-pods` / `kxn-tenants` group by `tags->>'namespace'` and `tags->>'pod'`, which only stream mode fills — use `--stream` for them. `kxn-pod-logs` (in `deploy/examples/grafana`, not in `kxn-stack`) splits `target` as `<namespace>/<pod>`, which `kxn logs` does not write; its namespace/pod filters stay empty.

Errors per namespace:

```sql
SELECT $__timeGroupAlias(time, '1m'), tags->>'namespace' AS metric, COUNT(*) AS value
FROM logs
WHERE $__timeFilter(time) AND level = 'error'
GROUP BY 1, 2
ORDER BY 1
```

**Loki instead of PostgreSQL**: `[[save]] type = "loki"`, `url = "loki://loki:3100"` (or `loki+https://…`, basic auth from `LOKI_USER` / `LOKI_PASSWORD`). Streams are labelled `{app="kxn", kind="log", origin="<origin>"}`. The shipped dashboards are SQL only and do not read Loki; in `kxn-stack`, `backend.type=loki` deploys Loki and a Loki datasource but none of the 19 dashboards apply.

## 4. Why PostgreSQL, and when Prometheus

They answer different questions, and `kxn watch` can feed both at once.

| | PostgreSQL (`[[save]] type = "postgres"`) | Prometheus (`kxn watch --metrics-port`) |
|---|---|---|
| What is kept | Each failing rule with its messages, conditions and the full object (JSONB), the rules, raw gathered objects, numeric metrics, log lines | Gauges for the **last** scan only: `kxn_rules_total`, `kxn_rules_passed`, `kxn_rules_failed`, `kxn_scan_duration_ms`, `kxn_violations_by_level` (labels `provider`, `target`, `level`) |
| History | Yes, per-table `retention` | Whatever your Prometheus retains, counts only |
| Questions | "Which pods were privileged last Tuesday, and what did the spec look like?", joins of violations with logs and metrics | "Alert when `kxn_rules_failed > 0`", trends of counts across many kxn instances |
| Dashboards shipped | 19–20, see above | None — build your own from [metrics.md](metrics.md) |
| Needs | A database | An existing Prometheus that scrapes kxn |

Use PostgreSQL for the audit trail and the dashboards. Add Prometheus when you already run Alertmanager and want kxn counts in it.

Enable both on the same process:

```bash
export KXN_PG_URL='postgresql://kxn:kxn@localhost:5432/kxn?sslmode=disable'
export KXN_METRICS_TOKEN="$(openssl rand -hex 32)"     # read when --metrics-port is set
kxn watch -c kxn.toml --metrics-port 9090
# local only, no token: --metrics-port 9090 --metrics-bind 127.0.0.1
# per-container / per-node CPU & RAM gauges (Kubernetes targets): add --metrics-resources
```

`--metrics-bind` defaults to `0.0.0.0`; without a token anyone who can reach the port reads target names. Scrape config and the `kxn logs --metrics-port` series (`kxn_logs_total`, `kxn_logs_by_source`, `kxn_logs_collection_duration_ms`; no token option) are in [metrics.md](metrics.md). Alert examples:

```promql
kxn_rules_failed > 0
kxn_violations_by_level{level="fatal"} > 0
```

In `kxn-stack`, the monitor already listens on 9090 (Service `kxn-stack-kxn-monitor-metrics`, no token). Set `kxn-monitor.metrics.serviceMonitor.enabled=true` if you run the Prometheus Operator. The chart has no value for a metrics token, and its readiness/liveness probes call `/metrics` without one, so adding a token through `extraEnv` makes the pod unready.

## 5. Troubleshooting

**Dashboards say "No data".**
1. Is kxn saving? `kxn watch` prints `save error: …` when a write fails. Check the `[[save]]` block and the URL (env var exported? `sslmode=require` is not supported).
2. `SELECT target, max(created_at) FROM scans GROUP BY 1;` and `SELECT resource_type, max(time) FROM metrics GROUP BY 1;` — if empty, kxn is not writing; if filled, Grafana is not reading.
3. The datasource uid must be exactly `kxn-pg` (*Connections → Data sources*: the edit URL ends in `/datasources/edit/kxn-pg`). Panels reference the uid, not the name.
4. The panel's `resource_type` must be gathered by your rules (see [§ 1](#1-kubernetes-in-5-minutes-the-kxn-stack-chart)).

**`kxn-stack`: no `kxn-logs` pod, or Grafana has no dashboards.** The release is not named `kxn-stack` (the `kxn-logs` Deployment then references a ServiceAccount `kxn-stack-kxn-monitor` that does not exist), or the namespace is not `kxn` (the Grafana sidecars only watch `kxn`). `helm uninstall` and reinstall with `helm install kxn-stack . -n kxn`.

**Gaps or saw-tooth time series.** Rows arrive once per scan `interval`. A query that buckets by minute (`date_trunc('minute', …)`, as the shipped dashboards do) over a 300 s interval leaves four empty buckets out of five. Use `$__timeGroupAlias(time, '5m')` with a bucket ≥ the interval, or lower the target `interval`. For counts from `scans`, divide by the number of cycles (`COUNT(DISTINCT batch_id)` per target, as in the query in [§ 2](#example-queries)) so a bucket holding several cycles is not counted several times.

**Pass rate is 0 % / "passed" series is empty.** `kxn watch` stores failing results only. Use `kxn_rules_passed` from the Prometheus endpoint for pass counts.

**Database keeps growing.** `scans` and `resources` have no default retention, and `resources` receives every gathered object each cycle. Set `retention = { scans = "30d", resources = "7d" }` in `[[save]]` (or `KXN_RETENTION_SCANS` / `KXN_RETENTION_RESOURCES`; in `kxn-stack` pass them through `kxn-monitor.extraEnv`). Pruning runs after each save; `resources` rows still referenced by a scan are kept.

**Log dashboards empty while the `logs` table fills.** You are in poll mode (`tags` empty): run `kxn logs … --stream`.
