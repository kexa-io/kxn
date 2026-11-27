# Kubernetes Pod Monitor

Run kxn as a pod in your cluster. Every two minutes it checks pod phases and node
CPU and memory, and it can send each violation to Discord, store it in
PostgreSQL and show it in a Grafana dashboard. Everything uses the official
`kexa/kxn` image and one manifest, [`deploy/kubernetes/kxn-pod-monitor.yaml`](../deploy/kubernetes/kxn-pod-monitor.yaml).

For a ready-made PostgreSQL, Grafana and 19 dashboards in one Helm release, see
[PostgreSQL + Grafana quickstart](quickstart-postgres-grafana.md) instead.

## Prerequisites

- `kubectl` access to the cluster, with rights to create a namespace and a ClusterRole
- metrics-server, for the node CPU and memory rules (`kubectl top nodes` works)
- The image `kexa/kxn`, published on Docker Hub (amd64 and arm64) by every release; the manifest pins the tag of its release
- Optional: a Discord webhook URL, a PostgreSQL database and a Grafana instance

## 1. Deploy

```bash
kubectl apply -f deploy/kubernetes/kxn-pod-monitor.yaml
kubectl -n kxn rollout status deployment/kxn-monitor
```

The manifest creates the `kxn` namespace, a read-only ClusterRole, a ConfigMap
holding `kxn.toml` and two rule files, and a one-replica Deployment running
`kxn watch`.

| Rule | Object | Fails when | Level |
|------|--------|------------|-------|
| `pod-not-failed` | `pods` | phase is `Failed` | 3 (fatal) |
| `pod-not-unknown` | `pods` | phase is `Unknown` | 3 (fatal) |
| `pod-not-pending` | `pods` | phase is `Pending` | 1 (warning) |
| `node-high-cpu` | `node_metrics` | `cpu_pct` (usage over allocatable) ≥ 90 | 2 (error) |
| `node-high-memory` | `node_metrics` | `memory_pct` ≥ 85 | 2 (error) |

## 2. See the scan results

Each cycle writes one line to the pod log:

```bash
kubectl -n kxn logs deployment/kxn-monitor
```

```
kxn watch | 1 target(s) | webhooks=0 | save=0
  my-cluster | provider=kubernetes | rules=5 | interval=120s
[07:27:49] my-cluster #1 FAIL | 771/775 passed | 3ms
```

To see each violation, run the same rules once inside the pod:

```bash
kubectl -n kxn exec deployment/kxn-monitor -- kxn kubernetes://in-cluster -R /etc/kxn/rules
```

```
   #  Level  Rule            Resource  Message
   1  ERROR  node-high-cpu   pve01     cpu_pct INF 90 but got 99.6
   2  ERROR  node-high-cpu   pve05     cpu_pct INF 90 but got 99.8
```

The same scan runs from your machine with your kubeconfig: copy the two rule
files of the ConfigMap into a directory and run `kxn k8s://<context> -R <directory>`.
Without `-R`, kxn runs the community Kubernetes rules instead.

## 3. Discord alerts

Store the webhook in the `kxn-secrets` Secret, then restart the pod so it reads
it. The manifest does not contain this Secret, so applying it again never
overwrites the value.

```bash
kubectl -n kxn create secret generic kxn-secrets \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/ID/TOKEN'
kubectl -n kxn rollout restart deployment/kxn-monitor
```

Test it with a pod that fails:

```bash
kubectl run test-fail --image=busybox --restart=Never -- false
# within two minutes, Discord receives the alert
kubectl delete pod test-fail
```

Discord receives one embed per violation:

```
🔴 pod-not-failed
Pod in Failed phase — needs immediate action
Target: my-cluster   Object type: pods   Severity: FATAL
Resource: default/test-fail   Node: <node>
Conditions failed: • phase DIFFERENT Failed but got Failed
```

The same violation on the same pod is sent again at most once per hour
(`kxn watch --alert-interval`, default 3600 s). To change the webhook, replace
the Secret and restart:

```bash
kubectl -n kxn create secret generic kxn-secrets \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/NEW_ID/NEW_TOKEN' \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n kxn rollout restart deployment/kxn-monitor
```

## 4. Save the results to PostgreSQL

kxn creates its tables on the first write, so the database only needs a user
with the `CREATE` privilege on its schema:

```sql
CREATE USER kxn WITH PASSWORD 'change-me';
CREATE DATABASE kxn OWNER kxn;
```

In `deploy/kubernetes/kxn-pod-monitor.yaml`, uncomment the `[[save]]` block of
`kxn.toml` and set the host of your database:

```toml
[[save]]
type = "postgres"
url = "postgresql://kxn:${PG_PASSWORD}@postgres.kxn.svc:5432/kxn"
origin = "my-cluster"
```

Add the password to `kxn-secrets` (every key of this Secret becomes an
environment variable of the pod, and kxn replaces `${PG_PASSWORD}` when it
starts), then apply and restart:

```bash
kubectl -n kxn create secret generic kxn-secrets \
  --from-literal=PG_PASSWORD='change-me' \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/ID/TOKEN' \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy/kubernetes/kxn-pod-monitor.yaml
kubectl -n kxn rollout restart deployment/kxn-monitor
```

Leave out `DISCORD_WEBHOOK` if you do not use Discord. The log line now ends the
header with `save=1`, and each cycle adds its violations to `scans` and the node
usage to `metrics`:

```sql
SELECT s.created_at, r.name, r.level, s.target
FROM scans s JOIN rules r ON r.id = s.rule_id
ORDER BY s.created_at DESC
LIMIT 20;
```

## 5. Grafana dashboard

The `kxn-compliance` dashboard of [`deploy/examples/grafana`](../deploy/examples/grafana/README.md) reads these tables. It expects a
PostgreSQL data source whose UID is `kxn-pg`, which the Grafana UI cannot set,
so create the data source and import the dashboard through the Grafana API:

<!-- x-release-please-start-version -->

```bash
GRAFANA=http://localhost:3000      # e.g. kubectl -n monitoring port-forward svc/grafana 3000:80
GRAFANA_AUTH='admin:your-grafana-password'

curl -s -u "$GRAFANA_AUTH" -H 'Content-Type: application/json' "$GRAFANA/api/datasources" -d '{
  "name": "kxn", "uid": "kxn-pg", "type": "postgres", "access": "proxy",
  "url": "postgres.kxn.svc:5432", "user": "kxn",
  "jsonData": {"database": "kxn", "sslmode": "disable"},
  "secureJsonData": {"password": "change-me"}}'

curl -fsSL https://raw.githubusercontent.com/kexa-io/kxn/v0.66.0/deploy/examples/grafana/kxn-compliance.json \
  | jq '{dashboard: ., overwrite: true}' \
  | curl -s -u "$GRAFANA_AUTH" -H 'Content-Type: application/json' "$GRAFANA/api/dashboards/db" -d @-
```

<!-- x-release-please-end -->

Open **Dashboards → Your cluster — Compliance**: pass rate and number of checks
of the last cycle, failing rules now, passes and failures per target over time,
and the 25 rules failing most in the last cycle, with their description and
level. The pass rate comes from the counts kxn writes each cycle from v0.65.0 on;
with an older image it stays empty.

The other dashboards of that directory (cluster, pods, namespaces…) read objects
that this manifest does not collect: its five rules only gather `pods` and
`node_metrics`. Use [kxn-stack](quickstart-postgres-grafana.md) for them.

## Customisation

Edit the rule files in the ConfigMap of the manifest to change levels or
thresholds, filter namespaces, or add conditions, then apply the manifest and
restart the pod. See [Rules](rules.md).

## Supported alert backends

`kxn watch` (daemon mode, used by this manifest) takes `--webhook URL` — Discord and Slack URLs are auto-detected and formatted natively. For other platforms, add an `[alerts]` table to `kxn.toml` (one list of URIs per severity; the same URIs work with `--alert` on `kxn <uri>` and `kxn monitor <uri>`):

```toml
[alerts]
error = ["slack://hooks.slack.com/services/T/B/xxx"]
fatal = ["pagerduty://routing-key", "discord://discord.com/api/webhooks/ID/TOKEN"]
```

| Backend | URI |
|---------|-----|
| Discord | `discord://discord.com/api/webhooks/ID/TOKEN` |
| Slack | `slack://hooks.slack.com/services/T/B/xxx` |
| Teams | `teams://outlook.webhook.office.com/...` |
| PagerDuty | `pagerduty://routing-key` |

See [Alerting and Saving](alerting-and-saving.md) for the full list.

## TLS verification (`K8S_INSECURE`)

In a pod, kxn verifies the API server certificate against the ServiceAccount CA
(`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`). If the pod log shows a
certificate error, as on OVH Managed Kubernetes, turn the verification off by
adding this variable to the container of the Deployment:

```yaml
env:
- name: K8S_INSECURE
  value: "true"
```

## Scan interval

`kxn watch` scans every 60 seconds by default (`-n`); this manifest sets `interval = 120` on its target. Adjust in `kxn.toml`:

```toml
[[targets]]
name = "my-cluster"
provider = "kubernetes"
uri = "kubernetes://in-cluster"
interval = 60  # seconds
```
