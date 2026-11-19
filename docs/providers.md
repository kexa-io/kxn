# kxn Providers

kxn supports 19 native providers (`docker` is Unix-only; `oracle` is an optional build feature) and 3000+ Terraform providers via gRPC bridge.

## Native Providers

### ssh

Connects via SSH to gather system configuration and state.

**URI scheme:** `ssh://user:password@host:port` or `ssh://user@host` (key-based)

**Configuration** (gather `-C` keys or environment variables): `SSH_HOST` (required), `SSH_USER` (default `root`), `SSH_PORT` (default `22`).

**Authentication**, first match wins: `SSH_PASSWORD` (or the password in the URI), `SSH_KEY` (private key content), `SSH_KEY_PATH` / `SSH_PRIVATE_KEY` (path to a private key file). With an `ssh://` URI and none of these set, kxn uses the first of `~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa` that exists; `kxn gather -p ssh` with plain keys does not, so give it a key explicitly (or pass `{"uri":"ssh://user@host"}`). Set `SSH_INSECURE=true` to skip host key verification.

**Resource types:**

| Type | Description |
|------|-------------|
| `sshd_config` | SSH daemon configuration |
| `sysctl` | Kernel parameters |
| `users` | System users |
| `services` | Systemd/init services |
| `file_permissions` | File ownership and permissions |
| `os_info` | OS release information |
| `system_stats` | CPU, memory, disk usage |
| `packages` | Packages with an available upgrade (`apt`, `yum`, `apk`) — not the full inventory |
| `packages_cve` | All installed packages (`dpkg`, `rpm`, `apk`) cross-referenced with the local CVE database |
| `logs` | System logs |
| `kubelet_config` | Kubelet configuration (Kubernetes nodes) |
| `k8s_master_config` | Kubernetes master configuration |
| `apache_config` | Apache HTTP Server configuration (empty when Apache is not installed) |
| `apache_permissions` | Ownership and permissions of Apache files |
| `nginx_config` | Resolved nginx configuration (`nginx -T`; empty when nginx is not installed) |
| `nginx_permissions` | Ownership and permissions of nginx files and TLS keys |
| `pam_config` | PAM stack (password quality, lockout, `su` restriction) |
| `audit_config` | auditd and syslog configuration |
| `firewall_config` | nftables / iptables ruleset |
| `filesystem_config` | Mount options, kernel modules, world-writable paths |
| `user_audit` | Account-level aggregates (UID 0 accounts, empty passwords, …) — needs read access to `/etc/shadow` |
| `auth_stats` | Recent SSH authentication failures/successes from the auth log |
| `fail2ban_status` | fail2ban jails and bans |
| `listening_ports` | Listening TCP/UDP sockets |

The OS and service collectors return nothing (rules reported as not evaluated) when the software is absent or the account cannot read what they need, rather than reporting a violation.

**Examples:**

```bash
# Quick CIS scan (key-based auth)
kxn ssh://root@10.0.0.1

# Password auth
kxn ssh://admin:mypassword@10.0.0.1

# Gather upgradable packages
kxn gather -p ssh -t packages -C '{"SSH_HOST":"10.0.0.1","SSH_USER":"root","SSH_KEY_PATH":"/root/.ssh/id_rsa"}'

# Same, with a URI (key fallback as for a quick scan)
kxn gather -p ssh -t packages -C '{"uri":"ssh://root@10.0.0.1"}'

# Gather system stats
kxn gather -p ssh -t system_stats -C '{"SSH_HOST":"10.0.0.1","SSH_USER":"root","SSH_INSECURE":"true"}'

# CVE scan on installed packages
kxn cve-update && kxn ssh://root@10.0.0.1 --rules rules/packages-cve.toml
```

### docker

Connects to the Docker daemon via Unix socket to monitor containers, images, and daemon configuration. Runs locally — no SSH required.

**URI scheme:** `docker://` — the local socket; `docker://?socket=/run/podman/podman.sock` for another one.

**Configuration:**

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Path to the Docker Unix socket |

**Resource types:**

| Type | Description |
|------|-------------|
| `docker_containers` | All containers with state, runtime config, and Compose labels |
| `docker_config` | Daemon configuration from `/etc/docker/daemon.json` |
| `docker_host` | What the Docker API reports about the daemon (version) |
| `docker_host_files` | Socket permissions, TLS config, audit rules — read from the host filesystem, served only when kxn runs on the daemon's host |
| `docker_images` | Local image listing |

**Key fields for `docker_containers`:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Container name |
| `state` | string | `running`, `exited`, `paused`, etc. |
| `running` | bool | True if currently running |
| `workdir` | string | Docker Compose project directory (`com.docker.compose.project.working_dir` label) |
| `service` | string | Docker Compose service name |
| `project` | string | Docker Compose project name |
| `image` | string | Image name |
| `privileged` | bool | Privileged mode |
| `pid_mode` | string | PID namespace mode |
| `network_mode` | string | Network mode |
| `memory_limit` | int | Memory limit in bytes (0 = unlimited) |
| `restart_policy_name` | string | Restart policy (`always`, `unless-stopped`, etc.) |

**Example — list all container states:**

```bash
kxn gather -p docker -t docker_containers
```

**Example — CIS Docker benchmark:**

```bash
kxn gather -p docker -t all | kxn scan -R rules --include "docker-cis-*"
```

**Docker Compose monitoring:**

Monitor that all services in a Compose stack are running and alert on Discord if any container goes down.

Say you have this stack in `/opt/myapp/docker-compose.yml`:

```yaml
# /opt/myapp/docker-compose.yml
services:
  web:
    image: nginx:alpine
    ports: ["80:80"]
    restart: unless-stopped

  api:
    image: node:20-alpine
    command: node server.js
    restart: unless-stopped

  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: secret
    restart: unless-stopped
```

Docker Compose automatically sets a `com.docker.compose.project.working_dir` label on every container with the directory where the compose file lives. kxn uses this to filter containers by stack.

**Step 1 — write the rule:**

```toml
# /opt/myapp/rules/stack-monitoring.toml
[metadata]
version = "1.0.0"
provider = "docker"

[[rules]]
name = "myapp-container-running"
description = "myapp container is down — check docker compose logs"
level = 3
object = "docker_containers"

  # Compliant if: not from this stack (ignore) OR running (healthy)
  # Any myapp container that is NOT running → violation → Discord alert
  [[rules.conditions]]
  operator = "OR"
  criteria = [
    { property = "workdir", condition = "DIFFERENT", value = "/opt/myapp" },
    { property = "state", condition = "EQUAL", value = "running" },
  ]
```

**Step 2 — add kxn as a sidecar service in your docker-compose.yml:**

```yaml
# /opt/myapp/docker-compose.yml
services:
  web:
    image: nginx:alpine
    ports: ["80:80"]
    restart: unless-stopped

  api:
    image: node:20-alpine
    command: node server.js
    restart: unless-stopped

  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: secret
    restart: unless-stopped

  kxn-monitor:
    image: kexa/kxn:latest
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./kxn.toml:/etc/kxn/kxn.toml:ro
      - ./rules/stack-monitoring.toml:/etc/kxn/rules/stack-monitoring.toml:ro
    environment:
      - DISCORD_WEBHOOK=${DISCORD_WEBHOOK}
    command: watch --config-file /etc/kxn/kxn.toml
```

**Step 3 — create kxn.toml:**

```toml
# /opt/myapp/kxn.toml
[rules]
mandatory = [
  { name = "stack-monitoring", path = "/etc/kxn/rules/stack-monitoring.toml" },
]

[[targets]]
name = "myapp"
provider = "docker"
interval = 60

# Level 3 rules route to the `fatal` channel list
[alerts]
fatal = ["${DISCORD_WEBHOOK}"]
```

**Step 4 — start:**

```bash
echo "DISCORD_WEBHOOK=https://discord.com/api/webhooks/..." > .env
docker compose up -d
```

kxn scans all containers every 60 seconds. If `web`, `api`, or `db` stops, a Discord alert fires. `kxn-monitor` itself is excluded because its workdir label matches the compose project directory (`/opt/myapp`), so it would also trigger an alert if it crashed — but `restart: unless-stopped` keeps it alive.

### postgresql

Connects to PostgreSQL databases for compliance scanning.

**URI scheme:** `postgresql://user:password@host:port` or `postgres://...` (port defaults to 5432). A `/dbname` path is accepted but ignored: kxn always connects to the `postgres` database and lists the others from there.

**Configuration** (gather `-C` keys or environment variables): `PG_HOST`, `PG_PORT`, `PG_USER`, `PG_PASSWORD`. `PG_DATABASE` and the libpq `PGHOST`-style variables are not read.

**TLS:** `?sslmode=disable|prefer|require|verify-ca|verify-full` (default `prefer`: TLS when the server offers it, no certificate check) and `?sslrootcert=/path/ca.pem`, or `PG_SSLMODE` / `PG_SSLROOTCERT`. Use `verify-full` in production. Any other query parameter is rejected.

**Resource types:**

| Type | Description |
|------|-------------|
| `databases` | Database listing (with tables, columns, indexes, views, functions, triggers) |
| `db_stats` | Database statistics (connections, cache hit ratio, bgwriter, replication lag) |
| `logs` | PostgreSQL logs (pg_stat_activity, pg_log, pg_conflicts) |
| `roles` | Database roles and permissions |
| `settings` | Server configuration parameters |
| `stat_activity` | Active connections and queries |
| `extensions` | Installed extensions |
| `replication` | Replication slots and replica status |
| `table_stats` | Per-table statistics (bloat, vacuum, scan counts) |
| `indexes` | Index usage and size statistics |
| `locks` | Blocked/waiting locks |
| `tablespaces` | Tablespace listing and sizes |

**Examples:**

```bash
# Quick CIS scan
kxn postgresql://admin:pass@localhost:5432/mydb

# Gather roles
kxn gather -p postgresql -t roles -C '{"uri":"postgresql://admin:pass@localhost/mydb"}'

# Check active locks
kxn gather -p postgresql -t locks -C '{"uri":"postgresql://admin:pass@localhost/mydb"}'

# Full CIS PostgreSQL benchmark, certificate verified
kxn "postgresql://admin:pass@db.internal?sslmode=verify-full&sslrootcert=/etc/ssl/db-ca.pem" --rules rules/postgresql-cis.toml
```

### mysql

Connects to MySQL/MariaDB databases.

**URI scheme:** `mysql://user:password@host:port` (port defaults to 3306). A `/dbname` path is accepted but ignored.

**Configuration** (gather `-C` keys or environment variables): `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD`.

**TLS:** `?sslmode=disable|prefer|require|verify-ca|verify-full` (default `prefer`) and `?sslca=/path/ca.pem` (alias `sslrootcert`), or `MYSQL_SSLMODE` / `MYSQL_SSLROOTCERT`. Any other query parameter is rejected.

**Resource types:**

| Type | Description |
|------|-------------|
| `databases` | Database listing (with tables, columns, indexes) |
| `db_stats` | Database statistics (connections, InnoDB buffer pool, replication lag) |
| `logs` | MySQL logs (warnings, errors, slow queries, general log) |
| `users` | Database users |
| `grants` | User privileges |
| `variables` | Server global variables |
| `status` | Server global status |
| `processlist` | Active processes |
| `engines` | Storage engines |
| `replication` | Replication status (SHOW REPLICA STATUS) |
| `table_stats` | Per-table statistics (fragmentation, size) |
| `indexes` | Index statistics and usage |
| `innodb_status` | InnoDB engine status (buffer pool, deadlocks, row ops) |
| `schema_sizes` | Per-schema data and index sizes |

**Examples:**

```bash
# Quick CIS scan
kxn mysql://root:pass@localhost:3306/mysql

# Gather users and grants
kxn gather -p mysql -t users -C '{"uri":"mysql://root:pass@localhost/mysql"}'
kxn gather -p mysql -t grants -C '{"uri":"mysql://root:pass@localhost/mysql"}'

# Check replication lag
kxn gather -p mysql -t replication -C '{"uri":"mysql://root:pass@replica.internal/mysql"}'
```

### mongodb

Connects to MongoDB instances and clusters.

**URI scheme:** `mongodb://user:password@host:port/dbname` or `mongodb+srv://...`

**Resource types:**

| Type | Description |
|------|-------------|
| `databases` | Database listing (with collections and indexes) |
| `db_stats` | Database statistics (connections, opcounters, WiredTiger cache) |
| `logs` | MongoDB logs (getLog global/startupWarnings, slow ops) |
| `users` | Database users |
| `serverStatus` | Full server status and metrics |
| `currentOp` | Current in-progress operations |
| `cmdLineOpts` | Command line options (security, TLS, network config) |
| `replication` | Replica set status (replSetGetStatus) |
| `collection_stats` | Per-collection statistics (size, fragmentation, indexes) |
| `indexes` | Index listing across all collections |
| `sharding` | Sharding status and balancer info |
| `profiling` | Profiling level per database |

**Examples:**

```bash
# Quick CIS scan
kxn mongodb://admin:pass@localhost:27017/admin

# Atlas (SRV)
kxn mongodb+srv://admin:pass@cluster0.abc.mongodb.net/admin

# Gather replica set status
kxn gather -p mongodb -t replication -C '{"uri":"mongodb://admin:pass@mongo.internal/admin"}'

# Check running operations
kxn gather -p mongodb -t currentOp -C '{"uri":"mongodb://admin:pass@localhost/admin"}'
```

### kubernetes

Talks to the Kubernetes API directly, with the same credentials as `kubectl`:

```bash
kxn k8s://homelab          # the "homelab" context of your kubeconfig
kxn k8s://                 # the current context
kxn k8s://in-cluster       # from a pod: its ServiceAccount
kxn k8s://homelab/monitoring          # only the monitoring namespace
kxn logs k8s://homelab/monitoring/kxn # log lines of the pods named kxn*
```

The path after the context is `/<namespace>/<pod>`; the pod is a name prefix.
`kxn logs` prints the last `--tail` lines (default 100) of each container,
`-f` keeps following, and `--level` / `--pattern` filter the lines.

The kubeconfig is `$KUBECONFIG` (several files separated by `:`) or
`~/.kube/config`. kxn takes the context's API server and CA, and the user's
token, token file, client certificate or **exec plugin** (`aws eks get-token`,
`gke-gcloud-auth-plugin`, `kubelogin`…), which it runs like `kubectl` does. The
legacy `auth-provider` entries are not supported. A context name that does not
exist is an error listing the available ones — kxn never falls back to another
cluster. `helm://<context>` works the same way.

In a pod with no kubeconfig, kxn uses the ServiceAccount token at
`/var/run/secrets/kubernetes.io/serviceaccount/token` and the cluster CA next to
it, found through `KUBERNETES_SERVICE_HOST`.

The settings below override the kubeconfig, or replace it entirely when
`K8S_API_URL` is set:

| Setting | Description |
|---------|-------------|
| `K8S_API_URL` | API server, e.g. `https://10.0.0.1` |
| `K8S_TOKEN` / `K8S_TOKEN_FILE` | Bearer token — a ServiceAccount, or what a cloud plugin issues (`gcloud auth print-access-token` for GKE, `az aks get-credentials` for AKS) |
| `K8S_CLIENT_CERT` + `K8S_CLIENT_KEY` | Client-certificate authentication — how self-managed clusters and `kubectl` admin kubeconfigs authenticate. Both are required together |
| `K8S_CA_FILE` | Cluster CA |
| `K8S_INSECURE=true` | Skip TLS verification entirely — a last resort, not a substitute for the CA |
| `K8S_TIMEOUT` | Per-request timeout in seconds (default 30). Raise it on clusters slow to serve large objects |
| `K8S_NAMESPACE` | Restrict collection to one namespace |

The certificate, key and CA each accept three forms: a file path, inline PEM, or
base64-encoded PEM — the last being what a kubeconfig stores in
`client-certificate-data`, `client-key-data` and `certificate-authority-data`,
so those values can be used as they are.

**CPU/RAM usage source:** `node_metrics`, `pod_metrics`, `pod_resource` and `pod_efficiency` read the Metrics API (`metrics.k8s.io`, i.e. metrics-server) and fall back to every kubelet's `/stats/summary` through the API-server proxy when it is not installed (needs `get` on `nodes/proxy`, granted by the Helm chart). Both report working-set memory and instantaneous CPU, so rules and dashboards see the same numbers either way; each row carries `source = "metrics-server" | "kubelet"`. Force one path with `K8S_USAGE_SOURCE=metrics-server|kubelet` (default `auto`). Threshold and right-sizing rules for these objects ship in `rules/kubernetes-resources.toml`.

**Log collection:** `kxn logs kubernetes://in-cluster` polls pod logs (`tailLines=100&timestamps=true`, max 50 pods per cycle) and forwards error/warn/fatal/panic/exception lines through the standard log pipeline (filter, metrics, save) — no separate agent (fluent-bit, promtail) required. Works alongside `kxn watch kubernetes://...` for scans + metrics.

**Resource types (69):**

| Type | Description |
|------|-------------|
| `pods` | Pod resources |
| `deployments` | Deployment resources |
| `services` | Service resources |
| `nodes` | Cluster nodes |
| `namespaces` | Namespaces |
| `ingresses` | Ingress resources |
| `configmaps` | ConfigMap resources |
| `secrets_metadata` | Secret metadata (no values) |
| `events` | Cluster events |
| `cluster_stats` | Cluster-level statistics |
| `rbac_cluster_roles` | RBAC ClusterRole resources |
| `rbac_cluster_role_bindings` | RBAC ClusterRoleBinding resources |
| `network_policies` | Network policies |
| `persistent_volumes` | Persistent Volumes |
| `persistent_volume_claims` | Persistent Volume Claims |
| `daemonsets` | DaemonSet resources |
| `statefulsets` | StatefulSet resources |
| `cronjobs` | CronJob resources |
| `service_accounts` | Service accounts |
| `jobs` | Job resources |
| `hpa` | Horizontal Pod Autoscalers |
| `resource_quotas` | Resource quotas |
| `limit_ranges` | Limit ranges |
| `node_metrics` | Node CPU/RAM usage plus allocatable and `cpu_pct` / `memory_pct` (metrics-server, kubelet fallback) |
| `pod_metrics` | Pod-level CPU/RAM usage, containers nested (metrics-server, kubelet fallback) |
| `pod_logs` | Pod log output |
| `roles` | Namespaced RBAC Role resources |
| `role_bindings` | Namespaced RBAC RoleBinding resources |
| `validating_webhook_configurations` | Validating admission webhooks |
| `mutating_webhook_configurations` | Mutating admission webhooks |
| `custom_resource_definitions` | Installed CRDs |
| `storage_classes` | StorageClass resources |
| `pod_disruption_budgets` | PodDisruptionBudget resources |
| `priority_classes` | PriorityClass resources |
| `tls_certs` | `kubernetes.io/tls` Secrets, parsed for certificate expiry metadata (never returns the PEM itself) |
| `pod_resource` | Flat per-(namespace, pod, container) CPU/RAM usage (metrics-server, kubelet fallback) |
| `pod_efficiency` | Per-container usage joined with requests/limits: `*_request_pct`, `*_limit_pct`, `*_slack_*`, `has_*_request/limit`, owning workload, QoS class |
| `k8s_jobs` | Job timing (duration, age, last success/failure age, state) for timeline dashboards |
| `netpol_coverage` | Per-pod NetworkPolicy coverage — ingress/egress enforcement and coverage percentage per namespace |
| `disk_usage` | Per-pod-attached PVC capacity/used/available |
| `endpoints` | Endpoints resources |
| `endpoint_slices` | EndpointSlice resources |
| `replicasets` | ReplicaSet resources |
| `leases` | Lease resources (leader-election) |
| `csi_drivers` | Installed CSIDriver resources |
| `csi_nodes` | CSINode resources |
| `volume_attachments` | VolumeAttachment resources |
| `certificate_signing_requests` | CertificateSigningRequest resources |
| `runtime_classes` | RuntimeClass resources |
| `pod_restarts` | Per-container restart counts, last-termination reason and the pod `phase` (one row per pod without container statuses, e.g. an evicted `Failed` pod) |
| `pod_status_phase` | Pod count rolled up by namespace and phase (Running/Pending/Failed/Succeeded/Unknown) |
| `container_oom_kills` | Per-namespace OOMKill counter (last 1h window, from Events) |
| `flow_schemas` | API Priority and Fairness FlowSchema resources |
| `priority_level_configurations` | API Priority and Fairness PriorityLevelConfiguration resources |
| `validating_admission_policies` | ValidatingAdmissionPolicy resources |
| `validating_admission_policy_bindings` | ValidatingAdmissionPolicyBinding resources |
| `server_version` | Cluster server version (major/minor/git_version) |
| `api_resources_summary` | All API groups and their preferred versions — flags deprecated APIs in use |
| `container_network` | Per-container network rx/tx bytes (kubelet stats summary) |
| `node_runtime` | Per-node aggregate runtime stats (image filesystem, allocatable vs used pods) |
| `istio_virtual_services` | Istio VirtualService resources (requires the Istio CRDs) |
| `istio_gateways` | Istio Gateway resources (requires the Istio CRDs) |
| `argo_applications` | Argo CD Application resources (requires the Argo CD CRDs) |
| `argo_workflows` | Argo Workflows resources (requires the Argo Workflows CRDs) |
| `cert_manager_certificates` | cert-manager Certificate resources (requires cert-manager CRDs) |
| `prometheus_rules` | Prometheus Operator PrometheusRule resources (requires the Prometheus Operator CRDs) |
| `service_monitors` | Prometheus Operator ServiceMonitor resources (requires the Prometheus Operator CRDs) |
| `flux_kustomizations` | Flux Kustomization resources (requires the Flux CRDs) |
| `dns_health` | In-cluster DNS resolution check (`kubernetes.default.svc.cluster.local`) — ok/latency/error |

Resource types marked "requires the ... CRDs" return empty results (not an error) on a cluster where that operator/CRD isn't installed.

**Examples:**

```bash
# Scan from outside the cluster (the host part of the URI is only a label)
K8S_API_URL=https://10.0.0.1:6443 K8S_TOKEN=$TOKEN K8S_CA_FILE=ca.crt kxn kubernetes://my-cluster

# Gather pods across all namespaces
kxn gather -p kubernetes -t pods

# Gather node metrics
kxn gather -p kubernetes -t node_metrics

# In-cluster (running inside a pod with a ServiceAccount)
K8S_INSECURE=true kxn kubernetes://in-cluster

# Run as a pod inside the cluster — see deploy/kubernetes/ for a full manifest
# with RBAC, Discord alerts, and pod health rules
```

### helm

Helm releases, read from the cluster's own state rather than from the `helm`
binary. Helm 3 keeps one Secret per release revision (type
`helm.sh/release.v1`), so there is nothing to shell out to and no extra
credential: this is the Kubernetes provider restricted to what Helm stores.
Scanning with `kubernetes://` collects the same objects; `helm://` targets
releases on their own.

**URI scheme:** `helm://` — same options as `kubernetes://`
(`?namespace=`, `?api_url=`, `?token=`, …).

**Resource types:**

| Type | Description |
|------|-------------|
| `helm_releases` | Current revision of each release: `name`, `namespace`, `chart`, `chart_version`, `app_version`, `revision`, `revisions` (revisions the cluster still keeps), `status`, `first_deployed`, `last_deployed`, `description`, `values` (user-supplied values only), `manifest_bytes` |

The listing asks the API server for metadata only
(`PartialObjectMetadataList`): the labels already carry each revision's release
name, status and number, so the current revision is chosen without reading a
single payload. Only those are then fetched in full, in parallel
(`K8S_HELM_CONCURRENCY`, default 4). It matters — on a cluster with 51
revisions, listing whole Secrets returned 3.8 MB in 214 s where the metadata
listing returns 64 KB in 1.2 s, because each payload carries the release's
entire rendered manifest.

A release whose payload could not be read keeps the fields its labels prove
(name, namespace, revision, status) and carries an `error` field instead of the
chart details, rather than silently going missing. Slow clusters may need
`K8S_TIMEOUT` above its 30 s default — single release Secrets took 21 s, 27 s
and 36 s on a real cluster.

### github

Connects to GitHub organizations and repositories.

**Authentication:** set `GITHUB_TOKEN` env var (personal access token or GitHub App token with `read:org`, `repo`, `security_events` scopes) and `GITHUB_ORG` (or pass `GITHUB_TOKEN` / `GITHUB_ORG` in `-C`).

**URI scheme:** `github://<org>`. The token is `GITHUB_TOKEN`, or, when it is unset, the one of a logged-in GitHub CLI (`gh auth token`).

**Resource types (25):**

| Type | Description |
|------|-------------|
| `organization` | Organization settings |
| `members` | Organization members (with role and 2FA status) |
| `outside_collaborators` | External collaborators |
| `teams` | Teams and membership |
| `webhooks` | Configured webhooks |
| `audit_log` | Audit log events |
| `security_managers` | Security manager teams |
| `custom_roles` | Custom repository roles |
| `repositories` | Repository listing (with branch protection, security settings) |
| `rulesets` | Organization rulesets |
| `environments` | Deployment environments across all repos |
| `deploy_keys` | Deploy keys across all repos |
| `autolinks` | Autolink references across all repos |
| `dependabot_alerts` | Dependabot vulnerability alerts |
| `secret_scanning_alerts` | Secret scanning alerts |
| `code_scanning_alerts` | Code scanning alerts |
| `actions_permissions` | Actions permissions and policies |
| `actions_org_secrets` | Organization-level Actions secrets |
| `actions_org_variables` | Organization-level Actions variables |
| `actions_runners` | Self-hosted runners |
| `actions_workflows` | Workflows across all repos |
| `packages` | Packages (npm, maven, docker, nuget, etc.) |
| `copilot_usage` | Copilot billing and usage |
| `codeowners` | CODEOWNERS file presence per repo |
| `community_metrics` | Community health metrics (public repos) |

**Examples:**

```bash
export GITHUB_TOKEN=ghp_xxx

# Gather Dependabot alerts
kxn gather -p github -t dependabot_alerts -C '{"GITHUB_ORG":"my-org"}'

# Gather all repos with branch protection status
kxn gather -p github -t repositories -C '{"GITHUB_ORG":"my-org"}'

# Full security scan (rules/github-security.toml)
kxn gather -p github -t all -C '{"GITHUB_ORG":"my-org"}' | kxn scan -R rules --include "github-sec-*"
```

Continuous monitoring with `kxn watch --config-file kxn.toml`:

```toml
[[rules.mandatory]]
name = "github-security"
path = "rules/github-security.toml"

[[targets]]
name = "github"
provider = "github"
config = { GITHUB_ORG = "my-org" }   # GITHUB_TOKEN from the environment
interval = 3600
```

### http

Probes HTTP/HTTPS endpoints.

**URI scheme:** `http://host` or `https://host`

**Configuration** (gather `-C` keys, or `HTTP_<KEY>` / `<KEY>` environment variables):

| Key | Description |
|-----|-------------|
| `URL` | Target URL (required). In `-C` / `[targets.config]` it may be a JSON array to probe several URLs |
| `METHOD` | `GET` (default), `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH` |
| `AUTHORIZATION` | Value of the `Authorization` header |
| `BODY` | Request body |
| `INSECURE` | `true` to skip TLS certificate verification |

Requests time out after 30 s, and redirects are not followed (a `301`/`302` is reported as such).

**Resource types:**

| Type | Description |
|------|-------------|
| `request` | HTTP probe returning status, headers, TLS info, certificate details, and timing |

**Examples:**

```bash
# OWASP / TLS scan
kxn https://example.com

# Gather raw probe data (status, headers, cert expiry)
kxn gather -p http -t request -C '{"URL":"https://api.example.com"}'

# Probe several endpoints at once
kxn gather -p http -t request -C '{"URL":["https://example.com","https://api.example.com/health"]}'

# Monitoring rules only
kxn https://example.com --rules rules/http-monitoring.toml
```

### grpc

Probes gRPC services.

**URI scheme:** `grpc://host:port` — port 443 means TLS (`https://`), any other port plaintext.

**Configuration** (gather `-C` keys, or `GRPC_<KEY>` / `<KEY>` environment variables): `ENDPOINT` (required, with a scheme: `http://host:port` or `https://host:port`; may be a JSON array), `TLS` (`true` to force TLS), `TIMEOUT` (seconds, default 10), `SERVICE` (service name for the health check, default: overall server health).

**Resource types:**

| Type | Description |
|------|-------------|
| `health_check` | gRPC health check |
| `connection` | Connection status |
| `reflection` | Service reflection metadata |
| `service_health` | Per-service health status |

**Examples:**

```bash
# Health check
kxn grpc://my-service:9090

# Gather service reflection metadata
kxn gather -p grpc -t reflection -C '{"ENDPOINT":"http://my-service:9090"}'
```

### cve

Fetches the public CVE feeds live (NVD API, CISA KEV catalog, FIRST EPSS API) so rules can alert on new entries. It does not read the local CVE database — that database (`kxn cve-update`) is what the `ssh` provider's `packages_cve` type uses for offline package matching.

**URI scheme:** `cve://` — query parameters become config keys, e.g. `cve://nvd?keywords=openssh,nginx&severity=critical&days_back=7`.

**Configuration** (or `CVE_<KEY>` environment variables): `KEYWORDS` (comma-separated NVD keyword searches), `SEVERITY` (CVSS v3 severity), `CPE_NAME`, `DAYS_BACK` (NVD publication window, default 7), `MAX_RESULTS`, `NVD_URL` / `KEV_URL` / `EPSS_URL` (feed overrides, e.g. an internal mirror), `API_KEY` (NVD API key; env `NVD_API_KEY`).

**Resource types:**

| Type | Description |
|------|-------------|
| `nvd_cves` | NVD CVE entries |
| `kev` | CISA Known Exploited Vulnerabilities |
| `epss` | Exploit Prediction Scoring System scores |

**Examples:**

```bash
# Sync the local CVE database used by packages_cve (NVD + CISA KEV + EPSS)
kxn cve-update

# Alert on new critical CVEs, KEV entries and high EPSS scores
kxn cve:// --rules rules/cve-monitoring.toml

# Detect CVEs in packages installed on a server (ssh provider + local database)
kxn ssh://root@10.0.0.1 --rules rules/packages-cve.toml

# Gather all CISA KEV entries (actively exploited)
kxn gather -p cve -t kev

# Gather top EPSS entries (highest exploit probability)
kxn gather -p cve -t epss
```

### googleworkspace

Audits Google Workspace: 2-Step Verification (2FA/MFA), Drive file sharing, third-party OAuth apps, groups, devices and domains. Calls the Admin SDK, Drive API and Groups Settings API directly — no Terraform.

**Provider name:** `googleworkspace` (alias `gws`)

**Authentication:** OAuth / Application Default Credentials (`gcloud auth application-default login`), or a service account with domain-wide delegation (`credentials_file` + `subject`).

**Resource types:**

| Type | Description |
|------|-------------|
| `users` | Directory users with 2SV/MFA, admin status, last login |
| `domains` | Registered domains, verification and SPF/DKIM/DMARC posture |
| `groups` | Groups with external-membership and posting settings |
| `oauth_tokens` | Third-party OAuth apps authorized by users |
| `mobile_devices` | Managed mobile devices and encryption status |
| `chromeos_devices` | Managed ChromeOS devices |
| `role_assignments` | Admin role assignments |
| `drive_files` | Owned Drive files with their sharing classification |

**Examples:**

```bash
# Audit your own account (after `gcloud auth application-default login`)
kxn gather -p googleworkspace -t all | kxn scan -R rules --include "gws-*"

# Audit the whole domain via a service account
kxn gather -p googleworkspace -t all \
  -C '{"credentials_file":"sa.json","subject":"admin@corp.com","scan_all_users":true}' \
  | kxn scan -R rules --include "gws-*"
```

Full setup guide and rule reference: [google-workspace.md](google-workspace.md). Ready-to-run example: [`deploy/examples/google-workspace/`](../deploy/examples/google-workspace/).

### oracle

Connects to Oracle Database. Behind the `oracle` build feature — not compiled into the default binary/Docker image; build with `cargo build --features oracle` to enable it.

**URI scheme:** `oracle://user:password@host:port/service_name`

**Resource types:**

| Type | Description |
|------|-------------|
| `users` | Database accounts and their status |
| `tables` | Table metadata |
| `privileges` | Granted system/object privileges |
| `sessions` | Active sessions |
| `parameters` | Instance parameters (`v$parameter`) |
| `views` | View definitions |
| `triggers` | Trigger definitions |
| `db_stats` | Instance-level statistics |
| `logs` | Alert log / recent errors |
| `tablespaces` | Tablespace usage |
| `datafiles` | Datafile metadata |
| `redo_logs` | Redo log group status |
| `indexes` | Index metadata |
| `jobs` | Scheduler jobs |
| `rman_backups` | RMAN backup history |

### aws

Native AWS provider, distinct from the Terraform `hashicorp/aws` bridge below.
Resources are listed and read through the Cloud Control API (one protocol for
every CloudFormation resource type); account-level IAM facts with no
CloudFormation type (credential report, account summary, password policy,
virtual MFA devices, server certificates) come from the IAM API. IAM calls use
the global `aws` partition endpoint — `aws-cn` and `aws-us-gov` are not handled.

**URI scheme:** `aws://<region>`, e.g. `aws://eu-west-3`. The region is
required: there is no fallback to `us-east-1`, because a scan of the wrong
region reports zero findings for the one that mattered. `?concurrency=N` sets
the number of parallel detail reads (default 8; Cloud Control throttles hard).

**Configuration** (gather `-C` keys or environment variables): `REGION` (env
`AWS_REGION`, then `AWS_DEFAULT_REGION`), `CONCURRENCY` (env `AWS_CONCURRENCY`).

**Credentials:** `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+
`AWS_SESSION_TOKEN` for temporary credentials). Without them kxn runs
`aws configure export-credentials`, so whatever the AWS CLI is logged in with
works (profiles, SSO, instance roles). The AWS CLI is not in the `kexa/kxn`
image: in a container, pass the environment variables.

**Resource types:**

| Type | Description |
|------|-------------|
| `aws_iam_account_password_policy` | Account password policy (shape used by `aws-iam-cis`) |
| `aws_iam_account_summary` | IAM account summary (root MFA, root access keys, …) |
| `aws_iam_credential_report` | IAM credential report, one row per user |
| `aws_iam_role` | IAM roles (shape used by `aws-iam-cis`) |
| `aws_iam_server_certificate` | IAM server certificates and their expiry |
| `aws_iam_support_role` | Whether a role carries `AWSSupportAccess` |
| `aws_iam_users` | IAM users (shape used by `aws-iam-cis`) |
| `aws_iam_virtual_mfa_devices` | Virtual MFA devices |
| `cloudtrail` | CloudTrail trails |
| `ebs_volume` | EBS volumes |
| `ecr_repository` | ECR repositories |
| `eks_cluster` | EKS clusters |
| `iam_account_password_policy` | Account password policy (shape used by `aws-cis`) |
| `iam_role` | IAM roles (shape used by `aws-cis`) |
| `iam_user` | IAM users (shape used by `aws-cis`) |
| `kms_key` | KMS keys |
| `rds_cluster` | RDS / Aurora clusters |
| `rds_instance` | RDS instances |
| `s3_bucket` | S3 buckets |
| `security_group` | EC2 security groups |
| `sns_topic` | SNS topics |
| `sqs_queue` | SQS queues |
| `vpc` | VPCs |

An object is served only when every property its rules read is produced. Not
served, so the matching rules of `rules/aws-cis.toml` and
`rules/aws-iam-cis.toml` are reported as *not evaluated*: `instance` (IMDSv2
setting not exposed by Cloud Control), `security_group_rule` (no port on
"all traffic" rules), `cloudwatch_log_group`, `load_balancer`,
`lambda_function`, `secrets_manager`, `s3_account_public_access_block` and
`ebs_encryption_by_default` (account-level settings), `aws_iam_policy` and
`aws_accessanalyzer_analyzer`.

**Examples:**

```bash
# CIS scan of one region (credentials from the environment or the AWS CLI)
kxn aws://eu-west-3 --rules rules/aws-cis.toml

# Gather S3 buckets
AWS_REGION=eu-west-3 kxn gather -p aws -t s3_bucket
```

### gcp

Native GCP provider, distinct from the Terraform `google` provider bridge below.

Unlike Azure, GCP has no single inventory endpoint that a scan can rely on:
Cloud Asset Inventory would be one, but it has to be enabled on the project
first, so collection goes service by service. Each object is served only once
every field its rules read is produced.

**URI scheme:** `gcp://project-id` or `google://project-id`. Query parameters become config keys, e.g. `gcp://my-project?key_max_age_days=30`.

**Configuration:** `PROJECT` (env `GCP_PROJECT`; the URI host sets it), `KEY_MAX_AGE_DAYS` (env `GCP_KEY_MAX_AGE_DAYS`, default 90) — the age after which a service account key is flagged.

**Credentials:** Application Default Credentials — a service account key via
`GOOGLE_APPLICATION_CREDENTIALS`, or a user login
(`gcloud auth application-default login`). `GOOGLE_OAUTH_ACCESS_TOKEN`
short-circuits both. Calls carry `x-goog-user-project`, which user credentials
need for APIs that require a billing project.

**Resource types:**

| Type | Description |
|------|-------------|
| `bigquery_dataset` | BigQuery datasets (access entries, default encryption) |
| `compute_disk` | Compute Engine persistent disks (customer-managed encryption key) |
| `compute_firewall` | VPC firewall rules |
| `compute_instance` | Compute Engine VMs: IP forwarding, OS Login / serial port / project SSH key metadata, public IPs, service account and scopes, Shielded VM |
| `compute_ssl_policy` | SSL policies (minimum TLS version) |
| `compute_subnetwork` | VPC subnetworks (flow log configuration) |
| `container_cluster` | GKE clusters: logging and monitoring services, legacy ABAC, network policy, private nodes, master authorized networks, node auto-upgrade |
| `logging_project_sink` | Project log sinks (destination, filter) |
| `service_account_keys` | Service account keys with their age; flags keys older than `KEY_MAX_AGE_DAYS` (default 90 days) |
| `storage_bucket` | Cloud Storage buckets: public access prevention, uniform bucket-level access, versioning |

`rules/gcp-cis.toml` also reads `compute_network`, `dns_managed_zone`,
`kms_crypto_key`, `service_account` and `sql_database_instance`, which this
provider does not serve: those rules are reported as *not evaluated* on a
`gcp://` scan. `rules/gcp-iam-cis.toml` is written for the Terraform `google`
provider (`google_*` objects).

Values are normalized to the names the rules use, which follow Terraform's
`google` schema — including its one-element-list convention, so a nested block
is read as `network_policy.0.enabled`. GCP omits false booleans on the wire
(proto3), so a missing flag is read as disabled; that is the API's encoding, not
a refusal to answer, and it is the only case where a value is filled in.

### azure

Native Azure Resource Manager provider, distinct from the Terraform `azurerm`
bridge below. ARM exposes one inventory endpoint and one detail endpoint for
every service, so this is a single generic collector: the subscription is listed
once per scan, and only the resources whose type kxn maps are read back in
detail (in parallel, bounded by `CONCURRENCY`, default 16).

**URI scheme:** `azure://subscription-id` or `azurerm://subscription-id` — with
no subscription, the first one the credentials can see is used. `?concurrency=N`
sets `CONCURRENCY`.

**Credentials**, in order: `AZURE_ACCESS_TOKEN`, then a service principal
(`AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID`), then whoever is
logged in with the Azure CLI. The CLI fallback is what makes `kxn azure://`
work on a workstation without provisioning anything; a daemon or a container
should use the service principal.

**Resource types:**

| Type | Description |
|------|-------------|
| `container_registry` | Azure Container Registries: admin user, public network access, anonymous pull |
| `log_analytics_workspace` | Log Analytics workspaces and their retention |
| `monitor_diagnostic_setting` | Subscription diagnostic settings (Activity Log export) |
| `mysql_flexible_server` | Azure Database for MySQL flexible servers (SSL enforcement) |
| `network_watcher` | Network Watchers, per region |
| `nsg` | Network security groups, with their rules flattened to `security_rules` |
| `security_center_subscription_pricing` | Microsoft Defender for Cloud plan per resource type |
| `virtual_machine` | Virtual machines |

An object appears here only once every field the rules read for it is produced.
`storage_account` is not served because CIS 3.9 and 3.10 read Storage Analytics
logging, which no ARM call answers. The `vm` and `disk` objects (managed-disk
checks) are not served yet — nothing populates `disk`. `postgresql_flexible_server`
is not served because CIS 4.3.8 reads a property the flexible-server API does not
have. `key_vault` is a sharper case: ARM
returns no `enableSoftDelete` / `enablePurgeProtection` at all on vaults where
they were never set, so CIS 8.4 and 8.5 cannot be answered from ARM data
without inventing a verdict — and a fabricated `false` reports every modern
vault as non-compliant. Those objects stay with the Terraform bridge for now.

On an `azure://` scan, the rules of `rules/azure-cis.toml` that read `aks_cluster`,
`app_service`, `disk`, `key_vault`, `postgresql_flexible_server`, `public_ip`,
`sql_server`, `storage_account` or `vm` are therefore reported as *not
evaluated*, and so is all of `rules/azure-iam-cis.toml`, whose objects are
Terraform names (`azuread_*`, `azurerm_role_assignment`, …) this provider does
not serve.

### microsoft.graph

Native Microsoft Graph provider for Entra ID (Azure AD), distinct from any Terraform `azuread` usage. Currently scoped to service principal / app registration auditing.

**URI scheme:** `microsoft.graph://` or `msgraph://` (the host part is ignored).

**Credentials:** a service principal (`AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`), otherwise the Azure CLI's logged-in session.

**Resource types:**

| Type | Description |
|------|-------------|
| `service_principals` | App registrations / service principals, their credentials and permissions |

### forgejo

Audits Forgejo (and Gitea) Actions CI/CD pipeline history — runs, individual jobs, and their logs — so pipeline health and failures are scannable like any other resource.

**URI scheme:** none — use `kxn gather -p forgejo` (alias `gitea`) or a `kxn.toml` target with `provider = "forgejo"`.

**Configuration** (or `FORGEJO_<KEY>` environment variables): `URL` (instance base URL, required), `TOKEN` (required; env `FORGEJO_TOKEN`), `REPOS` (required, comma-separated `owner/repo` list), `MAX_RUNS_PER_REPO` (default 100).

```bash
kxn gather -p forgejo -t pipeline_runs -C '{"URL":"https://git.example.com","REPOS":"ops/infra,ops/app"}'
```

**Resource types:**

| Type | Description |
|------|-------------|
| `pipeline_runs` | One row per workflow run, with status/conclusion |
| `pipeline_jobs` | Individual jobs within a run |
| `pipeline_logs` | Job log output |

### prometheus

Scrapes any HTTP endpoint serving the [Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/) (Traefik, node-exporter, blackbox-exporter, an app's own `/metrics`) and turns each `name{labels} value` line into a kxn metric record — no PromQL query engine, just a scraper.

**Config** (`-C` / `[targets.config]` keys, or `PROM_<KEY>` environment variables): `URL` (required — the metrics endpoint; a URL with no path gets `/metrics` appended), `BEARER_TOKEN` (optional), `INSECURE` (skip TLS verification), `INCLUDE_PREFIXES`/`EXCLUDE_PREFIXES` (comma-separated metric name filters — exclude is handy for dropping `go_*`/`process_*` runtime noise).

**URI scheme:** `prometheus://host:port/path` / `prom://…` is accepted, but in this release the URL it builds is not read by the provider, so set `URL` in the config (or `PROM_URL` in the environment) as well:

```bash
kxn gather -p prometheus -t prometheus_metrics -C '{"URL":"http://node-exporter:9100/metrics","EXCLUDE_PREFIXES":"go_,process_"}'
```

**Resource types:**

| Type | Description |
|------|-------------|
| `prometheus_metrics` | Every scraped metric line as one record |

### local

Runs the same checks as the `ssh` provider but against the machine kxn itself is running on, over a local shell instead of an SSH connection. Useful for a host-level scan without needing SSH access to itself, or as an in-container/in-pod self-check.

**URI scheme:** `local://`

**Resource types (18):** `sshd_config`, `sysctl`, `users`, `services`, `file_permissions`, `os_info`, `packages`, `apache_config`, `apache_permissions`, `nginx_config`, `nginx_permissions`, `pam_config`, `audit_config`, `firewall_config`, `filesystem_config`, `auth_stats`, `fail2ban_status`, `listening_ports` (same parsers as `ssh`, run locally). Not available locally: `system_stats`, `packages_cve`, `logs`, `kubelet_config`, `k8s_master_config`, `user_audit`.

## Terraform Providers (3000+)

kxn bridges to any Terraform provider via gRPC, giving access to thousands of cloud resource types without custom code.

**Cached examples:**

| Provider | Registry Name |
|----------|---------------|
| AWS | `hashicorp/aws` |
| Google Cloud | `hashicorp/google` |
| Azure Resource Manager | `hashicorp/azurerm` |
| Azure AD | `hashicorp/azuread` |
| Kubernetes | `hashicorp/kubernetes` |
| Helm | `hashicorp/helm` |
| Vault | `hashicorp/vault` |
| Microsoft Graph | `microsoft/msgraph` |
| Cloudflare | `cloudflare/cloudflare` |
| GitHub | `integrations/github` |
| Proxmox | `bpg/proxmox` |

Use `kxn list-providers` to see all available providers, or `kxn gather -p <terraform-provider> -t <type>` to collect resources.

## URI Schemes

These are the schemes accepted by `kxn <uri>`, `kxn monitor <uri>`, a `kxn.toml` target `uri`, and `{"uri": ...}` in `kxn gather -C`:

| Scheme | Provider |
|--------|----------|
| `ssh://` | ssh |
| `local://` | local |
| `postgresql://` | postgresql |
| `postgres://` | postgresql |
| `mysql://` | mysql |
| `mongodb://` | mongodb |
| `mongodb+srv://` | mongodb |
| `oracle://` | oracle (optional build feature) |
| `http://` | http |
| `https://` | http |
| `grpc://` | grpc |
| `cve://` | cve |
| `aws://` | aws |
| `azure://` | azure |
| `azurerm://` | azure |
| `gcp://` | gcp |
| `google://` | gcp |
| `msgraph://` | microsoft.graph |
| `microsoft.graph://` | microsoft.graph |
| `prometheus://` | prometheus |
| `prom://` | prometheus |
| `kubernetes://` | kubernetes |
| `k8s://` | kubernetes |
| `helm://` | helm |

| `github://<org>` | github |
| `docker://` | docker |
| `forgejo://<host>[/<owner>/<repo>]` | forgejo |
| `googleworkspace://<domain>` | googleworkspace |

## Gather Command

Collect resources from any provider:

```bash
# Basic gather
kxn gather -p <provider> -t <resource-type>

# With configuration
kxn gather -p <provider> -t <resource-type> -C '<json-config>'

# Verbose output
kxn gather -p <provider> -t <resource-type> -v
```

**Examples:**

```bash
# SSH upgradable packages
kxn gather -p ssh -t packages -C '{"SSH_HOST":"10.0.0.1","SSH_USER":"admin","SSH_KEY_PATH":"/home/me/.ssh/id_ed25519"}'
kxn gather -p ssh -t packages -C '{"uri":"ssh://admin@10.0.0.1"}'

# PostgreSQL roles
kxn gather -p postgresql -t roles -C '{"uri":"postgresql://user:pass@localhost/mydb"}'

# HTTP endpoint probe
kxn gather -p http -t request -C '{"URL":"https://example.com"}'

# CVE database query
kxn gather -p cve -t kev
```
