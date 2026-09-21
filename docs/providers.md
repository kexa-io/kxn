# kxn Providers

kxn supports 15 native providers on all platforms (16 including `docker`, Unix-only; 17 with the optional `oracle` build feature) and 3000+ Terraform providers via gRPC bridge.

## Native Providers

### ssh

Connects via SSH to gather system configuration and state.

**URI scheme:** `ssh://user:password@host:port` or `ssh://user@host` (key-based)

**Authentication:** password in URI, or key via `SSH_KEY_PATH` / `SSH_KEY` env var. Set `SSH_INSECURE=true` to skip host key verification.

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
| `packages` | Installed packages |
| `packages_cve` | Packages cross-referenced with CVE database |
| `logs` | System logs |
| `kubelet_config` | Kubelet configuration (Kubernetes nodes) |
| `k8s_master_config` | Kubernetes master configuration |

**Examples:**

```bash
# Quick CIS scan (key-based auth)
kxn ssh://root@10.0.0.1

# Password auth
kxn ssh://admin:mypassword@10.0.0.1

# Gather installed packages
kxn gather -p ssh -t packages -C '{"SSH_HOST":"10.0.0.1","SSH_USER":"root","SSH_KEY_PATH":"/root/.ssh/id_rsa"}'

# Gather system stats
kxn gather -p ssh -t system_stats -C '{"SSH_HOST":"10.0.0.1","SSH_USER":"root","SSH_INSECURE":"true"}'

# CVE scan on installed packages
kxn cve-update && kxn ssh://root@10.0.0.1 --rules rules/cve-monitoring.toml
```

### docker

Connects to the Docker daemon via Unix socket to monitor containers, images, and daemon configuration. Runs locally — no SSH required.

**URI scheme:** `docker://`

**Configuration:**

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Path to the Docker Unix socket |

**Resource types:**

| Type | Description |
|------|-------------|
| `docker_containers` | All containers with state, runtime config, and Compose labels |
| `docker_config` | Daemon configuration from `/etc/docker/daemon.json` |
| `docker_host` | Socket permissions, TLS config, audit rules |
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
kxn scan --provider docker --rules rules/docker-cis.toml
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
    command: watch --config /etc/kxn/kxn.toml
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
uri = "docker://"
interval = 60

[[alerts]]
type = "discord"
webhook = "${secret:env:DISCORD_WEBHOOK}"
min_level = 3
```

**Step 4 — start:**

```bash
echo "DISCORD_WEBHOOK=https://discord.com/api/webhooks/..." > .env
docker compose up -d
```

kxn scans all containers every 60 seconds. If `web`, `api`, or `db` stops, a Discord alert fires. `kxn-monitor` itself is excluded because its workdir label matches the compose project directory (`/opt/myapp`), so it would also trigger an alert if it crashed — but `restart: unless-stopped` keeps it alive.

### postgresql

Connects to PostgreSQL databases for compliance scanning.

**URI scheme:** `postgresql://user:password@host:port/dbname` or `postgres://...`

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

# Full CIS PostgreSQL benchmark
kxn scan --provider postgresql --provider-config '{"uri":"postgresql://admin:pass@db.internal/prod"}' --rules rules/postgresql-cis.toml
```

### mysql

Connects to MySQL/MariaDB databases.

**URI scheme:** `mysql://user:password@host:port/dbname`

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

Connects to Kubernetes clusters via kubeconfig (out-of-cluster) or the ServiceAccount token at `/var/run/secrets/kubernetes.io/serviceaccount/token` (in-cluster). In-cluster mode is auto-detected via `KUBERNETES_SERVICE_HOST`. Set `K8S_INSECURE=true` to skip TLS verification when the cluster CA is not in the trust store.

**Log collection:** `kxn logs kubernetes://in-cluster` polls pod logs (`tailLines=100&timestamps=true`, max 50 pods per cycle) and forwards error/warn/fatal/panic/exception lines through the standard log pipeline (filter, metrics, save) — no separate agent (fluent-bit, promtail) required. Works alongside `kxn watch kubernetes://...` for scans + metrics.

**Resource types (68):**

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
| `node_metrics` | Node-level metrics (metrics-server) |
| `pod_metrics` | Pod-level metrics (metrics-server) |
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
| `pod_resource` | Flat per-(namespace, pod, container) view of metrics-server data |
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
| `pod_restarts` | Per-container restart counts and last-termination reason |
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
# Scan with local kubeconfig (current context)
kxn kubernetes://my-cluster

# Gather pods across all namespaces
kxn gather -p kubernetes -t pods

# Gather node metrics
kxn gather -p kubernetes -t node_metrics

# In-cluster (running inside a pod with a ServiceAccount)
K8S_INSECURE=true kxn kubernetes://in-cluster

# Run as a pod inside the cluster — see deploy/kubernetes/ for a full manifest
# with RBAC, Discord alerts, and pod health rules
```

### github

Connects to GitHub organizations and repositories.

**Authentication:** set `GITHUB_TOKEN` env var (personal access token or GitHub App token with `read:org`, `repo`, `security_events` scopes).

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
# Scan an organization (token from env)
export GITHUB_TOKEN=ghp_xxx
kxn github://my-org

# Gather Dependabot alerts
kxn gather -p github -t dependabot_alerts -C '{"GITHUB_ORG":"my-org"}'

# Gather all repos with branch protection status
kxn gather -p github -t repositories -C '{"GITHUB_ORG":"my-org"}'

# Full security scan
kxn github://my-org --rules rules/github-security.toml
```

### http

Probes HTTP/HTTPS endpoints.

**URI scheme:** `http://host` or `https://host`

**Resource types:**

| Type | Description |
|------|-------------|
| `request` | HTTP probe returning status, headers, TLS info, certificate details, and timing |

**Examples:**

```bash
# OWASP / TLS scan
kxn https://example.com

# Gather raw probe data (status, headers, cert expiry)
kxn gather -p http -t request -C '{"url":"https://api.example.com"}'

# Monitor multiple endpoints with alerts
kxn https://example.com --rules rules/http-monitoring.toml
```

### grpc

Probes gRPC services.

**URI scheme:** `grpc://host:port`

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
kxn gather -p grpc -t reflection -C '{"host":"my-service","port":"9090"}'
```

### cve

Queries the local CVE database (synced via `kxn cve-update`). Zero network calls during scans — everything runs from a local SQLite database.

**URI scheme:** `cve://`

**Resource types:**

| Type | Description |
|------|-------------|
| `nvd_cves` | NVD CVE entries |
| `kev` | CISA Known Exploited Vulnerabilities |
| `epss` | Exploit Prediction Scoring System scores |

**Examples:**

```bash
# Sync the CVE database (NVD + CISA KEV + EPSS)
kxn cve-update

# Detect CVEs in packages installed on a server
kxn ssh://root@10.0.0.1 --rules rules/cve-monitoring.toml

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

### gcp

Native GCP provider, distinct from the Terraform `google` provider bridge below. Currently scoped to one thing: auditing service account key age so long-lived, un-rotated keys show up as violations.

**URI scheme:** `gcp://project-id`

**Resource types:**

| Type | Description |
|------|-------------|
| `service_account_keys` | Service account keys with their age; flags keys older than the configurable max-age threshold (default 90 days) |

### microsoft.graph

Native Microsoft Graph provider for Entra ID (Azure AD), distinct from any Terraform `azuread` usage. Currently scoped to service principal / app registration auditing.

**URI scheme:** `microsoft.graph://tenant-id`

**Resource types:**

| Type | Description |
|------|-------------|
| `service_principals` | App registrations / service principals, their credentials and permissions |

### forgejo

Audits Forgejo (and Gitea) Actions CI/CD pipeline history — runs, individual jobs, and their logs — so pipeline health and failures are scannable like any other resource.

**URI scheme:** `forgejo://host`

**Resource types:**

| Type | Description |
|------|-------------|
| `pipeline_runs` | One row per workflow run, with status/conclusion |
| `pipeline_jobs` | Individual jobs within a run |
| `pipeline_logs` | Job log output |

### prometheus

Scrapes any HTTP endpoint serving the [Prometheus text exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/) (Traefik, node-exporter, blackbox-exporter, an app's own `/metrics`) and turns each `name{labels} value` line into a kxn metric record — no PromQL query engine, just a scraper.

**URI scheme:** `prometheus://host` (or point `config.URL` directly at the metrics endpoint)

**Config:** `URL` (required), `BEARER_TOKEN` (optional), `INSECURE` (skip TLS verification), `INCLUDE_PREFIXES`/`EXCLUDE_PREFIXES` (comma-separated metric name filters — exclude is handy for dropping `go_*`/`process_*` runtime noise).

**Resource types:**

| Type | Description |
|------|-------------|
| `prometheus_metrics` | Every scraped metric line as one record |

### local

Runs the same checks as the `ssh` provider (sshd_config, sysctl, users, services, file permissions, OS info, packages) but against the machine kxn itself is running on, over a local shell instead of an SSH connection. Useful for a host-level scan without needing SSH access to itself, or as an in-container/in-pod self-check.

**URI scheme:** `local://`

**Resource types:** `sshd_config`, `sysctl`, `users`, `services`, `file_permissions`, `os_info`, `packages` (same parsers as `ssh`, run locally).

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

| Scheme | Provider |
|--------|----------|
| `docker://` | docker |
| `ssh://` | ssh |
| `postgresql://` | postgresql |
| `postgres://` | postgresql |
| `mysql://` | mysql |
| `mongodb://` | mongodb |
| `mongodb+srv://` | mongodb |
| `oracle://` | oracle |
| `http://` | http |
| `https://` | http |
| `grpc://` | grpc |
| `cve://` | cve |

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
# SSH system packages
kxn gather -p ssh -t packages -C '{"host":"10.0.0.1","user":"admin"}'

# PostgreSQL roles
kxn gather -p postgresql -t roles -C '{"uri":"postgresql://user:pass@localhost/mydb"}'

# HTTP endpoint probe
kxn gather -p http -t request -C '{"url":"https://example.com"}'

# CVE database query
kxn gather -p cve -t kev
```
