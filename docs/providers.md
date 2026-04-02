# kxn Providers

kxn supports 9 native providers and 3000+ Terraform providers via gRPC bridge.

## Native Providers

### ssh

Connects via SSH to gather system configuration and state.

**URI scheme:** `ssh://user:password@host:port` or `ssh://user@host` (key-based)

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

### kubernetes

Connects to Kubernetes clusters via kubeconfig.

**Resource types (26):**

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
| `node_metrics` | Node-level metrics |
| `pod_metrics` | Pod-level metrics |
| `pod_logs` | Pod log output |

### github

Connects to GitHub organizations and repositories.

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

### http

Probes HTTP/HTTPS endpoints.

**URI scheme:** `http://host` or `https://host`

**Resource types:**

| Type | Description |
|------|-------------|
| `request` | HTTP probe returning status, headers, TLS info, certificate details, and timing |

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

### cve

Queries the local CVE database (synced via `kxn cve-update`).

**URI scheme:** `cve://`

**Resource types:**

| Type | Description |
|------|-------------|
| `nvd_cves` | NVD CVE entries |
| `kev` | CISA Known Exploited Vulnerabilities |
| `epss` | Exploit Prediction Scoring System scores |

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
