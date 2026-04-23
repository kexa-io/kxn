# Alerting and Saving

kxn can send alerts when violations are detected and persist scan results to storage backends. Both can be configured via `kxn.toml` or CLI flags.

## Alert backends (14)

Alerts are sent when a scan produces violations. Use `--alert` (repeatable) to specify destinations.

```bash
kxn scan ssh://root@host --alert slack://hooks.slack.com/services/T00/B00/xxx
kxn scan ssh://root@host --alert slack://... --alert discord://...
```

### Supported alert URIs

| Backend | URI format | Protocol |
|---------|-----------|----------|
| **Slack** | `slack://hooks.slack.com/services/T00/B00/xxx` | Block Kit via webhook |
| **Discord** | `discord://discord.com/api/webhooks/ID/TOKEN` | Discord webhook |
| **Teams** | `teams://outlook.webhook.office.com/...` | Adaptive Cards via webhook |
| **Email** | `email://user:pass@smtp.host:587/to@mail.com` | SMTP |
| **SMS** | `sms://sid:token@twilio/+1234567890` | Twilio API |
| **Jira** | `jira://user:token@company.atlassian.net/PROJECT` | Jira REST API (creates issues) |
| **PagerDuty** | `pagerduty://routing-key` | Events API v2 |
| **OpsGenie** | `opsgenie://api-key` | OpsGenie Alert API |
| **ServiceNow** | `servicenow://user:pass@instance.service-now.com` | REST API (creates incidents) |
| **Linear** | `linear://api-key/TEAM` | Linear GraphQL API |
| **Splunk On-Call** | `splunk://routing-key` | VictorOps/Splunk On-Call |
| **Zendesk** | `zendesk://user:token@subdomain.zendesk.com` | Zendesk REST API (creates tickets) |
| **Kafka** | `kafka://broker:8082/topic` | Kafka REST Proxy |
| **Generic webhook** | `https://custom.example.com/hook` | HTTP POST with JSON payload |

### Alert payload

All alert backends receive a structured payload containing:

- **Target name** -- which target was scanned
- **Violation list** -- rule name, description, severity level, affected resource, failure messages
- **Timestamp** -- when the scan ran

Platform-specific backends format this data natively:
- Slack uses Block Kit blocks
- Teams uses Adaptive Cards
- Jira/Linear/ServiceNow/Zendesk create issues/tickets with structured fields
- Generic webhooks receive a JSON object

### Example: multiple alert destinations

```bash
kxn scan ssh://root@prod-server \
  --alert slack://hooks.slack.com/services/T00/B00/xxx \
  --alert pagerduty://your-routing-key \
  --alert jira://bot:token@company.atlassian.net/SEC
```

## Save backends (17)

Save backends persist full scan results and time-series metrics. Use `--save` (repeatable) on the CLI or `[[save]]` blocks in `kxn.toml`.

```bash
kxn scan ssh://root@host --save postgresql://user:pass@db:5432/kxn
kxn scan ssh://root@host --save postgresql://... --save file:///tmp/results.jsonl
kxn scan ssh://root@host --save loki://loki.monitoring.svc:3100
```

### Supported save URIs

| Backend | URI format | Description |
|---------|-----------|-------------|
| **PostgreSQL** | `postgresql://user:pass@host:5432/db` | Relational, ideal for Grafana dashboards |
| **MySQL** | `mysql://user:pass@host:3306/db` | Relational storage |
| **MongoDB** | `mongodb://user:pass@host:27017/db` | Document store |
| **Elasticsearch** | `elasticsearch://host:9200/index` | Full-text search and analytics |
| **OpenSearch** | `opensearch://host:9200/index` | Elasticsearch-compatible |
| **S3** | `s3://bucket/prefix` | AWS object storage (JSON files) |
| **GCS** | `gs://bucket/prefix` | Google Cloud Storage |
| **Azure Blob** | `az://container/prefix` | Azure Blob Storage |
| **Kafka** | `kafka://broker:8082/topic` | Event streaming via REST Proxy |
| **Event Hubs** | `eventhubs://namespace.servicebus.windows.net/hub` | Azure Event Hubs |
| **SNS** | `sns://arn:aws:sns:region:account:topic` | AWS Simple Notification Service |
| **Pub/Sub** | `pubsub://project/topic` | Google Cloud Pub/Sub |
| **Redis** | `redis://host:6379/channel` | Redis Pub/Sub channel |
| **Splunk HEC** | `splunkhec://host:8088/index` | Splunk HTTP Event Collector (token via `SPLUNK_HEC_TOKEN` env var) |
| **InfluxDB** | `influxdb://host:8086/bucket` | Time-series database |
| **Grafana Loki** | `loki://host:3100` (`loki+https://` for TLS) | Loki push API. Emits three streams labelled `{app="kxn", kind="scan|metric|log", origin=...}`. Optional auth via `LOKI_USER`/`LOKI_PASSWORD` (Basic), `LOKI_TOKEN` (Bearer / Grafana Cloud), or `LOKI_TENANT` (`X-Scope-OrgID`) env vars. |
| **File** | `file:///path/to/results.jsonl` | Local JSON Lines file |

### `[[save]]` in kxn.toml

For daemon mode (`kxn watch`), configure save backends in the config file:

```toml
[[save]]
type = "postgres"
url = "postgresql://user:pass@host:5432/kxn"
origin = "kxn-daemon"
only_errors = false
[save.tags]
environment = "production"
team = "platform"

[[save]]
type = "mongodb"
url = "mongodb://user:pass@host:27017/kxn"
origin = "kxn-daemon"
only_errors = true
[save.tags]
environment = "production"

[[save]]
type = "loki"
url = "loki://loki.monitoring.svc:3100"
origin = "kxn-daemon"
compression = "gzip"                           # HTTP backends only
```

| Field         | Type   | Required | Default   | Description                                  |
|---------------|--------|----------|-----------|----------------------------------------------|
| `type`        | string | yes      |           | Backend identifier (see table above)         |
| `url`         | string | yes      |           | Connection URI                               |
| `origin`      | string | no       | `"kxn"`   | Label identifying the scan source            |
| `only_errors` | bool   | no       | `false`   | Only persist failing results (violations)    |
| `compression` | string | no       | none      | HTTP body compression for `elasticsearch`, `splunk-hec`, `loki`. `"gzip"` / `"gz"` supported (case-insensitive). `"none"` / `""` / `"off"` / unknown algorithms pass through uncompressed with a warning. |
| `[save.tags]` | table  | no       | `{}`      | Arbitrary key-value metadata attached to every record |

### What gets saved

Each save backend receives two types of data:

**Scan records** -- one per rule evaluation:
- Target, provider, rule name, description, severity level
- Object type and content (JSON)
- Pass/fail status and failure messages
- Compliance references (CIS, OWASP, etc.)
- Batch ID, timestamp, and tags

**Metric records** -- flattened numeric values from gathered resources (for time-series backends like InfluxDB, Loki, Grafana via PostgreSQL, etc.):
- Target, provider, resource type
- Metric name, numeric value, string value
- Timestamp

Metric extraction is automatic for resource types that produce useful time-series data: `system_stats`, `os_info`, `pg_settings`, `mysql_variables`, `http_response`, `db_stats`, `cluster_stats`, `node_metrics`, `pod_metrics`.

**Log records** -- one record per collected log line (produced by `kxn logs`):
- Target, source, level, message, host, unit, timestamp
- Supported by: `postgres`, `elasticsearch`, `file` / `jsonl`, `kafka`, `splunk-hec`, `loki`. Other backends skip logs silently.

## Secret interpolation in URIs

Both alert and save URIs support `${...}` secret interpolation:

```toml
[[save]]
type = "postgres"
url = "postgresql://${secret:gcp:my-project/db-user}:${secret:gcp:my-project/db-pass}@host:5432/kxn"
```

Supported secret backends:

| Syntax | Backend |
|--------|---------|
| `${VAR_NAME}` | Environment variable |
| `${secret:gcp:project/name}` | GCP Secret Manager |
| `${secret:aws:name/key}` | AWS Secrets Manager |
| `${secret:azure:vault/name}` | Azure Key Vault |
| `${secret:vault:path/key}` | HashiCorp Vault |

See [Configuration](configuration.md) for full details on secret interpolation.

## CLI vs config file

| Feature | CLI flag | Config file |
|---------|----------|-------------|
| Alert destination | `--alert URI` (repeatable) | Not yet in `kxn.toml` |
| Save destination | `--save URI` (repeatable) | `[[save]]` blocks |
| Tags | Not available via CLI | `[save.tags]` table |
| `only_errors` filter | Not available via CLI | `only_errors = true` |
| Origin label | Not available via CLI | `origin = "..."` |

For one-shot scans, use `--alert` and `--save` flags. For daemon mode (`kxn watch`), configure `[[save]]` blocks in `kxn.toml` -- targets are scanned on their configured interval, and results are automatically saved to all configured backends.

## Error handling

Alert and save failures are non-fatal. If a backend is unreachable or returns an error, kxn logs the error to stderr and continues with the remaining backends. This ensures a single backend outage does not block scan results from reaching other destinations.

---

## End-to-end example: PostgreSQL monitoring → Grafana

This example sets up continuous compliance monitoring for a PostgreSQL database, saves results to Grafana Loki for log-based dashboards, and sends Discord alerts on violations.

### What you get

- CIS PostgreSQL benchmark scanned every 60 seconds
- All scan results and DB metrics streamed to Loki as structured JSON
- Discord alert when a violation is detected (level ≥ 2)
- Grafana dashboard showing compliance trend and metric history

### Step 1 — create a read-only monitoring user in PostgreSQL

```sql
CREATE USER kxn_monitor WITH PASSWORD 'change-me';
GRANT pg_monitor TO kxn_monitor;
GRANT CONNECT ON DATABASE myapp TO kxn_monitor;
```

### Step 2 — write kxn.toml

```toml
# kxn.toml
[rules]
mandatory = [
  { name = "postgresql-cis", path = "${rules_dir}/postgresql-cis.toml" },
]

[[targets]]
name = "prod-db"
provider = "postgresql"
uri = "postgresql://kxn_monitor:${secret:env:DB_PASSWORD}@db.internal:5432/myapp"
interval = 60

[[alerts]]
type = "discord"
webhook = "${secret:env:DISCORD_WEBHOOK}"
min_level = 2

[[save]]
type = "loki"
url = "loki://loki.monitoring.svc:3100"
origin = "kxn-prod"
compression = "gzip"
[save.tags]
environment = "production"
target = "prod-db"
```

### Step 3 — run with Docker Compose

```yaml
# docker-compose.yml
services:
  kxn-monitor:
    image: kexa/kxn:latest
    restart: unless-stopped
    volumes:
      - ./kxn.toml:/etc/kxn/kxn.toml:ro
    environment:
      - DB_PASSWORD=${DB_PASSWORD}
      - DISCORD_WEBHOOK=${DISCORD_WEBHOOK}
    command: watch --config /etc/kxn/kxn.toml
```

```bash
# .env
DB_PASSWORD=change-me
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
```

```bash
docker compose up -d
```

### Step 4 — query in Grafana

kxn pushes three Loki streams per target:

| Stream label | Content |
|---|---|
| `{app="kxn", kind="scan", origin="kxn-prod"}` | One JSON line per rule result (pass or fail) |
| `{app="kxn", kind="metric", origin="kxn-prod"}` | Numeric metrics extracted from DB stats |
| `{app="kxn", kind="log", origin="kxn-prod"}` | Collected log lines (if `kxn logs` is configured) |

**Violations over time** (LogQL):

```logql
{app="kxn", kind="scan", origin="kxn-prod"}
  | json
  | passed = "false"
  | line_format "{{.rule_name}} — {{.level}} — {{.target}}"
```

**Connection count metric** (LogQL → time series):

```logql
{app="kxn", kind="metric", origin="kxn-prod"}
  | json
  | metric_name = "connections_total"
  | unwrap metric_value
  | __error__ = ""
```

**Compliance rate** (percentage of passing rules per scan):

```logql
sum(count_over_time({app="kxn", kind="scan", origin="kxn-prod"} | json | passed="true" [1m]))
/
sum(count_over_time({app="kxn", kind="scan", origin="kxn-prod"} | json [1m]))
* 100
```

### Optional: also save to PostgreSQL for SQL dashboards

If your Grafana already uses a PostgreSQL datasource, you can save kxn results to a dedicated table and build dashboards with standard SQL queries:

```toml
# append to kxn.toml
[[save]]
type = "postgres"
url = "postgresql://kxn:${secret:env:KXN_DB_PASSWORD}@metrics-db:5432/kxn"
origin = "kxn-prod"
[save.tags]
environment = "production"
```

kxn auto-creates the `kxn_scans` and `kxn_metrics` tables on first run. Sample Grafana SQL:

```sql
-- Violations per hour
SELECT
  date_trunc('hour', created_at) AS time,
  count(*) FILTER (WHERE passed = false) AS violations,
  count(*) AS total
FROM kxn_scans
WHERE target = 'prod-db'
  AND created_at > now() - interval '24h'
GROUP BY 1
ORDER BY 1;
```

---

## End-to-end example: AWS monitoring → Grafana

Continuous CIS AWS benchmark scan using the Terraform `hashicorp/aws` provider, with results saved to Loki and violations sent to Discord.

### Step 1 — IAM permissions

Create a read-only IAM user or role. Minimum required policies:
- `ReadOnlyAccess` (AWS managed policy) — covers EC2, S3, IAM, RDS, VPC, CloudTrail, etc.

```bash
# Option A: IAM user credentials
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=eu-west-1

# Option B: IAM role (EC2, ECS, Lambda — no credentials needed)
# kxn uses the instance metadata service automatically
```

### Step 2 — kxn.toml

```toml
# kxn.toml
[rules]
mandatory = [
  { name = "aws-cis",     path = "${rules_dir}/aws-cis.toml" },
  { name = "aws-iam-cis", path = "${rules_dir}/aws-iam-cis.toml" },
]

[[targets]]
name = "aws-prod"
provider = "hashicorp/aws"
rules = ["aws-cis", "aws-iam-cis"]
interval = 3600
[targets.config]
region = "eu-west-1"

[[alerts]]
type = "discord"
webhook = "${secret:env:DISCORD_WEBHOOK}"
min_level = 2

[[save]]
type = "loki"
url = "loki://loki.monitoring.svc:3100"
origin = "kxn-aws-prod"
compression = "gzip"
[save.tags]
environment = "production"
cloud = "aws"
region = "eu-west-1"
```

### Step 3 — Docker Compose

```yaml
# docker-compose.yml
services:
  kxn-monitor:
    image: kexa/kxn:latest
    restart: unless-stopped
    volumes:
      - ./kxn.toml:/etc/kxn/kxn.toml:ro
    environment:
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - AWS_DEFAULT_REGION=eu-west-1
      - DISCORD_WEBHOOK=${DISCORD_WEBHOOK}
    command: watch --config /etc/kxn/kxn.toml
```

### Step 4 — Grafana (LogQL)

```logql
# CIS violations on AWS
{app="kxn", kind="scan", origin="kxn-aws-prod"}
  | json
  | passed = "false"
  | line_format "{{.rule_name}} — level {{.level}} — {{.object_type}}"
```

```logql
# Compliance rate per hour
sum(count_over_time({app="kxn", kind="scan", origin="kxn-aws-prod"} | json | passed="true" [1h]))
/
sum(count_over_time({app="kxn", kind="scan", origin="kxn-aws-prod"} | json [1h]))
* 100
```

---

## End-to-end example: Azure monitoring → Grafana

CIS Azure benchmark scan using `hashicorp/azurerm` + `hashicorp/azuread`.

### Step 1 — Service principal

```bash
# Create a service principal with Reader role
az ad sp create-for-rbac --name kxn-monitor --role Reader \
  --scopes /subscriptions/<subscription-id>

# Output: appId, password, tenant
export AZURE_TENANT_ID=<tenant>
export AZURE_CLIENT_ID=<appId>
export AZURE_CLIENT_SECRET=<password>
export AZURE_SUBSCRIPTION_ID=<subscription-id>
```

For Azure AD resources, also grant the service principal `Directory.Read.All` in Microsoft Graph.

### Step 2 — kxn.toml

```toml
# kxn.toml
[rules]
mandatory = [
  { name = "azure-cis",     path = "${rules_dir}/azure-cis.toml" },
  { name = "azure-iam-cis", path = "${rules_dir}/azure-iam-cis.toml" },
]

[[targets]]
name = "azure-prod"
provider = "hashicorp/azurerm"
rules = ["azure-cis"]
interval = 3600
[targets.config]
subscription_id = "${secret:env:AZURE_SUBSCRIPTION_ID}"

[[targets]]
name = "azure-ad"
provider = "hashicorp/azuread"
rules = ["azure-iam-cis"]
interval = 3600

[[alerts]]
type = "discord"
webhook = "${secret:env:DISCORD_WEBHOOK}"
min_level = 2

[[save]]
type = "loki"
url = "loki://loki.monitoring.svc:3100"
origin = "kxn-azure-prod"
compression = "gzip"
[save.tags]
environment = "production"
cloud = "azure"
```

### Step 3 — Docker Compose

```yaml
# docker-compose.yml
services:
  kxn-monitor:
    image: kexa/kxn:latest
    restart: unless-stopped
    volumes:
      - ./kxn.toml:/etc/kxn/kxn.toml:ro
    environment:
      - AZURE_TENANT_ID=${AZURE_TENANT_ID}
      - AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
      - AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}
      - AZURE_SUBSCRIPTION_ID=${AZURE_SUBSCRIPTION_ID}
      - DISCORD_WEBHOOK=${DISCORD_WEBHOOK}
    command: watch --config /etc/kxn/kxn.toml
```

### Step 4 — Grafana (LogQL)

```logql
# Azure CIS violations
{app="kxn", kind="scan", origin="kxn-azure-prod"}
  | json
  | passed = "false"
  | line_format "{{.rule_name}} — {{.level}} — {{.target}}"
```

---

## End-to-end example: GCP monitoring → Grafana

CIS Google Cloud benchmark scan using `hashicorp/google`.

### Step 1 — Service account

```bash
# Create a service account
gcloud iam service-accounts create kxn-monitor \
  --display-name "kxn compliance monitor"

# Grant Viewer role (read-only access to all resources)
gcloud projects add-iam-policy-binding my-project \
  --member "serviceAccount:kxn-monitor@my-project.iam.gserviceaccount.com" \
  --role "roles/viewer"

# Export credentials
gcloud iam service-accounts keys create kxn-sa.json \
  --iam-account kxn-monitor@my-project.iam.gserviceaccount.com

export GOOGLE_APPLICATION_CREDENTIALS=/path/to/kxn-sa.json
```

On GCE / Cloud Run, use Workload Identity instead — no key file needed.

### Step 2 — kxn.toml

```toml
# kxn.toml
[rules]
mandatory = [
  { name = "gcp-cis",     path = "${rules_dir}/gcp-cis.toml" },
  { name = "gcp-iam-cis", path = "${rules_dir}/gcp-iam-cis.toml" },
]

[[targets]]
name = "gcp-prod"
provider = "hashicorp/google"
rules = ["gcp-cis", "gcp-iam-cis"]
interval = 3600
[targets.config]
project = "my-project"
region  = "europe-west1"

[[alerts]]
type = "discord"
webhook = "${secret:env:DISCORD_WEBHOOK}"
min_level = 2

[[save]]
type = "loki"
url = "loki://loki.monitoring.svc:3100"
origin = "kxn-gcp-prod"
compression = "gzip"
[save.tags]
environment = "production"
cloud = "gcp"
project = "my-project"
```

### Step 3 — Docker Compose

```yaml
# docker-compose.yml
services:
  kxn-monitor:
    image: kexa/kxn:latest
    restart: unless-stopped
    volumes:
      - ./kxn.toml:/etc/kxn/kxn.toml:ro
      - ./kxn-sa.json:/etc/kxn/sa.json:ro
    environment:
      - GOOGLE_APPLICATION_CREDENTIALS=/etc/kxn/sa.json
      - DISCORD_WEBHOOK=${DISCORD_WEBHOOK}
    command: watch --config /etc/kxn/kxn.toml
```

### Step 4 — Grafana (LogQL)

```logql
# GCP CIS violations
{app="kxn", kind="scan", origin="kxn-gcp-prod"}
  | json
  | passed = "false"
  | line_format "{{.rule_name}} — level {{.level}} — {{.object_type}}"
```

```logql
# Multi-cloud compliance comparison (all origins)
sum by (origin) (
  count_over_time({app="kxn", kind="scan"} | json | passed="false" [1h])
)
```
