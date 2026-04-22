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
