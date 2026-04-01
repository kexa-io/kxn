# kxn

Multi-cloud compliance scanner in Rust. Single binary, no runtime, URI-driven.

Successor to [Kexa](https://github.com/kexa-io/Kexa) (TypeScript).

## Why kxn

One binary. One URI. Full compliance scan.

```bash
kxn postgresql://user:pass@host:5432
```

No config files. No runtime. No server. Just point and scan.

## Modes

```bash
# One-shot scan (cron-friendly, exit code 1 on violations)
kxn ssh://root@server --compliance

# Continuous monitoring daemon
kxn monitor mysql://user:pass@host --alert slack://hooks.slack.com/T/B/x

# MCP server for Claude Desktop / Claude Code
kxn serve --mcp

# Webhook server for reactive compliance
kxn serve --webhook --port 8080 --save kafka://broker:8082/compliance
```

## Reactive Compliance (killer feature)

No competitor does this. kxn receives cloud events in real-time and scans resources as they are created or modified.

```
+------------------+     +------------------+     +------------------+
| Azure Event Grid |     | AWS EventBridge  |     | CloudEvents      |
+--------+---------+     +--------+---------+     +--------+---------+
         |                        |                        |
         +------------------------+------------------------+
                                  |
                                  v
                    +----------------------------+
                    | kxn serve --webhook :8080  |
                    |                            |
                    |  POST /event  (auto-scan)  |
                    |  POST /scan   (check JSON) |
                    |  POST /ingest (fan-in)     |
                    |  GET  /health              |
                    +----------------------------+
                                  |
              +-------------------+-------------------+
              |                   |                   |
              v                   v                   v
       +-----------+       +-----------+       +-----------+
       |  14 alert |       |  16 save  |       |  736+     |
       |  backends |       |  backends |       |  rules    |
       +-----------+       +-----------+       +-----------+
```

### Full pipeline example with Azure

```
Azure Resource Group                    kxn (webhook)                    Downstream
=====================                   =============                    ==========

 Developer creates    Event Grid         POST /event
 an Azure VM     ---> subscription --->  receive event
                                         detect: azurerm provider
                                         gather: VM config via Terraform gRPC
                                         scan: CIS Azure + IAM rules
                                              |
                                              |---> alert: pagerduty://routing-key
                                              |---> alert: slack://hooks.slack.com/T/B/x
                                              |---> alert: jira://u:t@co.atlassian.net/SEC
                                              |
                                              |---> save: kafka://broker:8082/compliance
                                              |---> save: elasticsearch://es:9200/kxn
                                              |---> save: influxdb://grafana:8086/metrics
                                              |
                                              v
                                         Kafka consumer ---> Jira ticket
                                         Grafana        ---> dashboard
                                         SIEM           ---> correlation
```

### Distributed fan-in architecture

```
+-------------------+
| kxn (ssh scan)    |---+
+-------------------+   |     +----------------------------+
                        +---> |                            |     +--> kafka://
+-------------------+   |     | kxn serve --webhook :8080  |---> +--> elasticsearch://
| kxn (pg scan)     |---+---> |                            |     +--> influxdb://
+-------------------+   |     | POST /ingest (aggregation) |     +--> pagerduty://
                        +---> |                            |     +--> jira://
+-------------------+   |     +----------------------------+
| kxn (aws scan)    |---+
+-------------------+   |
                        |
+-------------------+   |
| Azure Event Grid  |---+  (POST /event)
+-------------------+
```

## Providers

| Provider | URI Scheme | Resources |
|----------|-----------|-----------|
| SSH | `ssh://` | sshd_config, sysctl, users, services, system_stats, logs |
| PostgreSQL | `postgresql://` | databases, roles, settings, extensions, db_stats |
| MySQL | `mysql://` | databases, users, grants, variables, status, db_stats |
| MongoDB | `mongodb://` | databases, users, serverStatus, currentOp, db_stats |
| Oracle | `oracle://` | users, tables, privileges, sessions, parameters |
| Kubernetes | `k8s://` | 26 types: pods, deployments, RBAC, network policies, metrics |
| GitHub | `github://` | organization, repos, webhooks, Dependabot, actions, CODEOWNERS |
| HTTP | `http://` | status, headers, TLS, certificate, timing |
| gRPC | `grpc://` | health_check, connection, reflection, service_health |
| Cloud Run | native | services, revisions, jobs |
| Azure WebApp | native | webapps, app_service_plans |
| Grafana | native | dashboards, datasources, alerts |
| **Terraform** | any | **3000+ providers** via gRPC bridge (AWS, GCP, Azure, Cloudflare, Vault...) |

## Alert Backends (14)

| URI | Service |
|-----|---------|
| `slack://hooks.slack.com/...` | Slack (Block Kit) |
| `discord://discord.com/...` | Discord (Embeds) |
| `teams://outlook.webhook.office.com/...` | Microsoft Teams |
| `email://user:pass@smtp:587/to@mail.com` | SMTP Email |
| `sms://sid:token@twilio/+1234567890` | Twilio SMS |
| `jira://user:token@co.atlassian.net/PROJECT` | Jira Cloud |
| `pagerduty://routing-key` | PagerDuty |
| `opsgenie://api-key` | Opsgenie |
| `servicenow://user:pass@instance.service-now.com` | ServiceNow |
| `linear://api-key/TEAM` | Linear |
| `splunk://routing-key` | Splunk On-Call |
| `zendesk://user:token@subdomain.zendesk.com` | Zendesk |
| `kafka://broker:8082/topic` | Kafka (event) |
| `https://custom.example.com/hook` | Generic webhook |

## Save Backends (16)

| Type | URI | Backend |
|------|-----|---------|
| Database | `postgresql://` | PostgreSQL |
| Database | `mysql://` | MySQL |
| Database | `mongodb://` | MongoDB |
| Search | `elasticsearch://` | Elasticsearch |
| Search | `opensearch://` | OpenSearch |
| Cloud | `s3://` | AWS S3 |
| Cloud | `gs://` | Google Cloud Storage |
| Cloud | `az://` | Azure Blob Storage |
| Event | `kafka://` | Kafka REST Proxy |
| Event | `eventhubs://` | Azure Event Hubs |
| Event | `sns://` | AWS SNS |
| Event | `pubsub://` | Google Cloud Pub/Sub |
| Event | `redis://` | Redis Pub/Sub |
| Monitor | `splunkhec://` | Splunk HEC |
| Monitor | `influxdb://` | InfluxDB v2 |
| Local | `file://` | JSONL file |

## Flags

| Flag | Description |
|------|-------------|
| `--compliance` | Include CIS, SOC-2, PCI-DSS compliance rules |
| `--alert <URI>` | Send violations to any alert backend (repeatable) |
| `--save <URI>` | Persist results to any save backend (repeatable) |
| `--rules <DIR>` | Custom rules directory (default: `./rules`) |
| `--min-level <N>` | Minimum severity: 0=info, 1=warning, 2=error, 3=fatal |
| `--output <FMT>` | Output format: text, json |
| `--verbose` | Show detailed violation output |

## MCP Server

```bash
kxn serve --mcp
```

8 tools for any MCP-compatible AI client:

| Tool | Description |
|------|-------------|
| `kxn_list_providers` | List native + Terraform providers |
| `kxn_list_resource_types` | Discover resource types for a provider |
| `kxn_list_rules` | Browse 736+ compliance rules |
| `kxn_provider_schema` | Discover Terraform provider schemas |
| `kxn_gather` | Collect resources from a target |
| `kxn_scan` | Full compliance scan of a configured target |
| `kxn_check_resource` | Check any JSON against conditions (zero infra) |
| `kxn_remediate` | Scan + auto-fix violations (2-step: list then apply selected) |

### Auto-Remediation

`kxn_remediate` works in two steps — never applies fixes without explicit selection:

```
1. kxn_remediate(target: "ssh-vm")
   → Lists all violations with available remediations

2. kxn_remediate(target: "ssh-vm", rules: ["ssh-cis-5.2.10-no-root-login"])
   → Applies ONLY the selected fixes
```

Supports SQL remediation (PostgreSQL ALTER SYSTEM, MySQL SET GLOBAL) and shell remediation (sshd_config, sysctl, chmod). Shell commands are batched — one service restart at the end instead of one per rule.

### Multi-Client Setup

```bash
# Configure all detected AI clients
kxn init --mcp-only

# Configure a specific client
kxn init --mcp-only --client gemini
kxn init --mcp-only --client cursor
kxn init --mcp-only --client codex
```

Supported clients: **Claude Desktop**, **Claude Code**, **Gemini CLI**, **Cursor**, **Windsurf**, **OpenCode**, **Codex**.

## Rules

736+ TOML rules covering CIS benchmarks, OWASP API Top 10, IAM, TLS, monitoring.

```toml
[metadata]
version = "1.0.0"
provider = "ssh"

[[rules]]
name = "ssh-cis-5.2.10-no-root-login"
description = "CIS 5.2.10 - Ensure SSH root login is disabled"
level = 2
object = "sshd_config"

  [[rules.conditions]]
  property = "permitrootlogin"
  condition = "EQUAL"
  value = "no"
```

Conditions: `EQUAL`, `DIFFERENT`, `SUP`, `INF`, `INCLUDE`, `REGEX`, `STARTS_WITH`, `ENDS_WITH`, `DATE_INF`, `DATE_SUP`, and nested `AND`/`OR`/`NAND`/`NOR`/`XOR`.

## Architecture

```
+----------------------------------------------------------------+
|                          kxn-cli                               |
|                                                                |
|  kxn <URI>              one-shot scan                          |
|  kxn monitor <URI>      continuous daemon                      |
|  kxn serve --mcp        Claude Desktop/Code                    |
|  kxn serve --webhook    reactive compliance engine             |
|  kxn scan/check/gather  classic CLI                            |
+----------------------------------------------------------------+
         |                    |                    |
         v                    v                    v
+------------------+  +----------------+  +------------------+
|   kxn-rules      |  |   kxn-core     |  |  kxn-providers   |
|                  |  |                |  |                  |
| TOML parser      |  | Rules engine   |  | 14 native        |
| 736+ rules       |  | 16 conditions  |  | providers        |
| Compliance maps  |  | Nested logic   |  |                  |
|                  |  | (AND/OR/NAND/  |  | Terraform gRPC   |
|                  |  |  NOR/XOR)      |  | bridge (3000+)   |
+------------------+  +----------------+  +------------------+
         |                    |                    |
         v                    v                    v
+------------------+  +----------------+  +------------------+
|   kxn-mcp        |  |   alerts (14)  |  |   save (16)      |
|                  |  |                |  |                  |
| MCP server       |  | Slack, Teams   |  | PostgreSQL, ES   |
| stdio transport  |  | Email, SMS     |  | Kafka, EventHubs |
| 8 tools          |  | Jira, PagerDuty|  | SNS, Pub/Sub     |
|                  |  | Opsgenie, etc. |  | InfluxDB, S3     |
+------------------+  +----------------+  +------------------+
```

## Development

```bash
cargo build
cargo test
```

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. IN NO EVENT SHALL THE AUTHORS, CONTRIBUTORS, OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR ITS USE.

**kxn is a compliance scanning tool, not a guarantee of security.** It identifies known misconfigurations and vulnerabilities based on public rules and databases (NVD, CISA KEV, CIS Benchmarks), but it does not replace professional security audits, penetration testing, or expert review. You are solely responsible for the security of your infrastructure and for validating scan results before acting on them.

CVE data is sourced from public feeds (NVD, CISA, EPSS) and may be incomplete, delayed, or contain inaccuracies. Always verify findings independently.

## License

[BSL 1.1](LICENSE) — Free for non-competing use. Changes to Apache 2.0 on 2030-03-25.
