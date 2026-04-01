# kxn

Die Sicherheitsschicht für KI-Agenten. Multi-Cloud-Compliance-Scanner in Rust.

Einzelnes Binary. Keine Runtime. URI-gesteuert. Agenten-nativ.

```bash
kxn ssh://root@server -o minimal
```

## KI-Agenten-Integration

kxn wurde für KI-Agenten entwickelt. Jeder Agent (Claude, GPT, Gemini, Copilot, Open-Source) kann Infrastruktursicherheit scannen, validieren und beheben.

### 9 unterstützte Agenten

```bash
kxn init --client claude-code   # MCP server (native)
kxn init --client claude-desktop
kxn init --client cursor        # MCP server
kxn init --client gemini        # MCP server
kxn init --client windsurf      # MCP server
kxn init --client opencode      # MCP server
kxn init --client codex         # MCP (TOML)
kxn init --client cline         # .clinerules instructions
kxn init --client copilot       # .github/copilot-instructions.md
```

### Export des Tool-Schemas

Jedes Agenten-Framework (LangChain, CrewAI, AutoGen, benutzerdefiniert) kann die kxn-Tools erkennen:

```bash
kxn tools                  # OpenAI function calling format
kxn tools -f anthropic     # Anthropic tool use format
kxn tools -f summary       # Human-readable summary
```

5 bereitgestellte Tools: `kxn_scan`, `kxn_gather`, `kxn_check`, `kxn_cve_lookup`, `kxn_remediate`.

### Beispiel eines Agenten-Workflows

```
Agent receives: "deploy new version to prod"
  1. kubectl apply -f deployment.yaml
  2. kxn kubernetes://cluster -o json         → 0 violations → continue
  3. kxn ssh://root@node -o json              → 2 CRITICAL CVEs → alert
  4. kxn_remediate(target, rules)             → auto-fix selected violations
  5. Audit trail: every action logged
```

Ohne kxn deployen Agenten blind. Mit kxn haben Agenten ein Sicherheitsbewusstsein.

## Schnellstart

```bash
# Install
cargo install --git https://github.com/kexa-io/kxn kxn-cli

# Scan
kxn ssh://root@server
kxn postgresql://user:pass@host:5432
kxn mysql://user:pass@host:3306

# CVE detection
kxn cve-update                           # sync NVD + CISA KEV + EPSS (43MB SQLite)
kxn ssh://root@server                    # includes package CVE scan

# Output formats
kxn ssh://root@server -o json            # structured JSON
kxn ssh://root@server -o csv             # CSV for Excel/reports
kxn ssh://root@server -o toml            # Git-friendly TOML
kxn ssh://root@server -o minimal         # compact colorized
```

## Modi

```bash
# One-shot scan (cron-friendly, exit code 1 on violations)
kxn ssh://root@server --compliance

# Continuous monitoring daemon
kxn monitor mysql://user:pass@host --alert slack://hooks.slack.com/T/B/x

# MCP server for AI agents
kxn serve --mcp

# Webhook server for reactive compliance
kxn serve --webhook --port 8080 --save kafka://broker:8082/compliance
```

## CVE-Erkennung

Lokale SQLite-Datenbank, synchronisiert aus öffentlichen Feeds. Keine API-Aufrufe während der Scans.

```bash
kxn cve-update                    # sync NVD + CISA KEV + EPSS → ~/.cache/kxn/cve.sqlite
kxn ssh://root@server             # detects CVEs in installed packages (dpkg/rpm/apk)
```

| Feed | Source | Entries |
|------|--------|---------|
| NVD | services.nvd.nist.gov | 29K+ CVEs |
| CISA KEV | cisa.gov | 1555 actively exploited |
| EPSS | api.first.org | 5000 top exploit probability |

Abfrage: < 1ms pro Paket. Offline. Air-Gap-kompatibel.

## Anbieter

| Provider | URI Scheme | Resources |
|----------|-----------|-----------|
| SSH | `ssh://` | sshd_config, sysctl, users, services, system_stats, packages_cve, logs |
| PostgreSQL | `postgresql://` | databases, roles, settings, extensions, db_stats |
| MySQL | `mysql://` | databases, users, grants, variables, status, db_stats |
| MongoDB | `mongodb://` | databases, users, serverStatus, currentOp, db_stats |
| Oracle | `oracle://` | users, tables, privileges, sessions, parameters |
| Kubernetes | `k8s://` | 26 types: pods, deployments, RBAC, network policies, metrics |
| GitHub | `github://` | organization, repos, webhooks, Dependabot, actions |
| HTTP | `http://` | status, headers, TLS, certificate, timing |
| gRPC | `grpc://` | health_check, connection, reflection |
| CVE | `cve://` | nvd_cves, kev, epss |
| **Terraform** | any | **3000+ providers** via gRPC bridge |

## Alert-Backends (14)

Slack, Discord, Teams, Email (SMTP), SMS (Twilio), Jira, PagerDuty, Opsgenie, ServiceNow, Linear, Splunk On-Call, Zendesk, Kafka, Generic webhook.

## Speicher-Backends (16)

PostgreSQL, MySQL, MongoDB, Elasticsearch, OpenSearch, S3, GCS, Azure Blob, Kafka, Event Hubs, SNS, Pub/Sub, Redis, Splunk HEC, InfluxDB, JSONL file.

## Regeln

736+ TOML-Regeln. CIS Benchmarks, OWASP API Top 10, CVE-Erkennung, IAM, TLS, Monitoring.

```toml
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

16 Bedingungen: `EQUAL`, `DIFFERENT`, `SUP`, `INF`, `INCLUDE`, `REGEX`, `STARTS_WITH`, `ENDS_WITH`, `DATE_INF`, `DATE_SUP`, verschachtelt `AND`/`OR`/`NAND`/`NOR`/`XOR`.

## MCP-Server

```bash
kxn serve --mcp
```

8 Tools für jeden MCP-kompatiblen KI-Client: `kxn_list_providers`, `kxn_list_resource_types`, `kxn_list_rules`, `kxn_provider_schema`, `kxn_gather`, `kxn_scan`, `kxn_check_resource`, `kxn_remediate`.

Auto-Remediierung in 2 Schritten (wendet niemals Korrekturen ohne explizite Auswahl an).

## Reaktive Compliance

kxn empfängt Cloud-Events in Echtzeit und scannt Ressourcen, sobald sie erstellt oder geändert werden.

```
Azure Event Grid / AWS EventBridge / CloudEvents
        |
        v
  kxn serve --webhook :8080
    POST /event  (auto-scan)
    POST /scan   (check JSON)
    POST /ingest (fan-in)
        |
        +--> alerts (Slack, PagerDuty, Jira...)
        +--> save (Kafka, Elasticsearch, Grafana...)
```

## Architektur

```
+----------------------------------------------------------------+
|                          kxn-cli                               |
|                                                                |
|  kxn <URI>              one-shot scan                          |
|  kxn monitor <URI>      continuous daemon                      |
|  kxn serve --mcp        AI agent MCP server                    |
|  kxn serve --webhook    reactive compliance engine             |
|  kxn tools              export tool schemas for any agent      |
|  kxn cve-update         sync CVE database                     |
+----------------------------------------------------------------+
         |                    |                    |
         v                    v                    v
+------------------+  +----------------+  +------------------+
|   kxn-rules      |  |   kxn-core     |  |  kxn-providers   |
|                  |  |                |  |                  |
| TOML parser      |  | Rules engine   |  | 14 native        |
| 736+ rules       |  | 16 conditions  |  | providers        |
| Compliance maps  |  | Nested logic   |  |                  |
|                  |  |                |  | Terraform gRPC   |
|                  |  |                |  | bridge (3000+)   |
|                  |  |                |  |                  |
|                  |  |                |  | CVE database     |
|                  |  |                |  | (SQLite, NVD+KEV)|
+------------------+  +----------------+  +------------------+
         |                    |                    |
         v                    v                    v
+------------------+  +----------------+  +------------------+
|   kxn-mcp        |  |   alerts (14)  |  |   save (16)      |
|                  |  |                |  |                  |
| MCP server       |  | Slack, Teams   |  | PostgreSQL, ES   |
| 9 AI agents      |  | Email, SMS     |  | Kafka, EventHubs |
| 8 tools          |  | Jira, PagerDuty|  | SNS, Pub/Sub     |
| Tool schema      |  | Opsgenie, etc. |  | InfluxDB, S3     |
+------------------+  +----------------+  +------------------+
```

## Entwicklung

```bash
cargo build
cargo test
```

## Haftungsausschluss

DIESE SOFTWARE WIRD "WIE BESEHEN" BEREITGESTELLT, OHNE JEGLICHE AUSDRÜCKLICHE ODER STILLSCHWEIGENDE GEWÄHRLEISTUNG. IN KEINEM FALL HAFTEN DIE AUTOREN, MITWIRKENDEN ODER URHEBERRECHTSINHABER FÜR ANSPRÜCHE, SCHÄDEN ODER SONSTIGE HAFTUNG, DIE SICH AUS ODER IN VERBINDUNG MIT DER SOFTWARE ODER DEREN NUTZUNG ERGEBEN.

**kxn ist ein Compliance-Scanning-Tool, keine Sicherheitsgarantie.** Es identifiziert bekannte Fehlkonfigurationen und Schwachstellen auf Basis öffentlicher Regeln und Datenbanken (NVD, CISA KEV, CIS Benchmarks), ersetzt jedoch keine professionellen Sicherheitsaudits, Penetrationstests oder Expertenbewertungen. Sie sind allein verantwortlich für die Sicherheit Ihrer Infrastruktur und für die Validierung der Scan-Ergebnisse, bevor Sie darauf reagieren.

CVE-Daten stammen aus öffentlichen Feeds (NVD, CISA, EPSS) und können unvollständig, verzögert oder ungenau sein. Überprüfen Sie Ergebnisse stets unabhängig.

## Lizenz

[BSL 1.1](LICENSE) — Kostenlos für nicht-konkurrierende Nutzung. Wechselt zu Apache 2.0 am 2030-03-25.
