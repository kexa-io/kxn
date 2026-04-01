# kxn

Уровень безопасности для ИИ-агентов. Мультиоблачный сканер соответствия на Rust.

Один бинарный файл. Без среды выполнения. На основе URI. Нативный для агентов.

```bash
kxn ssh://root@server -o minimal
```

## Интеграция с ИИ-агентами

kxn создан для ИИ-агентов. Любой агент (Claude, GPT, Gemini, Copilot, с открытым исходным кодом) может сканировать, проверять и устранять проблемы безопасности инфраструктуры.

### 9 поддерживаемых агентов

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

### Экспорт схемы инструментов

Любой фреймворк для агентов (LangChain, CrewAI, AutoGen, пользовательский) может обнаруживать инструменты kxn:

```bash
kxn tools                  # OpenAI function calling format
kxn tools -f anthropic     # Anthropic tool use format
kxn tools -f summary       # Human-readable summary
```

5 доступных инструментов: `kxn_scan`, `kxn_gather`, `kxn_check`, `kxn_cve_lookup`, `kxn_remediate`.

### Пример рабочего процесса агента

```
Agent receives: "deploy new version to prod"
  1. kubectl apply -f deployment.yaml
  2. kxn kubernetes://cluster -o json         → 0 violations → continue
  3. kxn ssh://root@node -o json              → 2 CRITICAL CVEs → alert
  4. kxn_remediate(target, rules)             → auto-fix selected violations
  5. Audit trail: every action logged
```

Без kxn агенты развертывают вслепую. С kxn у агентов есть чувство безопасности.

## Быстрый старт

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

## Режимы

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

## Обнаружение CVE

Локальная база данных SQLite, синхронизированная из публичных источников. Ноль API-вызовов во время сканирования.

```bash
kxn cve-update                    # sync NVD + CISA KEV + EPSS → ~/.cache/kxn/cve.sqlite
kxn ssh://root@server             # detects CVEs in installed packages (dpkg/rpm/apk)
```

| Feed | Source | Entries |
|------|--------|---------|
| NVD | services.nvd.nist.gov | 29K+ CVEs |
| CISA KEV | cisa.gov | 1555 actively exploited |
| EPSS | api.first.org | 5000 top exploit probability |

Поиск: менее 1 мс на пакет. Офлайн. Совместим с изолированными средами.

## Провайдеры

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

## Бэкенды оповещений (14)

Slack, Discord, Teams, Email (SMTP), SMS (Twilio), Jira, PagerDuty, Opsgenie, ServiceNow, Linear, Splunk On-Call, Zendesk, Kafka, Generic webhook.

## Бэкенды сохранения (16)

PostgreSQL, MySQL, MongoDB, Elasticsearch, OpenSearch, S3, GCS, Azure Blob, Kafka, Event Hubs, SNS, Pub/Sub, Redis, Splunk HEC, InfluxDB, JSONL file.

## Правила

736+ правил TOML. Стандарты CIS, OWASP API Top 10, обнаружение CVE, IAM, TLS, мониторинг.

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

16 условий: `EQUAL`, `DIFFERENT`, `SUP`, `INF`, `INCLUDE`, `REGEX`, `STARTS_WITH`, `ENDS_WITH`, `DATE_INF`, `DATE_SUP`, вложенные `AND`/`OR`/`NAND`/`NOR`/`XOR`.

## Сервер MCP

```bash
kxn serve --mcp
```

8 инструментов для любого MCP-совместимого ИИ-клиента: `kxn_list_providers`, `kxn_list_resource_types`, `kxn_list_rules`, `kxn_provider_schema`, `kxn_gather`, `kxn_scan`, `kxn_check_resource`, `kxn_remediate`.

Автоматическое исправление в 2 шага (никогда не применяет исправления без явного выбора).

## Реактивное соответствие

kxn получает облачные события в реальном времени и сканирует ресурсы при их создании или изменении.

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

## Архитектура

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

## Разработка

```bash
cargo build
cargo test
```

## Отказ от ответственности

ДАННОЕ ПРОГРАММНОЕ ОБЕСПЕЧЕНИЕ ПРЕДОСТАВЛЯЕТСЯ «КАК ЕСТЬ», БЕЗ КАКИХ-ЛИБО ГАРАНТИЙ, ЯВНЫХ ИЛИ ПОДРАЗУМЕВАЕМЫХ. НИ ПРИ КАКИХ ОБСТОЯТЕЛЬСТВАХ АВТОРЫ, УЧАСТНИКИ ИЛИ ПРАВООБЛАДАТЕЛИ НЕ НЕСУТ ОТВЕТСТВЕННОСТИ ЗА КАКИЕ-ЛИБО ПРЕТЕНЗИИ, УБЫТКИ ИЛИ ИНЫЕ ОБЯЗАТЕЛЬСТВА, ВОЗНИКАЮЩИЕ В СВЯЗИ С ПРОГРАММНЫМ ОБЕСПЕЧЕНИЕМ ИЛИ ЕГО ИСПОЛЬЗОВАНИЕМ.

**kxn -- это инструмент сканирования соответствия, а не гарантия безопасности.** Он выявляет известные ошибки конфигурации и уязвимости на основе публичных правил и баз данных (NVD, CISA KEV, CIS Benchmarks), но не заменяет профессиональный аудит безопасности, тестирование на проникновение или экспертную проверку. Вы несете полную ответственность за безопасность своей инфраструктуры и за проверку результатов сканирования перед принятием мер.

Данные CVE получены из публичных источников (NVD, CISA, EPSS) и могут быть неполными, устаревшими или содержать неточности. Всегда проверяйте результаты самостоятельно.

## Лицензия

[BSL 1.1](LICENSE) — бесплатно для неконкурентного использования. Переход на Apache 2.0 25.03.2030.
