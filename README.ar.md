# kxn

طبقة الأمان لوكلاء الذكاء الاصطناعي. ماسح امتثال سحابي متعدد مكتوب بلغة Rust.

ملف ثنائي واحد. بدون بيئة تشغيل. يعتمد على URI. مُصمّم للوكلاء.

```bash
kxn ssh://root@server -o minimal
```

## تكامل وكلاء الذكاء الاصطناعي

kxn مصمّم لوكلاء الذكاء الاصطناعي. أي وكيل (Claude، GPT، Gemini، Copilot، مفتوح المصدر) يمكنه فحص البنية التحتية وأمانها والتحقق منها وإصلاحها.

### 9 وكلاء مدعومين

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

### تصدير مخطط الأدوات

أي إطار عمل للوكلاء (LangChain، CrewAI، AutoGen، مخصص) يمكنه اكتشاف أدوات kxn:

```bash
kxn tools                  # OpenAI function calling format
kxn tools -f anthropic     # Anthropic tool use format
kxn tools -f summary       # Human-readable summary
```

5 أدوات مكشوفة: `kxn_scan`، `kxn_gather`، `kxn_check`، `kxn_cve_lookup`، `kxn_remediate`.

### مثال على سير عمل الوكيل

```
Agent receives: "deploy new version to prod"
  1. kubectl apply -f deployment.yaml
  2. kxn kubernetes://cluster -o json         → 0 violations → continue
  3. kxn ssh://root@node -o json              → 2 CRITICAL CVEs → alert
  4. kxn_remediate(target, rules)             → auto-fix selected violations
  5. Audit trail: every action logged
```

بدون kxn، تنشر الوكلاء بشكل أعمى. مع kxn، تمتلك الوكلاء ضميرًا أمنيًا.

## البدء السريع

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

## الأوضاع

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

## كشف CVE

قاعدة بيانات SQLite محلية مُتزامنة من مصادر عامة. بدون استدعاءات API أثناء الفحص.

```bash
kxn cve-update                    # sync NVD + CISA KEV + EPSS → ~/.cache/kxn/cve.sqlite
kxn ssh://root@server             # detects CVEs in installed packages (dpkg/rpm/apk)
```

| Feed | Source | Entries |
|------|--------|---------|
| NVD | services.nvd.nist.gov | 29K+ CVEs |
| CISA KEV | cisa.gov | 1555 actively exploited |
| EPSS | api.first.org | 5000 top exploit probability |

البحث: أقل من 1 مللي ثانية لكل حزمة. بدون اتصال. متوافق مع البيئات المعزولة.

## الموفرون

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

## واجهات التنبيه (14)

Slack، Discord، Teams، Email (SMTP)، SMS (Twilio)، Jira، PagerDuty، Opsgenie، ServiceNow، Linear، Splunk On-Call، Zendesk، Kafka، Generic webhook.

## واجهات الحفظ (16)

PostgreSQL، MySQL، MongoDB، Elasticsearch، OpenSearch، S3، GCS، Azure Blob، Kafka، Event Hubs، SNS، Pub/Sub، Redis، Splunk HEC، InfluxDB، JSONL file.

## القواعد

أكثر من 736 قاعدة TOML. معايير CIS، OWASP API Top 10، كشف CVE، IAM، TLS، المراقبة.

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

16 شرطًا: `EQUAL`، `DIFFERENT`، `SUP`، `INF`، `INCLUDE`، `REGEX`، `STARTS_WITH`، `ENDS_WITH`، `DATE_INF`، `DATE_SUP`، متداخلة `AND`/`OR`/`NAND`/`NOR`/`XOR`.

## خادم MCP

```bash
kxn serve --mcp
```

8 أدوات لأي عميل ذكاء اصطناعي متوافق مع MCP: `kxn_list_providers`، `kxn_list_resource_types`، `kxn_list_rules`، `kxn_provider_schema`، `kxn_gather`، `kxn_scan`، `kxn_check_resource`، `kxn_remediate`.

إصلاح تلقائي في خطوتين (لا يطبّق الإصلاحات أبدًا بدون اختيار صريح).

## الامتثال التفاعلي

يستقبل kxn أحداث السحابة في الوقت الفعلي ويفحص الموارد عند إنشائها أو تعديلها.

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

## الهندسة المعمارية

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

## التطوير

```bash
cargo build
cargo test
```

## إخلاء المسؤولية

هذا البرنامج مقدّم "كما هو"، بدون أي ضمان من أي نوع، صريح أو ضمني. لا يتحمل المؤلفون أو المساهمون أو أصحاب حقوق الطبع والنشر بأي حال من الأحوال أي مسؤولية عن أي مطالبة أو أضرار أو التزامات أخرى ناشئة عن البرنامج أو استخدامه أو فيما يتعلق به.

**kxn أداة فحص امتثال، وليس ضمانًا للأمان.** يحدّد التكوينات الخاطئة والثغرات المعروفة بناءً على قواعد وقواعد بيانات عامة (NVD، CISA KEV، CIS Benchmarks)، لكنه لا يحلّ محل عمليات التدقيق الأمني المهنية أو اختبارات الاختراق أو المراجعة المتخصصة. أنت المسؤول الوحيد عن أمان بنيتك التحتية وعن التحقق من نتائج الفحص قبل التصرف بناءً عليها.

بيانات CVE مصدرها مصادر عامة (NVD، CISA، EPSS) وقد تكون غير مكتملة أو متأخرة أو تحتوي على عدم دقة. تحقق دائمًا من النتائج بشكل مستقل.

## الترخيص

[BSL 1.1](LICENSE) — مجاني للاستخدام غير المنافس. يتحول إلى Apache 2.0 في 2030-03-25.
