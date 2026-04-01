# kxn

Yapay zeka ajanları için güvenlik katmanı. Rust ile geliştirilmiş çoklu bulut uyumluluk tarayıcısı.

Tek ikili dosya. Çalışma zamanı gerektirmez. URI tabanlı. Ajan doğal.

```bash
kxn ssh://root@server -o minimal
```

## Yapay Zeka Ajanı Entegrasyonu

kxn, yapay zeka ajanları için tasarlanmıştır. Herhangi bir ajan (Claude, GPT, Gemini, Copilot, açık kaynak) altyapı güvenliğini tarayabilir, doğrulayabilir ve düzeltebilir.

### 9 desteklenen ajan

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

### Araç şeması dışa aktarımı

Herhangi bir ajan çerçevesi (LangChain, CrewAI, AutoGen, özel) kxn araçlarını keşfedebilir:

```bash
kxn tools                  # OpenAI function calling format
kxn tools -f anthropic     # Anthropic tool use format
kxn tools -f summary       # Human-readable summary
```

5 araç sunulmaktadır: `kxn_scan`, `kxn_gather`, `kxn_check`, `kxn_cve_lookup`, `kxn_remediate`.

### Ajan iş akışı örneği

```
Agent receives: "deploy new version to prod"
  1. kubectl apply -f deployment.yaml
  2. kxn kubernetes://cluster -o json         → 0 violations → continue
  3. kxn ssh://root@node -o json              → 2 CRITICAL CVEs → alert
  4. kxn_remediate(target, rules)             → auto-fix selected violations
  5. Audit trail: every action logged
```

kxn olmadan ajanlar körlemesine dağıtım yapar. kxn ile ajanlar bir güvenlik bilincine sahip olur.

## Hızlı Başlangıç

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

## Modlar

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

## CVE Tespiti

Herkese açık akışlardan senkronize edilen yerel SQLite veritabanı. Taramalar sırasında sıfır API çağrısı.

```bash
kxn cve-update                    # sync NVD + CISA KEV + EPSS → ~/.cache/kxn/cve.sqlite
kxn ssh://root@server             # detects CVEs in installed packages (dpkg/rpm/apk)
```

| Feed | Source | Entries |
|------|--------|---------|
| NVD | services.nvd.nist.gov | 29K+ CVEs |
| CISA KEV | cisa.gov | 1555 actively exploited |
| EPSS | api.first.org | 5000 top exploit probability |

Arama: paket başına < 1ms. Çevrimdışı. Air-gap uyumlu.

## Sağlayıcılar

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

## Uyarı Arka Uçları (14)

Slack, Discord, Teams, Email (SMTP), SMS (Twilio), Jira, PagerDuty, Opsgenie, ServiceNow, Linear, Splunk On-Call, Zendesk, Kafka, genel webhook.

## Kaydetme Arka Uçları (16)

PostgreSQL, MySQL, MongoDB, Elasticsearch, OpenSearch, S3, GCS, Azure Blob, Kafka, Event Hubs, SNS, Pub/Sub, Redis, Splunk HEC, InfluxDB, JSONL dosyası.

## Kurallar

736+ TOML kuralı. CIS kıyaslamaları, OWASP API Top 10, CVE tespiti, IAM, TLS, izleme.

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

16 koşul: `EQUAL`, `DIFFERENT`, `SUP`, `INF`, `INCLUDE`, `REGEX`, `STARTS_WITH`, `ENDS_WITH`, `DATE_INF`, `DATE_SUP`, iç içe `AND`/`OR`/`NAND`/`NOR`/`XOR`.

## MCP Sunucusu

```bash
kxn serve --mcp
```

MCP uyumlu herhangi bir yapay zeka istemcisi için 8 araç: `kxn_list_providers`, `kxn_list_resource_types`, `kxn_list_rules`, `kxn_provider_schema`, `kxn_gather`, `kxn_scan`, `kxn_check_resource`, `kxn_remediate`.

2 adımda otomatik düzeltme (açık seçim yapılmadan asla düzeltme uygulamaz).

## Reaktif Uyumluluk

kxn, bulut olaylarını gerçek zamanlı olarak alır ve kaynakları oluşturuldukları veya değiştirildikleri anda tarar.

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

## Mimari

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

## Geliştirme

```bash
cargo build
cargo test
```

## Sorumluluk Reddi

BU YAZILIM, AÇIK VEYA ZIMNİ HERHANGİ BİR GARANTİ OLMAKSIZIN "OLDUĞU GİBİ" SUNULMAKTADIR. HİÇBİR DURUMDA YAZARLAR, KATKILAR VEYA TELİF HAKKI SAHİPLERİ, YAZILIMDAN VEYA KULLANIMINDAN KAYNAKLANAN HERHANGİ BİR TALEP, HASAR VEYA DİĞER SORUMLULUKTAN SORUMLU TUTULAMAZ.

**kxn bir uyumluluk tarama aracıdır, güvenlik garantisi değildir.** Herkese açık kurallara ve veritabanlarına (NVD, CISA KEV, CIS Benchmarks) dayanarak bilinen yapılandırma hatalarını ve güvenlik açıklarını tespit eder, ancak profesyonel güvenlik denetimlerinin, sızma testlerinin veya uzman incelemelerinin yerini almaz. Altyapınızın güvenliğinden ve tarama sonuçlarını eyleme geçirmeden önce doğrulamaktan yalnızca siz sorumlusunuz.

CVE verileri herkese açık akışlardan (NVD, CISA, EPSS) sağlanmaktadır ve eksik, gecikmeli veya hatalı olabilir. Bulguları her zaman bağımsız olarak doğrulayın.

## Lisans

[BSL 1.1](LICENSE) — Rekabet dışı kullanım için ücretsiz. 2030-03-25 tarihinde Apache 2.0'a geçiş.
