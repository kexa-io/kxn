# kxn

AI एजेंटों के लिए सुरक्षा परत। Rust में निर्मित मल्टी-क्लाउड अनुपालन स्कैनर।

एक बाइनरी। कोई रनटाइम नहीं। URI-आधारित। एजेंट-नेटिव।

```bash
kxn ssh://root@server -o minimal
```

## AI एजेंट एकीकरण

kxn AI एजेंटों के लिए बनाया गया है। कोई भी एजेंट (Claude, GPT, Gemini, Copilot, ओपन-सोर्स) इन्फ्रास्ट्रक्चर सुरक्षा को स्कैन, सत्यापित और रेमेडिएट कर सकता है।

### 9 समर्थित एजेंट

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

### टूल स्कीमा एक्सपोर्ट

कोई भी एजेंट फ्रेमवर्क (LangChain, CrewAI, AutoGen, कस्टम) kxn टूल्स खोज सकता है:

```bash
kxn tools                  # OpenAI function calling format
kxn tools -f anthropic     # Anthropic tool use format
kxn tools -f summary       # Human-readable summary
```

5 टूल उपलब्ध: `kxn_scan`, `kxn_gather`, `kxn_check`, `kxn_cve_lookup`, `kxn_remediate`।

### एजेंट वर्कफ़्लो उदाहरण

```
Agent receives: "deploy new version to prod"
  1. kubectl apply -f deployment.yaml
  2. kxn kubernetes://cluster -o json         → 0 violations → continue
  3. kxn ssh://root@node -o json              → 2 CRITICAL CVEs → alert
  4. kxn_remediate(target, rules)             → auto-fix selected violations
  5. Audit trail: every action logged
```

kxn के बिना, एजेंट अंधाधुंध डिप्लॉय करते हैं। kxn के साथ, एजेंटों में सुरक्षा चेतना होती है।

## त्वरित शुरुआत

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

## मोड

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

## CVE डिटेक्शन

सार्वजनिक फ़ीड से सिंक की गई स्थानीय SQLite डेटाबेस। स्कैन के दौरान शून्य API कॉल।

```bash
kxn cve-update                    # sync NVD + CISA KEV + EPSS → ~/.cache/kxn/cve.sqlite
kxn ssh://root@server             # detects CVEs in installed packages (dpkg/rpm/apk)
```

| Feed | Source | Entries |
|------|--------|---------|
| NVD | services.nvd.nist.gov | 29K+ CVEs |
| CISA KEV | cisa.gov | 1555 actively exploited |
| EPSS | api.first.org | 5000 top exploit probability |

लुकअप: प्रति पैकेज 1ms से कम। ऑफ़लाइन। एयर-गैप संगत।

## प्रोवाइडर

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

## अलर्ट बैकएंड (14)

Slack, Discord, Teams, Email (SMTP), SMS (Twilio), Jira, PagerDuty, Opsgenie, ServiceNow, Linear, Splunk On-Call, Zendesk, Kafka, Generic webhook।

## सेव बैकएंड (16)

PostgreSQL, MySQL, MongoDB, Elasticsearch, OpenSearch, S3, GCS, Azure Blob, Kafka, Event Hubs, SNS, Pub/Sub, Redis, Splunk HEC, InfluxDB, JSONL file।

## नियम

736+ TOML नियम। CIS बेंचमार्क, OWASP API Top 10, CVE डिटेक्शन, IAM, TLS, मॉनिटरिंग।

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

16 शर्तें: `EQUAL`, `DIFFERENT`, `SUP`, `INF`, `INCLUDE`, `REGEX`, `STARTS_WITH`, `ENDS_WITH`, `DATE_INF`, `DATE_SUP`, नेस्टेड `AND`/`OR`/`NAND`/`NOR`/`XOR`।

## MCP सर्वर

```bash
kxn serve --mcp
```

किसी भी MCP-संगत AI क्लाइंट के लिए 8 टूल: `kxn_list_providers`, `kxn_list_resource_types`, `kxn_list_rules`, `kxn_provider_schema`, `kxn_gather`, `kxn_scan`, `kxn_check_resource`, `kxn_remediate`।

2 चरणों में ऑटो-रेमेडिएशन (स्पष्ट चयन के बिना कभी फ़िक्स लागू नहीं करता)।

## रिएक्टिव अनुपालन

kxn रियल-टाइम में क्लाउड इवेंट प्राप्त करता है और संसाधनों को बनाए या संशोधित किए जाने पर स्कैन करता है।

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

## आर्किटेक्चर

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

## विकास

```bash
cargo build
cargo test
```

## अस्वीकरण

यह सॉफ़्टवेयर "जैसा है" प्रदान किया गया है, बिना किसी प्रकार की वारंटी के, व्यक्त या निहित। किसी भी स्थिति में लेखक, योगदानकर्ता या कॉपीराइट धारक सॉफ़्टवेयर या इसके उपयोग से उत्पन्न या संबंधित किसी भी दावे, क्षति या अन्य देयता के लिए उत्तरदायी नहीं होंगे।

**kxn एक अनुपालन स्कैनिंग टूल है, सुरक्षा की गारंटी नहीं।** यह सार्वजनिक नियमों और डेटाबेस (NVD, CISA KEV, CIS Benchmarks) के आधार पर ज्ञात गलत कॉन्फ़िगरेशन और कमज़ोरियों की पहचान करता है, लेकिन यह पेशेवर सुरक्षा ऑडिट, पेनेट्रेशन टेस्टिंग या विशेषज्ञ समीक्षा का विकल्प नहीं है। आप अपने इन्फ्रास्ट्रक्चर की सुरक्षा और स्कैन परिणामों को कार्रवाई से पहले सत्यापित करने के लिए पूरी तरह ज़िम्मेदार हैं।

CVE डेटा सार्वजनिक फ़ीड (NVD, CISA, EPSS) से प्राप्त है और अधूरा, विलंबित या गलत हो सकता है। हमेशा स्वतंत्र रूप से निष्कर्षों को सत्यापित करें।

## लाइसेंस

[BSL 1.1](LICENSE) — गैर-प्रतिस्पर्धी उपयोग के लिए निःशुल्क। 2030-03-25 को Apache 2.0 में परिवर्तित होता है।
