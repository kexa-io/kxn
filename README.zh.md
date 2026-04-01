# kxn

AI代理的安全层。基于Rust的多云合规扫描器。

单一二进制文件。无需运行时。URI驱动。代理原生。

```bash
kxn ssh://root@server -o minimal
```

## AI代理集成

kxn专为AI代理构建。任何代理（Claude、GPT、Gemini、Copilot、开源）都可以扫描、验证和修复基础设施安全问题。

### 9个支持的代理

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

### 工具模式导出

任何代理框架（LangChain、CrewAI、AutoGen、自定义）都可以发现kxn工具：

```bash
kxn tools                  # OpenAI function calling format
kxn tools -f anthropic     # Anthropic tool use format
kxn tools -f summary       # Human-readable summary
```

提供5个工具：`kxn_scan`、`kxn_gather`、`kxn_check`、`kxn_cve_lookup`、`kxn_remediate`。

### 代理工作流示例

```
Agent receives: "deploy new version to prod"
  1. kubectl apply -f deployment.yaml
  2. kxn kubernetes://cluster -o json         → 0 violations → continue
  3. kxn ssh://root@node -o json              → 2 CRITICAL CVEs → alert
  4. kxn_remediate(target, rules)             → auto-fix selected violations
  5. Audit trail: every action logged
```

没有kxn，代理会盲目部署。有了kxn，代理就具备了安全意识。

## 快速开始

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

## 模式

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

## CVE检测

从公开源同步的本地SQLite数据库。扫描期间零API调用。

```bash
kxn cve-update                    # sync NVD + CISA KEV + EPSS → ~/.cache/kxn/cve.sqlite
kxn ssh://root@server             # detects CVEs in installed packages (dpkg/rpm/apk)
```

| Feed | Source | Entries |
|------|--------|---------|
| NVD | services.nvd.nist.gov | 29K+ CVEs |
| CISA KEV | cisa.gov | 1555 actively exploited |
| EPSS | api.first.org | 5000 top exploit probability |

查询：每个包不到1ms。离线运行。支持气隙环境。

## 提供者

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

## 告警后端 (14)

Slack、Discord、Teams、Email (SMTP)、SMS (Twilio)、Jira、PagerDuty、Opsgenie、ServiceNow、Linear、Splunk On-Call、Zendesk、Kafka、通用webhook。

## 存储后端 (16)

PostgreSQL、MySQL、MongoDB、Elasticsearch、OpenSearch、S3、GCS、Azure Blob、Kafka、Event Hubs、SNS、Pub/Sub、Redis、Splunk HEC、InfluxDB、JSONL文件。

## 规则

736+条TOML规则。CIS基准、OWASP API Top 10、CVE检测、IAM、TLS、监控。

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

16种条件：`EQUAL`、`DIFFERENT`、`SUP`、`INF`、`INCLUDE`、`REGEX`、`STARTS_WITH`、`ENDS_WITH`、`DATE_INF`、`DATE_SUP`，嵌套`AND`/`OR`/`NAND`/`NOR`/`XOR`。

## MCP服务器

```bash
kxn serve --mcp
```

面向MCP兼容AI客户端的8个工具：`kxn_list_providers`、`kxn_list_resource_types`、`kxn_list_rules`、`kxn_provider_schema`、`kxn_gather`、`kxn_scan`、`kxn_check_resource`、`kxn_remediate`。

2步自动修复（未经明确选择绝不应用修复）。

## 响应式合规

kxn实时接收云事件，在资源创建或修改时进行扫描。

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

## 架构

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

## 开发

```bash
cargo build
cargo test
```

## 免责声明

本软件按"原样"提供，不提供任何明示或暗示的保证。在任何情况下，作者、贡献者或版权持有者均不对因本软件或其使用而产生或与之相关的任何索赔、损害或其他责任承担责任。

**kxn是合规扫描工具，而非安全保证。** 它基于公开规则和数据库（NVD、CISA KEV、CIS基准）识别已知的配置错误和漏洞，但不能替代专业安全审计、渗透测试或专家审查。您需自行负责基础设施的安全以及在采取行动前验证扫描结果。

CVE数据来源于公开源（NVD、CISA、EPSS），可能不完整、存在延迟或包含不准确信息。请务必独立验证发现的问题。

## 许可证

[BSL 1.1](LICENSE) — 非竞争性使用免费。2030-03-25变更为Apache 2.0。
