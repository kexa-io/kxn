# kxn

AIエージェントのためのセキュリティレイヤー。Rustで構築されたマルチクラウドコンプライアンススキャナー。

単一バイナリ。ランタイム不要。URI駆動。エージェントネイティブ。

```bash
kxn ssh://root@server -o minimal
```

## AIエージェント統合

kxnはAIエージェントのために構築されています。あらゆるエージェント（Claude、GPT、Gemini、Copilot、オープンソース）がインフラストラクチャのセキュリティをスキャン、検証、修復できます。

### 9つのサポートされるエージェント

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

### ツールスキーマのエクスポート

あらゆるエージェントフレームワーク（LangChain、CrewAI、AutoGen、カスタム）がkxnツールを検出できます：

```bash
kxn tools                  # OpenAI function calling format
kxn tools -f anthropic     # Anthropic tool use format
kxn tools -f summary       # Human-readable summary
```

公開される5つのツール：`kxn_scan`、`kxn_gather`、`kxn_check`、`kxn_cve_lookup`、`kxn_remediate`。

### エージェントワークフロー例

```
Agent receives: "deploy new version to prod"
  1. kubectl apply -f deployment.yaml
  2. kxn kubernetes://cluster -o json         → 0 violations → continue
  3. kxn ssh://root@node -o json              → 2 CRITICAL CVEs → alert
  4. kxn_remediate(target, rules)             → auto-fix selected violations
  5. Audit trail: every action logged
```

kxnなしでは、エージェントは盲目的にデプロイします。kxnがあれば、エージェントはセキュリティ意識を持ちます。

## クイックスタート

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

## モード

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

## CVE検出

公開フィードから同期されたローカルSQLiteデータベース。スキャン中のAPI呼び出しゼロ。

```bash
kxn cve-update                    # sync NVD + CISA KEV + EPSS → ~/.cache/kxn/cve.sqlite
kxn ssh://root@server             # detects CVEs in installed packages (dpkg/rpm/apk)
```

| Feed | Source | Entries |
|------|--------|---------|
| NVD | services.nvd.nist.gov | 29K+ CVEs |
| CISA KEV | cisa.gov | 1555 actively exploited |
| EPSS | api.first.org | 5000 top exploit probability |

ルックアップ：パッケージあたり1ms未満。オフライン。エアギャップ対応。

## プロバイダー

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

## アラートバックエンド (14)

Slack、Discord、Teams、Email (SMTP)、SMS (Twilio)、Jira、PagerDuty、Opsgenie、ServiceNow、Linear、Splunk On-Call、Zendesk、Kafka、汎用webhook。

## 保存バックエンド (16)

PostgreSQL、MySQL、MongoDB、Elasticsearch、OpenSearch、S3、GCS、Azure Blob、Kafka、Event Hubs、SNS、Pub/Sub、Redis、Splunk HEC、InfluxDB、JSONLファイル。

## ルール

736以上のTOMLルール。CISベンチマーク、OWASP API Top 10、CVE検出、IAM、TLS、モニタリング。

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

16の条件：`EQUAL`、`DIFFERENT`、`SUP`、`INF`、`INCLUDE`、`REGEX`、`STARTS_WITH`、`ENDS_WITH`、`DATE_INF`、`DATE_SUP`、ネストされた`AND`/`OR`/`NAND`/`NOR`/`XOR`。

## MCP サーバー

```bash
kxn serve --mcp
```

MCP対応AIクライアント向けの8つのツール：`kxn_list_providers`、`kxn_list_resource_types`、`kxn_list_rules`、`kxn_provider_schema`、`kxn_gather`、`kxn_scan`、`kxn_check_resource`、`kxn_remediate`。

2ステップの自動修復（明示的な選択なしに修正を適用することはありません）。

## リアクティブコンプライアンス

kxnはクラウドイベントをリアルタイムで受信し、リソースが作成または変更された際にスキャンを実行します。

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

## アーキテクチャ

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

## 開発

```bash
cargo build
cargo test
```

## 免責事項

本ソフトウェアは「現状のまま」提供され、明示的または暗示的を問わず、いかなる種類の保証もありません。著者、貢献者、または著作権者は、本ソフトウェアまたはその使用に起因する、または関連するいかなる請求、損害、またはその他の責任についても一切責任を負いません。

**kxnはコンプライアンススキャンツールであり、セキュリティの保証ではありません。** 公開ルールおよびデータベース（NVD、CISA KEV、CISベンチマーク）に基づいて既知の設定ミスおよび脆弱性を特定しますが、専門的なセキュリティ監査、ペネトレーションテスト、または専門家によるレビューの代替にはなりません。インフラストラクチャのセキュリティおよびスキャン結果の検証は、お客様ご自身の責任です。

CVEデータは公開フィード（NVD、CISA、EPSS）から取得されており、不完全、遅延、または不正確な場合があります。発見事項は必ず独自に検証してください。

## ライセンス

[BSL 1.1](LICENSE) — 競合しない使用については無料。2030-03-25にApache 2.0に変更されます。
