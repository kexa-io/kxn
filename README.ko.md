# kxn

AI 에이전트를 위한 보안 레이어. Rust로 구축된 멀티클라우드 컴플라이언스 스캐너.

단일 바이너리. 런타임 불필요. URI 기반. 에이전트 네이티브.

```bash
kxn ssh://root@server -o minimal
```

## AI 에이전트 통합

kxn은 AI 에이전트를 위해 구축되었습니다. 모든 에이전트(Claude, GPT, Gemini, Copilot, 오픈소스)가 인프라 보안을 스캔, 검증, 복구할 수 있습니다.

### 9개의 지원 에이전트

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

### 도구 스키마 내보내기

모든 에이전트 프레임워크(LangChain, CrewAI, AutoGen, 커스텀)에서 kxn 도구를 검색할 수 있습니다:

```bash
kxn tools                  # OpenAI function calling format
kxn tools -f anthropic     # Anthropic tool use format
kxn tools -f summary       # Human-readable summary
```

5개의 도구 제공: `kxn_scan`, `kxn_gather`, `kxn_check`, `kxn_cve_lookup`, `kxn_remediate`.

### 에이전트 워크플로 예시

```
Agent receives: "deploy new version to prod"
  1. kubectl apply -f deployment.yaml
  2. kxn kubernetes://cluster -o json         → 0 violations → continue
  3. kxn ssh://root@node -o json              → 2 CRITICAL CVEs → alert
  4. kxn_remediate(target, rules)             → auto-fix selected violations
  5. Audit trail: every action logged
```

kxn 없이는 에이전트가 맹목적으로 배포합니다. kxn이 있으면 에이전트가 보안 의식을 갖습니다.

## 빠른 시작

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

## 모드

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

## CVE 탐지

공개 피드에서 동기화된 로컬 SQLite 데이터베이스. 스캔 중 API 호출 없음.

```bash
kxn cve-update                    # sync NVD + CISA KEV + EPSS → ~/.cache/kxn/cve.sqlite
kxn ssh://root@server             # detects CVEs in installed packages (dpkg/rpm/apk)
```

| Feed | Source | Entries |
|------|--------|---------|
| NVD | services.nvd.nist.gov | 29K+ CVEs |
| CISA KEV | cisa.gov | 1555 actively exploited |
| EPSS | api.first.org | 5000 top exploit probability |

조회: 패키지당 1ms 미만. 오프라인. 에어갭 호환.

## 프로바이더

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

## 알림 백엔드 (14)

Slack, Discord, Teams, Email (SMTP), SMS (Twilio), Jira, PagerDuty, Opsgenie, ServiceNow, Linear, Splunk On-Call, Zendesk, Kafka, 범용 webhook.

## 저장 백엔드 (16)

PostgreSQL, MySQL, MongoDB, Elasticsearch, OpenSearch, S3, GCS, Azure Blob, Kafka, Event Hubs, SNS, Pub/Sub, Redis, Splunk HEC, InfluxDB, JSONL 파일.

## 규칙

736개 이상의 TOML 규칙. CIS 벤치마크, OWASP API Top 10, CVE 탐지, IAM, TLS, 모니터링.

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

16개의 조건: `EQUAL`, `DIFFERENT`, `SUP`, `INF`, `INCLUDE`, `REGEX`, `STARTS_WITH`, `ENDS_WITH`, `DATE_INF`, `DATE_SUP`, 중첩된 `AND`/`OR`/`NAND`/`NOR`/`XOR`.

## MCP 서버

```bash
kxn serve --mcp
```

MCP 호환 AI 클라이언트를 위한 8개 도구: `kxn_list_providers`, `kxn_list_resource_types`, `kxn_list_rules`, `kxn_provider_schema`, `kxn_gather`, `kxn_scan`, `kxn_check_resource`, `kxn_remediate`.

2단계 자동 복구(명시적 선택 없이 수정을 적용하지 않습니다).

## 리액티브 컴플라이언스

kxn은 클라우드 이벤트를 실시간으로 수신하고, 리소스가 생성되거나 수정될 때 스캔합니다.

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

## 아키텍처

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

## 개발

```bash
cargo build
cargo test
```

## 면책 조항

본 소프트웨어는 명시적이든 묵시적이든 어떠한 종류의 보증 없이 "있는 그대로" 제공됩니다. 저자, 기여자 또는 저작권 보유자는 본 소프트웨어 또는 그 사용으로 인해 발생하거나 이와 관련된 청구, 손해 또는 기타 책임에 대해 어떠한 경우에도 책임을 지지 않습니다.

**kxn은 컴플라이언스 스캔 도구이며, 보안을 보장하지 않습니다.** 공개 규칙 및 데이터베이스(NVD, CISA KEV, CIS 벤치마크)를 기반으로 알려진 설정 오류 및 취약점을 식별하지만, 전문 보안 감사, 침투 테스트 또는 전문가 검토를 대체하지 않습니다. 인프라 보안 및 스캔 결과 검증에 대한 책임은 전적으로 사용자에게 있습니다.

CVE 데이터는 공개 피드(NVD, CISA, EPSS)에서 가져오며, 불완전하거나 지연되거나 부정확할 수 있습니다. 발견 사항은 반드시 독립적으로 검증하십시오.

## 라이선스

[BSL 1.1](LICENSE) — 경쟁하지 않는 사용에 대해 무료. 2030-03-25에 Apache 2.0으로 변경됩니다.
