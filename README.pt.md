# kxn

A camada de segurança para agentes de IA. Scanner de conformidade multi-nuvem em Rust.

Binário único. Sem runtime. Baseado em URI. Nativo para agentes.

```bash
kxn ssh://root@server -o minimal
```

## Integração com Agentes de IA

kxn foi construído para agentes de IA. Qualquer agente (Claude, GPT, Gemini, Copilot, open-source) pode escanear, validar e remediar a segurança da infraestrutura.

### 9 agentes compatíveis

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

### Exportação do esquema de ferramentas

Qualquer framework de agentes (LangChain, CrewAI, AutoGen, personalizado) pode descobrir as ferramentas do kxn:

```bash
kxn tools                  # OpenAI function calling format
kxn tools -f anthropic     # Anthropic tool use format
kxn tools -f summary       # Human-readable summary
```

5 ferramentas expostas: `kxn_scan`, `kxn_gather`, `kxn_check`, `kxn_cve_lookup`, `kxn_remediate`.

### Exemplo de fluxo de trabalho de um agente

```
Agent receives: "deploy new version to prod"
  1. kubectl apply -f deployment.yaml
  2. kxn kubernetes://cluster -o json         → 0 violations → continue
  3. kxn ssh://root@node -o json              → 2 CRITICAL CVEs → alert
  4. kxn_remediate(target, rules)             → auto-fix selected violations
  5. Audit trail: every action logged
```

Sem kxn, os agentes implantam às cegas. Com kxn, os agentes têm consciência de segurança.

## Início Rápido

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

## Modos

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

## Detecção de CVE

Banco de dados SQLite local sincronizado a partir de feeds públicos. Zero chamadas de API durante os escaneamentos.

```bash
kxn cve-update                    # sync NVD + CISA KEV + EPSS → ~/.cache/kxn/cve.sqlite
kxn ssh://root@server             # detects CVEs in installed packages (dpkg/rpm/apk)
```

| Feed | Source | Entries |
|------|--------|---------|
| NVD | services.nvd.nist.gov | 29K+ CVEs |
| CISA KEV | cisa.gov | 1555 actively exploited |
| EPSS | api.first.org | 5000 top exploit probability |

Consulta: < 1ms por pacote. Offline. Compatível com ambientes isolados (air-gap).

## Provedores

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

## Backends de Alertas (14)

Slack, Discord, Teams, Email (SMTP), SMS (Twilio), Jira, PagerDuty, Opsgenie, ServiceNow, Linear, Splunk On-Call, Zendesk, Kafka, Generic webhook.

## Backends de Armazenamento (16)

PostgreSQL, MySQL, MongoDB, Elasticsearch, OpenSearch, S3, GCS, Azure Blob, Kafka, Event Hubs, SNS, Pub/Sub, Redis, Splunk HEC, InfluxDB, JSONL file.

## Regras

736+ regras TOML. CIS benchmarks, OWASP API Top 10, detecção de CVE, IAM, TLS, monitoramento.

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

16 condições: `EQUAL`, `DIFFERENT`, `SUP`, `INF`, `INCLUDE`, `REGEX`, `STARTS_WITH`, `ENDS_WITH`, `DATE_INF`, `DATE_SUP`, aninhadas `AND`/`OR`/`NAND`/`NOR`/`XOR`.

## Servidor MCP

```bash
kxn serve --mcp
```

8 ferramentas para qualquer cliente de IA compatível com MCP: `kxn_list_providers`, `kxn_list_resource_types`, `kxn_list_rules`, `kxn_provider_schema`, `kxn_gather`, `kxn_scan`, `kxn_check_resource`, `kxn_remediate`.

Auto-remediação em 2 etapas (nunca aplica correções sem seleção explícita).

## Conformidade Reativa

kxn recebe eventos da nuvem em tempo real e escaneia recursos à medida que são criados ou modificados.

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

## Arquitetura

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

## Desenvolvimento

```bash
cargo build
cargo test
```

## Aviso Legal

ESTE SOFTWARE É FORNECIDO "NO ESTADO EM QUE SE ENCONTRA", SEM GARANTIA DE QUALQUER TIPO, EXPRESSA OU IMPLÍCITA. EM NENHUMA HIPÓTESE OS AUTORES, COLABORADORES OU TITULARES DOS DIREITOS AUTORAIS SERÃO RESPONSÁVEIS POR QUALQUER RECLAMAÇÃO, DANO OU OUTRA RESPONSABILIDADE DECORRENTE DE, OU EM CONEXÃO COM O SOFTWARE OU SEU USO.

**kxn é uma ferramenta de escaneamento de conformidade, não uma garantia de segurança.** Identifica configurações incorretas e vulnerabilidades conhecidas com base em regras públicas e bancos de dados (NVD, CISA KEV, CIS Benchmarks), mas não substitui auditorias de segurança profissionais, testes de penetração ou revisões de especialistas. Você é o único responsável pela segurança da sua infraestrutura e por validar os resultados do escaneamento antes de agir com base neles.

Os dados de CVE são provenientes de feeds públicos (NVD, CISA, EPSS) e podem estar incompletos, atrasados ou conter imprecisões. Sempre verifique os achados de forma independente.

## Licença

[BSL 1.1](LICENSE) — Gratuito para uso não competitivo. Muda para Apache 2.0 em 2030-03-25.
