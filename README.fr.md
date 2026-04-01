# kxn

La couche de securite pour les agents IA. Scanner de compliance multi-cloud en Rust.

Un seul binaire. Pas de runtime. Pilote par URI. Concu pour les agents IA.

```bash
kxn ssh://root@server -o minimal
```

## Integration agents IA

kxn est concu pour les agents IA. N'importe quel agent (Claude, GPT, Gemini, Copilot, open-source) peut scanner, valider et remedier la securite de l'infrastructure.

### 9 agents supportes

```bash
kxn init --client claude-code   # Serveur MCP (natif)
kxn init --client claude-desktop
kxn init --client cursor        # Serveur MCP
kxn init --client gemini        # Serveur MCP
kxn init --client windsurf      # Serveur MCP
kxn init --client opencode      # Serveur MCP
kxn init --client codex         # MCP (TOML)
kxn init --client cline         # Instructions .clinerules
kxn init --client copilot       # .github/copilot-instructions.md
```

### Export des schemas d'outils

N'importe quel framework d'agent (LangChain, CrewAI, AutoGen, custom) peut decouvrir les outils kxn :

```bash
kxn tools                  # Format OpenAI function calling
kxn tools -f anthropic     # Format Anthropic tool use
kxn tools -f summary       # Resume lisible
```

5 outils exposes : `kxn_scan`, `kxn_gather`, `kxn_check`, `kxn_cve_lookup`, `kxn_remediate`.

### Workflow agent

```
L'agent recoit : "deploie la nouvelle version en prod"
  1. kubectl apply -f deployment.yaml
  2. kxn kubernetes://cluster -o json         → 0 violations → continue
  3. kxn ssh://root@node -o json              → 2 CVE CRITIQUES → alerte
  4. kxn_remediate(target, rules)             → correction automatique
  5. Audit trail : chaque action tracee
```

Sans kxn, les agents deploient a l'aveugle. Avec kxn, les agents ont une conscience securite.

## Demarrage rapide

```bash
# Installation
cargo install --git https://github.com/kexa-io/kxn kxn-cli

# Scanner
kxn ssh://root@server
kxn postgresql://user:pass@host:5432
kxn mysql://user:pass@host:3306

# Detection CVE
kxn cve-update                           # sync NVD + CISA KEV + EPSS (43 Mo SQLite)
kxn ssh://root@server                    # inclut le scan CVE des packages

# Formats de sortie
kxn ssh://root@server -o json            # JSON structure
kxn ssh://root@server -o csv             # CSV pour Excel/rapports
kxn ssh://root@server -o toml            # TOML versionnable Git
kxn ssh://root@server -o minimal         # compact colorise
```

## Modes

```bash
# Scan ponctuel (compatible cron, exit code 1 si violations)
kxn ssh://root@server --compliance

# Daemon de monitoring continu
kxn monitor mysql://user:pass@host --alert slack://hooks.slack.com/T/B/x

# Serveur MCP pour agents IA
kxn serve --mcp

# Serveur webhook pour compliance reactive
kxn serve --webhook --port 8080 --save kafka://broker:8082/compliance
```

## Detection CVE

Base SQLite locale synchronisee depuis les feeds publics. Zero appel API pendant les scans.

```bash
kxn cve-update                    # sync NVD + CISA KEV + EPSS → ~/.cache/kxn/cve.sqlite
kxn ssh://root@server             # detecte les CVE dans les packages installes (dpkg/rpm/apk)
```

| Feed | Source | Entrees |
|------|--------|---------|
| NVD | services.nvd.nist.gov | 29 000+ CVE |
| CISA KEV | cisa.gov | 1 555 activement exploitees |
| EPSS | api.first.org | 5 000 top probabilite d'exploitation |

Lookup : < 1 ms par package. Hors-ligne. Compatible air-gap.

## Providers

| Provider | Schema URI | Ressources |
|----------|-----------|-----------|
| SSH | `ssh://` | sshd_config, sysctl, users, services, system_stats, packages_cve, logs |
| PostgreSQL | `postgresql://` | databases, roles, settings, extensions, db_stats |
| MySQL | `mysql://` | databases, users, grants, variables, status, db_stats |
| MongoDB | `mongodb://` | databases, users, serverStatus, currentOp, db_stats |
| Oracle | `oracle://` | users, tables, privileges, sessions, parameters |
| Kubernetes | `k8s://` | 26 types : pods, deployments, RBAC, network policies, metrics |
| GitHub | `github://` | organization, repos, webhooks, Dependabot, actions |
| HTTP | `http://` | status, headers, TLS, certificat, timing |
| gRPC | `grpc://` | health_check, connection, reflection |
| CVE | `cve://` | nvd_cves, kev, epss |
| **Terraform** | tous | **3 000+ providers** via bridge gRPC |

## Backends d'alerte (14)

Slack, Discord, Teams, Email (SMTP), SMS (Twilio), Jira, PagerDuty, Opsgenie, ServiceNow, Linear, Splunk On-Call, Zendesk, Kafka, Webhook generique.

## Backends de sauvegarde (16)

PostgreSQL, MySQL, MongoDB, Elasticsearch, OpenSearch, S3, GCS, Azure Blob, Kafka, Event Hubs, SNS, Pub/Sub, Redis, Splunk HEC, InfluxDB, fichier JSONL.

## Regles

736+ regles TOML. Benchmarks CIS, OWASP API Top 10, detection CVE, IAM, TLS, monitoring.

```toml
[[rules]]
name = "ssh-cis-5.2.10-no-root-login"
description = "CIS 5.2.10 - S'assurer que le login root SSH est desactive"
level = 2
object = "sshd_config"

  [[rules.conditions]]
  property = "permitrootlogin"
  condition = "EQUAL"
  value = "no"
```

16 conditions : `EQUAL`, `DIFFERENT`, `SUP`, `INF`, `INCLUDE`, `REGEX`, `STARTS_WITH`, `ENDS_WITH`, `DATE_INF`, `DATE_SUP`, imbrication `AND`/`OR`/`NAND`/`NOR`/`XOR`.

## Serveur MCP

```bash
kxn serve --mcp
```

8 outils pour tout client IA compatible MCP : `kxn_list_providers`, `kxn_list_resource_types`, `kxn_list_rules`, `kxn_provider_schema`, `kxn_gather`, `kxn_scan`, `kxn_check_resource`, `kxn_remediate`.

Auto-remediation en 2 etapes (n'applique jamais de correctifs sans selection explicite).

## Compliance reactive

kxn recoit les evenements cloud en temps reel et scanne les ressources des leur creation ou modification.

```
Azure Event Grid / AWS EventBridge / CloudEvents
        |
        v
  kxn serve --webhook :8080
    POST /event  (scan auto)
    POST /scan   (verifier JSON)
    POST /ingest (fan-in)
        |
        +--> alertes (Slack, PagerDuty, Jira...)
        +--> sauvegarde (Kafka, Elasticsearch, Grafana...)
```

## Architecture

```
+----------------------------------------------------------------+
|                          kxn-cli                               |
|                                                                |
|  kxn <URI>              scan ponctuel                          |
|  kxn monitor <URI>      daemon continu                         |
|  kxn serve --mcp        serveur MCP pour agents IA             |
|  kxn serve --webhook    moteur de compliance reactive          |
|  kxn tools              export schemas pour tout agent         |
|  kxn cve-update         sync base CVE                         |
+----------------------------------------------------------------+
         |                    |                    |
         v                    v                    v
+------------------+  +----------------+  +------------------+
|   kxn-rules      |  |   kxn-core     |  |  kxn-providers   |
|                  |  |                |  |                  |
| Parseur TOML     |  | Moteur regles  |  | 14 natifs        |
| 736+ regles      |  | 16 conditions  |  |                  |
| Mappings         |  | Logique        |  | Bridge Terraform |
| compliance       |  | imbriquee      |  | gRPC (3 000+)    |
|                  |  |                |  |                  |
|                  |  |                |  | Base CVE         |
|                  |  |                |  | (SQLite, NVD+KEV)|
+------------------+  +----------------+  +------------------+
         |                    |                    |
         v                    v                    v
+------------------+  +----------------+  +------------------+
|   kxn-mcp        |  |  alertes (14)  |  | sauvegarde (16)  |
|                  |  |                |  |                  |
| Serveur MCP      |  | Slack, Teams   |  | PostgreSQL, ES   |
| 9 agents IA      |  | Email, SMS     |  | Kafka, EventHubs |
| 8 outils         |  | Jira, PagerDuty|  | SNS, Pub/Sub     |
| Schema outils    |  | Opsgenie, etc. |  | InfluxDB, S3     |
+------------------+  +----------------+  +------------------+
```

## Developpement

```bash
cargo build
cargo test
```

## Avertissement

CE LOGICIEL EST FOURNI "TEL QUEL", SANS GARANTIE D'AUCUNE SORTE, EXPLICITE OU IMPLICITE. EN AUCUN CAS LES AUTEURS, CONTRIBUTEURS OU DETENTEURS DU COPYRIGHT NE POURRONT ETRE TENUS RESPONSABLES DE TOUT DOMMAGE, RECLAMATION OU AUTRE RESPONSABILITE DECOULANT DE, OU EN LIEN AVEC LE LOGICIEL OU SON UTILISATION.

**kxn est un outil de scan de compliance, pas une garantie de securite.** Il identifie les mauvaises configurations et vulnerabilites connues a partir de regles et bases de donnees publiques (NVD, CISA KEV, benchmarks CIS), mais il ne remplace pas les audits de securite professionnels, les tests de penetration ou la revue d'experts. Vous etes seul responsable de la securite de votre infrastructure et de la validation des resultats de scan avant d'agir.

Les donnees CVE proviennent de feeds publics (NVD, CISA, EPSS) et peuvent etre incompletes, en retard ou contenir des inexactitudes. Verifiez toujours les resultats independamment.

## Licence

[BSL 1.1](LICENSE) — Gratuit pour usage non-concurrent. Passage a Apache 2.0 le 25/03/2030.
