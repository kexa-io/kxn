<p align="center">
  <img src="assets/logo.png" alt="kxn" width="120">
</p>

<h1 align="center">kxn — Kexa Next Gen</h1>

<p align="center"><strong>Small. Fast. Relentless.</strong></p>

<p align="center">Multi-cloud compliance scanner in Rust. 9 native providers + 3000 via Terraform. 1770 rules. Single binary.</p>

<p align="center">
  <a href="README.md">EN</a> |
  <a href="README.fr.md">FR</a> |
  <a href="README.es.md">ES</a> |
  <a href="README.pt.md">PT</a> |
  <a href="README.de.md">DE</a> |
  <a href="README.ja.md">JA</a> |
  <a href="README.ko.md">KO</a> |
  <a href="README.zh.md">ZH</a> |
  <a href="README.ar.md">AR</a> |
  <a href="README.hi.md">HI</a> |
  <a href="README.ru.md">RU</a> |
  <a href="README.it.md">IT</a> |
  <a href="README.tr.md">TR</a>
</p>

```
$ kxn ssh://root@server
kxn | ssh://root@server | 289 rules (12 files) from ~/.cache/kxn/rules

target | 171/2799 passed | 2628 violations | 65ms

   #  Level  Rule                                  Resource              Message
────  ─────  ────────────────────────────────────  ────────────────────  ──────────────────────────────
   1  WARN   pve-no-pending-updates                packages              upgradable_count EQUAL Numb...
   2  ERROR  apache-cis-2.3-server-tokens          apache_config         servertokens EQUAL String("...
   3  ERROR  apache-cis-2.4-server-signature       apache_config         serversignature EQUAL Strin...
   4  ERROR  apache-cis-2.5-no-directory-listing   apache_config         options_indexes EQUAL Strin...
   5  FATAL  apache-cis-3.1-deny-root-directory    apache_config         root_directory_access EQUAL...
   6  ERROR  apache-cis-3.2-no-htaccess-override   apache_config         allowoverride EQUAL String(...
   7  ERROR  apache-cis-3.3-default-deny           apache_config         default_access EQUAL String...
```

```
$ kxn remediate ssh://root@server

  134 remediable violations  │  13 fatal  77 error  44 warn

  ── APACHE-CIS
    1  ERROR  apache-cis-2.3-server-tokens
              CIS 2.3 - Ensure ServerTokens is set to 'Prod' to minimize information disclosure
              shell: sed -i 's/^#\?\s*ServerTokens.*/ServerTokens Prod/' /etc/httpd/conf/httpd.conf
    2  ERROR  apache-cis-2.4-server-signature
              CIS 2.4 - Ensure ServerSignature is set to 'Off' to prevent version leakage
              shell: sed -i 's/^#\?\s*ServerSignature.*/ServerSignature Off/' /etc/httpd/conf/httpd.c

$ kxn remediate ssh://root@server --rule docker-cis-1.4
1 remediation(s) to apply:

  [docker-cis-1.4-docker-sock-permissions] CIS 1.4 - Ensure docker.sock file permissions are set to 660 or more restrictive
    -> shell: chmod 660 /var/run/docker.sock
    => APPLIED (1/1)

Done: 1/1 remediations applied.
```

## Install

```bash
# macOS / Linux (Homebrew)
brew install kexa-io/tap/kxn

# From source
cargo install --git https://github.com/kexa-io/kxn kxn-cli

# Download binary
curl -fsSL https://github.com/kexa-io/kxn/releases/latest/download/kxn-$(uname -m)-$(uname -s | tr A-Z a-z).tar.gz | tar xz

# Docker
docker pull kexa/kxn:latest
```

## Docker quick scan

No install required — pull and scan any target in one command.

```bash
# Scan a server over SSH
docker run --rm kexa/kxn:latest ssh://root@192.168.1.10

# Scan a Kubernetes cluster (uses your local kubeconfig)
docker run --rm -v ~/.kube:/root/.kube:ro kexa/kxn:latest kubernetes://my-cluster

# Scan in-cluster (from a pod with ServiceAccount)
docker run --rm -e K8S_INSECURE=true kexa/kxn:latest kubernetes://in-cluster

# Scan with a custom rule file and output to JSON
docker run --rm \
  -v $(pwd)/rules:/rules:ro \
  kexa/kxn:latest scan \
  --provider kubernetes \
  --rules /rules/pods-not-running.toml \
  -o json

# Continuous monitoring with Discord alerts
docker run -d \
  -v $(pwd)/kxn.toml:/etc/kxn/kxn.toml:ro \
  -e DISCORD_WEBHOOK="https://discord.com/api/webhooks/..." \
  kexa/kxn:latest watch --config /etc/kxn/kxn.toml --webhook "$DISCORD_WEBHOOK"
```

## Scan anything

```bash
# Servers
kxn ssh://root@server

# Databases
kxn postgresql://user:pass@host:5432
kxn mysql://user:pass@host:3306
kxn mongodb://user:pass@host:27017

# Kubernetes
kxn kubernetes://cluster                     # 26 resource types, CIS K8s benchmark

# GitHub
kxn github://org                             # repos, webhooks, actions, RBAC

# Web / APIs
kxn https://example.com                      # TLS, headers, OWASP
kxn grpc://host:9090                         # health, reflection

# CVE detection
kxn cve-update                               # sync NVD + CISA KEV + EPSS
kxn ssh://root@server                        # detects CVEs in installed packages

# Any Terraform provider (3000+)
kxn scan --provider aws --provider-config '{"region":"eu-west-1"}'
kxn scan --provider google --provider-config '{"project":"my-project"}'
kxn scan --provider cloudflare
```

## Output formats

```bash
kxn ssh://root@server                        # colorized minimal (default)
kxn ssh://root@server -o table               # table with columns
kxn ssh://root@server -o json                # structured JSON
kxn ssh://root@server -o csv                 # CSV for spreadsheets
kxn ssh://root@server -o sarif               # SARIF for GitHub Security
kxn ssh://root@server -o html                # standalone HTML report
```

## Fix violations

```bash
# List remediable violations
kxn remediate ssh://root@server

# Apply specific fixes (by number or name)
kxn remediate ssh://root@server --rule 1 --rule 4
kxn remediate ssh://root@server --rule ssh-cis-5.2.10

# Apply all fixes matching a pattern
kxn remediate ssh://root@server --apply-filter apache-cis

# Dry-run (show what would happen)
kxn remediate ssh://root@server --rule 1 --dry-run
```

Remediation actions: shell commands, SQL queries, webhooks, binaries. Defined per-rule in TOML.

## Continuous monitoring

```bash
# Daemon mode (scans every 60s, alerts on violations)
kxn watch -c kxn.toml

# Quick monitor with alerts
kxn monitor ssh://root@server --alert slack://hooks.slack.com/T/B/x

# Centralized log collection — SSH or Kubernetes
kxn logs ssh://root@server                   # SSH journal
kxn logs kubernetes://in-cluster             # K8s pod error/warn/fatal lines
kxn logs                                     # all targets from kxn.toml
kxn logs --level error --source auth         # filtered

# Save results to databases / observability backends
kxn monitor ssh://root@server --save postgresql://localhost:5432/kxn
kxn monitor ssh://root@server --save elasticsearch://localhost:9200/kxn
kxn monitor ssh://root@server --save loki://loki.monitoring.svc:3100

# Prometheus metrics
kxn watch -c kxn.toml --metrics-port 9090
```

## AI agent integration

kxn is built for AI agents. Any agent (Claude, GPT, Gemini, Copilot) can scan, validate, and remediate infrastructure.

```bash
# One-command setup for 7 AI clients
kxn init --client claude-code                # MCP server
kxn init --client claude-desktop
kxn init --client cursor
kxn init --client windsurf
kxn init --client codex
kxn init --client gemini
kxn init --client opencode

# Export tool schemas for any framework
kxn tools                                    # OpenAI format
kxn tools -f anthropic                       # Anthropic format

# MCP server (5 tools: scan, gather, check, cve_lookup, remediate)
kxn serve
```

Agent workflow:
```
Agent: "deploy to production"
  1. kubectl apply -f deployment.yaml
  2. kxn kubernetes://cluster -o json   -> 0 violations -> continue
  3. kxn ssh://root@node -o json        -> 2 CRITICAL CVEs -> alert
  4. kxn remediate ssh://root@node      -> auto-fix
  5. kxn ssh://root@node -o json        -> 0 violations -> done
```

## CVE detection

Local SQLite database synced from public feeds. Zero API calls during scans.

```bash
kxn cve-update                               # sync NVD + CISA KEV + EPSS
kxn ssh://root@server                        # detects CVEs in installed packages
```

| Feed | Source | Entries |
|------|--------|---------|
| NVD | nist.gov | 29K+ CVEs |
| CISA KEV | cisa.gov | 1555 actively exploited |
| EPSS | first.org | 5000 top exploit probability |

Lookup: < 1ms per package. Offline. Air-gap compatible.

## Providers

| Provider | URI | Resources |
|----------|-----|-----------|
| SSH | `ssh://user@host` | sshd_config, sysctl, users, services, packages, CVEs, logs, system_stats |
| PostgreSQL | `postgresql://` | databases, roles, settings, extensions, stats, logs |
| MySQL | `mysql://` | databases, users, grants, variables, status, stats, logs |
| MongoDB | `mongodb://` | databases, users, serverStatus, currentOp, stats, logs |
| Oracle | `oracle://` | users, tables, privileges, sessions, parameters (optional feature) |
| Kubernetes | `k8s://` | 26 types: pods, deployments, services, RBAC, network policies, metrics |
| GitHub | `github://org` | repos, webhooks, actions, teams, Dependabot, branch protection |
| HTTP | `https://` | status, headers, TLS certificate, timing, OWASP checks |
| gRPC | `grpc://` | health, connection, reflection |
| CVE | `cve://` | NVD, CISA KEV, EPSS feeds |
| **Terraform** | any | **3000+ providers** (AWS, Azure, GCP, Cloudflare, Datadog, Okta...) via gRPC bridge |

## Rules

736+ TOML rules covering CIS benchmarks, OWASP API Top 10, CVE detection, IAM, TLS, monitoring.

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

  [[rules.remediation]]
  type = "shell"
  command = "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart sshd"
  timeout = 15
```

| Category | Rules | Frameworks |
|----------|-------|-----------|
| SSH/Linux CIS | ~120 | CIS, SOC2, PCI-DSS |
| Kubernetes CIS | ~80 | CIS K8s, NIST |
| Database CIS | ~80 | CIS PostgreSQL/MySQL/MongoDB/Oracle |
| Cloud CIS | ~150 | CIS AWS/Azure/GCP, IAM |
| Web/API | ~60 | OWASP API Top 10, TLS |
| CVE/Packages | ~20 | NVD, CISA KEV |
| Monitoring | ~150 | Custom health checks |
| Docker/Nginx/Apache | ~75 | CIS Docker, CIS Nginx |

16 condition operators: `EQUAL`, `DIFFERENT`, `SUP`, `INF`, `REGEX`, `INCLUDE`, `STARTS_WITH`, `ENDS_WITH`, `DATE_INF`, `DATE_SUP`, nested `AND`/`OR`/`NAND`/`NOR`/`XOR`.

## Alert backends (13)

Slack, Discord, Teams, Email (SMTP), SMS (Twilio), Jira, PagerDuty, Opsgenie, ServiceNow, Linear, Splunk, Zendesk, Kafka.

## Save backends (17)

PostgreSQL, MySQL, MongoDB, Elasticsearch, OpenSearch, S3, GCS, Azure Blob, Kafka, Event Hubs, SNS, Pub/Sub, Redis, Splunk HEC, InfluxDB, **Grafana Loki**, JSONL file.

HTTP backends (Elasticsearch, Splunk HEC, Loki) support optional `compression = "gzip"` on the `[[save]]` block — reduces egress on repetitive NDJSON payloads (typically ~8× on scan batches).

## Configuration

```toml
# kxn.toml
[rules]
min_level = 1

[[rules.mandatory]]
name = "ssh-cis"
path = "rules/ssh-cis.toml"

[[targets]]
name = "production-server"
provider = "ssh"
uri = "ssh://root@${secret:env:PROD_HOST}"
rules = ["ssh-cis-*", "ssh-monitoring"]
interval = 300

[[targets]]
name = "production-db"
provider = "postgresql"
uri = "postgresql://admin:${secret:vault:prod/db-password}@db.internal:5432"
rules = ["postgresql-*"]

[[save]]
type = "elasticsearch"
url = "elasticsearch://localhost:9200/kxn"
compression = "gzip"                         # optional, HTTP backends only

[[save]]
type = "postgres"
url = "postgresql://kxn:kxn@localhost:5432/kxn"

[[save]]
type = "loki"                                # Grafana Loki — scans, metrics, logs
url = "loki://loki.monitoring.svc:3100"
origin = "kxn-prod"
compression = "gzip"
```

Secret interpolation: `${secret:env:VAR}`, `${secret:aws:name/key}`, `${secret:azure:vault/name}`, `${secret:vault:path/key}`, `${secret:gcp:project/name}`.

## Architecture

```
+----------------------------------------------------------------+
|                          kxn-cli                               |
|                                                                |
|  kxn <URI>              one-shot scan                          |
|  kxn watch              continuous daemon                      |
|  kxn logs               centralized log collection             |
|  kxn remediate          scan + fix violations                  |
|  kxn serve              MCP server for AI agents               |
|  kxn cve-update         sync CVE database                     |
+----------------------------------------------------------------+
         |                    |                    |
         v                    v                    v
+------------------+  +----------------+  +------------------+
|   kxn-rules      |  |   kxn-core     |  |  kxn-providers   |
|                  |  |                |  |                  |
| TOML parser      |  | Rules engine   |  | 9 native         |
| 1770+ rules      |  | 16 conditions  |  | providers        |
| CIS/OWASP maps   |  | Nested logic   |  |                  |
|                  |  |                |  | Terraform gRPC   |
|                  |  |                |  | bridge (3000+)   |
+------------------+  +----------------+  +------------------+
         |                    |                    |
         v                    v                    v
+------------------+  +----------------+  +------------------+
|   kxn-mcp        |  |   alerts (13)  |  |   save (16)      |
|                  |  |                |  |                  |
| MCP server       |  | Slack, Teams   |  | PostgreSQL, ES   |
| 7 AI clients     |  | Email, SMS     |  | Kafka, S3, GCS   |
| 5 tools          |  | Jira, PagerDuty|  | InfluxDB, Redis  |
+------------------+  +----------------+  +------------------+
```

## Development

```bash
cargo build                    # build all crates
cargo test                     # run tests
cargo clippy                   # lint
```

5 crates: `kxn-cli`, `kxn-core`, `kxn-rules`, `kxn-providers`, `kxn-mcp`.

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. kxn is a compliance scanning tool, not a guarantee of security. It identifies known misconfigurations and vulnerabilities based on public rules and databases (NVD, CISA KEV, CIS Benchmarks), but does not replace professional security audits. You are solely responsible for the security of your infrastructure and for validating scan results before acting on them.

## License

[BSL 1.1](LICENSE) -- Free for non-competing use. Converts to Apache 2.0 on 2030-03-25.
