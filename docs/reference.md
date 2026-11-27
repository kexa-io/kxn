# kxn reference

The full tour of kxn's command line. Start with the [README](../README.md) and
[Getting started](getting-started.md); come here for every option.

## Docker quick scan

No install required — pull and scan any target in one command.

<!-- x-release-please-start-version -->

```bash
# Scan a server over SSH
docker run --rm kexa/kxn:v0.67.0 ssh://root@192.168.1.10

# Scan a Kubernetes cluster with a context of your kubeconfig (the image runs
# as user kxn; exec plugins such as aws/gcloud are not in the image, so use a
# kubeconfig with a token or client certificate)
docker run --rm -v ~/.kube/config:/home/kxn/.kube/config:ro kexa/kxn:v0.67.0 k8s://my-context

# Scan in-cluster (from a pod with ServiceAccount)
docker run --rm -e K8S_INSECURE=true kexa/kxn:v0.67.0 kubernetes://in-cluster

# Scan with a custom rule file and output to JSON
docker run --rm \
  -v ~/.kube:/home/kxn/.kube:ro \
  -v $(pwd)/rules:/rules:ro \
  kexa/kxn:v0.67.0 k8s://my-context \
  --rules /rules/pods-not-running.toml \
  -o json

# Continuous monitoring with Discord alerts
docker run -d \
  -v $(pwd)/kxn.toml:/etc/kxn/kxn.toml:ro \
  -e DISCORD_WEBHOOK="https://discord.com/api/webhooks/..." \
  kexa/kxn:v0.67.0 watch --config /etc/kxn/kxn.toml --webhook "$DISCORD_WEBHOOK"
```

<!-- x-release-please-end -->

## Scan anything

```bash
# Servers
kxn ssh://root@server

# Network devices over SSH: the OS is detected (or forced with ?os=)
kxn get ssh://audit@10.0.0.254 device -o table       # vendor, os, version, model, hostname
kxn ssh://audit@fw01?os=fortios                      # ios, ios-xe, nx-os, asa, eos, junos,
                                                     # srlinux, routeros, fortios, pan-os

# Databases
kxn postgresql://user:pass@host:5432
kxn mysql://user:pass@host:3306
kxn mongodb://user:pass@host:27017

# Kubernetes (a kubeconfig context, the in-cluster ServiceAccount,
# or K8S_API_URL + K8S_TOKEN + K8S_CA_FILE)
kxn k8s://my-context                         # 70 resource types, CIS K8s benchmark

# Cloud (native providers)
kxn aws://eu-west-1                          # region is required
kxn azure://<subscription-id>
kxn gcp://my-project

# Web / APIs
kxn https://example.com                      # TLS, headers, OWASP
kxn grpc://host:9090                         # health, reflection

# CVE detection
kxn cve-update                               # sync NVD, CISA KEV, EPSS and distro trackers
kxn ssh://root@server                        # detects CVEs in installed packages

# GitHub, Docker, Forgejo, Google Workspace
kxn github://my-org                          # GITHUB_TOKEN, or your `gh` login
kxn docker://                                # local socket, Unix only
kxn forgejo://git.example.com/owner/repo     # FORGEJO_TOKEN
kxn googleworkspace://example.com

# Any Terraform provider (3000+), via the gRPC bridge
kxn gather -p hashicorp/aws -t aws_instance -C '{"region":"eu-west-1"}'
```

## Output formats

```bash
kxn ssh://root@server                        # text table (default)
kxn ssh://root@server -o json                # structured JSON
kxn ssh://root@server -o csv                 # CSV for spreadsheets
kxn ssh://root@server -o html                # standalone HTML report
kxn ssh://root@server -o minimal             # condensed summary by level
```

Quick-scan formats: `text`, `json`, `csv`, `toml`, `html`, `minimal`, `quiet`, `compact`, `ia`. SARIF is produced by `kxn scan --output sarif` (resources as JSON on stdin).

## Compliance frameworks

```bash
kxn ssh://root@server --framework nis2            # NIS2 rules only, then a table per NIS2 measure
kxn azure://<subscription> --framework gdpr,soc2  # several frameworks (rgpd = gdpr)
kxn list-rules -R rules --framework soc2          # the rules that count for SOC 2
```

Every security rule maps to NIS2 (art. 21(2)), SOC 2 and GDPR, on every
provider. See [Compliance frameworks](compliance-frameworks.md).

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

Remediation actions, defined per rule in TOML: shell commands, SQL queries, Lua scripts, webhooks, binaries, Azure service principal secret rotation (`rotateSPSecret`) and GCP service account key rotation (`rotateSAKey`). Host fixes (shell, SQL, Lua) run once per rule; per-resource fixes (rotations, webhook, binary) run for every violation. A shell fix that exits non-zero counts as failed. When a selected fix does not fully apply, `kxn remediate` reports `PARTIAL (n/m)` or `FAILED` and exits 1; `--dry-run` exits 0.

## Continuous monitoring

```bash
# Daemon mode (scans every 60s, alerts on violations)
kxn watch -c kxn.toml

# Quick monitor with alerts
kxn monitor ssh://root@server --alert slack://hooks.slack.com/T/B/x

# Centralized log collection — SSH or Kubernetes
kxn logs ssh://root@server                   # SSH journal
kxn logs postgresql://user@db:5432/postgres # database log (also mysql://, mongodb://, oracle://)
kxn logs mongodb://admin@db:27017 -f        # keep polling for new lines
kxn logs kubernetes://in-cluster             # K8s pod log lines (--level error to filter)
kxn logs                                     # all targets from kxn.toml
kxn logs --level error --source auth         # filtered

# Save results to databases / observability backends
kxn monitor ssh://root@server --save postgresql://localhost:5432/kxn
kxn monitor ssh://root@server --save elasticsearch://localhost:9200/kxn
kxn monitor ssh://root@server --save loki://loki.monitoring.svc:3100

# Prometheus metrics (scan results; add --metrics-resources for per-pod/node CPU & RAM gauges; series listed in docs/metrics.md)
# Binds 0.0.0.0 by default: set a bearer token (--metrics-token or KXN_METRICS_TOKEN),
# or restrict with --metrics-bind 127.0.0.1
kxn watch -c kxn.toml --metrics-port 9090 --metrics-token "$KXN_METRICS_TOKEN"
kxn watch -c kxn.toml --metrics-port 9090 --metrics-bind 127.0.0.1 --metrics-resources
kxn watch -c kxn.toml --usage-interval 10s      # CPU/RAM every 10 s (5s, 1s), rollups + 5m/1h tiers in Postgres

# Kubernetes right-sizing: usage vs requests → recommended requests (KRR-style)
kxn recommend kubernetes://in-cluster                       # table, 14d history from [[save]] postgres or 1 live sample
kxn recommend -n app --samples 5 --every 1m --format toon   # live sampling, TOON output for an LLM prompt
kxn recommend --window 7d --format pdf -o rightsizing.pdf   # printable report
kxn recommend --patch-dir ./patches                         # strategic-merge patches per workload; --apply [--yes] patches via the API
```

## AI agent integration

kxn is built for AI agents. Any agent (Claude, GPT, Gemini, Copilot) can scan, validate, and remediate infrastructure.

```bash
# Register the MCP server with every installed agent (21 supported)
kxn init --mcp-only
kxn init --mcp-only --client cursor          # one agent; repeatable
# claude-code, claude-desktop, copilot, vscode, cursor, gemini, codex, vibe, droid,
# trae, opencode, openclaw, pi, omp, hermes, windsurf, cline, roo, kilocode,
# antigravity, kimi. See docs/agent-integration.md for each config file.

# Export tool schemas for any framework
kxn tools                                    # OpenAI format
kxn tools -f anthropic                       # Anthropic format

# MCP server (9 tools: kxn_list_providers, kxn_list_resource_types,
# kxn_list_rules, kxn_provider_schema, kxn_gather, kxn_scan,
# kxn_check_resource, kxn_list_targets, kxn_remediate)
kxn serve --mcp
```

Agent workflow:
```
Agent: "deploy to production"
  1. kubectl apply -f deployment.yaml
  2. kxn k8s://my-context -o json      -> 0 violations -> continue
  3. kxn ssh://root@node -o json        -> 2 CRITICAL CVEs -> alert
  4. kxn remediate ssh://root@node      -> auto-fix
  5. kxn ssh://root@node -o json        -> 0 violations -> done
```

### Prompts for AI assistants

Copy one of these prompts into your assistant. Both use commands that exist in this repository.

<details>
<summary><strong>Install kxn in Kubernetes (read-only)</strong></summary>

You install kxn (kexa/kxn) in a Kubernetes cluster, read-only.

Constraints:
- Image pinned to an exact tag: docker.io/kexa/kxn:v0.67.0. Never use :latest. <!-- x-release-please-version -->
- Dedicated ServiceAccount, bound only to the built-in ClusterRole "view". No write permission.
- Start from deploy/kubernetes/kxn-watch-readonly.yaml in the kxn repository. Change only the namespace, the image tag and the targets. Do not write the manifests from scratch.
- Never print a secret in the output.

Steps, in order:
1. Namespace and ServiceAccount, with a ClusterRoleBinding to "view".
2. Rules: an initContainer runs `kxn rules pull --dir /rules` into a shared emptyDir volume. The rules are not fetched at runtime.
3. kxn.toml: one [[targets]] entry with uri = "kubernetes://in-cluster". "provider" is optional when "uri" is set. A [rules] section is optional.
4. Run: kxn -c /etc/kxn/kxn.toml watch -R /rules --metrics-port 9090 --interval 300
5. Verify:
   - The log shows "rules=N" with N > 0.
   - The log shows "#1 OK" or "#1 FAIL" with the number of checks.
   - curl with the bearer token from the kxn-metrics secret (never print it) on http://<service>:9090/metrics returns kxn_rules_total, kxn_rules_passed, kxn_rules_failed. Without the token the answer is 401.

If the output says:
- "No rules loaded": the initContainer did not run or wrote to another path. Check its logs and the -R value. Do not change the rules.
- "no provider specified": add uri = "kubernetes://in-cluster" to the target.
- "forbidden" from the Kubernetes API: the ServiceAccount is missing the ClusterRoleBinding to "view". Do not add write permissions to fix it.
- Port 9090 closed: `--metrics-port` is an option of `watch` (and `logs`), not of `kxn monitor`, which does not expose metrics.

Return the YAML files ready to apply, then the list of verification commands.

Full version with the same content: [docs/ai-install-prompt.md](ai-install-prompt.md).

</details>

<details>
<summary><strong>Scan and fix infrastructure</strong></summary>

```text
You audit infrastructure with kxn (kexa/kxn).

- Scan with JSON output: `kxn <uri> -o json`. Targets: ssh://user@host, kubernetes://in-cluster (or kubernetes://cluster with K8S_API_URL + K8S_TOKEN), postgresql://..., https://...
- Summarize violations by level (fatal, error, warning, info) and by rule name.
- Before any fix, list the remediable violations with `kxn remediate <uri>` and run `kxn remediate <uri> --rule <name> --dry-run`.
- Apply a fix only if I confirm it. Then rescan and report the difference.
- Never print passwords, tokens or webhook URLs from the output.
```

</details>

## CVE detection

Local SQLite database synced from public feeds. Zero API calls during scans.

```bash
kxn cve-update                               # sync NVD, CISA KEV, EPSS and distro trackers
kxn ssh://root@server                        # detects CVEs in installed packages
```

| Feed | Source | Entries |
|------|--------|---------|
| NVD | nist.gov | CVEs modified in the last 120 days on the first sync, then every change since the last sync |
| CISA KEV | cisa.gov | The full Known Exploited Vulnerabilities catalog |
| EPSS | first.org | The 5000 highest exploit probabilities |
| Distro trackers | Debian, Ubuntu, Alpine, AlmaLinux | Security advisories per distribution (AlmaLinux data also covers Rocky, RHEL and CentOS Stream) |

Lookup: < 1ms per package. Offline. Air-gap compatible.

## Providers

| Provider | URI / access | Resources |
|----------|-----|-----------|
| SSH | `ssh://user@host` | sshd_config, sysctl, users, services, packages, CVEs, logs, system_stats |
| Local | `local://` | the machine kxn itself runs on — no remote connection needed |
| Docker | `docker://` | containers, images, daemon config — local socket, no SSH needed (Unix only) |
| PostgreSQL | `postgresql://` | databases, roles, settings, extensions, stats, logs |
| MySQL | `mysql://` | databases, users, grants, variables, status, stats, logs |
| MongoDB | `mongodb://` | databases, users, serverStatus, currentOp, stats, logs |
| Oracle | `oracle://` | users, tables, privileges, sessions, parameters (behind the `oracle` build feature, not compiled in by default) |
| Kubernetes | `kubernetes://` / `k8s://` | 70 types: workloads, RBAC, network policies, metrics, admission control, plus Istio/Argo CD/cert-manager/Prometheus Operator/Flux resources when those CRDs are installed. Uses a kubeconfig context (`k8s://<context>`), the in-cluster ServiceAccount, or K8S_API_URL + K8S_TOKEN / client cert + K8S_CA_FILE |
| Helm | `helm://` | Helm releases in the cluster (same Kubernetes credentials) |
| AWS (native) | `aws://<region>` | IAM, S3, VPC/security groups, EBS, RDS, EKS, ECR, KMS, CloudTrail, SNS/SQS (credentials from env or the `aws` CLI) |
| Azure (native) | `azure://<subscription-id>` | NSGs, VMs, container registries, MySQL flexible servers, Network Watcher, Log Analytics, diagnostic settings, Defender pricing (Azure Resource Manager) |
| GCP (native) | `gcp://<project>` | service account keys, compute, firewall, GKE, buckets, BigQuery, logging sinks |
| Microsoft Graph | `msgraph://` / `microsoft.graph://` | Entra ID service principal/app registration auditing |
| GitHub | `github://<org>` (`GITHUB_TOKEN` or `gh` login) | organization, repos, webhooks, actions, teams, Dependabot, branch protection |
| Forgejo/Gitea | `forgejo://<host>[/<owner>/<repo>]` (`FORGEJO_TOKEN`) | CI/CD pipeline runs, jobs and logs — self-hosted git Actions history |
| Google Workspace | `googleworkspace://<domain>` | users, groups, domains, devices, role assignments, OAuth tokens |
| HTTP | `https://` | status, headers, TLS certificate, timing, OWASP checks |
| gRPC | `grpc://` | health, connection, reflection |
| Prometheus | `prometheus://` | scrape any Prometheus exposition-format endpoint into metric records |
| CVE | `cve://` | NVD, CISA KEV, EPSS feeds |
| **Terraform** | `kxn gather -p hashicorp/<name>` | **3000+ providers** (AWS, Azure, GCP, Cloudflare, Datadog, Okta...) via gRPC bridge — not usable as `kxn watch` targets |

Full list at runtime: `kxn list-providers` — see [docs/providers.md](providers.md) for detailed resource types per provider.

## Rules

1,500+ TOML rules covering CIS benchmarks, OWASP API Top 10, CVE detection, IAM, TLS, monitoring, each security rule mapped to NIS2, SOC 2 and GDPR.

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
| SSH/Linux CIS | 81 | CIS, SOC2, PCI-DSS |
| Kubernetes CIS | 108 | CIS K8s, NIST |
| Database CIS | 183 | CIS PostgreSQL/MySQL/MongoDB/Oracle/Cassandra |
| Database DBA and security | 124 | DBA checks, Oracle security |
| Cloud CIS | 250 | CIS AWS/Azure/GCP, IAM |
| Cloud best practices and secret rotation | 52 | AWS, Azure, GCP, Vault |
| Microsoft 365 | 189 | CIS M365, CISA SCuBA, Intune |
| Google Workspace | 175 | CIS Google Workspace, CISA SCuBA |
| GitHub/GitLab | 26 | Security settings |
| Web/API/gRPC | 120 | OWASP API Top 10, TLS |
| CVE/Packages | 17 | NVD, CISA KEV |
| Monitoring | 131 | Custom health checks |
| Docker/Nginx/Apache | 92 | CIS Docker, CIS Nginx, CIS Apache |
| Other (Proxmox, Windows updates) | 7 | |

34 condition types — equality/comparison (`EQUAL`, `DIFFERENT`, `SUP`, `INF`, `SUP_OR_EQUAL`, `INF_OR_EQUAL`), string (`INCLUDE`, `NOT_INCLUDE`, `INCLUDE_NOT_SENSITIVE`, `NOT_INCLUDE_NOT_SENSITIVE`, `STARTS_WITH`, `NOT_STARTS_WITH`, `ENDS_WITH`, `NOT_ENDS_WITH`, `REGEX`, `NOT_REGEX`), array quantifiers (`ALL`, `NOT_ANY`, `SOME`, `ONE`), array counting (`COUNT`, `COUNT_SUP`, `COUNT_INF`, `COUNT_SUP_OR_EQUAL`, `COUNT_INF_OR_EQUAL`), dates (`DATE_EQUAL`, `DATE_SUP`, `DATE_INF`, `DATE_SUP_OR_EQUAL`, `DATE_INF_OR_EQUAL`, `DATE_INTERVAL`), ranges/sets (`INTERVAL`, `IN`, `NOT_IN`) — plus 7 logical operators for nesting: `AND`, `OR`, `NAND`, `NOR`, `XOR`, `XNOR`, `NOT`. Full semantics in [docs/rules.md](rules.md).

## Alert backends (14)

Slack, Discord, Teams, Google Chat, Email (SMTP), SMS (Twilio), Jira, PagerDuty, Opsgenie, ServiceNow, Linear, Splunk, Zendesk, Kafka.

## Save backends (19)

PostgreSQL, MySQL, MongoDB, Cassandra, SQL Server, Elasticsearch, OpenSearch, S3, GCS, Azure Blob, Kafka, Event Hubs, SNS, Pub/Sub, Redis, Splunk HEC, InfluxDB, **Grafana Loki**, JSONL file.

Every backend stores scan results and metrics. `kxn logs` lines go to PostgreSQL, MySQL, MongoDB, Cassandra, SQL Server, Elasticsearch / OpenSearch, Loki, Kafka, Splunk HEC and JSONL files. See [what each backend stores](alerting-and-saving.md#what-each-backend-stores).

The Elasticsearch/OpenSearch and Splunk HEC backends support optional `compression = "gzip"` on the `[[save]]` block — reduces egress on repetitive NDJSON payloads (typically ~8× on scan batches). Other backends, Loki included, ignore it.

## Configuration

```toml
# kxn.toml
[rules]
min_level = 1

[[rules.mandatory]]
name = "ssh-cis"
path = "rules/ssh-cis.toml"

[[rules.mandatory]]
name = "ssh-monitoring"
path = "rules/ssh-monitoring.toml"

[[rules.mandatory]]
name = "postgresql-cis"
path = "rules/postgresql-cis.toml"

[[targets]]
name = "production-server"
provider = "ssh"
uri = "ssh://root@${secret:env:PROD_HOST}"
rules = ["ssh-cis", "ssh-monitoring"]        # rule-set names (globs allowed, e.g. "ssh-*")
interval = 300

[[targets]]
name = "production-db"
provider = "postgresql"
uri = "postgresql://admin:${secret:vault:prod/db-password}@db.internal:5432"
rules = ["postgresql-*"]

[[save]]
type = "elasticsearch"
url = "elasticsearch://localhost:9200/kxn"
compression = "gzip"                         # optional, Elasticsearch/Splunk HEC only

[[save]]
type = "postgres"
url = "postgresql://kxn:kxn@localhost:5432/kxn"

[[save]]
type = "loki"                                # Grafana Loki — scans, metrics, logs
url = "loki://loki.monitoring.svc:3100"
origin = "kxn-prod"
```

Secret interpolation: `${VAR}` or `${secret:env:VAR}`, `${secret:aws:name/key}`, `${secret:azure:vault/name}`, `${secret:vault:path/key}`, `${secret:gcp:project/name}`. Azure and GCP references are split on the first `/`, so the vault or project name cannot contain a `/`; AWS and Vault references are split on the last `/`, so a secret name or KV path may contain `/` and the last segment is the key. Backends need credentials: AWS from env or the `aws` CLI, Azure Key Vault from `AZURE_CLIENT_ID`/`AZURE_CLIENT_SECRET`/`AZURE_TENANT_ID`, Vault from `VAULT_ADDR`+`VAULT_TOKEN` (or `HCP_*`), GCP from application default credentials. See [docs/configuration.md](configuration.md).

## Development

```bash
cargo build                    # build all crates
cargo test                     # run tests
cargo clippy                   # lint
```

6 crates: `kxn-cli`, `kxn-core`, `kxn-rules`, `kxn-providers`, `kxn-mcp`, `kxn-wasm`.
