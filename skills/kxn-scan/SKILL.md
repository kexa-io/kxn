---
name: kxn-scan
description: |
  Use kxn (https://kxn.kexa.io) to scan and remediate infrastructure compliance,
  CVEs, and configuration issues across SSH/Linux servers, Kubernetes clusters,
  PostgreSQL/MySQL/MongoDB databases, GitHub orgs, HTTP/gRPC endpoints, and any
  Terraform-managed cloud resource. Trigger when the user asks to audit, scan,
  check, or harden infrastructure, list CVEs, or auto-remediate violations.
---

# kxn-scan — Drive kxn from natural language

This skill lets Claude pilot **kxn**, a Rust compliance scanner that turns natural-language requests like *"audit my server"* into the right scan against the right target.

## When to use this skill

Activate this skill whenever the user asks to:

- **Audit / scan / check** infrastructure (servers, databases, K8s, GitHub, HTTP endpoints, Terraform-managed cloud resources).
- **Look for CVEs** in installed packages or against the CISA KEV catalog.
- **Harden** something against a known benchmark (CIS, NIST 800-53, PCI-DSS, SOC-2, ISO 27001, OWASP API Top 10).
- **Remediate** detected violations (list, dry-run, apply).
- **Set up monitoring** (continuous scan loop, Prometheus metrics, log forwarding to Loki, webhook alerts to Discord/Slack/Teams).

If the user just wants generic infosec advice with no specific target, this skill is **not** the right fit — answer from your own knowledge.

## Pre-flight check

Before running anything, verify kxn is installed and remember its version:

```bash
kxn --version
```

If the command is not found, suggest one of these install paths and stop until the user confirms:

- macOS / Linux: `brew install kexa-io/tap/kxn`
- Linux binary: `curl -L https://github.com/kexa-io/kxn/releases/latest/download/kxn-x86_64-unknown-linux-gnu.tar.gz | tar -xz && sudo mv kxn /usr/local/bin/`
- Windows: download `kxn-x86_64-pc-windows-msvc.zip` from <https://github.com/kexa-io/kxn/releases/latest>
- Docker: `docker run --rm kexa/kxn:latest <uri>`
- Build: `cargo install --git https://github.com/kexa-io/kxn kxn-cli`

## Target URI cheat-sheet

kxn takes a URI as its primary argument. Pick the right scheme based on what the user describes:

| User says | URI |
|---|---|
| "my server <host>", "ssh into …" | `ssh://root@<host>` |
| "my postgres at <host>:<port>" | `postgresql://<user>:<pass>@<host>:<port>` |
| "my mysql / mongo / mariadb …" | `mysql://…`, `mongodb://…` |
| "my k8s / kubernetes cluster" | `kubernetes://<context>` (or `kubernetes://in-cluster` from a Pod) |
| "my GitHub org <org>" | `github://<org>` (with `GITHUB_TOKEN` in env) |
| "the HTTPS endpoint <url>" | `https://<host>/...` |
| "the gRPC service at …" | `grpc://<host>:<port>` |
| "a docker host / container" | `docker://localhost` |
| "an AWS / Azure / GCP / Scaleway / OVH / Cloudflare resource" | `kxn gather --provider hashicorp/aws --resource-type all` etc. |

Always **confirm credentials are non-empty** before passing them on the command line. For SSH prefer key-based auth (`SSH_KEY=...`) over inline passwords. For databases prefer environment variables (`PG_HOST`, `PG_USER`, `PG_PASSWORD`, …) when available — the URI form leaks the password into shell history.

## Common workflows

### 1 · One-shot compliance scan

```bash
# Default: text output, all built-in CIS rules
kxn ssh://root@server

# JSON output for parsing inside Claude
kxn ssh://root@server -o json

# Subset of rules — useful when investigating a specific theme
kxn ssh://root@server --include 'ssh-cis-5.2.*'
```

### 2 · CVE detection (offline, sub-millisecond)

```bash
# Sync the local DB once (NVD + KEV + EPSS + Debian/Ubuntu/Alpine/RHEL advisories)
kxn cve-update

# Then any SSH scan also reports CVEs in installed packages
kxn ssh://root@server
```

### 3 · Continuous monitoring loop

```bash
# Re-scan every 30 s, expose Prometheus on :9090, alert Discord on new failures
kxn watch -c kxn.toml --interval 30 --metrics-port 9090 --webhook "$DISCORD_WEBHOOK"
```

A starter `kxn.toml` config the user can paste:

```toml
[[targets]]
name = "my-server"
provider = "ssh"
config = { SSH_HOST = "prod-01" }
interval = 30

[[targets]]
name = "my-pg"
provider = "postgresql"
config = { PG_HOST = "db.prod", PG_USER = "kxn", PG_PORT = "5432", PG_DATABASE = "kxn" }
interval = 60
```

### 4 · Centralized log forwarding (Kubernetes)

```bash
# In-cluster: tails error/warn/fatal lines from every pod, ships to Loki
kxn monitor kubernetes://in-cluster --save loki://loki.monitoring.svc:3100
```

### 5 · Remediation

Always show a **dry-run** first and let the user confirm before applying:

```bash
# List remediation candidates
kxn remediate ssh://root@server

# Show what would change for rule #1
kxn remediate ssh://root@server --rule 1 --dry-run

# Apply once the user confirms
kxn remediate ssh://root@server --rule 1
```

## Reading the output

kxn's text output looks like:

```
kxn | ssh://root@server | 301 rules (12 files) from ./rules
target | 54/180 passed | 126 violations | 2ms

   #  Level  Rule                                  Resource              Message
────  ─────  ────────────────────────────────────  ────────────────────  ──────────────────────────────
   1  FATAL  pkg-cve-kev-exploited                 curl                  CVE-2024-XXXX matches CISA KEV
   2  ERROR  ssh-cis-5.2.10-no-root-login          sshd_config           PermitRootLogin EQUAL no but got yes
   ...
```

When summarizing for the user:

1. **Lead with the headline** — `passed/total` and the **fatal+error count**.
2. **Group violations by theme** — auth, network, packaging, logging, etc.
3. **Surface FATAL first**, then ERROR, then WARN, then INFO. Don't drown the user in INFO.
4. **For each violation, propose the fix** — prefer the kxn `remediate` command when available; otherwise give the manual edit (config file path + line).

For JSON output, the violations live in `targets[].violations[]` with `rule`, `level`, `message`, and `resource` fields. Parse, don't regex.

## Useful tags / filters

```bash
kxn ssh://root@server --tag security        # only security-tagged rules
kxn ssh://root@server --min-level 2         # ERROR + FATAL only
kxn ssh://root@server --any-tag cve,kev     # CVE-related rules only
kxn list-rules                              # full inventory of available rules
kxn list-providers                          # what kxn can scan today
```

## Failure modes — and what to do

| Symptom | Likely cause | Action |
|---|---|---|
| `command not found: kxn` | Not installed | Suggest install path (see Pre-flight). |
| `Error: PostgreSQL URI must include a user` | Anonymous URI | Ask the user for the username, default to `postgres` only for trust-auth contexts. |
| `Error: connection refused` (k8s) | No kubeconfig / wrong context | Run `kubectl config current-context` first; if in a Pod, use `kubernetes://in-cluster`. |
| `No rules found for provider 'X'` | Custom rule dir empty | Pass `-R /path/to/rules` or `kxn rules pull` to download community rules. |
| Scan runs but `0 violations` everywhere | Wrong target type | Verify with `kxn list-providers`; the user may have meant a different scheme. |

## Boundaries — when to defer

- **Don't run remediation without dry-run + user confirmation**, even if the user says "fix it" — show what will change first.
- **Don't pass production secrets in shell args** — propose env vars or a config file.
- **Don't scan third-party infrastructure** the user doesn't own — politely ask for confirmation that they have authorization.
- **For multi-cluster / fleet operations**, build a `kxn.toml` with multiple `[[targets]]` and use `kxn watch` instead of looping scans yourself.

## Reference docs

- Full provider list: <https://github.com/kexa-io/kxn/blob/main/docs/providers.md>
- Rule schema: <https://github.com/kexa-io/kxn/blob/main/docs/rules.md>
- Helm charts (`kxn-monitor`, `kxn-logs`, `kxn-stack`): <https://github.com/kexa-io/kxn/tree/main/deploy/helm>
- Cookbook (full K8s observability stack in 10 min): <https://github.com/kexa-io/kxn/blob/main/docs/cookbook-k8s-monitoring.md>
- Project home: <https://kxn.kexa.io>
