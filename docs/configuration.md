# Configuration

kxn uses a TOML configuration file (`kxn.toml`) for rules, save backends, and daemon targets.

## Config file discovery

kxn searches for `kxn.toml` in this order:

1. `./kxn.toml` (current directory)
2. `~/.config/kxn/kxn.toml`
3. `~/.kxn.toml`

`kxn watch`, `kxn logs` and `kxn scan` only pick up `./kxn.toml` on their own; pass `-c <path>` for any other location.

## Minimal config for `kxn watch`

The smallest working config for daemon mode. `[rules]` is optional.

```toml
[[targets]]
name = "cluster"
provider = "kubernetes"          # optional when uri is set: derived from the scheme
uri = "kubernetes://in-cluster"
```

Run it with an explicit rules directory:

```bash
kxn rules pull                                   # one-time download of community rules
kxn watch --config kxn.toml -R ~/.cache/kxn/rules --metrics-port 9090
```

### Rules directory resolution (`kxn watch`)

Rules for `[[targets]]` are loaded in this order. The first match wins:

1. `-R <dir>` / `--rules <dir>`
2. The `[[rules.mandatory]]` and `[[rules.optional]]` sets in kxn.toml, if any are declared
3. `./rules`
4. `$XDG_CACHE_HOME/kxn/rules`, usually `~/.cache/kxn/rules` (where `kxn rules pull` writes)

The `[rules]` filters (`min_level`, `include`, `exclude`, `tags`) apply in every case.
If no rules are loaded, `kxn watch` exits with an error instead of running with zero rules.

## `[rules]` section

Global filters applied on top of all rule sets.

```toml
[rules]
min_level = 0          # Minimum severity: 0=info, 1=warning, 2=error, 3=fatal
# include = ["ssh-cis-*"]      # Glob patterns: keep only these rule names
# exclude = ["*-deprecated"]   # Glob patterns to exclude rules by name
# tags = ["cis"]               # Keep only rules carrying all of these tags
# source = "https://github.com/kexa-io/kxn-rules/archive/refs/heads/main.tar.gz"
# refresh = "24h"              # How often downloaded rules are checked for changes
```

| Field       | Type       | Default | Description                              |
|-------------|------------|---------|------------------------------------------|
| `min_level` | integer    | `0`     | Only evaluate rules at or above this level |
| `include`   | string[]   | `[]`    | Glob patterns; when set, only matching rule names are kept |
| `exclude`   | string[]   | `[]`    | Glob patterns to exclude rule names      |
| `tags`      | string[]   | `[]`    | Only keep rules that have all of these tags |
| `source`    | string     | kexa-io/kxn-rules archive | URL of a `.tar.gz` archive of rule packs — GitHub, GitLab, Forgejo or any HTTP server (a fork, an internal mirror). Also `KXN_RULES_SOURCE` |
| `refresh`   | duration   | `24h`   | How often the downloaded rules are checked for changes; `"0"` never checks. Also `KXN_RULES_REFRESH` |

Community rules are downloaded into `~/.cache/kxn/rules` the first time a scan
needs them, then checked at most once per `refresh` with one conditional
request: when the archive has not changed the server answers 304 and nothing is
downloaded. `kxn rules pull` checks immediately, `kxn rules pull --force`
downloads in any case. A `./rules` directory or an explicit `--rules` is always
used as is, without any download.

## `[[rules.mandatory]]` -- always enforced

Mandatory rule sets are always evaluated. They cannot be disabled by `--disable`.

```toml
[[rules.mandatory]]
name = "ssh-cis"
path = "rules/ssh-cis.toml"

[[rules.mandatory]]
name = "http-security"
path = "rules/http-security.toml"

[[rules.mandatory]]
name = "monitoring"
path = "rules/monitoring.toml"
```

| Field  | Type   | Required | Description                     |
|--------|--------|----------|---------------------------------|
| `name` | string | yes      | Unique identifier for the set   |
| `path` | string | yes      | Path to the TOML rule file      |

## `[[rules.optional]]` -- toggled by name

Optional rule sets can be enabled or disabled per scan.

```toml
[[rules.optional]]
name = "postgresql-cis"
path = "rules/postgresql-cis.toml"
enabled = true                        # enabled by default

[[rules.optional]]
name = "mysql-cis"
path = "rules/mysql-cis.toml"
enabled = false                       # must be explicitly enabled
```

| Field     | Type   | Required | Default | Description                       |
|-----------|--------|----------|---------|-----------------------------------|
| `name`    | string | yes      |         | Unique identifier for the set     |
| `path`    | string | yes      |         | Path to the TOML rule file        |
| `enabled` | bool   | no       | `false` | Whether the set is on by default  |

CLI overrides:

```bash
kxn scan                          # mandatory + default-enabled optional
kxn scan --enable mysql-cis       # also enable mysql-cis
kxn scan --disable http-security  # disable an optional set
kxn scan --only-mandatory         # only mandatory rules
kxn scan --all                    # everything
```

## `[[save]]` -- persist scan results

Save backends store scan results and metrics (for dashboards, auditing, etc.).

```toml
[[save]]
type = "postgres"
url = "postgresql://user:pass@host:5432/kxn"
origin = "kxn-daemon"
only_errors = false
[save.tags]
environment = "production"
```

| Field         | Type   | Required | Default   | Description                                  |
|---------------|--------|----------|-----------|----------------------------------------------|
| `type`        | string | yes      |           | Backend type (see table below)               |
| `url`         | string | yes      |           | Connection URI (supports secret interpolation)|
| `origin`      | string | no       | `"kxn"`   | Label identifying the scan source            |
| `only_errors` | bool   | no       | `false`   | Only save failing results                    |
| `[save.tags]` | table  | no       | `{}`      | Arbitrary key-value tags attached to records |

Supported `type` values:

| Type                         | URL scheme                                          |
|------------------------------|-----------------------------------------------------|
| `postgres` / `postgresql`    | `postgresql://user:pass@host:5432/db`               |
| `mysql` / `mariadb`          | `mysql://user:pass@host:3306/db`                    |
| `mongodb` / `mongo`          | `mongodb://user:pass@host:27017/db`                 |
| `elasticsearch` / `opensearch` | `elasticsearch://host:9200/index`                 |
| `s3` / `gcs` / `azure`      | `s3://bucket/prefix`, `gs://bucket/prefix`, `az://container/prefix` |
| `kafka`                      | `kafka://broker:8082/topic`                         |
| `eventhubs`                  | `eventhubs://namespace.servicebus.windows.net/hub`  |
| `sns`                        | `sns://arn:aws:sns:region:account:topic`             |
| `pubsub`                     | `pubsub://project/topic`                            |
| `redis`                      | `redis://host:6379/channel`                         |
| `splunkhec`                  | `splunkhec://token@host:8088`                       |
| `loki` / `grafana-loki`      | `loki://host:3100`, `loki+https://host`             |
| `influxdb`                   | `influxdb://host:8086/bucket`                       |
| `file` / `jsonl`             | `file:///path/to/results.jsonl`                     |

You can also pass save URIs on the CLI with `--save` (repeatable), on a quick scan or `kxn monitor`:

```bash
kxn ssh://root@host --save postgresql://user:pass@db:5432/kxn --save file:///tmp/results.jsonl
```

## `[[targets]]` -- daemon mode

Targets define what `kxn watch` (daemon mode) scans on a recurring schedule.

```toml
[[targets]]
name = "postgresql"
uri = "postgresql://postgres:${secret:gcp:my-project/pg-password}@host:5432/postgres"
rules = ["postgresql-cis", "postgresql-monitoring"]
interval = 60
```

| Field      | Type     | Required | Description                                      |
|------------|----------|----------|--------------------------------------------------|
| `name`     | string   | yes      | Human-readable target identifier                 |
| `uri`      | string   | yes*     | Connection URI — supports `${secret:...}` interpolation |
| `provider` | string   | no       | Explicit provider name (derived from the URI scheme if omitted) |
| `rules`    | string[] | no       | Rule-**set** names to evaluate (the `name` of a `[[rules.*]]` entry, or the file stem when rules come from `-R`). A plain name matches as a substring; a pattern with `*` is an anchored glob. Empty means all loaded sets |
| `interval` | integer  | no       | Scan interval in seconds (default: `watch --interval`, 60) |
| `remediate` | bool | no | Apply this target's rule remediations during `kxn watch` (default: off, see below) |
| `[targets.config]` | table | no  | Provider-specific key-value config — string values support `${secret:...}` interpolation |

*Either `uri` or `provider` + `[targets.config]` must be specified — and they
compose: a URI sets the provider and its connection settings, `[targets.config]`
overlays it key by key. Both forms behave the same in `kxn watch`, `kxn monitor`
and the MCP tools, so one kxn.toml works everywhere.

### Target with explicit provider config

Some providers (like CVE feeds) don't use a connection URI:

```toml
[[targets]]
name = "cve-watch"
provider = "cve"
rules = ["cve-monitoring"]
interval = 3600
[targets.config]
KEYWORDS = "openssh,postgresql,mysql,nginx,linux"
SEVERITY = "HIGH"
DAYS_BACK = "7"
MAX_RESULTS = "50"
```

### Applying remediations from the daemon (`remediate`)

`kxn watch` never applies a rule's remediation unless you ask for it. A fix
rewrites the target — `sed -i` on a config file, `systemctl restart`, a secret
rotation — so it stays opt-in:

```toml
[[targets]]
name = "lab"
provider = "ssh"
rules = ["ssh-cis"]
interval = 300
remediate = true          # this target only
```

CLI equivalent for every target: `kxn watch --remediate`. A `remediate` set on a
target wins over the flag, so a production target can opt out of a daemon that
is globally allowed to fix things.

Without it, the daemon reports once per rule what it could have done:

```
[10:22:31] lab remediation available for ssh-cis-permit-root-login (1 action(s))
           — not applied; run with --remediate or set remediate = true on the target
```

When it is enabled, a rule's fix runs **once per cycle**, not once per violating
resource: a single `/etc/passwd` scan can report the same rule on 130 users, and
re-running the fix 130 times changes nothing. For one-shot, unattended runs
(CronJob, CI), use `kxn remediate <uri> --auto` instead of the daemon.

### Kubernetes usage sampler (`usage_interval`)

```toml
[[targets]]
name = "k8s"
provider = "kubernetes"
interval = 30            # compliance / health scan
usage_interval = "10s"   # CPU & RAM: 1s, 5s, 10s … on a dedicated loop
usage_flush = "60s"      # avg/max rollups written to [[save]] backends
```

With `usage_interval` set, container and node CPU/RAM are sampled on their own loop, read straight from the kubelets (`/stats/summary`, no metrics-server needed below 15 s). Rules on `pod_resource`, `node_metrics` and `pod_efficiency` run on every sample (so a memory spike is alerted within one period), the `--metrics-resources` gauges refresh at that rate, and every `usage_flush` the samples are condensed into one row per container/node — average and maximum over the window — written to the flat `pod_resource` / `node_resource` tables (the schema the kxn-stack dashboards use) plus 5-minute and 1-hour tiers (`*_5m`, `*_1h`). Kubelets refresh cAdvisor stats every 10 s by default (`--housekeeping-interval`); a 1 s or 5 s period only helps on clusters where that flag was lowered. CLI equivalent: `kxn watch --usage-interval 10s --usage-flush 60s`.

Retention for the usage tables lives in `[[save]].retention`: `pod_resource` (raw rows, default `7d`), `usage_5m` (default `90d`), `usage_1h` (default `730d`). Unlike the other tables these defaults apply even when unset, so a fast sampler never grows unbounded. `kxn recommend` picks the tier that covers its `--window` automatically.

`logs` and `metrics` default to `7d` when unset. `scans` and `resources` hold compliance history and are kept unless you set a window for them; `"0"` disables pruning for any table.

## `[alerts]` — route alerts by severity

Each violation is sent to the channels of its severity, with the same URI forms as the CLI `--alert` option (`slack://`, `discord://`, `teams://`, `email://`, `sms://`, `jira://`, …). Routes apply to every target in watch mode.

```toml
[alerts]
info    = []                                            # nothing (log only)
warning = []
error   = ["slack://hooks.slack.com/services/${secret:aws:kxn-alerts/slack_error}"]
fatal   = ["slack://hooks.slack.com/services/${secret:aws:kxn-alerts/slack_fatal}", "email://ops@example.com"]
```

Routes add to the existing `webhook` settings; they do not replace them. The same deduplication window (`--alert-interval`) applies. Secrets are resolved in every route.

## Secret interpolation

`${...}` placeholders are resolved at runtime in **both** `uri` and any string value inside `[targets.config]`. This keeps every secret out of config files.

### Supported backends

| Syntax | Backend | Auth |
|--------|---------|------|
| `${VAR_NAME}` or `${secret:env:VAR_NAME}` | Environment variable | Variable must be set |
| `${secret:gcp:project/secret-name}` | GCP Secret Manager | ADC (`gcloud auth application-default login`), `GOOGLE_APPLICATION_CREDENTIALS`, or the metadata server (Workload Identity) |
| `${secret:aws:secret-name/key}` | AWS Secrets Manager (JSON key of the secret) | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, else the `aws` CLI (profile, SSO, instance role); region `AWS_REGION`, default `us-east-1` |
| `${secret:azure:vault-name/secret-name}` | Azure Key Vault | `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` (no managed identity) |
| `${secret:vault:path/key}` | HashiCorp Vault | `VAULT_ADDR` + `VAULT_TOKEN`, or `HCP_CLIENT_ID` + `HCP_CLIENT_SECRET` + `HCP_API_URL` |

The reference is split on the **first** `/`: the part before it (project, secret name, vault name, path) cannot contain a `/`.

### Where interpolation applies

Placeholders are resolved in:

- `uri` — the target connection string
- Any string value inside `[targets.config]` — e.g. `PG_PASSWORD`, `SSH_PASSWORD`, `AZURE_CLIENT_SECRET`
- `webhook` lists in `[[targets]]`
- `[alerts]` channel URIs
- `url` in `[[save]]` backends

```toml
# In uri
[[targets]]
name = "prod-db"
uri = "postgresql://kxn:${secret:gcp:my-project/db-pass}@host:5432"

# In [targets.config]  ← also resolved
[[targets]]
name = "pg-prod"
provider = "postgresql"
[targets.config]
PG_HOST     = "db.internal"
PG_USER     = "kxn"
PG_PASSWORD = "${secret:gcp:my-project/db-pass}"   # fetched from Secret Manager

# In [[save]] url
[[save]]
type = "loki"
url = "loki://loki.internal:3100"
```

### Testing locally

With `gcloud` installed, authenticate ADC once:

```bash
gcloud auth application-default login
```

Then any `${secret:gcp:project/secret-name}` in `kxn.toml` is resolved using your user credentials. On GKE/GCE, Workload Identity / the metadata server is used automatically — no extra setup.

Quick smoke-test:

```bash
# Create a test secret
echo -n "my-password" | gcloud secrets create kxn-test --data-file=- --project=my-project

# Add to kxn.toml
# PG_PASSWORD = "${secret:gcp:my-project/kxn-test}"

# kxn resolves it at startup — a connection error (not a secret error) confirms it worked
kxn watch --config kxn.toml
```

### Security

kxn automatically redacts secrets in log output:
- `${...}` placeholders are replaced with `***`
- URI credentials (`scheme://user:pass@host`) are replaced with `scheme://***:***@host`

---

## Securing secrets with a vault

The goal is to keep database passwords, webhook URLs and other target secrets out of `kxn.toml` and `.env`: kxn.toml holds only `${secret:...}` references, and kxn fetches the values at startup.

Two limits shape every setup below:

- **Each secret backend needs its own credentials** in the kxn process environment (see the table in [Summary](#summary)). Only GCP Secret Manager works with a passwordless identity (Workload Identity / metadata server). Azure Key Vault has no managed-identity support; AWS needs env credentials or the `aws` CLI.
- **Cloud scanning credentials cannot come from a vault.** The native `azure`, `aws` and `gcp` providers read their credentials from the process environment (or a CLI login / the metadata server), not from `[targets.config]`. Putting `AZURE_CLIENT_SECRET = "${secret:...}"` in `[targets.config]` does not authenticate the scan. Use vault references for target URIs, `[targets.config]` values read by the provider (e.g. `PG_PASSWORD`), webhooks, `[alerts]` and `[[save]]` URLs.

The last segment of an AWS or Vault reference is the key: `${secret:aws:<secret-name>/<json-key>}` (the secret name may contain `/`, as in `prod/db/creds`) and `${secret:vault:<api-path>/<key>}`. Azure and GCP references are `${secret:azure:<vault-name>/<secret-name>}` and `${secret:gcp:<project>/<secret-name>}`.

`kxn watch` accepts native providers only (`azure`, `aws`, `gcp`, `kubernetes`, `ssh`, `postgresql`, …); a `hashicorp/*` Terraform provider in `[[targets]]` is skipped.

---

### Azure Key Vault

**The pattern:** kxn runs with a service principal in its environment. The same `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` / `AZURE_TENANT_ID` authenticate both the Key Vault lookups and the native `azure` provider. Key Vault holds everything else.

**Step 1 — store the other secrets in Key Vault**

```bash
az keyvault create --name kxn-vault --resource-group myRG --location westeurope

az keyvault secret set --vault-name kxn-vault --name discord-webhook --value "<id>/<token>"
az keyvault secret set --vault-name kxn-vault --name db-password     --value "pg-secret"
```

**Step 2 — grant the service principal read access**

```bash
# Secrets: read
az keyvault set-policy --name kxn-vault --spn <app-id> --secret-permissions get

# Resources: read-only on the subscription to scan
az role assignment create --assignee <app-id> --role Reader --scope /subscriptions/<subscription-id>
```

**Step 3 — environment and kxn.toml**

```bash
export AZURE_TENANT_ID=<tenant-id>
export AZURE_CLIENT_ID=<app-id>
export AZURE_CLIENT_SECRET=<client-secret>     # e.g. from a Kubernetes Secret
```

```toml
# kxn.toml — paths are relative to this file
[rules]
mandatory = [
  { name = "azure-cis",     path = "rules/azure-cis.toml" },
  { name = "azure-iam-cis", path = "rules/azure-iam-cis.toml" },
]

[[targets]]
name = "azure-prod"
uri = "azure://<subscription-id>"
rules = ["azure-cis", "azure-iam-cis"]
interval = 3600

[[targets]]
name = "prod-db"
uri = "postgresql://kxn_monitor:${secret:azure:kxn-vault/db-password}@db.internal:5432"
interval = 60

[alerts]
error = ["discord://discord.com/api/webhooks/${secret:azure:kxn-vault/discord-webhook}"]
fatal = ["discord://discord.com/api/webhooks/${secret:azure:kxn-vault/discord-webhook}"]

[[save]]
type = "loki"
url = "loki://loki.monitoring.svc:3100"
origin = "kxn-prod"
```

---

### AWS Secrets Manager

**The pattern:** credentials come from `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN`), or, when those are unset, from the `aws` CLI (`aws configure export-credentials`), which covers profiles, SSO, instance roles and IRSA. The `aws` CLI is **not** in the `kexa/kxn` image: in a container, pass env credentials or build an image that adds the CLI. Secrets Manager is called in `AWS_REGION` (default `us-east-1`).

**Step 1 — store the secrets** (one JSON secret, one key per value; the secret name cannot contain `/`)

```bash
aws secretsmanager create-secret \
  --name kxn-prod \
  --secret-string '{
    "db_password":     "pg-secret",
    "discord_webhook": "<id>/<token>"
  }'
```

**Step 2 — IAM permissions for kxn's identity**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FetchKxnSecrets",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:eu-west-1:123456789:secret:kxn-prod-*"
    }
  ]
}
```

For the scan itself, attach a read-only policy such as `SecurityAudit`.

**Step 3 — kxn.toml**

```toml
# kxn.toml — AWS_REGION=eu-west-1 and AWS credentials are in the environment
[rules]
mandatory = [
  { name = "aws-cis",     path = "rules/aws-cis.toml" },
  { name = "aws-iam-cis", path = "rules/aws-iam-cis.toml" },
]

[[targets]]
name = "aws-prod"
uri = "aws://eu-west-1"
rules = ["aws-cis", "aws-iam-cis"]
interval = 3600

[[targets]]
name = "prod-db"
uri = "postgresql://kxn_monitor:${secret:aws:kxn-prod/db_password}@db.internal:5432"
interval = 60

[alerts]
error = ["discord://discord.com/api/webhooks/${secret:aws:kxn-prod/discord_webhook}"]
fatal = ["discord://discord.com/api/webhooks/${secret:aws:kxn-prod/discord_webhook}"]

[[save]]
type = "loki"
url = "loki://loki.monitoring.svc:3100"
origin = "kxn-prod"
```

---

### GCP Secret Manager — no credentials in the pod

**The pattern:** kxn runs on GKE with Workload Identity. Both the Secret Manager lookups and the native `gcp` provider use application default credentials, which the metadata server provides — no JSON key file anywhere.

**Step 1 — store the secrets**

```bash
gcloud services enable secretmanager.googleapis.com

echo -n "<id>/<token>" | gcloud secrets create kxn-discord-webhook --data-file=-
echo -n "pg-secret"    | gcloud secrets create kxn-db-password     --data-file=-
```

**Step 2 — Workload Identity binding**

```bash
# The kxn pod uses the "kxn" Kubernetes service account in the "kxn" namespace
gcloud iam service-accounts add-iam-policy-binding kxn-monitor@my-project.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:my-project.svc.id.goog[kxn/kxn]"

# Read the secrets
for secret in kxn-discord-webhook kxn-db-password; do
  gcloud secrets add-iam-policy-binding $secret \
    --member "serviceAccount:kxn-monitor@my-project.iam.gserviceaccount.com" \
    --role roles/secretmanager.secretAccessor
done

# Read-only access for the scan
gcloud projects add-iam-policy-binding my-project \
  --member "serviceAccount:kxn-monitor@my-project.iam.gserviceaccount.com" \
  --role roles/iam.securityReviewer
```

**Step 3 — kxn.toml (no secrets, no env vars)**

```toml
# kxn.toml
[rules]
mandatory = [
  { name = "gcp-cis",            path = "rules/gcp-cis.toml" },
  { name = "gcp-best-practices", path = "rules/gcp-best-practices.toml" },
]

[[targets]]
name = "gcp-prod"
uri = "gcp://my-project"
rules = ["gcp-cis", "gcp-best-practices"]
interval = 3600

[[targets]]
name = "prod-db"
uri = "postgresql://kxn_monitor:${secret:gcp:my-project/kxn-db-password}@db.internal:5432"
interval = 60

[alerts]
error = ["discord://discord.com/api/webhooks/${secret:gcp:my-project/kxn-discord-webhook}"]
fatal = ["discord://discord.com/api/webhooks/${secret:gcp:my-project/kxn-discord-webhook}"]

[[save]]
type = "loki"
url = "loki://loki.monitoring.svc:3100"
origin = "kxn-prod"
```

---

### HashiCorp Vault

kxn uses one of two modes, chosen from the environment:

- **HCP Vault Secrets**, when `HCP_CLIENT_ID`, `HCP_CLIENT_SECRET` and `HCP_API_URL` are all set. `${secret:vault:<path>/<key>}` reads `$HCP_API_URL/<path>:<key>` with a token obtained from the HCP client credentials.
- **Self-hosted Vault or OpenBao** otherwise, with `VAULT_ADDR` and a static `VAULT_TOKEN` (`BAO_ADDR` / `BAO_TOKEN` work too; no Kubernetes or AppRole auth). `${secret:vault:<api-path>/<key>}` reads `$VAULT_ADDR/v1/<api-path>` and returns `data.data.<key>` (KV v2) or `data.<key>` (KV v1).

The API path is the one the HTTP API uses, so a KV v2 secret includes `data/`
after its mount — `vault kv get secret/kxn/db` is `${secret:vault:secret/data/kxn/db/<key>}`:

```toml
# kxn.toml — password stored with: bao kv put secret/kxn/db password=...
[[targets]]
name = "prod-db"
uri = "postgresql://kxn_monitor:${secret:vault:secret/data/kxn/db/password}@db.internal:5432"
interval = 60
```

Cloud scanning credentials for `azure` / `aws` targets go in the process environment the same way.

---

### Summary

| Backend | Credentials kxn needs | What's in the environment |
|-------|----------------------|--------------------------|
| Azure Key Vault | Service principal (client credentials); no managed identity | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |
| AWS Secrets Manager | Env credentials, or the `aws` CLI (profile, SSO, instance role, IRSA) — the CLI is not in the Docker image | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (or the CLI), `AWS_REGION` (default `us-east-1`) |
| GCP Secret Manager | Application default credentials (Workload Identity, metadata server, `GOOGLE_APPLICATION_CREDENTIALS`) | Nothing on GKE/GCE with Workload Identity |
| HashiCorp Vault | Static token, or HCP client credentials | `VAULT_ADDR` + `VAULT_TOKEN`, or `HCP_CLIENT_ID` + `HCP_CLIENT_SECRET` + `HCP_API_URL` |

## Environment variable fallback

Provider-specific configuration can also be set via environment variables when not using `kxn.toml`. Common examples:

```bash
# SSH
export SSH_KEY_PATH=~/.ssh/id_rsa

# PostgreSQL
export PG_HOST=localhost
export PG_PORT=5432
export PG_USER=postgres
export PG_PASSWORD=secret

# MySQL
export MYSQL_HOST=localhost
export MYSQL_PORT=3306
export MYSQL_USER=root
export MYSQL_PASSWORD=secret

# NVD API key (optional, raises the NVD rate limit): no env var is read,
# pass it to the sync command instead: kxn cve-update --nvd-api-key <key>


# Kubernetes: exclude pod name patterns (comma-separated regexes) from the
# cluster-wide total_restarts count — useful for a pod known to restart
# often for reasons unrelated to actual health (e.g. an operator that
# loses its leader-election lease periodically on some managed clusters).
export K8S_RESTART_EXCLUDE_POD_PATTERNS="^cilium-operator-,^konnectivity-agent-"

# kxn itself: once a day, interactive runs check whether a newer release
# exists and print one line on stderr if so. Off in CI and when stderr is not
# a terminal; turn it off everywhere with:
export KXN_NO_UPDATE_CHECK=1
```

## Full example

```toml
# kxn.toml — production configuration

[rules]
min_level = 1

[[rules.mandatory]]
name = "ssh-cis"
path = "rules/ssh-cis.toml"

[[rules.mandatory]]
name = "monitoring"
path = "rules/monitoring.toml"

[[rules.optional]]
name = "postgresql-cis"
path = "rules/postgresql-cis.toml"
enabled = true

[[rules.optional]]
name = "mysql-cis"
path = "rules/mysql-cis.toml"
enabled = false

[[save]]
type = "postgres"
url = "postgresql://${secret:gcp:my-project/db-user}:${secret:gcp:my-project/db-pass}@db:5432/kxn"
origin = "kxn-prod"
only_errors = false
[save.tags]
environment = "production"
team = "platform"

[[targets]]
name = "prod-db"
uri = "postgresql://postgres:${secret:aws:prod/pg-pass}@db.internal:5432/postgres"
rules = ["postgresql-cis", "postgresql-monitoring"]
interval = 60

[[targets]]
name = "prod-ssh"
uri = "ssh://root@app-server"
rules = ["ssh-cis", "monitoring"]
interval = 60

[[targets]]
name = "cve-watch"
provider = "cve"
rules = ["cve-monitoring"]
interval = 3600
[targets.config]
KEYWORDS = "openssh,postgresql,nginx"
SEVERITY = "HIGH"
DAYS_BACK = "7"
MAX_RESULTS = "50"
```
