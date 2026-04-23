# Configuration

kxn uses a TOML configuration file (`kxn.toml`) for rules, save backends, and daemon targets.

## Config file discovery

kxn searches for `kxn.toml` in this order:

1. `./kxn.toml` (current directory)
2. `~/.config/kxn/kxn.toml`
3. `~/.kxn.toml`

## `[rules]` section

Global filters applied on top of all rule sets.

```toml
[rules]
min_level = 0          # Minimum severity: 0=info, 1=warning, 2=error, 3=fatal
# exclude = ["*-deprecated"]   # Glob patterns to exclude rules by name
```

| Field       | Type       | Default | Description                              |
|-------------|------------|---------|------------------------------------------|
| `min_level` | integer    | `0`     | Only evaluate rules at or above this level |
| `exclude`   | string[]   | `[]`    | Glob patterns to exclude rule names      |

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
kxn scan --only mandatory         # only mandatory rules
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
| `influxdb`                   | `influxdb://host:8086/bucket`                       |
| `file` / `jsonl`             | `file:///path/to/results.jsonl`                     |

You can also pass save URIs on the CLI with `--save` (repeatable):

```bash
kxn scan ssh://root@host --save postgresql://user:pass@db:5432/kxn --save file:///tmp/results.jsonl
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
| `provider` | string   | no       | Explicit provider name (inferred from URI scheme if omitted) |
| `rules`    | string[] | yes      | Rule set names to evaluate against this target   |
| `interval` | integer  | yes      | Scan interval in seconds                         |
| `[targets.config]` | table | no  | Provider-specific key-value config — string values support `${secret:...}` interpolation |

*Either `uri` or `provider` + `[targets.config]` must be specified.

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

## Secret interpolation

`${...}` placeholders are resolved at runtime in **both** `uri` and any string value inside `[targets.config]`. This keeps every secret out of config files.

### Supported backends

| Syntax | Backend | Auth |
|--------|---------|------|
| `${VAR_NAME}` | Environment variable | Variable must be set |
| `${secret:gcp:project/secret-name}` | GCP Secret Manager | ADC (`gcloud auth application-default login`) or `GOOGLE_APPLICATION_CREDENTIALS` |
| `${secret:aws:secret-name/key}` | AWS Secrets Manager | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` or IAM instance role |
| `${secret:azure:vault-name/secret-name}` | Azure Key Vault | `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` or managed identity |
| `${secret:vault:path/key}` | HashiCorp Vault | `VAULT_ADDR` + `VAULT_TOKEN` |

### Where interpolation applies

Placeholders are resolved in:

- `uri` — the target connection string
- Any string value inside `[targets.config]` — e.g. `PG_PASSWORD`, `SSH_PASSWORD`, `AZURE_CLIENT_SECRET`
- `url` in `[[save]]` backends

```toml
# In uri
[[targets]]
name = "prod-db"
uri = "postgresql://kxn:${secret:gcp:my-project/db-pass}@host:5432/db"

# In [targets.config]  ← also resolved
[[targets]]
name = "pg-prod"
provider = "postgresql"
[targets.config]
PG_HOST     = "db.internal"
PG_USER     = "kxn"
PG_PASSWORD = "${secret:gcp:my-project/db-pass}"   # fetched from Secret Manager
AZURE_CLIENT_SECRET = "${secret:azure:my-vault/azure-client-secret}"

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

The goal is zero credentials in `kxn.toml` and zero credentials in `.env`. This means the scanning credentials themselves — `AZURE_CLIENT_SECRET`, `AWS_ACCESS_KEY_ID`, database passwords, webhook URLs — are stored in a vault and fetched by kxn at runtime using a **passwordless identity** (managed identity, IAM instance role, Workload Identity).

```
kxn running on AKS (managed identity)
  → fetches AZURE_CLIENT_SECRET from Azure Key Vault    (no env var needed)
  → fetches DB_PASSWORD from Azure Key Vault            (no env var needed)
  → scans Azure resources using the fetched credentials
  → sends violations to Discord using the fetched webhook
```

No `.env` file. No secrets in the container. Only the vault reference in `kxn.toml`.

---

### Azure Key Vault — scanning Azure with zero credentials

**The pattern:** kxn runs on AKS with a managed identity. The managed identity authenticates to Key Vault automatically — no `AZURE_CLIENT_SECRET` anywhere.

**Step 1 — store the scanning credentials in Key Vault**

```bash
az keyvault create --name kxn-vault --resource-group myRG --location westeurope

# The service principal used to scan Azure resources
az keyvault secret set --vault-name kxn-vault --name azure-tenant-id     --value "<tenant-id>"
az keyvault secret set --vault-name kxn-vault --name azure-client-id     --value "<app-id>"
az keyvault secret set --vault-name kxn-vault --name azure-client-secret --value "<client-secret>"

# Other secrets kxn needs
az keyvault secret set --vault-name kxn-vault --name discord-webhook --value "https://discord.com/api/webhooks/..."
az keyvault secret set --vault-name kxn-vault --name db-password     --value "pg-secret"
```

**Step 2 — create a managed identity for kxn and grant it Key Vault access**

```bash
# Create the managed identity
az identity create --name kxn-identity --resource-group myRG

# Grant it access to read secrets from the vault
az keyvault set-policy --name kxn-vault \
  --object-id $(az identity show --name kxn-identity --resource-group myRG --query principalId -o tsv) \
  --secret-permissions get list
```

**Step 3 — bind the identity to the AKS pod (Workload Identity)**

```bash
# Enable Workload Identity on the cluster
az aks update --name my-cluster --resource-group myRG --enable-oidc-issuer --enable-workload-identity

# Create the federated credential
az identity federated-credential create \
  --identity-name kxn-identity \
  --resource-group myRG \
  --name kxn-aks-binding \
  --issuer $(az aks show --name my-cluster --resource-group myRG --query oidcIssuerProfile.issuerUrl -o tsv) \
  --subject "system:serviceaccount:kxn:kxn"
```

**Step 4 — kxn.toml (no secrets, no env vars)**

```toml
# kxn.toml
# All values are fetched from Azure Key Vault using the managed identity.
# Nothing sensitive is written here.

[rules]
mandatory = [
  { name = "azure-cis",     path = "${rules_dir}/azure-cis.toml" },
  { name = "azure-iam-cis", path = "${rules_dir}/azure-iam-cis.toml" },
]

[[targets]]
name = "azure-prod"
provider = "hashicorp/azurerm"
rules = ["azure-cis", "azure-iam-cis"]
interval = 3600
[targets.config]
# kxn reads these at startup from Key Vault, then uses them to authenticate to Azure
AZURE_TENANT_ID     = "${secret:azure:kxn-vault/azure-tenant-id}"
AZURE_CLIENT_ID     = "${secret:azure:kxn-vault/azure-client-id}"
AZURE_CLIENT_SECRET = "${secret:azure:kxn-vault/azure-client-secret}"
subscription_id     = "<subscription-id>"

[[targets]]
name = "prod-db"
uri = "postgresql://kxn_monitor:${secret:azure:kxn-vault/db-password}@db.internal:5432/myapp"
interval = 60

[[alerts]]
type = "discord"
webhook = "${secret:azure:kxn-vault/discord-webhook}"
min_level = 2

[[save]]
type = "loki"
url = "loki://loki.monitoring.svc:3100"
origin = "kxn-prod"
compression = "gzip"
```

**The pod runs with no environment variables at all.** The managed identity authenticates to Key Vault transparently.

---

### AWS Secrets Manager — scanning AWS with zero credentials

**The pattern:** kxn runs on EC2/ECS/EKS with an IAM instance role. The role authenticates to Secrets Manager automatically — no `AWS_ACCESS_KEY_ID` anywhere.

**Step 1 — store the scanning credentials**

```bash
aws secretsmanager create-secret \
  --name kxn/prod \
  --secret-string '{
    "aws_access_key_id":     "AKIA...",
    "aws_secret_access_key": "...",
    "db_password":           "pg-secret",
    "discord_webhook":       "https://discord.com/api/webhooks/..."
  }'
```

**Step 2 — IAM role for kxn**

The role attached to the EC2/ECS/EKS node needs two things:
- Read access to Secrets Manager to fetch credentials at startup
- Read-only access to AWS resources to run the CIS scan

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FetchKxnSecrets",
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:eu-west-1:123456789:secret:kxn/prod-*"
    },
    {
      "Sid": "ScanResources",
      "Effect": "Allow",
      "Action": ["ec2:Describe*", "s3:List*", "iam:List*", "iam:Get*", "rds:Describe*"],
      "Resource": "*"
    }
  ]
}
```

On EKS, use IRSA (IAM Roles for Service Accounts) to bind the role to the kxn pod's service account.

**Step 3 — kxn.toml (no secrets, no env vars)**

```toml
# kxn.toml
[rules]
mandatory = [
  { name = "aws-cis",     path = "${rules_dir}/aws-cis.toml" },
  { name = "aws-iam-cis", path = "${rules_dir}/aws-iam-cis.toml" },
]

[[targets]]
name = "aws-prod"
provider = "hashicorp/aws"
rules = ["aws-cis", "aws-iam-cis"]
interval = 3600
[targets.config]
# Fetched from Secrets Manager using the instance role — no env vars needed
AWS_ACCESS_KEY_ID     = "${secret:aws:kxn/prod/aws_access_key_id}"
AWS_SECRET_ACCESS_KEY = "${secret:aws:kxn/prod/aws_secret_access_key}"
region                = "eu-west-1"

[[targets]]
name = "prod-db"
uri = "postgresql://kxn_monitor:${secret:aws:kxn/prod/db_password}@db.internal:5432/myapp"
interval = 60

[[alerts]]
type = "discord"
webhook = "${secret:aws:kxn/prod/discord_webhook}"
min_level = 2

[[save]]
type = "loki"
url = "loki://loki.monitoring.svc:3100"
origin = "kxn-prod"
compression = "gzip"
```

---

### GCP Secret Manager — scanning GCP with zero credentials

**The pattern:** kxn runs on GKE with Workload Identity. The pod's Kubernetes service account maps to a GCP service account — no JSON key file anywhere.

**Step 1 — store the scanning credentials**

```bash
gcloud services enable secretmanager.googleapis.com

# The service account key used to scan GCP resources
# (or skip this if using Workload Identity for the scan too — then no key needed at all)
gcloud iam service-accounts keys create /tmp/kxn-sa.json \
  --iam-account kxn-scanner@my-project.iam.gserviceaccount.com

echo -n "$(cat /tmp/kxn-sa.json)" | \
  gcloud secrets create kxn-gcp-sa-key --data-file=-

echo -n "https://discord.com/api/webhooks/..." | \
  gcloud secrets create kxn-discord-webhook --data-file=-

echo -n "pg-secret" | \
  gcloud secrets create kxn-db-password --data-file=-
```

**Step 2 — Workload Identity binding**

```bash
# The kxn pod uses the "kxn" Kubernetes service account in the "kxn" namespace
gcloud iam service-accounts add-iam-policy-binding kxn-monitor@my-project.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:my-project.svc.id.goog[kxn/kxn]"

# Grant access to the secrets
for secret in kxn-gcp-sa-key kxn-discord-webhook kxn-db-password; do
  gcloud secrets add-iam-policy-binding $secret \
    --member "serviceAccount:kxn-monitor@my-project.iam.gserviceaccount.com" \
    --role roles/secretmanager.secretAccessor
done
```

**Step 3 — kxn.toml (no secrets, no env vars)**

```toml
# kxn.toml
[rules]
mandatory = [
  { name = "gcp-cis",     path = "${rules_dir}/gcp-cis.toml" },
  { name = "gcp-iam-cis", path = "${rules_dir}/gcp-iam-cis.toml" },
]

[[targets]]
name = "gcp-prod"
provider = "hashicorp/google"
rules = ["gcp-cis", "gcp-iam-cis"]
interval = 3600
[targets.config]
# SA key fetched from Secret Manager at startup via Workload Identity
GOOGLE_APPLICATION_CREDENTIALS_JSON = "${secret:gcp:my-project/kxn-gcp-sa-key}"
project = "my-project"
region  = "europe-west1"

[[targets]]
name = "prod-db"
uri = "postgresql://kxn_monitor:${secret:gcp:my-project/kxn-db-password}@db.internal:5432/myapp"
interval = 60

[[alerts]]
type = "discord"
webhook = "${secret:gcp:my-project/kxn-discord-webhook}"
min_level = 2

[[save]]
type = "loki"
url = "loki://loki.monitoring.svc:3100"
origin = "kxn-prod"
compression = "gzip"
```

---

### HashiCorp Vault — multi-cloud, any environment

Vault works everywhere — on-prem, multi-cloud, bare metal. kxn authenticates to Vault using Kubernetes service account tokens (no static token needed in the pod).

**Step 1 — store all scanning credentials in Vault**

```bash
vault secrets enable -path=kxn kv-v2

vault kv put kxn/azure \
  tenant_id="<tenant-id>" \
  client_id="<app-id>" \
  client_secret="<secret>"

vault kv put kxn/aws \
  access_key_id="AKIA..." \
  secret_access_key="..."

vault kv put kxn/common \
  db_password="pg-secret" \
  discord_webhook="https://discord.com/api/webhooks/..."
```

**Step 2 — Kubernetes auth (no static tokens)**

```bash
# Enable the Kubernetes auth method
vault auth enable kubernetes

vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc"

# Policy: kxn can read its own secrets
vault policy write kxn-policy - <<EOF
path "kxn/data/*" { capabilities = ["read"] }
EOF

# Bind the kxn service account to the policy
vault write auth/kubernetes/role/kxn \
  bound_service_account_names=kxn \
  bound_service_account_namespaces=kxn \
  policies=kxn-policy \
  ttl=1h
```

**Step 3 — kxn.toml**

```toml
# kxn.toml
# VAULT_ADDR is the only thing in the environment — no secrets.
[rules]
mandatory = [
  { name = "azure-cis", path = "${rules_dir}/azure-cis.toml" },
  { name = "aws-cis",   path = "${rules_dir}/aws-cis.toml" },
]

[[targets]]
name = "azure-prod"
provider = "hashicorp/azurerm"
rules = ["azure-cis"]
interval = 3600
[targets.config]
AZURE_TENANT_ID     = "${secret:vault:kxn/data/azure/tenant_id}"
AZURE_CLIENT_ID     = "${secret:vault:kxn/data/azure/client_id}"
AZURE_CLIENT_SECRET = "${secret:vault:kxn/data/azure/client_secret}"

[[targets]]
name = "aws-prod"
provider = "hashicorp/aws"
rules = ["aws-cis"]
interval = 3600
[targets.config]
AWS_ACCESS_KEY_ID     = "${secret:vault:kxn/data/aws/access_key_id}"
AWS_SECRET_ACCESS_KEY = "${secret:vault:kxn/data/aws/secret_access_key}"
region = "eu-west-1"

[[targets]]
name = "prod-db"
uri = "postgresql://kxn_monitor:${secret:vault:kxn/data/common/db_password}@db.internal:5432/myapp"
interval = 60

[[alerts]]
type = "discord"
webhook = "${secret:vault:kxn/data/common/discord_webhook}"
min_level = 2
```

`VAULT_ADDR=https://vault.internal:8200` is set in the pod environment. The pod authenticates automatically using its Kubernetes service account token — no static `VAULT_TOKEN` needed.

---

### Summary

| Vault | Auth method (pod/VM) | What's in the environment |
|-------|----------------------|--------------------------|
| Azure Key Vault | Managed identity / Workload Identity | Nothing |
| AWS Secrets Manager | IAM instance role / IRSA | Nothing |
| GCP Secret Manager | Workload Identity | Nothing |
| HashiCorp Vault | Kubernetes service account token | `VAULT_ADDR` only |

## Environment variable fallback

Provider-specific configuration can also be set via environment variables when not using `kxn.toml`. Common examples:

```bash
# SSH
export SSH_KEY_PATH=~/.ssh/id_rsa

# PostgreSQL
export PGHOST=localhost
export PGPORT=5432
export PGUSER=postgres
export PGPASSWORD=secret

# MySQL
export MYSQL_HOST=localhost
export MYSQL_PORT=3306
export MYSQL_USER=root
export MYSQL_PASSWORD=secret

# NVD API (optional, increases rate limit)
export NVD_API_KEY=your-api-key
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
