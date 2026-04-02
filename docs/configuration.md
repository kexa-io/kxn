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
| `uri`      | string   | yes*     | Connection URI for the provider                  |
| `provider` | string   | no       | Explicit provider name (inferred from URI scheme if omitted) |
| `rules`    | string[] | yes      | Rule set names to evaluate against this target   |
| `interval` | integer  | yes      | Scan interval in seconds                         |
| `[targets.config]` | table | no  | Provider-specific key-value configuration        |

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

Any string value in `kxn.toml` can contain `${...}` placeholders that are resolved at runtime. This keeps secrets out of config files.

### Supported backends

| Syntax | Backend | Requirements |
|--------|---------|-------------|
| `${env:VAR_NAME}` or `${VAR_NAME}` | Environment variable | Variable must be set |
| `${secret:gcp:project/secret-name}` | GCP Secret Manager | GCP credentials (ADC or `GOOGLE_APPLICATION_CREDENTIALS`) |
| `${secret:aws:secret-name/key}` | AWS Secrets Manager | AWS credentials (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` or IAM role) |
| `${secret:azure:vault-name/secret-name}` | Azure Key Vault | Azure credentials (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` or managed identity) |
| `${secret:vault:path/key}` | HashiCorp Vault | `VAULT_ADDR` and `VAULT_TOKEN` environment variables |

### Examples

```toml
# Environment variable (both forms are equivalent)
url = "postgresql://${DB_USER}:${DB_PASS}@host:5432/db"
url = "postgresql://${env:DB_USER}:${env:DB_PASS}@host:5432/db"

# GCP Secret Manager
url = "postgresql://${secret:gcp:my-project/db-user}:${secret:gcp:my-project/db-pass}@host:5432/db"

# AWS Secrets Manager
url = "mysql://${secret:aws:prod-db/username}:${secret:aws:prod-db/password}@host:3306/db"

# Azure Key Vault
url = "mongodb://${secret:azure:my-vault/mongo-user}:${secret:azure:my-vault/mongo-pass}@host:27017/db"

# HashiCorp Vault
url = "postgresql://${secret:vault:secret/data/myapp/db-user}:${secret:vault:secret/data/myapp/db-pass}@host:5432/db"
```

Multiple secret references can be mixed in a single string. Unresolved placeholders remain as-is (useful for debugging).

### Security

kxn automatically redacts secrets in log output:
- `${...}` placeholders are replaced with `***`
- URI credentials (`scheme://user:pass@host`) are replaced with `scheme://***:***@host`

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
