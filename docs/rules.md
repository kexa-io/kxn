# Rules System

kxn uses TOML-based compliance rules to evaluate infrastructure resources. The project ships with 1,000+ rules covering CIS benchmarks, OWASP, NIST, and more.

## Rule Files

59 rule files are included in the `rules/` directory (58 rule packs plus `compliance-mapping.toml`):

| File | Domain |
|------|--------|
| `apache-cis.toml` | Apache HTTP Server CIS |
| `api-monitoring.toml` | API health monitoring |
| `api-security.toml` | API security (OWASP) |
| `aws-cis.toml` | AWS CIS Benchmark |
| `aws-iam-cis.toml` | AWS IAM CIS |
| `aws-secrets-rotation.toml` | AWS Secrets Manager / KMS rotation (Terraform `hashicorp/aws`) |
| `azure-cis.toml` | CIS Microsoft Azure Foundations Benchmark v6.0.0 |
| `azure-cis-entra.toml` | CIS Azure v6.0.0 Entra ID controls (`microsoft.graph`) |
| `azure-best-practices.toml` | Azure hardening beyond CIS (compute, databases, containers, RBAC) |
| `azure-secrets-rotation.toml` | Azure Key Vault key and secret rotation |
| `azure-sp-expiry.toml` | Azure service principal secret expiry (`microsoft.graph`) |
| `compliance-mapping.toml` | Cross-framework compliance mappings |
| `cve-monitoring.toml` | CVE monitoring |
| `db-log-monitoring.toml` | Database log monitoring |
| `docker-cis.toml` | Docker CIS Benchmark |
| `gcp-cis.toml` | CIS Google Cloud Platform Foundations Benchmark v3.0.0 |
| `gcp-best-practices.toml` | GCP hardening beyond CIS (IAM, storage, disks) |
| `gcp-gke.toml` | GKE cluster hardening |
| `gcp-sa-key-expiry.toml` | GCP service account key rotation |
| `gcp-secrets-rotation.toml` | GCP Secret Manager rotation |
| `github-security.toml` | GitHub repository security |
| `google-workspace-audit.toml` | Google Workspace audit (native `googleworkspace` provider) |
| `google-workspace-cis.toml` | CIS Google Workspace Foundations Benchmark v1.4.0 (native `googleworkspace` provider, Cloud Identity Policy API) |
| `google-workspace-scuba.toml` | CISA SCuBA baselines for Google Workspace (ScubaGoggles v1.1.0) |
| `grafana-monitoring.toml` | Grafana monitoring |
| `grpc-monitoring.toml` | gRPC service monitoring |
| `grpc-security.toml` | gRPC security |
| `harbor-monitoring.toml` | Harbor container health (`docker`) |
| `http-cve-2026-119618.toml` | CVE-2026-119618 (Apache httpd mod_http2) over HTTP |
| `http-monitoring.toml` | HTTP endpoint monitoring |
| `http-security.toml` | HTTP security headers |
| `intune-devices.toml` | Intune managed devices: compliance, encryption, jailbreak, check-in, compliance policy per platform (`m365`) |
| `kubernetes-cis.toml` | Kubernetes CIS Benchmark |
| `kubernetes-master-cis.toml` | Kubernetes master node CIS |
| `kubernetes-node-cis.toml` | Kubernetes worker node CIS |
| `kubernetes-resources.toml` | Kubernetes CPU/memory saturation and right-sizing |
| `kubernetes.toml` | Kubernetes general |
| `linux-cis.toml` | Linux CIS Benchmark |
| `log-monitoring.toml` | Log monitoring |
| `m365-cis.toml` | CIS Microsoft 365 Foundations Benchmark v7.0.0: Entra ID, Exchange Online, Defender for Office 365, SharePoint, Teams (`m365`) |
| `m365-scuba.toml` | CISA SCuBA baselines for Microsoft 365 (ScubaGear v2.0.0): Entra ID, Exchange, Defender, SharePoint, Teams (`m365`) |
| `cassandra-cis.toml` | CIS Apache Cassandra 5.0 Benchmark v1.1.0 (13 of 20 controls) |
| `cassandra-monitoring.toml` | Cassandra replication, durability, client TLS, thread pools |
| `mongodb-cis.toml` | CIS MongoDB 7 and 8 Benchmark v2.0.0 (18 of 23 controls) |
| `mongodb-dba.toml` | MongoDB DBA checks |
| `mongodb-monitoring.toml` | MongoDB monitoring |
| `monitoring.toml` | General monitoring |
| `mysql-cis.toml` | CIS MySQL Community Server 8.4 Benchmark v1.1.0 (40 controls) |
| `mysql-dba.toml` | MySQL DBA checks |
| `mysql-monitoring.toml` | MySQL monitoring |
| `nginx-cis.toml` | Nginx CIS |
| `oracle-cis.toml` | CIS Oracle Database 19c Benchmark v2.0.0, Level 1 (69 controls) |
| `oracle-dba.toml` | Oracle DBA checks |
| `oracle-monitoring.toml` | Oracle monitoring |
| `oracle-security.toml` | Oracle security |
| `packages-cve.toml` | Package CVE detection |
| `postgresql-cis.toml` | CIS PostgreSQL 17 Benchmark v1.1.0 (42 controls) |
| `postgresql-dba.toml` | PostgreSQL DBA checks |
| `postgresql-monitoring.toml` | PostgreSQL monitoring |
| `proxmox.toml` | Proxmox VE |
| `ssh-cis.toml` | SSH CIS Benchmark |
| `ssh-cve-2026-119618.toml` | CVE-2026-119618 (Apache httpd mod_http2) via installed packages |
| `ssh-monitoring.toml` | SSH monitoring |
| `ssh-packages.toml` | SSH package inventory |
| `vault-secrets-rotation.toml` | HashiCorp Vault KV v2 secret age (Terraform `hashicorp/vault`) |

## Rule Structure

Each rule file has two sections: metadata and rules.

```toml
[metadata]
version = "1.0.0"
provider = "ssh"
description = "CIS Benchmark for SSH (OpenSSH Server)"
tags = ["cis", "ssh", "security"]

[[rules]]
name = "ssh-cis-5.2.10-no-root-login"
description = "CIS 5.2.10 - Ensure SSH root login is disabled"
level = 2
object = "sshd_config"
tags = ["authentication"]

  [[rules.compliance]]
  framework = "CIS"
  control = "5.2.10"
  section = "SSH Server Configuration"

  [[rules.compliance]]
  framework = "NIST-800-53"
  control = "AC-7"
  section = "Unsuccessful Logon Attempts"

  [[rules.conditions]]
  property = "permitrootlogin"
  condition = "EQUAL"
  value = "no"

  [[rules.remediation]]
  type = "shell"
  command = "sed -i '/^#*PermitRootLogin/d' /etc/ssh/sshd_config && echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && sshd -t && systemctl restart sshd"
  timeout = 15
```

### Metadata Fields

| Field | Required | Description |
|-------|----------|-------------|
| `version` | No | Rule file version |
| `provider` | No (recommended) | Target provider (ssh, postgresql, mysql, etc.) |
| `description` | No | Human-readable description |
| `tags` | No | Tags inherited by every rule of the file, for filtering |

The parser accepts a file without `[metadata]`, but `provider` decides where a
pack runs: `kxn <uri> --rules <dir>` loads only the packs whose `provider`
matches the target (a pack without one is skipped), and a scan that knows its
target reports the rules of a pack written for another provider as *not
evaluated*. `kxn <uri> --rules <file>` loads that one file whatever its provider.

### Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique rule identifier |
| `description` | No | Human-readable description |
| `level` | Yes | Severity: `0`–`3` or `"info"`, `"warning"`, `"error"`, `"fatal"` |
| `object` | No (in practice yes) | Resource type to evaluate. Without it the rule is evaluated against the whole gathered payload |
| `tags` | No | Tags for filtering |
| `conditions` | Yes | Evaluation conditions (see below) |
| `apply_to` | No | Only evaluate resources matching a filter: `"value"` matches the `name` property, `"property=value"` any property |
| `webhook` | No | Extra webhook URLs notified for this rule's violations (`kxn watch`), in addition to the global ones |
| `compliance` | No | Compliance framework mappings |
| `remediation` | No | Automated fix actions (see below) |

## Severity Levels

| Level | Name | Description |
|-------|------|-------------|
| 0 | Info | Informational, no action needed |
| 1 | Warning | Should be reviewed |
| 2 | Error | Must be fixed |
| 3 | Fatal | Critical security issue |

## Conditions

### Simple Conditions

```toml
[[rules.conditions]]
property = "permitrootlogin"
condition = "EQUAL"
value = "no"
```

### Supported Condition Types (34)

**Equality / comparison**

| Condition | Description |
|-----------|-------------|
| `EQUAL` | Exact match (`actual == expected`) |
| `DIFFERENT` | Not equal (`actual != expected`) |
| `SUP` | Greater than (`actual > expected`) |
| `INF` | Less than (`actual < expected`) |
| `SUP_OR_EQUAL` | Greater than or equal (`actual >= expected`) |
| `INF_OR_EQUAL` | Less than or equal (`actual <= expected`) |
| `IN` | Value is in a list |
| `NOT_IN` | Value is not in a list |
| `INTERVAL` | Value is within a numeric interval |

**String / array membership**

| Condition | Description |
|-----------|-------------|
| `INCLUDE` | Contains value (string substring or array membership) |
| `NOT_INCLUDE` | Does not contain value |
| `INCLUDE_NOT_SENSITIVE` | Case-insensitive contains |
| `NOT_INCLUDE_NOT_SENSITIVE` | Case-insensitive not-contains |
| `REGEX` | Regular expression match |
| `NOT_REGEX` | Regular expression does not match |
| `STARTS_WITH` | String prefix match |
| `NOT_STARTS_WITH` | String does not start with |
| `ENDS_WITH` | String suffix match |
| `NOT_ENDS_WITH` | String does not end with |

**Array aggregate**

| Condition | Description |
|-----------|-------------|
| `ALL` | All array elements satisfy the sub-condition |
| `SOME` | At least one array element satisfies the sub-condition |
| `ONE` | Exactly one array element satisfies the sub-condition |
| `NOT_ANY` | No array element satisfies the sub-condition |
| `COUNT` | Array length equals expected |
| `COUNT_SUP` | Array length greater than expected |
| `COUNT_INF` | Array length less than expected |
| `COUNT_SUP_OR_EQUAL` | Array length greater than or equal to expected |
| `COUNT_INF_OR_EQUAL` | Array length less than or equal to expected |

A property that is `null` counts as an empty collection: `ALL` over it holds
(there is nothing to violate), `SOME`/`ONE` match nothing, and `COUNT*` see a
length of 0. Kubernetes ships objects shaped like this — a system-managed `Role`
with `rules: null` — and the alternative is to report those resources as
violating every rule that looks at the property. A property that is *absent*
from the resource is not a collection and still fails the aggregate conditions.

**Date / time**

| Condition | Description |
|-----------|-------------|
| `DATE_EQUAL` | Same calendar day as the date in `value` |
| `DATE_SUP` | Age greater than `value`: the date is earlier than now minus `value` |
| `DATE_INF` | Age less than `value`: the date is later than now minus `value` |
| `DATE_SUP_OR_EQUAL` | Age greater than or equal to `value` |
| `DATE_INF_OR_EQUAL` | Age less than or equal to `value` |
| `DATE_INTERVAL` | Date between the two dates in `value`, separated by a space (`"2025-01-01 2025-12-31"`) |

The property is parsed as RFC 3339 or a common date format (`%Y-%m-%d`,
`%Y-%m-%d %H:%M:%S`, `%d/%m/%Y`, …); add `date = "<strftime format>"` to the
condition for any other format. For `DATE_SUP`, `DATE_INF` and their
`_OR_EQUAL` forms, `value` is an age relative to now, written as positional
`"seconds minutes hours days weeks months years"` — `"0 0 0 90"` is 90 days:

```toml
[[rules.conditions]]
property = "last_rotated"
condition = "DATE_INF"
value = "0 0 0 90"        # compliant when rotated less than 90 days ago
date = "%d.%m.%Y"         # optional, when the value is not in a standard format
```

### Nested Conditions (ParentRules)

Combine multiple conditions with logical operators:

```toml
[[rules.conditions]]
operator = "OR"
criteria = [
  { property = "automountServiceAccountToken", condition = "EQUAL", value = false },
  { property = "serviceAccountName", condition = "DIFFERENT", value = "default" },
]
```

Supported operators: `AND`, `OR`, `NAND`, `NOR`, `XOR`, `XNOR`, `NOT`.

Nesting is unlimited -- a `criteria` entry can itself contain an `operator` + `criteria` array.

## Compliance Mappings

Rules can map to one or more compliance frameworks:

```toml
[[rules.compliance]]
framework = "CIS"
control = "5.2.10"
section = "SSH Server Configuration"

[[rules.compliance]]
framework = "PCI-DSS"
control = "2.2.4"

[[rules.compliance]]
framework = "ISO-27001"
control = "A.8.5"
section = "Secure Authentication"
```

### Supported Frameworks

- **CIS** -- Center for Internet Security Benchmarks
- **NIST-800-53** -- NIST Security and Privacy Controls
- **PCI-DSS** -- Payment Card Industry Data Security Standard
- **SOC-2** -- Service Organization Control 2
- **ISO-27001** -- Information Security Management
- **OWASP** -- Open Web Application Security Project
- **CISA** -- Cybersecurity and Infrastructure Security Agency
- **HIPAA** -- Health Insurance Portability and Accountability Act

## Remediation

Rules can include automated remediation commands:

```toml
[[rules.remediation]]
type = "shell"
command = "sed -i '/^#*PermitRootLogin/d' /etc/ssh/sshd_config && echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && sshd -t && systemctl restart sshd"
timeout = 15
```

A `shell` remediation always runs **on the scanned target**, through its provider:
`ssh` executes it on the remote host, `local` on the machine running kxn, and any
other provider (kubernetes, http, a database…) refuses it. There is no local
fallback — a fix such as `sed -i ... /etc/ssh/sshd_config` is written for the
target and must never land on the host running kxn. Use `type = "binary"` for the
opposite: a fixer script run on the kxn host, fed the violation through the
`KXN_CONTEXT` environment variable.

All remediation types:

| `type` | Fields | What it does |
|--------|--------|--------------|
| `shell` | `command`, `timeout` (s, default 30) | Runs the command on the target (`ssh` / `local` only) |
| `binary` | `path`, `args`, `timeout` (s, default 30) | Runs a program on the kxn host with `KXN_CONTEXT` set to the violation JSON |
| `webhook` | `url`, `method` (default `POST`), `headers` | Sends the violation JSON to a URL |
| `sql` | `query`, `reload` (default `true`) | Runs SQL on the target database (postgresql, mysql); `reload` calls `pg_reload_conf()` afterwards. Applied only through the MCP tool `kxn_remediate` — the CLI refuses it |
| `rotateSPSecret` | `vault`, `secret_name` | Rotates an Azure service principal secret and stores the new one in Key Vault (needs `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`) |
| `rotateSAKey` | `project`, `secret` | Rotates a GCP service account key and stores the new JSON key in Secret Manager |
| `lua` | `script`, `timeout` | Parsed but not executed by this build (reported as a premium feature) |

Remediations are never applied on their own. Every path is explicit:

- `kxn remediate <uri>` lists what could be fixed and applies nothing.
- `kxn remediate <uri> --rule <name>` applies the ones you name, `--auto` applies
  them all (unattended runs: CronJob, CI), `--dry-run` shows either without
  touching the target.
- `kxn watch` applies nothing unless started with `--remediate`, or unless the
  target carries `remediate = true`. When enabled, a rule's fix runs once per
  cycle, not once per violating resource.
- The MCP tool `kxn_remediate` lists by default and only applies the rules an
  agent names explicitly.

## Validating rules

A rule names the object it inspects (`object = "sshd_config"`). If no collector
produces that object, the rule can never fire — a scan reports it as *not
evaluated*, not as a violation, because nothing was ever checked. `kxn rules validate` catches that before a scan does not:

```bash
kxn rules validate -R rules/
```

It builds the catalogue of every object the native providers declare and every
object the Terraform profiles map, then checks each rule against it:

- **unreachable** — no collector produces the object; the rule can never fire
  (with the closest known object name, for typos);
- **mismatched** — the object exists but is produced by a provider other than
  the one the pack declares, so the rule only fires on the wrong kind of target;
- **not compiled** — the pack targets a provider this build left out (`oracle`
  behind its feature, `docker` off unix): those rules are simply not checkable
  here, and are reported apart rather than counted as broken.

It exits 1 when a rule is unreachable, so it can gate CI; `--no-fail` reports
without failing, and `--json` emits the findings for tooling.

## Community Rules

Download the latest community rules from the kxn-rules repository:

```bash
# Download/update community rules
kxn rules pull

# List available rule sets
kxn rules list
```

## Custom Rules

Create TOML files in the `rules/` directory following the structure above. Rules are automatically discovered during scans.

## Rule Filtering

Filter which rules `kxn scan` (resources on stdin or `--resource`) evaluates:

```bash
# Include/exclude by name pattern
kxn scan --include "ssh-*" --exclude "*monitoring*"

# Filter by tags
kxn scan --tag cis                # rules must have ALL specified tags
kxn scan --any-tag cis --any-tag security   # rules must have ANY specified tag

# Filter by severity
kxn scan --min-level 2            # only error and fatal

# Enable/disable optional rule SETS declared in kxn.toml ([[rules.optional]] names)
kxn scan -c kxn.toml --enable "postgresql-monitoring"
kxn scan -c kxn.toml --disable "http-security"

# Only mandatory rule sets
kxn scan -c kxn.toml --only-mandatory

# All rule sets (even optional ones disabled by default)
kxn scan -c kxn.toml --all

# Output format
kxn scan --output json            # structured JSON (ScanSummary)
kxn scan --output sarif           # SARIF format (for GitHub Code Scanning, etc.)
kxn scan --sarif-file out.sarif   # write SARIF to file instead of stdout
```
