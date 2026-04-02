# Rules System

kxn uses TOML-based compliance rules to evaluate infrastructure resources. The project ships with 736+ rules covering CIS benchmarks, OWASP, NIST, and more.

## Rule Files

48 rule files are included in the `rules/` directory:

| File | Domain |
|------|--------|
| `apache-cis.toml` | Apache HTTP Server CIS |
| `api-monitoring.toml` | API health monitoring |
| `api-security.toml` | API security (OWASP) |
| `aws-cis.toml` | AWS CIS Benchmark |
| `aws-iam-cis.toml` | AWS IAM CIS |
| `azure-cis.toml` | Azure CIS Benchmark |
| `azure-iam-cis.toml` | Azure IAM CIS |
| `compliance-mapping.toml` | Cross-framework compliance mappings |
| `cve-monitoring.toml` | CVE monitoring |
| `db-log-monitoring.toml` | Database log monitoring |
| `docker-cis.toml` | Docker CIS Benchmark |
| `entra-id-cis.toml` | Entra ID (Azure AD) CIS |
| `gcp-cis.toml` | GCP CIS Benchmark |
| `gcp-iam-cis.toml` | GCP IAM CIS |
| `github-security.toml` | GitHub repository security |
| `google-workspace-cis.toml` | Google Workspace CIS |
| `grafana-monitoring.toml` | Grafana monitoring |
| `grpc-monitoring.toml` | gRPC service monitoring |
| `grpc-security.toml` | gRPC security |
| `http-monitoring.toml` | HTTP endpoint monitoring |
| `http-security.toml` | HTTP security headers |
| `kubernetes-cis.toml` | Kubernetes CIS Benchmark |
| `kubernetes-master-cis.toml` | Kubernetes master node CIS |
| `kubernetes-node-cis.toml` | Kubernetes worker node CIS |
| `kubernetes.toml` | Kubernetes general |
| `linux-cis.toml` | Linux CIS Benchmark |
| `log-monitoring.toml` | Log monitoring |
| `mongodb-cis.toml` | MongoDB CIS |
| `mongodb-dba.toml` | MongoDB DBA checks |
| `mongodb-monitoring.toml` | MongoDB monitoring |
| `monitoring.toml` | General monitoring |
| `mysql-cis.toml` | MySQL CIS |
| `mysql-dba.toml` | MySQL DBA checks |
| `mysql-monitoring.toml` | MySQL monitoring |
| `nginx-cis.toml` | Nginx CIS |
| `o365-cis.toml` | Office 365 CIS |
| `oracle-cis.toml` | Oracle Database CIS |
| `oracle-dba.toml` | Oracle DBA checks |
| `oracle-monitoring.toml` | Oracle monitoring |
| `oracle-security.toml` | Oracle security |
| `packages-cve.toml` | Package CVE detection |
| `postgresql-cis.toml` | PostgreSQL CIS |
| `postgresql-dba.toml` | PostgreSQL DBA checks |
| `postgresql-monitoring.toml` | PostgreSQL monitoring |
| `proxmox.toml` | Proxmox VE |
| `ssh-cis.toml` | SSH CIS Benchmark |
| `ssh-monitoring.toml` | SSH monitoring |
| `ssh-packages.toml` | SSH package inventory |

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
| `version` | Yes | Rule file version |
| `provider` | Yes | Target provider (ssh, postgresql, mysql, etc.) |
| `description` | No | Human-readable description |
| `tags` | No | Tags for filtering |

### Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique rule identifier |
| `description` | Yes | Human-readable description |
| `level` | Yes | Severity: 0=info, 1=warning, 2=error, 3=fatal |
| `object` | Yes | Resource type to evaluate |
| `tags` | No | Tags for filtering |
| `conditions` | Yes | Evaluation conditions (see below) |
| `compliance` | No | Compliance framework mappings |
| `remediation` | No | Automated fix commands |

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

### Supported Condition Types (33)

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

**Date / time**

| Condition | Description |
|-----------|-------------|
| `DATE_EQUAL` | Date equals expected |
| `DATE_SUP` | Date is after expected |
| `DATE_INF` | Date is before expected |
| `DATE_SUP_OR_EQUAL` | Date is after or equal to expected |
| `DATE_INF_OR_EQUAL` | Date is before or equal to expected |
| `DATE_INTERVAL` | Date is within an interval |

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

Remediations are never applied automatically. Use `kxn_remediate` (MCP) or the CLI to review and selectively apply fixes.

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

Filter which rules are evaluated during a scan:

```bash
# Include/exclude by name pattern
kxn scan --include "ssh-*" --exclude "*monitoring*"

# Filter by tags
kxn scan --tag cis                # rules must have ALL specified tags
kxn scan --any-tag cis,security   # rules must have ANY specified tag

# Filter by severity
kxn scan --min-level 2            # only error and fatal

# Enable/disable specific rules
kxn scan --enable "ssh-cis-5.2.10-no-root-login"
kxn scan --disable "ssh-cis-5.2.19-disable-empty-passwords"

# Only mandatory rules
kxn scan --only-mandatory

# Include all rules (even disabled by default)
kxn scan --all

# Output format
kxn scan --output json            # structured JSON (ScanSummary)
kxn scan --output sarif           # SARIF format (for GitHub Code Scanning, etc.)
kxn scan --sarif-file out.sarif   # write SARIF to file instead of stdout
```
