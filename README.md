# kxn

Multi-cloud compliance scanner in Rust.

Successor to [Kexa](https://github.com/kexa-io/Kexa) (TypeScript). Single binary, no runtime, URI-driven interface.

## Key Features

- **URI-based scanning** -- point at any target with a single command
- **43+ TOML rule files** -- CIS benchmarks, OWASP API Top 10, monitoring baselines
- **10 native providers** -- SSH, PostgreSQL, MySQL, MongoDB, Kubernetes, GitHub, HTTP, gRPC, Cloud Run, Azure WebApp
- **Terraform gRPC bridge** -- scan any Terraform provider (AWS, GCP, Azure, Cloudflare, Vault, etc.)
- **MCP server** -- integrate with Claude Desktop / Claude Code via `kxn serve --mcp`
- **Alerts** -- Slack, Discord, generic webhooks
- **Save backends** -- persist results to 9 storage backends via URI

## Quick Start

```bash
cargo install kxn
```

One-shot scan:

```bash
kxn postgresql://user:pass@host:5432
kxn ssh://root@server --compliance
kxn http://api.example.com
```

Monitor mode with alerts and persistence:

```bash
kxn monitor mysql://user:pass@host:3306 \
  --alert slack://hooks.slack.com/services/T/B/x \
  --save elasticsearch://es:9200/kxn
```

## Providers

| Provider | URI Scheme | Description |
|----------|-----------|-------------|
| SSH | `ssh://` | System config, CIS hardening, sysctl, services |
| PostgreSQL | `postgresql://` | Databases, roles, settings, extensions |
| MySQL | `mysql://` | Databases, users, grants, variables |
| MongoDB | `mongodb://` | Databases, users, serverStatus, currentOp |
| Kubernetes | `kubernetes://` | 26 resource types: pods, deployments, RBAC, network policies |
| GitHub | `github://` | Organization, repos, webhooks, Dependabot, actions |
| HTTP | `http://` `https://` | TLS, headers, response validation |
| gRPC | `grpc://` | Health checks, reflection, service health |
| Cloud Run | Native config | Google Cloud Run services |
| Azure WebApp | Native config | Azure Web App services |
| Terraform | Any | AWS, GCP, Azure, Cloudflare, Vault via gRPC bridge |

## Flags

| Flag | Description |
|------|-------------|
| `--compliance` | Include CIS, SOC-2, PCI-DSS compliance rules |
| `--alert <URI>` | Send violations to Slack, Discord, or webhook |
| `--save <URI>` | Persist results to a storage backend |
| `--rules <DIR>` | Custom rules directory (default: `./rules`) |
| `--min-level <N>` | Minimum severity: 0=info, 1=warning, 2=error, 3=fatal |
| `--output <FMT>` | Output format: `text`, `json`, `sarif` |
| `--verbose` | Show detailed violation output |

## Save Backends

| URI Scheme | Backend |
|------------|---------|
| `postgresql://` | PostgreSQL |
| `mysql://` | MySQL |
| `mongodb://` | MongoDB |
| `elasticsearch://` | Elasticsearch |
| `opensearch://` | OpenSearch |
| `s3://` | AWS S3 |
| `gs://` | Google Cloud Storage |
| `az://` | Azure Blob Storage |
| `file://` | Local JSONL file |

## MCP Server

Expose kxn as an MCP tool server for Claude Desktop or Claude Code:

```bash
kxn serve --mcp
```

Provides 7 tools: `kxn_list_providers`, `kxn_list_resource_types`, `kxn_list_rules`, `kxn_provider_schema`, `kxn_gather`, `kxn_scan`, `kxn_check_resource`.

## Rules

Rules are defined in TOML with support for nested conditions:

```toml
[metadata]
version = "1.0.0"
provider = "ssh"

[[rules]]
name = "ssh-cis-5.2.10-no-root-login"
description = "CIS 5.2.10 - Ensure SSH root login is disabled"
level = 2

  [[rules.conditions]]
  property = "permitrootlogin"
  condition = "EQUAL"
  value = "no"
```

Supported conditions: `EQUAL`, `DIFFERENT`, `SUP`, `INF`, `SUP_OR_EQUAL`, `INF_OR_EQUAL`, `INCLUDE`, `REGEX`, `STARTS_WITH`, `ENDS_WITH`, `DATE_INF`, `DATE_SUP`, and nested `AND`/`OR`/`NAND`/`NOR`/`XOR` operators.

## Architecture

```
kxn scan --provider aws --rules cis.toml
    |
    v
+-------------------------------------------------------------+
|                        kxn-cli                              |
|  Commands: scan, check, gather, list-rules, list-providers  |
|            monitor, serve --mcp                             |
+-------------------------------------------------------------+
              |               |               |
              v               v               v
+------------------+ +----------------+ +------------------+
|   kxn-rules      | |   kxn-core     | |  kxn-providers   |
|                  | |                | |                  |
| TOML parser      | | Rules engine   | | gRPC bridge to   |
| Rule validation  | | 16 conditions  | | Terraform        |
| Rule index       | | Nested logic   | | providers        |
|                  | |                | |                  |
|                  | |                | | 10 native        |
|                  | |                | | providers        |
+------------------+ +----------------+ +------------------+
              |               |               |
              v               v               v
                     +----------------+
                     |   kxn-mcp      |
                     |                |
                     | MCP server     |
                     | stdio/SSE      |
                     | 7 tools        |
                     +----------------+
```

## Development

```bash
cargo build
cargo test
```

## License

See [LICENSE](LICENSE).
