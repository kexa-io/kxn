# Getting Started with kxn

kxn is a multi-cloud compliance scanner written in Rust. Single binary, no runtime dependencies, 1,500+ community rules.

## Installation

### Homebrew (macOS/Linux)

```bash
brew install kexa-io/tap/kxn
```

### GitHub Releases

Download the prebuilt binary for your platform from [GitHub Releases](https://github.com/kexa-io/kxn/releases). Assets are named by target triple: `kxn-x86_64-unknown-linux-gnu.tar.gz`, `kxn-aarch64-unknown-linux-gnu.tar.gz`, `kxn-x86_64-apple-darwin.tar.gz`, `kxn-aarch64-apple-darwin.tar.gz`, `kxn-x86_64-pc-windows-msvc.zip`, `kxn-aarch64-pc-windows-msvc.zip`.

```bash
curl -fsSL https://github.com/kexa-io/kxn/releases/latest/download/kxn-x86_64-unknown-linux-gnu.tar.gz | tar xz
```

### Docker

```bash
docker run --rm kexa/kxn:v0.64.0 ssh://root@server
```

### From source (Cargo)

```bash
# needs a Rust toolchain and protoc; the binaries above need neither
cargo install --git https://github.com/kexa-io/kxn kxn-cli
```

### Verify

```bash
kxn --version
# kxn 0.64.0
```

## Quick Scan

kxn uses URIs to target infrastructure. No config file needed for one-shot scans:

```bash
# SSH server
kxn ssh://root@server

# PostgreSQL database
kxn postgresql://user:pass@host:5432

# MySQL database
kxn mysql://user:pass@host:3306

# MongoDB database
kxn mongodb://user:pass@host:27017

# Kubernetes: a context of your kubeconfig (k8s://in-cluster from a pod)
kxn k8s://my-context
```

Each scan automatically selects the rules whose `metadata.provider` matches the target and reports compliance violations. Rules are read from `./rules`, then the user cache directory (`~/.cache/kxn/rules` on Linux, `~/Library/Caches/kxn/rules` on macOS; filled by `kxn rules pull`), then a `rules` directory next to the binary. Use `--rules <dir-or-file.toml>` to point elsewhere.

## Output Formats

Control output with the `-o` flag:

```bash
kxn ssh://root@server -o text      # default, human-readable
kxn ssh://root@server -o json      # structured JSON
kxn ssh://root@server -o csv       # CSV for spreadsheets
kxn ssh://root@server -o toml      # TOML format
kxn ssh://root@server -o html      # HTML report
kxn ssh://root@server -o minimal   # colorized summary
```

Other formats: `quiet`, `compact`, `ia`. An unknown format is an error.

## Filtering by Severity

Use `--min-level` to filter results by severity (0=info, 1=warning, 2=error, 3=fatal):

```bash
# Only errors and fatals
kxn ssh://root@server --min-level 2
```

## CIS Compliance

CIS benchmark packs (`*-cis.toml`) for the target's provider are loaded by default, alongside the monitoring packs. To run a single pack:

```bash
kxn ssh://root@server --rules ~/.cache/kxn/rules/ssh-cis.toml
```

## CVE Detection

Update the local CVE database, then scans automatically include CVE detection:

```bash
kxn cve-update
kxn ssh://root@server
```

## Alerts

Send scan results to Slack or other destinations:

```bash
kxn ssh://root@server --alert slack://hooks.slack.com/services/T00/B00/xxx
```

## Saving Results

Persist scan results to a database:

```bash
kxn ssh://root@server --save postgresql://user:pass@host:5432/kxn
```

## Verbose Mode

Get detailed output during scanning:

```bash
kxn ssh://root@server -v
```

## Configuration File

For repeated scans, create a `kxn.toml` configuration file in your project directory. This lets you define targets, rules, alerts, and save backends in one place.

## Providers

kxn ships with 23 native providers (Oracle is an optional build feature, so the default build has 22):

| Provider | URI scheme (quick scan) | Notes |
|----------|------------------------|-------|
| SSH | `ssh://` | |
| PostgreSQL | `postgresql://` | |
| MySQL | `mysql://` | |
| MongoDB | `mongodb://` | |
| Cassandra | `cassandra://` | |
| Oracle | `oracle://` | Only in builds with the `oracle` feature |
| HTTP | `http://` / `https://` | |
| gRPC | `grpc://` | |
| CVE | `cve://` | |
| Local | `local://` | The machine kxn runs on |
| Kubernetes | `kubernetes://` / `k8s://` | `k8s://<context>` uses that kubeconfig context (none: the current one); `k8s://in-cluster` the pod's ServiceAccount |
| Helm | `helm://` | Helm releases (Kubernetes credentials) |
| AWS | `aws://<region>` | Env credentials or the `aws` CLI |
| Azure | `azure://<subscription-id>` | |
| GCP | `gcp://<project>` | |
| Microsoft 365 | `m365://` | Service principal in `AZURE_*` env vars |
| Microsoft Graph | `msgraph://` | `AZURE_*` env vars, or the Azure CLI login |
| Prometheus | `prometheus://host:port/metrics` | |
| GitHub | `github://<org>` | `GITHUB_TOKEN`, or the `gh` CLI login |
| GitLab | `gitlab://<host>` | `GITLAB_TOKEN` |
| Forgejo / Gitea | `forgejo://<host>/<owner>/<repo>` | `FORGEJO_TOKEN` |
| Docker | `docker://` | The local socket (Unix only) |
| Google Workspace | `googleworkspace://<domain>` | Application Default Credentials |

Run `kxn list-providers` for the list compiled into your binary. Additionally, 3000+ Terraform providers are available via the built-in gRPC bridge (`kxn gather -p hashicorp/<name> -t <type>`).

## AI Agent Integration

### Claude Code, Cursor and other agents

Register the kxn MCP server with every agent installed on this machine, or with one:

```bash
kxn init --mcp-only
kxn init --mcp-only --client claude-code
```

[Agent integration](agent-integration.md) lists the 21 supported agents and the file each one uses.

### MCP Server

Run kxn as an MCP server for Claude Desktop or other MCP clients:

```bash
kxn serve --mcp
```

## Next Steps

- Browse the rules: `kxn list-rules -R ~/.cache/kxn/rules` (`list-rules` reads `./rules` by default; run `kxn rules pull` first)
- List available providers: `kxn list-providers`
- Explore the [rules/](../rules/) directory for example TOML rule files
- Store scans, metrics and Kubernetes logs in PostgreSQL and graph them in Grafana: [quickstart-postgres-grafana.md](quickstart-postgres-grafana.md)
- Visit [github.com/kexa-io/kxn](https://github.com/kexa-io/kxn) for full documentation
