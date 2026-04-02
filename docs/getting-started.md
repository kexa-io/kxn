# Getting Started with kxn v0.19.0

kxn is a multi-cloud compliance scanner written in Rust. Single binary, no runtime dependencies, 736+ built-in rules.

## Installation

### Homebrew (macOS/Linux)

```bash
brew install kexa-io/tap/kxn
```

### Cargo (from source)

```bash
cargo install --git https://github.com/kexa-io/kxn kxn-cli
```

### GitHub Releases

Download the prebuilt binary for your platform from [GitHub Releases](https://github.com/kexa-io/kxn/releases).

### Verify

```bash
kxn --version
# kxn 0.19.0
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
```

Each scan automatically selects matching rules and reports compliance violations.

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

## Filtering by Severity

Use `--min-level` to filter results by severity (0=info, 1=warning, 2=error, 3=fatal):

```bash
# Only errors and fatals
kxn ssh://root@server --min-level 2
```

## CIS Compliance

Apply CIS benchmark rules with the `--compliance` flag:

```bash
kxn ssh://root@server --compliance
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

kxn ships with 9 native providers:

| Provider | URI scheme (quick scan) | Notes |
|----------|------------------------|-------|
| SSH | `ssh://` | |
| PostgreSQL | `postgresql://` | |
| MySQL | `mysql://` | |
| MongoDB | `mongodb://` | |
| Oracle | `oracle://` | |
| HTTP | `http://` / `https://` | |
| gRPC | `grpc://` | |
| CVE | `cve://` | |
| Kubernetes | — | Use `kxn gather --provider kubernetes` |
| GitHub | — | Use `kxn gather --provider github` |

Additionally, 3000+ Terraform providers are available via the built-in gRPC bridge.

## AI Agent Integration

### Claude Code / Cursor

Initialize kxn as an AI agent tool:

```bash
kxn init --client claude-code
kxn init --client cursor
```

### MCP Server

Run kxn as an MCP server for Claude Desktop or other MCP clients:

```bash
kxn serve --mcp
```

## Next Steps

- Browse the 736+ built-in rules: `kxn list-rules`
- List available providers: `kxn list-providers`
- Explore the [rules/](../rules/) directory for example TOML rule files
- Visit [github.com/kexa-io/kxn](https://github.com/kexa-io/kxn) for full documentation
