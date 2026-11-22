# Architecture

kxn is one Rust binary built from six crates. A scan always follows the same
path: a **provider** gathers resources from a target, the **rules engine**
evaluates them against TOML rule packs, and the results go to the terminal,
to alert channels and to storage backends.

```mermaid
flowchart LR
    subgraph targets["Targets"]
        direction TB
        T1["Servers<br/>ssh://"]
        T2["Databases<br/>postgresql:// mysql:// mongodb://"]
        T3["Kubernetes<br/>kubernetes://"]
        T4["Cloud<br/>aws:// azure:// gcp://"]
        T5["Web & APIs<br/>https://"]
        T6["GitHub, Docker,<br/>Terraform providers…"]
    end

    subgraph kxn["kxn — single binary"]
        direction TB
        P["kxn-providers<br/>19 native providers<br/>+ Terraform gRPC bridge"]
        R["kxn-rules<br/>TOML rule packs<br/>1000+ rules, CIS / OWASP maps"]
        C["kxn-core<br/>rules engine<br/>34 conditions, nested logic"]
        P -- "resources (JSON)" --> C
        R -- "rules" --> C
    end

    subgraph out["Results"]
        direction TB
        O1["Terminal<br/>text, json, csv, html…"]
        O2["Alerts<br/>Slack, Teams, Discord,<br/>email, Jira, PagerDuty…"]
        O3["Storage<br/>PostgreSQL, Loki,<br/>Elasticsearch, S3, Kafka…"]
        O4["Prometheus<br/>/metrics"]
    end

    targets --> P
    C --> O1
    C --> O2
    C --> O3
    C --> O4
```

## How kxn runs

```mermaid
flowchart TB
    U(["You or an AI agent"])
    U -->|"kxn #lt;uri#gt;"| Q["Quick scan<br/>one target, once"]
    U -->|"kxn watch"| W["Daemon<br/>every target of kxn.toml, on an interval"]
    U -->|"kxn logs"| L["Log collection<br/>SSH hosts, Kubernetes pods, databases"]
    U -->|"kxn serve --mcp"| M["MCP server<br/>Claude, Cursor, Copilot…"]
    U -->|"kxn serve --webhook"| H["HTTP API<br/>/scan /event /ingest"]
    U -->|"kxn remediate"| F["Fix violations<br/>shell, webhook, secret rotation"]
```

## Crates

| Crate | Role |
|---|---|
| `kxn-cli` | The `kxn` binary: commands, alerts, storage backends, Prometheus endpoint |
| `kxn-core` | Rules engine: conditions, operators, evaluation |
| `kxn-rules` | Rule pack parser, `kxn.toml` configuration, secret references |
| `kxn-providers` | Native providers and the Terraform provider bridge |
| `kxn-mcp` | MCP server exposing kxn to AI agents |
| `kxn-wasm` | The rules engine compiled to WebAssembly |

## Development

```bash
cargo build      # build all crates (needs protoc)
cargo test       # run the tests
cargo clippy     # lint
```
