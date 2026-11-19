<p align="center">
  <img src="assets/logo.png" alt="kxn" width="120">
</p>

<h1 align="center">kxn</h1>

<p align="center"><strong>Find what's misconfigured or vulnerable in your servers, databases, Kubernetes, cloud and websites — with one command.</strong></p>

<p align="center">One Rust binary. No agent to install. 1000+ rules (CIS, OWASP, CVEs). Open source, MIT.</p>

<p align="center">
  <a href="https://github.com/kexa-io/kxn/releases/latest"><img src="https://img.shields.io/github/v/release/kexa-io/kxn?sort=semver" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License"></a>
  <a href="https://github.com/kexa-io/kxn/releases"><img src="https://img.shields.io/github/downloads/kexa-io/kxn/total" alt="Downloads"></a>
  <a href="https://hub.docker.com/r/kexa/kxn"><img src="https://img.shields.io/docker/pulls/kexa/kxn" alt="Docker pulls"></a>
  <a href="https://github.com/kexa-io/homebrew-tap"><img src="https://img.shields.io/badge/homebrew-kexa--io%2Ftap-orange" alt="Homebrew"></a>
</p>

<p align="center">
  <a href="docs/getting-started.md">Getting started</a> ·
  <a href="docs/quickstart-postgres-grafana.md">Dashboards</a> ·
  <a href="docs/providers.md">Providers</a> ·
  <a href="docs/rules.md">Rules</a> ·
  <a href="docs/reference.md">Reference</a>
</p>

## Try it

```bash
curl -fsSL https://raw.githubusercontent.com/kexa-io/kxn/main/install.sh | sh
kxn https://your-site.com
```

The first command installs the `kxn` binary on Linux or macOS. The second downloads the community rules, checks TLS, the certificate and
security headers, and lists each failed rule with its severity. kxn exits with
code 1 when a rule fails, so it drops straight into CI.

## Other ways to install

| | |
|---|---|
| Homebrew (macOS, Linux) | `brew install kexa-io/tap/kxn` |
| Cargo (from source, needs `protoc`) | `cargo install --git https://github.com/kexa-io/kxn kxn-cli` |
| Docker | `docker run --rm kexa/kxn:v0.57.1 <target>` |
| Windows, or any binary | Download from the [releases page](https://github.com/kexa-io/kxn/releases) (x86_64 and arm64) |

## What it checks

Give kxn a target; it loads every rule pack for that kind of target.

| Target | Command | What you get |
|---|---|---|
| Linux server | `kxn ssh://root@10.0.0.1` | CIS hardening, SSH config, users, services, firewall |
| PostgreSQL / MySQL / MongoDB | `kxn postgresql://user:pass@db:5432` | CIS benchmark, roles, settings, replication |
| Kubernetes | `kxn kubernetes://in-cluster` from a pod, or set `K8S_API_URL` + `K8S_TOKEN` | CIS benchmark, RBAC, privileged pods, resources |
| AWS / Azure / GCP | `kxn aws://eu-west-1` (uses your cloud credentials) | CIS benchmarks (IAM, storage, network, logging) |
| Website / API | `kxn https://example.com` | TLS, certificate, security headers |
| Package CVEs | `kxn cve-update`, then `kxn ssh://root@host` | Installed packages vs NVD, CISA KEV, EPSS and distribution trackers |
| GitHub, Docker, 3000+ Terraform providers | `kxn gather -p github -t all -C '{"GITHUB_ORG":"my-org"}'` (with `GITHUB_TOKEN`) | Raw resources as JSON, to check with rules ([how](docs/providers.md#github)) |

Scans only read. Fixes run only when you ask for them: `kxn remediate`, `kxn watch --remediate`, or the `kxn_remediate` tool of the MCP server.

## Keep watching

List your targets in `./kxn.toml` ([example](kxn.toml.example)), download the
rules once, then run kxn as a daemon:

```bash
kxn rules pull
kxn watch --metrics-port 9090
```

It rescans on an interval and can:

- **alert** — Slack, Teams, Discord, email, Jira, PagerDuty and more ([alerting](docs/alerting-and-saving.md))
- **store** results — PostgreSQL, Loki, Elasticsearch, S3, Kafka… with ready-made Grafana dashboards ([5-minute setup](docs/quickstart-postgres-grafana.md))
- **expose** Prometheus metrics ([metrics](docs/metrics.md))
- **collect logs** from servers and Kubernetes pods (`kxn logs`)

On Kubernetes, the [`kxn-stack`](deploy/helm/kxn-stack) Helm chart installs kxn, PostgreSQL and Grafana with the dashboards, and scans the cluster.

## Use it from AI agents

kxn is an MCP server. In Claude Code:

```bash
claude mcp add kxn -- kxn serve --mcp
```

Your agent can then scan targets, explain results and propose fixes. For
Cursor, Claude Desktop, Gemini and other clients, see
[agent integration](docs/agent-integration.md).

## FAQ

### Do I need to install anything on my servers?

No. kxn uses what is already there: SSH (key file or password) for servers, a
database connection, the Kubernetes API (token or client certificate) and the
cloud providers' APIs.

### Does kxn send my data anywhere?

No telemetry. kxn talks to the targets you scan and to GitHub (rules,
updates); CVE feeds and Terraform providers are fetched only when you use them.
Results stay on your machine unless you send them to an alert channel, a
storage backend or an AI agent.

### Can it break something?

Scans are read-only. Changes happen only when you ask for a fix, on the
violations you pick.

### Can I write my own rules?

Yes, in TOML: a resource type, a property, a condition. See [rules](docs/rules.md).

### How is it different from Trivy or Prowler?

Trivy focuses on images, code and clusters, Prowler on cloud accounts. kxn
also checks live servers over SSH, databases and websites from the same
binary, and keeps watching them.

### What does it cost?

Nothing. kxn is open source under the [MIT License](LICENSE).

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | Install, first scans, rules |
| [Dashboards in 5 minutes](docs/quickstart-postgres-grafana.md) | kxn → PostgreSQL → Grafana, Kubernetes logs, Prometheus |
| [Providers](docs/providers.md) | Every target type, its options and credentials |
| [Rules](docs/rules.md) | Rule packs and writing your own |
| [Configuration](docs/configuration.md) | `kxn.toml`, targets, secrets |
| [Alerting & storage](docs/alerting-and-saving.md) | Alert channels and storage backends |
| [CVE detection](docs/cve-detection.md) | Package vulnerabilities |
| [Reference](docs/reference.md) | Every command and option |
| [Architecture](docs/architecture.md) | How kxn is built |

## Contributing

Issues and pull requests are welcome. Build with `cargo build` (needs `protoc`),
test with `cargo test`.

## License

[MIT](LICENSE). kxn reports known misconfigurations and vulnerabilities; it does
not replace a security audit.
