# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in kxn, please report it privately:

- **Preferred**: [Open a private security advisory on GitHub](https://github.com/kexa-io/kxn/security/advisories/new)
- **Email**: security@kexa.io

**Response time**: we aim to acknowledge reports within 72 hours.

**Do not**:
- Open public GitHub issues for security vulnerabilities
- Disclose unpatched vulnerabilities on social media or forums

## Scope

kxn is a compliance scanner that connects to target systems (SSH, PostgreSQL, MySQL, MongoDB, Kubernetes, HTTP endpoints, etc.) using credentials provided by the operator. Security-sensitive areas include:

- **Credential handling** — `${secret:...}` interpolation (env, GCP, AWS, Azure, Vault)
- **Remote execution** — SSH gatherer, remediation commands executed on targets
- **MCP server** — exposed to LLM clients; input validation on all tool arguments
- **Terraform provider bridge** — gRPC subprocess launching, binary integrity via SHA256
- **Rule engine** — condition evaluation on attacker-controlled JSON

## Supported Versions

Only the latest minor release receives security patches. Upgrade to the newest release before reporting.

## Disclosure Timeline

1. **Day 0** — Acknowledgement sent to reporter
2. **Day 7** — Severity assessment shared with reporter
3. **Day 30** — Patch released + CVE filed (if applicable)
4. **Day 90** — Public disclosure (or earlier if a fix is already deployed)

Critical vulnerabilities (RCE, credential exfiltration, sandbox escape) may be fast-tracked.

## Hardening Tips for Operators

- Never store plaintext credentials in `kxn.toml`. Use the `${secret:...}` interpolation with a cloud KMS or HashiCorp Vault.
- Run `kxn` with the least privilege required for the scan (read-only SSH user, scoped DB role).
- Review remediation actions before applying them — remediation runs shell commands on targets.
- Rotate credentials used by `kxn` on a regular cadence and scope them per-target.

## Dependency & Supply Chain

- `cargo audit` runs on every pull request (non-blocking signal).
- Terraform provider binaries are verified by SHA256 checksum before execution.
- Release binaries are built from tagged commits in GitHub Actions; checksums published with each release.
