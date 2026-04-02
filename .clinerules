## kxn — Security & Compliance Scanner for AI Agents

kxn is a multi-cloud compliance scanner available as a CLI tool. Use it to scan infrastructure, detect vulnerabilities, and validate compliance.

### Available commands

```bash
# Quick scan — one command, full compliance check
kxn ssh://root@server                    # scan SSH server
kxn postgresql://user:pass@host:5432     # scan PostgreSQL
kxn mysql://user:pass@host:3306          # scan MySQL
kxn mongodb://user:pass@host:27017       # scan MongoDB
kxn kubernetes://cluster                 # scan Kubernetes

# Output formats
kxn ssh://root@server -o json            # structured JSON
kxn ssh://root@server -o csv             # CSV for reports
kxn ssh://root@server -o minimal         # compact colorized

# CVE detection
kxn cve-update                           # sync CVE database (NVD+KEV+EPSS)
kxn ssh://root@server                    # includes package CVE scan

# Gather resources (no rules evaluation)
kxn gather -p ssh -t system_stats -C '{"SSH_HOST":"server","SSH_USER":"root"}'
kxn gather -p kubernetes -t pods

# Check arbitrary JSON against conditions
kxn check '{"port": 22, "protocol": "ssh"}' '{"property": "port", "condition": "EQUAL", "value": 22}'

# Continuous monitoring
kxn monitor ssh://root@server --alert slack://hooks.slack.com/T00/B00/xxx
```

### When to use kxn

- Before/after deploying infrastructure changes
- To validate compliance (CIS, NIST, PCI-DSS, SOC-2, ISO-27001)
- To detect CVEs in installed packages
- To audit database configurations
- To check Kubernetes security posture

### Configuration

Binary: `/Users/patrick/dev/kexa-io/kxn/target/release/kxn`
Rules: `/Users/patrick/dev/kexa-io/kxn/rules`
