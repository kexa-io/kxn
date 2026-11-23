---
name: kxn
description: Scan cloud accounts, Microsoft 365 and Google Workspace tenants, servers, databases, Kubernetes clusters and websites for misconfigurations and CVEs with kxn, against CIS, CISA SCuBA, NIS2 and DORA. Use when the user asks to audit, harden, check compliance, find security misconfigurations or vulnerable packages, or explain or fix a kxn finding.
---

# kxn

kxn is a read-only compliance scanner. One command scans a target given as a URI
and reports every rule that fails, with the benchmark's control number
(for example `m365-cis-5.2.2.1-mfa-admin-roles`). It exits with code 1 when at
least one rule fails, which is a result, not a crash.

If `kxn` is not on the PATH, install it:

```bash
curl -fsSL https://raw.githubusercontent.com/kexa-io/kxn/main/install.sh | sh
```

The first scan downloads the community rules to `~/.cache/kxn/rules`
(`kxn rules pull` does it explicitly).

## Scan a target

```bash
kxn <uri> -o json
```

Always use `-o json` when you need to read the results: it returns `total`,
`passed`, `failed`, `by_level` and a `violations` array where each item has
`rule`, `description`, `level_label`, `object_type`, `messages` and
`compliance` (the CIS, SCuBA, NIS2 or DORA references).

| Target | URI | Credentials kxn uses |
|---|---|---|
| Google Cloud project | `gcp://<project-id>` | gcloud Application Default Credentials |
| Azure subscription | `azure://<subscription-id>` | `az login` |
| AWS region | `aws://<region>` | the AWS CLI profile and environment |
| Microsoft 365 tenant | `m365://` | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` of an app with read-only Graph, Exchange and Teams permissions |
| Google Workspace | `googleworkspace://<domain>` | an admin account through gcloud ADC |
| Linux or Windows server | `ssh://user@host` | SSH key or agent |
| PostgreSQL, MySQL, MongoDB | `postgresql://user:pass@host:5432`, `mysql://...`, `mongodb://...` | the connection string |
| Kubernetes | `k8s://<context>` | kubeconfig |
| Website | `https://example.com` | none |

Useful options on a scan:

- `--compliance` adds the compliance packs (CIS, SCuBA) to the default rules.
- `-R <path>` runs one rule file or directory, for example
  `-R ~/.cache/kxn/rules/m365/scuba.toml`.
- `-l <n>` keeps findings at or above a level: 0 info, 1 warning, 2 error, 3 fatal.
- `-o` also accepts `text`, `csv`, `html`, `minimal` and `compact`.

## Work with the user

- Scan only targets the user named or clearly owns. Ask before scanning a
  production system you were not asked about.
- Never print or store secrets from the environment or connection strings. Put
  credentials in environment variables, not in commands you echo back.
- Summarise by severity first: fatal, then error, then warning. Quote the rule
  name and its control number, say what was found (`messages`) and why it
  matters, then the fix.
- When a control is not evaluated or a whole object type is missing, say so;
  usually the credentials lack a permission. Do not report it as passing.

## Fix findings

Scans never change anything. Fixes are a separate, explicit step:

```bash
kxn remediate <uri>                       # list the fixes the rules carry
kxn remediate <uri> -r <rule> --dry-run   # show the commands for one rule
kxn remediate <uri> -r <rule>             # apply it
```

Show the dry run and get the user's approval before applying any fix. For
findings without a built-in fix, propose the change (console setting, Terraform,
policy) and let the user apply it.

## Other commands

- `kxn cve-update` syncs NVD, CISA KEV and EPSS locally; server and container
  scans then match installed packages against it.
- `kxn list-rules -R <path>` lists the rules in a pack.
- `kxn rules list` shows the community rule sets.
- `kxn get <uri> <object-type>` prints the raw objects a rule would see, which
  helps explain why a rule failed.
- `kxn watch` rescans on an interval and sends alerts. Set it up only when the
  user asks for continuous monitoring.

Docs: https://github.com/kexa-io/kxn/tree/main/docs
