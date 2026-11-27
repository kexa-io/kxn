# Compliance frameworks: NIS2, SOC 2 and GDPR

Every security rule kxn ships is mapped to the NIS2 measure, the SOC 2 Trust
Services Criterion and the GDPR article it gives evidence for, on every
platform: clouds, Microsoft 365, Google Workspace, Kubernetes, Linux servers,
databases, web servers, GitHub and GitLab, vaults. A scan can keep only the
rules of one framework and print, after its findings, a table per control.

kxn checks configurations. It gives continuous, dated evidence for the
technical measures of these frameworks; it does not cover their governance
and process parts (risk analysis, policies, training, incident reporting to an
authority, contracts with processors, records of processing). Those stay with
your ISMS, DPO and auditor. [What kxn cannot check](#what-kxn-cannot-check)
lists them.

## Coverage

Of the 1,569 rules in [`rules/`](../rules), on every provider:

| Framework | Rules mapped | Controls |
|-----------|-------------:|----------|
| NIS2, Directive (EU) 2022/2555, art. 21(2) | 1,311 | 21.2.b, c, d, e, f, g, h, i, j |
| SOC 2, Trust Services Criteria (2017) | 1,315 | CC6.1, CC6.6, CC6.7, CC7.1, CC7.2, CC8.1, CC9.2, A1.2, C1.1 |
| GDPR, Regulation (EU) 2016/679 | 1,293 | art. 25, 32(1)(a), 32(1)(b), 32(1)(c), 33, 44 |

The rules left out are performance and capacity checks (CPU, connections,
replication lag...), which are not security controls. DORA, CIS, CISA SCuBA,
ISO 27001, PCI DSS and NIST 800-53 mappings are kept where the packs had them.

## Scan one framework

`--framework` keeps the rules mapped to a framework and adds a per-control
table after the findings. Case, spaces and dashes do not matter (`soc2`,
`SOC-2`); `rgpd` is accepted for GDPR. Separate several with commas.

```bash
kxn ssh://admin@server --framework nis2
kxn azure://<subscription> --framework gdpr
kxn k8s://prod --framework nis2,soc2,gdpr
kxn list-rules -R rules --framework soc2          # which rules count for SOC 2
```

`kxn monitor`, `kxn watch` and `kxn scan` take the same option. In `kxn.toml`,
for `kxn watch`:

```toml
[rules]
frameworks = ["NIS2", "GDPR"]
```

Real output on a Linux test server (OpenSSH container), after the findings:

```
NIS2 | 4 controls | 237 rules: 32 passed, 34 failed, 171 not evaluated
  Control     Section                                                       Pass    Fail     N/E
  21.2.b      Incident handling                                                1       6      13
  21.2.e      Security in acquisition, development and maintenance            12      23      70
  21.2.h      Cryptography                                                     1       0      33
  21.2.i      Access control and asset management                             18       5      55
```

and on an Azure test subscription with `--framework gdpr`:

```
GDPR | 6 controls | 122 rules: 13 passed, 68 failed, 41 not evaluated
  Control     Section                                                       Pass    Fail     N/E
  25          Data protection by design and by default                         0       7      14
  32.1.a      Pseudonymisation and encryption of personal data                 5      14       6
  32.1.b      Confidentiality, integrity, availability and resilience of       5      27       8
  32.1.c      Ability to restore availability and access to personal dat       0       7       0
  33          Notification of a personal data breach (detection)               0      12       4
  44          Transfers of personal data to third countries                    3       1       9
```

A rule counts once per control: **Fail** when it has at least one violation,
**N/E** (not evaluated) when the target has none of the objects it reads (an
Apache rule on a server without Apache), **Pass** otherwise. The table is
printed with the text output; with `-o json` every violation carries its
`compliance` list instead.

## NIS2 (art. 21(2))

| Measure | What the rules check | Rules |
|---------|----------------------|------:|
| 21.2.a Risk analysis and security policies | Process: not checked | 0 |
| 21.2.b Incident handling | Audit logs on, kept and exported; alerts on security events; failed logins | 150 |
| 21.2.c Business continuity | Backups, point-in-time recovery, versioning, soft delete, replication | 40 |
| 21.2.d Supply chain security | Third-party apps and consent, marketplace apps, cross-tenant access | 7 |
| 21.2.e Secure acquisition, development and maintenance | Hardening (CIS), patches and CVEs, branch protection and reviews | 342 |
| 21.2.f Effectiveness assessment | The scans themselves, with history in a [save backend](alerting-and-saving.md) | 1 |
| 21.2.g Cyber hygiene and training | Password and key hygiene (the training part is a process) | 24 |
| 21.2.h Cryptography | TLS versions and ciphers, encryption at rest, KMS keys and their rotation | 177 |
| 21.2.i Access control and asset management | Least privilege, admin accounts, public exposure, inventory, data residency | 561 |
| 21.2.j Multi-factor authentication | MFA enforced, phishing-resistant methods | 10 |

## SOC 2

| Criterion | What the rules check | Rules |
|-----------|----------------------|------:|
| CC6.1 Logical access security and encryption | Accounts, roles, MFA, keys, encryption at rest | 512 |
| CC6.6 Protection against threats from outside system boundaries | Public endpoints, firewalls, network policies, open ports | 138 |
| CC6.7 Protection of data in transmission | TLS, HSTS, certificates, mail authentication (SPF, DKIM, DMARC) | 121 |
| CC7.1 Detection of configuration changes and vulnerabilities | Hardening baselines, CVEs, patches, vulnerability scanning | 333 |
| CC7.2 Monitoring of system components for anomalies | Audit logs, alerting, log retention | 138 |
| CC8.1 Change management | Branch protection, required reviews and status checks, signed commits | 8 |
| CC9.2 Vendor and business partner risk | Third-party apps, consent, external collaborators | 10 |
| A1.2 Backup and recovery infrastructure | Backups, recovery, replication | 41 |
| C1.1 Confidential information | Data residency | 14 |

## GDPR

| Article | What the rules check | Rules |
|---------|----------------------|------:|
| 25 Data protection by design and by default | Nothing public by default: buckets, databases, sharing, anonymous access | 139 |
| 32(1)(a) Pseudonymisation and encryption | Encryption at rest and in transit, key management | 200 |
| 32(1)(b) Confidentiality, integrity, availability and resilience | Access control, MFA, hardening, patching | 762 |
| 32(1)(c) Restore availability and access | Backups and recovery | 41 |
| 33 Personal data breach notification | Detection: audit logs and alerts, without which a breach cannot be reported within 72 hours | 137 |
| 44 Transfers to third countries | Data residency, see below | 14 |

## Data residency (GDPR art. 44)

Two packs check that resources live in the EU or the EEA:

- [`rules/gcp-data-residency.toml`](../rules/gcp-data-residency.toml): every
  Google Cloud resource (Cloud Asset Inventory), by its location. EU regions
  and zones, the `eu` multi-region and `global` pass, as does an asset with no
  location at all (an API key).
- [`rules/azure-data-residency.toml`](../rules/azure-data-residency.toml):
  13 Azure types that hold data (storage, SQL, PostgreSQL, MySQL, Cosmos DB,
  VMs and disks, App Service, AKS, Key Vault, registries, Log Analytics,
  backup vaults), by region.

London (`europe-west2`, `uksouth`) and Zurich (`europe-west6`,
`switzerlandnorth`) are outside the EU. The UK and Switzerland have an
adequacy decision (art. 45), so a transfer there needs no extra safeguard:
copy the pack, add those regions to the lists, and load your copy with `-R`.

AWS is scanned one region at a time (`aws://eu-west-3`), so there is no
residency rule for it: scan the regions you use and check that each is in the
EU. Microsoft 365 and Google Workspace data location is a tenant setting that
no API exposes in a way kxn reads today.

## How the mappings are made

[`scripts/map-compliance.py`](../scripts/map-compliance.py) sorts each rule
into one control category (MFA, backups, encryption in transit or at rest,
public exposure, logging, vulnerabilities, change management, supply chain,
access, hardening) from its name, description, object and properties, and
writes the NIS2, SOC 2 and GDPR blocks of that category into the rule file. A
block a rule already has for a framework is never replaced, so a hand-written
mapping always wins. CI runs the script with `--check`: a new security rule
without its mappings fails the build.

```bash
python3 scripts/map-compliance.py            # add the missing blocks
python3 scripts/map-compliance.py --report   # category of every rule
```

## What kxn cannot check

- **NIS2:** risk analysis and security policies (21.2.a), training (21.2.g),
  incident reporting to the CSIRT within 24 and 72 hours (art. 23), management
  body accountability (art. 20).
- **SOC 2:** control environment and risk assessment (CC1 to CC5), vendor
  contracts, the audit itself by a CPA firm.
- **GDPR:** lawful basis and consent (art. 6 and 7), data subject rights
  (art. 12 to 22), records of processing (art. 30), DPIA (art. 35), DPO
  (art. 37), processor contracts (art. 28), retention periods of personal data
  (art. 5(1)(e)), which depend on what each store holds.
