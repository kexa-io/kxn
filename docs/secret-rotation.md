# Secret rotation — SP secrets & Service Account keys

kxn can detect expiring secrets on cloud service accounts and automatically rotate them, storing the new credential in a secrets manager.

## Overview

```
kxn gathers all SP/SA credentials
  → finds secrets expiring in < 7 days
  → addPassword / creates new key
  → stores new secret in Key Vault / Secret Manager
  → removes old credential
  → prints FAILED and exits 1 if a rotation fails
```

`kxn remediate` itself sends no alert. Use `kxn monitor --alert` (see [Continuous monitoring](#continuous-monitoring)) to be told about credentials that are close to expiry.

Two providers are supported:

| Cloud | Identity | Secrets store | Provider URI |
|-------|----------|--------------|-------------|
| Azure | Service Principal (App Registration) | Azure Key Vault | `msgraph://` |
| GCP   | Service Account | Secret Manager | `gcp://project-id` |

---

## Azure — Service Principal secrets

### How it works

kxn uses the Microsoft Graph API to enumerate all application registrations and their `passwordCredentials`. For each credential it computes `days_until_expiry` and surfaces three alert levels.

**Required permissions** (on the kxn service principal):

| Permission | Purpose |
|-----------|---------|
| `Application.Read.All` | List all applications and credentials |
| `Application.ReadWrite.All` | Add/remove password credentials (rotation only) |

Grant via Azure CLI:
```bash
az ad app permission add \
  --id <kxn-app-id> \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role \  # Application.Read.All
                    1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9=Role     # Application.ReadWrite.All

az ad app permission admin-consent --id <kxn-app-id>
```

**For Key Vault write access**, assign `Key Vault Secrets Officer` to the kxn service principal on the target vault. This role applies to vaults that use the Azure RBAC permission model; on a vault that uses access policies, grant the service principal the `Set` secret permission instead:
```bash
az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee <kxn-sp-object-id> \
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<vault>
```

### Environment variables

```bash
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_ID="..."       # kxn service principal appId
export AZURE_CLIENT_SECRET="..."   # kxn service principal secret
```

A scan works without these variables if you are logged in with `az login`: kxn then uses the Azure CLI's token. Rotation does not: `rotateSPSecret` requires all three variables and fails with `AZURE_TENANT_ID not set` (or the client ID or secret) when one is missing.

### Scan for expiring secrets

```bash
kxn msgraph:// --rules rules/azure-sp-expiry.toml
```

### Rule file — `rules/azure-sp-expiry.toml`

The shipped file contains the three detection rules below, without the `[[rules.remediation]]` block or the `apply_to` line. To enable rotation, add them to your copy of the file in the rules directory that `kxn remediate` reads (`./rules`, else `~/.cache/kxn/rules`, or the directory given with `-R`). Without a remediation block, `kxn remediate` reports `No remediable violations found.`

```toml
[metadata]
version = "1.0.0"
provider = "microsoft.graph"
description = "Azure Service Principal secret expiration checks"
tags = ["azure", "security", "sp", "rotation"]

[[rules]]
name = "sp-secret-expired"
description = "Service principal secret is expired — rotate immediately"
level = 3
object = "service_principals"

  [[rules.conditions]]
  operator = "AND"
  criteria = [
    { property = "days_until_expiry", condition = "SUP", value = "0" },
  ]

[[rules]]
name = "sp-secret-expiring-7d"
description = "Service principal secret expires in less than 7 days — rotate now"
level = 3
object = "service_principals"
# apply_to = "display_name=my-app"  # optional: restrict to specific SP

  [[rules.conditions]]
  operator = "AND"
  criteria = [
    { property = "days_until_expiry", condition = "SUP", value = "7" },
  ]

  [[rules.remediation]]
  type = "rotateSPSecret"
  vault = "my-keyvault"
  secret_name = "sp-secret"

[[rules]]
name = "sp-secret-expiring-30d"
description = "Service principal secret expires in less than 30 days — plan rotation"
level = 2
object = "service_principals"

  [[rules.conditions]]
  operator = "AND"
  criteria = [
    { property = "days_until_expiry", condition = "SUP", value = "30" },
  ]
```

> **Condition semantics:** `SUP N` means "desired state: days > N". Violation fires when `days_until_expiry ≤ N`.

> **`apply_to`:** Use `apply_to = "display_name=my-app"` to restrict the remediation to a specific SP. Without it, every credential in the tenant that violates the rule is rotated.

> **One `vault`/`secret_name` per rule:** every credential rotated by the same rule is written to the same Key Vault secret, each overwriting the previous one. Use one rule with its own `apply_to` and `secret_name` per application when more than one SP can be affected.

### What a rotation does

1. `POST /applications/{app_object_id}/addPassword` on Microsoft Graph creates a password named `<display_name> (rotated by kxn)`, valid for 365 days.
2. The new value is written with `PUT https://<vault>.vault.azure.net/secrets/<secret_name>` (a new version of the secret). Underscores in `secret_name` are replaced by hyphens, as Key Vault does not accept them. If this write fails, the rotation stops: the new password already exists on the application and the old one is kept.
3. `POST /applications/{app_object_id}/removePassword` deletes the old credential. It is retried 3 times, 5 seconds apart; if it still fails, kxn prints a warning and the old credential stays in place (the rotation is still counted as applied).

### Run remediation

```bash
# List what would be rotated (no changes)
kxn remediate msgraph://

# Rotate for one rule (dry-run)
kxn remediate msgraph:// --rule sp-secret-expiring-7d --dry-run

# Apply rotation
kxn remediate msgraph:// --rule sp-secret-expiring-7d
```

The list shows one numbered row per violating credential. `--rule <number>` selects one row; `--rule <name>` selects every row of that rule. A failed rotation prints `=> FAILED` and makes `kxn remediate` exit with status 1.

### Resource fields (gathered by `msgraph://`)

| Field | Type | Description |
|-------|------|-------------|
| `app_id` | string | Application (client) ID |
| `app_object_id` | string | Application object ID (used for addPassword) |
| `display_name` | string | Application display name |
| `credential_id` | string | Password credential key ID |
| `credential_name` | string | Credential display name |
| `end_date_time` | string | Expiry datetime (ISO 8601) |
| `days_until_expiry` | integer | Days until expiry (negative = already expired) |
| `expired` | boolean | `true` when `days_until_expiry` is negative |

One object is produced per password credential. An application with no password credential still produces one object, with `credential_id`, `credential_name`, `end_date_time` and `days_until_expiry` set to `null`; the expiry rules do not flag it.

---

## GCP — Service Account keys

### How it works

kxn uses the GCP IAM API to list the user-managed keys of every service account in a project. For each key it computes `days_until_expiry`:

- if the key has a real expiry date (`validBeforeTime`), from that date;
- if it never expires (GCP reports year 9999), from an effective expiry of creation date + `KEY_MAX_AGE_DAYS` (default 90). Set it with `gcp://my-project-id?KEY_MAX_AGE_DAYS=60` or the `GCP_KEY_MAX_AGE_DAYS` environment variable.

The rotation creates a new JSON key (`KEY_ALG_RSA_2048`), stores it as a new version of the Secret Manager secret, then deletes the old key. Deletion is retried 3 times, 3 seconds apart; if it still fails, kxn prints a warning and the old key stays in place.

**Required IAM roles** (on the kxn service account):

| Role | Purpose |
|------|---------|
| `roles/iam.serviceAccountKeyAdmin` | List, create, delete SA keys |
| `roles/secretmanager.secretVersionAdder` | Store new secret versions (create the secret beforehand with `gcloud secrets create`; kxn creates a missing secret only if its service account may read and create secrets, e.g. `roles/secretmanager.admin`) |
| `roles/iam.serviceAccountViewer` | List service accounts |

### Authentication

```bash
# Option 1 — Application Default Credentials (recommended for GCP VMs/GKE)
gcloud auth application-default login

# Option 2 — Service account key file
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/keyfile.json"
```

### Scan for expiring keys

```bash
kxn gcp://my-project-id --rules rules/gcp-sa-key-expiry.toml
```

### Rule file — `rules/gcp-sa-key-expiry.toml`

As for Azure, the shipped file has no `[[rules.remediation]]` block and no `apply_to` line: add them to your copy in the rules directory to enable rotation.

```toml
[metadata]
version = "1.0.0"
provider = "gcp"
description = "GCP Service Account key rotation checks"
tags = ["gcp", "security", "sa", "rotation"]

[[rules]]
name = "sa-key-expired"
description = "Service account key is expired or past max rotation age — rotate immediately"
level = 3
object = "service_account_keys"

  [[rules.conditions]]
  operator = "AND"
  criteria = [
    { property = "days_until_expiry", condition = "SUP", value = "0" },
  ]

[[rules]]
name = "sa-key-expiring-7d"
description = "Service account key expires or needs rotation in less than 7 days"
level = 3
object = "service_account_keys"
# apply_to = "email=my-sa@project.iam.gserviceaccount.com"

  [[rules.conditions]]
  operator = "AND"
  criteria = [
    { property = "days_until_expiry", condition = "SUP", value = "7" },
  ]

  [[rules.remediation]]
  type = "rotateSAKey"
  project = "my-project-id"
  secret = "my-sa-key"

[[rules]]
name = "sa-key-expiring-30d"
description = "Service account key expires or needs rotation in less than 30 days — plan rotation"
level = 2
object = "service_account_keys"

  [[rules.conditions]]
  operator = "AND"
  criteria = [
    { property = "days_until_expiry", condition = "SUP", value = "30" },
  ]
```

### Run remediation

```bash
# List what would be rotated
kxn remediate gcp://my-project-id

# Apply rotation for every key flagged by the rule
kxn remediate gcp://my-project-id --rule sa-key-expiring-7d
```

Without `apply_to`, every key that violates the rule is rotated, and each new key is added as a new version of the same secret. Use one rule per service account, each with its own `apply_to` and `secret`, when more than one account can be affected.

### Resource fields (gathered by `gcp://`)

| Field | Type | Description |
|-------|------|-------------|
| `email` | string | Service account email |
| `key_id` | string | Key ID (used for deletion) |
| `key_algorithm` | string | `KEY_ALG_RSA_2048` etc. |
| `valid_after_time` | string | Key creation time (ISO 8601) |
| `valid_before_time` | string | Effective expiry time (ISO 8601): the key's own expiry, or creation + `KEY_MAX_AGE_DAYS` for a key that never expires |
| `days_until_expiry` | integer | Days until expiry (negative = already expired) |
| `key_type` | string | `USER_MANAGED` (only user-managed keys are gathered) |

---

## Continuous monitoring

Run kxn as a scheduled monitor to alert on expiring secrets before they cause outages:

```bash
# Check every 24h, alert on Discord
kxn monitor msgraph:// \
  --rules rules/azure-sp-expiry.toml \
  --interval 86400 \
  --alert discord://discord.com/api/webhooks/<id>/<token>

# GCP equivalent
kxn monitor gcp://my-project-id \
  --rules rules/gcp-sa-key-expiry.toml \
  --interval 86400 \
  --alert discord://discord.com/api/webhooks/<id>/<token>
```

Or watch several targets in one daemon with a config file (`kxn monitor` takes a single URI; `kxn watch` reads `[[targets]]`):

```toml
# kxn.toml
[rules]
mandatory = [
  { name = "azure-sp-expiry",   path = "rules/azure-sp-expiry.toml" },
  { name = "gcp-sa-key-expiry", path = "rules/gcp-sa-key-expiry.toml" },
]

[[targets]]
name = "azure-sps"
uri = "msgraph://"
rules = ["azure-sp-expiry"]
interval = 3600

[[targets]]
name = "gcp-keys"
uri = "gcp://my-project-id"
rules = ["gcp-sa-key-expiry"]
interval = 3600

[alerts]
error = ["discord://discord.com/api/webhooks/<id>/<token>"]
fatal = ["discord://discord.com/api/webhooks/<id>/<token>"]
```

```bash
kxn watch -c kxn.toml
```
