# Secret rotation — SP secrets & Service Account keys

kxn can detect expiring secrets on cloud service accounts and automatically rotate them, storing the new credential in a secrets manager.

## Overview

```
kxn gathers all SP/SA credentials
  → finds secrets expiring in < 7 days
  → addPassword / creates new key
  → stores new secret in Key Vault / Secret Manager
  → removes old credential
  → sends alert if anything fails
```

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

**For Key Vault write access**, assign `Key Vault Secrets Officer` to the kxn service principal on the target vault:
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

### Scan for expiring secrets

```bash
kxn scan msgraph://
```

### Rule file — `rules/azure-sp-expiry.toml`

```toml
[metadata]
version = "1.0.0"
provider = "microsoft.graph"
description = "Azure Service Principal secret expiration checks"
tags = ["azure", "security", "sp", "rotation"]

[[rules]]
name = "sp-secret-expired"
description = "Service principal secret is expired — rotate immediately"
level = 5
object = "service_principals"

  [[rules.conditions]]
  operator = "AND"
  criteria = [
    { property = "days_until_expiry", condition = "SUP", value = "0" },
  ]

[[rules]]
name = "sp-secret-expiring-7d"
description = "Service principal secret expires in less than 7 days — rotate now"
level = 4
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

> **`apply_to`:** Use `apply_to = "display_name=my-app"` to restrict the remediation to a specific SP. Without it, the first matching SP in the tenant is rotated.

### Run remediation

```bash
# List what would be rotated (no changes)
kxn remediate msgraph://

# Rotate rule #1 (dry-run)
kxn remediate msgraph:// --rule 1 --dry-run

# Apply rotation
kxn remediate msgraph:// --rule 1
```

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

---

## GCP — Service Account keys

### How it works

kxn uses the GCP IAM API to list all service account keys across a project. For each user-managed key it computes `days_until_expiry`. The rotation creates a new JSON key, stores it in Secret Manager, then deletes the old key.

**Required IAM roles** (on the kxn service account):

| Role | Purpose |
|------|---------|
| `roles/iam.serviceAccountKeyAdmin` | List, create, delete SA keys |
| `roles/secretmanager.secretVersionAdder` | Store new secrets |
| `roles/resourcemanager.projectViewer` | List service accounts |

### Authentication

```bash
# Option 1 — Application Default Credentials (recommended for GCP VMs/GKE)
gcloud auth application-default login

# Option 2 — Service account key file
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/keyfile.json"

# Option 3 — Key file content
export GCP_CREDENTIALS_JSON='{"type":"service_account",...}'
```

### Scan for expiring keys

```bash
kxn scan gcp://my-project-id
```

### Rule file — `rules/gcp-sa-key-expiry.toml`

```toml
[metadata]
version = "1.0.0"
provider = "gcp"
description = "GCP Service Account key expiration checks"
tags = ["gcp", "security", "sa", "rotation"]

[[rules]]
name = "sa-key-expired"
description = "Service account key is expired — rotate immediately"
level = 5
object = "service_account_keys"

  [[rules.conditions]]
  operator = "AND"
  criteria = [
    { property = "days_until_expiry", condition = "SUP", value = "0" },
  ]

[[rules]]
name = "sa-key-expiring-7d"
description = "Service account key expires in less than 7 days — rotate now"
level = 4
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
description = "Service account key expires in less than 30 days — plan rotation"
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

# Apply rotation for rule #1
kxn remediate gcp://my-project-id --rule 1
```

### Resource fields (gathered by `gcp://`)

| Field | Type | Description |
|-------|------|-------------|
| `email` | string | Service account email |
| `key_id` | string | Key ID (used for deletion) |
| `key_algorithm` | string | `KEY_ALG_RSA_2048` etc. |
| `valid_after_time` | string | Key creation time (ISO 8601) |
| `valid_before_time` | string | Key expiry time (ISO 8601) |
| `days_until_expiry` | integer | Days until expiry (negative = already expired) |
| `key_type` | string | `USER_MANAGED` (only user-managed keys are gathered) |

---

## Continuous monitoring

Run kxn as a scheduled monitor to alert on expiring secrets before they cause outages:

```bash
# Check every 24h, alert on Discord
kxn monitor msgraph:// \
  --interval 86400 \
  --discord https://discord.com/api/webhooks/...

# GCP equivalent
kxn monitor gcp://my-project-id \
  --interval 86400 \
  --discord https://discord.com/api/webhooks/...
```

Or combine with other providers in a single monitor run using a config file:

```toml
# kxn.toml
[[targets]]
uri = "msgraph://"

[[targets]]
uri = "gcp://my-project-id"
```

```bash
kxn monitor --config kxn.toml --interval 3600
```
