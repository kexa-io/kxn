# Event-driven compliance — Azure Event Grid → kxn CIS

Instead of waiting for the next scheduled scan, kxn can react instantly to resource creation or modification events. When Azure creates a VM, storage account, or any resource, Event Grid fires a webhook to kxn, which fetches the real resource from ARM and runs CIS rules immediately.

```
Azure creates VM
  → Event Grid fires POST /event to kxn
  → kxn fetches the VM config from ARM REST API
  → kxn runs azure-cis rules
  → violation found → Discord alert in seconds
```

## How it works

`kxn serve --webhook` starts an HTTP server with four routes:

| Route | Purpose |
|-------|---------|
| `POST /event` | Receive Azure Event Grid (or AWS EventBridge / CloudEvents) events |
| `POST /scan` | Check a JSON resource against rules directly |
| `POST /ingest` | Receive scan results (JSON array) and forward them to the `--save` / `--alert` backends |
| `GET /health` | Health check (returns the kxn version; no API key required) |

The server refuses to start without an API key (`--api-key` or the `KXN_WEBHOOK_API_KEY` env var) — see [API key authentication](#api-key-authentication).

When `/event` receives an Azure Event Grid event, kxn:
1. Extracts the `resourceUri` from the event payload (or the `subject` when there is none). Anything that is not an ARM path under `/subscriptions/` is refused
2. Calls `GET https://management.azure.com{resourceUri}?api-version=...`. The API version is inferred from the resource type, and retried once with the version ARM suggests if it is refused. The token comes from `AZURE_ACCESS_TOKEN` if set, else from the service principal (`AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`), else from the Azure CLI login
3. Runs the Azure rules (packs with `provider = "azure"` or `"azurerm"`) whose `object` matches the resource type — see the mapping in Step 2
4. Sends the violations to the `--save` backends and the `--alert` channels (the record's target is the resource id), and returns the result in the HTTP response

kxn treats any Event Grid event this way, whatever its `eventType`: restrict the subscription to `Microsoft.Resources.ResourceWriteSuccess` (as below) so that deletions are not fetched.

## Setup

### Step 1 — Service principal with Reader access

```bash
# Create a service principal
az ad sp create-for-rbac --name kxn-events --role Reader \
  --scopes /subscriptions/<subscription-id>
# Save the appId, password, tenant
```

### Step 2 — CIS rules for Azure

Download the community rules or write your own:

```bash
kxn rules pull                      # writes to ~/.cache/kxn/rules
mkdir -p rules && cp ~/.cache/kxn/rules/azure-*.toml rules/
```

For a known ARM resource type, kxn only runs the rules whose `object` is the matching name below, and the properties are read from the ARM JSON (`properties.*`) plus a few normalized fields (for storage accounts: `enable_https_traffic_only`, `min_tls_version`, `allow_blob_public_access`, ...). For any other resource type, only rules without an `object` are evaluated, against the whole ARM resource.

| ARM type | Rule `object` |
|----------|---------------|
| `Microsoft.Storage/storageAccounts` | `storage_account` |
| `Microsoft.Network/networkSecurityGroups` | `nsg` |
| `Microsoft.Compute/virtualMachines` | `vm` |
| `Microsoft.Compute/disks` | `disk` |
| `Microsoft.KeyVault/vaults` | `key_vault` |
| `Microsoft.Sql/servers/databases` | `sql_database` |
| `Microsoft.Sql/servers` | `sql_server` |
| `Microsoft.ContainerService/managedClusters` | `aks_cluster` |
| `Microsoft.Web/sites` | `app_service` |
| `Microsoft.Network/publicIPAddresses` | `public_ip` |

Example `rules/azure-events.toml`:

```toml
[metadata]
version = "1.0.0"
provider = "azure"
description = "Azure checks run on resource write events"
tags = ["azure", "cis"]

# Encryption at host must be enabled on VMs
[[rules]]
name = "azure-vm-encryption-at-host"
description = "VM does not use encryption at host"
level = 2
object = "vm"

  [[rules.conditions]]
  property = "properties.securityProfile.encryptionAtHost"
  condition = "EQUAL"
  value = true

# Storage accounts must enforce TLS 1.2
[[rules]]
name = "azure-storage-min-tls"
description = "Storage account accepts TLS versions older than 1.2"
level = 2
object = "storage_account"

  [[rules.conditions]]
  property = "min_tls_version"
  condition = "EQUAL"
  value = "TLS1_2"
```

### Step 3 — Start the webhook server (`kxn serve --webhook`)

```bash
export AZURE_TENANT_ID="<tenant-id>"
export AZURE_CLIENT_ID="<app-id>"
export AZURE_CLIENT_SECRET="<password>"
export KXN_WEBHOOK_API_KEY="$(openssl rand -hex 32)"   # required

kxn serve --webhook \
  --port 8080 \
  --rules ./rules \
  --alert "discord://discord.com/api/webhooks/<id>/<token>" \
  --min-level 2
```

With Docker:

<!-- x-release-please-start-version -->

```bash
docker run -d \
  --name kxn-events \
  -p 8080:8080 \
  -v $(pwd)/rules:/rules \
  -e AZURE_TENANT_ID="<tenant-id>" \
  -e AZURE_CLIENT_ID="<app-id>" \
  -e AZURE_CLIENT_SECRET="<password>" \
  -e KXN_WEBHOOK_API_KEY="$KXN_WEBHOOK_API_KEY" \
  kexa/kxn:v0.67.0 \
  serve --webhook --port 8080 --rules /rules \
  --alert "discord://discord.com/api/webhooks/<id>/<token>" --min-level 2
```

<!-- x-release-please-end -->

### Step 4 — Connect Azure Event Grid

kxn must be reachable from Azure. Use your public IP or [ngrok](https://ngrok.com) for local testing:

```bash
# Local testing
ngrok http 8080
# → https://abc123.ngrok.io
```

Create the Event Grid subscription on your resource group (fires on all resource writes):

```bash
az eventgrid event-subscription create \
  --name kxn-cis-realtime \
  --source-resource-id /subscriptions/<sub>/resourceGroups/<rg> \
  --endpoint https://<your-host>:8080/event \
  --included-event-types "Microsoft.Resources.ResourceWriteSuccess"
```

Azure immediately sends a `SubscriptionValidationEvent` — kxn handles the handshake automatically.

## Testing locally

### Simulate an event with curl

```bash
# Get a real resource URI from your subscription
RESOURCE_URI=$(az storage account list --query "[0].id" -o tsv)

curl -X POST http://localhost:8080/event \
  -H "Content-Type: application/json" \
  -H "x-api-key: $KXN_WEBHOOK_API_KEY" \
  -d "[{
    \"id\": \"test-001\",
    \"eventType\": \"Microsoft.Resources.ResourceWriteSuccess\",
    \"subject\": \"$RESOURCE_URI\",
    \"eventTime\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"data\": {
      \"resourceUri\": \"$RESOURCE_URI\",
      \"operationName\": \"Microsoft.Storage/storageAccounts/write\",
      \"status\": \"Succeeded\"
    }
  }]"
```

Expected response:

```json
{
  "event_type": "Microsoft.Resources.ResourceWriteSuccess",
  "provider": "azurerm",
  "scanned": true,
  "total": 5,
  "failed": 2,
  "message": "5 rules checked, 2 violations",
  "saved": false,
  "alerted": true
}
```

`saved` and `alerted` say whether the violations went to the `--save` backends and the `--alert` channels. Both are `false` when there was no violation or no such destination is configured.

### Test the full flow end-to-end

```bash
# Create a VM — Event Grid fires automatically if subscription is set up
az vm create \
  -g <rg> -n test-cis-vm \
  --image Ubuntu2204 --size Standard_B1s \
  --admin-username azureuser --generate-ssh-keys \
  --no-wait

# kxn logs will show:
# [event] fetched Azure resource: /subscriptions/.../virtualMachines/test-cis-vm (Microsoft.Compute/virtualMachines)
# [event] 3 rule(s) for object='vm'
# [event] scan result: 3 rules checked, 1 violation(s)
# and the violation is posted to the --alert channel
```

### Validate the Event Grid handshake manually

```bash
curl -X POST http://localhost:8080/event \
  -H "Content-Type: application/json" \
  -H "x-api-key: $KXN_WEBHOOK_API_KEY" \
  -d '[{
    "eventType": "Microsoft.EventGrid.SubscriptionValidationEvent",
    "data": { "validationCode": "abc123" }
  }]'
# Response: {"validationResponse":"abc123"}
```

## API key authentication

An API key is mandatory: `kxn serve --webhook` refuses to start without `--api-key` or the `KXN_WEBHOOK_API_KEY` env var.

```bash
kxn serve --webhook --port 8080 --rules ./rules --api-key "$KXN_SECRET"
```

All requests to `/event`, `/scan` and `/ingest` must include the header (`/health` is open):

```
x-api-key: <your-secret>
```

Azure Event Grid supports custom headers on webhooks:

```bash
az eventgrid event-subscription create \
  --name kxn-cis-realtime \
  --source-resource-id /subscriptions/<sub>/resourceGroups/<rg> \
  --endpoint https://<host>:8080/event \
  --delivery-attribute-mapping x-api-key static "$KXN_SECRET" \
  --included-event-types "Microsoft.Resources.ResourceWriteSuccess"
```

## Supported event sources

| Source | Format | Route |
|--------|--------|-------|
| Azure Event Grid | Array of events with `eventType` + `data.resourceUri` | `POST /event` |
| AWS EventBridge | Object with `source` + `detail-type` | `POST /event` |
| CloudEvents (CNCF) | `ce-type` / `ce-source` headers (binary mode), or `specversion` + `type` + `source` in the body (structured mode) | `POST /event` |

Only Azure Event Grid events trigger a fetch of the real resource. kxn does not fetch the resource for AWS EventBridge events or CloudEvents. It evaluates the rules of the matching provider against a stub object `{resource_type, resource_id, event: true}`:

- AWS events use the `aws` packs. `resource_type` is the `detail-type`, and `resource_id` is `detail.resourceId` or `detail.arn`.
- CloudEvents are mapped from their `source`: `azure`/`microsoft` → `azurerm`, `aws`/`amazon` → `aws`, `google`/`gcp` → `gcp`; any other source finds no rules. `resource_type` is the CloudEvent `type` and `resource_id` is the literal `cloudevent`.

Rules that read real resource properties find nothing in the stub, so these events are mainly useful with rules written for the stub's fields. Violations are saved and alerted as for Azure events.

## Architecture for production

```
Azure Resource Group
  ├─ Event Grid System Topic
  │    └─ Subscription → POST https://kxn.internal/event
  └─ Resources (VMs, Storage, NSGs, ...)

kxn serve --webhook
  ├─ Receives event
  ├─ Fetches resource from ARM
  ├─ Runs the Azure rules matching the resource type
  └─ Alerts → Discord / Slack / Teams
       └─ Saves → Loki / PostgreSQL
```

Kubernetes deployment:

<!-- x-release-please-start-version -->

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kxn-webhook
  namespace: kxn
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kxn-webhook
  template:
    metadata:
      labels:
        app: kxn-webhook
    spec:
      containers:
        - name: kxn
          image: kexa/kxn:v0.67.0
          args:
            - serve
            - --webhook
            - --port=8080
            - --rules=/rules
            - --alert
            - $(DISCORD_ALERT_URI)   # full URI: discord://discord.com/api/webhooks/<id>/<token>
            - --min-level=2
          ports:
            - containerPort: 8080
          # kxn-azure-creds holds AZURE_TENANT_ID, AZURE_CLIENT_ID and
          # AZURE_CLIENT_SECRET, as created in kubernetes-rotation-azure.md
          envFrom:
            - secretRef:
                name: kxn-azure-creds
          env:
            - name: KXN_WEBHOOK_API_KEY
              valueFrom:
                secretKeyRef:
                  name: kxn-webhook-api-key
                  key: api-key
            - name: DISCORD_ALERT_URI
              valueFrom:
                secretKeyRef:
                  name: kxn-discord
                  key: alert-uri
          volumeMounts:
            - name: rules
              mountPath: /rules
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
      volumes:
        - name: rules
          configMap:
            name: kxn-rules
---
apiVersion: v1
kind: Service
metadata:
  name: kxn-webhook
  namespace: kxn
spec:
  selector:
    app: kxn-webhook
  ports:
    - port: 8080
      targetPort: 8080
```

<!-- x-release-please-end -->
