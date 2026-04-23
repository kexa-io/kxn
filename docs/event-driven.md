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

`kxn serve --webhook` starts an HTTP server with three routes:

| Route | Purpose |
|-------|---------|
| `POST /event` | Receive Azure Event Grid (or AWS EventBridge / CloudEvents) events |
| `POST /scan` | Check a JSON resource against rules directly |
| `GET /health` | Health check |

When `/event` receives an Azure `ResourceWriteSuccess` event, kxn:
1. Extracts the `resourceUri` from the event payload
2. Calls `GET https://management.azure.com{resourceUri}?api-version=...` with a service principal token
3. Runs all `azurerm` CIS rules against the fetched resource
4. Sends Discord/Slack alerts for any violations

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
kxn rules pull
ls rules/azure-*.toml
```

Example `rules/azure-vm-cis.toml`:

```toml
[metadata]
version = "1.0.0"
provider = "azurerm"
description = "Azure VM CIS checks"
tags = ["azure", "vm", "cis"]

# Disk encryption must be enabled
[[rules]]
name = "azure-vm-disk-encryption"
description = "VM OS disk is not encrypted — enable Azure Disk Encryption"
level = 3
object = "properties.storageProfile.osDisk"

  [[rules.conditions]]
  operator = "AND"
  criteria = [
    { property = "encryptionSettings.enabled", condition = "EQUAL", value = "true" },
  ]

# No public IP directly attached
[[rules]]
name = "azure-vm-no-public-ip"
description = "VM has a public IP attached — use a load balancer or bastion instead"
level = 2
object = "properties.networkProfile.networkInterfaces"

  [[rules.conditions]]
  operator = "AND"
  criteria = [
    { property = "properties.primary", condition = "EQUAL", value = "true" },
  ]
```

### Step 3 — Start kxn webhook server

```bash
export AZURE_TENANT_ID="<tenant-id>"
export AZURE_CLIENT_ID="<app-id>"
export AZURE_CLIENT_SECRET="<password>"

kxn serve --webhook \
  --port 8080 \
  --rules ./rules \
  --alert "discord://${DISCORD_WEBHOOK}" \
  --min-level 2
```

With Docker:

```bash
docker run -d \
  --name kxn-events \
  -p 8080:8080 \
  -v $(pwd)/rules:/rules \
  -e AZURE_TENANT_ID="<tenant-id>" \
  -e AZURE_CLIENT_ID="<app-id>" \
  -e AZURE_CLIENT_SECRET="<password>" \
  -e DISCORD_WEBHOOK="https://discord.com/api/webhooks/..." \
  kexa/kxn:latest \
  serve --webhook --port 8080 --rules /rules \
  --alert "discord://${DISCORD_WEBHOOK}" --min-level 2
```

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
  "message": "5 rules checked, 2 violations"
}
```

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
# [event] 3 rules checked, 1 violation
# → Discord alert sent
```

### Validate the Event Grid handshake manually

```bash
curl -X POST http://localhost:8080/event \
  -H "Content-Type: application/json" \
  -d '[{
    "eventType": "Microsoft.EventGrid.SubscriptionValidationEvent",
    "data": { "validationCode": "abc123" }
  }]'
# Response: {"validationResponse":"abc123"}
```

## API key authentication

Protect the endpoint with an API key:

```bash
kxn serve --webhook --port 8080 --rules ./rules --api-key "$KXN_SECRET"
```

All requests must include the header:

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
| CloudEvents (CNCF) | `specversion` + `type` header or body | `POST /event` |

## Architecture for production

```
Azure Resource Group
  ├─ Event Grid System Topic
  │    └─ Subscription → POST https://kxn.internal/event
  └─ Resources (VMs, Storage, NSGs, ...)

kxn webhook server
  ├─ Receives event
  ├─ Fetches resource from ARM
  ├─ Runs CIS rules (azurerm provider)
  └─ Alerts → Discord / Slack / Teams
       └─ Saves → Loki / PostgreSQL
```

Kubernetes deployment:

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
          image: kexa/kxn:latest
          args:
            - serve
            - --webhook
            - --port=8080
            - --rules=/rules
            - --alert
            - discord://$(DISCORD_WEBHOOK)
            - --min-level=2
          ports:
            - containerPort: 8080
          env:
            - name: AZURE_TENANT_ID
              valueFrom:
                secretKeyRef:
                  name: kxn-azure-creds
                  key: tenant-id
            - name: AZURE_CLIENT_ID
              valueFrom:
                secretKeyRef:
                  name: kxn-azure-creds
                  key: client-id
            - name: AZURE_CLIENT_SECRET
              valueFrom:
                secretKeyRef:
                  name: kxn-azure-creds
                  key: client-secret
            - name: DISCORD_WEBHOOK
              valueFrom:
                secretKeyRef:
                  name: kxn-discord
                  key: webhook-url
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
