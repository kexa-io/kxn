# Automated SP secret rotation on Kubernetes — Azure

This guide deploys kxn as a Kubernetes CronJob that scans Azure Service Principal secrets daily and rotates any that expire within 7 days, storing the new secret in Azure Key Vault.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Kubernetes CronJob (kxn)                           │
│                                                     │
│  kxn remediate msgraph://                           │
│    → Microsoft Graph API  (list SP credentials)     │
│    → Graph addPassword    (create new secret)       │
│    → Azure Key Vault      (store new secret)        │
│    → Graph removePassword (delete old secret)       │
└─────────────────────────────────────────────────────┘
```

## Prerequisites

- A Kubernetes cluster (AKS or any cluster with outbound internet access)
- An Azure Service Principal for kxn with the following permissions:
  - Microsoft Graph: `Application.Read.All`, `Application.ReadWrite.All` (application permissions, admin-consented)
  - Azure RBAC: `Key Vault Secrets Officer` on the target vault
- `kubectl` configured against your cluster
- kxn image available (`kexa/kxn:v0.58.0` on Docker Hub, or your own registry)

## Step 1 — Create the kxn Service Principal (if not already done)

```bash
# Create SP
az ad app create --display-name "kxn-rotator"
KXN_APP_ID=$(az ad app list --display-name "kxn-rotator" --query "[0].appId" -o tsv)
az ad sp create --id "$KXN_APP_ID"
KXN_SP_OBJECT_ID=$(az ad sp show --id "$KXN_APP_ID" --query id -o tsv)

# Create a client secret
KXN_SECRET=$(az ad app credential reset --id "$KXN_APP_ID" --query password -o tsv)

# Grant Graph permissions
az ad app permission add \
  --id "$KXN_APP_ID" \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions \
    9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role \
    1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9=Role

az ad app permission admin-consent --id "$KXN_APP_ID"

# Grant Key Vault access
VAULT_NAME="my-keyvault"
VAULT_RG="my-rg"
VAULT_ID=$(az keyvault show --name "$VAULT_NAME" --resource-group "$VAULT_RG" --query id -o tsv)

az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee-object-id "$KXN_SP_OBJECT_ID" \
  --assignee-principal-type ServicePrincipal \
  --scope "$VAULT_ID"
```

## Step 2 — Kubernetes namespace and credentials Secret

```bash
kubectl create namespace kxn
```

```bash
kubectl create secret generic kxn-azure-creds \
  --namespace kxn \
  --from-literal=AZURE_TENANT_ID="<your-tenant-id>" \
  --from-literal=AZURE_CLIENT_ID="$KXN_APP_ID" \
  --from-literal=AZURE_CLIENT_SECRET="$KXN_SECRET"
```

## Step 3 — Rules ConfigMap

```bash
kubectl create configmap kxn-rules-azure \
  --namespace kxn \
  --from-file=rules/azure-sp-expiry.toml
```

Or inline:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kxn-rules-azure
  namespace: kxn
data:
  azure-sp-expiry.toml: |
    [metadata]
    version = "1.0.0"
    provider = "microsoft.graph"

    [[rules]]
    name = "sp-secret-expiring-7d"
    description = "SP secret expires in less than 7 days"
    level = 3
    object = "service_principals"
    apply_to = "display_name=my-app"   # restrict to specific SP

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
    description = "SP secret expires in less than 30 days"
    level = 2
    object = "service_principals"

      [[rules.conditions]]
      operator = "AND"
      criteria = [
        { property = "days_until_expiry", condition = "SUP", value = "30" },
      ]
```

## Step 4 — CronJob manifest

```yaml
# kxn-azure-rotation.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: kxn-azure-rotation
  namespace: kxn
spec:
  schedule: "0 6 * * *"          # every day at 06:00 UTC
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 2
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: kxn
              image: kexa/kxn:v0.58.0
              args:
                - remediate
                - "msgraph://"
                - --rules-dir
                - /rules
                - --auto              # apply all remediable violations without prompting
              envFrom:
                - secretRef:
                    name: kxn-azure-creds
              volumeMounts:
                - name: rules
                  mountPath: /rules
              resources:
                requests:
                  cpu: 100m
                  memory: 64Mi
                limits:
                  cpu: 500m
                  memory: 256Mi
          volumes:
            - name: rules
              configMap:
                name: kxn-rules-azure
```

Apply:

```bash
kubectl apply -f kxn-azure-rotation.yaml
```

## Step 5 — Verify

Run a job immediately (this applies the rotation, like the CronJob):

```bash
# Trigger a one-off job
kubectl create job kxn-azure-test \
  --namespace kxn \
  --from=cronjob/kxn-azure-rotation

# Watch logs
kubectl logs -n kxn -l job-name=kxn-azure-test -f
```

Expected output when a rotation is applied:

```
✓ Gathered 12 resources

  1 remediable violations  │  1 fatal  0 error  0 warn

  ── SERVICE_PRINCIPALS
  1  FATAL  sp-secret-expiring-7d
            SP secret expires in less than 7 days
            rotate SP secret → keyvault:my-keyvault/sp-secret
    [rotate-sp-secret] New secret stored in KV my-keyvault/sp-secret (hint: AbCdEfGh...)
        => APPLIED (1/1)

Done: 1/1 remediations applied.
```

Verify the new secret is in Key Vault:

```bash
az keyvault secret show \
  --vault-name my-keyvault \
  --name sp-secret \
  --query "{updated: attributes.updated, value: value}" \
  -o json
```

## Azure Workload Identity / managed identity — not supported

SP secret rotation authenticates to Microsoft Graph with the client-credentials flow only: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` **and** `AZURE_CLIENT_SECRET` must be set. Federated (Workload Identity) tokens and managed identities are not supported for rotation, so keep the `kxn-azure-creds` Secret from Step 2.

## Alerting on failure

`kxn remediate` has no alerting option and does not read the `[alerts]` table of `kxn.toml`. A failed rotation makes the Job fail (`backoffLimit`), so alert on failed Jobs with your cluster monitoring. To be notified about secrets that are close to expiry, run a separate scan with alerts, for example:

```yaml
args:
  - monitor
  - "msgraph://"
  - --rules
  - /rules
  - --interval
  - "86400"
  - --alert
  - "discord://discord.com/api/webhooks/<id>/<token>"
```

See [alerting-and-saving.md](alerting-and-saving.md) for the other alert URIs and the `[alerts]` table used by `kxn watch`.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `AZURE_TENANT_ID not set` | Secret not mounted | Check `envFrom.secretRef.name` matches the Secret name |
| `app_object_id not found in context` | Graph returned an error object instead of real data | Verify `Application.Read.All` is granted and admin-consented |
| `No remediable violations found` | `apply_to` filter too strict, or credentials correct but all SPs healthy | Check `apply_to` value matches the SP `display_name` exactly |
| `Key Vault Secrets Officer` missing | SP lacks KV access | Re-run `az role assignment create` step |
| `Directory_ConcurrencyViolation` | Azure AD eventual consistency | kxn retries automatically (3 attempts × 5 s) |
