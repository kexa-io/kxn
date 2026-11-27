# Automated SP secret rotation on Kubernetes — Azure

This guide deploys kxn as a Kubernetes CronJob that scans Azure Service Principal secrets daily and rotates every one that expires within 7 days (restricted by the rule's `apply_to`, if set), storing the new secret in Azure Key Vault.

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
  - Azure RBAC: `Key Vault Secrets Officer` on the target vault (RBAC permission model; on an access-policy vault, grant the `Set` secret permission instead)
- `kubectl` configured against your cluster
- kxn image available (`kexa/kxn` on Docker Hub, or your own registry)

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

The shipped `rules/azure-sp-expiry.toml` only detects expiring secrets: it has no `[[rules.remediation]]` block, so with it as is the job reports `No remediable violations found.` Add the `rotateSPSecret` block shown below to the file before creating the ConfigMap, or define the ConfigMap inline:

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

<!-- x-release-please-start-version -->

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
              image: kexa/kxn:v0.67.0
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

<!-- x-release-please-end -->

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
✓ Gathered 1 resources
1 remediation(s) to apply:

  FATAL  sp-secret-expiring-7d
        SP secret expires in less than 7 days
        rotate SP secret → keyvault:my-keyvault/sp-secret
    [rotate-sp-secret] New secret stored in KV my-keyvault/sp-secret (hint: AbCdEfGh...)
        => APPLIED (1/1)

Done: 1/1 remediations applied.
```

"Gathered 1 resources" counts the gathered document, not the service principals. Each violating credential gets its own entry. A failed rotation prints `=> FAILED`, and the run ends with `N of M remediation(s) did not fully apply` and exit status 1.

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

`kxn remediate` has no alerting option and does not read the `[alerts]` table of `kxn.toml`. A failed rotation makes `kxn remediate` exit with status 1, so the Job fails (after `backoffLimit` retries): alert on failed Jobs with your cluster monitoring. To be notified about secrets that are close to expiry, run a separate scan with alerts, for example:

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
| `Graph GET /applications... failed (403)` | Graph refuses to list applications | Verify `Application.Read.All` is granted and admin-consented |
| `No remediable violations found` | No `[[rules.remediation]]` block in the mounted rules, `apply_to` filter too strict, or all SPs healthy | Check the ConfigMap content and that `apply_to` matches the SP `display_name` exactly |
| `addPassword failed (403 ...)` | `Application.ReadWrite.All` missing or not admin-consented | Grant it and re-run `az ad app permission admin-consent` |
| `Key Vault PUT failed (403 ...)` | SP lacks KV access | Re-run `az role assignment create` step |
| `removePassword failed after 3 attempts` (warning) | Azure AD eventual consistency (e.g. `Directory_ConcurrencyViolation`) | kxn retries the removal 3 times, 5 s apart; if it still fails, the new secret is stored but the old credential remains: remove it by hand |
