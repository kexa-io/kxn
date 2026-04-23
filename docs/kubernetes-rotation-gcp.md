# Automated SA key rotation on Kubernetes — GCP

This guide deploys kxn as a Kubernetes CronJob that scans GCP Service Account keys daily and rotates any that are older than the configured threshold, storing the new JSON key in Secret Manager.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Kubernetes CronJob (kxn)                           │
│                                                     │
│  kxn remediate gcp://my-project                     │
│    → IAM API    (list SA keys in project)           │
│    → IAM API    (create new JSON key)               │
│    → Secret Manager (store new key as new version)  │
│    → IAM API    (delete old key)                    │
└─────────────────────────────────────────────────────┘
```

## Prerequisites

- A Kubernetes cluster (GKE or any cluster with outbound internet access)
- A GCP Service Account for kxn with the following roles:
  - `roles/iam.serviceAccountKeyAdmin` — list, create, delete SA keys
  - `roles/iam.serviceAccountViewer` — list service accounts in the project
  - `roles/secretmanager.secretVersionAdder` — store new secret versions
  - `roles/secretmanager.secretCreator` — create secrets if they don't exist yet
- `kubectl` configured against your cluster

## Step 1 — Create the kxn Service Account

```bash
PROJECT_ID="my-project"

# Create the SA
gcloud iam service-accounts create kxn-rotator \
  --display-name "kxn SA key rotator" \
  --project "$PROJECT_ID"

KXN_SA="kxn-rotator@${PROJECT_ID}.iam.gserviceaccount.com"

# Grant required roles
for ROLE in \
  roles/iam.serviceAccountKeyAdmin \
  roles/iam.serviceAccountViewer \
  roles/secretmanager.secretVersionAdder \
  roles/secretmanager.secretCreator; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$KXN_SA" \
    --role="$ROLE"
done
```

## Step 2 — Kubernetes namespace

```bash
kubectl create namespace kxn
```

---

## Option A — Key file (simpler, works on any cluster)

### Create a JSON key and store it in Kubernetes

```bash
gcloud iam service-accounts keys create /tmp/kxn-sa-key.json \
  --iam-account "$KXN_SA" \
  --project "$PROJECT_ID"

kubectl create secret generic kxn-gcp-creds \
  --namespace kxn \
  --from-file=key.json=/tmp/kxn-sa-key.json

rm /tmp/kxn-sa-key.json
```

### Rules ConfigMap

```bash
kubectl create configmap kxn-rules-gcp \
  --namespace kxn \
  --from-file=rules/gcp-sa-key-expiry.toml
```

Or inline (customize `project` and `secret` to match your environment):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kxn-rules-gcp
  namespace: kxn
data:
  gcp-sa-key-expiry.toml: |
    [metadata]
    version = "1.0.0"
    provider = "gcp"

    [[rules]]
    name = "sa-key-expiring-7d"
    description = "SA key expires or needs rotation in less than 7 days"
    level = 4
    object = "service_account_keys"
    # apply_to = "email=my-app@project.iam.gserviceaccount.com"

      [[rules.conditions]]
      operator = "AND"
      criteria = [
        { property = "days_until_expiry", condition = "SUP", value = "7" },
      ]

      [[rules.remediation]]
      type = "rotateSAKey"
      project = "my-project"
      secret = "my-sa-key"

    [[rules]]
    name = "sa-key-expiring-30d"
    description = "SA key expires or needs rotation in less than 30 days"
    level = 2
    object = "service_account_keys"

      [[rules.conditions]]
      operator = "AND"
      criteria = [
        { property = "days_until_expiry", condition = "SUP", value = "30" },
      ]
```

### CronJob manifest (key file)

```yaml
# kxn-gcp-rotation.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: kxn-gcp-rotation
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
              image: ghcr.io/kexa-io/kxn:latest
              args:
                - remediate
                - "gcp://my-project"
                - --rules-dir
                - /rules
                - --auto
              env:
                - name: GOOGLE_APPLICATION_CREDENTIALS
                  value: /var/secrets/gcp/key.json
              volumeMounts:
                - name: gcp-creds
                  mountPath: /var/secrets/gcp
                  readOnly: true
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
            - name: gcp-creds
              secret:
                secretName: kxn-gcp-creds
            - name: rules
              configMap:
                name: kxn-rules-gcp
```

```bash
kubectl apply -f kxn-gcp-rotation.yaml
```

---

## Option B — Workload Identity (GKE, recommended)

With Workload Identity, no key file is needed. The kxn pod authenticates directly as the GCP service account via the GKE metadata server.

### Enable Workload Identity on the cluster

```bash
CLUSTER_NAME="my-cluster"
CLUSTER_ZONE="europe-west1-b"

gcloud container clusters update "$CLUSTER_NAME" \
  --zone "$CLUSTER_ZONE" \
  --workload-pool="${PROJECT_ID}.svc.id.goog"
```

### Create a Kubernetes ServiceAccount and bind it to the GCP SA

```bash
kubectl create serviceaccount kxn \
  --namespace kxn

# Allow the K8s SA to impersonate the GCP SA
gcloud iam service-accounts add-iam-policy-binding "$KXN_SA" \
  --member="serviceAccount:${PROJECT_ID}.svc.id.goog[kxn/kxn]" \
  --role="roles/iam.workloadIdentityUser"

# Annotate the K8s SA
kubectl annotate serviceaccount kxn \
  --namespace kxn \
  iam.gke.io/gcp-service-account="$KXN_SA"
```

### CronJob manifest (Workload Identity)

```yaml
# kxn-gcp-rotation-wi.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: kxn-gcp-rotation
  namespace: kxn
spec:
  schedule: "0 6 * * *"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 2
      template:
        spec:
          restartPolicy: OnFailure
          serviceAccountName: kxn        # bound to GCP SA via annotation
          containers:
            - name: kxn
              image: ghcr.io/kexa-io/kxn:latest
              args:
                - remediate
                - "gcp://my-project"
                - --rules-dir
                - /rules
                - --auto
              # No GOOGLE_APPLICATION_CREDENTIALS — uses metadata server
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
                name: kxn-rules-gcp
```

```bash
kubectl apply -f kxn-gcp-rotation-wi.yaml
```

---

## Configuring the rotation threshold

By default kxn considers keys healthy for 90 days. Override via the URI:

```yaml
args:
  - remediate
  - "gcp://my-project?KEY_MAX_AGE_DAYS=60"   # rotate keys older than 60 days
  - --rules-dir
  - /rules
  - --auto
```

Or set the env var `GCP_KEY_MAX_AGE_DAYS` in the container.

## Step — Verify

Trigger a one-off job to confirm everything works:

```bash
kubectl create job kxn-gcp-test \
  --namespace kxn \
  --from=cronjob/kxn-gcp-rotation

kubectl logs -n kxn -l job-name=kxn-gcp-test -f
```

Expected output when a rotation is applied:

```
✓ Gathered 3 resources

  1 remediable violations  │  1 fatal  0 error  0 warn

  ── SERVICE_ACCOUNT_KEYS
  1  FATAL  sa-key-expiring-7d
            SA key expires or needs rotation in less than 7 days
            rotate SA key → secretmanager:my-project/my-sa-key
    [rotate-sa-key] New key stored in Secret Manager my-project/my-sa-key (key: 5e2c00c6...)
        => APPLIED (1/1)

Done: 1/1 remediations applied.
```

Verify the new key version in Secret Manager:

```bash
gcloud secrets versions list my-sa-key --project my-project
```

Verify old key was deleted:

```bash
gcloud iam service-accounts keys list \
  --iam-account="my-app@my-project.iam.gserviceaccount.com" \
  --project my-project
```

## Using the rotated key in another application

After each rotation, Secret Manager holds the latest JSON key as the most recent version. Consume it from another pod:

```bash
# In another CronJob or Deployment, fetch the latest version:
gcloud secrets versions access latest \
  --secret="my-sa-key" \
  --project="my-project" \
  > /var/secrets/gcp/key.json
```

Or mount it via the [Secret Manager CSI driver](https://secrets-store-csi-driver.sigs.k8s.io/) so the pod always sees the current version without a restart.

## Monitoring multiple projects

To scan more than one GCP project, create one CronJob per project, or pass a kxn config file with multiple targets:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kxn-config
  namespace: kxn
data:
  kxn.toml: |
    [[targets]]
    uri = "gcp://project-a"

    [[targets]]
    uri = "gcp://project-b?KEY_MAX_AGE_DAYS=60"
```

```yaml
args:
  - remediate
  - --config
  - /config/kxn.toml
  - --rules-dir
  - /rules
  - --auto
```

## Alerting on failure

```yaml
args:
  - remediate
  - "gcp://my-project"
  - --rules-dir
  - /rules
  - --auto
  - --discord
  - "https://discord.com/api/webhooks/..."
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `GCP auth failed` | No credentials found | Set `GOOGLE_APPLICATION_CREDENTIALS` or use Workload Identity |
| `Gathered 0 resources` | SA lacks `iam.serviceAccountViewer` | Add `roles/iam.serviceAccountViewer` to the kxn SA |
| `IAM GET ... failed (403)` | SA lacks `serviceAccountKeyAdmin` | Add `roles/iam.serviceAccountKeyAdmin` |
| `Secret Manager addVersion failed (403)` | SA lacks Secret Manager write roles | Add `roles/secretmanager.secretVersionAdder` and `roles/secretmanager.secretCreator` |
| `Secret Manager addVersion failed (404)` | Secret doesn't exist yet | kxn creates it automatically on first rotation |
| `No remediable violations found` | All keys within threshold, or `apply_to` too strict | Lower `KEY_MAX_AGE_DAYS` to test, or check `apply_to` filter |
| `org policy constraint iam.disableServiceAccountKeyCreation` | Org policy blocks key creation | Create a standalone project outside the org, or use Workload Identity instead of SA keys |
