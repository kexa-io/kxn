# Kubernetes Pod Monitor

Deploy kxn as an in-cluster pod to continuously scan your Kubernetes cluster and send alerts (Discord, Slack, PagerDuty, etc.) when pods enter a failed state.

## Prerequisites

- A running Kubernetes cluster with `kubectl` access
- The official image `kexa/kxn:v0.64.0`, published on Docker Hub (amd64 and arm64) by every release; the manifest already uses it
- A Discord (or other) webhook URL

## 1. Create the Discord webhook secret

```bash
kubectl create namespace kxn
kubectl create secret generic kxn-secrets -n kxn \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/ID/TOKEN'
```

## 2. Deploy

The manifest does not contain the `kxn-secrets` Secret, so it does not overwrite the one created in step 1:

```bash
kubectl apply -f deploy/kubernetes/kxn-pod-monitor.yaml
kubectl -n kxn get pods -w
```

## 3. Verify

```bash
# Check logs
kubectl -n kxn logs -l app=kxn-monitor -f

# Test with a failing pod
kubectl run test-fail --image=busybox --restart=Never -- false
# Wait ~2 minutes → Discord alert fires
kubectl delete pod test-fail
```

## Alert format

Discord receives one embed per failing pod:

```
🔴 pod-not-failed
Pod in Failed phase — needs immediate action
Target: ovh-cluster   Object type: pods   Severity: FATAL
Resource: default/test-fail   Node: <node>
Conditions failed: • phase DIFFERENT Failed but got Failed
```

The same violation on the same pod is sent again at most once per hour (`kxn watch --alert-interval`, default 3600 s).

## Update the webhook after regenerating it

```bash
kubectl create secret generic kxn-secrets -n kxn \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/NEW_ID/NEW_TOKEN' \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n kxn rollout restart deployment/kxn-monitor
```

## Customisation

Edit the `pods-not-running.toml` rules in the ConfigMap to adjust severity levels, add namespaces filters, or add more conditions. See [Rules documentation](rules.md).

## Supported alert backends

`kxn watch` (daemon mode, used by this manifest) takes `--webhook URL` — Discord and Slack URLs are auto-detected and formatted natively. For other platforms, add an `[alerts]` table to `kxn.toml` (one list of URIs per severity; the same URIs work with `--alert` on `kxn <uri>` and `kxn monitor <uri>`):

```toml
[alerts]
error = ["slack://hooks.slack.com/services/T/B/xxx"]
fatal = ["pagerduty://routing-key", "discord://discord.com/api/webhooks/ID/TOKEN"]
```

| Backend | URI |
|---------|-----|
| Discord | `discord://discord.com/api/webhooks/ID/TOKEN` |
| Slack | `slack://hooks.slack.com/services/T/B/xxx` |
| Teams | `teams://outlook.webhook.office.com/...` |
| PagerDuty | `pagerduty://routing-key` |

See [Alerting and Saving](alerting-and-saving.md) for the full list.

## TLS verification (`K8S_INSECURE`)

In a pod, kxn verifies the API server certificate against the ServiceAccount CA (`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`). The manifest sets `K8S_INSECURE=true`, which turns that verification off; it was needed on OVH Managed Kubernetes. On a cluster whose API certificate verifies against the ServiceAccount CA, remove these lines from the Deployment:

```yaml
- name: K8S_INSECURE
  value: "true"
```

## Scan interval

`kxn watch` scans every 60 seconds by default (`-n`); this manifest sets `interval = 120` on its target. Adjust in `kxn.toml`:

```toml
[[targets]]
name = "my-cluster"
provider = "kubernetes"
uri = "kubernetes://in-cluster"
interval = 60  # seconds
```
