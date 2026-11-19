#!/usr/bin/env bash
# Builds the kind cluster used by kxn-demo.tape.
#
#   ./assets/demo/setup-kind.sh          # create cluster + workloads + port-forwards, write demo.env
#   ./assets/demo/setup-kind.sh down     # stop port-forwards and delete the cluster
#
# Works with docker or podman (export KIND_EXPERIMENTAL_PROVIDER=podman).
set -euo pipefail

CLUSTER=${CLUSTER:-kxn-demo}
CTX=kind-$CLUSTER
OUT=${OUT:-$(pwd)/demo-work}
PG_PORT=${PG_PORT:-25432}
SSH_PORT=${SSH_PORT:-22222}
K="kubectl --context $CTX"

if [ "${1:-}" = "down" ]; then
  [ -f "$OUT/port-forward.pids" ] && xargs -r kill < "$OUT/port-forward.pids" 2>/dev/null || true
  kind delete cluster --name "$CLUSTER"
  exit 0
fi

mkdir -p "$OUT"
kind get clusters 2>/dev/null | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER"

$K apply -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata: {name: demo}
---
# Deliberately bad workloads: privileged, :latest, no resource limits
apiVersion: apps/v1
kind: Deployment
metadata: {name: legacy-web, namespace: demo}
spec:
  replicas: 2
  selector: {matchLabels: {app: legacy-web}}
  template:
    metadata: {labels: {app: legacy-web}}
    spec:
      containers:
      - name: web
        image: nginx:latest
        securityContext: {privileged: true, runAsUser: 0}
---
apiVersion: v1
kind: Pod
metadata: {name: payment-worker, namespace: demo}
spec:
  containers:
  - name: worker
    image: busybox:latest
    command: ["sh", "-c", "i=0; while true; do i=$((i+1)); echo \"INFO processed batch $i\"; echo \"ERROR payment gateway timeout after 30s (order=$i)\"; sleep 3; done"]
---
apiVersion: v1
kind: Pod
metadata: {name: crashy, namespace: demo}
spec:
  containers:
  - name: app
    image: busybox:latest
    command: ["sh", "-c", "echo 'FATAL cannot open config'; exit 1"]
---
apiVersion: v1
kind: Pod
metadata: {name: postgres, namespace: demo, labels: {app: postgres}}
spec:
  containers:
  - name: postgres
    image: postgres:16
    env:
    - {name: POSTGRES_PASSWORD, value: demo}
    - {name: POSTGRES_DB, value: kxn}
    resources:
      requests: {cpu: 100m, memory: 256Mi}
      limits: {cpu: "1", memory: 512Mi}
---
# "Legacy VM": an old Debian snapshot with sshd, for the package CVE scan
apiVersion: v1
kind: Pod
metadata: {name: legacy-vm, namespace: demo, labels: {app: legacy-vm}}
spec:
  containers:
  - name: sshd
    image: debian:bookworm-20240110
    command: ["bash", "-c"]
    args:
    - |
      set -e
      apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends openssh-server >/dev/null
      echo 'root:demo' | chpasswd
      printf 'PermitRootLogin yes\nPasswordAuthentication yes\nPort 2222\n' > /etc/ssh/sshd_config.d/demo.conf
      mkdir -p /run/sshd && exec /usr/sbin/sshd -D -e
    readinessProbe:
      tcpSocket: {port: 2222}
      periodSeconds: 3
---
# Read-only identity for kxn (kxn does not read kubeconfig: it uses K8S_API_URL + K8S_TOKEN)
apiVersion: v1
kind: ServiceAccount
metadata: {name: kxn-reader, namespace: default}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: kxn-reader}
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["get", "list", "watch"]
- nonResourceURLs: ["*"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: kxn-reader}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: kxn-reader}
subjects:
- {kind: ServiceAccount, name: kxn-reader, namespace: default}
EOF

$K -n demo wait --for=condition=Ready pod/postgres pod/legacy-vm pod/payment-worker --timeout=300s
$K -n demo rollout status deploy/legacy-web --timeout=300s

# Port-forwards for the database and SSH targets
[ -f "$OUT/port-forward.pids" ] && xargs -r kill < "$OUT/port-forward.pids" 2>/dev/null || true
: > "$OUT/port-forward.pids"
$K -n demo port-forward pod/postgres "$PG_PORT:5432" >/dev/null 2>&1 & echo $! >> "$OUT/port-forward.pids"
$K -n demo port-forward pod/legacy-vm "$SSH_PORT:2222" >/dev/null 2>&1 & echo $! >> "$OUT/port-forward.pids"
sleep 3

API=$(kubectl config view --raw --minify --context "$CTX" -o jsonpath='{.clusters[0].cluster.server}')
kubectl config view --raw --minify --context "$CTX" \
  -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$OUT/ca.crt"
TOKEN=$($K -n default create token kxn-reader --duration=24h)

cat > "$OUT/demo.env" <<EOF
export K8S_API_URL=$API
export K8S_TOKEN=$TOKEN
export K8S_CA_FILE=$OUT/ca.crt
export SSH_INSECURE=true
export PG_PORT=$PG_PORT
export SSH_PORT=$SSH_PORT
EOF

# Config for `kxn watch` / `kxn logs` (rule paths are relative to this file:
# mount it next to the repo's rules/ directory)
cat > "$OUT/kxn.toml" <<EOF
[[rules.mandatory]]
name = "kubernetes-cis"
path = "rules/kubernetes-cis.toml"

[[rules.mandatory]]
name = "postgresql-cis"
path = "rules/postgresql-cis.toml"

[[save]]
type = "postgres"
url = "postgresql://postgres:demo@localhost:$PG_PORT/kxn?sslmode=disable"

[[targets]]
name = "kind"
uri = "kubernetes://kind"
rules = ["kubernetes-cis"]
interval = 30

[[targets]]
name = "orders-db"
uri = "postgresql://postgres:demo@localhost:$PG_PORT?sslmode=disable"
rules = ["postgresql-cis"]
interval = 30
EOF

echo "Ready. Environment: $OUT/demo.env  Config: $OUT/kxn.toml"
