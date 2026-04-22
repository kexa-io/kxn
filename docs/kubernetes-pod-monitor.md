# Kubernetes Pod Monitor

Deploy kxn as an in-cluster pod to continuously scan your Kubernetes cluster and send alerts (Discord, Slack, PagerDuty, etc.) when pods enter a failed state.

---

## English

### Prerequisites

- A running Kubernetes cluster with `kubectl` access
- A Harbor (or other OCI) registry accessible from the cluster, or build the image locally
- A Discord (or other) webhook URL

### 1. Build and push the image

**Using Kaniko (in-cluster build):**

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: kaniko-kxn
  namespace: build
spec:
  restartPolicy: Never
  containers:
  - name: kaniko
    image: gcr.io/kaniko-project/executor:latest
    args:
    - --context=git://github.com/kexa-io/kxn.git#refs/heads/main
    - --dockerfile=Dockerfile
    - --destination=YOUR_REGISTRY/kxn:latest
    - --cache=true
    resources:
      requests:
        cpu: 500m
        memory: 2Gi
      limits:
        cpu: "2"
        memory: 6Gi
    volumeMounts:
    - mountPath: /kaniko/.docker
      name: docker-config
  volumes:
  - name: docker-config
    secret:
      secretName: YOUR_REGISTRY_SECRET
      items:
      - key: .dockerconfigjson
        path: config.json
EOF
```

**Or locally:**

```bash
docker build -t YOUR_REGISTRY/kxn:latest .
docker push YOUR_REGISTRY/kxn:latest
```

### 2. Create the Discord webhook secret

```bash
kubectl create namespace kxn
kubectl create secret generic kxn-secrets -n kxn \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/ID/TOKEN'
```

### 3. Deploy

Edit `deploy/kubernetes/kxn-pod-monitor.yaml` to set your registry image, then:

```bash
kubectl apply -f deploy/kubernetes/kxn-pod-monitor.yaml
kubectl -n kxn get pods -w
```

### 4. Verify

```bash
# Check logs
kubectl -n kxn logs -l app=kxn-monitor -f

# Test with a failing pod
kubectl run test-fail --image=busybox --restart=Never -- false
# Wait ~2 minutes → Discord alert fires
kubectl delete pod test-fail
```

### Alert format

```
🔴 [FATAL] pod-not-failed — Pod en état Failed — intervention immédiate requise
phase DIFFERENT Failed but got Failed
```

### Customisation

Edit the `pods-not-running.toml` rules in the ConfigMap to adjust severity levels, add namespaces filters, or add more conditions. See [Rules documentation](rules.md).

---

## Français

### Prérequis

- Un cluster Kubernetes avec accès `kubectl`
- Un registry OCI (Harbor, ghcr.io, Docker Hub) accessible depuis le cluster
- Une URL de webhook Discord (ou autre)

### 1. Builder et pousser l'image

**Via Kaniko (build in-cluster) :**

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: kaniko-kxn
  namespace: build
spec:
  restartPolicy: Never
  containers:
  - name: kaniko
    image: gcr.io/kaniko-project/executor:latest
    args:
    - --context=git://github.com/kexa-io/kxn.git#refs/heads/main
    - --dockerfile=Dockerfile
    - --destination=VOTRE_REGISTRY/kxn:latest
    - --cache=true
    resources:
      requests:
        cpu: 500m
        memory: 2Gi
      limits:
        cpu: "2"
        memory: 6Gi
    volumeMounts:
    - mountPath: /kaniko/.docker
      name: docker-config
  volumes:
  - name: docker-config
    secret:
      secretName: VOTRE_SECRET_REGISTRY
      items:
      - key: .dockerconfigjson
        path: config.json
EOF
```

**Ou en local :**

```bash
docker build -t VOTRE_REGISTRY/kxn:latest .
docker push VOTRE_REGISTRY/kxn:latest
```

### 2. Créer le Secret du webhook Discord

```bash
kubectl create namespace kxn
kubectl create secret generic kxn-secrets -n kxn \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/ID/TOKEN'
```

### 3. Déployer

Éditer `deploy/kubernetes/kxn-pod-monitor.yaml` pour renseigner l'image, puis :

```bash
kubectl apply -f deploy/kubernetes/kxn-pod-monitor.yaml
kubectl -n kxn get pods -w
```

### 4. Vérifier

```bash
# Voir les logs
kubectl -n kxn logs -l app=kxn-monitor -f

# Tester avec un pod en erreur
kubectl run test-fail --image=busybox --restart=Never -- false
# Attendre ~2 min → alerte Discord reçue
kubectl delete pod test-fail
```

### Mettre à jour le webhook après régénération

```bash
kubectl create secret generic kxn-secrets -n kxn \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/NOUVEL_ID/NOUVEAU_TOKEN' \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n kxn rollout restart deployment/kxn-monitor
```

---

## Español

### Requisitos previos

- Un clúster de Kubernetes con acceso `kubectl`
- Un registro OCI (Harbor, ghcr.io, Docker Hub) accesible desde el clúster
- Una URL de webhook de Discord (u otro servicio)

### 1. Construir y publicar la imagen

**Con Kaniko (build dentro del clúster):**

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: kaniko-kxn
  namespace: build
spec:
  restartPolicy: Never
  containers:
  - name: kaniko
    image: gcr.io/kaniko-project/executor:latest
    args:
    - --context=git://github.com/kexa-io/kxn.git#refs/heads/main
    - --dockerfile=Dockerfile
    - --destination=SU_REGISTRY/kxn:latest
    - --cache=true
    resources:
      requests:
        cpu: 500m
        memory: 2Gi
      limits:
        cpu: "2"
        memory: 6Gi
    volumeMounts:
    - mountPath: /kaniko/.docker
      name: docker-config
  volumes:
  - name: docker-config
    secret:
      secretName: SU_SECRET_REGISTRY
      items:
      - key: .dockerconfigjson
        path: config.json
EOF
```

**O localmente:**

```bash
docker build -t SU_REGISTRY/kxn:latest .
docker push SU_REGISTRY/kxn:latest
```

### 2. Crear el Secret del webhook

```bash
kubectl create namespace kxn
kubectl create secret generic kxn-secrets -n kxn \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/ID/TOKEN'
```

### 3. Desplegar

Editar `deploy/kubernetes/kxn-pod-monitor.yaml` con la imagen correcta, luego:

```bash
kubectl apply -f deploy/kubernetes/kxn-pod-monitor.yaml
kubectl -n kxn get pods -w
```

### 4. Verificar

```bash
kubectl -n kxn logs -l app=kxn-monitor -f

kubectl run test-fail --image=busybox --restart=Never -- false
# Esperar ~2 minutos → alerta Discord recibida
kubectl delete pod test-fail
```

---

## Deutsch

### Voraussetzungen

- Ein laufender Kubernetes-Cluster mit `kubectl`-Zugriff
- Eine OCI-Registry (Harbor, ghcr.io, Docker Hub) aus dem Cluster erreichbar
- Eine Discord-Webhook-URL (oder anderer Dienst)

### 1. Image bauen und pushen

**Mit Kaniko (In-Cluster-Build):**

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: kaniko-kxn
  namespace: build
spec:
  restartPolicy: Never
  containers:
  - name: kaniko
    image: gcr.io/kaniko-project/executor:latest
    args:
    - --context=git://github.com/kexa-io/kxn.git#refs/heads/main
    - --dockerfile=Dockerfile
    - --destination=IHRE_REGISTRY/kxn:latest
    - --cache=true
    resources:
      requests:
        cpu: 500m
        memory: 2Gi
      limits:
        cpu: "2"
        memory: 6Gi
    volumeMounts:
    - mountPath: /kaniko/.docker
      name: docker-config
  volumes:
  - name: docker-config
    secret:
      secretName: IHR_REGISTRY_SECRET
      items:
      - key: .dockerconfigjson
        path: config.json
EOF
```

**Oder lokal:**

```bash
docker build -t IHRE_REGISTRY/kxn:latest .
docker push IHRE_REGISTRY/kxn:latest
```

### 2. Discord-Webhook-Secret erstellen

```bash
kubectl create namespace kxn
kubectl create secret generic kxn-secrets -n kxn \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/ID/TOKEN'
```

### 3. Deployen

`deploy/kubernetes/kxn-pod-monitor.yaml` mit dem richtigen Image bearbeiten, dann:

```bash
kubectl apply -f deploy/kubernetes/kxn-pod-monitor.yaml
kubectl -n kxn get pods -w
```

### 4. Verifizieren

```bash
kubectl -n kxn logs -l app=kxn-monitor -f

kubectl run test-fail --image=busybox --restart=Never -- false
# ~2 Minuten warten → Discord-Alarm empfangen
kubectl delete pod test-fail
```

---

## 日本語 (Japanese)

### 前提条件

- `kubectl` アクセス可能な Kubernetes クラスター
- クラスターからアクセス可能な OCI レジストリ（Harbor、ghcr.io など）
- Discord Webhook URL（または他の通知サービス）

### 1. イメージのビルドとプッシュ

**Kaniko を使ったクラスター内ビルド：**

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: kaniko-kxn
  namespace: build
spec:
  restartPolicy: Never
  containers:
  - name: kaniko
    image: gcr.io/kaniko-project/executor:latest
    args:
    - --context=git://github.com/kexa-io/kxn.git#refs/heads/main
    - --dockerfile=Dockerfile
    - --destination=YOUR_REGISTRY/kxn:latest
    - --cache=true
    resources:
      requests:
        cpu: 500m
        memory: 2Gi
    volumeMounts:
    - mountPath: /kaniko/.docker
      name: docker-config
  volumes:
  - name: docker-config
    secret:
      secretName: YOUR_REGISTRY_SECRET
      items:
      - key: .dockerconfigjson
        path: config.json
EOF
```

### 2. Secret の作成

```bash
kubectl create namespace kxn
kubectl create secret generic kxn-secrets -n kxn \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/ID/TOKEN'
```

### 3. デプロイ

```bash
kubectl apply -f deploy/kubernetes/kxn-pod-monitor.yaml
kubectl -n kxn logs -l app=kxn-monitor -f
```

### 4. テスト

```bash
kubectl run test-fail --image=busybox --restart=Never -- false
# 約2分後に Discord へアラートが送信されます
kubectl delete pod test-fail
```

---

## 한국어 (Korean)

### 전제 조건

- `kubectl` 접근 가능한 Kubernetes 클러스터
- 클러스터에서 접근 가능한 OCI 레지스트리
- Discord Webhook URL

### 1. 이미지 빌드 및 푸시

```bash
docker build -t YOUR_REGISTRY/kxn:latest .
docker push YOUR_REGISTRY/kxn:latest
```

### 2. Secret 생성

```bash
kubectl create namespace kxn
kubectl create secret generic kxn-secrets -n kxn \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/ID/TOKEN'
```

### 3. 배포

```bash
kubectl apply -f deploy/kubernetes/kxn-pod-monitor.yaml
kubectl -n kxn get pods -w
```

### 4. 테스트

```bash
kubectl run test-fail --image=busybox --restart=Never -- false
# 약 2분 후 Discord 알림 수신
kubectl delete pod test-fail
```

---

## 中文 (Chinese)

### 先决条件

- 可以使用 `kubectl` 访问的 Kubernetes 集群
- 集群可访问的 OCI 镜像仓库
- Discord Webhook URL

### 1. 构建并推送镜像

```bash
docker build -t YOUR_REGISTRY/kxn:latest .
docker push YOUR_REGISTRY/kxn:latest
```

### 2. 创建 Secret

```bash
kubectl create namespace kxn
kubectl create secret generic kxn-secrets -n kxn \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/ID/TOKEN'
```

### 3. 部署

```bash
kubectl apply -f deploy/kubernetes/kxn-pod-monitor.yaml
kubectl -n kxn get pods -w
```

### 4. 验证

```bash
kubectl run test-fail --image=busybox --restart=Never -- false
# 等待约 2 分钟 → 收到 Discord 告警
kubectl delete pod test-fail
```

---

## Português

### Pré-requisitos

- Um cluster Kubernetes com acesso `kubectl`
- Um registro OCI (Harbor, ghcr.io, Docker Hub) acessível pelo cluster
- Uma URL de webhook do Discord (ou outro serviço)

### 1. Construir e publicar a imagem

```bash
docker build -t SEU_REGISTRY/kxn:latest .
docker push SEU_REGISTRY/kxn:latest
```

### 2. Criar o Secret do webhook

```bash
kubectl create namespace kxn
kubectl create secret generic kxn-secrets -n kxn \
  --from-literal=DISCORD_WEBHOOK='https://discord.com/api/webhooks/ID/TOKEN'
```

### 3. Implantar

```bash
kubectl apply -f deploy/kubernetes/kxn-pod-monitor.yaml
kubectl -n kxn get pods -w
```

### 4. Verificar

```bash
kubectl run test-fail --image=busybox --restart=Never -- false
# Aguardar ~2 minutos → alerta Discord recebido
kubectl delete pod test-fail
```

---

## Notes communes / Common notes

### Supported alert backends

Replace `--webhook` with `--alert` in `kxn scan` for richer platform integrations:

| Backend | URI |
|---------|-----|
| Discord | `https://discord.com/api/webhooks/ID/TOKEN` |
| Slack | `slack://hooks.slack.com/services/T/B/xxx` |
| Teams | `teams://outlook.webhook.office.com/...` |
| PagerDuty | `pagerduty://routing-key` |

For `kxn watch` (daemon mode), use `--webhook URL` — Discord and Slack URLs are auto-detected and formatted natively.

### OVH Managed Kubernetes

When running on OVH Managed Kubernetes, the cluster CA is not in the Debian container trust store. Add this env var to the Deployment:

```yaml
- name: K8S_INSECURE
  value: "true"
```

### Scan interval

Default is 120 seconds. Adjust in `kxn.toml`:

```toml
[[targets]]
name = "my-cluster"
provider = "kubernetes"
uri = "kubernetes://in-cluster"
interval = 60  # seconds
```
