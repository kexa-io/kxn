# Kubernetes Pod Monitor

Deploy kxn as an in-cluster pod to continuously scan your Kubernetes cluster and send alerts (Discord, Slack, PagerDuty, etc.) when pods enter a failed state.

---

## English

### Prerequisites

- A running Kubernetes cluster with `kubectl` access
- The official image `kexa/kxn:v0.64.0` (Docker Hub, used by the manifest), or your own build pushed to a registry the cluster can reach
- A Discord (or other) webhook URL

### 1. Build and push the image (optional)

Skip this step if you use the official `kexa/kxn:v0.64.0` image.

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

The manifest uses `kexa/kxn:v0.64.0`; edit the `image:` in `deploy/kubernetes/kxn-pod-monitor.yaml` only if you built your own. The manifest does not contain the `kxn-secrets` Secret, so it does not overwrite the one created in step 2. Then:

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

Discord receives one embed per failing pod:

```
🔴 pod-not-failed
Pod en état Failed — intervention immédiate requise
Target: ovh-cluster   Object type: pods   Severity: FATAL
Resource: default/test-fail   Node: <node>
Conditions failed: • phase DIFFERENT Failed but got Failed
```

The same violation on the same pod is sent again at most once per hour (`kxn watch --alert-interval`, default 3600 s).

### Customisation

Edit the `pods-not-running.toml` rules in the ConfigMap to adjust severity levels, add namespaces filters, or add more conditions. See [Rules documentation](rules.md).

---

## Français

### Prérequis

- Un cluster Kubernetes avec accès `kubectl`
- L'image officielle `kexa/kxn:v0.64.0` (Docker Hub, utilisée par le manifeste), ou votre propre build poussé dans un registry accessible depuis le cluster
- Une URL de webhook Discord (ou autre)

### 1. Builder et pousser l'image (optionnel)

Étape inutile avec l'image officielle `kexa/kxn:v0.64.0`.

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

Le manifeste utilise `kexa/kxn:v0.64.0` ; ne modifier l'`image:` de `deploy/kubernetes/kxn-pod-monitor.yaml` que pour une image construite soi-même. Le manifeste ne contient pas le Secret `kxn-secrets` et n'écrase donc pas celui créé à l'étape 2. Puis :

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
- La imagen oficial `kexa/kxn:v0.64.0` (Docker Hub, usada por el manifiesto), o una imagen propia en un registro accesible desde el clúster
- Una URL de webhook de Discord (u otro servicio)

### 1. Construir y publicar la imagen (opcional)

Paso innecesario con la imagen oficial `kexa/kxn:v0.64.0`.

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

El manifiesto usa `kexa/kxn:v0.64.0`; modificar la `image:` de `deploy/kubernetes/kxn-pod-monitor.yaml` solo para una imagen propia. El manifiesto no contiene el Secret `kxn-secrets` y no sobrescribe el creado en el paso 2. Luego:

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
- Das offizielle Image `kexa/kxn:v0.64.0` (Docker Hub, im Manifest verwendet) oder ein eigenes Image in einer aus dem Cluster erreichbaren Registry
- Eine Discord-Webhook-URL (oder anderer Dienst)

### 1. Image bauen und pushen (optional)

Mit dem offiziellen Image `kexa/kxn:v0.64.0` entfällt dieser Schritt.

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

Das Manifest verwendet `kexa/kxn:v0.64.0`; das `image:` in `deploy/kubernetes/kxn-pod-monitor.yaml` nur für ein selbst gebautes Image ändern. Das Manifest enthält das Secret `kxn-secrets` nicht und überschreibt das in Schritt 2 erstellte nicht. Dann:

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
- 公式イメージ `kexa/kxn:v0.64.0`（Docker Hub、マニフェストで使用）、またはクラスターからアクセス可能なレジストリにある独自イメージ
- Discord Webhook URL（または他の通知サービス）

### 1. イメージのビルドとプッシュ（任意）

公式イメージ `kexa/kxn:v0.64.0` を使う場合、この手順は不要です。

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

マニフェストは `kexa/kxn:v0.64.0` を使用します。独自にビルドしたイメージを使う場合のみ `image:` を変更してください。マニフェストには Secret `kxn-secrets` が含まれないため、手順 2 で作成した Secret は上書きされません。

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
- 공식 이미지 `kexa/kxn:v0.64.0`(Docker Hub, 매니페스트에서 사용) 또는 클러스터에서 접근 가능한 레지스트리의 자체 이미지
- Discord Webhook URL

### 1. 이미지 빌드 및 푸시 (선택 사항)

공식 이미지 `kexa/kxn:v0.64.0`을 사용하면 이 단계는 필요 없습니다.

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

매니페스트는 `kexa/kxn:v0.64.0`을 사용합니다. 직접 빌드한 이미지를 쓸 때만 `image:`를 수정하세요. 매니페스트에는 Secret `kxn-secrets`가 없으므로 2단계에서 만든 Secret을 덮어쓰지 않습니다.

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
- 官方镜像 `kexa/kxn:v0.64.0`（Docker Hub，清单所用），或推送到集群可访问仓库的自建镜像
- Discord Webhook URL

### 1. 构建并推送镜像（可选）

使用官方镜像 `kexa/kxn:v0.64.0` 时可跳过此步骤。

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

清单使用 `kexa/kxn:v0.64.0`；仅在使用自建镜像时修改 `image:`。清单不包含 Secret `kxn-secrets`，因此不会覆盖第 2 步创建的 Secret。

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
- A imagem oficial `kexa/kxn:v0.64.0` (Docker Hub, usada pelo manifesto), ou uma imagem própria em um registro acessível pelo cluster
- Uma URL de webhook do Discord (ou outro serviço)

### 1. Construir e publicar a imagem (opcional)

Etapa desnecessária com a imagem oficial `kexa/kxn:v0.64.0`.

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

O manifesto usa `kexa/kxn:v0.64.0`; altere a `image:` de `deploy/kubernetes/kxn-pod-monitor.yaml` somente para uma imagem própria. O manifesto não contém o Secret `kxn-secrets` e não sobrescreve o criado na etapa 2.

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

### TLS verification (`K8S_INSECURE`)

In a pod, kxn verifies the API server certificate against the ServiceAccount CA (`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`). The manifest sets `K8S_INSECURE=true`, which turns that verification off; it was needed on OVH Managed Kubernetes. On a cluster whose API certificate verifies against the ServiceAccount CA, remove these lines from the Deployment:

```yaml
- name: K8S_INSECURE
  value: "true"
```

### Scan interval

`kxn watch` scans every 60 seconds by default (`-n`); this manifest sets `interval = 120` on its target. Adjust in `kxn.toml`:

```toml
[[targets]]
name = "my-cluster"
provider = "kubernetes"
uri = "kubernetes://in-cluster"
interval = 60  # seconds
```
