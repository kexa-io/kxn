use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use base64::Engine as _;
use serde_json::{json, Value};
use x509_parser::prelude::*;

const RESOURCE_TYPES: &[&str] = &[
    "pods",
    "deployments",
    "services",
    "nodes",
    "namespaces",
    "ingresses",
    "configmaps",
    "secrets_metadata",
    "events",
    "cluster_stats",
    "rbac_cluster_roles",
    "rbac_cluster_role_bindings",
    "network_policies",
    "persistent_volumes",
    "persistent_volume_claims",
    "daemonsets",
    "statefulsets",
    "cronjobs",
    "service_accounts",
    "jobs",
    "hpa",
    "resource_quotas",
    "limit_ranges",
    "node_metrics",
    "pod_metrics",
    "pod_logs",
    "roles",
    "role_bindings",
    "validating_webhook_configurations",
    "mutating_webhook_configurations",
    "custom_resource_definitions",
    "storage_classes",
    "pod_disruption_budgets",
    "priority_classes",
    "tls_certs",
    "pod_resource",
];

pub struct KubernetesProvider {
    api_url: String,
    token: Option<String>,
    namespace: Option<String>,
    client: reqwest::Client,
}

impl KubernetesProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let api_url = get_config_or_env(&config, "K8S_API_URL", Some("K8S"))
            .or_else(|| get_config_or_env(&config, "KUBERNETES_SERVICE_HOST", Some("K8S")).map(|h| {
                let port = get_config_or_env(&config, "KUBERNETES_SERVICE_PORT", Some("K8S")).unwrap_or("443".into());
                format!("https://{}:{}", h, port)
            }))
            .unwrap_or_else(|| "https://kubernetes.default.svc".into());

        let token_file = get_config_or_env(&config, "K8S_TOKEN_FILE", Some("K8S"))
            .unwrap_or_else(|| "/var/run/secrets/kubernetes.io/serviceaccount/token".into());
        let ca_file = get_config_or_env(&config, "K8S_CA_FILE", Some("K8S"))
            .unwrap_or_else(|| "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt".into());

        let token = get_config_or_env(&config, "K8S_TOKEN", Some("K8S"))
            .or_else(|| std::fs::read_to_string(&token_file).ok());

        let namespace = get_config_or_env(&config, "K8S_NAMESPACE", Some("K8S"));

        // Only skip TLS verification when explicitly opted-in via K8S_INSECURE=true
        let insecure = get_config_or_env(&config, "K8S_INSECURE", Some("K8S"))
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(insecure);

        // In-cluster: load the cluster CA so TLS to the API server validates.
        // Without this, reqwest only trusts system CAs, which never include the
        // private self-signed CA used by managed Kubernetes API servers.
        if !insecure {
            if let Ok(ca_pem) = std::fs::read(&ca_file) {
                let cert = reqwest::Certificate::from_pem(&ca_pem)
                    .map_err(|e| ProviderError::InvalidConfig(format!("K8S_CA_FILE {}: {}", ca_file, e)))?;
                builder = builder.add_root_certificate(cert);
            }
        }

        let client = builder
            .build()
            .map_err(|e| ProviderError::Connection(format!("HTTP client: {}", e)))?;

        Ok(Self {
            api_url: api_url.trim_end_matches('/').to_string(),
            token,
            namespace,
            client,
        })
    }

    async fn api_get(&self, path: &str) -> Result<Value, ProviderError> {
        let url = format!("{}{}", self.api_url, path);
        let mut req = self.client.get(&url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await
            .map_err(|e| ProviderError::Connection(format!("K8s API: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Query(format!("K8s {} ({}): {}", path, status, text)));
        }

        resp.json().await
            .map_err(|e| ProviderError::Query(format!("K8s parse: {}", e)))
    }

    async fn api_get_text(&self, path: &str) -> Result<String, ProviderError> {
        let url = format!("{}{}", self.api_url, path);
        let mut req = self.client.get(&url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await
            .map_err(|e| ProviderError::Connection(format!("K8s API: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Query(format!("K8s {} ({}): {}", path, status, text)));
        }

        resp.text().await
            .map_err(|e| ProviderError::Query(format!("K8s text parse: {}", e)))
    }

    fn ns_prefix(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("/api/v1/namespaces/{}", ns),
            None => "/api/v1".to_string(),
        }
    }

    fn ns_apps_prefix(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("/apis/apps/v1/namespaces/{}", ns),
            None => "/apis/apps/v1".to_string(),
        }
    }

    fn ns_networking_prefix(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("/apis/networking.k8s.io/v1/namespaces/{}", ns),
            None => "/apis/networking.k8s.io/v1".to_string(),
        }
    }

    fn extract_items(&self, resp: &Value) -> Vec<Value> {
        resp.get("items")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
    }

    async fn gather_pods(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/pods", self.ns_prefix())).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|pod| {
            let metadata = pod.get("metadata").unwrap_or(&Value::Null);
            let spec = pod.get("spec").unwrap_or(&Value::Null);
            let status = pod.get("status").unwrap_or(&Value::Null);
            let containers: Vec<Value> = spec.get("containers")
                .and_then(|c| c.as_array())
                .map(|arr| arr.iter().map(|c| {
                    let sc = c.get("securityContext").unwrap_or(&Value::Null);
                    json!({
                        "name": c.get("name"),
                        "image": c.get("image"),
                        "resources": c.get("resources"),
                        "ports": c.get("ports"),
                        "securityContext": sc,
                        "privileged": sc.get("privileged").and_then(|v| v.as_bool()).unwrap_or(false),
                        "runAsNonRoot": sc.get("runAsNonRoot"),
                        "runAsUser": sc.get("runAsUser"),
                        "readOnlyRootFilesystem": sc.get("readOnlyRootFilesystem").and_then(|v| v.as_bool()).unwrap_or(false),
                        "allowPrivilegeEscalation": sc.get("allowPrivilegeEscalation").and_then(|v| v.as_bool()).unwrap_or(true),
                        "capabilities": sc.get("capabilities"),
                        "livenessProbe": c.get("livenessProbe").is_some(),
                        "readinessProbe": c.get("readinessProbe").is_some(),
                    })
                }).collect())
                .unwrap_or_default();

            let init_containers: Vec<Value> = spec.get("initContainers")
                .and_then(|c| c.as_array())
                .map(|arr| arr.iter().map(|c| {
                    let sc = c.get("securityContext").unwrap_or(&Value::Null);
                    json!({
                        "name": c.get("name"),
                        "image": c.get("image"),
                        "privileged": sc.get("privileged").and_then(|v| v.as_bool()).unwrap_or(false),
                    })
                }).collect())
                .unwrap_or_default();

            let pod_sc = spec.get("securityContext").unwrap_or(&Value::Null);

            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "labels": metadata.get("labels"),
                "phase": status.get("phase"),
                "node": spec.get("nodeName"),
                "serviceAccountName": spec.get("serviceAccountName"),
                "automountServiceAccountToken": spec.get("automountServiceAccountToken"),
                "hostNetwork": spec.get("hostNetwork").and_then(|v| v.as_bool()).unwrap_or(false),
                "hostPID": spec.get("hostPID").and_then(|v| v.as_bool()).unwrap_or(false),
                "hostIPC": spec.get("hostIPC").and_then(|v| v.as_bool()).unwrap_or(false),
                "securityContext": pod_sc,
                "runAsNonRoot": pod_sc.get("runAsNonRoot"),
                "runAsUser": pod_sc.get("runAsUser"),
                "fsGroup": pod_sc.get("fsGroup"),
                "volumes": spec.get("volumes"),
                "restart_count": status.get("containerStatuses")
                    .and_then(|cs| cs.as_array())
                    .map(|arr| arr.iter().map(|c| c.get("restartCount").and_then(|v| v.as_i64()).unwrap_or(0)).sum::<i64>()),
                "containers": containers,
                "initContainers": init_containers,
                "start_time": status.get("startTime"),
                "conditions": status.get("conditions"),
            })
        }).collect())
    }

    async fn gather_deployments(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/deployments", self.ns_apps_prefix())).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|dep| {
            let metadata = dep.get("metadata").unwrap_or(&Value::Null);
            let spec = dep.get("spec").unwrap_or(&Value::Null);
            let status = dep.get("status").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "replicas": spec.get("replicas"),
                "ready_replicas": status.get("readyReplicas"),
                "available_replicas": status.get("availableReplicas"),
                "unavailable_replicas": status.get("unavailableReplicas"),
                "strategy": spec.get("strategy").and_then(|s| s.get("type")),
                "conditions": status.get("conditions"),
            })
        }).collect())
    }

    async fn gather_services(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/services", self.ns_prefix())).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|svc| {
            let metadata = svc.get("metadata").unwrap_or(&Value::Null);
            let spec = svc.get("spec").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "type": spec.get("type"),
                "cluster_ip": spec.get("clusterIP"),
                "external_ip": spec.get("externalIPs"),
                "ports": spec.get("ports"),
                "selector": spec.get("selector"),
            })
        }).collect())
    }

    async fn gather_nodes(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get("/api/v1/nodes").await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|node| {
            let metadata = node.get("metadata").unwrap_or(&Value::Null);
            let status = node.get("status").unwrap_or(&Value::Null);
            let allocatable = status.get("allocatable").unwrap_or(&Value::Null);
            let capacity = status.get("capacity").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "labels": metadata.get("labels"),
                "conditions": status.get("conditions"),
                "allocatable_cpu": allocatable.get("cpu"),
                "allocatable_memory": allocatable.get("memory"),
                "capacity_cpu": capacity.get("cpu"),
                "capacity_memory": capacity.get("memory"),
                "os_image": status.get("nodeInfo").and_then(|n| n.get("osImage")),
                "kubelet_version": status.get("nodeInfo").and_then(|n| n.get("kubeletVersion")),
                "container_runtime": status.get("nodeInfo").and_then(|n| n.get("containerRuntimeVersion")),
            })
        }).collect())
    }

    async fn gather_namespaces(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get("/api/v1/namespaces").await?;
        Ok(self.extract_items(&resp))
    }

    async fn gather_ingresses(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/ingresses", self.ns_networking_prefix())).await?;
        Ok(self.extract_items(&resp))
    }

    async fn gather_configmaps(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/configmaps", self.ns_prefix())).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|cm| {
            let metadata = cm.get("metadata").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "labels": metadata.get("labels"),
                "data_keys": cm.get("data").and_then(|d| d.as_object()).map(|o| o.keys().cloned().collect::<Vec<_>>()),
            })
        }).collect())
    }

    async fn gather_secrets_metadata(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/secrets", self.ns_prefix())).await?;
        let items = self.extract_items(&resp);
        // Only metadata — never expose secret data
        Ok(items.iter().map(|sec| {
            let metadata = sec.get("metadata").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "type": sec.get("type"),
                "labels": metadata.get("labels"),
                "data_keys": sec.get("data").and_then(|d| d.as_object()).map(|o| o.keys().cloned().collect::<Vec<_>>()),
            })
        }).collect())
    }

    /// Lists `kubernetes.io/tls` Secrets and parses each certificate to expose
    /// expiry metadata. We never return the cert PEM itself — only fields useful
    /// for monitoring (CN, issuer, validity window, expires_in_days, expired).
    async fn gather_tls_certs(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/secrets", self.ns_prefix())).await?;
        let items = self.extract_items(&resp);
        let now = chrono::Utc::now().timestamp();
        let b64 = base64::engine::general_purpose::STANDARD;

        let mut out = Vec::new();
        for sec in items.iter() {
            if sec.get("type").and_then(|v| v.as_str()) != Some("kubernetes.io/tls") {
                continue;
            }
            let metadata = sec.get("metadata").unwrap_or(&Value::Null);
            let name = metadata.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let namespace = metadata.get("namespace").and_then(|v| v.as_str()).unwrap_or("");

            let crt_b64 = sec
                .get("data")
                .and_then(|d| d.get("tls.crt"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if crt_b64.is_empty() {
                continue;
            }
            let pem_bytes = match b64.decode(crt_b64) {
                Ok(b) => b,
                Err(_) => continue,
            };
            // tls.crt may bundle multiple certs (leaf + intermediates); the leaf
            // is the first PEM block.
            let (_, pem) = match parse_x509_pem(&pem_bytes) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let (_, cert) = match parse_x509_certificate(&pem.contents) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let not_before = cert.tbs_certificate.validity.not_before.timestamp();
            let not_after = cert.tbs_certificate.validity.not_after.timestamp();
            let expires_in_days = (not_after - now) as f64 / 86400.0;
            let common_name = cert
                .tbs_certificate
                .subject
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .unwrap_or("");
            let issuer = cert
                .tbs_certificate
                .issuer
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .unwrap_or("");

            out.push(json!({
                "name": name,
                "namespace": namespace,
                "common_name": common_name,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "expires_in_days": expires_in_days,
                "expired": expires_in_days <= 0.0,
            }));
        }
        Ok(out)
    }

    async fn gather_events(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/events?limit=200", self.ns_prefix())).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().filter_map(|evt| {
            let event_type = evt.get("type").and_then(|v| v.as_str()).unwrap_or("Normal");
            // Only Warning/Error events
            if event_type == "Normal" { return None; }
            Some(json!({
                "type": event_type,
                "reason": evt.get("reason"),
                "message": evt.get("message"),
                "count": evt.get("count"),
                "first_timestamp": evt.get("firstTimestamp"),
                "last_timestamp": evt.get("lastTimestamp"),
                "involved_object": evt.get("involvedObject"),
            }))
        }).collect())
    }

    async fn gather_rbac_cluster_roles(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get("/apis/rbac.authorization.k8s.io/v1/clusterroles").await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|cr| {
            let metadata = cr.get("metadata").unwrap_or(&Value::Null);
            let rules = cr.get("rules").and_then(|r| r.as_array()).cloned().unwrap_or_default();
            let has_wildcard = rules.iter().any(|r| {
                r.get("resources").and_then(|v| v.as_array())
                    .map(|arr| arr.iter().any(|v| v.as_str() == Some("*")))
                    .unwrap_or(false)
                    && r.get("verbs").and_then(|v| v.as_array())
                    .map(|arr| arr.iter().any(|v| v.as_str() == Some("*")))
                    .unwrap_or(false)
            });
            json!({
                "name": metadata.get("name"),
                "labels": metadata.get("labels"),
                "rules_count": rules.len(),
                "has_wildcard_access": has_wildcard,
                "rules": rules,
            })
        }).collect())
    }

    async fn gather_rbac_cluster_role_bindings(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings").await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|crb| {
            let metadata = crb.get("metadata").unwrap_or(&Value::Null);
            let subjects = crb.get("subjects").and_then(|s| s.as_array()).cloned().unwrap_or_default();
            let role_ref = crb.get("roleRef").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "role_ref_name": role_ref.get("name"),
                "role_ref_kind": role_ref.get("kind"),
                "subjects": subjects.iter().map(|s| json!({
                    "kind": s.get("kind"),
                    "name": s.get("name"),
                    "namespace": s.get("namespace"),
                })).collect::<Vec<_>>(),
                "subjects_count": subjects.len(),
            })
        }).collect())
    }

    async fn gather_network_policies(&self) -> Result<Vec<Value>, ProviderError> {
        let prefix = match &self.namespace {
            Some(ns) => format!("/apis/networking.k8s.io/v1/namespaces/{}/networkpolicies", ns),
            None => "/apis/networking.k8s.io/v1/networkpolicies".to_string(),
        };
        let resp = self.api_get(&prefix).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|np| {
            let metadata = np.get("metadata").unwrap_or(&Value::Null);
            let spec = np.get("spec").unwrap_or(&Value::Null);
            let policy_types = spec.get("policyTypes")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
                .unwrap_or_default();
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "pod_selector": spec.get("podSelector"),
                "policy_types": policy_types,
                "ingress_rules_count": spec.get("ingress").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
                "egress_rules_count": spec.get("egress").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
            })
        }).collect())
    }

    async fn gather_persistent_volumes(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get("/api/v1/persistentvolumes").await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|pv| {
            let metadata = pv.get("metadata").unwrap_or(&Value::Null);
            let spec = pv.get("spec").unwrap_or(&Value::Null);
            let status = pv.get("status").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "capacity": spec.get("capacity").and_then(|c| c.get("storage")),
                "access_modes": spec.get("accessModes"),
                "reclaim_policy": spec.get("persistentVolumeReclaimPolicy"),
                "storage_class": spec.get("storageClassName"),
                "phase": status.get("phase"),
                "claim_ref": spec.get("claimRef").map(|cr| json!({
                    "name": cr.get("name"),
                    "namespace": cr.get("namespace"),
                })),
            })
        }).collect())
    }

    async fn gather_persistent_volume_claims(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/persistentvolumeclaims", self.ns_prefix())).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|pvc| {
            let metadata = pvc.get("metadata").unwrap_or(&Value::Null);
            let spec = pvc.get("spec").unwrap_or(&Value::Null);
            let status = pvc.get("status").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "storage_class": spec.get("storageClassName"),
                "access_modes": spec.get("accessModes"),
                "requested_storage": spec.get("resources").and_then(|r| r.get("requests")).and_then(|r| r.get("storage")),
                "phase": status.get("phase"),
                "volume_name": spec.get("volumeName"),
            })
        }).collect())
    }

    async fn gather_daemonsets(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/daemonsets", self.ns_apps_prefix())).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|ds| {
            let metadata = ds.get("metadata").unwrap_or(&Value::Null);
            let status = ds.get("status").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "desired": status.get("desiredNumberScheduled"),
                "current": status.get("currentNumberScheduled"),
                "ready": status.get("numberReady"),
                "available": status.get("numberAvailable"),
                "misscheduled": status.get("numberMisscheduled"),
            })
        }).collect())
    }

    async fn gather_statefulsets(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/statefulsets", self.ns_apps_prefix())).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|ss| {
            let metadata = ss.get("metadata").unwrap_or(&Value::Null);
            let spec = ss.get("spec").unwrap_or(&Value::Null);
            let status = ss.get("status").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "replicas": spec.get("replicas"),
                "ready_replicas": status.get("readyReplicas"),
                "current_replicas": status.get("currentReplicas"),
                "service_name": spec.get("serviceName"),
            })
        }).collect())
    }

    async fn gather_cronjobs(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("/apis/batch/v1{}/cronjobs",
            self.namespace.as_ref().map(|ns| format!("/namespaces/{}", ns)).unwrap_or_default()
        )).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|cj| {
            let metadata = cj.get("metadata").unwrap_or(&Value::Null);
            let spec = cj.get("spec").unwrap_or(&Value::Null);
            let status = cj.get("status").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "schedule": spec.get("schedule"),
                "suspend": spec.get("suspend"),
                "concurrency_policy": spec.get("concurrencyPolicy"),
                "last_schedule_time": status.get("lastScheduleTime"),
                "active_jobs": status.get("active").and_then(|a| a.as_array()).map(|a| a.len()).unwrap_or(0),
            })
        }).collect())
    }

    async fn gather_service_accounts(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/serviceaccounts", self.ns_prefix())).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|sa| {
            let metadata = sa.get("metadata").unwrap_or(&Value::Null);
            let secrets = sa.get("secrets").and_then(|s| s.as_array()).map(|a| a.len()).unwrap_or(0);
            let automount = sa.get("automountServiceAccountToken").and_then(|v| v.as_bool());
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "secrets_count": secrets,
                "automount_token": automount,
            })
        }).collect())
    }

    async fn gather_jobs(&self) -> Result<Vec<Value>, ProviderError> {
        let prefix = match &self.namespace {
            Some(ns) => format!("/apis/batch/v1/namespaces/{}/jobs", ns),
            None => "/apis/batch/v1/jobs".to_string(),
        };
        let resp = self.api_get(&prefix).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|job| {
            let metadata = job.get("metadata").unwrap_or(&Value::Null);
            let spec = job.get("spec").unwrap_or(&Value::Null);
            let status = job.get("status").unwrap_or(&Value::Null);
            let conditions = status.get("conditions").and_then(|c| c.as_array()).cloned().unwrap_or_default();
            let failed_cond = conditions.iter().any(|c| {
                c.get("type").and_then(|v| v.as_str()) == Some("Failed")
                    && c.get("status").and_then(|v| v.as_str()) == Some("True")
            });
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "completions": spec.get("completions"),
                "parallelism": spec.get("parallelism"),
                "backoff_limit": spec.get("backoffLimit"),
                "active": status.get("active"),
                "succeeded": status.get("succeeded"),
                "failed": status.get("failed"),
                "is_failed": failed_cond,
                "start_time": status.get("startTime"),
                "completion_time": status.get("completionTime"),
            })
        }).collect())
    }

    async fn gather_hpa(&self) -> Result<Vec<Value>, ProviderError> {
        let prefix = match &self.namespace {
            Some(ns) => format!("/apis/autoscaling/v2/namespaces/{}/horizontalpodautoscalers", ns),
            None => "/apis/autoscaling/v2/horizontalpodautoscalers".to_string(),
        };
        let resp = self.api_get(&prefix).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|hpa| {
            let metadata = hpa.get("metadata").unwrap_or(&Value::Null);
            let spec = hpa.get("spec").unwrap_or(&Value::Null);
            let status = hpa.get("status").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "min_replicas": spec.get("minReplicas"),
                "max_replicas": spec.get("maxReplicas"),
                "current_replicas": status.get("currentReplicas"),
                "desired_replicas": status.get("desiredReplicas"),
                "target_ref": spec.get("scaleTargetRef"),
                "metrics": spec.get("metrics"),
                "current_metrics": status.get("currentMetrics"),
                "conditions": status.get("conditions"),
            })
        }).collect())
    }

    async fn gather_resource_quotas(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/resourcequotas", self.ns_prefix())).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|rq| {
            let metadata = rq.get("metadata").unwrap_or(&Value::Null);
            let status = rq.get("status").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "hard": status.get("hard"),
                "used": status.get("used"),
            })
        }).collect())
    }

    async fn gather_limit_ranges(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get(&format!("{}/limitranges", self.ns_prefix())).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|lr| {
            let metadata = lr.get("metadata").unwrap_or(&Value::Null);
            let spec = lr.get("spec").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "limits": spec.get("limits"),
            })
        }).collect())
    }

    async fn gather_node_metrics(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get("/apis/metrics.k8s.io/v1beta1/nodes").await
            .map_err(|_| ProviderError::Query("metrics-server not available (install metrics-server for node_metrics)".into()))?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|nm| {
            let metadata = nm.get("metadata").unwrap_or(&Value::Null);
            let usage = nm.get("usage").unwrap_or(&Value::Null);
            let cpu_raw = usage.get("cpu").and_then(|v| v.as_str()).unwrap_or("0");
            let mem_raw = usage.get("memory").and_then(|v| v.as_str()).unwrap_or("0");
            json!({
                "name": metadata.get("name"),
                "cpu": cpu_raw,
                "memory": mem_raw,
                "cpu_millicores": parse_cpu_to_millicores(cpu_raw),
                "memory_mib": parse_memory_to_mib(mem_raw),
                "timestamp": nm.get("timestamp"),
            })
        }).collect())
    }

    async fn gather_pod_metrics(&self) -> Result<Vec<Value>, ProviderError> {
        let prefix = match &self.namespace {
            Some(ns) => format!("/apis/metrics.k8s.io/v1beta1/namespaces/{}/pods", ns),
            None => "/apis/metrics.k8s.io/v1beta1/pods".to_string(),
        };
        let resp = self.api_get(&prefix).await
            .map_err(|_| ProviderError::Query("metrics-server not available (install metrics-server for pod_metrics)".into()))?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|pm| {
            let metadata = pm.get("metadata").unwrap_or(&Value::Null);
            let containers: Vec<Value> = pm.get("containers")
                .and_then(|c| c.as_array())
                .map(|arr| arr.iter().map(|c| {
                    let cpu_raw = c.get("usage").and_then(|u| u.get("cpu")).and_then(|v| v.as_str()).unwrap_or("0");
                    let mem_raw = c.get("usage").and_then(|u| u.get("memory")).and_then(|v| v.as_str()).unwrap_or("0");
                    json!({
                        "name": c.get("name"),
                        "cpu": cpu_raw,
                        "memory": mem_raw,
                        "cpu_millicores": parse_cpu_to_millicores(cpu_raw),
                        "memory_mib": parse_memory_to_mib(mem_raw),
                    })
                }).collect())
                .unwrap_or_default();
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "containers": containers,
                "timestamp": pm.get("timestamp"),
            })
        }).collect())
    }

    /// Flat per-container view of metrics-server data, one JSON row per
    /// (namespace, pod, container) — easier to query in dashboards than the
    /// nested `pod_metrics` shape, which keeps containers as a JSON array.
    async fn gather_pod_resource(&self) -> Result<Vec<Value>, ProviderError> {
        let prefix = match &self.namespace {
            Some(ns) => format!("/apis/metrics.k8s.io/v1beta1/namespaces/{}/pods", ns),
            None => "/apis/metrics.k8s.io/v1beta1/pods".to_string(),
        };
        let resp = self.api_get(&prefix).await
            .map_err(|_| ProviderError::Query("metrics-server not available (install metrics-server for pod_resource)".into()))?;
        let items = self.extract_items(&resp);

        let mut out = Vec::new();
        for pm in items.iter() {
            let metadata = pm.get("metadata").unwrap_or(&Value::Null);
            let namespace = metadata.get("namespace").and_then(|v| v.as_str()).unwrap_or("");
            let pod = metadata.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let timestamp = pm.get("timestamp").cloned().unwrap_or(Value::Null);
            let containers = pm.get("containers").and_then(|c| c.as_array());
            let containers = match containers {
                Some(c) => c,
                None => continue,
            };
            for c in containers.iter() {
                let cname = c.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let cpu_raw = c.get("usage").and_then(|u| u.get("cpu")).and_then(|v| v.as_str()).unwrap_or("0");
                let mem_raw = c.get("usage").and_then(|u| u.get("memory")).and_then(|v| v.as_str()).unwrap_or("0");
                out.push(json!({
                    "namespace": namespace,
                    "pod": pod,
                    "container": cname,
                    "cpu_millicores": parse_cpu_to_millicores(cpu_raw),
                    "memory_mib": parse_memory_to_mib(mem_raw),
                    "timestamp": timestamp,
                }));
            }
        }
        Ok(out)
    }

    async fn gather_pod_logs(&self) -> Result<Vec<Value>, ProviderError> {
        // Get recent error/warning logs from pods (last 100 lines per pod, limited to 50 pods)
        let resp = self.api_get(&format!("{}/pods", self.ns_prefix())).await?;
        let pods = self.extract_items(&resp);

        let mut logs = Vec::new();
        for pod in pods.iter().take(50) {
            let name = pod.pointer("/metadata/name").and_then(|v| v.as_str()).unwrap_or("");
            let namespace = pod.pointer("/metadata/namespace").and_then(|v| v.as_str()).unwrap_or("default");
            let phase = pod.pointer("/status/phase").and_then(|v| v.as_str()).unwrap_or("");

            // Only get logs from running/failed pods
            if phase != "Running" && phase != "Failed" {
                continue;
            }

            let log_url = format!("/api/v1/namespaces/{}/pods/{}/log?tailLines=100&timestamps=true", namespace, name);
            if let Ok(text) = self.api_get_text(&log_url).await {
                let error_lines: Vec<&str> = text.lines()
                    .filter(|l| {
                        let lower = l.to_lowercase();
                        lower.contains("error") || lower.contains("warn") || lower.contains("fatal")
                            || lower.contains("panic") || lower.contains("exception")
                    })
                    .collect();

                if !error_lines.is_empty() {
                    logs.push(json!({
                        "pod": name,
                        "namespace": namespace,
                        "phase": phase,
                        "error_lines": error_lines.len(),
                        "logs": error_lines.iter().take(20).collect::<Vec<_>>(),
                    }));
                }
            }
        }
        Ok(logs)
    }

    async fn gather_cluster_stats(&self) -> Result<Vec<Value>, ProviderError> {
        let mut stats = serde_json::Map::new();

        // Count pods by phase
        let pods_resp = self.api_get(&format!("{}/pods", self.ns_prefix())).await?;
        let pods = self.extract_items(&pods_resp);
        let total_pods = pods.len();
        let running = pods.iter().filter(|p| p.pointer("/status/phase") == Some(&json!("Running"))).count();
        let pending = pods.iter().filter(|p| p.pointer("/status/phase") == Some(&json!("Pending"))).count();
        let failed = pods.iter().filter(|p| p.pointer("/status/phase") == Some(&json!("Failed"))).count();

        stats.insert("pods_total".into(), json!(total_pods));
        stats.insert("pods_running".into(), json!(running));
        stats.insert("pods_pending".into(), json!(pending));
        stats.insert("pods_failed".into(), json!(failed));

        // Total restarts
        let total_restarts: i64 = pods.iter().map(|p| {
            p.pointer("/status/containerStatuses")
                .and_then(|cs| cs.as_array())
                .map(|arr| arr.iter().map(|c| c.get("restartCount").and_then(|v| v.as_i64()).unwrap_or(0)).sum::<i64>())
                .unwrap_or(0)
        }).sum();
        stats.insert("total_restarts".into(), json!(total_restarts));

        // Count deployments
        let deps_resp = self.api_get(&format!("{}/deployments", self.ns_apps_prefix())).await.ok();
        if let Some(resp) = deps_resp {
            let deps = self.extract_items(&resp);
            let total_deps = deps.len();
            let unavailable = deps.iter().filter(|d| {
                d.pointer("/status/unavailableReplicas").and_then(|v| v.as_i64()).unwrap_or(0) > 0
            }).count();
            stats.insert("deployments_total".into(), json!(total_deps));
            stats.insert("deployments_unavailable".into(), json!(unavailable));
        }

        // Nodes
        let nodes_resp = self.api_get("/api/v1/nodes").await.ok();
        if let Some(resp) = nodes_resp {
            let nodes = self.extract_items(&resp);
            let total_nodes = nodes.len();
            let ready_nodes = nodes.iter().filter(|n| {
                n.pointer("/status/conditions")
                    .and_then(|c| c.as_array())
                    .map(|arr| arr.iter().any(|cond| {
                        cond.get("type") == Some(&json!("Ready")) && cond.get("status") == Some(&json!("True"))
                    }))
                    .unwrap_or(false)
            }).count();
            stats.insert("nodes_total".into(), json!(total_nodes));
            stats.insert("nodes_ready".into(), json!(ready_nodes));
            stats.insert("nodes_not_ready".into(), json!(total_nodes - ready_nodes));
        }

        // Warning events count
        let events_resp = self.api_get(&format!("{}/events", self.ns_prefix())).await.ok();
        if let Some(resp) = events_resp {
            let events = self.extract_items(&resp);
            let warning_events = events.iter().filter(|e| e.get("type") == Some(&json!("Warning"))).count();
            stats.insert("warning_events".into(), json!(warning_events));
        }

        Ok(vec![Value::Object(stats)])
    }

    /// Namespaced Roles (rbac.authorization.k8s.io/v1).
    /// Cluster-scoped roles are reported by `gather_rbac_cluster_roles`.
    async fn gather_roles(&self) -> Result<Vec<Value>, ProviderError> {
        let path = match &self.namespace {
            Some(ns) => format!("/apis/rbac.authorization.k8s.io/v1/namespaces/{}/roles", ns),
            None => "/apis/rbac.authorization.k8s.io/v1/roles".to_string(),
        };
        let resp = self.api_get(&path).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|r| {
            let metadata = r.get("metadata").unwrap_or(&Value::Null);
            let rules = r.get("rules").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let has_wildcard = rules.iter().any(|rule| {
                rule.get("resources").and_then(|v| v.as_array())
                    .map(|arr| arr.iter().any(|v| v.as_str() == Some("*")))
                    .unwrap_or(false)
                    && rule.get("verbs").and_then(|v| v.as_array())
                    .map(|arr| arr.iter().any(|v| v.as_str() == Some("*")))
                    .unwrap_or(false)
            });
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "labels": metadata.get("labels"),
                "rules_count": rules.len(),
                "has_wildcard_access": has_wildcard,
                "rules": rules,
            })
        }).collect())
    }

    /// Namespaced RoleBindings (rbac.authorization.k8s.io/v1).
    async fn gather_role_bindings(&self) -> Result<Vec<Value>, ProviderError> {
        let path = match &self.namespace {
            Some(ns) => format!("/apis/rbac.authorization.k8s.io/v1/namespaces/{}/rolebindings", ns),
            None => "/apis/rbac.authorization.k8s.io/v1/rolebindings".to_string(),
        };
        let resp = self.api_get(&path).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|rb| {
            let metadata = rb.get("metadata").unwrap_or(&Value::Null);
            let subjects = rb.get("subjects").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let role_ref = rb.get("roleRef").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "role_ref_name": role_ref.get("name"),
                "role_ref_kind": role_ref.get("kind"),
                "role_ref_api_group": role_ref.get("apiGroup"),
                "subjects": subjects.iter().map(|s| json!({
                    "kind": s.get("kind"),
                    "name": s.get("name"),
                    "namespace": s.get("namespace"),
                })).collect::<Vec<_>>(),
                "subjects_count": subjects.len(),
            })
        }).collect())
    }

    /// ValidatingWebhookConfigurations — cluster-scoped admission policies
    /// that can reject requests. Knowing what's installed is essential for
    /// security audit and debugging admission failures.
    async fn gather_validating_webhook_configurations(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self
            .api_get("/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations")
            .await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|w| Self::map_webhook_configuration(w, false)).collect())
    }

    /// MutatingWebhookConfigurations — cluster-scoped admission policies
    /// that can rewrite incoming objects (e.g. Istio injection, OPA mutating).
    async fn gather_mutating_webhook_configurations(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self
            .api_get("/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations")
            .await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|w| Self::map_webhook_configuration(w, true)).collect())
    }

    fn map_webhook_configuration(w: &Value, mutating: bool) -> Value {
        let metadata = w.get("metadata").unwrap_or(&Value::Null);
        let webhooks = w.get("webhooks").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        json!({
            "name": metadata.get("name"),
            "kind": if mutating { "MutatingWebhookConfiguration" } else { "ValidatingWebhookConfiguration" },
            "labels": metadata.get("labels"),
            "webhooks_count": webhooks.len(),
            "webhooks": webhooks.iter().map(|h| json!({
                "name": h.get("name"),
                "failure_policy": h.get("failurePolicy"),
                "side_effects": h.get("sideEffects"),
                "timeout_seconds": h.get("timeoutSeconds"),
                "admission_review_versions": h.get("admissionReviewVersions"),
                "namespace_selector": h.get("namespaceSelector"),
                "object_selector": h.get("objectSelector"),
                "client_config": h.get("clientConfig").map(|cc| json!({
                    "url": cc.get("url"),
                    "service": cc.get("service"),
                    "ca_bundle_present": cc.get("caBundle").is_some(),
                })),
                "rules": h.get("rules"),
            })).collect::<Vec<_>>(),
        })
    }

    /// CustomResourceDefinitions — inventory of operators / CRDs installed
    /// on the cluster. Surface counter signals when an operator is removed
    /// without cleanup or when an unexpected CRD appears.
    async fn gather_custom_resource_definitions(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self
            .api_get("/apis/apiextensions.k8s.io/v1/customresourcedefinitions")
            .await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|crd| {
            let metadata = crd.get("metadata").unwrap_or(&Value::Null);
            let spec = crd.get("spec").unwrap_or(&Value::Null);
            let names = spec.get("names").unwrap_or(&Value::Null);
            let versions = spec.get("versions").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let served_versions: Vec<String> = versions.iter()
                .filter(|v| v.get("served").and_then(|s| s.as_bool()).unwrap_or(false))
                .filter_map(|v| v.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect();
            json!({
                "name": metadata.get("name"),
                "labels": metadata.get("labels"),
                "group": spec.get("group"),
                "scope": spec.get("scope"),
                "kind": names.get("kind"),
                "plural": names.get("plural"),
                "singular": names.get("singular"),
                "categories": names.get("categories"),
                "versions": versions.iter().map(|v| v.get("name")).collect::<Vec<_>>(),
                "served_versions": served_versions,
                "creation_timestamp": metadata.get("creationTimestamp"),
            })
        }).collect())
    }

    /// StorageClasses — disk provisioners + default flag + encryption hints.
    async fn gather_storage_classes(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get("/apis/storage.k8s.io/v1/storageclasses").await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|sc| {
            let metadata = sc.get("metadata").unwrap_or(&Value::Null);
            let annotations = metadata.get("annotations").unwrap_or(&Value::Null);
            let is_default = annotations
                .get("storageclass.kubernetes.io/is-default-class")
                .and_then(|v| v.as_str())
                .map(|s| s == "true")
                .unwrap_or(false);
            json!({
                "name": metadata.get("name"),
                "labels": metadata.get("labels"),
                "is_default": is_default,
                "provisioner": sc.get("provisioner"),
                "parameters": sc.get("parameters"),
                "reclaim_policy": sc.get("reclaimPolicy"),
                "volume_binding_mode": sc.get("volumeBindingMode"),
                "allow_volume_expansion": sc.get("allowVolumeExpansion"),
                "mount_options": sc.get("mountOptions"),
            })
        }).collect())
    }

    /// PodDisruptionBudgets — voluntary disruption guarantees per workload.
    async fn gather_pod_disruption_budgets(&self) -> Result<Vec<Value>, ProviderError> {
        let path = match &self.namespace {
            Some(ns) => format!("/apis/policy/v1/namespaces/{}/poddisruptionbudgets", ns),
            None => "/apis/policy/v1/poddisruptionbudgets".to_string(),
        };
        let resp = self.api_get(&path).await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|pdb| {
            let metadata = pdb.get("metadata").unwrap_or(&Value::Null);
            let spec = pdb.get("spec").unwrap_or(&Value::Null);
            let status = pdb.get("status").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "namespace": metadata.get("namespace"),
                "min_available": spec.get("minAvailable"),
                "max_unavailable": spec.get("maxUnavailable"),
                "selector": spec.get("selector"),
                "current_healthy": status.get("currentHealthy"),
                "desired_healthy": status.get("desiredHealthy"),
                "expected_pods": status.get("expectedPods"),
                "disruptions_allowed": status.get("disruptionsAllowed"),
            })
        }).collect())
    }

    /// PriorityClasses — preemption order. Workloads at high priority can
    /// evict lower ones; misconfigured priority is a frequent disruption cause.
    async fn gather_priority_classes(&self) -> Result<Vec<Value>, ProviderError> {
        let resp = self.api_get("/apis/scheduling.k8s.io/v1/priorityclasses").await?;
        let items = self.extract_items(&resp);
        Ok(items.iter().map(|pc| {
            let metadata = pc.get("metadata").unwrap_or(&Value::Null);
            json!({
                "name": metadata.get("name"),
                "labels": metadata.get("labels"),
                "value": pc.get("value"),
                "global_default": pc.get("globalDefault"),
                "preemption_policy": pc.get("preemptionPolicy"),
                "description": pc.get("description"),
            })
        }).collect())
    }
}

/// Parse Kubernetes CPU quantity string to millicores (f64).
/// Handles: "1840m" → 1840.0, "181461688n" → 181.46, "2" → 2000.0
fn parse_cpu_to_millicores(s: &str) -> f64 {
    if let Some(val) = s.strip_suffix('m') {
        val.parse::<f64>().unwrap_or(0.0)
    } else if let Some(val) = s.strip_suffix('n') {
        val.parse::<f64>().unwrap_or(0.0) / 1_000_000.0
    } else if let Some(val) = s.strip_suffix('u') {
        val.parse::<f64>().unwrap_or(0.0) / 1_000.0
    } else {
        s.parse::<f64>().unwrap_or(0.0) * 1000.0
    }
}

/// Parse Kubernetes memory quantity string to mebibytes (f64).
/// Handles: "3148864Ki" → 3075.0, "512Mi" → 512.0, "1Gi" → 1024.0, "536870912" → 512.0
fn parse_memory_to_mib(s: &str) -> f64 {
    if let Some(val) = s.strip_suffix("Ki") {
        val.parse::<f64>().unwrap_or(0.0) / 1024.0
    } else if let Some(val) = s.strip_suffix("Mi") {
        val.parse::<f64>().unwrap_or(0.0)
    } else if let Some(val) = s.strip_suffix("Gi") {
        val.parse::<f64>().unwrap_or(0.0) * 1024.0
    } else if let Some(val) = s.strip_suffix("Ti") {
        val.parse::<f64>().unwrap_or(0.0) * 1024.0 * 1024.0
    } else if let Some(val) = s.strip_suffix('K') {
        val.parse::<f64>().unwrap_or(0.0) / 1000.0 / 1.048576
    } else if let Some(val) = s.strip_suffix('M') {
        val.parse::<f64>().unwrap_or(0.0) / 1.048576
    } else if let Some(val) = s.strip_suffix('G') {
        val.parse::<f64>().unwrap_or(0.0) * 1000.0 / 1.048576
    } else {
        s.parse::<f64>().unwrap_or(0.0) / 1024.0 / 1024.0
    }
}

#[async_trait::async_trait]
impl Provider for KubernetesProvider {
    fn name(&self) -> &str {
        "kubernetes"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        match resource_type {
            "pods" => self.gather_pods().await,
            "deployments" => self.gather_deployments().await,
            "services" => self.gather_services().await,
            "nodes" => self.gather_nodes().await,
            "namespaces" => self.gather_namespaces().await,
            "ingresses" => self.gather_ingresses().await,
            "configmaps" => self.gather_configmaps().await,
            "secrets_metadata" => self.gather_secrets_metadata().await,
            "events" => self.gather_events().await,
            "cluster_stats" => self.gather_cluster_stats().await,
            "rbac_cluster_roles" => self.gather_rbac_cluster_roles().await,
            "rbac_cluster_role_bindings" => self.gather_rbac_cluster_role_bindings().await,
            "network_policies" => self.gather_network_policies().await,
            "persistent_volumes" => self.gather_persistent_volumes().await,
            "persistent_volume_claims" => self.gather_persistent_volume_claims().await,
            "daemonsets" => self.gather_daemonsets().await,
            "statefulsets" => self.gather_statefulsets().await,
            "cronjobs" => self.gather_cronjobs().await,
            "service_accounts" => self.gather_service_accounts().await,
            "jobs" => self.gather_jobs().await,
            "hpa" => self.gather_hpa().await,
            "resource_quotas" => self.gather_resource_quotas().await,
            "limit_ranges" => self.gather_limit_ranges().await,
            "node_metrics" => self.gather_node_metrics().await,
            "pod_metrics" => self.gather_pod_metrics().await,
            "pod_logs" => self.gather_pod_logs().await,
            "roles" => self.gather_roles().await,
            "role_bindings" => self.gather_role_bindings().await,
            "validating_webhook_configurations" => {
                self.gather_validating_webhook_configurations().await
            }
            "mutating_webhook_configurations" => {
                self.gather_mutating_webhook_configurations().await
            }
            "custom_resource_definitions" => self.gather_custom_resource_definitions().await,
            "storage_classes" => self.gather_storage_classes().await,
            "pod_disruption_budgets" => self.gather_pod_disruption_budgets().await,
            "priority_classes" => self.gather_priority_classes().await,
            "tls_certs" => self.gather_tls_certs().await,
            "pod_resource" => self.gather_pod_resource().await,
            _ => Err(ProviderError::UnsupportedResourceType(resource_type.to_string())),
        }
    }
}
