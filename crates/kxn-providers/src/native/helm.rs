//! Helm provider — releases read from the cluster, not from the `helm` binary.
//!
//! Helm 3 keeps its state in Kubernetes itself (one Secret per release
//! revision), so there is nothing to shell out to and no extra credential: this
//! is the Kubernetes provider restricted to what Helm stores. Scanning a
//! cluster with `kubernetes://` collects the same objects; `helm://` exists to
//! target releases on their own.

use serde_json::Value;

use super::kubernetes::KubernetesProvider;
use crate::error::ProviderError;
use crate::traits::Provider;

pub(crate) const RESOURCE_TYPES: &[&str] = &["helm_releases"];

pub struct HelmProvider {
    inner: KubernetesProvider,
}

impl HelmProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        Ok(Self {
            inner: KubernetesProvider::new(config)?,
        })
    }
}

#[async_trait::async_trait]
impl Provider for HelmProvider {
    fn name(&self) -> &str {
        "helm"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        if !RESOURCE_TYPES.contains(&resource_type) {
            return Err(ProviderError::UnsupportedResourceType(
                resource_type.to_string(),
            ));
        }
        self.inner.gather(resource_type).await
    }
}
