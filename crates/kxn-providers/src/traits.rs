use crate::error::ProviderError;
use serde_json::Value;

/// Simplified provider trait for kxn: gather-only (no create/update/delete).
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    /// Get provider name
    fn name(&self) -> &str;

    /// Get available resource types
    async fn resource_types(&self) -> Result<Vec<String>, ProviderError>;

    /// Gather resources of a given type
    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError>;

    /// Gather all resource types at once (override for providers that need
    /// a single connection for all types, like Oracle OCI)
    async fn gather_all(&self) -> Result<std::collections::HashMap<String, Vec<Value>>, ProviderError> {
        let types = self.resource_types().await?;
        let mut result = std::collections::HashMap::new();
        for rt in types {
            match self.gather(&rt).await {
                Ok(items) => { result.insert(rt, items); }
                Err(e) => {
                    result.insert(rt, vec![serde_json::json!({"error": e.to_string()})]);
                }
            }
        }
        Ok(result)
    }
}
