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
}
