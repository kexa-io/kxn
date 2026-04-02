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

    /// Execute SQL on the target (supported by postgresql, mysql).
    /// Default: not supported.
    async fn execute_sql(&self, _sql: &str) -> Result<String, ProviderError> {
        Err(ProviderError::InvalidConfig(
            "execute_sql not supported by this provider".to_string(),
        ))
    }

    /// Execute a shell command on the target (supported by ssh).
    /// Default: not supported.
    async fn execute_shell(&self, _command: &str) -> Result<String, ProviderError> {
        Err(ProviderError::InvalidConfig(
            "execute_shell not supported by this provider".to_string(),
        ))
    }

    /// Gather all resource types. Sequential by default — providers that
    /// support parallel gathering (separate connections) should override.
    async fn gather_all(&self) -> Result<std::collections::HashMap<String, Vec<Value>>, ProviderError> {
        let types = self.resource_types().await?;
        let mut result = std::collections::HashMap::new();
        for rt in types {
            match self.gather(&rt).await {
                Ok(items) => { result.insert(rt, items); }
                Err(e) => {
                    tracing::warn!(resource_type = %rt, error = %e, "Gather failed for resource type");
                    result.insert(rt, vec![serde_json::json!({"error": e.to_string()})]);
                }
            }
        }
        Ok(result)
    }
}
