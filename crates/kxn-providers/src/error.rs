use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum ProviderError {
    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("Rate limited: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("Operation timeout")]
    Timeout,

    #[error("Unsupported resource type: {0}")]
    UnsupportedResourceType(String),

    #[error("Connection failed: {0}")]
    Connection(String),

    #[error("Query failed: {0}")]
    Query(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("DNS resolution failed: {0}")]
    Dns(String),
}
