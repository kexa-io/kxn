pub mod http;
pub mod mongodb;
pub mod mysql;
pub mod postgresql;
pub mod ssh;

#[cfg(feature = "oracle")]
pub mod oracle;

use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::Value;

/// Names of all built-in native providers.
pub fn native_provider_names() -> Vec<&'static str> {
    #[cfg(feature = "oracle")]
    {
        vec!["http", "mongodb", "mysql", "postgresql", "oracle", "ssh"]
    }
    #[cfg(not(feature = "oracle"))]
    {
        vec!["http", "mongodb", "mysql", "postgresql", "ssh"]
    }
}

/// Create a native provider by name.
pub fn create_native_provider(
    name: &str,
    config: Value,
) -> Result<Box<dyn Provider>, ProviderError> {
    match name {
        "http" => Ok(Box::new(http::HttpProvider::new(config)?)),
        "mongodb" => Ok(Box::new(mongodb::MongodbProvider::new(config)?)),
        "mysql" => Ok(Box::new(mysql::MySqlProvider::new(config)?)),
        "postgresql" => Ok(Box::new(postgresql::PostgresqlProvider::new(config)?)),
        "ssh" => Ok(Box::new(ssh::SshProvider::new(config)?)),
        #[cfg(feature = "oracle")]
        "oracle" => Ok(Box::new(oracle::OracleProvider::new(config)?)),
        _ => Err(ProviderError::NotFound(format!(
            "Unknown native provider: {}",
            name
        ))),
    }
}
