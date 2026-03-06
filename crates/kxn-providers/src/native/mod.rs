pub mod http;
pub mod mongodb;
pub mod mysql;
pub mod postgresql;
pub mod ssh;
pub mod kubernetes;
pub mod github;
pub mod cloud_run;
pub mod azure_webapp;

#[cfg(feature = "oracle")]
pub mod oracle;

use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::Value;

/// Names of all built-in native providers.
pub fn native_provider_names() -> Vec<&'static str> {
    let mut names = vec![
        "http", "mongodb", "mysql", "postgresql", "ssh",
        "kubernetes", "github", "cloud_run", "azure_webapp",
    ];
    #[cfg(feature = "oracle")]
    names.push("oracle");
    names.sort();
    names
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
        "kubernetes" | "k8s" => Ok(Box::new(kubernetes::KubernetesProvider::new(config)?)),
        "github" | "gh" => Ok(Box::new(github::GithubProvider::new(config)?)),
        "cloud_run" | "cloudrun" => Ok(Box::new(cloud_run::CloudRunProvider::new(config)?)),
        "azure_webapp" | "azurewebapp" => Ok(Box::new(azure_webapp::AzureWebAppProvider::new(config)?)),
        #[cfg(feature = "oracle")]
        "oracle" => Ok(Box::new(oracle::OracleProvider::new(config)?)),
        _ => Err(ProviderError::NotFound(format!(
            "Unknown native provider: {}",
            name
        ))),
    }
}
