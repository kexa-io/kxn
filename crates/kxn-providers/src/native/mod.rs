#[cfg(unix)]
pub mod docker;
pub mod gcp;
pub mod http;
pub mod grpc;
pub mod microsoft_graph;
pub mod mongodb;
pub mod mysql;
pub mod postgresql;
pub mod ssh;
pub mod kubernetes;
pub mod kubernetes_log_tail;
pub mod github;
pub mod cve_feeds;
pub mod local;

#[cfg(feature = "oracle")]
pub mod oracle;

use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::Value;

/// Names of all built-in native providers.
pub fn native_provider_names() -> Vec<&'static str> {
    let mut names = vec![
        "cve", "gcp", "http", "grpc", "local", "microsoft.graph", "mongodb", "mysql",
        "postgresql", "ssh", "kubernetes", "github",
    ];
    #[cfg(unix)]
    names.push("docker");
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
        "cve" => Ok(Box::new(cve_feeds::CveFeedsProvider::new(config)?)),
        #[cfg(unix)]
        "docker" => Ok(Box::new(docker::DockerProvider::new(config)?)),
        "http" => Ok(Box::new(http::HttpProvider::new(config)?)),
        "grpc" => Ok(Box::new(grpc::GrpcProvider::new(config)?)),
        "mongodb" => Ok(Box::new(mongodb::MongodbProvider::new(config)?)),
        "mysql" => Ok(Box::new(mysql::MySqlProvider::new(config)?)),
        "postgresql" => Ok(Box::new(postgresql::PostgresqlProvider::new(config)?)),
        "ssh" => Ok(Box::new(ssh::SshProvider::new(config)?)),
        "local" => Ok(Box::new(local::LocalProvider::new(config)?)),
        "kubernetes" | "k8s" => Ok(Box::new(kubernetes::KubernetesProvider::new(config)?)),
        "github" | "gh" => Ok(Box::new(github::GithubProvider::new(config)?)),
        "gcp" | "google" => Ok(Box::new(gcp::GcpProvider::new(config)?)),
        "microsoft.graph" | "msgraph" => Ok(Box::new(microsoft_graph::MicrosoftGraphProvider::new(config)?)),
        #[cfg(feature = "oracle")]
        "oracle" => Ok(Box::new(oracle::OracleProvider::new(config)?)),
        _ => Err(ProviderError::NotFound(format!(
            "Unknown native provider: {}",
            name
        ))),
    }
}
