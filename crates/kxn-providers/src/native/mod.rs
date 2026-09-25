pub mod azure;
#[cfg(unix)]
pub mod docker;
pub mod gcp;
pub mod helm;
pub mod googleworkspace;
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
pub mod forgejo;
pub mod cve_feeds;
pub mod local;
pub mod prometheus;

#[cfg(feature = "oracle")]
pub mod oracle;

use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::Value;


/// Every native provider kxn can be built with, including the ones this build
/// left out (`docker` is unix-only, `oracle` is behind a feature). Used to tell
/// "this provider is not compiled in" apart from "nothing produces this object".
pub const ALL_NATIVE_PROVIDERS: &[&str] = &[
    "azure", "cve", "docker", "forgejo", "gcp", "github", "googleworkspace", "grpc", "helm", "http", "kubernetes",
    "local", "microsoft.graph", "mongodb", "mysql", "oracle", "postgresql", "prometheus", "ssh",
];

/// What each native provider can produce, without constructing it — no
/// credentials, no network, no connection. This is the catalogue a rule's
/// `object` is checked against: a rule naming something no provider produces is
/// never evaluated, and today that silence is indistinguishable from "this
/// resource is compliant".
pub fn native_catalog() -> Vec<(&'static str, &'static [&'static str])> {
    let mut catalog: Vec<(&'static str, &'static [&'static str])> = vec![
        ("azure", azure::RESOURCE_TYPES),
        ("cve", cve_feeds::RESOURCE_TYPES),
        ("forgejo", forgejo::RESOURCE_TYPES),
        ("gcp", gcp::RESOURCE_TYPES),
        ("github", github::RESOURCE_TYPES),
        ("googleworkspace", googleworkspace::RESOURCE_TYPES),
        ("grpc", grpc::RESOURCE_TYPES),
        ("helm", helm::RESOURCE_TYPES),
        ("http", http::RESOURCE_TYPES),
        ("kubernetes", kubernetes::RESOURCE_TYPES),
        ("local", local::RESOURCE_TYPES),
        ("microsoft.graph", microsoft_graph::RESOURCE_TYPES),
        ("mongodb", mongodb::RESOURCE_TYPES),
        ("mysql", mysql::RESOURCE_TYPES),
        ("postgresql", postgresql::RESOURCE_TYPES),
        ("prometheus", prometheus::RESOURCE_TYPES),
        ("ssh", ssh::RESOURCE_TYPES),
    ];
    #[cfg(unix)]
    catalog.push(("docker", docker::RESOURCE_TYPES));
    #[cfg(feature = "oracle")]
    catalog.push(("oracle", oracle::RESOURCE_TYPES));
    catalog.sort_by_key(|(name, _)| *name);
    catalog
}

/// Names of all built-in native providers.
pub fn native_provider_names() -> Vec<&'static str> {
    let mut names = vec![
        "azure", "cve", "gcp", "googleworkspace", "helm", "http", "grpc", "local", "microsoft.graph", "mongodb",
        "mysql", "postgresql", "ssh", "kubernetes", "github", "forgejo", "prometheus",
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
        "azure" | "azurerm" => Ok(Box::new(azure::AzureProvider::new(config)?)),
        "cve" => Ok(Box::new(cve_feeds::CveFeedsProvider::new(config)?)),
        #[cfg(unix)]
        "docker" => Ok(Box::new(docker::DockerProvider::new(config)?)),
        "http" => Ok(Box::new(http::HttpProvider::new(config)?)),
        "grpc" => Ok(Box::new(grpc::GrpcProvider::new(config)?)),
        "helm" => Ok(Box::new(helm::HelmProvider::new(config)?)),
        "mongodb" => Ok(Box::new(mongodb::MongodbProvider::new(config)?)),
        "mysql" => Ok(Box::new(mysql::MySqlProvider::new(config)?)),
        "postgresql" => Ok(Box::new(postgresql::PostgresqlProvider::new(config)?)),
        "ssh" => Ok(Box::new(ssh::SshProvider::new(config)?)),
        "local" => Ok(Box::new(local::LocalProvider::new(config)?)),
        "kubernetes" | "k8s" => Ok(Box::new(kubernetes::KubernetesProvider::new(config)?)),
        "github" | "gh" => Ok(Box::new(github::GithubProvider::new(config)?)),
        "forgejo" | "gitea" => Ok(Box::new(forgejo::ForgejoProvider::new(config)?)),
        "gcp" | "google" => Ok(Box::new(gcp::GcpProvider::new(config)?)),
        "googleworkspace" | "gws" => {
            Ok(Box::new(googleworkspace::GoogleWorkspaceProvider::new(config)?))
        }
        "microsoft.graph" | "msgraph" => Ok(Box::new(microsoft_graph::MicrosoftGraphProvider::new(config)?)),
        "prometheus" | "prom" => Ok(Box::new(prometheus::PrometheusProvider::new(config)?)),
        #[cfg(feature = "oracle")]
        "oracle" => Ok(Box::new(oracle::OracleProvider::new(config)?)),
        _ => Err(ProviderError::NotFound(format!(
            "Unknown native provider: {}",
            name
        ))),
    }
}
