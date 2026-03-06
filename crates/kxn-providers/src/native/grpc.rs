use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Value};
use std::time::Instant;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tracing::debug;

/// gRPC health check provider.
///
/// Uses the standard `grpc.health.v1.Health` protocol to check gRPC services.
/// Also gathers connection info, TLS status, and optionally gRPC reflection.
pub struct GrpcProvider {
    config: Value,
}

const RESOURCE_TYPES: &[&str] = &["health_check", "connection", "reflection", "service_health"];

impl GrpcProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        let has_endpoint = get_config_or_env(&config, "ENDPOINT", Some("GRPC")).is_some();
        if !has_endpoint {
            return Err(ProviderError::InvalidConfig(
                "gRPC provider requires ENDPOINT (config or env GRPC_ENDPOINT)".into(),
            ));
        }
        Ok(Self { config })
    }

    fn get_endpoints(&self) -> Vec<String> {
        if let Some(Value::Array(arr)) = self
            .config
            .get("ENDPOINT")
            .or(self.config.get("endpoint"))
        {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else if let Some(ep) = get_config_or_env(&self.config, "ENDPOINT", Some("GRPC")) {
            vec![ep]
        } else {
            vec![]
        }
    }

    fn use_tls(&self) -> bool {
        get_config_or_env(&self.config, "TLS", Some("GRPC"))
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false)
    }

    fn timeout_secs(&self) -> u64 {
        get_config_or_env(&self.config, "TIMEOUT", Some("GRPC"))
            .and_then(|v| v.parse().ok())
            .unwrap_or(10)
    }

    async fn connect(&self, endpoint_url: &str) -> Result<(Channel, Value), Value> {
        let start = Instant::now();
        let use_tls = self.use_tls() || endpoint_url.starts_with("https://");
        let timeout = self.timeout_secs();

        let mut ep = Endpoint::from_shared(endpoint_url.to_string()).map_err(|e| {
            json!({
                "endpoint": endpoint_url,
                "connected": false,
                "error": format!("Invalid endpoint: {}", e),
                "connect_time_ms": 0,
                "tls_enabled": false,
            })
        })?;

        ep = ep.timeout(std::time::Duration::from_secs(timeout));
        ep = ep.connect_timeout(std::time::Duration::from_secs(timeout));

        if use_tls {
            let tls_config = ClientTlsConfig::new().with_enabled_roots();
            ep = ep.tls_config(tls_config).map_err(|e| {
                json!({
                    "endpoint": endpoint_url,
                    "connected": false,
                    "error": format!("TLS config error: {}", e),
                    "connect_time_ms": start.elapsed().as_millis() as u64,
                    "tls_enabled": true,
                })
            })?;
        }

        let channel = ep.connect().await.map_err(|e| {
            json!({
                "endpoint": endpoint_url,
                "connected": false,
                "error": format!("Connection failed: {}", e),
                "connect_time_ms": start.elapsed().as_millis() as u64,
                "tls_enabled": use_tls,
            })
        })?;

        let connect_time = start.elapsed().as_millis() as u64;

        let conn_info = json!({
            "endpoint": endpoint_url,
            "connected": true,
            "connect_time_ms": connect_time,
            "tls_enabled": use_tls,
            "error": null,
        });

        Ok((channel, conn_info))
    }

    async fn gather_health_check(&self, endpoint_url: &str) -> Value {
        let (channel, _) = match self.connect(endpoint_url).await {
            Ok(c) => c,
            Err(err) => return err,
        };

        let service_name = get_config_or_env(&self.config, "SERVICE", Some("GRPC"))
            .unwrap_or_default();

        let start = Instant::now();

        // Use raw gRPC call for health check to avoid needing generated code
        let request = tonic::Request::new(HealthCheckRequest {
            service: service_name.clone(),
        });

        let mut client = HealthClient::new(channel);
        match client.check(request).await {
            Ok(response) => {
                let resp = response.into_inner();
                let elapsed = start.elapsed().as_millis() as u64;
                let status_str = match resp.status {
                    0 => "UNKNOWN",
                    1 => "SERVING",
                    2 => "NOT_SERVING",
                    3 => "SERVICE_UNKNOWN",
                    _ => "UNRECOGNIZED",
                };

                json!({
                    "endpoint": endpoint_url,
                    "service": service_name,
                    "status": status_str,
                    "status_code": resp.status,
                    "response_time_ms": elapsed,
                    "grpc_status": "OK",
                    "error": null,
                })
            }
            Err(status) => {
                let elapsed = start.elapsed().as_millis() as u64;
                json!({
                    "endpoint": endpoint_url,
                    "service": service_name,
                    "status": "ERROR",
                    "status_code": -1,
                    "response_time_ms": elapsed,
                    "grpc_status": format!("{:?}", status.code()),
                    "error": status.message().to_string(),
                })
            }
        }
    }

    async fn gather_connection(&self, endpoint_url: &str) -> Value {
        match self.connect(endpoint_url).await {
            Ok((_, info)) => info,
            Err(err) => err,
        }
    }

    async fn gather_reflection(&self, endpoint_url: &str) -> Value {
        let (channel, _) = match self.connect(endpoint_url).await {
            Ok(c) => c,
            Err(_) => {
                return json!({
                    "endpoint": endpoint_url,
                    "available": false,
                    "service_count": 0,
                    "services": [],
                    "error": "connection failed",
                });
            }
        };

        // gRPC Server Reflection v1 — list services
        let mut client = ServerReflectionClient::new(channel);
        let request = tonic::Request::new(tokio_stream::once(ServerReflectionRequest {
            host: String::new(),
            message_request: Some(
                server_reflection_request::MessageRequest::ListServices(String::new()),
            ),
        }));

        match client.server_reflection_info(request).await {
            Ok(response) => {
                let mut stream = response.into_inner();
                let mut services = Vec::new();

                while let Ok(Some(msg)) = stream.message().await {
                    if let Some(
                        server_reflection_response::MessageResponse::ListServicesResponse(list),
                    ) = msg.message_response
                    {
                        for svc in &list.service {
                            services.push(json!(svc.name));
                        }
                    }
                }

                json!({
                    "endpoint": endpoint_url,
                    "available": true,
                    "service_count": services.len(),
                    "services": services,
                    "error": null,
                })
            }
            Err(status) => {
                debug!(
                    "gRPC reflection not available on {}: {}",
                    endpoint_url,
                    status.message()
                );
                json!({
                    "endpoint": endpoint_url,
                    "available": false,
                    "service_count": 0,
                    "services": [],
                    "error": status.message().to_string(),
                })
            }
        }
    }

    async fn gather_service_health(&self, endpoint_url: &str) -> Value {
        // First get list of services via reflection
        let reflection = self.gather_reflection(endpoint_url).await;
        let services: Vec<String> = reflection
            .get("services")
            .and_then(|s| s.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        if services.is_empty() {
            return json!({
                "endpoint": endpoint_url,
                "services": [],
                "all_serving": false,
                "error": "no services found via reflection",
            });
        }

        let (channel, _) = match self.connect(endpoint_url).await {
            Ok(c) => c,
            Err(_) => {
                return json!({
                    "endpoint": endpoint_url,
                    "services": [],
                    "all_serving": false,
                    "error": "connection failed",
                });
            }
        };

        let mut client = HealthClient::new(channel);
        let mut service_statuses = Vec::new();
        let mut all_serving = true;

        for svc in &services {
            let request = tonic::Request::new(HealthCheckRequest {
                service: svc.clone(),
            });
            let status_str = match client.check(request).await {
                Ok(resp) => match resp.into_inner().status {
                    1 => "SERVING".to_string(),
                    other => {
                        all_serving = false;
                        format_health_status(other)
                    }
                },
                Err(e) => {
                    all_serving = false;
                    format!("ERROR: {:?}", e.code())
                }
            };
            service_statuses.push(json!({
                "name": svc,
                "status": status_str,
            }));
        }

        json!({
            "endpoint": endpoint_url,
            "services": service_statuses,
            "all_serving": all_serving,
            "error": null,
        })
    }
}

#[async_trait::async_trait]
impl Provider for GrpcProvider {
    fn name(&self) -> &str {
        "grpc"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        let endpoints = self.get_endpoints();
        let mut results = Vec::with_capacity(endpoints.len());

        for ep in &endpoints {
            let result = match resource_type {
                "health_check" => self.gather_health_check(ep).await,
                "connection" => self.gather_connection(ep).await,
                "reflection" => self.gather_reflection(ep).await,
                "service_health" => self.gather_service_health(ep).await,
                _ => {
                    return Err(ProviderError::UnsupportedResourceType(
                        resource_type.to_string(),
                    ))
                }
            };
            results.push(result);
        }

        Ok(results)
    }
}

fn format_health_status(code: i32) -> String {
    match code {
        0 => "UNKNOWN".to_string(),
        1 => "SERVING".to_string(),
        2 => "NOT_SERVING".to_string(),
        3 => "SERVICE_UNKNOWN".to_string(),
        _ => format!("UNRECOGNIZED({})", code),
    }
}

// ============================================================================
// gRPC Health Check Protocol (grpc.health.v1)
// Manual message definitions to avoid requiring proto compilation
// ============================================================================

#[derive(Clone, prost::Message)]
pub struct HealthCheckRequest {
    #[prost(string, tag = "1")]
    pub service: String,
}

#[derive(Clone, prost::Message)]
pub struct HealthCheckResponse {
    #[prost(int32, tag = "1")]
    pub status: i32,
}

/// Minimal gRPC Health client using tonic.
#[derive(Debug, Clone)]
pub struct HealthClient<T> {
    inner: tonic::client::Grpc<T>,
}

impl HealthClient<Channel> {
    pub fn new(channel: Channel) -> Self {
        let inner = tonic::client::Grpc::new(channel);
        Self { inner }
    }

    pub async fn check(
        &mut self,
        request: tonic::Request<HealthCheckRequest>,
    ) -> Result<tonic::Response<HealthCheckResponse>, tonic::Status> {
        self.inner.ready().await.map_err(|e| {
            tonic::Status::new(tonic::Code::Unknown, format!("Service not ready: {}", e))
        })?;
        let path = http::uri::PathAndQuery::from_static("/grpc.health.v1.Health/Check");
        let codec = tonic::codec::ProstCodec::default();
        self.inner.unary(request, path, codec).await
    }
}

// ============================================================================
// gRPC Server Reflection Protocol (grpc.reflection.v1)
// ============================================================================

#[derive(Clone, prost::Message)]
pub struct ServerReflectionRequest {
    #[prost(string, tag = "1")]
    pub host: String,
    #[prost(oneof = "server_reflection_request::MessageRequest", tags = "3, 4, 5, 6, 7")]
    pub message_request: Option<server_reflection_request::MessageRequest>,
}

pub mod server_reflection_request {
    #[derive(Clone, prost::Oneof)]
    pub enum MessageRequest {
        #[prost(string, tag = "3")]
        FileByFilename(String),
        #[prost(string, tag = "4")]
        FileContainingSymbol(String),
        #[prost(message, tag = "5")]
        FileContainingExtension(super::ExtensionRequest),
        #[prost(string, tag = "6")]
        AllExtensionNumbersOfType(String),
        #[prost(string, tag = "7")]
        ListServices(String),
    }
}

#[derive(Clone, prost::Message)]
pub struct ExtensionRequest {
    #[prost(string, tag = "1")]
    pub containing_type: String,
    #[prost(int32, tag = "2")]
    pub extension_number: i32,
}

#[derive(Clone, prost::Message)]
pub struct ServerReflectionResponse {
    #[prost(string, tag = "1")]
    pub valid_host: String,
    #[prost(message, optional, tag = "2")]
    pub original_request: Option<ServerReflectionRequest>,
    #[prost(
        oneof = "server_reflection_response::MessageResponse",
        tags = "4, 5, 6"
    )]
    pub message_response: Option<server_reflection_response::MessageResponse>,
}

pub mod server_reflection_response {
    #[derive(Clone, prost::Oneof)]
    pub enum MessageResponse {
        #[prost(message, tag = "4")]
        FileDescriptorResponse(super::FileDescriptorResponse),
        #[prost(message, tag = "5")]
        AllExtensionNumbersResponse(super::ExtensionNumberResponse),
        #[prost(message, tag = "6")]
        ListServicesResponse(super::ListServiceResponse),
    }
}

#[derive(Clone, prost::Message)]
pub struct FileDescriptorResponse {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub file_descriptor_proto: Vec<Vec<u8>>,
}

#[derive(Clone, prost::Message)]
pub struct ExtensionNumberResponse {
    #[prost(string, tag = "1")]
    pub base_type_name: String,
    #[prost(int32, repeated, tag = "2")]
    pub extension_number: Vec<i32>,
}

#[derive(Clone, prost::Message)]
pub struct ListServiceResponse {
    #[prost(message, repeated, tag = "1")]
    pub service: Vec<ServiceResponse>,
}

#[derive(Clone, prost::Message)]
pub struct ServiceResponse {
    #[prost(string, tag = "1")]
    pub name: String,
}

/// Minimal gRPC Server Reflection client.
#[derive(Debug, Clone)]
pub struct ServerReflectionClient<T> {
    inner: tonic::client::Grpc<T>,
}

impl ServerReflectionClient<Channel> {
    pub fn new(channel: Channel) -> Self {
        let inner = tonic::client::Grpc::new(channel);
        Self { inner }
    }

    pub async fn server_reflection_info(
        &mut self,
        request: tonic::Request<tokio_stream::Once<ServerReflectionRequest>>,
    ) -> Result<tonic::Response<tonic::Streaming<ServerReflectionResponse>>, tonic::Status> {
        self.inner.ready().await.map_err(|e| {
            tonic::Status::new(tonic::Code::Unknown, format!("Service not ready: {}", e))
        })?;
        let path = http::uri::PathAndQuery::from_static(
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        );
        let codec = tonic::codec::ProstCodec::default();
        self.inner.streaming(request, path, codec).await
    }
}
