//! Terraform Plugin Client — manages provider process lifecycle.
//! Stripped to gather-only (no plan/apply/import).

use crate::error::ProviderError;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use tracing::{debug, info, warn};

use super::handshake::PluginHandshake;
use super::protocol::*;

/// Client for a running Terraform provider plugin
pub struct PluginClient {
    process: Child,
    pub(crate) client: PluginClientInner,
    schemas_v5: Option<tfplugin5::get_provider_schema::Response>,
    schemas_v6: Option<tfplugin6::get_provider_schema::Response>,
}

impl PluginClient {
    pub fn is_running(&mut self) -> bool {
        match self.process.try_wait() {
            Ok(None) => true,
            Ok(Some(status)) => {
                warn!("Provider process exited with status: {}", status);
                false
            }
            Err(e) => {
                warn!("Error checking provider process: {}", e);
                false
            }
        }
    }

    /// Launch a provider plugin and establish gRPC connection
    pub async fn launch(binary_path: &Path) -> Result<Self, ProviderError> {
        info!("Launching provider plugin: {:?}", binary_path);

        let mut process = Command::new(binary_path)
            .env(
                "TF_PLUGIN_MAGIC_COOKIE",
                "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2",
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ProviderError::Api(format!("Failed to launch provider: {}", e)))?;

        // Read handshake line from stdout
        let stdout = process
            .stdout
            .take()
            .ok_or_else(|| ProviderError::Api("Failed to capture provider stdout".to_string()))?;
        let stderr = process.stderr.take();

        let (handshake_line, remaining_stdout) = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::task::spawn_blocking(move || {
                let mut reader = BufReader::new(stdout);
                let mut line = String::new();
                reader.read_line(&mut line)?;
                Ok::<_, std::io::Error>((line, reader.into_inner()))
            }),
        )
        .await
        .map_err(|_| ProviderError::Api("Timeout waiting for provider handshake (30s)".to_string()))?
        .map_err(|e| ProviderError::Api(format!("Task join error: {}", e)))?
        .map_err(|e| ProviderError::Api(format!("Failed to read handshake: {}", e)))?;

        if handshake_line.trim().is_empty() {
            return Err(ProviderError::Api("Provider returned empty handshake".to_string()));
        }

        // Drain stdout in background (go-plugin requires this)
        tokio::spawn(async move {
            let _ = tokio::task::spawn_blocking(move || {
                let mut reader = BufReader::new(remaining_stdout);
                let mut line = String::new();
                loop {
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) => line.clear(),
                        Err(_) => break,
                    }
                }
            })
            .await;
        });

        // Drain stderr in background
        if let Some(stderr) = stderr {
            tokio::spawn(async move {
                let _ = tokio::task::spawn_blocking(move || {
                    let mut reader = BufReader::new(stderr);
                    let mut line = String::new();
                    loop {
                        match reader.read_line(&mut line) {
                            Ok(0) => break,
                            Ok(_) => {
                                if line.contains("@level\":\"error\"") {
                                    warn!("Provider error: {}", line.trim());
                                }
                                line.clear();
                            }
                            Err(_) => break,
                        }
                    }
                })
                .await;
            });
        }

        info!("Received handshake: {}", handshake_line.trim());
        let handshake = PluginHandshake::parse(&handshake_line)?;

        if handshake.protocol != "grpc" {
            return Err(ProviderError::Api(format!(
                "Unsupported protocol: {}",
                handshake.protocol
            )));
        }

        let channel = match handshake.network_type.as_str() {
            "unix" => Self::connect_unix(&handshake.network_addr).await?,
            "tcp" => Self::connect_tcp(&handshake.network_addr).await?,
            _ => {
                return Err(ProviderError::Api(format!(
                    "Unsupported network type: {}",
                    handshake.network_type
                )))
            }
        };

        let (client, schemas_v5, schemas_v6) = Self::detect_and_get_schema(channel).await?;
        info!("Provider plugin connected successfully");

        Ok(Self {
            process,
            client,
            schemas_v5,
            schemas_v6,
        })
    }

    /// Detect protocol version and get schema
    async fn detect_and_get_schema(
        channel: Channel,
    ) -> Result<
        (
            PluginClientInner,
            Option<tfplugin5::get_provider_schema::Response>,
            Option<tfplugin6::get_provider_schema::Response>,
        ),
        ProviderError,
    > {
        debug!("Trying tfplugin5 protocol...");
        let mut client5 = ProviderClient5::new(channel.clone())
            .max_decoding_message_size(256 * 1024 * 1024);
        let request = tfplugin5::get_provider_schema::Request {};

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            client5.get_schema(request),
        )
        .await;

        match result {
            Ok(Ok(response)) => {
                info!("Provider uses tfplugin5 protocol");
                let schema = response.into_inner();
                Ok((PluginClientInner::V5(client5), Some(schema), None))
            }
            Ok(Err(e)) => {
                if e.code() == tonic::Code::Unimplemented {
                    debug!("Trying tfplugin6...");
                    let mut client6 = ProviderClient6::new(channel)
                        .max_decoding_message_size(256 * 1024 * 1024);
                    let request = tfplugin6::get_provider_schema::Request {};
                    let response = tokio::time::timeout(
                        std::time::Duration::from_secs(120),
                        client6.get_provider_schema(request),
                    )
                    .await
                    .map_err(|_| ProviderError::Api("Timeout getting schema (30s)".to_string()))?
                    .map_err(|e| ProviderError::Api(format!("Failed to get schema: {}", e)))?;

                    info!("Provider uses tfplugin6 protocol");
                    let schema = response.into_inner();
                    Ok((PluginClientInner::V6(client6), None, Some(schema)))
                } else {
                    Err(ProviderError::Api(format!(
                        "Failed to detect provider protocol: {}",
                        e
                    )))
                }
            }
            Err(_) => Err(ProviderError::Api(
                "Timeout detecting provider protocol (30s)".to_string(),
            )),
        }
    }

    #[cfg(unix)]
    async fn connect_unix(path: &str) -> Result<Channel, ProviderError> {
        use std::time::Duration;

        let path_clone = path.to_string();

        let endpoint = Endpoint::try_from("http://[::]:50051")
            .map_err(|e| ProviderError::Api(format!("Failed to create endpoint: {}", e)))?
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(60))
            .keep_alive_while_idle(true)
            .http2_adaptive_window(false)
            .initial_stream_window_size(1024 * 1024)
            .initial_connection_window_size(1024 * 1024);

        let channel = endpoint
            .connect_with_connector(service_fn(move |_uri: Uri| {
                let path = path_clone.clone();
                async move {
                    let stream = UnixStream::connect(&path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await
            .map_err(|e| ProviderError::Api(format!("Failed to connect to Unix socket: {}", e)))?;

        debug!("Unix socket channel established");
        Ok(channel)
    }

    #[cfg(not(unix))]
    async fn connect_unix(_path: &str) -> Result<Channel, ProviderError> {
        Err(ProviderError::Api(
            "Unix sockets not supported on this platform".to_string(),
        ))
    }

    async fn connect_tcp(addr: &str) -> Result<Channel, ProviderError> {
        use std::time::Duration;

        let endpoint = format!("http://{}", addr);
        Channel::from_shared(endpoint)
            .map_err(|e| ProviderError::Api(format!("Invalid address: {}", e)))?
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(60))
            .keep_alive_while_idle(true)
            .http2_adaptive_window(false)
            .initial_stream_window_size(1024 * 1024)
            .initial_connection_window_size(1024 * 1024)
            .connect()
            .await
            .map_err(|e| ProviderError::Api(format!("Failed to connect: {}", e)))
    }

    pub async fn get_schema(&self) -> Result<SchemaResponse<'_>, ProviderError> {
        match &self.client {
            PluginClientInner::V5(_) => Ok(SchemaResponse::V5(
                self.schemas_v5
                    .as_ref()
                    .ok_or_else(|| ProviderError::Api("Schema not available".to_string()))?,
            )),
            PluginClientInner::V6(_) => Ok(SchemaResponse::V6(
                self.schemas_v6
                    .as_ref()
                    .ok_or_else(|| ProviderError::Api("Schema not available".to_string()))?,
            )),
        }
    }

    /// Configure the provider
    pub async fn configure(&mut self, config: serde_json::Value) -> Result<(), ProviderError> {
        debug!("Configuring provider...");

        let config_msgpack = rmp_serde::to_vec_named(&config)
            .map_err(|e| ProviderError::Api(format!("Failed to serialize config: {}", e)))?;

        match &mut self.client {
            PluginClientInner::V5(client) => {
                let request = tfplugin5::configure::Request {
                    terraform_version: "1.9.0".to_string(),
                    config: Some(tfplugin5::DynamicValue {
                        json: vec![],
                        msgpack: config_msgpack,
                    }),
                    client_capabilities: Some(tfplugin5::ClientCapabilities {
                        deferral_allowed: false,
                        write_only_attributes_allowed: false,
                    }),
                };

                let response = client
                    .configure(request)
                    .await
                    .map_err(|e| ProviderError::Api(format!("Configure failed: {}", e)))?
                    .into_inner();

                if let Some(diag) = response.diagnostics.iter().find(|d| {
                    d.severity == tfplugin5::diagnostic::Severity::Error as i32
                }) {
                    return Err(ProviderError::Api(format!(
                        "Provider configuration error: {} - {}",
                        diag.summary, diag.detail
                    )));
                }
            }
            PluginClientInner::V6(client) => {
                let config_msgpack_v6 = rmp_serde::to_vec_named(&config)
                    .map_err(|e| ProviderError::Api(format!("Failed to serialize config: {}", e)))?;
                let request = tfplugin6::configure_provider::Request {
                    terraform_version: "1.9.0".to_string(),
                    config: Some(tfplugin6::DynamicValue {
                        json: vec![],
                        msgpack: config_msgpack_v6,
                    }),
                    client_capabilities: Some(tfplugin6::ClientCapabilities {
                        deferral_allowed: false,
                        write_only_attributes_allowed: false,
                    }),
                };

                let response = client
                    .configure_provider(request)
                    .await
                    .map_err(|e| ProviderError::Api(format!("ConfigureProvider failed: {}", e)))?
                    .into_inner();

                if let Some(diag) = response.diagnostics.iter().find(|d| {
                    d.severity == tfplugin6::diagnostic::Severity::Error as i32
                }) {
                    return Err(ProviderError::Api(format!(
                        "Provider configuration error: {} - {}",
                        diag.summary, diag.detail
                    )));
                }
            }
        }

        Ok(())
    }

    /// Stop the provider gracefully
    pub async fn stop(&mut self) -> Result<(), ProviderError> {
        debug!("Stopping provider plugin");

        match &mut self.client {
            PluginClientInner::V5(client) => {
                let request = tfplugin5::stop::Request {};
                let _ = client.stop(request).await;
            }
            PluginClientInner::V6(client) => {
                let request = tfplugin6::stop_provider::Request {};
                let _ = client.stop_provider(request).await;
            }
        }

        if let Err(e) = self.process.kill() {
            warn!("Failed to kill provider process: {}", e);
        }

        Ok(())
    }
}

impl Drop for PluginClient {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}
