//! gRPC read_resource operation for gathering resources.

use crate::error::ProviderError;
use tracing::debug;

use super::client::PluginClient;
use super::protocol::*;

impl PluginClient {
    /// Read a resource's current state (gather operation)
    pub async fn read_resource(
        &mut self,
        type_name: &str,
        current_state: serde_json::Value,
    ) -> Result<ReadResponse, ProviderError> {
        debug!("ReadResource for {}", type_name);

        let state_msgpack = rmp_serde::to_vec_named(&current_state)
            .map_err(|e| ProviderError::Api(format!("Failed to serialize state: {}", e)))?;

        match &mut self.client {
            PluginClientInner::V5(client) => {
                let request = tfplugin5::read_resource::Request {
                    type_name: type_name.to_string(),
                    current_state: Some(tfplugin5::DynamicValue {
                        json: vec![],
                        msgpack: state_msgpack,
                    }),
                    private: vec![],
                    provider_meta: None,
                    client_capabilities: Some(tfplugin5::ClientCapabilities {
                        deferral_allowed: false,
                        write_only_attributes_allowed: false,
                    }),
                    current_identity: None,
                };

                let response = client
                    .read_resource(request)
                    .await
                    .map_err(|e| ProviderError::Api(format!("ReadResource failed: {}", e)))?
                    .into_inner();

                if let Some(diag) = response.diagnostics.iter().find(|d| {
                    d.severity == tfplugin5::diagnostic::Severity::Error as i32
                }) {
                    return Err(ProviderError::Api(format!(
                        "Read error: {} - {}",
                        diag.summary, diag.detail
                    )));
                }

                Ok(ReadResponse::V5(response))
            }
            PluginClientInner::V6(client) => {
                let request = tfplugin6::read_resource::Request {
                    type_name: type_name.to_string(),
                    current_state: Some(tfplugin6::DynamicValue {
                        json: vec![],
                        msgpack: state_msgpack,
                    }),
                    private: vec![],
                    provider_meta: None,
                    client_capabilities: Some(tfplugin6::ClientCapabilities {
                        deferral_allowed: false,
                        write_only_attributes_allowed: false,
                    }),
                    current_identity: None,
                };

                let response = client
                    .read_resource(request)
                    .await
                    .map_err(|e| ProviderError::Api(format!("ReadResource failed: {}", e)))?
                    .into_inner();

                if let Some(diag) = response.diagnostics.iter().find(|d| {
                    d.severity == tfplugin6::diagnostic::Severity::Error as i32
                }) {
                    return Err(ProviderError::Api(format!(
                        "Read error: {} - {}",
                        diag.summary, diag.detail
                    )));
                }

                Ok(ReadResponse::V6(response))
            }
        }
    }

    /// Read a data source (listing/query operation)
    pub async fn read_data_source(
        &mut self,
        type_name: &str,
        config: serde_json::Value,
    ) -> Result<DataSourceResponse, ProviderError> {
        debug!("ReadDataSource for {}", type_name);

        let config_msgpack = rmp_serde::to_vec_named(&config)
            .map_err(|e| ProviderError::Api(format!("Failed to serialize config: {}", e)))?;

        match &mut self.client {
            PluginClientInner::V5(client) => {
                let request = tfplugin5::read_data_source::Request {
                    type_name: type_name.to_string(),
                    config: Some(tfplugin5::DynamicValue {
                        json: vec![],
                        msgpack: config_msgpack,
                    }),
                    provider_meta: None,
                    client_capabilities: Some(tfplugin5::ClientCapabilities {
                        deferral_allowed: false,
                        write_only_attributes_allowed: false,
                    }),
                };

                let response = client
                    .read_data_source(request)
                    .await
                    .map_err(|e| ProviderError::Api(format!("ReadDataSource failed: {}", e)))?
                    .into_inner();

                if let Some(diag) = response.diagnostics.iter().find(|d| {
                    d.severity == tfplugin5::diagnostic::Severity::Error as i32
                }) {
                    return Err(ProviderError::Api(format!(
                        "DataSource error: {} - {}",
                        diag.summary, diag.detail
                    )));
                }

                Ok(DataSourceResponse::V5(response))
            }
            PluginClientInner::V6(client) => {
                let request = tfplugin6::read_data_source::Request {
                    type_name: type_name.to_string(),
                    config: Some(tfplugin6::DynamicValue {
                        json: vec![],
                        msgpack: config_msgpack,
                    }),
                    provider_meta: None,
                    client_capabilities: Some(tfplugin6::ClientCapabilities {
                        deferral_allowed: false,
                        write_only_attributes_allowed: false,
                    }),
                };

                let response = client
                    .read_data_source(request)
                    .await
                    .map_err(|e| ProviderError::Api(format!("ReadDataSource failed: {}", e)))?
                    .into_inner();

                if let Some(diag) = response.diagnostics.iter().find(|d| {
                    d.severity == tfplugin6::diagnostic::Severity::Error as i32
                }) {
                    return Err(ProviderError::Api(format!(
                        "DataSource error: {} - {}",
                        diag.summary, diag.detail
                    )));
                }

                Ok(DataSourceResponse::V6(response))
            }
        }
    }
}
