//! TerraformProvider — gather-only wrapper around PluginClient.

use crate::error::ProviderError;
use serde_json::Value;
use tracing::{debug, info};

use super::client::PluginClient;
use super::protocol::SchemaResponse;
use super::registry::{ProviderAddress, ProviderRegistry};

/// Generate a `block_defaults_vN` function for each protocol version.
/// The generated function recursively builds a JSON object from a schema Block.
macro_rules! impl_block_defaults {
    ($fn_name:ident, $mod:ident) => {
        fn $fn_name(
            block: &$mod::schema::Block,
            user_config: &Value,
        ) -> Value {
            use $mod::schema::nested_block::NestingMode;

            let mut map = serde_json::Map::new();

            for attr in &block.attributes {
                map.insert(attr.name.clone(), Value::Null);
            }

            for bt in &block.block_types {
                let default = if let Some(nested_block) = &bt.block {
                    match NestingMode::try_from(bt.nesting) {
                        Ok(NestingMode::Single) | Ok(NestingMode::Group) => {
                            $fn_name(nested_block, &Value::Null)
                        }
                        Ok(NestingMode::List) | Ok(NestingMode::Set) => Value::Array(vec![]),
                        Ok(NestingMode::Map) => Value::Object(serde_json::Map::new()),
                        _ => Value::Null,
                    }
                } else {
                    Value::Null
                };
                map.insert(bt.type_name.clone(), default);
            }

            // Overlay user config
            if let Value::Object(user_map) = user_config {
                for (k, v) in user_map {
                    if map.contains_key(k.as_str()) {
                        if let (Some(Value::Object(existing)), Value::Object(user_nested)) =
                            (map.get(k.as_str()), v)
                        {
                            let mut merged = existing.clone();
                            for (nk, nv) in user_nested {
                                merged.insert(nk.clone(), nv.clone());
                            }
                            map.insert(k.clone(), Value::Object(merged));
                        } else {
                            map.insert(k.clone(), v.clone());
                        }
                    }
                }
            }

            Value::Object(map)
        }
    };
}

use super::protocol::tfplugin5;
use super::protocol::tfplugin6;

impl_block_defaults!(block_defaults_v5, tfplugin5);
impl_block_defaults!(block_defaults_v6, tfplugin6);

/// A configured Terraform provider ready for gathering resources.
pub struct TerraformProvider {
    pub address: ProviderAddress,
    client: PluginClient,
    resource_types: Vec<String>,
    data_source_types: Vec<String>,
}

impl TerraformProvider {
    /// Create a provider for schema discovery only (no configure step, no credentials needed).
    pub async fn schema_only(
        address: ProviderAddress,
        version: Option<&str>,
    ) -> Result<Self, ProviderError> {
        let registry = ProviderRegistry::new()?;

        info!("Getting provider binary for {} (schema only)", address.full_name());
        let binary_path = registry.get_provider(&address, version).await?;

        let client = PluginClient::launch(&binary_path).await?;
        let resource_types = Self::extract_resource_types(&client).await?;
        let data_source_types = Self::extract_data_source_types(&client).await?;

        info!(
            "Provider {} schema loaded: {} resource types, {} data sources",
            address.full_name(),
            resource_types.len(),
            data_source_types.len()
        );

        Ok(Self {
            address,
            client,
            resource_types,
            data_source_types,
        })
    }

    /// Get attribute names for a resource type from the provider schema.
    pub async fn type_attributes(&self, type_name: &str) -> Result<Vec<String>, ProviderError> {
        let schema = self.client.get_schema().await?;
        let attrs = match &schema {
            SchemaResponse::V5(s) => s.resource_schemas.get(type_name).and_then(|s| {
                s.block.as_ref().map(|b| b.attributes.iter().map(|a| a.name.clone()).collect())
            }),
            SchemaResponse::V6(s) => s.resource_schemas.get(type_name).and_then(|s| {
                s.block.as_ref().map(|b| b.attributes.iter().map(|a| a.name.clone()).collect())
            }),
        };
        attrs.ok_or_else(|| ProviderError::NotFound(format!("Resource type not found: {}", type_name)))
    }

    /// Get attribute names for a data source type from the provider schema.
    pub async fn data_source_attributes(&self, type_name: &str) -> Result<Vec<String>, ProviderError> {
        let schema = self.client.get_schema().await?;
        let attrs = match &schema {
            SchemaResponse::V5(s) => s.data_source_schemas.get(type_name).and_then(|s| {
                s.block.as_ref().map(|b| b.attributes.iter().map(|a| a.name.clone()).collect())
            }),
            SchemaResponse::V6(s) => s.data_source_schemas.get(type_name).and_then(|s| {
                s.block.as_ref().map(|b| b.attributes.iter().map(|a| a.name.clone()).collect())
            }),
        };
        attrs.ok_or_else(|| ProviderError::NotFound(format!("Data source type not found: {}", type_name)))
    }

    /// Create and configure a Terraform provider.
    pub async fn new(
        address: ProviderAddress,
        config: Value,
        version: Option<&str>,
    ) -> Result<Self, ProviderError> {
        let registry = ProviderRegistry::new()?;

        info!("Getting provider binary for {}", address.full_name());
        let binary_path = registry.get_provider(&address, version).await?;

        let mut client = PluginClient::launch(&binary_path).await?;
        let resource_types = Self::extract_resource_types(&client).await?;
        let data_source_types = Self::extract_data_source_types(&client).await?;

        let full_config = Self::build_provider_config(&client, &config).await?;
        client.configure(full_config).await?;

        info!(
            "Provider {} configured with {} resource types, {} data sources",
            address.full_name(),
            resource_types.len(),
            data_source_types.len()
        );

        Ok(Self {
            address,
            client,
            resource_types,
            data_source_types,
        })
    }

    async fn extract_resource_types(client: &PluginClient) -> Result<Vec<String>, ProviderError> {
        let schema = client.get_schema().await?;
        let types = match &schema {
            SchemaResponse::V5(s) => s.resource_schemas.keys().cloned().collect(),
            SchemaResponse::V6(s) => s.resource_schemas.keys().cloned().collect(),
        };
        Ok(types)
    }

    async fn extract_data_source_types(client: &PluginClient) -> Result<Vec<String>, ProviderError> {
        let schema = client.get_schema().await?;
        let types = match &schema {
            SchemaResponse::V5(s) => s.data_source_schemas.keys().cloned().collect(),
            SchemaResponse::V6(s) => s.data_source_schemas.keys().cloned().collect(),
        };
        Ok(types)
    }

    /// Build provider config with recursive block defaults + user overrides
    async fn build_provider_config(
        client: &PluginClient,
        user_config: &Value,
    ) -> Result<Value, ProviderError> {
        let schema = client.get_schema().await?;
        let config = match &schema {
            SchemaResponse::V5(s) => match s.provider.as_ref().and_then(|p| p.block.as_ref()) {
                Some(block) => block_defaults_v5(block, user_config),
                None => Value::Object(serde_json::Map::new()),
            },
            SchemaResponse::V6(s) => match s.provider.as_ref().and_then(|p| p.block.as_ref()) {
                Some(block) => block_defaults_v6(block, user_config),
                None => Value::Object(serde_json::Map::new()),
            },
        };
        Ok(config)
    }

    pub fn resource_types(&self) -> &[String] {
        &self.resource_types
    }

    pub fn data_source_types(&self) -> &[String] {
        &self.data_source_types
    }

    pub async fn read_resource(
        &mut self,
        resource_type: &str,
        state: Value,
    ) -> Result<Option<Value>, ProviderError> {
        debug!("Reading resource {} with state", resource_type);
        let response = self.client.read_resource(resource_type, state).await?;

        if let Some(new_state) = response.new_state() {
            match new_state.to_value() {
                Ok(v) => Ok(Some(v)),
                Err(e) => Err(ProviderError::Api(format!("Failed to decode state: {}", e))),
            }
        } else {
            Ok(None)
        }
    }

    /// Build data source config with recursive block defaults + user overrides
    pub async fn build_data_source_config(
        &self,
        type_name: &str,
        user_config: Value,
    ) -> Result<Value, ProviderError> {
        let schema = self.client.get_schema().await?;
        let config = match &schema {
            SchemaResponse::V5(s) => {
                match s.data_source_schemas.get(type_name).and_then(|ds| ds.block.as_ref()) {
                    Some(block) => block_defaults_v5(block, &user_config),
                    None => Value::Object(serde_json::Map::new()),
                }
            }
            SchemaResponse::V6(s) => {
                match s.data_source_schemas.get(type_name).and_then(|ds| ds.block.as_ref()) {
                    Some(block) => block_defaults_v6(block, &user_config),
                    None => Value::Object(serde_json::Map::new()),
                }
            }
        };
        Ok(config)
    }

    pub async fn read_data_source(
        &mut self,
        type_name: &str,
        config: Value,
    ) -> Result<Option<Value>, ProviderError> {
        debug!("Reading data source {}", type_name);
        let response = self.client.read_data_source(type_name, config).await?;

        if let Some(state) = response.state() {
            match state.to_value() {
                Ok(v) => Ok(Some(v)),
                Err(e) => Err(ProviderError::Api(format!("Failed to decode data source: {}", e))),
            }
        } else {
            Ok(None)
        }
    }

    pub async fn stop(&mut self) -> Result<(), ProviderError> {
        self.client.stop().await
    }
}

impl Drop for TerraformProvider {
    fn drop(&mut self) {
        // PluginClient Drop handles killing the process
    }
}
