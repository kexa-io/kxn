//! Proto modules and response wrapper types for tfplugin5/tfplugin6.

use tonic::transport::Channel;

// Include the generated proto code for both protocols
pub mod tfplugin5 {
    tonic::include_proto!("tfplugin5");
}

pub mod tfplugin6 {
    tonic::include_proto!("tfplugin6");
}

pub use tfplugin5::provider_client::ProviderClient as ProviderClient5;
pub use tfplugin6::provider_client::ProviderClient as ProviderClient6;

/// Enum to hold either tfplugin5 or tfplugin6 client.
/// Clone-safe for concurrent gRPC operations via HTTP/2 multiplexing.
#[derive(Clone)]
pub enum PluginClientInner {
    V5(ProviderClient5<Channel>),
    V6(ProviderClient6<Channel>),
}

// ─── Response wrapper types ─────────────────────────────────────────────────

pub enum SchemaResponse<'a> {
    V5(&'a tfplugin5::get_provider_schema::Response),
    V6(&'a tfplugin6::get_provider_schema::Response),
}

pub enum ReadResponse {
    V5(tfplugin5::read_resource::Response),
    V6(tfplugin6::read_resource::Response),
}

impl ReadResponse {
    pub fn new_state(&self) -> Option<DynamicValueRef<'_>> {
        match self {
            ReadResponse::V5(r) => r.new_state.as_ref().map(DynamicValueRef::V5),
            ReadResponse::V6(r) => r.new_state.as_ref().map(DynamicValueRef::V6),
        }
    }
}

pub enum DataSourceResponse {
    V5(tfplugin5::read_data_source::Response),
    V6(tfplugin6::read_data_source::Response),
}

impl DataSourceResponse {
    pub fn state(&self) -> Option<DynamicValueRef<'_>> {
        match self {
            DataSourceResponse::V5(r) => r.state.as_ref().map(DynamicValueRef::V5),
            DataSourceResponse::V6(r) => r.state.as_ref().map(DynamicValueRef::V6),
        }
    }
}

pub enum DynamicValueRef<'a> {
    V5(&'a tfplugin5::DynamicValue),
    V6(&'a tfplugin6::DynamicValue),
}

impl<'a> DynamicValueRef<'a> {
    pub fn json(&self) -> &[u8] {
        match self {
            DynamicValueRef::V5(v) => &v.json,
            DynamicValueRef::V6(v) => &v.json,
        }
    }

    pub fn msgpack(&self) -> &[u8] {
        match self {
            DynamicValueRef::V5(v) => &v.msgpack,
            DynamicValueRef::V6(v) => &v.msgpack,
        }
    }

    /// Decode the value as serde_json::Value (from msgpack or json)
    pub fn to_value(&self) -> Result<serde_json::Value, String> {
        let msgpack = self.msgpack();
        let json = self.json();

        if !msgpack.is_empty() {
            rmp_serde::from_slice(msgpack)
                .map_err(|e| format!("Failed to decode msgpack: {}", e))
        } else if !json.is_empty() {
            serde_json::from_slice(json)
                .map_err(|e| format!("Failed to decode json: {}", e))
        } else {
            Err("No data in DynamicValue".to_string())
        }
    }
}
