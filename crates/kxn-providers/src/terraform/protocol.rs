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
    ///
    /// Terraform providers may return msgpack with `bin` types (DynamicPseudoType),
    /// which `rmp_serde` cannot directly deserialize to `serde_json::Value`.
    /// We first try `rmp_serde`, then fall back to `rmpv` with bin-to-string conversion.
    pub fn to_value(&self) -> Result<serde_json::Value, String> {
        let msgpack = self.msgpack();
        let json = self.json();

        if !msgpack.is_empty() {
            rmp_serde::from_slice(msgpack).or_else(|_| {
                let rmpv_val: rmpv::Value = rmpv::decode::read_value(
                    &mut &msgpack[..],
                )
                .map_err(|e| format!("Failed to decode msgpack: {}", e))?;
                rmpv_to_json(&rmpv_val)
            })
        } else if !json.is_empty() {
            serde_json::from_slice(json)
                .map_err(|e| format!("Failed to decode json: {}", e))
        } else {
            Err("No data in DynamicValue".to_string())
        }
    }
}

/// Convert an rmpv::Value to serde_json::Value, handling binary data.
///
/// Terraform's DynamicPseudoType encodes JSON values as msgpack `bin`.
/// We try to parse bin data as nested msgpack first, then as UTF-8 string,
/// then fall back to base64.
fn rmpv_to_json(val: &rmpv::Value) -> Result<serde_json::Value, String> {
    match val {
        rmpv::Value::Nil => Ok(serde_json::Value::Null),
        rmpv::Value::Boolean(b) => Ok(serde_json::Value::Bool(*b)),
        rmpv::Value::Integer(i) => {
            if let Some(n) = i.as_i64() {
                Ok(serde_json::Value::Number(n.into()))
            } else if let Some(n) = i.as_u64() {
                Ok(serde_json::Value::Number(n.into()))
            } else {
                Ok(serde_json::Value::Null)
            }
        }
        rmpv::Value::F32(f) => serde_json::Number::from_f64(*f as f64)
            .map(serde_json::Value::Number)
            .ok_or_else(|| "Invalid float".to_string()),
        rmpv::Value::F64(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .ok_or_else(|| "Invalid float".to_string()),
        rmpv::Value::String(s) => Ok(serde_json::Value::String(
            s.as_str().unwrap_or_default().to_string(),
        )),
        rmpv::Value::Binary(bytes) => {
            // Try to decode as nested msgpack (Terraform DynamicPseudoType pattern)
            if let Ok(nested) = rmpv::decode::read_value(&mut &bytes[..]) {
                if let Ok(json) = rmpv_to_json(&nested) {
                    return Ok(json);
                }
            }
            // Try as UTF-8 string
            if let Ok(s) = std::str::from_utf8(bytes) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(s) {
                    return Ok(parsed);
                }
                return Ok(serde_json::Value::String(s.to_string()));
            }
            // Fall back to base64
            use base64::Engine;
            Ok(serde_json::Value::String(
                base64::engine::general_purpose::STANDARD.encode(bytes),
            ))
        }
        rmpv::Value::Array(arr) => {
            let items: Result<Vec<_>, _> = arr.iter().map(rmpv_to_json).collect();
            Ok(serde_json::Value::Array(items?))
        }
        rmpv::Value::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (k, v) in entries {
                let key = match k {
                    rmpv::Value::String(s) => s.as_str().unwrap_or_default().to_string(),
                    other => format!("{}", other),
                };
                map.insert(key, rmpv_to_json(v)?);
            }
            Ok(serde_json::Value::Object(map))
        }
        rmpv::Value::Ext(_, bytes) => {
            if let Ok(nested) = rmpv::decode::read_value(&mut &bytes[..]) {
                return rmpv_to_json(&nested);
            }
            Ok(serde_json::Value::Null)
        }
    }
}
