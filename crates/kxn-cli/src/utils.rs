use serde_json::Value;

/// Convert a toml::Table to serde_json::Value without intermediate string serialization.
pub fn toml_table_to_json(table: &toml::Table) -> Value {
    fn convert(val: &toml::Value) -> Value {
        match val {
            toml::Value::String(s) => Value::String(s.clone()),
            toml::Value::Integer(i) => Value::Number((*i).into()),
            toml::Value::Float(f) => serde_json::Number::from_f64(*f)
                .map(Value::Number)
                .unwrap_or(Value::String(f.to_string())),
            toml::Value::Boolean(b) => Value::Bool(*b),
            toml::Value::Datetime(dt) => Value::String(dt.to_string()),
            toml::Value::Array(arr) => Value::Array(arr.iter().map(convert).collect()),
            toml::Value::Table(tbl) => {
                let mut map = serde_json::Map::new();
                for (k, v) in tbl {
                    map.insert(k.clone(), convert(v));
                }
                Value::Object(map)
            }
        }
    }
    convert(&toml::Value::Table(table.clone()))
}
