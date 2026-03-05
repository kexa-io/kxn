use crate::error::ProviderError;

/// Plugin handshake info parsed from stdout
#[derive(Debug)]
pub struct PluginHandshake {
    #[allow(dead_code)]
    pub core_protocol_version: u32,
    pub plugin_protocol_version: u32,
    pub network_type: String,
    pub network_addr: String,
    pub protocol: String,
}

impl PluginHandshake {
    /// Parse the go-plugin handshake line
    /// Format: "CORE_PROTOCOL_VERSION|APP_PROTOCOL_VERSION|NETWORK_TYPE|NETWORK_ADDR|PROTOCOL|SERVER_CERT\n"
    pub fn parse(line: &str) -> Result<Self, ProviderError> {
        let parts: Vec<&str> = line.trim().split('|').collect();
        if parts.len() < 5 {
            return Err(ProviderError::Api(format!(
                "Invalid handshake line: {}",
                line
            )));
        }

        Ok(Self {
            core_protocol_version: parts[0].parse().unwrap_or(1),
            plugin_protocol_version: parts[1].parse().unwrap_or(5),
            network_type: parts[2].to_string(),
            network_addr: parts[3].to_string(),
            protocol: parts[4].to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_parse() {
        let line = "1|6|unix|/tmp/plugin123456|grpc|\n";
        let handshake = PluginHandshake::parse(line).unwrap();
        assert_eq!(handshake.core_protocol_version, 1);
        assert_eq!(handshake.plugin_protocol_version, 6);
        assert_eq!(handshake.network_type, "unix");
        assert_eq!(handshake.network_addr, "/tmp/plugin123456");
        assert_eq!(handshake.protocol, "grpc");
    }

    #[test]
    fn test_handshake_parse_tcp() {
        let line = "1|6|tcp|127.0.0.1:12345|grpc|\n";
        let handshake = PluginHandshake::parse(line).unwrap();
        assert_eq!(handshake.network_type, "tcp");
        assert_eq!(handshake.network_addr, "127.0.0.1:12345");
    }
}
