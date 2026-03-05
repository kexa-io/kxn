use crate::config::get_config_or_env;
use crate::error::ProviderError;
use crate::traits::Provider;
use serde_json::{json, Value};
use std::time::Instant;

pub struct HttpProvider {
    config: Value,
}

impl HttpProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        // Validate that URL is provided
        let has_url = get_config_or_env(&config, "URL", Some("HTTP")).is_some();
        if !has_url {
            return Err(ProviderError::InvalidConfig(
                "HTTP provider requires URL (config or env HTTP_URL)".into(),
            ));
        }
        Ok(Self { config })
    }

    fn get_urls(&self) -> Vec<String> {
        if let Some(Value::Array(arr)) = self.config.get("URL").or(self.config.get("url")) {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else if let Some(url) = get_config_or_env(&self.config, "URL", Some("HTTP")) {
            vec![url]
        } else {
            vec![]
        }
    }

    async fn gather_request(&self, url: &str) -> Value {
        let method = get_config_or_env(&self.config, "METHOD", Some("HTTP"))
            .unwrap_or_else(|| "GET".into());
        let authorization = get_config_or_env(&self.config, "AUTHORIZATION", Some("HTTP"));
        let body = get_config_or_env(&self.config, "BODY", Some("HTTP"));

        let mut result = json!({
            "url": url,
            "code": null,
            "headers": {},
            "body": null,
            "delays": null,
            "ip": [],
            "certificate": null,
            "tls": null,
        });

        // DNS resolution
        if let Some(host) = extract_host(url) {
            match resolve_dns(&host).await {
                Ok(ips) => {
                    result["ip"] = json!(ips);
                }
                Err(e) => {
                    result["dns_error"] = json!(e);
                }
            }
        }

        // TLS certificate extraction (for https URLs)
        if url.starts_with("https://") {
            if let Some(host) = extract_host(url) {
                let port = extract_port(url).unwrap_or(443);
                match extract_tls_info(&host, port).await {
                    Ok((cert, tls)) => {
                        result["certificate"] = cert;
                        result["tls"] = tls;
                    }
                    Err(e) => {
                        result["tls_error"] = json!(e);
                    }
                }
            }
        }

        // HTTP request
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build();

        let client = match client {
            Ok(c) => c,
            Err(e) => {
                result["error"] = json!(format!("Failed to build HTTP client: {}", e));
                return result;
            }
        };

        let method_parsed = match method.to_uppercase().as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            "PATCH" => reqwest::Method::PATCH,
            other => {
                result["error"] = json!(format!("Unsupported HTTP method: {}", other));
                return result;
            }
        };

        let mut req = client.request(method_parsed, url);

        if let Some(auth) = &authorization {
            req = req.header("Authorization", auth.as_str());
        }

        // Custom headers from config
        if let Some(Value::Object(headers)) = self.config.get("HEADERS").or(self.config.get("headers")) {
            for (k, v) in headers {
                if let Some(s) = v.as_str() {
                    req = req.header(k.as_str(), s);
                }
            }
        }

        if let Some(b) = &body {
            req = req.body(b.clone());
        }

        let start = Instant::now();
        match req.send().await {
            Ok(resp) => {
                let elapsed = start.elapsed().as_millis() as u64;
                result["code"] = json!(resp.status().as_u16());
                result["delays"] = json!(elapsed);

                let mut headers_map = serde_json::Map::new();
                for (name, value) in resp.headers() {
                    if let Ok(v) = value.to_str() {
                        headers_map.insert(
                            name.as_str().to_string(),
                            Value::String(v.to_string()),
                        );
                    }
                }
                result["headers"] = Value::Object(headers_map);

                match resp.text().await {
                    Ok(text) => {
                        // Truncate body to 1MB to avoid memory issues
                        let max_body = 1_048_576;
                        if text.len() > max_body {
                            result["body"] = json!(&text[..max_body]);
                            result["body_truncated"] = json!(true);
                        } else {
                            result["body"] = json!(text);
                        }
                    }
                    Err(e) => {
                        result["body_error"] = json!(format!("{}", e));
                    }
                }
            }
            Err(e) => {
                let elapsed = start.elapsed().as_millis() as u64;
                result["delays"] = json!(elapsed);
                result["error"] = json!(format!("Request failed: {}", e));
            }
        }

        result
    }
}

#[async_trait::async_trait]
impl Provider for HttpProvider {
    fn name(&self) -> &str {
        "http"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(vec!["request".to_string()])
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        if resource_type != "request" {
            return Err(ProviderError::UnsupportedResourceType(
                resource_type.to_string(),
            ));
        }

        let urls = self.get_urls();
        let mut results = Vec::with_capacity(urls.len());
        for url in &urls {
            results.push(self.gather_request(url).await);
        }
        Ok(results)
    }
}

fn extract_host(url: &str) -> Option<String> {
    url::Url::parse(url).ok().and_then(|u| u.host_str().map(String::from))
}

fn extract_port(url: &str) -> Option<u16> {
    url::Url::parse(url).ok().and_then(|u| u.port())
}

async fn resolve_dns(host: &str) -> Result<Vec<String>, String> {
    use hickory_resolver::TokioResolver;

    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| format!("Failed to create DNS resolver: {}", e))?
        .build();

    let response = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| format!("DNS lookup failed for {}: {}", host, e))?;

    Ok(response.iter().map(|ip: std::net::IpAddr| ip.to_string()).collect())
}

async fn extract_tls_info(host: &str, port: u16) -> Result<(Value, Value), String> {
    use tokio::net::TcpStream;

    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("TLS connector build error: {}", e))?;

    let connector = tokio_native_tls::TlsConnector::from(connector);

    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("TCP connect failed: {}", e))?;

    let tls_stream = connector
        .connect(host, stream)
        .await
        .map_err(|e| format!("TLS handshake failed: {}", e))?;

    let mut cert_json = Value::Null;
    let tls_json = json!({ "connected": true });

    if let Some(cert) = tls_stream.get_ref().peer_certificate()
        .map_err(|e| format!("Failed to get peer certificate: {}", e))?
    {
        let der = cert.to_der().map_err(|e| format!("DER encode error: {}", e))?;
        cert_json = parse_x509_basic(&der);
    }

    Ok((cert_json, tls_json))
}

/// Parse basic X.509 info from DER bytes without a full ASN.1 parser.
fn parse_x509_basic(der: &[u8]) -> Value {
    // We store the raw DER as base64 for downstream rules
    use std::fmt::Write;
    let mut hex = String::with_capacity(der.len() * 2);
    for b in der.iter().take(64) {
        let _ = write!(hex, "{:02x}", b);
    }
    json!({
        "der_prefix": hex,
        "der_length": der.len(),
    })
}
