use crate::error::ProviderError;
use crate::native::native_provider_names;
use serde_json::Value;

/// Resolve a config value: JSON config > env `PREFIX_KEY` > env `KEY`.
pub fn get_config_or_env(config: &Value, key: &str, prefix: Option<&str>) -> Option<String> {
    // 1. JSON config (case-insensitive key lookup)
    if let Value::Object(map) = config {
        let key_upper = key.to_uppercase();
        let key_lower = key.to_lowercase();
        for (k, v) in map {
            if k == key || k.to_uppercase() == key_upper || k.to_lowercase() == key_lower {
                return match v {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    Value::Bool(b) => Some(b.to_string()),
                    _ => Some(v.to_string()),
                };
            }
        }
    }

    // 2. Env PREFIX_KEY
    if let Some(pfx) = prefix {
        let env_key = format!("{}_{}", pfx, key.to_uppercase());
        if let Ok(val) = std::env::var(&env_key) {
            return Some(val);
        }
    }

    // 3. Env KEY
    if let Ok(val) = std::env::var(key.to_uppercase()) {
        return Some(val);
    }

    None
}

/// Like `get_config_or_env` but returns an error if the key is missing.
pub fn require_config(
    config: &Value,
    key: &str,
    prefix: Option<&str>,
) -> Result<String, ProviderError> {
    get_config_or_env(config, key, prefix).ok_or_else(|| {
        let sources = if let Some(pfx) = prefix {
            format!(
                "config[\"{}\"], env ${}_{}, or env ${}",
                key,
                pfx,
                key.to_uppercase(),
                key.to_uppercase()
            )
        } else {
            format!("config[\"{}\"] or env ${}", key, key.to_uppercase())
        };
        ProviderError::InvalidConfig(format!("Missing required config: {}", sources))
    })
}

/// Resolve a configured target to the provider that scans it and the config
/// that provider expects.
///
/// Both documented target forms are accepted, and they compose:
///
/// - `uri = "postgresql://user:pass@host/db"` — provider and connection
///   settings come from the scheme (the form used by `kxn.toml.example` and
///   docs/configuration.md);
/// - `provider = "cve"` + `[targets.config]` — for providers with no
///   connection URI.
///
/// `extra` (the `[targets.config]` table) overlays whatever the URI supplied,
/// so a URI can be completed key by key. An explicit `provider` that disagrees
/// with the URI scheme wins, with a warning; the scheme still supplies config.
///
/// Callers must interpolate `${secret:...}` placeholders before calling.
pub fn resolve_target(
    uri: Option<&str>,
    provider: Option<&str>,
    extra: Value,
) -> Result<(String, Value), ProviderError> {
    let from_uri = match uri {
        Some(u) => Some(parse_target_uri(u)?),
        None => None,
    };

    let (name, mut config) = match (provider, from_uri) {
        (Some(explicit), Some((uri_provider, uri_config))) => {
            if explicit != uri_provider {
                tracing::warn!(
                    explicit = %explicit, from_uri = %uri_provider,
                    "target declares a provider that disagrees with its URI scheme; using the explicit one"
                );
            }
            (explicit.to_string(), uri_config)
        }
        (Some(explicit), None) => (explicit.to_string(), Value::Object(Default::default())),
        (None, Some((uri_provider, uri_config))) => (uri_provider, uri_config),
        (None, None) => {
            return Err(ProviderError::InvalidConfig(
                "target has neither `uri` nor `provider`".to_string(),
            ))
        }
    };

    if let Value::Object(extra) = extra {
        if !config.is_object() {
            config = Value::Object(Default::default());
        }
        let map = config.as_object_mut().expect("config is an object");
        for (k, v) in extra {
            map.insert(k, v);
        }
    }

    Ok((name, config))
}

/// Copy a database URI's query parameters into the provider config.
///
/// libpq-style URIs carry the TLS settings there, and they were dropped on the
/// floor: `postgresql://…?sslmode=require` connected exactly like one without
/// it, so an operator who had asked for encryption got none and was told
/// nothing. A parameter this code does not understand is refused rather than
/// ignored, for the same reason.
fn db_query_params(parsed: &url::Url, config: &mut Value) -> Result<(), ProviderError> {
    for (key, value) in parsed.query_pairs() {
        let suffix = match key.as_ref() {
            "sslmode" | "ssl_mode" => "SSLMODE",
            "sslrootcert" | "ssl_root_cert" | "sslca" => "SSLROOTCERT",
            "dbname" | "database" => "DATABASE",
            other => {
                return Err(ProviderError::InvalidConfig(format!(
                    "unknown URI parameter '{other}'; supported: sslmode, sslrootcert, dbname"
                )))
            }
        };
        // Unprefixed: `get_config_or_env` looks the key up literally in the
        // config and only prefixes when falling back to the environment, so
        // `PG_SSLMODE` in the JSON would never be read.
        config[suffix] = Value::String(value.to_string());
    }
    Ok(())
}

/// Every scheme `parse_target_uri` understands.
///
/// The CLI decides whether a bare first argument is a target or a subcommand by
/// looking for one of these, and it used to keep its own shorter copy: the
/// parser accepted `prometheus://`, `local://`, `msgraph://` and `k8s://` while
/// the dispatcher answered "unrecognized subcommand" for all four. One list,
/// read by both, and a test that keeps it in step with the match below.
pub const URI_SCHEMES: &[&str] = &[
    "aws",
    "cassandra",
    "postgresql",
    "postgres",
    "mysql",
    "mongodb",
    "mongodb+srv",
    "ssh",
    "local",
    "oracle",
    "http",
    "https",
    "grpc",
    "cve",
    "azure",
    "azurerm",
    "msgraph",
    "microsoft.graph",
    "m365",
    "microsoft365",
    "o365",
    "gcp",
    "google",
    "prometheus",
    "prom",
    "helm",
    "kubernetes",
    "k8s",
    "github",
    "docker",
    "forgejo",
    "googleworkspace",
    "gitlab",
];

/// Parse a target URI into (provider_name, config JSON).
///
/// Supported schemes: postgresql, mysql, mongodb, ssh, local, oracle, http, https, grpc
pub fn parse_target_uri(uri: &str) -> Result<(String, Value), ProviderError> {
    // `local://` has no host and url::Url::parse rejects it — short-circuit.
    if uri == "local://" || uri.starts_with("local://") {
        return Ok(("local".to_string(), serde_json::json!({})));
    }

    // kubernetes:// or k8s:// — handled before URL parsing: the part after
    // `://` names a kubeconfig context, and context names are not host names
    // (EKS uses `arn:aws:eks:…`, which url::Url rejects as a bad port).
    // Nothing means the current context, `in-cluster` the pod's
    // ServiceAccount. Optional query params override defaults:
    //   kubernetes://in-cluster?namespace=foo&insecure=true
    let kube = [("kubernetes://", "kubernetes"), ("k8s://", "kubernetes"), ("helm://", "helm")]
        .into_iter()
        .find_map(|(prefix, provider)| uri.strip_prefix(prefix).map(|rest| (rest, provider)));
    if let Some((rest, provider)) = kube {
        let mut config = serde_json::json!({});
        let (context, namespace, pod) = kube_target_from_uri(uri);
        if let Some(context) = context {
            config["K8S_CONTEXT"] = Value::String(context);
        }
        if let Some(namespace) = namespace {
            config["K8S_NAMESPACE"] = Value::String(namespace);
        }
        if let Some(pod) = pod {
            config["K8S_POD"] = Value::String(pod);
        }
        if let Some((_, query)) = rest.split_once('?') {
            for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                let upper = match key.as_ref() {
                    "namespace" | "ns" => "K8S_NAMESPACE".to_string(),
                    "insecure" => "K8S_INSECURE".to_string(),
                    "api_url" => "K8S_API_URL".to_string(),
                    "token" => "K8S_TOKEN".to_string(),
                    "ca_file" => "K8S_CA_FILE".to_string(),
                    "token_file" => "K8S_TOKEN_FILE".to_string(),
                    other => format!("K8S_{}", other.to_uppercase()),
                };
                config[upper] = Value::String(value.to_string());
            }
        }
        return Ok((provider.to_string(), config));
    }

    // Providers whose target is a name rather than a host:port.
    //   github://<org>                     token: GITHUB_TOKEN, else `gh auth token`
    //   docker://                          the local Docker socket (?socket=… to change)
    //   forgejo://<host>[/<owner>/<repo>]  token: FORGEJO_TOKEN; https unless ?insecure
    //   googleworkspace://<domain>         credentials: ADC or ?credentials_file=…
    //   gitlab://<host>                    token: GITLAB_TOKEN; https unless ?insecure=true
    for (prefix, provider) in [
        ("github://", "github"),
        ("docker://", "docker"),
        ("forgejo://", "forgejo"),
        ("googleworkspace://", "googleworkspace"),
        ("gitlab://", "gitlab"),
    ] {
        let Some(rest) = uri.strip_prefix(prefix) else { continue };
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let path = path.trim_end_matches('/');
        let (head, tail) = path.split_once('/').unwrap_or((path, ""));
        let mut config = serde_json::json!({});
        match provider {
            "github" if !head.is_empty() => config["GITHUB_ORG"] = Value::String(head.to_string()),
            "forgejo" if !head.is_empty() => {
                config["URL"] = Value::String(format!("https://{head}"));
                if !tail.is_empty() {
                    config["REPOS"] = Value::String(tail.to_string());
                }
            }
            "googleworkspace" if !head.is_empty() => config["DOMAIN"] = Value::String(head.to_string()),
            "gitlab" if !head.is_empty() => config["URL"] = Value::String(format!("https://{head}")),
            _ => {}
        }
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            let key = match (provider, k.as_ref()) {
                ("docker", "socket") => "DOCKER_SOCKET".to_string(),
                _ => k.to_uppercase(),
            };
            config[key] = Value::String(v.to_string());
        }
        return Ok((provider.to_string(), config));
    }

    let parsed = url::Url::parse(uri)
        .map_err(|e| ProviderError::InvalidConfig(format!("Invalid URI: {}", e)))?;
    let scheme = parsed.scheme().to_lowercase();

    let (provider, config) = match scheme.as_str() {
        "postgresql" | "postgres" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(5432);
            let user = parsed.username();
            let password = parsed.password().unwrap_or("");
            if user.is_empty() {
                return Err(ProviderError::InvalidConfig(
                    "PostgreSQL URI must include a user".into(),
                ));
            }
            let mut config = serde_json::json!({
                "PG_HOST": host,
                "PG_PORT": port.to_string(),
                "PG_USER": user,
                "PG_PASSWORD": password,
            });
            // The path names the database, as in every libpq URI.
            let dbname = parsed.path().trim_start_matches('/');
            if !dbname.is_empty() {
                config["DATABASE"] = Value::String(dbname.to_string());
            }
            db_query_params(&parsed, &mut config)?;
            ("postgresql".to_string(), config)
        }
        "mysql" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(3306);
            let user = parsed.username();
            let password = parsed.password().unwrap_or("");
            if user.is_empty() {
                return Err(ProviderError::InvalidConfig(
                    "MySQL URI must include a user".into(),
                ));
            }
            let mut config = serde_json::json!({
                "MYSQL_HOST": host,
                "MYSQL_PORT": port.to_string(),
                "MYSQL_USER": user,
                "MYSQL_PASSWORD": password,
            });
            let dbname = parsed.path().trim_start_matches('/');
            if !dbname.is_empty() {
                config["DATABASE"] = Value::String(dbname.to_string());
            }
            db_query_params(&parsed, &mut config)?;
            ("mysql".to_string(), config)
        }
        "cassandra" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(9042);
            let user = urlencoding::decode(parsed.username()).map(|c| c.into_owned()).unwrap_or_default();
            let password = parsed
                .password()
                .map(|p| urlencoding::decode(p).map(|c| c.into_owned()).unwrap_or_default())
                .unwrap_or_default();
            let mut config = serde_json::json!({
                "CASSANDRA_HOST": host,
                "CASSANDRA_PORT": port.to_string(),
            });
            // Credentials left out of the URI come from CASSANDRA_USER and
            // CASSANDRA_PASSWORD; an empty value here would hide them.
            if !user.is_empty() {
                config["CASSANDRA_USER"] = Value::String(user);
            }
            if !password.is_empty() {
                config["CASSANDRA_PASSWORD"] = Value::String(password);
            }
            ("cassandra".to_string(), config)
        }
        "mongodb" | "mongodb+srv" => (
            "mongodb".to_string(),
            serde_json::json!({ "MONGODB_URI": uri }),
        ),
        "ssh" => {
            let host = parsed.host_str().unwrap_or("");
            if host.is_empty() {
                return Err(ProviderError::InvalidConfig(
                    "SSH URI must include a host (e.g. ssh://root@myserver)".into(),
                ));
            }
            let port = parsed.port().unwrap_or(22);
            let user = if parsed.username().is_empty() {
                "root"
            } else {
                parsed.username()
            };
            let password = parsed.password().unwrap_or("");
            let mut config = serde_json::json!({
                "SSH_HOST": host,
                "SSH_PORT": port.to_string(),
                "SSH_USER": user,
            });
            // ssh://admin@fw01?os=fortios — a network device; unset: detected.
            for (key, value) in parsed.query_pairs() {
                if key == "os" {
                    config["SSH_OS"] = Value::String(value.to_string());
                }
            }
            if !password.is_empty() {
                config["SSH_PASSWORD"] = Value::String(password.to_string());
            } else if let Ok(p) = std::env::var("SSH_PASSWORD") {
                config["SSH_PASSWORD"] = Value::String(p);
            } else if let Ok(k) = std::env::var("SSH_KEY_PATH") {
                config["SSH_KEY_PATH"] = Value::String(k);
            } else if let Some(home) = dirs::home_dir() {
                for name in &["id_ed25519", "id_rsa", "id_ecdsa"] {
                    let path = home.join(".ssh").join(name);
                    if path.exists() {
                        config["SSH_KEY_PATH"] =
                            Value::String(path.to_string_lossy().to_string());
                        break;
                    }
                }
            }
            ("ssh".to_string(), config)
        }
        "oracle" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(1521);
            let user = parsed.username();
            let password = parsed.password().unwrap_or("");
            let service = parsed.path().trim_start_matches('/');
            if user.is_empty() {
                return Err(ProviderError::InvalidConfig(
                    "Oracle URI must include a user".into(),
                ));
            }
            (
                "oracle".to_string(),
                serde_json::json!({
                    "ORACLE_HOST": host,
                    "ORACLE_PORT": port.to_string(),
                    "ORACLE_USER": user,
                    "ORACLE_PASSWORD": password,
                    "ORACLE_SERVICE_NAME": if service.is_empty() { "XEPDB1" } else { service },
                }),
            )
        }
        "http" | "https" => (
            "http".to_string(),
            serde_json::json!({ "URL": uri }),
        ),
        "grpc" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().unwrap_or(443);
            // The provider asks for `ENDPOINT`; this used to hand it
            // `GRPC_HOST` and `GRPC_PORT`, two names it never reads, so every
            // `grpc://` target was refused as having no endpoint configured.
            (
                "grpc".to_string(),
                serde_json::json!({
                    // With a scheme: the provider's transport needs one, and a
                    // bare `host:port` fails with "transport error".
                    "ENDPOINT": format!("{}://{}:{}", if port == 443 { "https" } else { "http" }, host, port),
                    "GRPC_HOST": host,
                    "GRPC_PORT": port.to_string(),
                    // 443 is the conventional TLS port; anything else is
                    // plaintext unless the caller says otherwise.
                    "TLS": (port == 443).to_string(),
                }),
            )
        }
        "cve" => {
            // cve://nvd — defaults to NVD + KEV + EPSS public feeds
            // cve://nvd?keywords=openssh,nginx&severity=critical&days=7
            let mut config = serde_json::json!({});
            // Parse query params as config
            for (key, value) in parsed.query_pairs() {
                config[key.to_uppercase().to_string()] =
                    Value::String(value.to_string());
            }
            // Host part as a hint (ignored, feeds are configured via env/config)
            ("cve".to_string(), config)
        }
        // azure://<subscription-id> or azure:// — Azure Resource Manager.
        // With no host the first subscription the credentials can see is used.
        "azure" | "azurerm" => {
            let mut config = serde_json::json!({});
            if let Some(sub) = parsed.host_str() {
                if !sub.is_empty() {
                    config["SUBSCRIPTION_ID"] = Value::String(sub.to_string());
                }
            }
            for (key, value) in parsed.query_pairs() {
                let upper = match key.as_ref() {
                    "subscription" | "subscription_id" => "SUBSCRIPTION_ID".to_string(),
                    "concurrency" => "CONCURRENCY".to_string(),
                    other => format!("AZURE_{}", other.to_uppercase()),
                };
                config[upper] = Value::String(value.to_string());
            }
            ("azure".to_string(), config)
        }
        // m365://[tenant-id] — Microsoft 365 (Graph, Exchange Online, Teams);
        // credentials from AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET.
        "m365" | "microsoft365" | "o365" => {
            let mut config = serde_json::json!({});
            if let Some(tenant) = parsed.host_str().filter(|h| !h.is_empty()) {
                config["TENANT_ID"] = Value::String(tenant.to_string());
            }
            ("m365".to_string(), config)
        }
        // msgraph:// — Microsoft Graph API provider (uses AZURE_* env vars)
        "msgraph" | "microsoft.graph" => {
            ("microsoft.graph".to_string(), serde_json::json!({}))
        }
        // gcp:// — GCP IAM provider; host is the project ID (gcp://my-project)
        // `aws://eu-west-3` — the region is the host, because a scan pointed at
        // the wrong region reports zero findings for the one that mattered and
        // the provider refuses to guess it.
        "aws" => {
            let region = parsed.host_str().unwrap_or_default();
            if region.is_empty() {
                return Err(ProviderError::InvalidConfig(
                    "AWS URI must name a region (e.g. aws://eu-west-3)".into(),
                ));
            }
            let mut config = serde_json::json!({ "REGION": region });
            for (key, value) in parsed.query_pairs() {
                let upper = match key.as_ref() {
                    "concurrency" => "CONCURRENCY".to_string(),
                    other => other.to_uppercase(),
                };
                config[upper] = Value::String(value.to_string());
            }
            ("aws".to_string(), config)
        }
        "gcp" | "google" => {
            let project = parsed.host_str().unwrap_or("").to_string();
            if project.is_empty() {
                return Err(ProviderError::InvalidConfig(
                    "GCP URI must include a project ID (e.g. gcp://my-project-id)".into(),
                ));
            }
            let mut config = serde_json::json!({ "PROJECT": project });
            // Forward optional query params (e.g. gcp://project?key_max_age_days=30)
            for (key, value) in parsed.query_pairs() {
                config[key.to_uppercase().to_string()] = Value::String(value.to_string());
            }
            ("gcp".to_string(), config)
        }
        // prometheus:// — scrape any Prometheus exposition endpoint.
        // The URL is reconstructed (scheme stripped, http:// added) so
        // both `prometheus://host:9100/metrics` and
        // `prometheus://host:9100/metrics?include_prefixes=traefik_,go_`
        // work. Optional query params map to the provider's config keys —
        // bare names, which is what it reads from the JSON config; the
        // `PROM_` prefix only applies to environment variables. With
        // `PROM_URL` here, every `prometheus://` target failed with
        // "Prometheus URL not set".
        "prometheus" | "prom" => {
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed.port().map(|p| format!(":{}", p)).unwrap_or_default();
            let path = if parsed.path().is_empty() { "/metrics" } else { parsed.path() };
            let mut config = serde_json::json!({
                "URL": format!("http://{}{}{}", host, port, path),
            });
            for (key, value) in parsed.query_pairs() {
                config[key.to_uppercase()] = Value::String(value.to_string());
            }
            ("prometheus".to_string(), config)
        }
        // helm:// — Helm releases, read from the cluster's own state. Takes the
        // same options as kubernetes:// since that is where Helm keeps them.
        _ => {
            return Err(ProviderError::InvalidConfig(format!(
                "Unsupported URI scheme '{}'. Supported: {}",
                scheme,
                URI_SCHEMES.join(", ")
            )));
        }
    };

    let native = native_provider_names();
    if !native.contains(&provider.as_str()) {
        return Err(ProviderError::NotFound(format!(
            "Provider '{}' is not available",
            provider
        )));
    }

    Ok((provider, config))
}

/// `kubernetes://<context>[/<namespace>[/<pod>]]`, from the raw URI:
/// context names are not host names — EKS uses `arn:aws:eks:…:cluster/<name>`
/// (one `/` of its own), others carry capitals or `@`, which URL host parsing
/// would mangle or lowercase.
fn kube_target_from_uri(uri: &str) -> (Option<String>, Option<String>, Option<String>) {
    let Some((_, rest)) = uri.split_once("://") else { return (None, None, None) };
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    let path = rest[..end].trim_end_matches('/');
    let parts: Vec<&str> = path.split('/').collect();
    let ctx_len = if path.starts_with("arn:") { 2.min(parts.len()) } else { 1 };
    let some = |s: String| (!s.is_empty()).then_some(s);
    let context = some(parts[..ctx_len].join("/"));
    let namespace = parts.get(ctx_len).map(|s| s.to_string()).and_then(some);
    let pod = parts.get(ctx_len + 1).map(|s| s.to_string()).and_then(some);
    (context, namespace, pod)
}

#[cfg(test)]
mod uri_scheme_tests {
    use super::*;

    #[test]
    fn kubernetes_uri_names_a_kubeconfig_context() {
        let ctx = |u: &str| parse_target_uri(u).unwrap().1.get("K8S_CONTEXT").and_then(|v| v.as_str()).map(String::from);
        assert_eq!(ctx("k8s://homelab").as_deref(), Some("homelab"));
        assert_eq!(ctx("kubernetes://Prod-EU?namespace=x").as_deref(), Some("Prod-EU"));
        assert_eq!(
            ctx("k8s://arn:aws:eks:eu-west-1:123:cluster/prod").as_deref(),
            Some("arn:aws:eks:eu-west-1:123:cluster/prod")
        );
        assert_eq!(ctx("kubernetes://"), None);
        let cfg = |u: &str, k: &str| parse_target_uri(u).unwrap().1.get(k).and_then(|v| v.as_str()).map(String::from);
        assert_eq!(cfg("k8s://homelab/monitoring/kxn", "K8S_CONTEXT").as_deref(), Some("homelab"));
        assert_eq!(cfg("k8s://homelab/monitoring/kxn", "K8S_NAMESPACE").as_deref(), Some("monitoring"));
        assert_eq!(cfg("k8s://homelab/monitoring/kxn", "K8S_POD").as_deref(), Some("kxn"));
        assert_eq!(cfg("k8s://homelab/monitoring", "K8S_POD"), None);
        let arn = "k8s://arn:aws:eks:eu-west-1:123:cluster/prod/default/api";
        assert_eq!(cfg(arn, "K8S_CONTEXT").as_deref(), Some("arn:aws:eks:eu-west-1:123:cluster/prod"));
        assert_eq!(cfg(arn, "K8S_NAMESPACE").as_deref(), Some("default"));
        assert_eq!(cfg(arn, "K8S_POD").as_deref(), Some("api"));
    }

    /// The URI must produce the keys the provider reads, or the target can
    /// never be built.
    #[test]
    fn prometheus_uri_yields_a_buildable_provider() {
        let (provider, config) =
            parse_target_uri("prometheus://node:9100/metrics?include_prefixes=go_").unwrap();
        assert_eq!(provider, "prometheus");
        assert_eq!(config["URL"], "http://node:9100/metrics");
        assert_eq!(config["INCLUDE_PREFIXES"], "go_");
        assert!(crate::create_native_provider("prometheus", config).is_ok());
    }

    /// The dispatcher and the parser must agree: a scheme listed in
    /// `URI_SCHEMES` has to reach a real branch of the match, and a scheme that
    /// is not listed has to be refused. Without this the two lists drift, which
    /// is how `prometheus://` became unreachable from the command line while
    /// the parser handled it.
    #[test]
    fn name_targets_map_to_their_provider_settings() {
        let (p, c) = parse_target_uri("github://kexa-io").unwrap();
        assert_eq!((p.as_str(), c["GITHUB_ORG"].as_str()), ("github", Some("kexa-io")));
        let (p, c) = parse_target_uri("forgejo://git.example.com/acme/api").unwrap();
        assert_eq!(p, "forgejo");
        assert_eq!(c["URL"], "https://git.example.com");
        assert_eq!(c["REPOS"], "acme/api");
        let (p, c) = parse_target_uri("docker://?socket=/run/podman/podman.sock").unwrap();
        assert_eq!((p.as_str(), c["DOCKER_SOCKET"].as_str()), ("docker", Some("/run/podman/podman.sock")));
        let (p, c) = parse_target_uri("m365://").unwrap();
        assert_eq!((p.as_str(), c.get("TENANT_ID")), ("m365", None));
        let (p, c) = parse_target_uri("o365://e17d1063-88c2-4368-9d08-203b84a1bb40").unwrap();
        assert_eq!((p.as_str(), c["TENANT_ID"].as_str()), ("m365", Some("e17d1063-88c2-4368-9d08-203b84a1bb40")));
        let (p, c) = parse_target_uri("googleworkspace://example.com").unwrap();
        assert_eq!((p.as_str(), c["DOMAIN"].as_str()), ("googleworkspace", Some("example.com")));
        let (p, c) = parse_target_uri("gitlab://gitlab.example.com?insecure=true").unwrap();
        assert_eq!((p.as_str(), c["URL"].as_str()), ("gitlab", Some("https://gitlab.example.com")));
        assert_eq!(c["INSECURE"], "true");
    }

    #[test]
    fn every_listed_scheme_is_parsed() {
        for scheme in URI_SCHEMES {
            let uri = format!("{scheme}://host");
            if let Err(e) = parse_target_uri(&uri) {
                let msg = e.to_string();
                assert!(
                    !msg.contains("Unsupported URI scheme"),
                    "{scheme} is advertised but not parsed: {msg}"
                );
            }
        }
    }

    #[test]
    fn an_unlisted_scheme_is_refused() {
        let err = parse_target_uri("ftp://host").expect_err("ftp is not a target");
        assert!(err.to_string().contains("Unsupported URI scheme"));
    }
}
