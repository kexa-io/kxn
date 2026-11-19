//! Read a kubeconfig the way `kubectl` does, so `kxn kubernetes://<context>`
//! works on a workstation without extracting an API URL, a CA and a token by
//! hand.
//!
//! The result is expressed as the provider's own `K8S_*` settings (API URL,
//! CA, bearer token or client certificate), which the Kubernetes provider
//! already knows how to use. Settings given explicitly always win.

use crate::error::ProviderError;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use yaml_rust2::{Yaml, YamlLoader};

/// Credentials and endpoint of one kubeconfig context, as `K8S_*` settings.
#[derive(Debug, Default, PartialEq)]
pub struct Resolved {
    pub settings: Map<String, Value>,
    /// The context actually used (the current one when none was named).
    pub context: String,
}

/// Kubeconfig files to read: `$KUBECONFIG` (a `:`-separated list, `;` on
/// Windows) or `~/.kube/config`. Only existing files are returned.
pub fn kubeconfig_paths() -> Vec<PathBuf> {
    let sep = if cfg!(windows) { ';' } else { ':' };
    let candidates: Vec<PathBuf> = match std::env::var("KUBECONFIG") {
        Ok(v) if !v.trim().is_empty() => v.split(sep).filter(|p| !p.is_empty()).map(PathBuf::from).collect(),
        _ => dirs::home_dir().map(|h| vec![h.join(".kube").join("config")]).unwrap_or_default(),
    };
    candidates.into_iter().filter(|p| p.is_file()).collect()
}

/// One parsed kubeconfig file, with the directory its relative paths are
/// relative to.
struct Doc {
    yaml: Yaml,
    dir: PathBuf,
}

fn load_docs(paths: &[PathBuf]) -> Result<Vec<Doc>, ProviderError> {
    let mut docs = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ProviderError::InvalidConfig(format!("kubeconfig {}: {}", path.display(), e)))?;
        let mut parsed = YamlLoader::load_from_str(&text)
            .map_err(|e| ProviderError::InvalidConfig(format!("kubeconfig {}: {}", path.display(), e)))?;
        if parsed.is_empty() {
            continue;
        }
        docs.push(Doc {
            yaml: parsed.swap_remove(0),
            dir: path.parent().map(Path::to_path_buf).unwrap_or_default(),
        });
    }
    Ok(docs)
}

/// The entry named `name` in the `section` list (`contexts`, `clusters`,
/// `users`) of the first file that has it — kubectl's merge rule.
fn find_named<'a>(docs: &'a [Doc], section: &str, name: &str) -> Option<(&'a Yaml, &'a Path)> {
    docs.iter().find_map(|d| {
        d.yaml[section].as_vec()?.iter().find_map(|entry| {
            (entry["name"].as_str() == Some(name)).then_some((entry, d.dir.as_path()))
        })
    })
}

fn names(docs: &[Doc], section: &str) -> Vec<String> {
    docs.iter()
        .filter_map(|d| d.yaml[section].as_vec())
        .flatten()
        .filter_map(|e| e["name"].as_str().map(String::from))
        .collect()
}

/// A file path from the kubeconfig, made absolute against the file's directory.
fn resolve_path(dir: &Path, p: &str) -> String {
    let path = Path::new(p);
    if path.is_absolute() {
        p.to_string()
    } else {
        dir.join(path).to_string_lossy().into_owned()
    }
}

/// Resolve `context` (or the current context when `None`) from the given
/// kubeconfig files.
pub fn resolve(paths: &[PathBuf], context: Option<&str>) -> Result<Resolved, ProviderError> {
    let docs = load_docs(paths)?;
    let context_name = match context {
        Some(c) => c.to_string(),
        None => docs
            .iter()
            .find_map(|d| d.yaml["current-context"].as_str().filter(|s| !s.is_empty()))
            .map(String::from)
            .ok_or_else(|| {
                ProviderError::InvalidConfig(
                    "kubeconfig has no current-context: name one, e.g. kubernetes://my-context".into(),
                )
            })?,
    };

    let (ctx, _) = find_named(&docs, "contexts", &context_name).ok_or_else(|| {
        ProviderError::InvalidConfig(format!(
            "kubeconfig context '{}' not found (available: {})",
            context_name,
            names(&docs, "contexts").join(", ")
        ))
    })?;
    let cluster_name = ctx["context"]["cluster"].as_str().unwrap_or_default();
    let user_name = ctx["context"]["user"].as_str().unwrap_or_default();

    let (cluster, cluster_dir) = find_named(&docs, "clusters", cluster_name).ok_or_else(|| {
        ProviderError::InvalidConfig(format!(
            "kubeconfig context '{}' points at cluster '{}', which is not defined",
            context_name, cluster_name
        ))
    })?;
    let cluster = &cluster["cluster"];

    let mut s = Map::new();
    let server = cluster["server"].as_str().ok_or_else(|| {
        ProviderError::InvalidConfig(format!("kubeconfig cluster '{}' has no server", cluster_name))
    })?;
    s.insert("K8S_API_URL".into(), Value::String(server.trim_end_matches('/').to_string()));

    // The provider reads a CA given as a path, inline PEM or base64 PEM.
    if let Some(data) = cluster["certificate-authority-data"].as_str() {
        s.insert("K8S_CA_FILE".into(), Value::String(data.to_string()));
    } else if let Some(file) = cluster["certificate-authority"].as_str() {
        s.insert("K8S_CA_FILE".into(), Value::String(resolve_path(cluster_dir, file)));
    }
    if cluster["insecure-skip-tls-verify"].as_bool() == Some(true) {
        s.insert("K8S_INSECURE".into(), Value::String("true".into()));
    }

    if !user_name.is_empty() {
        if let Some((user, user_dir)) = find_named(&docs, "users", user_name) {
            user_settings(&user["user"], user_dir, &mut s)?;
        }
    }

    Ok(Resolved { settings: s, context: context_name })
}

fn user_settings(user: &Yaml, dir: &Path, s: &mut Map<String, Value>) -> Result<(), ProviderError> {
    let mut put = |k: &str, v: String| {
        s.insert(k.to_string(), Value::String(v));
    };

    // Client certificate — inline data first, then files.
    match (user["client-certificate-data"].as_str(), user["client-key-data"].as_str()) {
        (Some(c), Some(k)) => {
            put("K8S_CLIENT_CERT", c.to_string());
            put("K8S_CLIENT_KEY", k.to_string());
        }
        _ => {
            if let (Some(c), Some(k)) = (user["client-certificate"].as_str(), user["client-key"].as_str()) {
                put("K8S_CLIENT_CERT", resolve_path(dir, c));
                put("K8S_CLIENT_KEY", resolve_path(dir, k));
            }
        }
    }

    if let Some(token) = user["token"].as_str() {
        put("K8S_TOKEN", token.to_string());
    } else if let Some(file) = user["tokenFile"].as_str() {
        put("K8S_TOKEN_FILE", resolve_path(dir, file));
    }

    if !user["exec"].is_badvalue() && !user["exec"].is_null() {
        exec_credential(&user["exec"], &mut put)?;
    }
    if !user["auth-provider"].is_badvalue() && !user["auth-provider"].is_null() {
        return Err(ProviderError::InvalidConfig(
            "kubeconfig user uses a legacy auth-provider, which kxn does not run; \
             switch to the exec plugin (e.g. gke-gcloud-auth-plugin, kubelogin)"
                .into(),
        ));
    }
    Ok(())
}

/// Run an exec credential plugin (`aws eks get-token`,
/// `gke-gcloud-auth-plugin`, `kubelogin`…) and keep what it returns.
fn exec_credential(exec: &Yaml, put: &mut impl FnMut(&str, String)) -> Result<(), ProviderError> {
    let command = exec["command"].as_str().ok_or_else(|| {
        ProviderError::InvalidConfig("kubeconfig exec plugin has no command".into())
    })?;
    let mut cmd = std::process::Command::new(command);
    if let Some(args) = exec["args"].as_vec() {
        cmd.args(args.iter().filter_map(|a| a.as_str()));
    }
    if let Some(env) = exec["env"].as_vec() {
        for e in env {
            if let (Some(n), Some(v)) = (e["name"].as_str(), e["value"].as_str()) {
                cmd.env(n, v);
            }
        }
    }
    let api_version = exec["apiVersion"]
        .as_str()
        .unwrap_or("client.authentication.k8s.io/v1beta1");
    cmd.env(
        "KUBERNETES_EXEC_INFO",
        serde_json::json!({
            "apiVersion": api_version,
            "kind": "ExecCredential",
            "spec": { "interactive": false }
        })
        .to_string(),
    );

    let out = cmd.output().map_err(|e| {
        ProviderError::Connection(format!("kubeconfig exec plugin `{}`: {}", command, e))
    })?;
    if !out.status.success() {
        return Err(ProviderError::Connection(format!(
            "kubeconfig exec plugin `{}` failed: {}",
            command,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let cred: Value = serde_json::from_slice(&out.stdout).map_err(|e| {
        ProviderError::Connection(format!("kubeconfig exec plugin `{}`: invalid output: {}", command, e))
    })?;
    let status = &cred["status"];
    if let Some(token) = status["token"].as_str() {
        put("K8S_TOKEN", token.to_string());
    }
    if let (Some(c), Some(k)) = (
        status["clientCertificateData"].as_str(),
        status["clientKeyData"].as_str(),
    ) {
        put("K8S_CLIENT_CERT", c.to_string());
        put("K8S_CLIENT_KEY", k.to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KUBECONFIG: &str = r#"
apiVersion: v1
kind: Config
current-context: lab
clusters:
- name: lab-cluster
  cluster:
    server: https://10.0.0.1:6443/
    certificate-authority-data: Q0FEQVRB
- name: dev-cluster
  cluster:
    server: https://dev:6443
    certificate-authority: certs/ca.crt
    insecure-skip-tls-verify: true
users:
- name: lab-admin
  user:
    client-certificate-data: Q0VSVA==
    client-key-data: S0VZ
- name: dev-user
  user:
    token: abc123
contexts:
- name: lab
  context:
    cluster: lab-cluster
    user: lab-admin
- name: dev
  context:
    cluster: dev-cluster
    user: dev-user
"#;

    fn write(dir: &Path) -> PathBuf {
        let p = dir.join("config");
        std::fs::write(&p, KUBECONFIG).unwrap();
        p
    }

    #[test]
    fn current_context_with_client_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let r = resolve(&[write(dir.path())], None).unwrap();
        assert_eq!(r.context, "lab");
        assert_eq!(r.settings["K8S_API_URL"], "https://10.0.0.1:6443");
        assert_eq!(r.settings["K8S_CA_FILE"], "Q0FEQVRB");
        assert_eq!(r.settings["K8S_CLIENT_CERT"], "Q0VSVA==");
        assert_eq!(r.settings["K8S_CLIENT_KEY"], "S0VZ");
        assert!(!r.settings.contains_key("K8S_TOKEN"));
    }

    #[test]
    fn named_context_with_token_and_relative_ca() {
        let dir = tempfile::tempdir().unwrap();
        let r = resolve(&[write(dir.path())], Some("dev")).unwrap();
        assert_eq!(r.settings["K8S_API_URL"], "https://dev:6443");
        assert_eq!(r.settings["K8S_TOKEN"], "abc123");
        assert_eq!(r.settings["K8S_INSECURE"], "true");
        assert_eq!(
            r.settings["K8S_CA_FILE"],
            dir.path().join("certs/ca.crt").to_string_lossy().as_ref()
        );
    }

    #[test]
    fn unknown_context_lists_the_available_ones() {
        let dir = tempfile::tempdir().unwrap();
        let err = resolve(&[write(dir.path())], Some("prod")).unwrap_err().to_string();
        assert!(err.contains("'prod' not found"), "{err}");
        assert!(err.contains("lab, dev"), "{err}");
    }
}
