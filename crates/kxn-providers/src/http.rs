/// Shared HTTP client for all provider operations (connection pooling + TLS reuse).
pub fn shared_client() -> &'static reqwest::Client {
    use std::sync::LazyLock;
    static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(5)
            .build()
            .expect("Failed to build HTTP client")
    });
    &CLIENT
}

#[cfg(test)]
mod client_timeout_tests {
    /// Every HTTP client in the workspace must carry a timeout.
    ///
    /// A bare reqwest client has no timeout: a server that accepts the connection
    /// and never answers holds the scan open forever, and `watch` then stops
    /// scanning everything else too. Four of them had crept in — two in the
    /// Terraform registry, one reading Vault secrets, and one as the *fallback*
    /// inside the alert client's builder, which silently downgraded every alert
    /// and save backend the moment the builder failed.
    ///
    /// reqwest does not expose a client's timeout, so the invariant is checked
    /// where it is written rather than where it is used.
    #[test]
    fn no_client_is_built_without_a_timeout() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("workspace root");

        let mut offenders = Vec::new();
        let mut stack = vec![root.join("crates")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("read file");
                for (n, line) in text.lines().enumerate() {
                    let code = line.trim();
                    if code.starts_with("//") || code.starts_with("///") {
                        continue;
                    }
                    // Split so this test does not match its own source.
                    if code.contains(concat!("Client", "::new()")) {
                        offenders.push(format!("{}:{}", path.display(), n + 1));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "an HTTP client is built without a timeout:\n  {}\nUse `crate::http::shared_client()`.",
            offenders.join("\n  ")
        );
    }
}
