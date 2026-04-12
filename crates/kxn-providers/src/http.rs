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
