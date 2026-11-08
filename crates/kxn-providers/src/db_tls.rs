//! How a database connection is encrypted, expressed once for every database
//! provider.
//!
//! Until this existed, `postgresql://` and `mysql://` connected in cleartext
//! with no way to ask for anything else: a compliance scanner pointed at a
//! production database sent its credentials, and every row it read back, over
//! an unencrypted socket.
//!
//! The vocabulary is libpq's, because operators already know it and because the
//! PostgreSQL and MySQL drivers both express less than it on their own:
//!
//! | mode          | encrypted | certificate chain | hostname |
//! |---------------|-----------|-------------------|----------|
//! | `disable`     | no        | —                 | —        |
//! | `prefer`      | if offered| not checked       | not checked |
//! | `require`     | yes       | not checked       | not checked |
//! | `verify-ca`   | yes       | checked           | not checked |
//! | `verify-full` | yes       | checked           | checked  |
//!
//! `prefer` is the default, as in libpq: it encrypts whenever the server
//! offers TLS and never breaks a connection that would have worked before.
//! It authenticates nothing, so it stops a passive listener and not an active
//! one — `verify-full` is the only mode that does both, and it is what a
//! production target deserves.

use crate::config::get_config_or_env;
use crate::error::ProviderError;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbSslMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl DbSslMode {
    /// Is TLS mandatory, i.e. must the connection fail rather than fall back?
    pub fn is_required(self) -> bool {
        !matches!(self, DbSslMode::Disable | DbSslMode::Prefer)
    }

    /// Must the server's certificate chain to a trusted root?
    pub fn verifies_certificate(self) -> bool {
        matches!(self, DbSslMode::VerifyCa | DbSslMode::VerifyFull)
    }

    /// Must the certificate match the host we asked for?
    pub fn verifies_hostname(self) -> bool {
        matches!(self, DbSslMode::VerifyFull)
    }
}

/// Read `<PREFIX>_SSLMODE` from the provider config or the environment.
///
/// An unknown value is refused rather than silently downgraded: a typo in
/// `verify-full` must not turn into "no encryption at all".
pub fn ssl_mode(config: &Value, prefix: &str) -> Result<DbSslMode, ProviderError> {
    let raw = match get_config_or_env(config, "SSLMODE", Some(prefix)) {
        Some(v) => v,
        None => return Ok(DbSslMode::Prefer),
    };
    parse_ssl_mode(&raw)
}

pub fn parse_ssl_mode(raw: &str) -> Result<DbSslMode, ProviderError> {
    match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "disable" | "disabled" | "off" => Ok(DbSslMode::Disable),
        "prefer" | "" => Ok(DbSslMode::Prefer),
        "require" | "required" | "on" => Ok(DbSslMode::Require),
        "verify-ca" => Ok(DbSslMode::VerifyCa),
        "verify-full" => Ok(DbSslMode::VerifyFull),
        other => Err(ProviderError::InvalidConfig(format!(
            "unknown sslmode '{other}'; expected disable, prefer, require, verify-ca or verify-full"
        ))),
    }
}

/// Path to a PEM root certificate, from `<PREFIX>_SSLROOTCERT`.
pub fn ssl_root_cert(config: &Value, prefix: &str) -> Option<String> {
    get_config_or_env(config, "SSLROOTCERT", Some(prefix)).filter(|p| !p.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default must be the one that encrypts, and it must be the one that
    /// cannot break a connection that worked before.
    #[test]
    fn the_default_prefers_tls_without_requiring_it() {
        let mode = ssl_mode(&serde_json::json!({}), "PG").expect("default");
        assert_eq!(mode, DbSslMode::Prefer);
        assert!(!mode.is_required());
        assert!(!mode.verifies_certificate());
    }

    #[test]
    fn each_mode_says_what_it_checks() {
        assert!(!DbSslMode::Disable.is_required());
        assert!(DbSslMode::Require.is_required());
        assert!(!DbSslMode::Require.verifies_certificate());
        assert!(DbSslMode::VerifyCa.verifies_certificate());
        assert!(!DbSslMode::VerifyCa.verifies_hostname());
        assert!(DbSslMode::VerifyFull.verifies_hostname());
    }

    #[test]
    fn spelling_is_forgiving_but_a_typo_is_refused() {
        assert_eq!(parse_ssl_mode("VERIFY_FULL").expect("ok"), DbSslMode::VerifyFull);
        assert_eq!(parse_ssl_mode(" require ").expect("ok"), DbSslMode::Require);
        // A typo must never resolve to the least secure mode.
        assert!(parse_ssl_mode("verify-fulll").is_err());
        assert!(parse_ssl_mode("yes").is_err());
    }

    #[test]
    fn the_mode_is_read_from_the_provider_config() {
        let cfg = serde_json::json!({ "SSLMODE": "verify-full" });
        assert_eq!(ssl_mode(&cfg, "PG").expect("ok"), DbSslMode::VerifyFull);
    }
}
