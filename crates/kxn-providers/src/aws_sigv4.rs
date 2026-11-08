//! One AWS Signature Version 4 signer for the whole workspace.
//!
//! Three hand-rolled copies of SigV4 existed before this module
//! (`kxn-cli/src/save/cloud_storage.rs` for s3, `kxn-cli/src/save/sns.rs` for
//! sns, `kxn-providers/src/secrets/aws_secrets.rs` for secretsmanager). They
//! diverged, and two of the divergences are outright bugs that this module is
//! shaped to make unrepresentable:
//!
//! 1. **The signed host was a literal.** `sns.rs` signs
//!    `host:sns.amazonaws.com` while sending `Host: sns.<region>.amazonaws.com`.
//!    A canonical request that disagrees with the wire request can never
//!    validate, so every SNS publish returns 403 SignatureDoesNotMatch. Here
//!    the host is a required field of [`SigningRequest`], and the signer puts
//!    the *same* string into the canonical headers and into the returned header
//!    map — the caller sets the headers it is handed, so the two cannot drift.
//!    [`host_from_url`] closes the loop by deriving that string from the URL
//!    the caller is about to hit.
//!
//! 2. **`AWS_SESSION_TOKEN` was ignored.** None of the three copies read it, so
//!    S3, SNS and Secrets Manager were unusable under IRSA, AssumeRole or SSO —
//!    i.e. under the default production setup on Kubernetes, where the static
//!    key pair does not exist at all. Temporary credentials are rejected unless
//!    the token travels in `x-amz-security-token` *and* that header is part of
//!    SignedHeaders. [`Credentials::session_token`] makes it a first-class field
//!    and the signer wires it into both places.
//!
//! A third, quieter hazard: all three copies wrote `SignedHeaders` by hand as a
//! literal string, which is only correct as long as someone keeps the list
//! alphabetically sorted by hand. Canonical headers live in a [`BTreeMap`] here,
//! so the sort order of the canonical block and of `SignedHeaders` come from the
//! same iteration and cannot disagree.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

/// SHA-256 of the empty body — the payload hash for every GET/DELETE and for
/// any request without a body.
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

#[derive(Debug, Clone, thiserror::Error)]
pub enum SigV4Error {
    #[error("{0} is not set")]
    MissingEnv(&'static str),
    #[error("cannot derive a Host header from {0}")]
    InvalidUrl(String),
    #[error("{0}")]
    NoCredentials(String),
}

/// AWS credentials, static or temporary.
#[derive(Clone)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
    /// Present for every credential source that is not a long-lived IAM user
    /// key: IRSA / EKS Pod Identity, `sts:AssumeRole`, SSO, EC2 instance roles.
    /// Absent means "static key pair"; it does not mean "no token needed".
    pub session_token: Option<String>,
}

/// Credentials exported by the AWS CLI, and when to ask again.
static CREDENTIAL_CACHE: std::sync::LazyLock<
    std::sync::Mutex<Option<(Credentials, std::time::Instant)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

impl Credentials {
    pub fn new(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        session_token: Option<String>,
    ) -> Self {
        Self {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            // An empty AWS_SESSION_TOKEN is what an unset variable looks like
            // after most shell/entrypoint templating; signing an empty token
            // would fail with a confusing InvalidClientTokenId.
            session_token: session_token.filter(|t| !t.trim().is_empty()),
        }
    }

    /// Read the standard AWS environment variables.
    ///
    /// Deliberately env-only: the whole point of this module is that the three
    /// existing call sites already read these two variables and simply forgot
    /// the third. Profile files and the IMDS/container credential endpoints are
    /// a separate concern (see the module docs of the AWS collector).
    /// Credentials from the environment, falling back to the AWS CLI.
    ///
    /// Shelling out to `aws configure export-credentials` is deliberate, and it
    /// is the same choice made for Azure (`az account get-access-token`) and
    /// GCP (`gcloud`): it covers *every* credential source the CLI supports —
    /// `~/.aws/credentials` profiles, SSO, `aws login`, IMDS, a
    /// `credential_process` — without reimplementing any of them. Reading only
    /// the environment meant an operator who had authenticated the ordinary way
    /// was told there were no credentials at all.
    ///
    /// The result is cached: this is called once per signed request, and
    /// spawning a process per request would dominate the scan.
    pub fn resolve() -> Result<Self, SigV4Error> {
        if let Ok(from_env) = Self::from_env() {
            return Ok(from_env);
        }

        let mut cache = CREDENTIAL_CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((creds, good_until)) = cache.as_ref() {
            if std::time::Instant::now() < *good_until {
                return Ok(creds.clone());
            }
        }

        let (creds, good_until) = Self::from_aws_cli()?;
        *cache = Some((creds.clone(), good_until));
        Ok(creds)
    }

    /// `aws configure export-credentials --format process`, and the instant after
    /// which the answer must be asked for again.
    fn from_aws_cli() -> Result<(Self, std::time::Instant), SigV4Error> {
        let output = std::process::Command::new("aws")
            .args(["configure", "export-credentials", "--format", "process"])
            .output()
            .map_err(|e| {
                SigV4Error::NoCredentials(format!(
                    "no AWS credentials in the environment and the AWS CLI could not be run                      ({e}); set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or install the                      AWS CLI and log in"
                ))
            })?;

        if !output.status.success() {
            return Err(SigV4Error::NoCredentials(format!(
                "no AWS credentials in the environment and `aws configure export-credentials`                  failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|e| {
            SigV4Error::NoCredentials(format!("the AWS CLI returned unreadable credentials: {e}"))
        })?;
        let (creds, expiry) = Self::from_cli_json(&parsed)?;
        tracing::debug!("AWS: using credentials exported by the AWS CLI");
        Ok((creds, expiry))
    }

    /// Split out from the process call so the JSON contract is testable.
    fn from_cli_json(parsed: &serde_json::Value) -> Result<(Self, std::time::Instant), SigV4Error> {
        let field = |name: &'static str| -> Result<String, SigV4Error> {
            parsed
                .get(name)
                .and_then(|v| v.as_str())
                .filter(|v| !v.is_empty())
                .map(String::from)
                .ok_or(SigV4Error::MissingEnv(name))
        };

        let creds = Self::new(
            field("AccessKeyId")?,
            field("SecretAccessKey")?,
            parsed
                .get("SessionToken")
                .and_then(|v| v.as_str())
                .filter(|t| !t.trim().is_empty())
                .map(String::from),
        );

        // Temporary credentials announce their expiry; re-ask a minute early so
        // a long scan cannot sign a request with a key that just died. A static
        // key pair has no expiry, and is re-read occasionally in case the
        // operator rotated or switched profile mid-session.
        let lifetime = parsed
            .get("Expiration")
            .and_then(|v| v.as_str())
            .and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok())
            .map(|exp| {
                let remaining = exp.timestamp() - chrono::Utc::now().timestamp();
                std::time::Duration::from_secs((remaining - 60).clamp(0, 3600) as u64)
            })
            .unwrap_or(std::time::Duration::from_secs(900));

        Ok((creds, std::time::Instant::now() + lifetime))
    }

    pub fn from_env() -> Result<Self, SigV4Error> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| SigV4Error::MissingEnv("AWS_ACCESS_KEY_ID"))?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| SigV4Error::MissingEnv("AWS_SECRET_ACCESS_KEY"))?;
        Ok(Self::new(
            access_key,
            secret_key,
            std::env::var("AWS_SESSION_TOKEN").ok(),
        ))
    }
}

/// Everything the canonical request is built from.
///
/// `host` is a field rather than "whatever the caller happened to put in
/// `headers`" so that forgetting it is a compile error instead of a runtime
/// 403 — that is the structural half of the `sns.rs` fix.
pub struct SigningRequest<'a> {
    pub region: &'a str,
    /// Signing name, e.g. `s3`, `sns`, `secretsmanager`, `iam`,
    /// `cloudcontrolapi`.
    pub service: &'a str,
    /// Uppercase HTTP method.
    pub method: &'a str,
    /// Host the request is actually sent to, port included when non-default.
    /// Use [`host_from_url`] on the very URL you are going to call.
    pub host: &'a str,
    /// Absolute path, already percent-encoded, starting with `/`. `/` for the
    /// query-protocol and JSON-RPC services; the object key for S3.
    pub canonical_uri: &'a str,
    /// Query parameters, in any order — the signer sorts and encodes them.
    pub query: &'a [(String, String)],
    /// Extra headers to sign (`content-type`, `x-amz-target`,
    /// `x-amz-content-sha256`, …). Names are lowercased by the signer. Do not
    /// pass `host`, `x-amz-date` or `x-amz-security-token`: the signer owns
    /// those three.
    pub headers: &'a BTreeMap<String, String>,
    /// Hex SHA-256 of the exact body bytes, or [`EMPTY_PAYLOAD_SHA256`].
    pub payload_sha256: &'a str,
}

/// Sign `req` at the current time.
pub fn sign(creds: &Credentials, req: &SigningRequest<'_>) -> BTreeMap<String, String> {
    sign_at(creds, req, Utc::now())
}

/// Sign `req` at an explicit instant.
///
/// The whole signature is a pure function of `now`, which is what makes the
/// published AWS test vector reproducible in a unit test.
///
/// Returns **every header the request must carry**: the caller's own headers
/// plus `host`, `x-amz-date`, `authorization`, and `x-amz-security-token` when
/// the credentials are temporary. Set exactly these — dropping one, or sending
/// a different value for one, invalidates the signature.
pub fn sign_at(
    creds: &Credentials,
    req: &SigningRequest<'_>,
    now: DateTime<Utc>,
) -> BTreeMap<String, String> {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    // BTreeMap, not a hand-written list: SignedHeaders and the canonical header
    // block are both produced by iterating this map, so they are sorted
    // identically by construction.
    let mut canonical: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in req.headers {
        canonical.insert(name.to_ascii_lowercase(), normalize_header_value(value));
    }
    canonical.insert("host".to_string(), normalize_header_value(req.host));
    canonical.insert("x-amz-date".to_string(), amz_date.clone());
    if let Some(token) = &creds.session_token {
        // Both halves matter: AWS rejects the request if the token header is
        // sent but unsigned, and rejects it if the token is missing entirely.
        canonical.insert("x-amz-security-token".to_string(), token.clone());
    }

    let signed_headers = canonical.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_headers = canonical
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v))
        .collect::<String>();

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method,
        req.canonical_uri,
        canonical_query_string(req.query),
        canonical_headers,
        signed_headers,
        req.payload_sha256,
    );

    let scope = format!(
        "{}/{}/{}/aws4_request",
        date_stamp, req.region, req.service
    );
    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        ALGORITHM,
        amz_date,
        scope,
        sha256_hex(canonical_request.as_bytes())
    );

    let key = signing_key(&creds.secret_key, &date_stamp, req.region, req.service);
    let signature = hex::encode(hmac_sha256(&key, string_to_sign.as_bytes()));

    let mut out = canonical;
    out.insert(
        "authorization".to_string(),
        format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            ALGORITHM, creds.access_key, scope, signed_headers, signature
        ),
    );
    out
}

/// Host (with port when it is not the scheme default) for a URL, ready to be
/// handed to [`SigningRequest::host`].
pub fn host_from_url(raw: &str) -> Result<String, SigV4Error> {
    let parsed = url::Url::parse(raw).map_err(|_| SigV4Error::InvalidUrl(raw.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| SigV4Error::InvalidUrl(raw.to_string()))?;
    // `Url::port()` is None for the scheme default, which is exactly when the
    // Host header must not carry a port.
    Ok(match parsed.port() {
        Some(port) => format!("{}:{}", host, port),
        None => host.to_string(),
    })
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Canonical query string: every key and value percent-encoded with the
/// RFC 3986 unreserved set, then sorted by encoded key and encoded value.
fn canonical_query_string(query: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k), uri_encode(v)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encode everything outside the RFC 3986 unreserved set, uppercase
/// hex. Note that a space becomes `%20`, never `+` — `+` is a legal literal
/// character in an AWS parameter value and encoding it as a space breaks
/// signatures for base64 payloads and for ARNs with `+` in a tag.
pub fn uri_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

/// Percent-encode a path, keeping `/` as a separator. For services other than
/// S3, AWS normalizes the path before signing; kxn only ever signs paths it
/// builds itself, so [`SigningRequest::canonical_uri`] is taken as already
/// canonical and this helper exists for callers that build a path from
/// user-supplied segments (an S3 object key, for instance).
pub fn encode_uri_path(path: &str) -> String {
    path.split('/')
        .map(uri_encode)
        .collect::<Vec<_>>()
        .join("/")
}

/// SigV4 header canonicalization: trim the ends, collapse runs of spaces.
fn normalize_header_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_was_space = false;
    for ch in value.trim().chars() {
        let is_space = ch == ' ' || ch == '\t';
        if is_space {
            if !last_was_space {
                out.push(' ');
            }
        } else {
            out.push(ch);
        }
        last_was_space = is_space;
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    // `new_from_slice` only fails for key sizes HMAC cannot take, and HMAC-SHA256
    // accepts any length, so this branch is unreachable for every input.
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `aws configure export-credentials --format process` is the contract that
    /// covers every credential source the CLI knows — profiles, SSO,
    /// `aws login`, IMDS. Note the format name: 2.37 rejects `--format json`,
    /// which is how this fallback silently did nothing the first time.
    #[test]
    fn reads_the_cli_process_credential_format() {
        let json = serde_json::json!({
            "Version": 1,
            "AccessKeyId": "ASIAEXAMPLE",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
            "Expiration": "2099-01-01T00:00:00+00:00"
        });
        let (creds, good_until) = Credentials::from_cli_json(&json).expect("parses");
        assert_eq!(creds.access_key, "ASIAEXAMPLE");
        assert_eq!(creds.session_token.as_deref(), Some("token"));
        // Far-future expiry is clamped to an hour, not trusted blindly.
        assert!(good_until <= std::time::Instant::now() + std::time::Duration::from_secs(3600));
    }

    /// A static key pair has no expiry and no session token; absence of the
    /// token must not be turned into an empty string, which would be signed.
    #[test]
    fn a_static_key_pair_has_no_session_token() {
        let json = serde_json::json!({
            "Version": 1,
            "AccessKeyId": "AKIAEXAMPLE",
            "SecretAccessKey": "secret",
            "SessionToken": ""
        });
        let (creds, _) = Credentials::from_cli_json(&json).expect("parses");
        assert!(creds.session_token.is_none());
    }

    /// An expired session must not be cached as if it were good: the CLI can
    /// hand back credentials whose expiry has already passed.
    #[test]
    fn an_already_expired_answer_is_not_cached_forward() {
        let json = serde_json::json!({
            "AccessKeyId": "ASIAEXAMPLE",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
            "Expiration": "2000-01-01T00:00:00+00:00"
        });
        let (_, good_until) = Credentials::from_cli_json(&json).expect("parses");
        assert!(good_until <= std::time::Instant::now());
    }

    #[test]
    fn incomplete_cli_output_is_an_error_not_an_empty_key() {
        let json = serde_json::json!({ "SecretAccessKey": "secret" });
        assert!(Credentials::from_cli_json(&json).is_err());
    }

    use chrono::TimeZone;

    fn example_creds(token: Option<&str>) -> Credentials {
        // The key pair AWS publishes with its signing examples. It is not a
        // credential: it authenticates nothing and exists only so that the
        // expected signatures below are reproducible.
        Credentials::new(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            token.map(String::from),
        )
    }

    fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).unwrap()
    }

    fn authorization(headers: &BTreeMap<String, String>) -> &str {
        headers
            .get("authorization")
            .expect("signer always emits an Authorization header")
    }

    fn field<'a>(auth: &'a str, name: &str) -> &'a str {
        auth.split(", ")
            .find_map(|part| part.trim().strip_prefix(name))
            .unwrap_or_else(|| panic!("no {name} in {auth}"))
    }

    /// The only proof of correctness available without an AWS account: the
    /// complete worked example from the AWS "Signature Version 4 signing
    /// process" documentation — `GET https://iam.amazonaws.com/?Action=ListUsers
    /// &Version=2010-05-08`, 20150830T123600Z, us-east-1/iam. If any part of
    /// the canonical request, the scope, the key derivation or the ordering is
    /// wrong, this signature does not come out.
    #[test]
    fn matches_the_published_aws_signing_example() {
        let mut headers = BTreeMap::new();
        headers.insert(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded; charset=utf-8".to_string(),
        );

        let signed = sign_at(
            &example_creds(None),
            &SigningRequest {
                region: "us-east-1",
                service: "iam",
                method: "GET",
                host: "iam.amazonaws.com",
                canonical_uri: "/",
                query: &[
                    ("Action".to_string(), "ListUsers".to_string()),
                    ("Version".to_string(), "2010-05-08".to_string()),
                ],
                headers: &headers,
                payload_sha256: EMPTY_PAYLOAD_SHA256,
            },
            at(2015, 8, 30, 12, 36, 0),
        );

        let auth = authorization(&signed);
        assert_eq!(
            field(auth, "Signature="),
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
            "authorization was {auth}"
        );
        assert_eq!(field(auth, "SignedHeaders="), "content-type;host;x-amz-date");
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request,"));
        assert_eq!(signed["x-amz-date"], "20150830T123600Z");
        assert_eq!(signed["host"], "iam.amazonaws.com");
        assert!(!signed.contains_key("x-amz-security-token"));
    }

    /// Second published known answer: the derived signing key for
    /// 20120215/us-east-1/iam in the AWS "deriving the signing key" example.
    /// It isolates the four-step HMAC chain from everything else.
    #[test]
    fn derives_the_published_signing_key() {
        let key = signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex::encode(key),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    /// The IRSA / AssumeRole / SSO case the three previous implementations
    /// could not express: the token must be sent *and* signed. Signing it
    /// without sending it, or sending it without signing it, both yield 403.
    #[test]
    fn a_session_token_is_both_sent_and_signed() {
        let headers = BTreeMap::new();
        let req = SigningRequest {
            region: "eu-west-3",
            service: "cloudcontrolapi",
            method: "POST",
            host: "cloudcontrolapi.eu-west-3.amazonaws.com",
            canonical_uri: "/",
            query: &[],
            headers: &headers,
            payload_sha256: EMPTY_PAYLOAD_SHA256,
        };
        let when = at(2024, 1, 2, 3, 4, 5);

        let with_token = sign_at(&example_creds(Some("FQoGZXIvYXdzEXAMPLETOKEN")), &req, when);
        let without = sign_at(&example_creds(None), &req, when);

        // Sent.
        assert_eq!(with_token["x-amz-security-token"], "FQoGZXIvYXdzEXAMPLETOKEN");
        // Signed: named in SignedHeaders, in sorted position.
        assert_eq!(
            field(authorization(&with_token), "SignedHeaders="),
            "host;x-amz-date;x-amz-security-token"
        );
        // And actually folded into the canonical request, not merely announced:
        // the same request without a token signs to something else.
        assert_ne!(
            field(authorization(&with_token), "Signature="),
            field(authorization(&without), "Signature="),
        );
        assert_eq!(
            field(authorization(&without), "SignedHeaders="),
            "host;x-amz-date"
        );
    }

    /// An empty AWS_SESSION_TOKEN is what an unset variable usually looks like
    /// after entrypoint templating; it must behave like "no token", not like a
    /// token whose value is "".
    #[test]
    fn an_empty_session_token_is_treated_as_absent() {
        let creds = Credentials::new("AKIDEXAMPLE", "secret", Some("   ".to_string()));
        assert!(creds.session_token.is_none());
        let headers = BTreeMap::new();
        let signed = sign_at(
            &creds,
            &SigningRequest {
                region: "us-east-1",
                service: "sns",
                method: "POST",
                host: "sns.us-east-1.amazonaws.com",
                canonical_uri: "/",
                query: &[],
                headers: &headers,
                payload_sha256: EMPTY_PAYLOAD_SHA256,
            },
            at(2024, 1, 2, 3, 4, 5),
        );
        assert!(!signed.contains_key("x-amz-security-token"));
    }

    /// The `sns.rs` bug, as a regression test: the host that goes into the
    /// canonical request is the one the caller passes, so a regional endpoint
    /// signs differently from the global one and the two can no longer be
    /// silently mixed.
    #[test]
    fn the_signed_host_follows_the_endpoint() {
        let headers = BTreeMap::new();
        let mk = |host: &str| {
            let signed = sign_at(
                &example_creds(None),
                &SigningRequest {
                    region: "eu-west-3",
                    service: "sns",
                    method: "POST",
                    host,
                    canonical_uri: "/",
                    query: &[],
                    headers: &headers,
                    payload_sha256: EMPTY_PAYLOAD_SHA256,
                },
                at(2024, 1, 2, 3, 4, 5),
            );
            (
                signed["host"].clone(),
                field(authorization(&signed), "Signature=").to_string(),
            )
        };
        let (regional_host, regional_sig) = mk("sns.eu-west-3.amazonaws.com");
        let (global_host, global_sig) = mk("sns.amazonaws.com");

        assert_eq!(regional_host, "sns.eu-west-3.amazonaws.com");
        assert_eq!(global_host, "sns.amazonaws.com");
        assert_ne!(regional_sig, global_sig);
    }

    #[test]
    fn host_comes_from_the_url_that_will_be_called() {
        assert_eq!(
            host_from_url("https://cloudcontrolapi.eu-west-3.amazonaws.com/").unwrap(),
            "cloudcontrolapi.eu-west-3.amazonaws.com"
        );
        // Default port for the scheme must not appear in the Host header.
        assert_eq!(
            host_from_url("https://bucket.s3.eu-west-3.amazonaws.com:443/key").unwrap(),
            "bucket.s3.eu-west-3.amazonaws.com"
        );
        // A non-default port must, which is how MinIO / LocalStack endpoints work.
        assert_eq!(
            host_from_url("http://localhost:9000/bucket/key").unwrap(),
            "localhost:9000"
        );
        assert!(host_from_url("not a url").is_err());
    }

    /// SignedHeaders is derived, never written by hand — insertion order must
    /// not leak into it.
    #[test]
    fn signed_headers_are_sorted_whatever_the_caller_does() {
        let mut headers = BTreeMap::new();
        headers.insert("X-Amz-Target".to_string(), "CloudApiService.GetResource".into());
        headers.insert("Content-Type".to_string(), "application/x-amz-json-1.0".into());
        headers.insert("x-amz-content-sha256".to_string(), EMPTY_PAYLOAD_SHA256.into());

        let signed = sign_at(
            &example_creds(Some("tok")),
            &SigningRequest {
                region: "us-east-1",
                service: "cloudcontrolapi",
                method: "POST",
                host: "cloudcontrolapi.us-east-1.amazonaws.com",
                canonical_uri: "/",
                query: &[],
                headers: &headers,
                payload_sha256: EMPTY_PAYLOAD_SHA256,
            },
            at(2024, 1, 2, 3, 4, 5),
        );
        assert_eq!(
            field(authorization(&signed), "SignedHeaders="),
            "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-amz-target"
        );
        // Header names are lowercased in the map the caller is told to send,
        // which is also what went into the canonical request.
        assert!(signed.contains_key("x-amz-target"));
        assert!(!signed.contains_key("X-Amz-Target"));
    }

    #[test]
    fn query_parameters_are_sorted_and_encoded() {
        assert_eq!(
            canonical_query_string(&[
                ("Version".into(), "2010-05-08".into()),
                ("Action".into(), "ListUsers".into()),
            ]),
            "Action=ListUsers&Version=2010-05-08"
        );
        // Space is %20, `+` stays a literal, `/` and `:` are encoded in values.
        assert_eq!(
            canonical_query_string(&[("k".into(), "a b+c/d:e".into())]),
            "k=a%20b%2Bc%2Fd%3Ae"
        );
        // Sorting is on the encoded form, and ties on the key break on the value.
        assert_eq!(
            canonical_query_string(&[("a".into(), "2".into()), ("a".into(), "1".into())]),
            "a=1&a=2"
        );
        assert_eq!(canonical_query_string(&[]), "");
    }

    #[test]
    fn header_values_are_canonicalized() {
        assert_eq!(normalize_header_value("  a   b  "), "a b");
        assert_eq!(
            normalize_header_value("application/x-www-form-urlencoded; charset=utf-8"),
            "application/x-www-form-urlencoded; charset=utf-8"
        );
    }

    #[test]
    fn paths_keep_their_separators() {
        assert_eq!(encode_uri_path("/a/b c/d"), "/a/b%20c/d");
        assert_eq!(encode_uri_path("/"), "/");
    }

    #[test]
    fn empty_payload_constant_is_the_sha256_of_nothing() {
        assert_eq!(sha256_hex(b""), EMPTY_PAYLOAD_SHA256);
    }
}
