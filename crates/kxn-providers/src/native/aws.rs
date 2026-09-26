//! Native AWS collector.
//!
//! # Why a generic collector and not one client per service
//!
//! The shape adopted in this repo (see `native/azure.rs`) is: one inventory
//! call per cloud, then one detail read per resource, then a normalizer that
//! renames the cloud's field names to the ones the rules read. AWS's equivalent
//! of the Azure Resource Manager listing is **Cloud Control API**
//! (`cloudcontrolapi.<region>.amazonaws.com`, `ListResources` + `GetResource`):
//! several hundred CloudFormation resource types behind one JSON-RPC protocol,
//! one signing name, one pagination scheme. Writing an S3 client, an RDS
//! client, an EKS client and so on would mean five XML dialects and five
//! pagination schemes for the same result.
//!
//! `aws_resources.rs` already reads Cloud Control-shaped payloads
//! (`TypeName` / `Identifier` / `Properties`) to extract resource relations, so
//! this is the shape the rest of the AWS code already expects.
//!
//! A handful of facts have no CloudFormation resource type at all — they are
//! account-level IAM reports rather than resources. Those get an explicit,
//! separately implemented IAM call: the credential report, the account summary,
//! the password policy, the virtual MFA device list and the server certificate
//! list. IAM speaks the old Query protocol and answers XML, which is why this
//! file carries a small XML reader.
//!
//! # The two rules this file is built around
//!
//! 1. **An object is declared in [`RESOURCE_TYPES`] only if every property its
//!    rules read is produced.** The rule engine turns a missing property into
//!    `Value::String("")` (`kxn-core/src/engine/evaluator.rs`), and `"" == true`
//!    is false, so a half-normalized object does not degrade into "unknown", it
//!    degrades into a *violation that is not real*. An object nothing produces
//!    is merely a gap; an object produced with holes is disinformation.
//!
//!    The same discipline applies per resource, not just per object: a
//!    normalizer returns `None` — and the resource is dropped with a warning —
//!    rather than emitting a record whose missing field would manufacture a
//!    finding.
//!
//! 2. **Never substitute a value for an answer the API did not give.** Where a
//!    field is absent *and AWS documents that absence as a value* (no
//!    `VersioningConfiguration` means a bucket was never versioned; no
//!    `CloudWatchLogsLogGroupArn` means the trail is not wired to CloudWatch),
//!    the documented meaning is used and the comment says so. Where absence is
//!    indistinguishable from a partial read, the resource is dropped instead.
//!
//! # Credentials
//!
//! Environment only, via [`Credentials::from_env`], session token included — see
//! `aws_sigv4.rs`. The IMDS and container-credential endpoints, `~/.aws/config`
//! profiles and `AWS_WEB_IDENTITY_TOKEN_FILE` are **not** implemented here; a
//! pod using IRSA has `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE` and no key
//! pair, so it needs an `sts:AssumeRoleWithWebIdentity` exchange this file does
//! not do. What it does support is the case where something upstream has
//! already exported the three variables.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::stream::{self, StreamExt};
use serde_json::{json, Map, Value};
use tokio::sync::Mutex;

use crate::aws_sigv4::{self, Credentials, SigningRequest};
use crate::error::ProviderError;
use crate::traits::Provider;

/// Objects this provider serves, every property of every rule included.
///
/// Deliberately absent, with the reason in each case:
///
/// * `instance` — CIS 2.8 reads `metadata_options.0.http_tokens`.
///   `AWS::EC2::Instance` has no `MetadataOptions` property in CloudFormation
///   at all (IMDSv2 is only configurable through a launch template), so Cloud
///   Control cannot answer it and every instance would be reported as IMDSv1.
/// * `security_group_rule` — CIS 5.2/5.3 read a scalar `from_port`. An
///   "all traffic" ingress (`IpProtocol: -1`) has no `FromPort` in any AWS API,
///   and it is precisely the worst case. Any number written there is invented,
///   and leaving it out makes the two rules pass silently on a wide-open group.
/// * `cloudwatch_log_group` — the two rules require `retention_in_days > 0` and
///   `<= 365`. A log group with no retention never expires, which satisfies the
///   intent and fails both rules under every encoding available.
/// * `load_balancer` — `listener_protocol` is a property of a listener, not of
///   a load balancer; no load balancer payload can carry it, so
///   `aws-cis-elb-https-listener` would fire on every ALB in the account.
/// * `lambda_function` — `policy_is_public` needs the function's
///   resource-based policy. `AWS::Lambda::Function` has no policy property and
///   `AWS::Lambda::Permission` cannot be listed without knowing the statement
///   ids.
/// * `secrets_manager` — rotation lives on `AWS::SecretsManager::RotationSchedule`;
///   `AWS::SecretsManager::Secret` has no rotation field, so `rotation_enabled`
///   is unanswerable from the secret.
/// * `s3_account_public_access_block` and `ebs_encryption_by_default` — both are
///   account-level settings (`s3control:GetPublicAccessBlock`,
///   `ec2:GetEbsEncryptionByDefault`) with no CloudFormation resource type.
/// * `aws_iam_policy` — CIS 1.22 looks for the AWS-managed
///   `AWSCloudShellFullAccess`. Cloud Control's `AWS::IAM::ManagedPolicy` lists
///   customer-managed policies only, so `allows_cloudshell_full_access` would
///   be `false` in every account: a guaranteed false negative. It needs
///   `iam:ListPolicies(OnlyAttached)` + `iam:GetPolicyVersion`.
/// * `aws_accessanalyzer_analyzer` — the rule reads `status`, which is not in
///   the `AWS::AccessAnalyzer::Analyzer` schema. It needs the Access Analyzer
///   REST API (`GET /analyzer`), a third protocol.
pub(crate) const RESOURCE_TYPES: &[&str] = &[
    "aws_iam_account_password_policy",
    "aws_iam_account_summary",
    "aws_iam_credential_report",
    "aws_iam_role",
    "aws_iam_server_certificate",
    "aws_iam_users",
    "aws_iam_virtual_mfa_devices",
    "cloudtrail",
    "ebs_volume",
    "ecr_repository",
    "eks_cluster",
    "iam_account_password_policy",
    "iam_role",
    "iam_user",
    "kms_key",
    "rds_cluster",
    "rds_instance",
    "s3_bucket",
    "security_group",
    "sns_topic",
    "sqs_queue",
    "vpc",
];

/// Objects served by the plain Cloud Control path: list identifiers, read each
/// one, normalize. Objects needing a join or an IAM call are handled separately
/// in [`AwsProvider::gather`].
const CLOUD_CONTROL_OBJECTS: &[(&str, &str)] = &[
    ("cloudtrail", "AWS::CloudTrail::Trail"),
    ("ebs_volume", "AWS::EC2::Volume"),
    ("ecr_repository", "AWS::ECR::Repository"),
    ("eks_cluster", "AWS::EKS::Cluster"),
    ("kms_key", "AWS::KMS::Key"),
    ("rds_cluster", "AWS::RDS::DBCluster"),
    ("rds_instance", "AWS::RDS::DBInstance"),
    ("s3_bucket", "AWS::S3::Bucket"),
    ("security_group", "AWS::EC2::SecurityGroup"),
    ("sns_topic", "AWS::SNS::Topic"),
    ("sqs_queue", "AWS::SQS::Queue"),
];

const IAM_API_VERSION: &str = "2010-05-08";
/// IAM is a global endpoint; in the `aws` partition its signing region is always
/// us-east-1 regardless of where the scan runs. `aws-cn` and `aws-us-gov` use
/// different endpoints and are not handled.
const IAM_HOST: &str = "iam.amazonaws.com";
const IAM_SIGNING_REGION: &str = "us-east-1";

const ADMINISTRATOR_ACCESS_ARN: &str = "arn:aws:iam::aws:policy/AdministratorAccess";
const SUPPORT_ACCESS_ARN: &str = "arn:aws:iam::aws:policy/AWSSupportAccess";

// ───────────────────────────── provider ─────────────────────────────

pub struct AwsProvider {
    region: String,
    /// Cloud Control throttles hard per account/region, so detail reads stay
    /// modest by default.
    concurrency: usize,
    /// Cloud Control resources, keyed by CloudFormation type name. Several
    /// objects share a source (`AWS::IAM::Role` feeds both `iam_role` and
    /// `aws_iam_role`), and `gather_all` walks every object in turn.
    cloud_control: Mutex<HashMap<String, Arc<Vec<Value>>>>,
    /// The credential report is one report for the whole account, and
    /// generating it is an asynchronous IAM operation — fetched at most once.
    credential_report: Mutex<Option<Arc<Vec<CredentialRow>>>>,
    /// `Some(None)` means IAM answered NoSuchEntity: the account has no
    /// password policy at all. That is an answer, not a failure, and it is not
    /// the same thing as "we never asked".
    password_policy: Mutex<Option<Option<Arc<Value>>>>,
}

impl AwsProvider {
    pub fn new(config: Value) -> Result<Self, ProviderError> {
        // No silent fallback to us-east-1. A compliance scan that quietly
        // inspects a region the operator did not mean reports "0 findings" for
        // the region they cared about, which is the most expensive possible
        // way to be wrong.
        let region = crate::config::get_config_or_env(&config, "REGION", Some("AWS"))
            .or_else(|| crate::config::get_config_or_env(&config, "DEFAULT_REGION", Some("AWS")))
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .ok_or_else(|| {
                ProviderError::InvalidConfig(
                    "no AWS region configured; set AWS_REGION or the provider's `region`"
                        .to_string(),
                )
            })?;

        let concurrency = crate::config::get_config_or_env(&config, "CONCURRENCY", Some("AWS"))
            .and_then(|c| c.parse().ok())
            .filter(|c| *c > 0)
            .unwrap_or(8);

        Ok(Self {
            region,
            concurrency,
            cloud_control: Mutex::new(HashMap::new()),
            credential_report: Mutex::new(None),
            password_policy: Mutex::new(None),
        })
    }

    fn credentials(&self) -> Result<Credentials, ProviderError> {
        Credentials::from_env().map_err(|e| ProviderError::Auth(e.to_string()))
    }

    // ─────────────────── Cloud Control transport ───────────────────

    fn cloud_control_url(&self) -> String {
        format!("https://cloudcontrolapi.{}.amazonaws.com/", self.region)
    }

    /// One signed `awsJson1.0` call against Cloud Control.
    async fn cloud_control_call(&self, operation: &str, body: Value) -> Result<Value, ProviderError> {
        let url = self.cloud_control_url();
        let host = aws_sigv4::host_from_url(&url)
            .map_err(|e| ProviderError::InvalidConfig(e.to_string()))?;
        let payload = serde_json::to_vec(&body)
            .map_err(|e| ProviderError::Api(format!("cannot encode Cloud Control request: {e}")))?;

        let mut headers = BTreeMap::new();
        headers.insert(
            "content-type".to_string(),
            "application/x-amz-json-1.0".to_string(),
        );
        headers.insert(
            "x-amz-target".to_string(),
            format!("CloudApiService.{operation}"),
        );

        let signed = aws_sigv4::sign(
            &self.credentials()?,
            &SigningRequest {
                region: &self.region,
                service: "cloudcontrolapi",
                method: "POST",
                host: &host,
                canonical_uri: "/",
                query: &[],
                headers: &headers,
                payload_sha256: &aws_sigv4::sha256_hex(&payload),
            },
        );

        let text = send_signed(&url, signed, payload, operation).await?;
        serde_json::from_str(&text).map_err(|e| {
            ProviderError::Api(format!("Cloud Control {operation}: invalid JSON response: {e}"))
        })
    }

    /// Every resource of one CloudFormation type, fully read.
    ///
    /// `ListResources` is documented to return only the primary identifier plus
    /// whatever the list handler happens to carry, which differs per type, so
    /// each identifier is read back with `GetResource` exactly as `azure.rs`
    /// reads each ARM id back. Trusting the listing payload would give a
    /// different set of properties per resource type — the silent-hole failure
    /// mode this file exists to avoid.
    async fn cloud_control_resources(
        &self,
        type_name: &str,
    ) -> Result<Arc<Vec<Value>>, ProviderError> {
        {
            let cache = self.cloud_control.lock().await;
            if let Some(hit) = cache.get(type_name) {
                return Ok(hit.clone());
            }
        }

        let mut identifiers: Vec<String> = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            let mut body = json!({ "TypeName": type_name, "MaxResults": 100 });
            if let Some(token) = &next_token {
                body["NextToken"] = json!(token);
            }
            let page = self.cloud_control_call("ListResources", body).await?;

            for descr in page
                .get("ResourceDescriptions")
                .and_then(|v| v.as_array())
                .map(|a| a.as_slice())
                .unwrap_or(&[])
            {
                if let Some(id) = descr.get("Identifier").and_then(|v| v.as_str()) {
                    identifiers.push(id.to_string());
                }
            }

            next_token = page
                .get("NextToken")
                .and_then(|v| v.as_str())
                .filter(|t| !t.is_empty())
                .map(String::from);
            if next_token.is_none() {
                break;
            }
        }

        let resources: Vec<Value> = stream::iter(identifiers)
            .map(|id| async move {
                let body = json!({ "TypeName": type_name, "Identifier": id });
                match self.cloud_control_call("GetResource", body).await {
                    Ok(resp) => match resource_properties(&resp) {
                        Some(props) => Some(json!({
                            "TypeName": type_name,
                            "Identifier": id,
                            "Properties": props,
                        })),
                        None => {
                            tracing::warn!(
                                resource_type = %type_name, identifier = %id,
                                "AWS: Cloud Control returned no readable Properties"
                            );
                            None
                        }
                    },
                    Err(e) => {
                        // A single unreadable resource must not fail the type:
                        // a deleting RDS instance or a cross-account KMS key is
                        // normal. It is dropped with a warning — never replaced
                        // by a placeholder that the rules would score.
                        tracing::warn!(
                            resource_type = %type_name, identifier = %id, error = %e,
                            "AWS: Cloud Control detail read failed"
                        );
                        None
                    }
                }
            })
            .buffer_unordered(self.concurrency)
            .filter_map(|r| async move { r })
            .collect()
            .await;

        let shared = Arc::new(resources);
        self.cloud_control
            .lock()
            .await
            .insert(type_name.to_string(), shared.clone());
        Ok(shared)
    }

    // ────────────────────── IAM transport ──────────────────────

    /// One signed IAM Query-protocol call. IAM answers XML, which
    /// [`parse_xml`] turns into the same `serde_json::Value` shape everything
    /// else in this file works with.
    async fn iam_call(
        &self,
        action: &str,
        params: &[(&str, String)],
    ) -> Result<Value, ProviderError> {
        let url = format!("https://{IAM_HOST}/");
        let mut form: Vec<(String, String)> = vec![
            ("Action".to_string(), action.to_string()),
            ("Version".to_string(), IAM_API_VERSION.to_string()),
        ];
        form.extend(params.iter().map(|(k, v)| (k.to_string(), v.clone())));
        let body = form
            .iter()
            .map(|(k, v)| format!("{}={}", aws_sigv4::uri_encode(k), aws_sigv4::uri_encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let payload = body.into_bytes();

        let mut headers = BTreeMap::new();
        headers.insert(
            "content-type".to_string(),
            "application/x-www-form-urlencoded; charset=utf-8".to_string(),
        );

        let signed = aws_sigv4::sign(
            &self.credentials()?,
            &SigningRequest {
                region: IAM_SIGNING_REGION,
                service: "iam",
                method: "POST",
                host: IAM_HOST,
                canonical_uri: "/",
                // The parameters travel in the body, so the canonical query
                // string is empty and the body is what gets hashed.
                query: &[],
                headers: &headers,
                payload_sha256: &aws_sigv4::sha256_hex(&payload),
            },
        );

        let text = send_signed(&url, signed, payload, action).await?;
        parse_xml(&text)
            .ok_or_else(|| ProviderError::Api(format!("IAM {action}: unparseable XML response")))
    }

    /// The account password policy, or `None` when IAM says there is none.
    ///
    /// The distinction matters: "no policy" is a real answer that makes every
    /// password rule fail on purpose, while a failed call must not be turned
    /// into "no policy" — that would invent a whole set of findings.
    async fn password_policy(&self) -> Result<Option<Arc<Value>>, ProviderError> {
        let mut slot = self.password_policy.lock().await;
        if let Some(cached) = slot.as_ref() {
            return Ok(cached.clone());
        }
        let resolved = match self.iam_call("GetAccountPasswordPolicy", &[]).await {
            Ok(doc) => doc
                .pointer("/GetAccountPasswordPolicyResult/PasswordPolicy")
                .map(|p| Arc::new(p.clone())),
            Err(ProviderError::NotFound(_)) => None,
            Err(e) => return Err(e),
        };
        *slot = Some(resolved.clone());
        Ok(resolved)
    }

    /// The account credential report, generated if needed.
    async fn credential_report(&self) -> Result<Arc<Vec<CredentialRow>>, ProviderError> {
        let mut slot = self.credential_report.lock().await;
        if let Some(cached) = slot.as_ref() {
            return Ok(cached.clone());
        }

        // GenerateCredentialReport is asynchronous: the first call on a cold
        // account returns STARTED and GetCredentialReport then fails with
        // ReportInProgress. Poll a bounded number of times rather than
        // returning an empty report, which would read as "no users".
        let mut csv: Option<String> = None;
        for attempt in 0..10u32 {
            let state = self
                .iam_call("GenerateCredentialReport", &[])
                .await?
                .pointer("/GenerateCredentialReportResult/State")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();

            if state == "COMPLETE" {
                let report = self.iam_call("GetCredentialReport", &[]).await?;
                let encoded = report
                    .pointer("/GetCredentialReportResult/Content")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ProviderError::Api("IAM credential report has no Content".to_string())
                    })?;
                let decoded = decode_base64(encoded).ok_or_else(|| {
                    ProviderError::Api("IAM credential report is not valid base64".to_string())
                })?;
                csv = Some(String::from_utf8_lossy(&decoded).into_owned());
                break;
            }

            tracing::debug!(state = %state, attempt, "AWS: waiting for the IAM credential report");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }

        // The report never became available within the polling budget. Not an
        // empty report: an empty report would read as "this account has no
        // users", which is a very different claim.
        let csv = csv.ok_or(ProviderError::Timeout)?;
        let rows = Arc::new(parse_credential_report(&csv));
        *slot = Some(rows.clone());
        Ok(rows)
    }

    /// IAM users read through Cloud Control, which answers JSON and already
    /// carries the inline policies and the permissions boundary — the two
    /// things `iam:ListUsers` does not return.
    async fn iam_users(&self) -> Result<Arc<Vec<Value>>, ProviderError> {
        self.cloud_control_resources("AWS::IAM::User").await
    }

    // ────────────────────── object builders ──────────────────────

    async fn gather_vpcs(&self) -> Result<Vec<Value>, ProviderError> {
        // The join is the whole point: `AWS::EC2::VPC` has no flow-log field,
        // so "flow logs on?" is answered by whether any AWS::EC2::FlowLog names
        // this VPC. If the flow-log listing fails we must fail too — answering
        // `false` for every VPC would invent a finding on the entire estate.
        let flow_logs = self.cloud_control_resources("AWS::EC2::FlowLog").await?;
        let vpcs = self.cloud_control_resources("AWS::EC2::VPC").await?;
        Ok(join_vpc_flow_logs(&vpcs, &flow_logs))
    }

    async fn gather_roles(&self, object: &str) -> Result<Vec<Value>, ProviderError> {
        let roles = self.cloud_control_resources("AWS::IAM::Role").await?;

        // CIS 1.18 asks whether *the account* has a support role. Every role
        // object therefore carries the same account-level answer, which is only
        // meaningful because the listing above is complete: a partial listing
        // returns Err before reaching here.
        let support_role_exists = roles.iter().any(|r| {
            managed_policy_arns(r.pointer("/Properties")).contains(&SUPPORT_ACCESS_ARN)
        });

        Ok(roles
            .iter()
            .filter_map(|r| normalize_role(object, r.get("Properties")?, support_role_exists))
            .collect())
    }

    async fn gather_iam_users_object(&self) -> Result<Vec<Value>, ProviderError> {
        let users = self.iam_users().await?;
        Ok(vec![iam_users_object(&users)])
    }

    async fn gather_users(&self) -> Result<Vec<Value>, ProviderError> {
        let report = self.credential_report().await?;
        let cc_users = self.iam_users().await?;
        let policy = self.password_policy().await?;

        let inline_counts: HashMap<String, u64> = cc_users
            .iter()
            .filter_map(|u| {
                let props = u.get("Properties")?;
                let name = props.get("UserName").and_then(|v| v.as_str())?;
                Some((name.to_string(), inline_policy_count(props)))
            })
            .collect();

        // Only present when the policy sets it; see `normalize_password_policy`.
        let max_age = policy
            .as_ref()
            .and_then(|p| p.get("MaxPasswordAge"))
            .and_then(as_u64);

        Ok(user_objects(&report, &inline_counts, max_age, Utc::now()))
    }

    async fn gather_credential_report(&self) -> Result<Vec<Value>, ProviderError> {
        let report = self.credential_report().await?;
        Ok(vec![credential_report_object(&report, Utc::now())?])
    }

    async fn gather_account_summary(&self) -> Result<Vec<Value>, ProviderError> {
        let doc = self.iam_call("GetAccountSummary", &[]).await?;
        let map = doc
            .pointer("/GetAccountSummaryResult/SummaryMap")
            .ok_or_else(|| ProviderError::Api("IAM GetAccountSummary has no SummaryMap".into()))?;
        let entries = summary_map(map);

        // Both counters are always present in a SummaryMap. If one is not, the
        // response is not the one we think we parsed, and guessing a 0 or a 1
        // would either invent or hide a root-account finding.
        let (Some(keys), Some(mfa)) = (
            entries.get("AccountAccessKeysPresent").copied(),
            entries.get("AccountMFAEnabled").copied(),
        ) else {
            return Err(ProviderError::Api(
                "IAM SummaryMap lacks AccountAccessKeysPresent or AccountMFAEnabled".to_string(),
            ));
        };

        Ok(vec![json!({
            "account_access_keys_present": keys,
            "account_mfa_enabled": mfa,
        })])
    }

    async fn gather_password_policy(&self, object: &str) -> Result<Vec<Value>, ProviderError> {
        match self.password_policy().await? {
            Some(policy) => Ok(normalize_password_policy(object, &policy)
                .into_iter()
                .collect()),
            // IAM answered NoSuchEntity: the account has no password policy.
            // There is no object to describe, and fabricating one with zeroed
            // fields would report seven findings that describe our guess rather
            // than the account.
            None => {
                tracing::warn!(
                    "AWS: the account has no IAM password policy; {object} rules cannot be evaluated"
                );
                Ok(Vec::new())
            }
        }
    }

    async fn gather_virtual_mfa_devices(&self) -> Result<Vec<Value>, ProviderError> {
        let mut root_virtual_mfa = false;
        let mut marker: Option<String> = None;
        loop {
            let params: Vec<(&str, String)> = match &marker {
                Some(m) => vec![("Marker", m.clone())],
                None => Vec::new(),
            };
            let doc = self.iam_call("ListVirtualMFADevices", &params).await?;
            let result = doc
                .get("ListVirtualMFADevicesResult")
                .ok_or_else(|| ProviderError::Api("IAM ListVirtualMFADevices: no result".into()))?;

            for device in members(result.get("VirtualMFADevices")) {
                // A virtual MFA device assigned to the root user means root is
                // *not* on hardware MFA, which is what CIS 1.6 asks.
                if device
                    .pointer("/User/Arn")
                    .and_then(|v| v.as_str())
                    .is_some_and(|arn| arn.ends_with(":root"))
                {
                    root_virtual_mfa = true;
                }
            }

            marker = next_marker(result);
            if marker.is_none() {
                break;
            }
        }
        Ok(vec![json!({ "root_virtual_mfa": root_virtual_mfa })])
    }

    async fn gather_server_certificates(&self) -> Result<Vec<Value>, ProviderError> {
        let now = Utc::now();
        let mut out = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let params: Vec<(&str, String)> = match &marker {
                Some(m) => vec![("Marker", m.clone())],
                None => Vec::new(),
            };
            let doc = self.iam_call("ListServerCertificates", &params).await?;
            let result = doc
                .get("ListServerCertificatesResult")
                .ok_or_else(|| ProviderError::Api("IAM ListServerCertificates: no result".into()))?;

            for cert in members(result.get("ServerCertificateMetadataList")) {
                let Some(expiration) = cert.get("Expiration").and_then(|v| v.as_str()) else {
                    tracing::warn!("AWS: server certificate without an Expiration; skipped");
                    continue;
                };
                let Some(expires_at) = parse_aws_timestamp(expiration) else {
                    tracing::warn!(expiration, "AWS: unparseable server certificate expiry; skipped");
                    continue;
                };
                out.push(json!({
                    "name": cert.get("ServerCertificateName").cloned().unwrap_or(Value::Null),
                    "arn": cert.get("Arn").cloned().unwrap_or(Value::Null),
                    "expiration": expiration,
                    "expired": expires_at < now,
                }));
            }

            marker = next_marker(result);
            if marker.is_none() {
                break;
            }
        }
        Ok(out)
    }
}

#[async_trait::async_trait]
impl Provider for AwsProvider {
    fn name(&self) -> &str {
        "aws"
    }

    async fn resource_types(&self) -> Result<Vec<String>, ProviderError> {
        Ok(RESOURCE_TYPES.iter().map(|s| s.to_string()).collect())
    }

    async fn gather(&self, resource_type: &str) -> Result<Vec<Value>, ProviderError> {
        if let Some((_, type_name)) = CLOUD_CONTROL_OBJECTS
            .iter()
            .find(|(object, _)| *object == resource_type)
        {
            let resources = self.cloud_control_resources(type_name).await?;
            return Ok(resources
                .iter()
                .filter_map(|r| {
                    let props = r.get("Properties")?;
                    let normalized = normalize(resource_type, props);
                    if normalized.is_none() {
                        tracing::warn!(
                            resource_type,
                            identifier = ?r.get("Identifier"),
                            "AWS: dropped — Cloud Control did not return every property the rules read"
                        );
                    }
                    normalized
                })
                .collect());
        }

        match resource_type {
            "vpc" => self.gather_vpcs().await,
            "iam_role" | "aws_iam_role" => self.gather_roles(resource_type).await,
            "aws_iam_users" => self.gather_iam_users_object().await,
            "iam_user" => self.gather_users().await,
            "aws_iam_credential_report" => self.gather_credential_report().await,
            "aws_iam_account_summary" => self.gather_account_summary().await,
            "aws_iam_account_password_policy" | "iam_account_password_policy" => {
                self.gather_password_policy(resource_type).await
            }
            "aws_iam_virtual_mfa_devices" => self.gather_virtual_mfa_devices().await,
            "aws_iam_server_certificate" => self.gather_server_certificates().await,
            other => Err(ProviderError::UnsupportedResourceType(other.to_string())),
        }
    }

    /// The default `gather_all` inserts `{"error": "..."}` as the single
    /// resource of a type that failed. For AWS that is actively harmful: the
    /// rules then read `is_multi_region_trail` off an error object, get `""`,
    /// and report a CloudTrail violation caused by a missing IAM permission.
    /// A type that cannot be collected is left out of the map instead — a gap
    /// the operator sees in the logs, not a finding they cannot reproduce.
    async fn gather_all(&self) -> Result<HashMap<String, Vec<Value>>, ProviderError> {
        let mut out = HashMap::new();
        for resource_type in RESOURCE_TYPES {
            match self.gather(resource_type).await {
                Ok(items) => {
                    out.insert((*resource_type).to_string(), items);
                }
                Err(e) => {
                    tracing::warn!(
                        resource_type, error = %e,
                        "AWS: resource type not collected; its rules will not be evaluated"
                    );
                }
            }
        }
        Ok(out)
    }
}

// ───────────────────────── HTTP plumbing ─────────────────────────

/// Send a request whose headers were produced by the signer, verbatim.
///
/// Every header the signer returned is set and nothing else is: an extra or
/// altered header is exactly what makes a correct signature look wrong.
async fn send_signed(
    url: &str,
    signed: BTreeMap<String, String>,
    payload: Vec<u8>,
    what: &str,
) -> Result<String, ProviderError> {
    let mut request = crate::http::shared_client().post(url);
    for (name, value) in &signed {
        // reqwest derives Host from the URL, and setting it by hand on top can
        // duplicate it; the signed value and the URL host are the same string
        // because the caller derived one from the other.
        if name == "host" {
            continue;
        }
        request = request.header(name.as_str(), value.as_str());
    }

    let response = request
        .body(payload)
        .send()
        .await
        .map_err(|e| ProviderError::Connection(format!("{what}: {e}")))?;

    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| ProviderError::Api(format!("{what}: cannot read response body: {e}")))?;

    if status.is_success() {
        return Ok(text);
    }
    Err(classify_error(status, &text, what))
}

/// Map an AWS error response onto the provider's error taxonomy so callers can
/// tell "you may not read this" from "this does not exist" from "slow down".
fn classify_error(status: reqwest::StatusCode, body: &str, what: &str) -> ProviderError {
    let code = error_code(body);
    let message = format!("{what} ({status}) {code}: {}", body.trim());
    match code.as_str() {
        "NoSuchEntity" | "ResourceNotFoundException" | "TypeNotFoundException" => {
            ProviderError::NotFound(message)
        }
        "AccessDenied" | "AccessDeniedException" | "UnauthorizedOperation"
        | "InvalidClientTokenId" | "SignatureDoesNotMatch" | "ExpiredToken"
        | "ExpiredTokenException" => ProviderError::Auth(message),
        "Throttling" | "ThrottlingException" | "TooManyRequestsException"
        | "RequestLimitExceeded" => ProviderError::RateLimited { retry_after_secs: 5 },
        _ if status == reqwest::StatusCode::TOO_MANY_REQUESTS => {
            ProviderError::RateLimited { retry_after_secs: 5 }
        }
        _ if status == reqwest::StatusCode::FORBIDDEN
            || status == reqwest::StatusCode::UNAUTHORIZED =>
        {
            ProviderError::Auth(message)
        }
        _ => ProviderError::Api(message),
    }
}

/// Pull the error code out of either AWS error dialect: the JSON one used by
/// Cloud Control (`__type` / `code`) and the XML one used by IAM (`<Code>`).
fn error_code(body: &str) -> String {
    if let Ok(json) = serde_json::from_str::<Value>(body) {
        for key in ["__type", "code", "Code"] {
            if let Some(raw) = json.get(key).and_then(|v| v.as_str()) {
                // `__type` is often `com.amazonaws...#AccessDeniedException`.
                return raw.rsplit(['#', ':']).next().unwrap_or(raw).to_string();
            }
        }
    }
    if let Some(doc) = parse_xml(body) {
        if let Some(code) = find_first(&doc, "Code").and_then(|v| v.as_str()) {
            return code.to_string();
        }
    }
    String::new()
}

// ───────────────────────── Cloud Control shapes ─────────────────────────

/// `GetResource` answers `{"ResourceDescription": {"Properties": "<json text>"}}`
/// — `Properties` is a JSON *document encoded as a string*, not an object.
fn resource_properties(response: &Value) -> Option<Value> {
    let raw = response
        .pointer("/ResourceDescription/Properties")
        .or_else(|| response.pointer("/Properties"))?;
    match raw {
        Value::String(s) => serde_json::from_str(s).ok(),
        other => Some(other.clone()),
    }
}

// ───────────────────── account-level assembly ─────────────────────

/// `enable_flow_logs` per VPC: a VPC has flow logs when some `AWS::EC2::FlowLog`
/// names it in `ResourceId`. The caller must have both listings in hand — a
/// missing flow-log listing would make every VPC look unmonitored.
fn join_vpc_flow_logs(vpcs: &[Value], flow_logs: &[Value]) -> Vec<Value> {
    let monitored: std::collections::HashSet<&str> = flow_logs
        .iter()
        .filter_map(|f| f.pointer("/Properties/ResourceId").and_then(|v| v.as_str()))
        .collect();

    vpcs.iter()
        .filter_map(|v| {
            let props = v.get("Properties")?;
            let vpc_id = props
                .get("VpcId")
                .and_then(|x| x.as_str())
                .or_else(|| v.get("Identifier").and_then(|x| x.as_str()))?;
            Some(json!({
                "id": vpc_id,
                "cidr_block": props.get("CidrBlock").cloned().unwrap_or(Value::Null),
                "enable_flow_logs": monitored.contains(vpc_id),
            }))
        })
        .collect()
}

/// The single account-level `aws_iam_users` object: `iam_user_count` is a
/// scalar on it and `users` is the array the `NOT_ANY` conditions walk.
fn iam_users_object(users: &[Value]) -> Value {
    let normalized: Vec<Value> = users
        .iter()
        .filter_map(|u| {
            let props = u.get("Properties")?;
            let name = props
                .get("UserName")
                .and_then(|v| v.as_str())
                .or_else(|| u.get("Identifier").and_then(|v| v.as_str()))?;
            Some(json!({
                "name": name,
                "inline_policies_count": inline_policy_count(props),
                // Absent means no boundary is attached — CloudFormation omits
                // `PermissionsBoundary` rather than sending null, and the rule
                // tests for exactly this empty string.
                "permissions_boundary": props
                    .get("PermissionsBoundary")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            }))
        })
        .collect();

    json!({ "iam_user_count": normalized.len(), "users": normalized })
}

/// One `iam_user` object per IAM user, merging the credential report with the
/// inline-policy counts and the account password policy.
fn user_objects(
    report: &[CredentialRow],
    inline_counts: &HashMap<String, u64>,
    max_password_age: Option<u64>,
    now: DateTime<Utc>,
) -> Vec<Value> {
    let mut out = Vec::new();
    for row in report {
        // The `<root_account>` row is deliberately skipped. The report states
        // root's `password_enabled` as `not_supported`, so `has_console_access`
        // cannot be answered for it, and the CIS 1.4 control it would serve is
        // answered properly by `aws_iam_account_summary`.
        if row.is_root {
            continue;
        }
        // Every user in the report must also be in the IAM user listing; if it
        // is not, the listing was partial and `inline_policies_count` would be
        // invented as 0 — which reads as compliant.
        let Some(inline) = inline_counts.get(&row.user) else {
            tracing::warn!(
                user = %row.user,
                "AWS: user is in the credential report but not in the IAM user listing; skipped"
            );
            continue;
        };

        let mut obj = Map::new();
        obj.insert("name".into(), json!(row.user));
        obj.insert("arn".into(), json!(row.arn));
        obj.insert("has_access_key".into(), json!(row.has_active_access_key()));
        obj.insert("has_console_access".into(), json!(row.password_enabled));
        obj.insert("mfa_active".into(), json!(row.mfa_active));
        obj.insert("inline_policies_count".into(), json!(inline));
        // The report's only rotation signal is `access_key_N_last_rotated`,
        // which for a never-rotated key is its creation date — so the key's age
        // and the time since its last rotation are the same number here.
        let age = row.oldest_active_key_age_days(now);
        obj.insert("access_key_age_days".into(), json!(age));
        obj.insert("access_key_last_rotated_days".into(), json!(age));
        // Left out when the policy does not expire passwords; see
        // `normalize_password_policy` for why no number is invented.
        if let Some(max_age) = max_password_age {
            obj.insert("password_max_age_days".into(), json!(max_age));
        }
        out.push(Value::Object(obj));
    }
    out
}

/// The single `aws_iam_credential_report` object.
fn credential_report_object(
    report: &[CredentialRow],
    now: DateTime<Utc>,
) -> Result<Value, ProviderError> {
    // Every credential report contains the root row. Its absence means the
    // report was truncated or malformed, and a report without root cannot
    // answer CIS 1.7 at all.
    let root = report.iter().find(|r| r.is_root).ok_or_else(|| {
        ProviderError::Api("IAM credential report has no <root_account> row".to_string())
    })?;
    let root_last_used_days = root.root_last_used_days(now).ok_or_else(|| {
        ProviderError::Api(
            "IAM credential report gives root neither a last-use nor a creation date".to_string(),
        )
    })?;

    let users: Vec<Value> = report
        .iter()
        .filter(|r| !r.is_root)
        .map(|r| {
            json!({
                "name": r.user,
                "active_access_keys": r.active_access_keys(),
                "access_key_age_days": r.oldest_active_key_age_days(now),
                "access_key_last_used_days": r.stalest_active_key_unused_days(now),
                "console_no_mfa": r.password_enabled && !r.mfa_active,
            })
        })
        .collect();

    Ok(json!({ "root_last_used_days": root_last_used_days, "users": users }))
}

// ───────────────────────── normalizers ─────────────────────────

/// Cloud Control properties → the object shape the rules read, or `None` when
/// a property a rule reads is not answerable from this payload.
fn normalize(object: &str, props: &Value) -> Option<Value> {
    match object {
        "cloudtrail" => normalize_cloudtrail(props),
        "ebs_volume" => normalize_ebs_volume(props),
        "ecr_repository" => normalize_ecr_repository(props),
        "eks_cluster" => normalize_eks_cluster(props),
        "kms_key" => normalize_kms_key(props),
        "rds_cluster" => normalize_rds_cluster(props),
        "rds_instance" => normalize_rds_instance(props),
        "s3_bucket" => normalize_s3_bucket(props),
        "security_group" => normalize_security_group(props),
        "sns_topic" => normalize_sns_topic(props),
        "sqs_queue" => normalize_sqs_queue(props),
        _ => None,
    }
}

fn normalize_cloudtrail(p: &Value) -> Option<Value> {
    Some(json!({
        "name": p.get("TrailName").cloned().unwrap_or(Value::Null),
        "arn": p.get("Arn").cloned().unwrap_or(Value::Null),
        "s3_bucket_name": p.get("S3BucketName").and_then(|v| v.as_str())?,
        "is_multi_region_trail": as_bool(p.get("IsMultiRegionTrail")?)?,
        "enable_log_file_validation": as_bool(p.get("EnableLogFileValidation")?)?,
        // DescribeTrails returns CloudWatchLogsLogGroupArn only for trails wired
        // to CloudWatch Logs; its absence is the answer "not wired", which is
        // exactly what `DIFFERENT ""` tests.
        "cloud_watch_logs_group_arn": p
            .get("CloudWatchLogsLogGroupArn")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
    }))
}

fn normalize_ebs_volume(p: &Value) -> Option<Value> {
    Some(json!({
        "id": p.get("VolumeId").cloned().unwrap_or(Value::Null),
        "encrypted": as_bool(p.get("Encrypted")?)?,
    }))
}

fn normalize_ecr_repository(p: &Value) -> Option<Value> {
    // Both are always present in a complete DescribeRepositories answer — ECR
    // reports `AES256` for the default and `scanOnPush: false` when scanning is
    // off — so an absent field means the read was partial, not that the feature
    // is disabled. Writing `AES256` or `false` here would put a verdict on a
    // repository nobody looked at.
    let encryption_type = p
        .pointer("/EncryptionConfiguration/EncryptionType")
        .and_then(|v| v.as_str())?;
    let scan_on_push = as_bool(p.pointer("/ImageScanningConfiguration/ScanOnPush")?)?;
    Some(json!({
        "name": p.get("RepositoryName").cloned().unwrap_or(Value::Null),
        // The rules address these through Terraform's list-of-one shape.
        "encryption_configuration": [{ "encryption_type": encryption_type }],
        "image_scanning_configuration": [{ "scan_on_push": scan_on_push }],
    }))
}

fn normalize_eks_cluster(p: &Value) -> Option<Value> {
    // DescribeCluster always returns resourcesVpcConfig, so its presence is the
    // signal that we hold a complete cluster body; only then is an absent
    // `Logging` safely read as "no log type enabled".
    let endpoint_public_access = as_bool(p.pointer("/ResourcesVpcConfig/EndpointPublicAccess")?)?;

    let enabled_log_types: Vec<Value> = p
        .pointer("/Logging/ClusterLogging/EnabledTypes")
        .and_then(|v| v.as_array())
        .map(|types| {
            types
                .iter()
                .filter_map(|t| t.get("Type").cloned())
                .collect()
        })
        .unwrap_or_default();

    // The rule tests `encryption_config DIFFERENT ""`, so "no envelope
    // encryption" has to be the empty string rather than an empty array: `[]`
    // is different from `""` and would silently pass.
    let encryption_config = match p.get("EncryptionConfig").and_then(|v| v.as_array()) {
        Some(cfg) if !cfg.is_empty() => Value::Array(cfg.clone()),
        _ => Value::String(String::new()),
    };

    Some(json!({
        "name": p.get("Name").cloned().unwrap_or(Value::Null),
        "endpoint_public_access": endpoint_public_access,
        "enabled_cluster_log_types": enabled_log_types,
        "encryption_config": encryption_config,
    }))
}

fn normalize_kms_key(p: &Value) -> Option<Value> {
    Some(json!({
        "id": p.get("KeyId").cloned().unwrap_or(Value::Null),
        "arn": p.get("Arn").cloned().unwrap_or(Value::Null),
        "rotation_enabled": as_bool(p.get("EnableKeyRotation")?)?,
    }))
}

fn normalize_rds_cluster(p: &Value) -> Option<Value> {
    Some(json!({
        "id": p.get("DBClusterIdentifier").cloned().unwrap_or(Value::Null),
        "storage_encrypted": as_bool(p.get("StorageEncrypted")?)?,
    }))
}

fn normalize_rds_instance(p: &Value) -> Option<Value> {
    // All six come from DescribeDBInstances, which returns each of them for
    // every engine (MonitoringInterval is 0 when enhanced monitoring is off).
    // Requiring all six means an instance is dropped, loudly, rather than
    // scored on five real fields and one guess.
    Some(json!({
        "id": p.get("DBInstanceIdentifier").cloned().unwrap_or(Value::Null),
        "storage_encrypted": as_bool(p.get("StorageEncrypted")?)?,
        "auto_minor_version_upgrade": as_bool(p.get("AutoMinorVersionUpgrade")?)?,
        "publicly_accessible": as_bool(p.get("PubliclyAccessible")?)?,
        "multi_az": as_bool(p.get("MultiAZ")?)?,
        "backup_retention_period": as_u64(p.get("BackupRetentionPeriod")?)?,
        "monitoring_interval": as_u64(p.get("MonitoringInterval")?)?,
    }))
}

fn normalize_s3_bucket(p: &Value) -> Option<Value> {
    // Since January 2023 every bucket has SSE-S3 applied by default and
    // GetBucketEncryption always returns a configuration. An absent
    // `BucketEncryption` therefore means Cloud Control did not carry it, not
    // that the bucket is unencrypted — and `""` here would flag every bucket in
    // the account. Its presence also anchors the rest of this payload as a
    // complete read.
    let sse = p
        .pointer("/BucketEncryption/ServerSideEncryptionConfiguration")
        .and_then(|v| v.as_array())
        .filter(|rules| !rules.is_empty())?;

    // GetBucketVersioning genuinely answers nothing for a bucket that was never
    // versioned, so an absent VersioningConfiguration is the answer "off".
    let versioning_enabled = p
        .pointer("/VersioningConfiguration/Status")
        .and_then(|v| v.as_str())
        == Some("Enabled");

    Some(json!({
        "name": p.get("BucketName").cloned().unwrap_or(Value::Null),
        "versioning": [{ "enabled": versioning_enabled }],
        "server_side_encryption_configuration": sse.clone(),
    }))
}

fn normalize_security_group(p: &Value) -> Option<Value> {
    Some(json!({
        "id": p.get("GroupId").cloned().unwrap_or(Value::Null),
        "name": p.get("GroupName").and_then(|v| v.as_str())?,
        // CloudFormation omits an empty list rather than sending `[]`, so no
        // `SecurityGroupIngress` means no ingress rule — which is the compliant
        // state CIS 5.4 is looking for on the default group.
        "ingress_rules_count": p
            .get("SecurityGroupIngress")
            .and_then(|v| v.as_array())
            .map(|r| r.len())
            .unwrap_or(0),
    }))
}

fn normalize_sns_topic(p: &Value) -> Option<Value> {
    // TopicArn is the primary identifier and is always in a complete read; it
    // anchors the absence of KmsMasterKeyId as "no CMK", which is what
    // GetTopicAttributes reports for an unencrypted topic.
    let arn = p.get("TopicArn").and_then(|v| v.as_str())?;
    Some(json!({
        "arn": arn,
        "name": p.get("TopicName").cloned().unwrap_or(Value::Null),
        "kms_master_key_id": p
            .get("KmsMasterKeyId")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
    }))
}

fn normalize_sqs_queue(p: &Value) -> Option<Value> {
    let arn = p.get("Arn").and_then(|v| v.as_str())?;
    Some(json!({
        "arn": arn,
        "name": p.get("QueueName").cloned().unwrap_or(Value::Null),
        // Note for whoever reads a finding here: the rule only looks at the
        // customer-managed key. A queue using SSE-SQS (`SqsManagedSseEnabled`)
        // is encrypted but has no KmsMasterKeyId, and will be reported.
        "kms_master_key_id": p
            .get("KmsMasterKeyId")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
    }))
}

fn normalize_role(object: &str, p: &Value, support_role_exists: bool) -> Option<Value> {
    let arn = p.get("Arn").and_then(|v| v.as_str())?;
    let trust = policy_document(p.get("AssumeRolePolicyDocument")?)?;
    let own_account = account_id_from_arn(arn)?;

    match object {
        "aws_iam_role" => Some(json!({
            "name": p.get("RoleName").cloned().unwrap_or(Value::Null),
            "arn": arn,
            "has_star_principal": trust_has_star_principal(&trust),
            "cross_account_without_external_id":
                trust_is_cross_account_without_external_id(&trust, &own_account),
            "support_role_exists": support_role_exists,
        })),
        "iam_role" => {
            let managed = managed_policy_arns(Some(p));
            let inline_admin = inline_policies(p)
                .iter()
                .any(policy_grants_full_admin);
            Some(json!({
                "name": p.get("RoleName").cloned().unwrap_or(Value::Null),
                "arn": arn,
                "has_admin_policy": managed.contains(&ADMINISTRATOR_ACCESS_ARN) || inline_admin,
            }))
        }
        _ => None,
    }
}

/// Password policy → the two object shapes that read it.
///
/// `MaxPasswordAge` and `PasswordReusePrevention` are returned by IAM **only
/// when they are set**. They are left out rather than zeroed:
///
/// * a missing `password_reuse_prevention` fails `SUP_OR_EQUAL 24`, which is
///   the correct verdict for a policy that has none;
/// * a missing `max_password_age` makes `INF_OR_EQUAL 90` pass, so a
///   never-expire policy is *not* flagged. That is a false negative, and it is
///   a limitation of the rule rather than of this data: `aws-cis-1.11` reads a
///   scalar age and has no way to express "passwords never expire". The fix
///   belongs in the rule (it should also require `expire_passwords == true`),
///   not in a number invented here.
fn normalize_password_policy(object: &str, p: &Value) -> Option<Value> {
    let min_length = as_u64(p.get("MinimumPasswordLength")?)?;
    let mut obj = Map::new();
    obj.insert("minimum_password_length".into(), json!(min_length));
    if let Some(reuse) = p.get("PasswordReusePrevention").and_then(as_u64) {
        obj.insert("password_reuse_prevention".into(), json!(reuse));
    }

    if object == "iam_account_password_policy" {
        // These four are always in the response when a policy exists.
        for (aws_name, rule_name) in [
            ("RequireUppercaseCharacters", "require_uppercase_characters"),
            ("RequireLowercaseCharacters", "require_lowercase_characters"),
            ("RequireNumbers", "require_numbers"),
            ("RequireSymbols", "require_symbols"),
        ] {
            obj.insert(rule_name.into(), json!(as_bool(p.get(aws_name)?)?));
        }
        if let Some(max_age) = p.get("MaxPasswordAge").and_then(as_u64) {
            obj.insert("max_password_age".into(), json!(max_age));
        }
        // Not read by any rule today, but it is the field that actually answers
        // "do passwords expire?" and it costs nothing to carry.
        if let Some(expire) = p.get("ExpirePasswords").and_then(as_bool) {
            obj.insert("expire_passwords".into(), json!(expire));
        }
    }

    Some(Value::Object(obj))
}

// ───────────────────────── IAM policy reading ─────────────────────────

/// A policy document as CloudFormation may hand it over: already an object, or
/// a JSON string, or a percent-encoded JSON string (the IAM Query API's form).
fn policy_document(raw: &Value) -> Option<Value> {
    match raw {
        Value::Object(_) => Some(raw.clone()),
        Value::String(s) => serde_json::from_str(s)
            .ok()
            .or_else(|| serde_json::from_str(&percent_decode(s)).ok()),
        _ => None,
    }
}

fn statements(doc: &Value) -> Vec<&Value> {
    match doc.get("Statement") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(single @ Value::Object(_)) => vec![single],
        _ => Vec::new(),
    }
}

/// A JSON field that AWS renders as either a scalar or a list.
fn string_list(v: Option<&Value>) -> Vec<&str> {
    match v {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).collect(),
        _ => Vec::new(),
    }
}

fn is_allow(stmt: &Value) -> bool {
    stmt.get("Effect").and_then(|v| v.as_str()) == Some("Allow")
}

/// `Action: "*"` on `Resource: "*"` in a single Allow — the `*:*` grant CIS 1.16
/// is about.
fn policy_grants_full_admin(doc: &Value) -> bool {
    statements(doc).iter().any(|stmt| {
        is_allow(stmt)
            && string_list(stmt.get("Action")).contains(&"*")
            && string_list(stmt.get("Resource")).contains(&"*")
    })
}

fn trust_has_star_principal(doc: &Value) -> bool {
    statements(doc).iter().any(|stmt| {
        if !is_allow(stmt) {
            return false;
        }
        match stmt.get("Principal") {
            Some(Value::String(s)) => s == "*",
            Some(p @ Value::Object(_)) => string_list(p.get("AWS")).contains(&"*"),
            _ => false,
        }
    })
}

/// A trust policy that lets another account assume the role without pinning an
/// external id (or an organization) is the classic confused-deputy setup.
fn trust_is_cross_account_without_external_id(doc: &Value, own_account: &str) -> bool {
    statements(doc).iter().any(|stmt| {
        if !is_allow(stmt) {
            return false;
        }
        let principals = match stmt.get("Principal") {
            Some(p @ Value::Object(_)) => string_list(p.get("AWS")),
            _ => return false,
        };
        let cross_account = principals.iter().any(|p| {
            // A bare "*" is the star-principal case, reported by its own field.
            *p != "*"
                && account_id_from_arn(p)
                    .or_else(|| twelve_digit_account(p))
                    .is_some_and(|acct| acct != own_account)
        });
        if !cross_account {
            return false;
        }
        !condition_pins_caller(stmt.get("Condition"))
    })
}

/// True when the statement's Condition block constrains *who* may assume, by
/// external id or by organization.
fn condition_pins_caller(condition: Option<&Value>) -> bool {
    let Some(Value::Object(operators)) = condition else {
        return false;
    };
    operators.values().any(|keys| match keys {
        Value::Object(map) => map.keys().any(|k| {
            let k = k.to_ascii_lowercase();
            k == "sts:externalid" || k == "aws:principalorgid" || k == "aws:principalorgpaths"
        }),
        _ => false,
    })
}

fn account_id_from_arn(arn: &str) -> Option<String> {
    let account = arn.split(':').nth(4)?;
    twelve_digit_account(account)
}

fn twelve_digit_account(s: &str) -> Option<String> {
    (s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.to_string())
}

/// CloudFormation omits `ManagedPolicyArns` when nothing is attached.
fn managed_policy_arns(props: Option<&Value>) -> Vec<&str> {
    string_list(props.and_then(|p| p.get("ManagedPolicyArns")))
}

/// `Policies: [{PolicyName, PolicyDocument}]` — CloudFormation's inline policies.
fn inline_policies(props: &Value) -> Vec<Value> {
    props
        .get("Policies")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|entry| entry.get("PolicyDocument").and_then(policy_document))
                .collect()
        })
        .unwrap_or_default()
}

fn inline_policy_count(props: &Value) -> u64 {
    props
        .get("Policies")
        .and_then(|v| v.as_array())
        .map(|p| p.len() as u64)
        .unwrap_or(0)
}

// ───────────────────────── credential report ─────────────────────────

/// One row of the IAM credential report, already interpreted.
#[derive(Debug, Clone)]
pub(crate) struct CredentialRow {
    pub user: String,
    pub arn: String,
    pub is_root: bool,
    pub password_enabled: bool,
    pub mfa_active: bool,
    pub user_creation_time: Option<DateTime<Utc>>,
    pub password_last_used: Option<DateTime<Utc>>,
    pub keys: Vec<AccessKeyRow>,
}

#[derive(Debug, Clone)]
pub(crate) struct AccessKeyRow {
    pub active: bool,
    pub last_rotated: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
}

impl CredentialRow {
    fn active_keys(&self) -> impl Iterator<Item = &AccessKeyRow> {
        self.keys.iter().filter(|k| k.active)
    }

    pub(crate) fn has_active_access_key(&self) -> bool {
        self.active_keys().next().is_some()
    }

    pub(crate) fn active_access_keys(&self) -> u64 {
        self.active_keys().count() as u64
    }

    /// Age of the oldest active access key, in days. A user with no active key
    /// has no stale key, and `0` is the answer to "how old is the oldest one" —
    /// not a placeholder for an answer the report withheld.
    pub(crate) fn oldest_active_key_age_days(&self, now: DateTime<Utc>) -> i64 {
        self.active_keys()
            .filter_map(|k| k.last_rotated)
            .map(|t| days_between(t, now))
            .max()
            .unwrap_or(0)
    }

    /// Days since the most recently used active key was last used. A key that
    /// has never been used falls back to its own creation date — which is what
    /// `access_key_N_last_rotated` holds for a key that was never rotated — so
    /// "created 200 days ago, never used" reads as 200 days unused, not as 0.
    pub(crate) fn stalest_active_key_unused_days(&self, now: DateTime<Utc>) -> i64 {
        self.active_keys()
            .filter_map(|k| k.last_used.or(k.last_rotated))
            .map(|t| days_between(t, now))
            .max()
            .unwrap_or(0)
    }

    /// Days since root last did anything: the most recent of its password use
    /// and its access-key uses. When root has never been used, the report still
    /// gives its creation date, and "unused since the account was created" is a
    /// fact the report states — not a value invented to fill a gap.
    pub(crate) fn root_last_used_days(&self, now: DateTime<Utc>) -> Option<i64> {
        let latest = std::iter::once(self.password_last_used)
            .chain(self.keys.iter().map(|k| k.last_used))
            .flatten()
            .max()
            .or(self.user_creation_time)?;
        Some(days_between(latest, now))
    }
}

/// Parse the credential report CSV.
///
/// The report has a fixed header and no quoted fields, so it is split by
/// column name rather than by position — AWS has added columns over time and
/// positional parsing silently shifts everything when it does.
pub(crate) fn parse_credential_report(csv: &str) -> Vec<CredentialRow> {
    let mut lines = csv.lines().filter(|l| !l.trim().is_empty());
    let Some(header) = lines.next() else {
        return Vec::new();
    };
    let columns: Vec<&str> = header.split(',').map(|c| c.trim()).collect();
    let index = |name: &str| columns.iter().position(|c| *c == name);

    let col_user = index("user");
    let col_arn = index("arn");
    let col_created = index("user_creation_time");
    let col_password = index("password_enabled");
    let col_password_used = index("password_last_used");
    let col_mfa = index("mfa_active");

    let mut rows = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split(',').collect();
        let get = |i: Option<usize>| i.and_then(|i| fields.get(i)).map(|s| s.trim()).unwrap_or("");

        let user = get(col_user).to_string();
        if user.is_empty() {
            continue;
        }

        let mut keys = Vec::new();
        for n in 1..=2 {
            let active = index(&format!("access_key_{n}_active"));
            let rotated = index(&format!("access_key_{n}_last_rotated"));
            let used = index(&format!("access_key_{n}_last_used_date"));
            if active.is_none() {
                continue;
            }
            keys.push(AccessKeyRow {
                active: get(active) == "true",
                last_rotated: parse_report_timestamp(get(rotated)),
                last_used: parse_report_timestamp(get(used)),
            });
        }

        rows.push(CredentialRow {
            is_root: user == "<root_account>",
            // `password_enabled` is `not_supported` on the root row, which is
            // neither true nor false; it reads as false here and the root row is
            // excluded from the `iam_user` object for exactly that reason.
            password_enabled: get(col_password) == "true",
            mfa_active: get(col_mfa) == "true",
            user_creation_time: parse_report_timestamp(get(col_created)),
            password_last_used: parse_report_timestamp(get(col_password_used)),
            arn: get(col_arn).to_string(),
            user,
            keys,
        });
    }
    rows
}

/// The report writes `N/A`, `no_information` and `not_supported` where there is
/// no timestamp. All three mean "no date", and none of them means "today".
fn parse_report_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    match raw {
        "" | "N/A" | "not_supported" | "no_information" => None,
        other => parse_aws_timestamp(other),
    }
}

fn parse_aws_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn days_between(from: DateTime<Utc>, to: DateTime<Utc>) -> i64 {
    (to - from).num_days()
}

// ───────────────────────── IAM XML ─────────────────────────

/// Minimal XML reader for the IAM Query protocol.
///
/// The workspace has no XML dependency and this file may not add one, so this
/// covers exactly the subset IAM emits: elements, text, self-closing tags,
/// comments, the XML declaration, and the five predefined entities. Attributes
/// are skipped — IAM puts data in elements, never in attributes. Repeated
/// sibling elements (`<member>`) collapse into an array.
///
/// Returns the root element's content, so `/GetAccountSummaryResult/SummaryMap`
/// addresses the same path a JSON reader would use.
fn parse_xml(input: &str) -> Option<Value> {
    let bytes = input.as_bytes();
    let mut pos = 0usize;
    // (element name, children, accumulated text)
    let mut stack: Vec<(String, Map<String, Value>, String)> = Vec::new();
    let mut root: Option<Value> = None;

    while pos < bytes.len() {
        let Some(open) = find_byte(bytes, pos, b'<') else {
            break;
        };
        if open > pos {
            if let Some(top) = stack.last_mut() {
                top.2.push_str(&unescape_xml(&input[pos..open]));
            }
        }
        // An unterminated tag means the document is truncated; the caller gets
        // None rather than a half-read body.
        let close = find_byte(bytes, open + 1, b'>')?;
        let tag = &input[open + 1..close];
        pos = close + 1;

        if tag.starts_with('?') || tag.starts_with('!') {
            continue; // declaration, comment, doctype
        }

        if let Some(name) = tag.strip_prefix('/') {
            let (open_name, children, text) = stack.pop()?;
            if open_name != name.trim() {
                return None;
            }
            let value = if children.is_empty() {
                Value::String(text.trim().to_string())
            } else {
                Value::Object(children)
            };
            match stack.last_mut() {
                Some(parent) => insert_repeatable(&mut parent.1, &open_name, value),
                None => root = Some(value),
            }
            continue;
        }

        let self_closing = tag.ends_with('/');
        let name = tag
            .trim_end_matches('/')
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        if name.is_empty() {
            return None;
        }
        if self_closing {
            match stack.last_mut() {
                Some(parent) => {
                    insert_repeatable(&mut parent.1, &name, Value::String(String::new()))
                }
                None => root = Some(Value::String(String::new())),
            }
        } else {
            stack.push((name, Map::new(), String::new()));
        }
    }

    stack.is_empty().then_some(root).flatten()
}

/// Second and further siblings of the same name turn the entry into an array.
fn insert_repeatable(map: &mut Map<String, Value>, name: &str, value: Value) {
    match map.get_mut(name) {
        Some(Value::Array(existing)) => existing.push(value),
        Some(slot) => {
            let first = slot.take();
            *slot = Value::Array(vec![first, value]);
        }
        None => {
            map.insert(name.to_string(), value);
        }
    }
}

fn find_byte(haystack: &[u8], from: usize, needle: u8) -> Option<usize> {
    haystack[from..].iter().position(|b| *b == needle).map(|i| i + from)
}

fn unescape_xml(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp..];
        match after.find(';').map(|end| (&after[1..end], end)) {
            Some((entity, end)) => {
                match entity {
                    "amp" => out.push('&'),
                    "lt" => out.push('<'),
                    "gt" => out.push('>'),
                    "quot" => out.push('"'),
                    "apos" => out.push('\''),
                    numeric if numeric.starts_with('#') => {
                        let parsed = if let Some(hex) = numeric
                            .strip_prefix("#x")
                            .or_else(|| numeric.strip_prefix("#X"))
                        {
                            u32::from_str_radix(hex, 16).ok()
                        } else {
                            numeric[1..].parse::<u32>().ok()
                        };
                        match parsed.and_then(char::from_u32) {
                            Some(c) => out.push(c),
                            None => out.push_str(&after[..=end]),
                        }
                    }
                    _ => out.push_str(&after[..=end]),
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(after);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Depth-first search for the first element with this name — used only to pull
/// `<Code>` out of an IAM error body, whose nesting differs between services.
fn find_first<'a>(doc: &'a Value, name: &str) -> Option<&'a Value> {
    match doc {
        Value::Object(map) => {
            if let Some(hit) = map.get(name) {
                return Some(hit);
            }
            map.values().find_map(|v| find_first(v, name))
        }
        Value::Array(items) => items.iter().find_map(|v| find_first(v, name)),
        _ => None,
    }
}

/// `<Xs><member>…</member></Xs>` — one member parses to an object, several to an
/// array, and none to nothing. All three have to walk the same way.
fn members(list: Option<&Value>) -> Vec<&Value> {
    match list.and_then(|l| l.get("member")) {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(single) => vec![single],
        None => Vec::new(),
    }
}

/// IAM's `SummaryMap` serializes as `<entry><key/><value/></entry>` pairs.
fn summary_map(map: &Value) -> HashMap<String, i64> {
    let entries = match map.get("entry") {
        Some(Value::Array(items)) => items.iter().collect::<Vec<_>>(),
        Some(single) => vec![single],
        None => Vec::new(),
    };
    entries
        .into_iter()
        .filter_map(|e| {
            let key = e.get("key")?.as_str()?.to_string();
            let value = e.get("value")?.as_str()?.parse::<i64>().ok()?;
            Some((key, value))
        })
        .collect()
}

/// IAM paginates with `IsTruncated` + `Marker`.
fn next_marker(result: &Value) -> Option<String> {
    let truncated = result
        .get("IsTruncated")
        .and_then(|v| v.as_str())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if !truncated {
        return None;
    }
    result
        .get("Marker")
        .and_then(|v| v.as_str())
        .filter(|m| !m.is_empty())
        .map(String::from)
}

// ───────────────────────── small helpers ─────────────────────────

/// AWS answers booleans as JSON booleans over Cloud Control and as the strings
/// `true`/`false` over the Query protocol. Anything else is not a boolean and
/// must not be coerced into one.
fn as_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn as_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .ok()
}

/// IAM's Query API returns policy documents percent-encoded.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap()
    }

    // ── declaration discipline ────────────────────────────────────────────

    #[test]
    fn every_cloud_control_object_is_declared() {
        for (object, _) in CLOUD_CONTROL_OBJECTS {
            assert!(
                RESOURCE_TYPES.contains(object),
                "{object} is mapped to a CloudFormation type but not declared"
            );
        }
    }

    #[test]
    fn declared_objects_are_sorted_and_unique() {
        let mut sorted = RESOURCE_TYPES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.as_slice(), RESOURCE_TYPES);
    }

    /// The objects deliberately left out must stay out: each was excluded
    /// because at least one property its rules read cannot be answered, and
    /// adding it back without that property manufactures findings.
    #[test]
    fn knowingly_unanswerable_objects_stay_out() {
        for object in [
            "instance",
            "security_group_rule",
            "cloudwatch_log_group",
            "load_balancer",
            "lambda_function",
            "secrets_manager",
            "s3_account_public_access_block",
            "ebs_encryption_by_default",
            "aws_iam_policy",
            "aws_accessanalyzer_analyzer",
        ] {
            assert!(
                !RESOURCE_TYPES.contains(&object),
                "{object} is declared but at least one property its rules read is unanswerable"
            );
        }
    }

    // ── Cloud Control envelope ────────────────────────────────────────────

    /// `GetResource` nests the resource body as a JSON string, exactly as the
    /// Cloud Control API reference shows it.
    #[test]
    fn reads_the_cloud_control_get_resource_envelope() {
        let response: Value = serde_json::from_str(
            r#"{
              "TypeName": "AWS::Kinesis::Stream",
              "ResourceDescription": {
                "Identifier": "MyStream",
                "Properties": "{\"StreamEncryption\":{\"EncryptionType\":\"KMS\"},\"Name\":\"MyStream\",\"RetentionPeriodHours\":168,\"ShardCount\":3}"
              }
            }"#,
        )
        .unwrap();
        let props = resource_properties(&response).expect("Properties is a JSON string");
        assert_eq!(props["Name"], json!("MyStream"));
        assert_eq!(props["ShardCount"], json!(3));
        assert_eq!(props["StreamEncryption"]["EncryptionType"], json!("KMS"));
    }

    #[test]
    fn a_get_resource_without_properties_yields_nothing() {
        let response = json!({ "TypeName": "AWS::S3::Bucket" });
        assert!(resource_properties(&response).is_none());
    }

    // ── normalizers: completeness ─────────────────────────────────────────

    #[test]
    fn normalizes_a_cloudtrail_trail() {
        let props = json!({
            "TrailName": "org-trail",
            "Arn": "arn:aws:cloudtrail:eu-west-3:123456789012:trail/org-trail",
            "S3BucketName": "aws-cloudtrail-logs-123456789012",
            "IsLogging": true,
            "IsMultiRegionTrail": true,
            "IncludeGlobalServiceEvents": true,
            "EnableLogFileValidation": true,
            "CloudWatchLogsLogGroupArn": "arn:aws:logs:eu-west-3:123456789012:log-group:ct:*"
        });
        let t = normalize("cloudtrail", &props).unwrap();
        assert_eq!(t["is_multi_region_trail"], json!(true));
        assert_eq!(t["enable_log_file_validation"], json!(true));
        assert_eq!(t["s3_bucket_name"], json!("aws-cloudtrail-logs-123456789012"));
        assert!(t["cloud_watch_logs_group_arn"].as_str().unwrap().starts_with("arn:aws:logs:"));
    }

    /// No CloudWatch integration is an answer, not a hole: the trail is still
    /// served and `DIFFERENT ""` correctly reports it.
    #[test]
    fn a_trail_without_cloudwatch_is_still_served() {
        let t = normalize(
            "cloudtrail",
            &json!({
                "TrailName": "local",
                "S3BucketName": "b",
                "IsMultiRegionTrail": false,
                "EnableLogFileValidation": false
            }),
        )
        .unwrap();
        assert_eq!(t["cloud_watch_logs_group_arn"], json!(""));
        assert_eq!(t["is_multi_region_trail"], json!(false));
    }

    /// A trail whose payload lost `IsMultiRegionTrail` is dropped. Emitting it
    /// would let the engine read `""`, which is not `true`, and report a
    /// multi-region violation nobody can reproduce in the console.
    #[test]
    fn a_partially_read_trail_is_dropped_rather_than_scored() {
        let partial = json!({ "TrailName": "t", "S3BucketName": "b", "EnableLogFileValidation": true });
        assert!(normalize("cloudtrail", &partial).is_none());
    }

    #[test]
    fn normalizes_an_rds_instance() {
        let props = json!({
            "DBInstanceIdentifier": "prod-1",
            "Engine": "postgres",
            "StorageEncrypted": true,
            "AutoMinorVersionUpgrade": true,
            "PubliclyAccessible": false,
            "MultiAZ": true,
            "BackupRetentionPeriod": 7,
            "MonitoringInterval": 60
        });
        let db = normalize("rds_instance", &props).unwrap();
        assert_eq!(db["storage_encrypted"], json!(true));
        assert_eq!(db["publicly_accessible"], json!(false));
        assert_eq!(db["backup_retention_period"], json!(7));
        assert_eq!(db["monitoring_interval"], json!(60));

        // Any one of the six missing drops the instance.
        let mut short = props.clone();
        short.as_object_mut().unwrap().remove("MonitoringInterval");
        assert!(normalize("rds_instance", &short).is_none());
    }

    /// The rules address S3 through Terraform's list-of-one shape
    /// (`versioning.0.enabled`), so the normalizer has to produce it.
    #[test]
    fn normalizes_an_s3_bucket_into_the_shape_rules_address() {
        let props = json!({
            "BucketName": "kxn-artifacts",
            "VersioningConfiguration": { "Status": "Enabled" },
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": [
                    { "ServerSideEncryptionByDefault": { "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "arn:aws:kms:eu-west-3:123456789012:key/abc" },
                      "BucketKeyEnabled": true }
                ]
            }
        });
        let b = normalize("s3_bucket", &props).unwrap();
        assert_eq!(
            kxn_core::engine::property::get_sub_property(&b, "versioning.0.enabled"),
            Some(&json!(true))
        );
        assert_ne!(b["server_side_encryption_configuration"], json!(""));
    }

    #[test]
    fn a_never_versioned_bucket_reads_as_not_versioned() {
        let b = normalize(
            "s3_bucket",
            &json!({
                "BucketName": "b",
                "BucketEncryption": { "ServerSideEncryptionConfiguration": [
                    { "ServerSideEncryptionByDefault": { "SSEAlgorithm": "AES256" } }
                ]}
            }),
        )
        .unwrap();
        assert_eq!(
            kxn_core::engine::property::get_sub_property(&b, "versioning.0.enabled"),
            Some(&json!(false))
        );
    }

    /// Since 2023 every bucket reports an encryption configuration, so a
    /// payload without one is a partial read — and `""` there would flag the
    /// whole account.
    #[test]
    fn a_bucket_without_an_encryption_block_is_dropped() {
        assert!(normalize("s3_bucket", &json!({ "BucketName": "b" })).is_none());
    }

    #[test]
    fn normalizes_an_eks_cluster() {
        let props = json!({
            "Name": "prod",
            "ResourcesVpcConfig": {
                "EndpointPublicAccess": false,
                "EndpointPrivateAccess": true,
                "SubnetIds": ["subnet-a", "subnet-b"]
            },
            "Logging": { "ClusterLogging": { "EnabledTypes": [
                { "Type": "api" }, { "Type": "audit" }
            ]}},
            "EncryptionConfig": [
                { "Provider": { "KeyArn": "arn:aws:kms:eu-west-3:123456789012:key/abc" },
                  "Resources": ["secrets"] }
            ]
        });
        let c = normalize("eks_cluster", &props).unwrap();
        assert_eq!(c["endpoint_public_access"], json!(false));
        assert_eq!(c["enabled_cluster_log_types"], json!(["api", "audit"]));
        assert_ne!(c["encryption_config"], json!(""));
    }

    /// `encryption_config` has to be the empty string when there is none: the
    /// rule tests `DIFFERENT ""`, and an empty array would quietly satisfy it.
    #[test]
    fn a_cluster_without_envelope_encryption_reports_an_empty_string() {
        let c = normalize(
            "eks_cluster",
            &json!({ "Name": "c", "ResourcesVpcConfig": { "EndpointPublicAccess": true } }),
        )
        .unwrap();
        assert_eq!(c["encryption_config"], json!(""));
        assert_eq!(c["enabled_cluster_log_types"], json!([]));
    }

    #[test]
    fn normalizes_an_ecr_repository() {
        let r = normalize(
            "ecr_repository",
            &json!({
                "RepositoryName": "app",
                "ImageScanningConfiguration": { "ScanOnPush": true },
                "EncryptionConfiguration": { "EncryptionType": "KMS",
                    "KmsKey": "arn:aws:kms:eu-west-3:123456789012:key/abc" }
            }),
        )
        .unwrap();
        assert_eq!(
            kxn_core::engine::property::get_sub_property(
                &r,
                "image_scanning_configuration.0.scan_on_push"
            ),
            Some(&json!(true))
        );
        assert_eq!(
            kxn_core::engine::property::get_sub_property(
                &r,
                "encryption_configuration.0.encryption_type"
            ),
            Some(&json!("KMS"))
        );
    }

    #[test]
    fn normalizes_a_security_group_and_counts_its_ingress() {
        let sg = normalize(
            "security_group",
            &json!({
                "GroupId": "sg-0abc",
                "GroupName": "default",
                "GroupDescription": "default VPC security group",
                "VpcId": "vpc-0123",
                "SecurityGroupIngress": [
                    { "IpProtocol": "-1", "SourceSecurityGroupId": "sg-0abc" }
                ]
            }),
        )
        .unwrap();
        assert_eq!(sg["name"], json!("default"));
        assert_eq!(sg["ingress_rules_count"], json!(1));

        // CloudFormation omits the list when it is empty; that is zero rules,
        // which is the compliant state CIS 5.4 looks for.
        let empty = normalize(
            "security_group",
            &json!({ "GroupId": "sg-1", "GroupName": "default" }),
        )
        .unwrap();
        assert_eq!(empty["ingress_rules_count"], json!(0));
    }

    #[test]
    fn normalizes_queue_and_topic_encryption() {
        let topic = normalize(
            "sns_topic",
            &json!({ "TopicArn": "arn:aws:sns:eu-west-3:123456789012:alerts",
                     "TopicName": "alerts" }),
        )
        .unwrap();
        assert_eq!(topic["kms_master_key_id"], json!(""));

        let encrypted = normalize(
            "sqs_queue",
            &json!({ "Arn": "arn:aws:sqs:eu-west-3:123456789012:q", "QueueName": "q",
                     "KmsMasterKeyId": "alias/aws/sqs" }),
        )
        .unwrap();
        assert_eq!(encrypted["kms_master_key_id"], json!("alias/aws/sqs"));
    }

    #[test]
    fn a_kms_key_without_a_rotation_answer_is_dropped() {
        assert!(normalize("kms_key", &json!({ "KeyId": "abc" })).is_none());
        let k = normalize("kms_key", &json!({ "KeyId": "abc", "EnableKeyRotation": true })).unwrap();
        assert_eq!(k["rotation_enabled"], json!(true));
    }

    // ── IAM roles ─────────────────────────────────────────────────────────

    #[test]
    fn spots_a_star_principal_in_a_trust_policy() {
        let props = json!({
            "RoleName": "wide-open",
            "Arn": "arn:aws:iam::123456789012:role/wide-open",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{ "Effect": "Allow", "Principal": { "AWS": "*" },
                                "Action": "sts:AssumeRole" }]
            }
        });
        let r = normalize_role("aws_iam_role", &props, true).unwrap();
        assert_eq!(r["has_star_principal"], json!(true));
        assert_eq!(r["support_role_exists"], json!(true));
    }

    #[test]
    fn cross_account_trust_needs_an_external_id() {
        let bare = json!({
            "RoleName": "vendor",
            "Arn": "arn:aws:iam::123456789012:role/vendor",
            "AssumeRolePolicyDocument": { "Statement": [{
                "Effect": "Allow",
                "Principal": { "AWS": "arn:aws:iam::210987654321:root" },
                "Action": "sts:AssumeRole"
            }]}
        });
        assert_eq!(
            normalize_role("aws_iam_role", &bare, false).unwrap()["cross_account_without_external_id"],
            json!(true)
        );

        let pinned = json!({
            "RoleName": "vendor",
            "Arn": "arn:aws:iam::123456789012:role/vendor",
            "AssumeRolePolicyDocument": { "Statement": [{
                "Effect": "Allow",
                "Principal": { "AWS": "arn:aws:iam::210987654321:root" },
                "Action": "sts:AssumeRole",
                "Condition": { "StringEquals": { "sts:ExternalId": "kxn-4f2a" } }
            }]}
        });
        assert_eq!(
            normalize_role("aws_iam_role", &pinned, false).unwrap()["cross_account_without_external_id"],
            json!(false)
        );

        // Same account is not cross-account, external id or not.
        let same = json!({
            "RoleName": "app",
            "Arn": "arn:aws:iam::123456789012:role/app",
            "AssumeRolePolicyDocument": { "Statement": [{
                "Effect": "Allow",
                "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
                "Action": "sts:AssumeRole"
            }]}
        });
        assert_eq!(
            normalize_role("aws_iam_role", &same, false).unwrap()["cross_account_without_external_id"],
            json!(false)
        );

        // A service principal is not an account at all.
        let service = json!({
            "RoleName": "lambda-exec",
            "Arn": "arn:aws:iam::123456789012:role/lambda-exec",
            "AssumeRolePolicyDocument": { "Statement": [{
                "Effect": "Allow",
                "Principal": { "Service": "lambda.amazonaws.com" },
                "Action": "sts:AssumeRole"
            }]}
        });
        let s = normalize_role("aws_iam_role", &service, false).unwrap();
        assert_eq!(s["cross_account_without_external_id"], json!(false));
        assert_eq!(s["has_star_principal"], json!(false));
    }

    #[test]
    fn detects_admin_through_managed_and_inline_policies() {
        let base = |extra: Value| {
            let mut props = json!({
                "RoleName": "r",
                "Arn": "arn:aws:iam::123456789012:role/r",
                "AssumeRolePolicyDocument": { "Statement": [] }
            });
            let obj = props.as_object_mut().unwrap();
            for (k, v) in extra.as_object().unwrap() {
                obj.insert(k.clone(), v.clone());
            }
            props
        };

        let managed = base(json!({ "ManagedPolicyArns": [ADMINISTRATOR_ACCESS_ARN] }));
        assert_eq!(
            normalize_role("iam_role", &managed, false).unwrap()["has_admin_policy"],
            json!(true)
        );

        let inline = base(json!({ "Policies": [{
            "PolicyName": "everything",
            "PolicyDocument": { "Statement": [
                { "Effect": "Allow", "Action": "*", "Resource": "*" }
            ]}
        }]}));
        assert_eq!(
            normalize_role("iam_role", &inline, false).unwrap()["has_admin_policy"],
            json!(true)
        );

        let scoped = base(json!({ "Policies": [{
            "PolicyName": "reader",
            "PolicyDocument": { "Statement": [
                { "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*" }
            ]}
        }]}));
        assert_eq!(
            normalize_role("iam_role", &scoped, false).unwrap()["has_admin_policy"],
            json!(false)
        );

        // A Deny on *:* is not an admin grant.
        let denied = base(json!({ "Policies": [{
            "PolicyName": "deny-all",
            "PolicyDocument": { "Statement": [
                { "Effect": "Deny", "Action": "*", "Resource": "*" }
            ]}
        }]}));
        assert_eq!(
            normalize_role("iam_role", &denied, false).unwrap()["has_admin_policy"],
            json!(false)
        );
    }

    #[test]
    fn a_role_without_a_trust_policy_is_dropped() {
        let props = json!({ "RoleName": "r", "Arn": "arn:aws:iam::123456789012:role/r" });
        assert!(normalize_role("aws_iam_role", &props, false).is_none());
    }

    #[test]
    fn reads_a_percent_encoded_trust_policy() {
        // The IAM Query API hands policy documents over percent-encoded.
        let encoded = "%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22*%22%7D%7D%5D%7D";
        let doc = policy_document(&json!(encoded)).expect("percent-encoded JSON");
        assert!(trust_has_star_principal(&doc));
    }

    // ── IAM XML ───────────────────────────────────────────────────────────

    /// The documented GetAccountSummary response shape.
    #[test]
    fn parses_the_iam_account_summary() {
        let xml = r#"<GetAccountSummaryResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetAccountSummaryResult>
    <SummaryMap>
      <entry><key>Users</key><value>16</value></entry>
      <entry><key>AccountMFAEnabled</key><value>0</value></entry>
      <entry><key>AccountAccessKeysPresent</key><value>1</value></entry>
      <entry><key>Groups</key><value>3</value></entry>
    </SummaryMap>
  </GetAccountSummaryResult>
  <ResponseMetadata>
    <RequestId>f1e38443-f1ad-11df-b1ef-a9265EXAMPLE</RequestId>
  </ResponseMetadata>
</GetAccountSummaryResponse>"#;
        let doc = parse_xml(xml).expect("valid IAM XML");
        let map = summary_map(doc.pointer("/GetAccountSummaryResult/SummaryMap").unwrap());
        assert_eq!(map.get("AccountMFAEnabled"), Some(&0));
        assert_eq!(map.get("AccountAccessKeysPresent"), Some(&1));
        assert_eq!(map.get("Users"), Some(&16));
    }

    #[test]
    fn parses_the_iam_password_policy() {
        let xml = r#"<GetAccountPasswordPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetAccountPasswordPolicyResult>
    <PasswordPolicy>
      <AllowUsersToChangePassword>true</AllowUsersToChangePassword>
      <RequireUppercaseCharacters>true</RequireUppercaseCharacters>
      <RequireSymbols>true</RequireSymbols>
      <ExpirePasswords>true</ExpirePasswords>
      <PasswordReusePrevention>24</PasswordReusePrevention>
      <RequireLowercaseCharacters>true</RequireLowercaseCharacters>
      <MaxPasswordAge>90</MaxPasswordAge>
      <RequireNumbers>true</RequireNumbers>
      <MinimumPasswordLength>14</MinimumPasswordLength>
      <HardExpiry>false</HardExpiry>
    </PasswordPolicy>
  </GetAccountPasswordPolicyResult>
  <ResponseMetadata><RequestId>7a62c49f-347e-4fc4-9331-6e8eEXAMPLE</RequestId></ResponseMetadata>
</GetAccountPasswordPolicyResponse>"#;
        let doc = parse_xml(xml).unwrap();
        let policy = doc
            .pointer("/GetAccountPasswordPolicyResult/PasswordPolicy")
            .unwrap();

        let short = normalize_password_policy("aws_iam_account_password_policy", policy).unwrap();
        assert_eq!(short["minimum_password_length"], json!(14));
        assert_eq!(short["password_reuse_prevention"], json!(24));

        let full = normalize_password_policy("iam_account_password_policy", policy).unwrap();
        assert_eq!(full["max_password_age"], json!(90));
        assert_eq!(full["require_symbols"], json!(true));
        assert_eq!(full["require_numbers"], json!(true));
        assert_eq!(full["require_uppercase_characters"], json!(true));
        assert_eq!(full["require_lowercase_characters"], json!(true));
    }

    /// A policy that does not expire passwords has no `MaxPasswordAge` in the
    /// response. The field stays out — no invented number stands in for it.
    #[test]
    fn a_never_expiring_policy_carries_no_invented_max_age() {
        let policy = json!({
            "MinimumPasswordLength": "8",
            "RequireUppercaseCharacters": "false",
            "RequireLowercaseCharacters": "false",
            "RequireNumbers": "false",
            "RequireSymbols": "false",
            "ExpirePasswords": "false"
        });
        let full = normalize_password_policy("iam_account_password_policy", &policy).unwrap();
        assert!(full.get("max_password_age").is_none());
        assert!(full.get("password_reuse_prevention").is_none());
        assert_eq!(full["expire_passwords"], json!(false));
        assert_eq!(full["minimum_password_length"], json!(8));
    }

    #[test]
    fn parses_virtual_mfa_devices_and_spots_root() {
        let xml = r#"<ListVirtualMFADevicesResponse>
  <ListVirtualMFADevicesResult>
    <IsTruncated>false</IsTruncated>
    <VirtualMFADevices>
      <member>
        <SerialNumber>arn:aws:iam::123456789012:mfa/root-account-mfa-device</SerialNumber>
        <User>
          <UserId>123456789012</UserId>
          <Arn>arn:aws:iam::123456789012:root</Arn>
          <CreateDate>2024-01-15T10:00:00Z</CreateDate>
        </User>
        <EnableDate>2024-02-01T09:00:00Z</EnableDate>
      </member>
    </VirtualMFADevices>
  </ListVirtualMFADevicesResult>
</ListVirtualMFADevicesResponse>"#;
        let doc = parse_xml(xml).unwrap();
        let result = doc.get("ListVirtualMFADevicesResult").unwrap();
        let devices = members(result.get("VirtualMFADevices"));
        assert_eq!(devices.len(), 1);
        assert!(devices[0]
            .pointer("/User/Arn")
            .and_then(|v| v.as_str())
            .unwrap()
            .ends_with(":root"));
        assert!(next_marker(result).is_none());
    }

    /// A single `<member>` parses to an object and several to an array; both
    /// have to walk the same way or a one-certificate account reads as zero.
    #[test]
    fn one_member_and_many_members_walk_alike() {
        let one = parse_xml("<R><L><member><A>1</A></member></L></R>").unwrap();
        let many =
            parse_xml("<R><L><member><A>1</A></member><member><A>2</A></member></L></R>").unwrap();
        assert_eq!(members(one.get("L")).len(), 1);
        assert_eq!(members(many.get("L")).len(), 2);
        assert_eq!(members(None).len(), 0);
    }

    #[test]
    fn parses_server_certificate_metadata() {
        let xml = r#"<ListServerCertificatesResponse>
  <ListServerCertificatesResult>
    <IsTruncated>false</IsTruncated>
    <ServerCertificateMetadataList>
      <member>
        <ServerCertificateId>ASCACKCEVSQ6C2EXAMPLE</ServerCertificateId>
        <ServerCertificateName>ProdServerCert</ServerCertificateName>
        <Expiration>2012-05-08T01:02:03Z</Expiration>
        <Path>/company/servercerts/</Path>
        <Arn>arn:aws:iam::123456789012:server-certificate/company/servercerts/ProdServerCert</Arn>
        <UploadDate>2010-05-08T01:02:03Z</UploadDate>
      </member>
    </ServerCertificateMetadataList>
  </ListServerCertificatesResult>
</ListServerCertificatesResponse>"#;
        let doc = parse_xml(xml).unwrap();
        let certs = members(
            doc.pointer("/ListServerCertificatesResult")
                .unwrap()
                .get("ServerCertificateMetadataList"),
        );
        let expiration = certs[0].get("Expiration").unwrap().as_str().unwrap();
        let expires_at = parse_aws_timestamp(expiration).unwrap();
        assert!(expires_at < now(), "2012 certificate is expired in 2025");
    }

    #[test]
    fn xml_handles_entities_self_closing_tags_and_declarations() {
        let xml = r#"<?xml version="1.0"?>
<!-- a comment -->
<Root><Text>a &amp; b &lt;c&gt; &#65;</Text><Empty/><Nested><X>1</X></Nested></Root>"#;
        let doc = parse_xml(xml).unwrap();
        assert_eq!(doc["Text"], json!("a & b <c> A"));
        assert_eq!(doc["Empty"], json!(""));
        assert_eq!(doc["Nested"]["X"], json!("1"));
    }

    #[test]
    fn unbalanced_xml_is_rejected_rather_than_half_read() {
        assert!(parse_xml("<A><B>1</A>").is_none());
        assert!(parse_xml("<A><B>1</B>").is_none());
        assert!(parse_xml("not xml at all").is_none());
    }

    #[test]
    fn reads_the_error_code_from_both_aws_dialects() {
        assert_eq!(
            error_code(r#"{"__type":"com.amazon.coral.service#AccessDeniedException"}"#),
            "AccessDeniedException"
        );
        let iam_error = r#"<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <Error><Type>Sender</Type><Code>NoSuchEntity</Code>
  <Message>The Password Policy with domain name 123456789012 cannot be found.</Message></Error>
  <RequestId>c7e9f0b1</RequestId>
</ErrorResponse>"#;
        assert_eq!(error_code(iam_error), "NoSuchEntity");
        // A missing password policy must surface as NotFound so the collector
        // can tell "no policy" from "the call failed".
        assert!(matches!(
            classify_error(reqwest::StatusCode::NOT_FOUND, iam_error, "GetAccountPasswordPolicy"),
            ProviderError::NotFound(_)
        ));
        assert!(matches!(
            classify_error(
                reqwest::StatusCode::FORBIDDEN,
                r#"{"__type":"SignatureDoesNotMatch"}"#,
                "ListResources"
            ),
            ProviderError::Auth(_)
        ));
    }

    // ── credential report ─────────────────────────────────────────────────

    const REPORT_HEADER: &str = "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated";

    fn report(rows: &[&str]) -> Vec<CredentialRow> {
        let mut csv = String::from(REPORT_HEADER);
        for row in rows {
            csv.push('\n');
            csv.push_str(row);
        }
        parse_credential_report(&csv)
    }

    #[test]
    fn parses_a_credential_report_by_column_name() {
        let rows = report(&[
            "<root_account>,arn:aws:iam::123456789012:root,2024-01-15T10:00:00+00:00,not_supported,2025-03-01T08:30:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
            "alice,arn:aws:iam::123456789012:user/alice,2024-02-01T00:00:00+00:00,true,2025-05-30T12:00:00+00:00,2024-02-01T00:00:00+00:00,N/A,false,true,2025-01-01T00:00:00+00:00,2025-05-20T00:00:00+00:00,eu-west-3,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]);
        assert_eq!(rows.len(), 2);

        let root = &rows[0];
        assert!(root.is_root);
        assert!(root.mfa_active);
        // `not_supported` is not `true`: it is not an answer at all.
        assert!(!root.password_enabled);
        assert!(!root.has_active_access_key());
        // 2025-03-01 → 2025-06-01
        assert_eq!(root.root_last_used_days(now()), Some(91));

        let alice = &rows[1];
        assert!(alice.password_enabled);
        assert!(!alice.mfa_active);
        assert!(alice.has_active_access_key());
        assert_eq!(alice.active_access_keys(), 1);
        assert_eq!(alice.oldest_active_key_age_days(now()), 151); // rotated 2025-01-01
        assert_eq!(alice.stalest_active_key_unused_days(now()), 12); // used 2025-05-20
    }

    /// A root account that has never signed in still has a creation date, and
    /// "unused since creation" is what the report is saying. Without this the
    /// property would be missing, the engine would read `""`, and CIS 1.7 would
    /// report that root is in daily use.
    #[test]
    fn a_never_used_root_is_measured_from_its_creation_date() {
        let rows = report(&[
            "<root_account>,arn:aws:iam::123456789012:root,2024-01-15T10:00:00+00:00,not_supported,no_information,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]);
        assert_eq!(rows[0].root_last_used_days(now()), Some(502));
    }

    /// An active key that was never used is stale for as long as it has
    /// existed, not for zero days.
    #[test]
    fn an_active_but_never_used_key_is_stale_since_creation() {
        let rows = report(&[
            "bob,arn:aws:iam::123456789012:user/bob,2023-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2024-06-01T00:00:00+00:00,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]);
        assert_eq!(rows[0].stalest_active_key_unused_days(now()), 365);
        assert_eq!(rows[0].oldest_active_key_age_days(now()), 365);
    }

    /// Two active keys is the CIS 1.13 case, and the ages must come from the
    /// older one.
    #[test]
    fn counts_both_access_keys() {
        let rows = report(&[
            "carol,arn:aws:iam::123456789012:user/carol,2023-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2025-05-01T00:00:00+00:00,2025-05-02T00:00:00+00:00,eu-west-3,s3,true,2024-01-01T00:00:00+00:00,N/A,N/A,N/A,false,N/A,false,N/A",
        ]);
        assert_eq!(rows[0].active_access_keys(), 2);
        assert_eq!(rows[0].oldest_active_key_age_days(now()), 517); // the 2024 key
    }

    /// An inactive key is not a stale key: it is disabled, which is the state
    /// CIS 1.12 asks for.
    #[test]
    fn inactive_keys_do_not_count() {
        let rows = report(&[
            "dave,arn:aws:iam::123456789012:user/dave,2020-01-01T00:00:00+00:00,true,2025-05-31T00:00:00+00:00,N/A,N/A,true,false,2015-01-01T00:00:00+00:00,2015-02-01T00:00:00+00:00,us-east-1,iam,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]);
        assert!(!rows[0].has_active_access_key());
        assert_eq!(rows[0].active_access_keys(), 0);
        assert_eq!(rows[0].oldest_active_key_age_days(now()), 0);
        assert_eq!(rows[0].stalest_active_key_unused_days(now()), 0);
    }

    /// Columns are looked up by name: AWS has appended columns to this report
    /// over the years, and positional parsing shifts every field when it does.
    #[test]
    fn column_order_does_not_matter() {
        let csv = "arn,user,mfa_active,access_key_1_active,access_key_1_last_rotated,user_creation_time,password_enabled\n\
                   arn:aws:iam::1:user/e,erin,true,true,2025-04-01T00:00:00+00:00,2024-01-01T00:00:00+00:00,true";
        let rows = parse_credential_report(csv);
        assert_eq!(rows[0].user, "erin");
        assert!(rows[0].mfa_active);
        assert_eq!(rows[0].oldest_active_key_age_days(now()), 61);
    }

    #[test]
    fn an_empty_report_is_empty_not_a_panic() {
        assert!(parse_credential_report("").is_empty());
        assert!(parse_credential_report(REPORT_HEADER).is_empty());
    }

    // ── IAM users through Cloud Control ───────────────────────────────────

    #[test]
    fn counts_inline_policies_and_reads_the_permissions_boundary() {
        let bounded = json!({
            "UserName": "alice",
            "Arn": "arn:aws:iam::123456789012:user/alice",
            "PermissionsBoundary": "arn:aws:iam::123456789012:policy/boundary",
            "Policies": [
                { "PolicyName": "p1", "PolicyDocument": { "Statement": [] } },
                { "PolicyName": "p2", "PolicyDocument": { "Statement": [] } }
            ]
        });
        assert_eq!(inline_policy_count(&bounded), 2);
        assert_eq!(
            bounded.get("PermissionsBoundary").and_then(|v| v.as_str()),
            Some("arn:aws:iam::123456789012:policy/boundary")
        );

        // CloudFormation omits both when they are not set.
        let plain = json!({ "UserName": "bob" });
        assert_eq!(inline_policy_count(&plain), 0);
        assert!(plain.get("PermissionsBoundary").is_none());
    }

    // ── account-level assembly ────────────────────────────────────────────

    /// CIS 3.9 is answered by a join, because `AWS::EC2::VPC` carries no
    /// flow-log field of its own.
    #[test]
    fn joins_vpcs_to_their_flow_logs() {
        let vpcs = vec![
            json!({ "Identifier": "vpc-monitored",
                    "Properties": { "VpcId": "vpc-monitored", "CidrBlock": "10.0.0.0/16" } }),
            json!({ "Identifier": "vpc-dark",
                    "Properties": { "VpcId": "vpc-dark", "CidrBlock": "10.1.0.0/16" } }),
        ];
        let flow_logs = vec![json!({
            "Identifier": "fl-1",
            "Properties": { "Id": "fl-1", "ResourceId": "vpc-monitored",
                            "ResourceType": "VPC", "TrafficType": "ALL" }
        })];

        let joined = join_vpc_flow_logs(&vpcs, &flow_logs);
        assert_eq!(joined.len(), 2);
        assert_eq!(joined[0]["enable_flow_logs"], json!(true));
        assert_eq!(joined[1]["enable_flow_logs"], json!(false));
        assert_eq!(joined[1]["id"], json!("vpc-dark"));
    }

    #[test]
    fn builds_the_account_level_iam_users_object() {
        let users = vec![
            json!({ "Identifier": "alice", "Properties": {
                "UserName": "alice",
                "PermissionsBoundary": "arn:aws:iam::123456789012:policy/boundary",
                "Policies": [{ "PolicyName": "p", "PolicyDocument": { "Statement": [] } }]
            }}),
            json!({ "Identifier": "bob", "Properties": { "UserName": "bob" } }),
        ];
        let object = iam_users_object(&users);
        assert_eq!(object["iam_user_count"], json!(2));

        let listed = object["users"].as_array().unwrap();
        assert_eq!(listed[0]["inline_policies_count"], json!(1));
        assert_eq!(
            listed[0]["permissions_boundary"],
            json!("arn:aws:iam::123456789012:policy/boundary")
        );
        // No boundary set is the empty string the NOT_ANY condition looks for.
        assert_eq!(listed[1]["inline_policies_count"], json!(0));
        assert_eq!(listed[1]["permissions_boundary"], json!(""));
    }

    #[test]
    fn builds_the_credential_report_object() {
        let rows = report(&[
            "<root_account>,arn:aws:iam::123456789012:root,2024-01-15T10:00:00+00:00,not_supported,2025-03-01T08:30:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
            "alice,arn:aws:iam::123456789012:user/alice,2024-02-01T00:00:00+00:00,true,2025-05-30T12:00:00+00:00,2024-02-01T00:00:00+00:00,N/A,false,true,2025-01-01T00:00:00+00:00,2025-05-20T00:00:00+00:00,eu-west-3,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]);
        let object = credential_report_object(&rows, now()).unwrap();
        assert_eq!(object["root_last_used_days"], json!(91));

        let users = object["users"].as_array().unwrap();
        assert_eq!(users.len(), 1, "root is reported through its own field, not as a user");
        assert_eq!(users[0]["name"], json!("alice"));
        assert_eq!(users[0]["active_access_keys"], json!(1));
        assert_eq!(users[0]["access_key_age_days"], json!(151));
        assert_eq!(users[0]["access_key_last_used_days"], json!(12));
        // Console password, no MFA — the CIS 1.15 case.
        assert_eq!(users[0]["console_no_mfa"], json!(true));

        // Every property the NOT_ANY conditions read must be on each element,
        // or the engine reads "" and scores it.
        for property in [
            "access_key_age_days",
            "access_key_last_used_days",
            "active_access_keys",
            "console_no_mfa",
        ] {
            assert!(users[0].get(property).is_some(), "{property} missing");
        }
    }

    /// A report with no root row cannot answer CIS 1.7, and guessing would put
    /// a number on a question nobody asked AWS.
    #[test]
    fn a_report_without_root_is_an_error_not_a_guess() {
        let rows = report(&[
            "alice,arn:aws:iam::1:user/alice,2024-02-01T00:00:00+00:00,true,N/A,N/A,N/A,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]);
        assert!(matches!(
            credential_report_object(&rows, now()),
            Err(ProviderError::Api(_))
        ));
    }

    #[test]
    fn builds_iam_user_objects_from_three_sources() {
        let rows = report(&[
            "<root_account>,arn:aws:iam::123456789012:root,2024-01-15T10:00:00+00:00,not_supported,2025-03-01T08:30:00+00:00,not_supported,not_supported,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
            "alice,arn:aws:iam::123456789012:user/alice,2024-02-01T00:00:00+00:00,true,2025-05-30T12:00:00+00:00,2024-02-01T00:00:00+00:00,N/A,false,true,2025-01-01T00:00:00+00:00,2025-05-20T00:00:00+00:00,eu-west-3,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]);
        let inline: HashMap<String, u64> = [("alice".to_string(), 2u64)].into_iter().collect();

        let users = user_objects(&rows, &inline, Some(90), now());
        assert_eq!(users.len(), 1, "the <root_account> row is not an IAM user");

        let alice = &users[0];
        // All eight properties the iam_user rules read.
        for property in [
            "name",
            "has_access_key",
            "has_console_access",
            "mfa_active",
            "inline_policies_count",
            "access_key_age_days",
            "access_key_last_rotated_days",
            "password_max_age_days",
        ] {
            assert!(alice.get(property).is_some(), "{property} missing");
        }
        assert_eq!(alice["name"], json!("alice"));
        assert_eq!(alice["has_access_key"], json!(true));
        assert_eq!(alice["has_console_access"], json!(true));
        assert_eq!(alice["mfa_active"], json!(false));
        assert_eq!(alice["inline_policies_count"], json!(2));
        assert_eq!(alice["password_max_age_days"], json!(90));
    }

    /// A user the IAM listing did not return is skipped rather than given an
    /// inline-policy count of zero, which the engine would read as compliant.
    #[test]
    fn a_user_missing_from_the_listing_is_skipped() {
        let rows = report(&[
            "ghost,arn:aws:iam::1:user/ghost,2024-02-01T00:00:00+00:00,true,N/A,N/A,N/A,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]);
        assert!(user_objects(&rows, &HashMap::new(), Some(90), now()).is_empty());
    }

    /// With no expiry in the password policy the field is absent, and it is the
    /// only one that may be: everything else the rules read is still there.
    #[test]
    fn users_carry_no_invented_password_age() {
        let rows = report(&[
            "alice,arn:aws:iam::1:user/alice,2024-02-01T00:00:00+00:00,true,N/A,N/A,N/A,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A",
        ]);
        let inline: HashMap<String, u64> = [("alice".to_string(), 0u64)].into_iter().collect();
        let users = user_objects(&rows, &inline, None, now());
        assert!(users[0].get("password_max_age_days").is_none());
        assert_eq!(users[0]["inline_policies_count"], json!(0));
    }

    // ── engine interaction ────────────────────────────────────────────────

    /// The reason for every "dropped rather than scored" decision above,
    /// pinned: the engine reads a missing property as an empty string, and an
    /// empty string satisfies none of the boolean rules.
    #[test]
    fn a_missing_property_is_read_as_an_empty_string_by_the_engine() {
        use kxn_core::engine::property::get_sub_property;
        let half_normalized = json!({ "s3_bucket_name": "b" });
        assert!(get_sub_property(&half_normalized, "is_multi_region_trail").is_none());
        // Which the evaluator turns into Value::String("") — and
        // check_equal(true, "") is false, i.e. a violation.
        assert!(!kxn_core::engine::conditions::check_equal(
            &json!(true),
            &json!("")
        ));
    }

    #[test]
    fn booleans_are_read_from_both_wire_formats() {
        assert_eq!(as_bool(&json!(true)), Some(true));
        assert_eq!(as_bool(&json!("false")), Some(false));
        assert_eq!(as_bool(&json!("TRUE")), Some(true));
        // Not a boolean: `not_supported`, 1, null — none of these may become one.
        assert_eq!(as_bool(&json!("not_supported")), None);
        assert_eq!(as_bool(&json!(1)), None);
        assert_eq!(as_bool(&Value::Null), None);
    }

    #[test]
    fn account_ids_are_read_out_of_arns() {
        assert_eq!(
            account_id_from_arn("arn:aws:iam::123456789012:role/app").as_deref(),
            Some("123456789012")
        );
        assert_eq!(account_id_from_arn("arn:aws:iam::aws:policy/X"), None);
        assert_eq!(twelve_digit_account("210987654321").as_deref(), Some("210987654321"));
        assert_eq!(twelve_digit_account("not-an-account"), None);
    }

    #[test]
    fn requires_an_explicit_region() {
        // A scanner that silently defaults to us-east-1 reports "no findings"
        // for the region the operator actually meant.
        let err = AwsProvider::new(json!({})).err();
        // The env of the test process may legitimately carry AWS_REGION; only
        // assert the failure shape when it does not.
        if std::env::var("AWS_REGION").is_err() && std::env::var("AWS_DEFAULT_REGION").is_err() {
            assert!(matches!(err, Some(ProviderError::InvalidConfig(_))));
        }
        let ok = AwsProvider::new(json!({ "region": "eu-west-3" })).unwrap();
        assert_eq!(ok.region, "eu-west-3");
        assert_eq!(ok.concurrency, 8);
    }
}
