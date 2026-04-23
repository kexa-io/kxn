use anyhow::Result;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kxn_core::check_rule;
use kxn_rules::{parse_file, RuleFile, SaveConfig};

/// Webhook server arguments (embedded in ServeArgs)
#[derive(Args, Clone)]
pub struct WebhookArgs {
    /// Port to listen on
    #[arg(long, default_value = "8080")]
    pub port: u16,

    /// Alert destinations (slack://, discord://, etc.)
    #[arg(long = "alert")]
    pub alerts: Vec<String>,

    /// Save backends (postgresql://, kafka://, etc.)
    #[arg(long = "save")]
    pub saves: Vec<String>,

    /// Rules directory
    #[arg(short = 'R', long = "rules", default_value = "./rules")]
    pub rules: String,

    /// Include compliance/monitoring rules
    #[arg(long)]
    pub compliance: bool,

    /// Minimum severity level filter
    #[arg(short = 'l', long = "min-level")]
    pub min_level: Option<u8>,

    /// API key for webhook authentication (also reads KXN_WEBHOOK_API_KEY env var)
    #[arg(long = "api-key")]
    pub api_key: Option<String>,
}

/// Shared state for axum handlers
#[allow(dead_code)]
struct AppState {
    rules_dir: PathBuf,
    rules: Vec<(String, RuleFile)>,
    alert_configs: Vec<(String, String)>,
    save_configs: Vec<SaveConfig>,
    compliance: bool,
    min_level: Option<u8>,
    api_key: Option<String>,
}

/// Start the webhook HTTP server
pub async fn run_webhook(args: WebhookArgs) -> Result<()> {
    let alert_configs: Vec<(String, String)> = args
        .alerts
        .iter()
        .map(|u| crate::alerts::parse_alert_uri(u))
        .collect::<Result<_>>()?;

    let save_configs: Vec<SaveConfig> = args
        .saves
        .iter()
        .map(|u| crate::save::parse_save_uri(u))
        .collect::<Result<_>>()?;

    let api_key = args
        .api_key
        .or_else(|| std::env::var("KXN_WEBHOOK_API_KEY").ok());

    let rules_dir = PathBuf::from(&args.rules);
    let rules = load_all_rules(&rules_dir).unwrap_or_else(|e| {
        eprintln!("Warning: failed to load rules at startup: {}", e);
        Vec::new()
    });
    eprintln!("Loaded {} rule files at startup", rules.len());

    let state = Arc::new(AppState {
        rules_dir,
        rules,
        alert_configs,
        save_configs,
        compliance: args.compliance,
        min_level: args.min_level,
        api_key,
    });

    let app = Router::new()
        .route("/health", get(handle_health))
        .route("/scan", post(handle_scan))
        .route("/event", post(handle_event))
        .route("/ingest", post(handle_ingest))
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024)) // 10MB max
        .with_state(state);

    let addr = format!("0.0.0.0:{}", args.port);
    eprintln!(
        "kxn webhook server listening on {} | rules={} | alerts={} | save={}",
        addr,
        args.rules,
        args.alerts.len(),
        args.saves.len()
    );

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Verify API key if configured. Uses constant-time comparison to prevent timing attacks.
fn check_api_key(state: &AppState, headers: &axum::http::HeaderMap) -> Result<(), StatusCode> {
    if let Some(ref expected) = state.api_key {
        let provided = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Constant-time comparison: always compare full length
        let expected_bytes = expected.as_bytes();
        let provided_bytes = provided.as_bytes();
        let len_match = expected_bytes.len() == provided_bytes.len();
        let content_match = expected_bytes
            .iter()
            .zip(provided_bytes.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
        if !len_match || !content_match {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /health
// ---------------------------------------------------------------------------

async fn handle_health() -> Json<Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": "0.12.0",
    }))
}

// ---------------------------------------------------------------------------
// POST /scan — check a JSON resource against rules
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ScanParams {
    /// Rules file name or glob (e.g. "ssh-cis" or "ssh-cis.toml")
    rules: Option<String>,
    /// Provider filter
    provider: Option<String>,
    /// Minimum severity level
    #[serde(rename = "min-level")]
    min_level: Option<u8>,
}

#[derive(Serialize)]
struct ScanResponse {
    total: usize,
    passed: usize,
    failed: usize,
    violations: Vec<ViolationOut>,
}

#[derive(Serialize)]
struct ViolationOut {
    rule: String,
    description: String,
    level: u8,
    level_label: String,
    messages: Vec<String>,
}

async fn handle_scan(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<ScanParams>,
    Json(resource): Json<Value>,
) -> impl IntoResponse {
    if let Err(status) = check_api_key(&state, &headers) {
        return (status, Json(serde_json::json!({"error": "unauthorized"})));
    }
    match do_scan(&state, &params, &resource) {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(&resp).unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"})))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        ),
    }
}

fn do_scan(
    state: &AppState,
    params: &ScanParams,
    resource: &Value,
) -> Result<ScanResponse> {
    let files = load_rules(state, params.rules.as_deref(), params.provider.as_deref())?;
    let min_level = params.min_level.or(state.min_level).unwrap_or(0);
    scan_with_files(&files, min_level, resource)
}

fn scan_with_files(
    files: &[(String, RuleFile)],
    min_level: u8,
    resource: &Value,
) -> Result<ScanResponse> {

    let mut total = 0usize;
    let mut passed = 0usize;
    let mut violations = Vec::new();

    for (_name, rule_file) in files {
        for rule in &rule_file.rules {
            if (rule.level as u8) < min_level {
                continue;
            }
            total += 1;
            let resources = extract_resources(resource, &rule.object);
            let targets = if resources.is_empty() {
                vec![resource]
            } else {
                resources
            };

            let mut rule_failed = false;
            for res in &targets {
                let results = check_rule(&rule.conditions, res);
                let failures: Vec<_> = results.iter().filter(|r| !r.result).collect();
                if !failures.is_empty() {
                    rule_failed = true;
                    let msgs: Vec<String> = failures
                        .iter()
                        .filter_map(|f| f.message.clone())
                        .collect();
                    violations.push(ViolationOut {
                        rule: rule.name.clone(),
                        description: rule.description.clone(),
                        level: rule.level as u8,
                        level_label: level_label(rule.level as u8).to_string(),
                        messages: msgs,
                    });
                }
            }
            if !rule_failed {
                passed += 1;
            }
        }
    }

    Ok(ScanResponse {
        total,
        passed,
        failed: violations.len(),
        violations,
    })
}

// ---------------------------------------------------------------------------
// POST /event — receive cloud events, trigger gather+scan
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct EventResponse {
    event_type: String,
    provider: Option<String>,
    scanned: bool,
    total: usize,
    failed: usize,
    message: String,
}

async fn handle_event(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    if let Err(status) = check_api_key(&state, &headers) {
        return (status, Json(serde_json::json!({"error": "unauthorized"})));
    }
    // Azure Event Grid SubscriptionValidation handshake
    if let Some(validation) = detect_azure_validation(&body) {
        return (StatusCode::OK, Json(validation));
    }

    let event_info = classify_event(&headers, &body);

    let resp = match event_info {
        EventInfo::Azure { resource_type, resource_id, resource_uri } => {
            process_azure_event(&state, &resource_type, &resource_id, resource_uri.as_deref()).await
        }
        EventInfo::Aws { source, detail_type, detail } => {
            let provider = aws_source_to_provider(&source);
            let resource_type = detail_type;
            let resource_id = detail
                .get("resourceId")
                .or_else(|| detail.get("arn"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            process_cloud_event(&state, &provider, &resource_type, &resource_id).await
        }
        EventInfo::CloudEvent { source, r#type, .. } => {
            let provider = cloudevent_source_to_provider(&source);
            process_cloud_event(&state, &provider, &r#type, "cloudevent").await
        }
        EventInfo::Unknown => EventResponse {
            event_type: "unknown".to_string(),
            provider: None,
            scanned: false,
            total: 0,
            failed: 0,
            message: "Unrecognized event format".to_string(),
        },
    };

    (StatusCode::OK, Json(serde_json::to_value(&resp).unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}))))
}

// ---------------------------------------------------------------------------
// POST /ingest — receive scan results, forward to save/alert
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct IngestRecord {
    target: Option<String>,
    provider: Option<String>,
    rule_name: Option<String>,
    rule_description: Option<String>,
    level: Option<u8>,
    level_label: Option<String>,
    object_type: Option<String>,
    object_content: Option<Value>,
    error: Option<bool>,
    messages: Option<Vec<String>>,
    conditions: Option<Value>,
}


async fn handle_ingest(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(records): Json<Vec<IngestRecord>>,
) -> impl IntoResponse {
    if let Err(status) = check_api_key(&state, &headers) {
        return (status, Json(serde_json::json!({"error": "unauthorized"})));
    }
    let count = records.len();
    let batch_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    let scan_records: Vec<crate::save::ScanRecord> = records
        .iter()
        .map(|r| ingest_to_scan_record(r, &batch_id, now))
        .collect();

    let mut saved = false;
    if !state.save_configs.is_empty() {
        let metrics = Vec::new();
        if let Err(e) = crate::save::save_all(&state.save_configs, &scan_records, &metrics).await {
            eprintln!("webhook ingest save error: {}", e);
        } else {
            saved = true;
        }
    }

    let has_errors = scan_records.iter().any(|r| r.error);
    let mut alerted = false;
    if has_errors && !state.alert_configs.is_empty() {
        let violations = records_to_violations(&scan_records);
        crate::alerts::send_alerts(&state.alert_configs, &violations, "webhook-ingest").await;
        alerted = true;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "received": count,
            "saved": saved,
            "alerted": alerted,
        })),
    )
}

// ---------------------------------------------------------------------------
// Helper: load rules from state
// ---------------------------------------------------------------------------

fn load_rules(
    state: &AppState,
    rules_filter: Option<&str>,
    provider_filter: Option<&str>,
) -> Result<Vec<(String, RuleFile)>> {
    let mut files = Vec::new();

    if let Some(name) = rules_filter {
        // Reject path traversal attempts
        if name.contains("..") || name.starts_with('/') {
            anyhow::bail!("Invalid rules parameter: {}", name);
        }
        // Filter from cached rules
        for (n, rf) in &state.rules {
            if n == name || n.contains(name) {
                files.push((n.clone(), rf.clone()));
            }
        }
        // Fallback: try loading from disk if not found in cache
        if files.is_empty() {
            let path = state.rules_dir.join(name);
            let path_toml = state.rules_dir.join(format!("{}.toml", name));
            if path.is_file() {
                let rf = parse_file(&path)
                    .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", path.display(), e))?;
                files.push((name.to_string(), rf));
            } else if path_toml.is_file() {
                let rf = parse_file(&path_toml)
                    .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", path_toml.display(), e))?;
                files.push((name.to_string(), rf));
            }
        }
    } else {
        // Use cached rules
        files = state.rules.clone();
    }

    // Filter by provider if specified.
    // "azure" and "azurerm" are treated as equivalent — community rules use "azure",
    // while Terraform provider references use "azurerm".
    if let Some(prov) = provider_filter {
        let azure_aliases = ["azure", "azurerm"];
        let is_azure = prov == "azure" || prov == "azurerm";
        files.retain(|(_, rf)| {
            let p = rf.metadata.as_ref().and_then(|m| m.provider.as_deref());
            match p {
                Some(rule_prov) if is_azure => azure_aliases.contains(&rule_prov),
                Some(rule_prov) => rule_prov == prov,
                None => false,
            }
        });
    }

    Ok(files)
}

fn load_all_rules(dir: &Path) -> Result<Vec<(String, RuleFile)>> {
    let pattern = dir.join("**/*.toml");
    let pattern_str = pattern
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid rules path"))?;

    let mut result = Vec::new();
    for entry in glob::glob(pattern_str).map_err(|e| anyhow::anyhow!("Glob error: {}", e))? {
        let path = entry.map_err(|e| anyhow::anyhow!("Glob error: {}", e))?;
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        match parse_file(&path) {
            Ok(rf) => result.push((name, rf)),
            Err(e) => eprintln!("Warning: failed to parse {}: {}", path.display(), e),
        }
    }
    Ok(result)
}

use super::extract_resources;

fn level_label(level: u8) -> &'static str {
    match level {
        0 => "info",
        1 => "warning",
        2 => "error",
        _ => "fatal",
    }
}

// ---------------------------------------------------------------------------
// Event classification
// ---------------------------------------------------------------------------

enum EventInfo {
    Azure { resource_type: String, resource_id: String, resource_uri: Option<String> },
    Aws { source: String, detail_type: String, detail: Value },
    #[allow(dead_code)]
    CloudEvent { source: String, r#type: String, data: Value },
    Unknown,
}

fn detect_azure_validation(body: &Value) -> Option<Value> {
    // Azure Event Grid sends an array with eventType =
    // "Microsoft.EventGrid.SubscriptionValidationEvent"
    let arr = body.as_array()?;
    let first = arr.first()?;
    let event_type = first.get("eventType")?.as_str()?;

    if event_type == "Microsoft.EventGrid.SubscriptionValidationEvent" {
        let code = first
            .get("data")?
            .get("validationCode")?
            .as_str()?;
        return Some(serde_json::json!({
            "validationResponse": code,
        }));
    }
    None
}

fn classify_event(
    headers: &axum::http::HeaderMap,
    body: &Value,
) -> EventInfo {
    // CloudEvents via headers
    if headers.contains_key("ce-type") {
        let source = headers
            .get("ce-source")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let ce_type = headers
            .get("ce-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        return EventInfo::CloudEvent {
            source,
            r#type: ce_type,
            data: body.clone(),
        };
    }

    // Azure Event Grid (array of events)
    if let Some(arr) = body.as_array() {
        if let Some(first) = arr.first() {
            if first.get("eventType").is_some() && first.get("data").is_some() {
                let resource_type = first
                    .get("eventType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let resource_id = first
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                // data.resourceUri is the ARM path usable for GET /resource
                let resource_uri = first
                    .get("data")
                    .and_then(|d| d.get("resourceUri"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                return EventInfo::Azure {
                    resource_type,
                    resource_id,
                    resource_uri,
                };
            }
        }
    }

    // AWS EventBridge
    if body.get("source").is_some() && body.get("detail-type").is_some() {
        let source = body["source"].as_str().unwrap_or("").to_string();
        let detail_type = body["detail-type"].as_str().unwrap_or("").to_string();
        let detail = body.get("detail").cloned().unwrap_or(Value::Null);
        return EventInfo::Aws {
            source,
            detail_type,
            detail,
        };
    }

    // CloudEvents in body (structured mode)
    if body.get("specversion").is_some() && body.get("type").is_some() {
        let source = body["source"].as_str().unwrap_or("").to_string();
        let ce_type = body["type"].as_str().unwrap_or("").to_string();
        let data = body.get("data").cloned().unwrap_or(Value::Null);
        return EventInfo::CloudEvent {
            source,
            r#type: ce_type,
            data,
        };
    }

    EventInfo::Unknown
}

fn aws_source_to_provider(source: &str) -> String {
    match source {
        s if s.starts_with("aws.") => "aws".to_string(),
        _ => "aws".to_string(),
    }
}

fn cloudevent_source_to_provider(source: &str) -> String {
    if source.contains("azure") || source.contains("microsoft") {
        "azurerm".to_string()
    } else if source.contains("aws") || source.contains("amazon") {
        "aws".to_string()
    } else if source.contains("google") || source.contains("gcp") {
        "google".to_string()
    } else {
        "unknown".to_string()
    }
}

/// Map an ARM resource type to the rule `object` name used in kxn TOML rules.
fn arm_type_to_rule_object(arm_type: &str) -> Option<&'static str> {
    let t = arm_type.to_lowercase();
    if t.contains("microsoft.storage/storageaccounts") { Some("storage_account") }
    else if t.contains("microsoft.network/networksecuritygroups") { Some("nsg") }
    else if t.contains("microsoft.compute/virtualmachines") { Some("vm") }
    else if t.contains("microsoft.compute/disks") { Some("disk") }
    else if t.contains("microsoft.keyvault/vaults") { Some("key_vault") }
    else if t.contains("microsoft.sql/servers/databases") { Some("sql_database") }
    else if t.contains("microsoft.sql/servers") { Some("sql_server") }
    else if t.contains("microsoft.containerservice/managedclusters") { Some("aks_cluster") }
    else if t.contains("microsoft.web/sites") { Some("app_service") }
    else if t.contains("microsoft.network/publicipaddresses") { Some("public_ip") }
    else { None }
}

/// Handle Azure Event Grid events: fetch the real resource from ARM, then scan.
async fn process_azure_event(
    state: &AppState,
    event_type: &str,
    subject: &str,
    resource_uri: Option<&str>,
) -> EventResponse {
    let mut files = match load_rules(state, None, Some("azurerm")) {
        Ok(f) => f,
        Err(e) => {
            return EventResponse {
                event_type: event_type.to_string(),
                provider: Some("azurerm".to_string()),
                scanned: false,
                total: 0,
                failed: 0,
                message: format!("Failed to load rules: {}", e),
            };
        }
    };

    if files.is_empty() {
        return EventResponse {
            event_type: event_type.to_string(),
            provider: Some("azurerm".to_string()),
            scanned: false,
            total: 0,
            failed: 0,
            message: "No rules found for provider 'azurerm'".to_string(),
        };
    }

    // subject is the ARM resource path — use it to fetch the real resource
    let arm_uri = resource_uri.unwrap_or(subject);
    let resource = match kxn_providers::azure_arm::fetch_resource(arm_uri).await {
        Ok(r) => {
            let arm_type = r.get("type").and_then(|v| v.as_str()).unwrap_or("?");
            eprintln!("[event] fetched Azure resource: {} ({})", arm_uri, arm_type);

            // Keep only rules whose object matches this resource type
            if let Some(rule_object) = arm_type_to_rule_object(arm_type) {
                for (_, rf) in &mut files {
                    rf.rules.retain(|r| r.object == rule_object);
                }
                files.retain(|(_, rf)| !rf.rules.is_empty());
                let total_rules: usize = files.iter().map(|(_, rf)| rf.rules.len()).sum();
                eprintln!("[event] {} rule(s) for object='{}'", total_rules, rule_object);
            }

            r
        }
        Err(e) => {
            eprintln!("[event] ARM fetch failed for {}: {} — using synthetic object", arm_uri, e);
            serde_json::json!({
                "id": arm_uri,
                "type": event_type,
                "subject": subject,
                "_fetch_error": e.to_string(),
            })
        }
    };

    let min_level = state.min_level.unwrap_or(0);
    match scan_with_files(&files, min_level, &resource) {
        Ok(resp) => {
            eprintln!("[event] scan result: {} rules checked, {} violation(s)", resp.total, resp.failed);
            EventResponse {
                event_type: event_type.to_string(),
                provider: Some("azurerm".to_string()),
                scanned: true,
                total: resp.total,
                failed: resp.failed,
                message: format!("{} rules checked, {} violations", resp.total, resp.failed),
            }
        }
        Err(e) => {
            eprintln!("[event] scan error: {}", e);
            EventResponse {
                event_type: event_type.to_string(),
                provider: Some("azurerm".to_string()),
                scanned: false,
                total: 0,
                failed: 0,
                message: format!("Scan error: {}", e),
            }
        }
    }
}

async fn process_cloud_event(
    state: &AppState,
    provider: &str,
    resource_type: &str,
    resource_id: &str,
) -> EventResponse {
    let files = match load_rules(state, None, Some(provider)) {
        Ok(f) => f,
        Err(e) => {
            return EventResponse {
                event_type: resource_type.to_string(),
                provider: Some(provider.to_string()),
                scanned: false,
                total: 0,
                failed: 0,
                message: format!("Failed to load rules: {}", e),
            };
        }
    };

    if files.is_empty() {
        return EventResponse {
            event_type: resource_type.to_string(),
            provider: Some(provider.to_string()),
            scanned: false,
            total: 0,
            failed: 0,
            message: format!("No rules found for provider '{}'", provider),
        };
    }

    let resource = serde_json::json!({
        "resource_type": resource_type,
        "resource_id": resource_id,
        "event": true,
    });

    let params = ScanParams {
        rules: None,
        provider: Some(provider.to_string()),
        min_level: state.min_level,
    };

    match do_scan(state, &params, &resource) {
        Ok(resp) => EventResponse {
            event_type: resource_type.to_string(),
            provider: Some(provider.to_string()),
            scanned: true,
            total: resp.total,
            failed: resp.failed,
            message: format!("{} rules checked, {} violations", resp.total, resp.failed),
        },
        Err(e) => EventResponse {
            event_type: resource_type.to_string(),
            provider: Some(provider.to_string()),
            scanned: false,
            total: 0,
            failed: 0,
            message: format!("Scan error: {}", e),
        },
    }
}

// ---------------------------------------------------------------------------
// Helper: convert ingest records
// ---------------------------------------------------------------------------

fn ingest_to_scan_record(
    r: &IngestRecord,
    batch_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> crate::save::ScanRecord {
    crate::save::ScanRecord {
        target: r.target.clone().unwrap_or_default(),
        provider: r.provider.clone().unwrap_or_default(),
        rule_name: r.rule_name.clone().unwrap_or_default(),
        rule_description: r.rule_description.clone().unwrap_or_default(),
        level: r.level.unwrap_or(0),
        level_label: r.level_label.clone().unwrap_or_default(),
        object_type: r.object_type.clone().unwrap_or_default(),
        object_content: r.object_content.clone().unwrap_or(Value::Null),
        error: r.error.unwrap_or(false),
        messages: r.messages.clone().unwrap_or_default(),
        conditions: r.conditions.clone().unwrap_or(Value::Null),
        compliance: Vec::new(),
        batch_id: batch_id.to_string(),
        timestamp: now,
        tags: HashMap::new(),
    }
}

fn records_to_violations(
    records: &[crate::save::ScanRecord],
) -> Vec<super::watch::Violation> {
    records
        .iter()
        .filter(|r| r.error)
        .map(|r| super::watch::Violation {
            rule: r.rule_name.clone(),
            description: r.rule_description.clone(),
            level: r.level,
            level_label: r.level_label.clone(),
            object_type: r.object_type.clone(),
            object_content: r.object_content.clone(),
            conditions: r.conditions.clone(),
            messages: r.messages.clone(),
            provider: r.provider.clone(),
            target: r.target.clone(),
            remediation_context: Value::Null,
            rule_webhooks: Vec::new(),
            compliance: r.compliance.clone(),
            remediation_actions: Vec::new(),
        })
        .collect()
}
