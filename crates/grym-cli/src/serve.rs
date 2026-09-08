#![deny(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post, put},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, FixedOffset, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::RwLock;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};
use url::Url;
use uuid::Uuid;

use grym_core::{
    Finding, OperatorAttestation, ScopeGuard, ScopedClient,
    audit::{AuditSink, MemoryAuditLog},
    config::{self, Deepness, TechniqueTier},
};
use grym_web_scanner::{
    chain_builder, command_injection, cors as cors_module, csrf, cve_db, fuzzer, graphql,
    host_header, http_smuggling, idor, jwt, nosqli, open_redirect, path_traversal, sqli, ssrf,
    ssti, tech_fingerprint, waf_detect, xss, xxe,
};

static ALL_MODULES: &[&str] = &[
    "sqli",
    "xss",
    "ssti",
    "ssrf",
    "cmd_injection",
    "path_traversal",
    "cors",
    "jwt",
    "open_redirect",
    "idor",
    "waf_detect",
    "smuggling",
    "xxe",
    "tech_fingerprint",
    "csrf",
    "nosqli",
    "graphql",
    "host_header",
    "fuzzer",
    "chain_builder",
];

// ── Server Configuration ─────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ServeConfig {
    pub host: String,
    pub port: u16,
    pub api_key: Option<String>,
    pub jwt_secret: Option<String>,
    pub allowed_origins: Vec<String>,
    pub rate_limit_per_minute: u32,
    pub body_limit_bytes: usize,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 9378,
            api_key: None,
            jwt_secret: None,
            allowed_origins: Vec::new(),
            rate_limit_per_minute: 60,
            body_limit_bytes: 2 * 1024 * 1024,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

// ── Request / Response types ───────────────────────────────────────────────

#[derive(Deserialize)]
struct ScanRequest {
    target: String,
    scan_types: Vec<String>,
}

#[derive(Serialize)]
struct ScanResponse {
    scan_id: String,
    target: String,
    findings: Vec<Finding>,
    modules_run: Vec<String>,
    duration_ms: u64,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    server_time: String,
}

#[derive(Serialize)]
struct ServerStateResponse {
    findings_count: usize,
    scan_count: usize,
    uptime_secs: u64,
}

#[derive(Deserialize)]
struct CveLookupRequest {
    name: String,
    version: String,
    purl: Option<String>,
    cpe: Option<String>,
}

#[derive(Serialize)]
struct CveLookupResponse {
    component: String,
    version: String,
    matches: Vec<CveMatch>,
}

#[derive(Serialize)]
struct CveMatch {
    id: String,
    sources: Vec<String>,
    cvss_score: Option<f32>,
    description: String,
    known_exploited: bool,
    references: Vec<String>,
}

#[derive(Serialize)]
struct ScanRecord {
    scan_id: String,
    target: String,
    modules_run: Vec<String>,
    finding_count: usize,
    duration_ms: u64,
}

#[derive(Deserialize)]
struct ExploitGenRequest {
    cve_id: Option<String>,
    target: Option<String>,
    format: Option<String>,
    callback_ip: Option<String>,
    callback_port: Option<u16>,
    include_shell: Option<bool>,
    obfuscate: Option<bool>,
}

#[derive(Serialize)]
struct ExploitGenResponse {
    exploit: Option<grym_web_scanner::exploit_gen::GeneratedExploit>,
    generated_variants: Vec<String>,
}

#[derive(Deserialize)]
struct PredictionRequest {
    component: String,
    version: String,
}

#[derive(Serialize)]
struct PredictionResponse {
    predictions: Vec<grym_cve_intel::ZeroDayPrediction>,
}

// ── Rate limiter ───────────────────────────────────────────────────────────

struct RateLimiterInner {
    buckets: RwLock<HashMap<String, Vec<Instant>>>,
    max_per_minute: u32,
}

impl RateLimiterInner {
    fn new(max_per_minute: u32) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            max_per_minute,
        }
    }

    async fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let mut buckets = self.buckets.write().await;
        let entry = buckets.entry(key.to_string()).or_insert_with(Vec::new);
        entry.retain(|t| now.duration_since(*t) < window);
        if entry.len() >= self.max_per_minute as usize {
            return false;
        }
        entry.push(now);
        true
    }
}

// ── Application state ─────────────────────────────────────────────────────

struct AppState {
    client: ScopedClient,
    findings: RwLock<Vec<Finding>>,
    scan_history: RwLock<Vec<ScanRecord>>,
    start_time: Instant,
    config: ServeConfig,
    rate_limiter: RateLimiterInner,
    settings: RwLock<grym_core::settings::GrymSettings>,
    /// Methodology checklist with per-session step progress.
    checklist: RwLock<grym_web_scanner::checklist::Checklist>,
}

// ── Handler helpers ───────────────────────────────────────────────────────

fn error_response(status: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({ "error": msg })))
}

fn create_dev_scope() -> anyhow::Result<config::ScopeConfig> {
    let offset =
        FixedOffset::east_opt(0).ok_or_else(|| anyhow::anyhow!("failed to create UTC offset"))?;
    let now: DateTime<FixedOffset> = Utc::now().with_timezone(&offset);
    let later = now
        + chrono::TimeDelta::try_hours(24).ok_or_else(|| anyhow::anyhow!("invalid time delta"))?;

    Ok(config::ScopeConfig {
        format_version: 1,
        engagement: config::Engagement {
            client: "grym-serve".into(),
            engagement_id: "serve-mode".into(),
            authorized_start: now,
            authorized_end: later,
            emergency_contact: "local".into(),
        },
        targets: config::TargetScope {
            allow: vec!["0.0.0.0/0".into(), "::0/0".into()],
            deny: vec![],
        },
        limits: config::LimitConfig {
            max_requests_per_second_global: 200,
            max_requests_per_second_per_host: 50,
            max_response_bytes: 4 * 1024 * 1024,
        },
        technique: config::TechniqueConfig {
            max_tier: TechniqueTier::StandardDetection,
            deepness: Deepness::Standard,
        },
        authorization: config::AuthorizationConfig {
            authorization_attested: true,
        },
        safety: config::SafetyConfig::default(),
    })
}

async fn run_module(client: &ScopedClient, url: &Url, scan_type: &str) -> Vec<Finding> {
    match scan_type {
        "sqli" => sqli::check_sqli(client, url).await.unwrap_or_default(),
        "xss" => xss::check_xss(client, url).await.unwrap_or_default(),
        "ssti" => ssti::check_ssti(client, url).await.unwrap_or_default(),
        "ssrf" => ssrf::check_ssrf(client, url).await.unwrap_or_default(),
        "cmd_injection" => command_injection::check_command_injection(client, url)
            .await
            .unwrap_or_default(),
        "path_traversal" => path_traversal::check_path_traversal(client, url)
            .await
            .unwrap_or_default(),
        "cors" => cors_module::check_cors(client, url)
            .await
            .unwrap_or_default(),
        "jwt" => jwt::check_jwt_config(client, url).await.unwrap_or_default(),
        "open_redirect" => open_redirect::check_open_redirect(client, url)
            .await
            .unwrap_or_default(),
        "idor" => idor::check_idor(client, url).await.unwrap_or_default(),
        "waf_detect" => waf_detect::detect_waf(client, url)
            .await
            .unwrap_or_default(),
        "smuggling" => http_smuggling::check_http_smuggling(client, url)
            .await
            .unwrap_or_default(),
        "xxe" => xxe::check_xxe(client, url).await.unwrap_or_default(),
        "tech_fingerprint" => tech_fingerprint::fingerprint_tech(client, url)
            .await
            .unwrap_or_default(),
        "csrf" => csrf::check_csrf(client, url).await.unwrap_or_default(),
        "nosqli" => nosqli::check_nosqli(client, url).await.unwrap_or_default(),
        "graphql" => graphql::check_graphql(client, url)
            .await
            .unwrap_or_default(),
        "host_header" => host_header::check_host_header_injection(client, url)
            .await
            .unwrap_or_default(),
        "fuzzer" => fuzzer::fuzz_all(client, url).await.unwrap_or_default(),
        "chain_builder" => chain_builder::build_chains_from_findings(client, url)
            .await
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

// ── Security Headers (2026) ───────────────────────────────────────────────

fn security_headers() -> Vec<(HeaderName, HeaderValue)> {
    vec![
        (
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'",
            ),
        ),
        (
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        (
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ),
        (
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("0"),
        ),
        (
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        ),
        (
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ),
        (
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static(
                "accelerometer=(),ambient-light-sensor=(),autoplay=(),battery=(),camera=(),cross-origin-isolated=(),display-capture=(),document-domain=(),encrypted-media=(),execution-while-not-rendered=(),execution-while-out-of-viewport=(),fullscreen=(),geolocation=(),gyroscope=(),hid=(),idle-detection=(),interest-cohort=(),magnetometer=(),microphone=(),midi=(),navigation-override=(),payment=(),picture-in-picture=(),publickey-credentials-get=(),screen-wake-lock=(),serial=(),speaker-selection=(),storage-access=(),usb=(),web-share=(),window-placement=()",
            ),
        ),
        (
            HeaderName::from_static("cross-origin-embedder-policy"),
            HeaderValue::from_static("require-corp"),
        ),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ),
        (
            HeaderName::from_static("cross-origin-resource-policy"),
            HeaderValue::from_static("same-origin"),
        ),
        (
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, max-age=0"),
        ),
        (header::PRAGMA, HeaderValue::from_static("no-cache")),
        (header::EXPIRES, HeaderValue::from_static("0")),
        (header::ACCEPT_RANGES, HeaderValue::from_static("none")),
    ]
}

// ── Middleware ────────────────────────────────────────────────────────────

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let path = req.uri().path().to_string();

    if path == "/health" {
        return next.run(req).await.into_response();
    }

    let config = &state.config;
    let has_auth = config.api_key.is_some() || config.jwt_secret.is_some();

    if !has_auth {
        return next.run(req).await.into_response();
    }

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());

    let authenticated = if let Some(ref header_val) = auth_header {
        if let Some(token) = header_val.strip_prefix("Bearer ") {
            if let Some(ref api_key) = config.api_key {
                token == api_key
            } else if let Some(ref jwt_secret) = config.jwt_secret {
                validate_jwt(token, jwt_secret).is_ok()
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    if authenticated {
        next.run(req).await.into_response()
    } else {
        error_response(
            StatusCode::UNAUTHORIZED,
            "Missing or invalid authentication. Provide Authorization: Bearer <api-key-or-jwt>",
        )
        .into_response()
    }
}

fn validate_jwt(token: &str, secret: &str) -> Result<serde_json::Value, ()> {
    type HmacSha256 = Hmac<Sha256>;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(());
    }

    // Decode and inspect the header to enforce HS256 only.
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| ())?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).map_err(|_| ())?;
    let alg = header.get("alg").and_then(|v| v.as_str()).ok_or(())?;
    if alg != "HS256" {
        return Err(());
    }

    // Verify the signature over "base64url(header).base64url(payload)".
    let message = format!("{}.{}", parts[0], parts[1]);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| ())?;
    mac.update(message.as_bytes());
    let expected = mac.finalize().into_bytes();

    let signature = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| ())?;
    if signature.len() != expected.len() {
        return Err(());
    }
    let mut diff: u8 = 0;
    for (a, b) in expected.as_slice().iter().zip(signature.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(());
    }

    // Decode the payload and require a valid `exp` claim.
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| ())?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|_| ())?;
    let now = Utc::now().timestamp();
    let exp = payload.get("exp").and_then(|v| v.as_i64()).ok_or(())?;
    if exp < now {
        return Err(());
    }

    Ok(payload)
}

async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let client_key = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').next().unwrap_or("unknown").trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let allowed = state.rate_limiter.check(&client_key).await;
    if !allowed {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded. Try again later.",
        )
        .into_response();
    }

    next.run(req).await.into_response()
}

async fn security_headers_middleware(req: Request, next: Next) -> impl IntoResponse {
    let mut response = next.run(req).await.into_response();
    let headers = response.headers_mut();
    for (name, value) in security_headers() {
        headers.insert(name.clone(), value.clone());
    }
    response
}

// ── Handlers ──────────────────────────────────────────────────────────────

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: "0.1.0".into(),
        server_time: Utc::now().to_rfc3339(),
    })
}

async fn scan_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, Json<serde_json::Value>)> {
    if req.target.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "target is required",
        ));
    }

    let scan_id = Uuid::now_v7().to_string();
    let start = Instant::now();

    let parsed_url = Url::parse(&req.target)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Invalid URL: {e}")))?;

    if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "Only http/https targets are allowed",
        ));
    }

    let run_all = req.scan_types.iter().any(|t| t == "all");
    let modules_to_run: Vec<String> = if run_all {
        ALL_MODULES.iter().map(|s| s.to_string()).collect()
    } else {
        let valid: Vec<String> = req
            .scan_types
            .iter()
            .filter(|t| ALL_MODULES.contains(&t.as_str()))
            .cloned()
            .collect();
        if valid.is_empty() {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "No valid scan types specified",
            ));
        }
        valid
    };

    let mut findings = Vec::new();
    for module in &modules_to_run {
        findings.extend(run_module(&state.client, &parsed_url, module).await);
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    {
        let mut store = state.findings.write().await;
        store.extend(findings.clone());
    }
    {
        let mut history = state.scan_history.write().await;
        history.push(ScanRecord {
            scan_id: scan_id.clone(),
            target: req.target.clone(),
            modules_run: modules_to_run.clone(),
            finding_count: findings.len(),
            duration_ms,
        });
    }

    Ok(Json(ScanResponse {
        scan_id,
        target: req.target,
        findings,
        modules_run: modules_to_run,
        duration_ms,
    }))
}

async fn findings_handler(State(state): State<Arc<AppState>>) -> Json<Vec<Finding>> {
    let store = state.findings.read().await;
    Json(store.clone())
}

async fn cve_lookup_handler(
    Json(req): Json<CveLookupRequest>,
) -> Result<Json<CveLookupResponse>, (StatusCode, Json<serde_json::Value>)> {
    if req.name.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "component name is required",
        ));
    }

    let component = grym_cve_intel::ComponentFingerprint {
        name: req.name,
        version: req.version,
        purl: req.purl,
        cpe: req.cpe,
        source: "serve".into(),
    };

    let correlator = grym_cve_intel::CveCorrelator::new();
    let result = correlator.correlate(&component).await.map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("CVE lookup failed: {e}"),
        )
    })?;

    let matches: Vec<CveMatch> = result
        .matches
        .into_iter()
        .map(|v| CveMatch {
            id: v.id,
            sources: v.sources,
            cvss_score: v.cvss_score,
            description: v.description,
            known_exploited: v.known_exploited,
            references: v.references,
        })
        .collect();

    Ok(Json(CveLookupResponse {
        component: result.component.name,
        version: result.component.version,
        matches,
    }))
}

async fn state_handler(State(state): State<Arc<AppState>>) -> Json<ServerStateResponse> {
    let findings_count = state.findings.read().await.len();
    let scan_count = state.scan_history.read().await.len();
    let uptime_secs = state.start_time.elapsed().as_secs();

    Json(ServerStateResponse {
        findings_count,
        scan_count,
        uptime_secs,
    })
}

async fn cve_db_handler() -> Json<Vec<grym_web_scanner::cve_db::CveEntry>> {
    Json(cve_db::get_cve_database())
}

// ── Playbook handlers ───────────────────────────────────────────────────

async fn playbook_payloads_handler() -> Json<Vec<grym_web_scanner::playbook::PayloadSet>> {
    Json(grym_web_scanner::playbook::payload_sets())
}

async fn playbook_payload_set_handler(
    axum::extract::Path(set_id): axum::extract::Path<String>,
) -> Result<Json<grym_web_scanner::playbook::PayloadSet>, (StatusCode, Json<serde_json::Value>)> {
    grym_web_scanner::playbook::payload_set(&set_id)
        .map(Json)
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "payload set not found"))
}

async fn playbook_techniques_handler() -> Json<Vec<grym_web_scanner::playbook::Technique>> {
    Json(grym_web_scanner::playbook::techniques())
}

async fn playbook_technique_handler(
    axum::extract::Path(tech_id): axum::extract::Path<String>,
) -> Result<Json<grym_web_scanner::playbook::Technique>, (StatusCode, Json<serde_json::Value>)> {
    grym_web_scanner::playbook::technique(&tech_id)
        .map(Json)
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "technique not found"))
}

async fn playbook_search_handler(
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> Result<Json<grym_web_scanner::playbook::SearchResult>, (StatusCode, Json<serde_json::Value>)> {
    let query = params
        .get("q")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            error_response(StatusCode::BAD_REQUEST, "query parameter 'q' is required")
        })?;
    Ok(Json(grym_web_scanner::playbook::search(&query)))
}

async fn playbook_checklist_handler(
    State(state): State<Arc<AppState>>,
) -> Json<grym_web_scanner::checklist::Checklist> {
    Json(state.checklist.read().await.clone())
}

#[derive(Deserialize)]
struct ChecklistToggleRequest {
    phase_id: String,
    step_id: String,
    checked: bool,
}

async fn playbook_checklist_toggle_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChecklistToggleRequest>,
) -> Result<Json<grym_web_scanner::checklist::Checklist>, (StatusCode, Json<serde_json::Value>)> {
    let mut checklist = state.checklist.write().await;
    if !checklist.set_checked(&req.phase_id, &req.step_id, req.checked) {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "phase_id/step_id combination not found",
        ));
    }
    Ok(Json(checklist.clone()))
}

#[derive(Deserialize)]
struct PlanRequest {
    target: String,
    #[serde(default)]
    technologies: Vec<String>,
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    engagement_id: String,
    /// Override tier/deepness; defaults come from loaded settings when omitted.
    max_tier: Option<u8>,
    deepness: Option<String>,
}

async fn playbook_plan_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PlanRequest>,
) -> Result<Json<grym_web_scanner::plan::EngagementPlan>, (StatusCode, Json<serde_json::Value>)> {
    if req.target.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "target is required",
        ));
    }
    // Tier/deepness defaults from the loaded scope settings.
    let scope_settings = state.settings.read().await.scope.clone();
    let limits = grym_web_scanner::plan::PlanLimits {
        max_tier: req.max_tier.unwrap_or(scope_settings.max_tier).min(4),
        deepness: req.deepness.unwrap_or(scope_settings.deepness),
    };
    let profile = grym_web_scanner::plan::TargetProfile {
        base_url: req.target,
        technologies: req.technologies,
        authenticated: req.authenticated,
        notes: Vec::new(),
        engagement_id: req.engagement_id,
    };
    Ok(Json(grym_web_scanner::plan::generate(&profile, &limits)))
}

async fn cve_lookup_by_id_handler(
    axum::extract::Path(cve_id): axum::extract::Path<String>,
) -> Result<Json<grym_web_scanner::cve_db::CveEntry>, (StatusCode, Json<serde_json::Value>)> {
    if cve_id.trim().is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "CVE ID is required",
        ));
    }
    cve_db::lookup_cve(&cve_id)
        .map(Json)
        .ok_or_else(|| error_response(StatusCode::NOT_FOUND, "CVE not found"))
}

async fn exploit_gen_handler(
    Json(req): Json<ExploitGenRequest>,
) -> Result<Json<ExploitGenResponse>, (StatusCode, Json<serde_json::Value>)> {
    let format = match req.format.as_deref().unwrap_or("python") {
        "python" => grym_web_scanner::exploit_gen::ExploitFormat::Python,
        "curl" => grym_web_scanner::exploit_gen::ExploitFormat::Curl,
        "bash" => grym_web_scanner::exploit_gen::ExploitFormat::Bash,
        "nuclei" => grym_web_scanner::exploit_gen::ExploitFormat::NucleiYaml,
        "go" => grym_web_scanner::exploit_gen::ExploitFormat::Go,
        "rust" => grym_web_scanner::exploit_gen::ExploitFormat::Rust,
        "powershell" => grym_web_scanner::exploit_gen::ExploitFormat::PowerShell,
        _ => grym_web_scanner::exploit_gen::ExploitFormat::Python,
    };

    let opts = grym_web_scanner::exploit_gen::ExploitGenOptions {
        target_url: req.target,
        target_ip: None,
        target_port: None,
        callback_ip: req.callback_ip,
        callback_port: req.callback_port,
        language: format,
        include_shell: req.include_shell.unwrap_or(false),
        obfuscate: req.obfuscate.unwrap_or(false),
    };

    let exploit = if let Some(cve_id) = req.cve_id {
        grym_web_scanner::exploit_gen::generate_cve_exploit_command(&cve_id, "http://target", &opts)
    } else {
        None
    };

    let generated_variants = if let Some(ref ex) = exploit {
        grym_web_scanner::exploit_gen::generate_payload_variants(&ex.code, 10)
    } else {
        Vec::new()
    };

    Ok(Json(ExploitGenResponse {
        exploit,
        generated_variants,
    }))
}

async fn predict_handler(Json(req): Json<PredictionRequest>) -> Json<PredictionResponse> {
    let engine = grym_cve_intel::PredictionEngine::new();
    let predictions = engine.predict_zero_days(&req.component, &req.version);
    Json(PredictionResponse { predictions })
}

async fn analyze_body_handler(Json(req): Json<serde_json::Value>) -> Json<PredictionResponse> {
    let engine = grym_cve_intel::PredictionEngine::new();
    let body = req.get("body").and_then(|v| v.as_str()).unwrap_or("");
    let component = req
        .get("component")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    Json(PredictionResponse {
        predictions: engine.analyze_response(body, component),
    })
}

// ── Settings Handlers ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct SettingsResponse {
    ollama: OllamaConfigResponse,
    scope: grym_core::settings::ScopeSettings,
    preferences: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
struct OllamaConfigResponse {
    base_url: String,
    reachable: bool,
    auto_detected: bool,
    version: Option<String>,
    available_models: Vec<String>,
    last_checked: Option<String>,
}

#[derive(Deserialize)]
struct ScopeUpdateRequest {
    engagement_id: Option<String>,
    client: Option<String>,
    authorized_start: Option<String>,
    authorized_end: Option<String>,
    emergency_contact: Option<String>,
    allow: Option<Vec<String>>,
    deny: Option<Vec<String>>,
    max_rps_global: Option<u32>,
    max_rps_host: Option<u32>,
    max_response_bytes: Option<u64>,
    max_tier: Option<u8>,
    deepness: Option<String>,
    authorization_attested: Option<bool>,
}

#[derive(Deserialize)]
struct OllamaUpdateRequest {
    base_url: Option<String>,
}

async fn get_settings_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SettingsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let settings = state.settings.read().await;
    Ok(Json(SettingsResponse {
        ollama: OllamaConfigResponse {
            base_url: settings.ollama.base_url.clone(),
            reachable: settings.ollama.reachable,
            auto_detected: settings.ollama.auto_detected,
            version: settings.ollama.version.clone(),
            available_models: settings.ollama.available_models.clone(),
            last_checked: settings.ollama.last_checked.clone(),
        },
        scope: settings.scope.clone(),
        preferences: settings.preferences.clone(),
    }))
}

async fn update_scope_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScopeUpdateRequest>,
) -> Result<Json<SettingsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mut settings = state.settings.write().await;

    if let Some(v) = req.engagement_id {
        settings.scope.engagement_id = v;
    }
    if let Some(v) = req.client {
        settings.scope.client = v;
    }
    if let Some(v) = req.authorized_start {
        settings.scope.authorized_start = v;
    }
    if let Some(v) = req.authorized_end {
        settings.scope.authorized_end = v;
    }
    if let Some(v) = req.emergency_contact {
        settings.scope.emergency_contact = v;
    }
    if let Some(v) = req.allow {
        settings.scope.allow = v;
    }
    if let Some(v) = req.deny {
        settings.scope.deny = v;
    }
    if let Some(v) = req.max_rps_global {
        settings.scope.max_rps_global = v;
    }
    if let Some(v) = req.max_rps_host {
        settings.scope.max_rps_host = v;
    }
    if let Some(v) = req.max_response_bytes {
        settings.scope.max_response_bytes = v;
    }
    if let Some(v) = req.max_tier {
        settings.scope.max_tier = v.min(4);
    }
    if let Some(v) = req.deepness {
        settings.scope.deepness = v;
    }
    if let Some(v) = req.authorization_attested {
        settings.scope.authorization_attested = v;
    }

    // Validate the scope config
    if let Err(e) = settings.scope.to_scope_config() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            &format!("Invalid scope: {e}"),
        ));
    }

    // Persist
    if let Err(e) = settings.save() {
        tracing::warn!("Failed to save settings: {e}");
    }

    drop(settings);
    get_settings_handler(State(state)).await
}

async fn validate_scope_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScopeUpdateRequest>,
) -> Json<serde_json::Value> {
    let settings = state.settings.read().await;
    let mut test_scope = settings.scope.clone();

    if let Some(v) = req.engagement_id {
        test_scope.engagement_id = v;
    }
    if let Some(v) = req.client {
        test_scope.client = v;
    }
    if let Some(v) = req.authorized_start {
        test_scope.authorized_start = v;
    }
    if let Some(v) = req.authorized_end {
        test_scope.authorized_end = v;
    }
    if let Some(v) = req.emergency_contact {
        test_scope.emergency_contact = v;
    }
    if let Some(v) = req.allow {
        test_scope.allow = v;
    }
    if let Some(v) = req.deny {
        test_scope.deny = v;
    }
    if let Some(v) = req.max_rps_global {
        test_scope.max_rps_global = v;
    }
    if let Some(v) = req.max_rps_host {
        test_scope.max_rps_host = v;
    }
    if let Some(v) = req.max_response_bytes {
        test_scope.max_response_bytes = v;
    }
    if let Some(v) = req.max_tier {
        test_scope.max_tier = v;
    }
    if let Some(v) = req.deepness {
        test_scope.deepness = v;
    }
    if let Some(v) = req.authorization_attested {
        test_scope.authorization_attested = v;
    }

    match test_scope.to_scope_config() {
        Ok(cfg) => Json(serde_json::json!({
            "valid": true,
            "policy_hash": cfg.hash().unwrap_or_default(),
        })),
        Err(e) => Json(serde_json::json!({
            "valid": false,
            "error": e,
        })),
    }
}

async fn update_ollama_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OllamaUpdateRequest>,
) -> Result<Json<SettingsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let mut settings = state.settings.write().await;

    if let Some(url) = req.base_url {
        settings.ollama.base_url = url.trim_end_matches('/').to_string();
        settings.ollama.auto_detected = false;
        settings.ollama.reachable =
            grym_core::settings::GrymSettings::check_ollama_url(&settings.ollama.base_url).await;
        if settings.ollama.reachable {
            settings.ollama.last_checked = Some(chrono::Utc::now().to_rfc3339());
        }
    }

    if let Err(e) = settings.save() {
        tracing::warn!("Failed to save settings: {e}");
    }

    drop(settings);
    get_settings_handler(State(state)).await
}

async fn test_ollama_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mut settings = state.settings.write().await;
    let reachable =
        grym_core::settings::GrymSettings::check_ollama_url(&settings.ollama.base_url).await;
    settings.ollama.reachable = reachable;
    if reachable {
        settings.ollama.last_checked = Some(chrono::Utc::now().to_rfc3339());
        settings.update_ollama_info().await;
    }

    Json(serde_json::json!({
        "reachable": reachable,
        "base_url": settings.ollama.base_url,
        "auto_detected": settings.ollama.auto_detected,
        "version": settings.ollama.version,
        "available_models": settings.ollama.available_models,
    }))
}

async fn auto_detect_ollama_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mut settings = state.settings.write().await;
    let found = settings.auto_detect_ollama().await;
    let _ = settings.save();

    Json(serde_json::json!({
        "auto_detected": found,
        "base_url": settings.ollama.base_url,
        "reachable": settings.ollama.reachable,
        "version": settings.ollama.version,
        "available_models": settings.ollama.available_models,
    }))
}

// ── Public entry point ────────────────────────────────────────────────────

pub async fn serve(config: ServeConfig) -> anyhow::Result<()> {
    let scope = create_dev_scope()?;
    let audit: Arc<dyn AuditSink> = Arc::new(MemoryAuditLog::default());
    let attestation = OperatorAttestation {
        engagement_id: scope.engagement.engagement_id.clone(),
        confirmation: OperatorAttestation::required_phrase(&scope.engagement.engagement_id),
    };
    let guard = ScopeGuard::new(scope, Some(attestation), audit)?;
    let client = ScopedClient::new(Arc::new(guard))?;

    let rate_limiter = RateLimiterInner::new(config.rate_limit_per_minute);

    // Load and auto-detect settings
    let mut grym_settings = grym_core::settings::GrymSettings::load();
    let ollama_found = grym_settings.auto_detect_ollama().await;
    if ollama_found {
        tracing::info!("Ollama auto-detected at {}", grym_settings.ollama.base_url);
        if let Some(ver) = &grym_settings.ollama.version {
            tracing::info!("Ollama version: {ver}");
        }
    } else {
        tracing::info!(
            "Ollama not detected at default URL. Configure via /settings/ollama or run auto-detect."
        );
    }
    let _ = grym_settings.save();

    let state = Arc::new(AppState {
        client,
        findings: RwLock::new(Vec::new()),
        scan_history: RwLock::new(Vec::new()),
        start_time: Instant::now(),
        config: config.clone(),
        rate_limiter,
        settings: RwLock::new(grym_settings),
        checklist: RwLock::new(grym_web_scanner::checklist::standard_web_checklist()),
    });

    let cors = if config.allowed_origins.is_empty() {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers(Any)
            .allow_credentials(false)
    } else {
        let origins: Vec<HeaderValue> = config
            .allowed_origins
            .iter()
            .filter_map(|o| HeaderValue::from_str(o).ok())
            .collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                header::ACCEPT,
                HeaderName::from_static("x-request-id"),
            ])
            .allow_credentials(false)
            .max_age(Duration::from_secs(86400))
    };

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/scan", post(scan_handler))
        .route("/findings", get(findings_handler))
        .route("/cve-lookup", post(cve_lookup_handler))
        .route("/cve-db", get(cve_db_handler))
        .route("/cve/{cve_id}", get(cve_lookup_by_id_handler))
        .route("/exploit", post(exploit_gen_handler))
        .route("/predict", post(predict_handler))
        .route("/analyze-body", post(analyze_body_handler))
        .route("/state", get(state_handler))
        // Playbook: payload library, techniques, checklists, plans
        .route("/playbook/payloads", get(playbook_payloads_handler))
        .route(
            "/playbook/payloads/{set_id}",
            get(playbook_payload_set_handler),
        )
        .route("/playbook/techniques", get(playbook_techniques_handler))
        .route(
            "/playbook/techniques/{tech_id}",
            get(playbook_technique_handler),
        )
        .route("/playbook/search", get(playbook_search_handler))
        .route("/playbook/checklist", get(playbook_checklist_handler))
        .route(
            "/playbook/checklist/toggle",
            post(playbook_checklist_toggle_handler),
        )
        .route("/playbook/plan", post(playbook_plan_handler))
        // Settings endpoints
        .route("/settings", get(get_settings_handler))
        .route("/settings/scope", put(update_scope_handler))
        .route("/settings/scope/validate", post(validate_scope_handler))
        .route("/settings/ollama", put(update_ollama_handler))
        .route("/settings/ollama/test", get(test_ollama_handler))
        .route(
            "/settings/ollama/auto-detect",
            post(auto_detect_ollama_handler),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(config.body_limit_bytes))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid address: {e}"))?;

    tracing::info!("Starting GRYM API server on http://{addr}");

    if config.tls_cert_path.is_some() || config.tls_key_path.is_some() {
        tracing::warn!(
            "TLS cert/key paths were provided but TLS is not yet supported directly. Use a reverse proxy (nginx, caddy) for TLS termination."
        );
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
