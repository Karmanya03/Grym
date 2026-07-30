#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    Router, Json, extract::State,
    routing::{get, post},
    http::StatusCode,
};
use chrono::{DateTime, FixedOffset, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::cors::{CorsLayer, Any};
use uuid::Uuid;
use url::Url;

use grym_core::{
    Finding, ScopedClient, ScopeGuard, OperatorAttestation,
    audit::{AuditSink, MemoryAuditLog},
    config::{self, Deepness, TechniqueTier},
};
use grym_web_scanner::{
    sqli, xss, ssti, ssrf, cors as cors_module, jwt, command_injection,
    path_traversal, open_redirect, idor, waf_detect, http_smuggling, xxe,
    tech_fingerprint, csrf, nosqli, graphql, host_header, fuzzer, chain_builder,
    cve_db,
};

static ALL_MODULES: &[&str] = &[
    "sqli", "xss", "ssti", "ssrf", "cmd_injection", "path_traversal",
    "cors", "jwt", "open_redirect", "idor", "waf_detect", "smuggling",
    "xxe", "tech_fingerprint", "csrf", "nosqli", "graphql", "host_header",
    "fuzzer", "chain_builder",
];

// ── Request / Response types ───────────────────────────────────────────────

#[derive(Deserialize)]
struct ScanRequest {
    target: String,
    scan_types: Vec<String>,
    #[serde(rename = "options")]
    _options: Option<ScanOptions>,
}

#[derive(Deserialize, Default)]
struct ScanOptions {
    #[serde(rename = "template")]
    _template: Option<String>,
    #[serde(rename = "timeout_secs")]
    _timeout_secs: Option<u64>,
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

// ── Application state ─────────────────────────────────────────────────────

struct AppState {
    client: ScopedClient,
    findings: RwLock<Vec<Finding>>,
    scan_history: RwLock<Vec<ScanRecord>>,
    start_time: Instant,
}

// ── Handler helpers ───────────────────────────────────────────────────────

fn error_response(status: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({ "error": msg })),
    )
}

fn create_dev_scope() -> anyhow::Result<config::ScopeConfig> {
    let offset = FixedOffset::east_opt(0)
        .ok_or_else(|| anyhow::anyhow!("failed to create UTC offset"))?;
    let now: DateTime<FixedOffset> = Utc::now().with_timezone(&offset);
    let later = now + chrono::TimeDelta::try_hours(24)
        .ok_or_else(|| anyhow::anyhow!("invalid time delta"))?;

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
        "cmd_injection" => command_injection::check_command_injection(client, url).await.unwrap_or_default(),
        "path_traversal" => path_traversal::check_path_traversal(client, url).await.unwrap_or_default(),
        "cors" => cors_module::check_cors(client, url).await.unwrap_or_default(),
        "jwt" => jwt::check_jwt_config(client, url).await.unwrap_or_default(),
        "open_redirect" => open_redirect::check_open_redirect(client, url).await.unwrap_or_default(),
        "idor" => idor::check_idor(client, url).await.unwrap_or_default(),
        "waf_detect" => waf_detect::detect_waf(client, url).await.unwrap_or_default(),
        "smuggling" => http_smuggling::check_http_smuggling(client, url).await.unwrap_or_default(),
        "xxe" => xxe::check_xxe(client, url).await.unwrap_or_default(),
        "tech_fingerprint" => tech_fingerprint::fingerprint_tech(client, url).await.unwrap_or_default(),
        "csrf" => csrf::check_csrf(client, url).await.unwrap_or_default(),
        "nosqli" => nosqli::check_nosqli(client, url).await.unwrap_or_default(),
        "graphql" => graphql::check_graphql(client, url).await.unwrap_or_default(),
        "host_header" => host_header::check_host_header_injection(client, url).await.unwrap_or_default(),
        "fuzzer" => fuzzer::fuzz_all(client, url).await.unwrap_or_default(),
        "chain_builder" => chain_builder::build_chains_from_findings(client, url).await.unwrap_or_default(),
        _ => Vec::new(),
    }
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
    let scan_id = Uuid::now_v7().to_string();
    let start = Instant::now();

    let parsed_url = Url::parse(&req.target)
        .map_err(|e| error_response(StatusCode::BAD_REQUEST, &format!("Invalid URL: {e}")))?;

    // Determine which modules to run
    let run_all = req.scan_types.iter().any(|t| t == "all");
    let modules_to_run: Vec<String> = if run_all {
        ALL_MODULES.iter().map(|s| s.to_string()).collect()
    } else {
        let valid: Vec<String> = req.scan_types.iter()
            .filter(|t| ALL_MODULES.contains(&t.as_str()))
            .cloned()
            .collect();
        if valid.is_empty() {
            return Err(error_response(StatusCode::BAD_REQUEST, "No valid scan types specified"));
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

async fn findings_handler(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<Finding>> {
    let store = state.findings.read().await;
    Json(store.clone())
}

async fn cve_lookup_handler(
    Json(req): Json<CveLookupRequest>,
) -> Result<Json<CveLookupResponse>, (StatusCode, Json<serde_json::Value>)> {
    let component = grym_cve_intel::ComponentFingerprint {
        name: req.name,
        version: req.version,
        purl: req.purl,
        cpe: req.cpe,
        source: "serve".into(),
    };

    let correlator = grym_cve_intel::CveCorrelator::new();
    let result = correlator.correlate(&component).await
        .map_err(|e| error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("CVE lookup failed: {e}")))?;

    let matches: Vec<CveMatch> = result.matches.into_iter().map(|v| CveMatch {
        id: v.id,
        sources: v.sources,
        cvss_score: v.cvss_score,
        description: v.description,
        known_exploited: v.known_exploited,
        references: v.references,
    }).collect();

    Ok(Json(CveLookupResponse {
        component: result.component.name,
        version: result.component.version,
        matches,
    }))
}

async fn state_handler(
    State(state): State<Arc<AppState>>,
) -> Json<ServerStateResponse> {
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

async fn cve_lookup_by_id_handler(
    axum::extract::Path(cve_id): axum::extract::Path<String>,
) -> Result<Json<grym_web_scanner::cve_db::CveEntry>, (StatusCode, Json<serde_json::Value>)> {
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

async fn predict_handler(
    Json(req): Json<PredictionRequest>,
) -> Json<PredictionResponse> {
    let engine = grym_cve_intel::PredictionEngine::new();
    let predictions = engine.predict_zero_days(&req.component, &req.version);
    Json(PredictionResponse { predictions })
}

async fn analyze_body_handler(
    Json(req): Json<serde_json::Value>,
) -> Json<PredictionResponse> {
    let engine = grym_cve_intel::PredictionEngine::new();
    let body = req.get("body").and_then(|v| v.as_str()).unwrap_or("");
    let component = req.get("component").and_then(|v| v.as_str()).unwrap_or("unknown");
    Json(PredictionResponse {
        predictions: engine.analyze_response(body, component),
    })
}

// ── Public entry point ────────────────────────────────────────────────────

pub async fn serve(host: &str, port: u16, _scope_path: Option<&str>) -> anyhow::Result<()> {
    let scope = create_dev_scope()?;
    let audit: Arc<dyn AuditSink> = Arc::new(MemoryAuditLog::default());
    let attestation = OperatorAttestation {
        engagement_id: scope.engagement.engagement_id.clone(),
        confirmation: OperatorAttestation::required_phrase(&scope.engagement.engagement_id),
    };
    let guard = ScopeGuard::new(scope, Some(attestation), audit)?;
    let client = ScopedClient::new(Arc::new(guard))?;

    let state = Arc::new(AppState {
        client,
        findings: RwLock::new(Vec::new()),
        scan_history: RwLock::new(Vec::new()),
        start_time: Instant::now(),
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::OPTIONS])
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/scan", post(scan_handler))
        .route("/findings", get(findings_handler))
        .route("/cve-lookup", post(cve_lookup_handler))
        .route("/cve-db", get(cve_db_handler))
        .route("/cve/:cve_id", get(cve_lookup_by_id_handler))
        .route("/exploit", post(exploit_gen_handler))
        .route("/predict", post(predict_handler))
        .route("/analyze-body", post(analyze_body_handler))
        .route("/state", get(state_handler))
        .layer(cors)
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid address: {e}"))?;

    tracing::info!("Starting GRYM API server on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
