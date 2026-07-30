#![deny(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use grym_core::{
    ScopeConfig, ScopeGuard, OperatorAttestation,
    audit::{AuditSink, MemoryAuditLog},
};
use grym_storage::{FindingStore, MemoryFindingStore};

mod serve;

/// GRYM — Scope-enforced security assessment platform.
#[derive(Debug, Parser)]
#[command(name = "grym", version, about = "Advanced Web/App PT Automation Toolkit", author)]
struct Cli {
    #[arg(long, global = true)]
    json_logs: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scope validation and inspection.
    Scope {
        #[command(subcommand)]
        command: ScopeCommand,
    },
    /// Passive reconnaissance (no packets to target).
    ReconPassive {
        /// Target domain to enumerate.
        domain: String,
        /// Path to scope config.
        #[arg(short, long, default_value = "config/scope.toml")]
        scope: PathBuf,
        /// Output findings as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Active reconnaissance (safe probes to target).
    ReconActive {
        /// Target URL.
        url: String,
        /// Path to scope config.
        #[arg(short, long, default_value = "config/scope.toml")]
        scope: PathBuf,
        /// Run port scan.
        #[arg(long)]
        port_scan: bool,
        /// Run vhost brute force.
        #[arg(long)]
        vhost_brute: bool,
        /// Run web crawler.
        #[arg(long)]
        crawl: bool,
        /// Run content discovery.
        #[arg(long)]
        content_discovery: bool,
        /// Run parameter discovery.
        #[arg(long)]
        param_discovery: bool,
        /// Run all active recon modules.
        #[arg(long)]
        all: bool,
    },
    /// Web vulnerability scanning.
    Scan {
        /// Target URL.
        url: String,
        /// Path to scope config.
        #[arg(short, long, default_value = "config/scope.toml")]
        scope: PathBuf,
        /// Scan for SQL injection.
        #[arg(long)]
        sqli: bool,
        /// Scan for XSS.
        #[arg(long)]
        xss: bool,
        /// Scan for SSTI.
        #[arg(long)]
        ssti: bool,
        /// Scan for JWT issues.
        #[arg(long)]
        jwt: bool,
        /// Scan for CORS misconfig.
        #[arg(long)]
        cors: bool,
        /// Scan for SSRF.
        #[arg(long)]
        ssrf: bool,
        /// Scan for command injection.
        #[arg(long)]
        cmd_injection: bool,
        /// Scan for path traversal.
        #[arg(long)]
        path_traversal: bool,
        /// Scan for open redirect.
        #[arg(long)]
        open_redirect: bool,
        /// Scan for IDOR.
        #[arg(long)]
        idor: bool,
        /// Scan for WAF detection.
        #[arg(long)]
        waf_detect: bool,
        /// Scan for HTTP request smuggling.
        #[arg(long)]
        smuggling: bool,
        /// Scan for XXE injection.
        #[arg(long)]
        xxe: bool,
        /// Scan for technology fingerprinting.
        #[arg(long)]
        tech_fingerprint: bool,
        /// Scan for CSRF vulnerabilities.
        #[arg(long)]
        csrf: bool,
        /// Run all vulnerability checks.
        #[arg(long)]
        all: bool,
        /// Output findings as JSON.
        #[arg(long)]
        json: bool,
        /// Use template file for signature-based checks.
        #[arg(short, long)]
        template: Option<PathBuf>,
    },
    /// CVE correlation for fingerprinted software.
    Cve {
        /// Software/product name.
        name: String,
        /// Version string.
        version: String,
        /// PURL for OSV query.
        #[arg(long)]
        purl: Option<String>,
        /// CPE for NVD query.
        #[arg(long)]
        cpe: Option<String>,
    },
    /// Generate reports from findings.
    Report {
        /// Path to findings JSON file.
        findings: PathBuf,
        /// Output format (json, markdown, html).
        #[arg(short, long, default_value = "markdown")]
        format: String,
        /// Output file path.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Engagement ID.
        #[arg(short, long)]
        engagement: Option<String>,
    },
    /// Launch the TUI dashboard.
    Tui {
        /// Path to scope config.
        #[arg(short, long, default_value = "config/scope.toml")]
        scope: PathBuf,
    },
    /// Start the local API server for the browser extension.
    Serve {
        /// Host to bind to (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Port to listen on (default: 9378)
        #[arg(long, default_value_t = 9378)]
        port: u16,
        /// Path to scope config
        #[arg(short, long, default_value = "config/scope.toml")]
        scope: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    initialize_tracing(cli.json_logs)?;

    match cli.command {
        Command::Scope { command } => handle_scope(command).await?,
        Command::ReconPassive { domain, scope: scope_path, json } => {
            handle_recon_passive(&domain, &scope_path, json).await?
        }
        Command::ReconActive { url, scope: scope_path, port_scan, vhost_brute, crawl, content_discovery, param_discovery, all } => {
            handle_recon_active(&url, &scope_path, port_scan || all, vhost_brute || all, crawl || all, content_discovery || all, param_discovery || all).await?
        }
        Command::Scan { url, scope: scope_path, sqli, xss, ssti, jwt, cors, ssrf, cmd_injection, path_traversal, open_redirect, idor, waf_detect, smuggling, xxe, tech_fingerprint, csrf, all, json, template } => {
            handle_scan(&url, &scope_path, sqli || all, xss || all, ssti || all, jwt || all, cors || all, ssrf || all, cmd_injection || all, path_traversal || all, open_redirect || all, idor || all, waf_detect || all, smuggling || all, xxe || all, tech_fingerprint || all, csrf || all, json, template).await?
        }
        Command::Cve { name, version, purl, cpe } => {
            handle_cve(&name, &version, purl.as_deref(), cpe.as_deref()).await?
        }
        Command::Report { findings, format, output, engagement } => {
            handle_report(&findings, &format, output.as_ref(), engagement.as_deref())?
        }
        Command::Tui { scope: _ } => {
            grym_tui::run().await?;
        }
        Command::Serve { host, port, scope: _ } => {
            serve::serve(&host, port, None).await?
        }
    }

    Ok(())
}

fn initialize_tracing(json_logs: bool) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("grym=info"));
    let result = if json_logs {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .try_init()
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .try_init()
    };
    result.map_err(|e| anyhow::anyhow!("tracing init: {}", e))
}

fn load_scope(path: &PathBuf) -> Result<(ScopeGuard, Arc<MemoryAuditLog>)> {
    let config = ScopeConfig::load(path)?;
    let audit = Arc::new(MemoryAuditLog::default());
    let attestation = OperatorAttestation {
        engagement_id: config.engagement.engagement_id.clone(),
        confirmation: OperatorAttestation::required_phrase(&config.engagement.engagement_id),
    };
    let guard = ScopeGuard::new(config, Some(attestation), audit.clone() as Arc<dyn AuditSink>)?;
    Ok((guard, audit))
}

async fn handle_scope(command: ScopeCommand) -> Result<()> {
    match command {
        ScopeCommand::Validate { path } => {
            let scope = ScopeConfig::load(&path)?;
            println!("✓ Scope valid: {}", path.display());
            println!("  Engagement: {}", scope.engagement.engagement_id);
            println!("  Client: {}", scope.engagement.client);
            println!("  Window: {} → {}", scope.engagement.authorized_start, scope.engagement.authorized_end);
            println!("  Policy hash: {}", scope.hash()?);
        }
        ScopeCommand::Show { path } => {
            let scope = ScopeConfig::load(&path)?;
            println!("Engagement: {}", scope.engagement.engagement_id);
            println!("Client: {}", scope.engagement.client);
            println!("Window: {} to {}", scope.engagement.authorized_start, scope.engagement.authorized_end);
            println!("Allowed rules: {}", scope.targets.allow.len());
            for rule in &scope.targets.allow {
                println!("  + {}", rule);
            }
            println!("Denied rules: {}", scope.targets.deny.len());
            for rule in &scope.targets.deny {
                println!("  - {}", rule);
            }
            println!("Max tier: {}", u8::from(scope.technique.max_tier));
            println!("Deepness: {:?}", scope.technique.deepness);
            println!("Policy hash: {}", scope.hash()?);
        }
    }
    Ok(())
}

#[derive(Debug, Subcommand)]
enum ScopeCommand {
    Validate {
        #[arg(default_value = "config/scope.toml")]
        path: PathBuf,
    },
    Show {
        #[arg(default_value = "config/scope.toml")]
        path: PathBuf,
    },
}

async fn handle_recon_passive(domain: &str, scope_path: &PathBuf, json: bool) -> Result<()> {
    println!("🔍 GRYM Passive Reconnaissance — target: {}", domain);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let (_guard, _audit) = load_scope(scope_path)?;
    let store = MemoryFindingStore::default();

    // DNS enumeration
    println!("[*] Enumerating DNS records...");
    let dns_records = grym_recon_passive::enumerate_dns_records(domain).await;
    for record in &dns_records {
        println!("  {} {} → {}", record.record_type, record.hostname, record.value);
    }

    // CT log enumeration
    println!("\n[*] Querying Certificate Transparency logs...");
    match grym_recon_passive::query_crtsh(domain).await {
        Ok(subdomains) => {
            println!("  Found {} unique subdomains:", subdomains.len());
            for sd in subdomains.iter().take(20) {
                println!("  ├─ {}", sd);
            }
            if subdomains.len() > 20 {
                println!("  └─ ... and {} more", subdomains.len() - 20);
            }
        }
        Err(e) => println!("  CT log query failed: {}", e),
    }

    // Subdomain enumeration
    println!("\n[*] Enumerating subdomains via passive sources...");
    let subdomains = grym_recon_passive::enumerate_subdomains(domain).await;
    let sub_findings = grym_recon_passive::subdomains_to_findings(&subdomains, domain);
    for f in &sub_findings {
        store.insert(f.clone())?;
    }
    println!("  Found {} active subdomains", subdomains.len());

    // Permutation candidates
    let permutations = grym_recon_passive::generate_subdomain_permutations(domain);
    println!("\n[*] Generated {} permutation candidates", permutations.len());

    println!("\n✓ Passive recon complete — {} findings stored", sub_findings.len());

    if json {
        println!("{}", serde_json::to_string_pretty(&store.all()?)?);
    }

    Ok(())
}

async fn handle_recon_active(
    url: &str,
    scope_path: &PathBuf,
    port_scan: bool,
    vhost_brute: bool,
    crawl: bool,
    content_discovery: bool,
    param_discovery: bool,
) -> Result<()> {
    println!("🔎 GRYM Active Reconnaissance — target: {}", url);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let (guard, _audit) = load_scope(scope_path)?;
    let client = grym_core::ScopedClient::new(Arc::new(guard))?;
    let parsed_url = url::Url::parse(url)?;
    let host = parsed_url.host_str().unwrap_or("unknown");
    let store = MemoryFindingStore::default();

    // Port scan
    if port_scan {
        println!("[*] Scanning common ports on {}...", host);
        let ports = grym_recon_active::scan_common_ports(host, grym_recon_active::COMMON_PORTS, 1500).await;
        let open: Vec<_> = ports.iter().filter(|p| p.open).collect();
        if open.is_empty() {
            println!("  No open ports found");
        } else {
            for p in &open {
                println!("  ├─ {}/{} — OPEN", p.port, p.service);
            }
            let findings = grym_recon_active::port_results_to_findings(&ports);
            for f in &findings {
                store.insert(f.clone())?;
            }
            println!("  └─ {} open ports found", open.len());
        }
    }

    // Vhost brute force
    if vhost_brute {
        println!("\n[*] Brute-forcing virtual hosts...");
        let vhosts = grym_recon_active::common_vhosts();
        let results = grym_recon_active::brute_force_vhosts(&client, &parsed_url, &vhosts).await;
        let interesting: Vec<_> = results.iter().filter(|r| r.different_from_base).collect();
        if interesting.is_empty() {
            println!("  No interesting vhosts found");
        } else {
            for r in interesting {
                println!("  ├─ {} — Status: {}, Title: {:?}", r.hostname, r.status, r.title);
            }
            let findings = grym_recon_active::vhost_results_to_findings(&results, &parsed_url);
            for f in &findings {
                store.insert(f.clone())?;
            }
        }
    }

    // Crawler
    if crawl {
        println!("\n[*] Crawling {}...", url);
        let results = grym_recon_active::crawl(&client, parsed_url.clone(), 2, 20).await;
        println!("  Crawled {} pages", results.len());
        for page in &results {
            println!("  ├─ {} (depth {}, {} links)", page.url, page.depth, page.links.len());
        }
        let findings = grym_recon_active::crawl_results_to_findings(&results);
        for f in &findings {
            store.insert(f.clone())?;
        }
    }

    // Content discovery
    if content_discovery {
        println!("\n[*] Discovering content paths...");
        let paths = grym_recon_active::common_paths();
        let results = grym_recon_active::discover_content(&client, &parsed_url, &paths).await;
        if results.is_empty() {
            println!("  No interesting paths found");
        } else {
            for r in &results {
                println!("  ├─ {} (HTTP {}, {} bytes)", r.url, r.status, r.content_length);
            }
            let findings = grym_recon_active::content_discovery_to_findings(&results);
            for f in &findings {
                store.insert(f.clone())?;
            }
        }
    }

    // Parameter discovery
    if param_discovery {
        println!("\n[*] Discovering parameters...");
        let params = grym_recon_active::common_parameters();
        let results = grym_recon_active::discover_parameters(&client, &parsed_url, &params).await?;
        if results.is_empty() {
            println!("  No valid parameters discovered");
        } else {
            for r in &results {
                println!("  ├─ ?{} (HTTP {}, {} bytes)", r.parameter, r.status, r.content_length);
            }
        }
    }

    println!("\n✓ Active recon complete — {} findings stored", store.all()?.len());

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_scan(
    url: &str,
    scope_path: &PathBuf,
    sqli: bool,
    xss: bool,
    ssti: bool,
    jwt: bool,
    cors: bool,
    ssrf: bool,
    cmd_injection: bool,
    path_traversal: bool,
    open_redirect: bool,
    idor: bool,
    waf_detect: bool,
    smuggling: bool,
    xxe: bool,
    tech_fingerprint: bool,
    csrf: bool,
    json: bool,
    template: Option<PathBuf>,
) -> Result<()> {
    println!("🛡️  GRYM Web Vulnerability Scanner — target: {}", url);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let (guard, _audit) = load_scope(scope_path)?;
    let client = grym_core::ScopedClient::new(Arc::new(guard))?;
    let parsed_url = url::Url::parse(url)?;
    let store = MemoryFindingStore::default();

    // Template-based scan
    if let Some(template_path) = template {
        println!("[*] Loading detection template: {:?}", template_path);
        let template_data = std::fs::read_to_string(&template_path)?;
        let detection_template = grym_template_engine::DetectionTemplate::from_yaml(&template_data)?;
        if let Some(finding) = grym_web_scanner::scan_template(&client, parsed_url.clone(), &detection_template).await? {
            store.insert(finding)?;
            println!("  Template matched!");
        }
    }

    // Test probe
    let probe = grym_recon_active::probe(&client, parsed_url.clone()).await?;
    println!("[*] Target probe: HTTP {} — {} bytes — {}ms",
        probe.status,
        probe.content_length.unwrap_or(0),
        probe.response_time_ms,
    );

    if sqli {
        println!("\n[*] Checking SQL Injection...");
        let findings = grym_web_scanner::sqli::check_sqli(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No SQLi detected");
        }
    }

    if xss {
        println!("\n[*] Checking XSS...");
        let findings = grym_web_scanner::xss::check_xss(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No XSS detected");
        }
    }

    if ssti {
        println!("\n[*] Checking SSTI...");
        let findings = grym_web_scanner::ssti::check_ssti(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No SSTI detected");
        }
    }

    if jwt {
        println!("\n[*] Checking JWT configuration...");
        let findings = grym_web_scanner::jwt::check_jwt_config(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No JWT issues detected");
        }
    }

    if cors {
        println!("\n[*] Checking CORS configuration...");
        let findings = grym_web_scanner::cors::check_cors(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No CORS issues detected");
        }
    }

    if ssrf {
        println!("\n[*] Checking SSRF...");
        let findings = grym_web_scanner::ssrf::check_ssrf(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No SSRF detected");
        }
    }

    if cmd_injection {
        println!("\n[*] Checking Command Injection...");
        let findings = grym_web_scanner::command_injection::check_command_injection(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No Command Injection detected");
        }
    }

    if path_traversal {
        println!("\n[*] Checking Path Traversal...");
        let findings = grym_web_scanner::path_traversal::check_path_traversal(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No Path Traversal detected");
        }
    }

    if open_redirect {
        println!("\n[*] Checking Open Redirect...");
        let findings = grym_web_scanner::open_redirect::check_open_redirect(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No Open Redirect detected");
        }
    }

    if idor {
        println!("\n[*] Checking IDOR...");
        let findings = grym_web_scanner::idor::check_idor(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No IDOR detected");
        }
    }

    if waf_detect {
        println!("\n[*] Detecting WAF...");
        let findings = grym_web_scanner::waf_detect::detect_waf(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No WAF detected");
        }
    }

    if smuggling {
        println!("\n[*] Checking HTTP Request Smuggling...");
        let findings = grym_web_scanner::http_smuggling::check_http_smuggling(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No HTTP Smuggling detected");
        }
    }

    if xxe {
        println!("\n[*] Checking XXE Injection...");
        let findings = grym_web_scanner::xxe::check_xxe(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No XXE detected");
        }
    }

    if tech_fingerprint {
        println!("\n[*] Fingerprinting Technology Stack...");
        let findings = grym_web_scanner::tech_fingerprint::fingerprint_tech(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No technologies identified");
        }
    }

    if csrf {
        println!("\n[*] Checking CSRF vulnerabilities...");
        let findings = grym_web_scanner::csrf::check_csrf(&client, &parsed_url).await?;
        for f in &findings {
            println!("  ⚠  {}", f.title);
            store.insert(f.clone())?;
        }
        if findings.is_empty() {
            println!("  No CSRF issues detected");
        }
    }

    let all_findings = store.all()?;
    println!("\n✓ Scan complete — {} findings", all_findings.len());

    // Show summary
    let high = all_findings.iter().filter(|f| f.severity >= grym_core::Severity::High).count();
    let med = all_findings.iter().filter(|f| f.severity == grym_core::Severity::Medium).count();
    let low = all_findings.iter().filter(|f| f.severity <= grym_core::Severity::Low).count();
    println!("  High/Critical: {}, Medium: {}, Low/Info: {}", high, med, low);

    if json {
        println!("\n{}", serde_json::to_string_pretty(&all_findings)?);
    }

    Ok(())
}

async fn handle_cve(name: &str, version: &str, purl: Option<&str>, cpe: Option<&str>) -> Result<()> {
    println!("📡 GRYM CVE Intelligence — {}/{}", name, version);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let component = grym_cve_intel::ComponentFingerprint {
        name: name.to_string(),
        version: version.to_string(),
        purl: purl.map(|s| s.to_string()),
        cpe: cpe.map(|s| s.to_string()),
        source: "cli".into(),
    };

    println!("Component:");
    println!("  Name: {}", component.name);
    println!("  Version: {}", component.version);
    if let Some(ref p) = component.purl {
        println!("  PURL: {}", p);
    }
    if let Some(ref c) = component.cpe {
        println!("  CPE: {}", c);
    }

    let correlator = grym_cve_intel::CveCorrelator::new();
    println!("\n[*] Querying vulnerability sources (NVD, OSV, KEV, GHSA)...");

    match correlator.correlate(&component).await {
        Ok(result) => {
            if result.matches.is_empty() {
                println!("\n  No known CVEs found for this component version.");
            } else {
                println!("\n  Found {} matching vulnerabilities:\n", result.matches.len());
                for vuln in &result.matches {
                    let exploited = if vuln.known_exploited { " [KNOWN EXPLOITED]" } else { "" };
                    println!("  ├─ {}{}", vuln.id, exploited);
                    println!("  │  Source: {}", vuln.sources.join(", "));
                    println!("  │  {}", vuln.description.chars().take(150).collect::<String>());
                    if let Some(ref score) = vuln.cvss_score {
                        println!("  │  CVSS: {}", score);
                    }
                    println!();
                }

                let findings = grym_cve_intel::correlation_to_findings(&result);
                println!("  Generated {} findings", findings.len());
                println!("\n{}", serde_json::to_string_pretty(&findings)?);
            }
        }
        Err(e) => {
            eprintln!("  CVE correlation failed: {}", e);
        }
    }

    Ok(())
}

fn handle_report(
    findings_path: &PathBuf,
    format: &str,
    output: Option<&PathBuf>,
    engagement: Option<&str>,
) -> Result<()> {
    println!("📊 GRYM Report Generator");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let data = std::fs::read_to_string(findings_path)?;
    let findings: Vec<grym_core::Finding> = serde_json::from_str(&data)?;

    let document = grym_report::ReportDocument {
        metadata: grym_report::ReportMetadata {
            engagement_id: engagement.unwrap_or("unknown").to_string(),
            scope_hash: "cli-generated".into(),
            partial: false,
        },
        findings,
    };

    let output_str = match format {
        "json" => grym_report::to_json(&document)?,
        "html" => grym_report::to_html(&document),
        _ => grym_report::to_markdown(&document),
    };

    if let Some(output_path) = output {
        std::fs::write(output_path, &output_str)?;
        println!("✓ Report written to: {}", output_path.display());
    } else {
        println!("{}", output_str);
    }

    Ok(())
}
