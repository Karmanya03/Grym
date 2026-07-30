#![deny(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use grym_core::{
    OperatorAttestation, ScopeConfig, ScopeGuard,
    audit::{AuditSink, MemoryAuditLog},
};
use grym_storage::{FindingStore, MemoryFindingStore};

mod serve;

/// GRYM — Scope-enforced security assessment platform.
#[derive(Debug, Parser)]
#[command(
    name = "grym",
    version,
    about = "Advanced Web/App PT Automation Toolkit",
    author
)]
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
    /// Interactive AI-powered pentesting agent.
    Ai {
        /// Prompt for the AI agent.
        prompt: String,
        /// Use the reasoning (mythos-sec:8b) model tier instead of lightweight default.
        #[arg(long)]
        reasoning: bool,
    },
    /// Automated CVE hunting — NVD feed analysis, variant hypothesis, PoC generation.
    Hunt {
        /// Target product description.
        target: String,
        /// Use the reasoning (mythos-sec:8b) model tier instead of lightweight default.
        #[arg(long)]
        reasoning: bool,
    },
    /// Manage settings (scope, Ollama, preferences) via CLI.
    Settings {
        #[command(subcommand)]
        command: SettingsCommand,
    },
    /// Start the hardened API server for the browser extension.
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
        /// API key for Bearer token authentication
        #[arg(long)]
        api_key: Option<String>,
        /// JWT secret for token authentication
        #[arg(long)]
        jwt_secret: Option<String>,
        /// Allowed CORS origins (comma-separated, defaults to all)
        #[arg(long)]
        allowed_origins: Option<String>,
        /// Rate limit per minute per client IP
        #[arg(long, default_value_t = 60)]
        rate_limit: u32,
        /// Maximum request body size in bytes
        #[arg(long, default_value_t = 2 * 1024 * 1024)]
        body_limit: usize,
        /// Path to TLS certificate file
        #[arg(long)]
        tls_cert: Option<String>,
        /// Path to TLS private key file
        #[arg(long)]
        tls_key: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    initialize_tracing(cli.json_logs)?;

    match cli.command {
        Command::Scope { command } => handle_scope(command).await?,
        Command::ReconPassive {
            domain,
            scope: scope_path,
            json,
        } => handle_recon_passive(&domain, &scope_path, json).await?,
        Command::ReconActive {
            url,
            scope: scope_path,
            port_scan,
            vhost_brute,
            crawl,
            content_discovery,
            param_discovery,
            all,
        } => {
            handle_recon_active(
                &url,
                &scope_path,
                port_scan || all,
                vhost_brute || all,
                crawl || all,
                content_discovery || all,
                param_discovery || all,
            )
            .await?
        }
        Command::Scan {
            url,
            scope: scope_path,
            sqli,
            xss,
            ssti,
            jwt,
            cors,
            ssrf,
            cmd_injection,
            path_traversal,
            open_redirect,
            idor,
            waf_detect,
            smuggling,
            xxe,
            tech_fingerprint,
            csrf,
            all,
            json,
            template,
        } => {
            handle_scan(
                &url,
                &scope_path,
                sqli || all,
                xss || all,
                ssti || all,
                jwt || all,
                cors || all,
                ssrf || all,
                cmd_injection || all,
                path_traversal || all,
                open_redirect || all,
                idor || all,
                waf_detect || all,
                smuggling || all,
                xxe || all,
                tech_fingerprint || all,
                csrf || all,
                json,
                template,
            )
            .await?
        }
        Command::Cve {
            name,
            version,
            purl,
            cpe,
        } => handle_cve(&name, &version, purl.as_deref(), cpe.as_deref()).await?,
        Command::Report {
            findings,
            format,
            output,
            engagement,
        } => handle_report(&findings, &format, output.as_ref(), engagement.as_deref())?,
        Command::Tui { scope: _ } => {
            grym_tui::run().await?;
        }
        Command::Settings { command } => handle_settings(command).await?,
        Command::Ai { prompt, reasoning } => {
            let tier = if reasoning {
                grym_ai_agent::ModelTier::Reasoning
            } else {
                grym_ai_agent::ModelTier::Lightweight
            };
            handle_ai(&prompt, tier).await?;
        }
        Command::Hunt { target, reasoning } => {
            let tier = if reasoning {
                grym_ai_agent::ModelTier::Reasoning
            } else {
                grym_ai_agent::ModelTier::Lightweight
            };
            handle_hunt(&target, tier).await?;
        }
        Command::Serve {
            host,
            port,
            scope: _,
            api_key,
            jwt_secret,
            allowed_origins,
            rate_limit,
            body_limit,
            tls_cert,
            tls_key,
        } => {
            let origins = allowed_origins
                .map(|s| s.split(',').map(|o| o.trim().to_string()).collect())
                .unwrap_or_default();
            let config = serve::ServeConfig {
                host,
                port,
                api_key,
                jwt_secret,
                allowed_origins: origins,
                rate_limit_per_minute: rate_limit,
                body_limit_bytes: body_limit,
                tls_cert_path: tls_cert,
                tls_key_path: tls_key,
            };
            serve::serve(config).await?
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
        tracing_subscriber::fmt().with_env_filter(filter).try_init()
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
    let guard = ScopeGuard::new(
        config,
        Some(attestation),
        audit.clone() as Arc<dyn AuditSink>,
    )?;
    Ok((guard, audit))
}

async fn handle_scope(command: ScopeCommand) -> Result<()> {
    match command {
        ScopeCommand::Validate { path } => {
            let scope = ScopeConfig::load(&path)?;
            println!("✓ Scope valid: {}", path.display());
            println!("  Engagement: {}", scope.engagement.engagement_id);
            println!("  Client: {}", scope.engagement.client);
            println!(
                "  Window: {} → {}",
                scope.engagement.authorized_start, scope.engagement.authorized_end
            );
            println!("  Policy hash: {}", scope.hash()?);
        }
        ScopeCommand::Show { path } => {
            let scope = ScopeConfig::load(&path)?;
            println!("Engagement: {}", scope.engagement.engagement_id);
            println!("Client: {}", scope.engagement.client);
            println!(
                "Window: {} to {}",
                scope.engagement.authorized_start, scope.engagement.authorized_end
            );
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

#[derive(Debug, Subcommand)]
enum SettingsCommand {
    /// Show all current settings.
    Show,
    /// Update scope configuration.
    Scope {
        /// Engagement ID.
        #[arg(long)]
        engagement_id: Option<String>,
        /// Client name.
        #[arg(long)]
        client: Option<String>,
        /// Authorized start timestamp (ISO 8601).
        #[arg(long)]
        authorized_start: Option<String>,
        /// Authorized end timestamp (ISO 8601).
        #[arg(long)]
        authorized_end: Option<String>,
        /// Allowed targets (comma-separated).
        #[arg(long)]
        allow: Option<String>,
        /// Denied targets (comma-separated).
        #[arg(long)]
        deny: Option<String>,
        /// Max technique tier (0-4).
        #[arg(long)]
        max_tier: Option<u8>,
        /// Deepness (quick, standard, deep, paranoid).
        #[arg(long)]
        deepness: Option<String>,
    },
    /// Configure Ollama connection.
    Ollama {
        /// Ollama server URL.
        #[arg(long)]
        url: Option<String>,
        /// Test the current connection.
        #[arg(long)]
        test: bool,
        /// Run auto-detection.
        #[arg(long)]
        auto_detect: bool,
    },
    /// Manage MCP server connections.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    /// List configured MCP servers.
    List,
    /// Add a new MCP server.
    Add {
        /// Unique name for this server.
        name: String,
        /// Transport type: stdio or http.
        #[arg(long, default_value = "stdio")]
        transport: String,
        /// Command (for stdio transport).
        #[arg(long)]
        command: Option<String>,
        /// Arguments (comma-separated, for stdio transport).
        #[arg(long)]
        args: Option<String>,
        /// URL (for http transport).
        #[arg(long)]
        url: Option<String>,
    },
    /// Remove an MCP server.
    Remove {
        /// Name of the server to remove.
        name: String,
    },
    /// Toggle enable/disable for an MCP server.
    Toggle {
        /// Name of the server.
        name: String,
    },
    /// Test connection to an MCP server and list its tools.
    Test {
        /// Name of the server to test.
        name: String,
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
        println!(
            "  {} {} → {}",
            record.record_type, record.hostname, record.value
        );
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
    println!(
        "\n[*] Generated {} permutation candidates",
        permutations.len()
    );

    println!(
        "\n✓ Passive recon complete — {} findings stored",
        sub_findings.len()
    );

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
        let ports =
            grym_recon_active::scan_common_ports(host, grym_recon_active::COMMON_PORTS, 1500).await;
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
                println!(
                    "  ├─ {} — Status: {}, Title: {:?}",
                    r.hostname, r.status, r.title
                );
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
            println!(
                "  ├─ {} (depth {}, {} links)",
                page.url,
                page.depth,
                page.links.len()
            );
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
                println!(
                    "  ├─ {} (HTTP {}, {} bytes)",
                    r.url, r.status, r.content_length
                );
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
                println!(
                    "  ├─ ?{} (HTTP {}, {} bytes)",
                    r.parameter, r.status, r.content_length
                );
            }
        }
    }

    println!(
        "\n✓ Active recon complete — {} findings stored",
        store.all()?.len()
    );

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
        let detection_template =
            grym_template_engine::DetectionTemplate::from_yaml(&template_data)?;
        if let Some(finding) =
            grym_web_scanner::scan_template(&client, parsed_url.clone(), &detection_template)
                .await?
        {
            store.insert(finding)?;
            println!("  Template matched!");
        }
    }

    // Test probe
    let probe = grym_recon_active::probe(&client, parsed_url.clone()).await?;
    println!(
        "[*] Target probe: HTTP {} — {} bytes — {}ms",
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
        let findings =
            grym_web_scanner::command_injection::check_command_injection(&client, &parsed_url)
                .await?;
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
        let findings =
            grym_web_scanner::path_traversal::check_path_traversal(&client, &parsed_url).await?;
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
        let findings =
            grym_web_scanner::open_redirect::check_open_redirect(&client, &parsed_url).await?;
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
        let findings =
            grym_web_scanner::http_smuggling::check_http_smuggling(&client, &parsed_url).await?;
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
        let findings =
            grym_web_scanner::tech_fingerprint::fingerprint_tech(&client, &parsed_url).await?;
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
    let high = all_findings
        .iter()
        .filter(|f| f.severity >= grym_core::Severity::High)
        .count();
    let med = all_findings
        .iter()
        .filter(|f| f.severity == grym_core::Severity::Medium)
        .count();
    let low = all_findings
        .iter()
        .filter(|f| f.severity <= grym_core::Severity::Low)
        .count();
    println!(
        "  High/Critical: {}, Medium: {}, Low/Info: {}",
        high, med, low
    );

    if json {
        println!("\n{}", serde_json::to_string_pretty(&all_findings)?);
    }

    Ok(())
}

async fn handle_cve(
    name: &str,
    version: &str,
    purl: Option<&str>,
    cpe: Option<&str>,
) -> Result<()> {
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
                println!(
                    "\n  Found {} matching vulnerabilities:\n",
                    result.matches.len()
                );
                for vuln in &result.matches {
                    let exploited = if vuln.known_exploited {
                        " [KNOWN EXPLOITED]"
                    } else {
                        ""
                    };
                    println!("  ├─ {}{}", vuln.id, exploited);
                    println!("  │  Source: {}", vuln.sources.join(", "));
                    println!(
                        "  │  {}",
                        vuln.description.chars().take(150).collect::<String>()
                    );
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

async fn handle_ai(prompt: &str, tier: grym_ai_agent::ModelTier) -> Result<()> {
    eprintln!(
        "🤖 GRYM AI Agent — tier: {}",
        if tier == grym_ai_agent::ModelTier::Reasoning {
            "mythos-sec:8b"
        } else {
            "qwen3.5:2b"
        }
    );
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    match grym_ai_agent::start_agent(prompt, tier).await {
        Ok((response, session_id)) => {
            eprintln!("\n✓ Agent session {} complete\n", &session_id[..8]);
            println!("{}", response);
        }
        Err(e) => {
            eprintln!("Agent error: {}", e);
        }
    }

    Ok(())
}

async fn handle_hunt(target: &str, tier: grym_ai_agent::ModelTier) -> Result<()> {
    eprintln!(
        "🎯 GRYM CVE Hunter — tier: {}",
        if tier == grym_ai_agent::ModelTier::Reasoning {
            "mythos-sec:8b"
        } else {
            "qwen3.5:2b"
        }
    );
    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    match grym_ai_agent::start_hunt(target, tier).await {
        Ok(session) => {
            eprintln!(
                "\n✓ Hunt complete — session {} — {} CVEs, {} hypotheses, {} templates\n",
                &session.id[..8],
                session.cves_analyzed.len(),
                session.hypotheses.len(),
                session.templates.len(),
            );
            println!("{}", serde_json::to_string_pretty(&session)?);
        }
        Err(e) => {
            eprintln!("Hunt error: {}", e);
        }
    }

    Ok(())
}

async fn handle_settings(command: SettingsCommand) -> Result<()> {
    match command {
        SettingsCommand::Show => {
            let settings = grym_core::settings::GrymSettings::load();
            println!("{}", serde_json::to_string_pretty(&settings)?);
        }
        SettingsCommand::Scope {
            engagement_id,
            client,
            authorized_start,
            authorized_end,
            allow,
            deny,
            max_tier,
            deepness,
        } => {
            let mut settings = grym_core::settings::GrymSettings::load();
            if let Some(v) = engagement_id {
                settings.scope.engagement_id = v;
            }
            if let Some(v) = client {
                settings.scope.client = v;
            }
            if let Some(v) = authorized_start {
                settings.scope.authorized_start = v;
            }
            if let Some(v) = authorized_end {
                settings.scope.authorized_end = v;
            }
            if let Some(v) = allow {
                settings.scope.allow = v.split(',').map(|s| s.trim().to_string()).collect();
            }
            if let Some(v) = deny {
                settings.scope.deny = v.split(',').map(|s| s.trim().to_string()).collect();
            }
            if let Some(v) = max_tier {
                settings.scope.max_tier = v.min(4);
            }
            if let Some(v) = deepness {
                settings.scope.deepness = v;
            }

            match settings.scope.to_scope_config() {
                Ok(cfg) => {
                    settings
                        .save()
                        .map_err(|e| anyhow::anyhow!("Failed to save: {e}"))?;
                    println!(
                        "✓ Scope updated — policy hash: {}",
                        cfg.hash().unwrap_or_default()
                    );
                }
                Err(e) => {
                    eprintln!("Invalid scope: {e}");
                }
            }
        }
        SettingsCommand::Ollama {
            url,
            test,
            auto_detect,
        } => {
            let mut settings = grym_core::settings::GrymSettings::load();
            if let Some(u) = url {
                settings.ollama.base_url = u.trim_end_matches('/').to_string();
            }
            if auto_detect {
                let found = settings.auto_detect_ollama().await;
                if found {
                    println!("✓ Ollama auto-detected at {}", settings.ollama.base_url);
                } else {
                    eprintln!("Ollama not found at default locations.");
                }
            }
            if test || auto_detect {
                let reachable =
                    grym_core::settings::GrymSettings::check_ollama_url(&settings.ollama.base_url)
                        .await;
                settings.ollama.reachable = reachable;
                if reachable {
                    settings.update_ollama_info().await;
                    println!("✓ Ollama reachable at {}", settings.ollama.base_url);
                    if let Some(ver) = &settings.ollama.version {
                        println!("  Version: {ver}");
                    }
                    if !settings.ollama.available_models.is_empty() {
                        println!("  Models: {}", settings.ollama.available_models.join(", "));
                    }
                } else {
                    eprintln!("✗ Ollama not reachable at {}", settings.ollama.base_url);
                }
            }
            settings
                .save()
                .map_err(|e| anyhow::anyhow!("Failed to save: {e}"))?;
        }
        SettingsCommand::Mcp { command } => handle_mcp(command).await?,
    }
    Ok(())
}

async fn handle_mcp(command: McpCommand) -> Result<()> {
    match command {
        McpCommand::List => {
            let settings = grym_core::settings::GrymSettings::load();
            if settings.mcp_servers.is_empty() {
                println!("No MCP servers configured.");
                println!("  Add one with: grym settings mcp add <name> --command <cmd>");
                return Ok(());
            }
            println!("Configured MCP servers:");
            for srv in &settings.mcp_servers {
                let status = if srv.enabled { "enabled" } else { "disabled" };
                match &srv.transport {
                    grym_core::settings::McpTransportConfig::Stdio { command, args } => {
                        let args_str = if args.is_empty() {
                            String::new()
                        } else {
                            format!(" {}", args.join(" "))
                        };
                        println!(
                            "  {:<20} [{status}] stdio: {}{}",
                            srv.name, command, args_str
                        );
                    }
                    grym_core::settings::McpTransportConfig::Http { url } => {
                        println!("  {:<20} [{status}] http: {}", srv.name, url);
                    }
                }
            }
        }
        McpCommand::Add {
            name,
            transport,
            command,
            args,
            url,
        } => {
            let mut settings = grym_core::settings::GrymSettings::load();

            let transport_config = match transport.to_lowercase().as_str() {
                "stdio" => {
                    let cmd = command.ok_or_else(|| {
                        anyhow::anyhow!("--command is required for stdio transport")
                    })?;
                    let parsed_args: Vec<String> = args
                        .as_ref()
                        .map(|a| a.split(',').map(|s| s.trim().to_string()).collect())
                        .unwrap_or_default();
                    grym_core::settings::McpTransportConfig::Stdio {
                        command: cmd,
                        args: parsed_args,
                    }
                }
                "http" => {
                    let endpoint =
                        url.ok_or_else(|| anyhow::anyhow!("--url is required for http transport"))?;
                    grym_core::settings::McpTransportConfig::Http { url: endpoint }
                }
                other => anyhow::bail!("Unknown transport type '{other}'. Use 'stdio' or 'http'."),
            };

            let server_config = grym_core::settings::McpServerConfig {
                name: name.clone(),
                transport: transport_config,
                enabled: true,
            };

            // Check for duplicate
            if settings.mcp_servers.iter().any(|s| s.name == name) {
                anyhow::bail!(
                    "MCP server '{}' already exists. Remove it first or use a different name.",
                    name
                );
            }

            settings.mcp_servers.push(server_config);
            settings
                .save()
                .map_err(|e| anyhow::anyhow!("Failed to save: {e}"))?;
            println!("✓ Added MCP server '{}'", name);
        }
        McpCommand::Remove { name } => {
            let mut settings = grym_core::settings::GrymSettings::load();
            let initial_len = settings.mcp_servers.len();
            settings.mcp_servers.retain(|s| s.name != name);
            if settings.mcp_servers.len() == initial_len {
                eprintln!("MCP server '{}' not found.", name);
            } else {
                settings
                    .save()
                    .map_err(|e| anyhow::anyhow!("Failed to save: {e}"))?;
                println!("✓ Removed MCP server '{}'", name);
            }
        }
        McpCommand::Toggle { name } => {
            let mut settings = grym_core::settings::GrymSettings::load();
            let idx = settings.mcp_servers.iter().position(|s| s.name == name);
            match idx {
                Some(i) => {
                    let srv = &mut settings.mcp_servers[i];
                    srv.enabled = !srv.enabled;
                    let status = if srv.enabled { "enabled" } else { "disabled" };
                    println!("✓ MCP server '{}' is now {status}", srv.name);
                    settings
                        .save()
                        .map_err(|e| anyhow::anyhow!("Failed to save: {e}"))?;
                }
                None => {
                    eprintln!("MCP server '{name}' not found.");
                }
            }
        }
        McpCommand::Test { name } => {
            let settings = grym_core::settings::GrymSettings::load();
            let config = settings.mcp_servers.iter().find(|s| s.name == name);
            let config = match config {
                Some(c) => c.clone(),
                None => {
                    anyhow::bail!("MCP server '{}' not found.", name);
                }
            };

            println!("[*] Testing connection to MCP server '{}'...", name);
            match grym_ai_agent::mcp::McpSession::connect(config).await {
                Ok(session) => {
                    let tools = {
                        let s = session.lock().await;
                        s.tools().to_vec()
                    };
                    println!("✓ Connected successfully!");
                    println!("  Discovered {} tools:", tools.len());
                    for tool in &tools {
                        println!("    - {}: {}", tool.full_name, tool.description);
                    }
                }
                Err(e) => {
                    eprintln!("✗ Connection failed: {e}");
                }
            }
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
