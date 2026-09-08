#![deny(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate as gen_completions, shells};
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
        /// Save findings to this JSON file for `grym report`.
        #[arg(short, long)]
        out: Option<PathBuf>,
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
    /// Payload library, technique reference, checklists, and engagement plans.
    Playbook {
        #[command(subcommand)]
        command: PlaybookCommand,
    },
    /// Browse the offline CVE knowledge base (525+ entries, no network).
    CveDb {
        #[command(subcommand)]
        command: CveDbCommand,
    },
    /// Generate offline PoCs, reverse shells, and web shells (authorized use).
    Exploit {
        #[command(subcommand)]
        command: ExploitCommand,
    },
    /// Check your environment: scope validity, settings, Ollama, DB integrity.
    Doctor {
        /// Path to scope config to validate.
        #[arg(short, long, default_value = "config/scope.toml")]
        scope: PathBuf,
    },
    /// Generate shell completions for the given shell.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: shells::Shell,
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
            out,
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
                out,
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
        Command::Playbook { command } => handle_playbook(command).await?,
        Command::CveDb { command } => handle_cve_db(command).await?,
        Command::Exploit { command } => handle_exploit(command).await?,
        Command::Doctor { scope } => handle_doctor(&scope).await?,
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            gen_completions(shell, &mut cmd, "grym", &mut std::io::stdout());
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
        ScopeCommand::Init {
            path,
            engagement_id,
            client,
            allow,
            days,
        } => {
            if path.exists() {
                anyhow::bail!(
                    "{} already exists — refusing to overwrite. Pick another path or delete it first.",
                    path.display()
                );
            }
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let start = chrono::Utc::now();
            let end = start + chrono::Duration::days(i64::from(days));
            let fmt = |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            let eid = engagement_id.unwrap_or_else(|| format!("ENG-{}", start.format("%Y%m%d")));
            let client_name = client.unwrap_or_else(|| "<CLIENT NAME>".into());
            let allow_rules = if allow.is_empty() {
                "<target.example.com>".to_string()
            } else {
                allow.join(", ")
            };
            let template = format!(
                "# GRYM scope — edit values, then validate: grym scope validate {path}\n# Deny rules always win. Everything not allowed is denied.\nformat_version = 1\n\n[engagement]\nclient = \"{client}\"\nengagement_id = \"{eid}\"\nauthorized_start = \"{start}\"\nauthorized_end = \"{end}\"\nemergency_contact = \"<security@client.example>\"\n\n[targets]\nallow = [{allow}]\ndeny = [\"*/logout\", \"*/admin/delete-account\"]\n\n[limits]\nmax_requests_per_second_global = 20\nmax_requests_per_second_per_host = 3\nmax_response_bytes = 2097152\n\n[technique]\nmax_tier = 1\ndeepness = \"standard\"\n\n[authorization]\n# Must be true and paired with the typed session confirmation for Tier 1+ work.\nauthorization_attested = false\n\n[safety]\nmax_redirects = 5\nblock_rate_threshold_percent = 60\nserver_error_threshold = 5\n",
                path = path.display(),
                client = client_name,
                eid = eid,
                start = fmt(start),
                end = fmt(end),
                allow = allow_rules,
            );
            std::fs::write(&path, template)?;
            println!("✓ Scope scaffold written to {}", path.display());
            println!("  Engagement: {eid} | window: {days} day(s) from now");
            println!("\nNext steps:");
            println!("  1. Edit {} — set real targets, client, and window", path.display());
            println!("  2. grym scope validate {}", path.display());
            println!("  3. grym doctor --scope {}", path.display());
            println!("  4. grym scan <url> --scope {} --all", path.display());
            return Ok(());
        }
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
    /// Create a new scope file from the bundled template (fails if it exists).
    Init {
        /// Path to write the new scope file.
        #[arg(default_value = "config/scope.toml")]
        path: PathBuf,
        /// Engagement ID to pre-fill.
        #[arg(long)]
        engagement_id: Option<String>,
        /// Client name to pre-fill.
        #[arg(long)]
        client: Option<String>,
        /// Allowed target rule (repeat or comma-separate).
        #[arg(long = "allow", value_delimiter = ',')]
        allow: Vec<String>,
        /// Days the authorization window stays open (from now).
        #[arg(long, default_value_t = 14)]
        days: u32,
    },
}

/// Payload library and technique reference commands.
#[derive(Debug, Subcommand)]
enum PlaybookCommand {
    /// List all payload sets (or show one by id).
    Payloads {
        /// Specific payload set id to display.
        id: Option<String>,
        /// Filter sets/payloads by keyword.
        #[arg(short, long)]
        search: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// List technique references (or show one by id).
    Techniques {
        /// Specific technique id to display.
        id: Option<String>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Search payloads and techniques by keyword.
    Search {
        /// Search keyword.
        query: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show the methodology checklist as markdown.
    Checklist {
        /// Render the checklist to this markdown file.
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Emit machine-readable JSON instead of markdown.
        #[arg(long)]
        json: bool,
    },
    /// Generate an engagement plan for a target.
    Plan {
        /// Target base URL.
        #[arg(short = 'u', long)]
        target: String,
        /// Known technologies (comma-separated).
        #[arg(short, long)]
        tech: Option<String>,
        /// Whether you have valid credentials.
        #[arg(long)]
        authenticated: bool,
        /// Max technique tier (overrides scope default).
        #[arg(long)]
        max_tier: Option<u8>,
        /// Deepness profile (quick/standard/deep/paranoid).
        #[arg(long)]
        deepness: Option<String>,
        /// Path to scope config for tier/deepness defaults.
        #[arg(short, long, default_value = "config/scope.toml")]
        scope: PathBuf,
        /// Write the plan to this markdown file.
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Offline CVE knowledge-base commands.
#[derive(Debug, Subcommand)]
enum CveDbCommand {
    /// List all CVEs (filter by severity or component).
    List {
        /// Filter by severity (critical/high/medium/low).
        #[arg(short, long)]
        severity: Option<String>,
        /// Filter by affected component substring.
        #[arg(short, long)]
        component: Option<String>,
        /// Show only actively-exploited (KEV) CVEs.
        #[arg(long)]
        exploited: bool,
    },
    /// Show full details for one CVE.
    Show { cve_id: String },
    /// Search CVEs by keyword (id, name, description, tags).
    Search { query: String },
}

/// Offline exploit/PoC generation commands.
#[derive(Debug, Subcommand)]
enum ExploitCommand {
    /// Generate a PoC/exploit script from a CVE id in the local DB.
    Cve {
        /// CVE identifier, e.g. CVE-2021-44228.
        cve_id: String,
        /// Target URL to embed in the PoC.
        #[arg(short = 'u', long)]
        target: Option<String>,
        /// Output language/format (python, curl, bash, nuclei, go, rust, powershell, metasploit).
        #[arg(short, long, default_value = "python")]
        lang: String,
        /// Write the PoC to this file instead of stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Generate a reverse-shell one-liner.
    ReverseShell {
        /// Callback host/IP.
        ip: String,
        /// Callback port.
        port: u16,
        /// Language (python, bash, powershell, nodejs, perl, ruby, lua, java, php, csharp).
        #[arg(short, long, default_value = "bash")]
        lang: String,
        /// Obfuscate the payload.
        #[arg(long)]
        obfuscate: bool,
    },
    /// Generate a minimal web shell (authorized engagements only).
    WebShell {
        /// Language (php, jsp, asp, aspx).
        lang: String,
        /// Write the shell to this file instead of stdout.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Generate mutated variants of a base payload.
    Variants {
        /// Base payload to mutate.
        payload: String,
        /// How many variants to produce.
        #[arg(short, long, default_value_t = 8)]
        count: usize,
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
    out: Option<PathBuf>,
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

    // Persist findings for later processing.
    let findings_path = out.clone().unwrap_or_else(|| PathBuf::from("findings.json"));
    std::fs::write(
        &findings_path,
        serde_json::to_string_pretty(&all_findings)?,
    )?;
    println!("\n✓ Findings saved to {}", findings_path.display());

    // Next-step hints so the operator always knows where to go from here.
    println!("\nNext steps:");
    if high > 0 {
        println!("  • grym report {} -f markdown -o report.md", findings_path.display());
        println!("  • grym playbook techniques        # exploit walkthroughs for what you found");
    } else {
        println!("  • Re-run with --all for broader module coverage");
        println!("  • grym recon-active <url> --all   # map more attack surface first");
    }
    println!("  • grym playbook plan -u {url}   # build a full engagement plan");

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

fn print_payload_set(set: &grym_web_scanner::playbook::PayloadSet) {
    println!("\n=== {} ({}) ===", set.title, set.id);
    println!("When to use: {}", set.when_to_use);
    println!();
    for p in &set.payloads {
        println!("  [{d}] {v}", d = p.difficulty, v = p.value);
        println!("      └─ {}", p.description);
    }
}

fn print_technique(t: &grym_web_scanner::playbook::Technique) {
    println!("\n=== {} ({}) ===", t.title, t.id);
    println!("Domain: {}", t.domain);
    println!("\nConcept: {}", t.concept);
    println!("\nSteps:");
    for (i, s) in t.steps.iter().enumerate() {
        println!("  {}. {}", i + 1, s);
    }
    println!("\nSuccess looks like: {}", t.success_looks_like);
    if !t.related_payload_sets.is_empty() {
        println!(
            "Related payload sets: {}",
            t.related_payload_sets.join(", ")
        );
    }
}

/// Parse a language string into an ExploitFormat, mirroring the serve API mapping.
fn parse_exploit_format(lang: &str) -> grym_web_scanner::exploit_gen::ExploitFormat {
    use grym_web_scanner::exploit_gen::ExploitFormat as F;
    match lang.to_lowercase().as_str() {
        "python" | "py" => F::Python,
        "python-requests" | "pyreq" => F::PythonRequests,
        "go" => F::Go,
        "rust" | "rs" => F::Rust,
        "curl" => F::Curl,
        "httpie" => F::HTTPie,
        "nuclei" | "yaml" => F::NucleiYaml,
        "metasploit" | "msf" | "ruby-msf" => F::MetasploitRuby,
        "bash" | "sh" => F::Bash,
        "powershell" | "ps1" => F::PowerShell,
        "javascript" | "js" => F::JavaScript,
        "nodejs" | "node" => F::NodeJs,
        "java" => F::Java,
        "php" => F::PHP,
        "burp" | "burp-intruder" => F::BurpIntruder,
        "ruby" | "rb" => F::Ruby,
        "perl" | "pl" => F::Perl,
        "lua" => F::Lua,
        "csharp" | "cs" | "c#" => F::CSharp,
        _ => F::Python,
    }
}

async fn handle_cve_db(command: CveDbCommand) -> Result<()> {
    let db = grym_web_scanner::cve_db::get_cve_database();

    match command {
        CveDbCommand::List {
            severity,
            component,
            exploited,
        } => {
            let sev_filter = severity.map(|s| s.to_lowercase());
            let comp_filter = component.map(|c| c.to_lowercase());
            let entries: Vec<_> = db
                .into_iter()
                .filter(|e| {
                    sev_filter
                        .as_ref()
                        .is_none_or(|s| e.severity.to_lowercase() == *s)
                        && comp_filter
                            .as_ref()
                            .is_none_or(|c| e.affected_component.to_lowercase().contains(c))
                        && (!exploited || e.known_exploited)
                })
                .collect();
            if entries.is_empty() {
                println!("No CVEs match the given filters.");
                return Ok(());
            }
            println!("CVE knowledge base — {} entries\n", entries.len());
            for e in &entries {
                let kev = if e.known_exploited { " [KEV]" } else { "" };
                println!(
                    "  {:<16} {:<8} {:>4}  {}{}",
                    e.cve_id,
                    e.severity,
                    format!("{:.1}", e.cvss_score),
                    e.name,
                    kev
                );
            }
            println!("\nDetails: grym cve-db show <id> | Search: grym cve-db search <kw>");
        }
        CveDbCommand::Show { cve_id } => {
            let upper = cve_id.to_uppercase();
            match grym_web_scanner::cve_db::lookup_cve(&upper) {
                Some(e) => {
                    println!("{} — {}{}", e.cve_id, e.name, if e.known_exploited { " [KNOWN EXPLOITED]" } else { "" });
                    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
                    println!("  Component:  {} ({})", e.affected_component, e.affected_versions.join(", "));
                    println!("  Severity:   {} (CVSS {:.1} — {})", e.severity, e.cvss_score, e.cvss_vector);
                    println!("  CWE:        {} | Attack: {} | OWASP: {}", e.cwe_id, e.attack_type, e.owasp_category);
                    println!("\n  {}", e.description);
                    if !e.payload_examples.is_empty() {
                        println!("\n  Payload examples:");
                        for p in &e.payload_examples {
                            println!("    • {p}");
                        }
                    }
                    if !e.detection_signatures.is_empty() {
                        println!("\n  Detection signatures:");
                        for s in &e.detection_signatures {
                            println!("    • {s}");
                        }
                    }
                    if !e.metasploit_modules.is_empty() {
                        println!("\n  Metasploit modules:");
                        for m in &e.metasploit_modules {
                            println!("    • {m}");
                        }
                    }
                    if !e.nuclei_templates.is_empty() {
                        println!("\n  Nuclei templates:");
                        for n in &e.nuclei_templates {
                            println!("    • {n}");
                        }
                    }
                    if !e.exploit_urls.is_empty() {
                        println!("\n  References:");
                        for u in &e.exploit_urls {
                            println!("    • {u}");
                        }
                    }
                    println!("\n  Remediation: {}", e.remediation);
                    if !e.patch_urls.is_empty() {
                        for u in &e.patch_urls {
                            println!("    • {u}");
                        }
                    }
                    println!("\nGenerate a PoC: grym exploit cve {} -u <target>", e.cve_id);
                }
                None => {
                    eprintln!("'{cve_id}' not found. Try 'grym cve-db search <keyword>'.");
                    anyhow::bail!("unknown CVE '{cve_id}'");
                }
            }
        }
        CveDbCommand::Search { query } => {
            let q = query.to_lowercase();
            let matches: Vec<_> = db
                .into_iter()
                .filter(|e| {
                    e.cve_id.to_lowercase().contains(&q)
                        || e.name.to_lowercase().contains(&q)
                        || e.description.to_lowercase().contains(&q)
                        || e.affected_component.to_lowercase().contains(&q)
                        || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
                })
                .collect();
            if matches.is_empty() {
                println!("No CVEs match '{query}'.");
                return Ok(());
            }
            println!("Search '{}': {} matches\n", query, matches.len());
            for e in &matches {
                let kev = if e.known_exploited { " [KEV]" } else { "" };
                println!(
                    "  {:<16} {:<8} {:>4}  {}{}",
                    e.cve_id,
                    e.severity,
                    format!("{:.1}", e.cvss_score),
                    e.name,
                    kev
                );
            }
        }
    }
    Ok(())
}

async fn handle_exploit(command: ExploitCommand) -> Result<()> {
    use grym_web_scanner::exploit_gen::{self, ExploitGenOptions, generate_payload_variants};

    match command {
        ExploitCommand::Cve {
            cve_id,
            target,
            lang,
            out,
        } => {
            let upper = cve_id.to_uppercase();
            let opts = ExploitGenOptions::new(parse_exploit_format(&lang))
                .with_target(target.as_deref().unwrap_or("http://<TARGET>"));
            let exploit = exploit_gen::generate_cve_exploit_command(&upper, "", &opts)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "No PoC template for '{upper}'. Try 'grym cve-db search' to find related CVEs."
                    )
                })?;
            let body = format!(
                "# {} — {}\n# Risk: {} | Auth required: {}\n# Usage: {}\n# Deps: {}\n\n{}\n",
                exploit.name,
                exploit.description,
                exploit.risk_level,
                exploit.requires_auth,
                exploit.usage,
                exploit.dependencies.join(", "),
                exploit.code
            );
            match out {
                Some(path) => {
                    std::fs::write(&path, &body)?;
                    println!("✓ PoC written to {} ({} format)", path.display(), lang);
                }
                None => println!("{body}"),
            }
        }
        ExploitCommand::ReverseShell {
            ip,
            port,
            lang,
            obfuscate,
        } => {
            let format = parse_exploit_format(&lang);
            let shell = exploit_gen::generate_reverse_shell(&ip, port, format, obfuscate);
            println!("# Reverse shell — {lang}{}", if obfuscate { " (obfuscated)" } else { "" });
            println!("# Authorized engagements only. Start your listener first.\n");
            println!("{shell}");
        }
        ExploitCommand::WebShell { lang, out } => {
            let shell = exploit_gen::generate_web_shell(&lang);
            match out {
                Some(path) => {
                    std::fs::write(&path, &shell)?;
                    println!("✓ Web shell written to {}", path.display());
                }
                None => println!("{shell}"),
            }
        }
        ExploitCommand::Variants { payload, count } => {
            let variants = generate_payload_variants(&payload, count);
            println!("{} variants of base payload:\n", variants.len());
            for (i, v) in variants.iter().enumerate() {
                println!("  {:>2}. {v}", i + 1);
            }
        }
    }
    Ok(())
}

async fn handle_doctor(scope_path: &PathBuf) -> Result<()> {
    println!("🩺 GRYM Doctor\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    let mut ok = true;

    // 1. Scope file.
    match grym_core::ScopeConfig::load(scope_path) {
        Ok(cfg) => {
            println!("✓ Scope: {} (engagement {})", scope_path.display(), cfg.engagement.engagement_id);
            if !cfg.targets.allow.is_empty() {
                println!("    allow: {} rule(s)", cfg.targets.allow.len());
            }
        }
        Err(e) => {
            ok = false;
            println!("✗ Scope: {} — {e}", scope_path.display());
            println!("    Fix: copy config/scope.example.toml and edit, or run 'grym scope init'.");
        }
    }

    // 2. Persisted settings readable.
    let settings = grym_core::settings::GrymSettings::load();
    println!("✓ Settings: loaded ({})", if settings.scope.engagement_id.is_empty() { "defaults" } else { "configured" });

    // 3. Ollama reachable.
    let mut s2 = settings.clone();
    let ollama_ok = s2.auto_detect_ollama().await;
    if ollama_ok {
        println!("✓ Ollama: reachable at {}", s2.ollama.base_url);
    } else {
        println!("⚠ Ollama: not reachable at {} (AI features unavailable; everything else works)", s2.ollama.base_url);
    }

    // 4. Playbook integrity.
    let sets = grym_web_scanner::playbook::payload_sets().len();
    let techniques = grym_web_scanner::playbook::techniques().len();
    let cves = grym_web_scanner::cve_db::get_cve_database().len();
    println!("✓ Knowledge base: {sets} payload sets, {techniques} techniques, {cves} CVE entries");

    println!(
        "\n{}",
        if ok {
            "All critical checks passed.".to_string()
        } else {
            "Some checks failed — see above for fixes.".to_string()
        }
    );
    if !ok {
        anyhow::bail!("doctor found problems");
    }
    Ok(())
}

async fn handle_playbook(command: PlaybookCommand) -> Result<()> {
    use grym_web_scanner::{checklist, plan as plan_mod, playbook};

    match command {
        PlaybookCommand::Payloads { id, search, json } => {
            if let Some(id) = id {
                match playbook::payload_set(&id) {
                    Some(set) => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&set)?);
                        } else {
                            print_payload_set(&set);
                        }
                    }
                    None => {
                        eprintln!(
                            "Unknown payload set '{id}'. Run 'grym playbook payloads' to list."
                        );
                        anyhow::bail!("unknown payload set '{id}'");
                    }
                }
                return Ok(());
            }
            let sets = match search {
                Some(q) => playbook::search(&q).payload_sets,
                None => playbook::payload_sets(),
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&sets)?);
                return Ok(());
            }
            if sets.is_empty() {
                println!("No matching payload sets.");
                return Ok(());
            }
            println!("Payload library — {} sets\n", sets.len());
            for set in &sets {
                println!(
                    "  {:<20} {:>2} payloads  {}",
                    set.id,
                    set.payloads.len(),
                    set.title
                );
            }
            println!("\nShow one with: grym playbook payloads <id>");
        }
        PlaybookCommand::Techniques { id, json } => {
            if let Some(id) = id {
                match playbook::technique(&id) {
                    Some(t) => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&t)?);
                        } else {
                            print_technique(&t);
                        }
                    }
                    None => {
                        eprintln!(
                            "Unknown technique '{id}'. Run 'grym playbook techniques' to list."
                        );
                        anyhow::bail!("unknown technique '{id}'");
                    }
                }
                return Ok(());
            }
            let techniques = playbook::techniques();
            if json {
                println!("{}", serde_json::to_string_pretty(&techniques)?);
                return Ok(());
            }
            println!("Technique reference — {} entries\n", techniques.len());
            let mut last_domain = String::new();
            for t in &techniques {
                if t.domain != last_domain {
                    println!("\n[{t}]", t = t.domain);
                    last_domain = t.domain.clone();
                }
                println!("  {:<26} {}", t.id, t.title);
            }
            println!("\nShow one with: grym playbook techniques <id>");
        }
        PlaybookCommand::Search { query, json } => {
            let result = playbook::search(&query);
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
                return Ok(());
            }
            println!(
                "Search '{}': {} payload sets, {} techniques",
                result.query,
                result.payload_sets.len(),
                result.techniques.len()
            );
            for set in &result.payload_sets {
                print_payload_set(set);
            }
            for t in &result.techniques {
                print_technique(t);
            }
        }
        PlaybookCommand::Checklist { out, json } => {
            let cl = checklist::standard_web_checklist();
            if json {
                println!("{}", serde_json::to_string_pretty(&cl)?);
                return Ok(());
            }
            let md = checklist::to_markdown(&cl);
            match out {
                Some(path) => {
                    std::fs::write(&path, &md)?;
                    println!("✓ Checklist written to {}", path.display());
                }
                None => println!("{md}"),
            }
        }
        PlaybookCommand::Plan {
            target,
            tech,
            authenticated,
            max_tier,
            deepness,
            scope: scope_path,
            out,
            json,
        } => {
            // Pull tier/deepness defaults from scope; CLI flags override.
            let (scope_tier, scope_deepness) = match grym_core::ScopeConfig::load(&scope_path) {
                Ok(cfg) => (
                    Some(u8::from(cfg.technique.max_tier)),
                    Some(format!("{:?}", cfg.technique.deepness).to_lowercase()),
                ),
                Err(_) => (None, None),
            };
            let limits = plan_mod::PlanLimits {
                max_tier: max_tier.or(scope_tier).unwrap_or(2).min(4),
                deepness: deepness
                    .or(scope_deepness)
                    .unwrap_or_else(|| "standard".into()),
            };
            let profile = plan_mod::TargetProfile {
                base_url: target,
                technologies: tech
                    .map(|t| {
                        t.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    })
                    .unwrap_or_default(),
                authenticated,
                notes: Vec::new(),
                engagement_id: String::new(),
            };
            let plan = plan_mod::generate(&profile, &limits);
            if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
                return Ok(());
            }
            let md = plan_mod::to_markdown(&plan);
            match out {
                Some(path) => {
                    std::fs::write(&path, &md)?;
                    println!("✓ Plan written to {}", path.display());
                }
                None => println!("{md}"),
            }
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
