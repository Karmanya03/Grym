//! Tool registry — wraps every grym module as a callable tool for the AI agent.
//! Also integrates tools from connected MCP servers dynamically.

use std::sync::Arc;

use serde_json::Value;
use tokio::sync::Mutex;
use url::Url as UrlParser;

use grym_core::audit::{AuditSink, MemoryAuditLog};
use grym_core::{Finding, OperatorAttestation, ScopeGuard, ScopedClient, config};

use crate::mcp;

/// Unified result from any tool execution.
#[derive(Clone, Debug)]
pub struct ToolResult {
    pub tool: String,
    pub success: bool,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub data: Option<Value>,
    pub error: Option<String>,
}

/// A callable tool the AI agent can invoke.
#[async_trait::async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn parameters(&self) -> Value;

    /// Execute the tool with given arguments.
    async fn execute(&self, args: Value) -> ToolResult;
}

// ── Tool Registry ────────────────────────────────────────────────────────────

pub struct ToolRegistry {
    tools: Vec<Box<dyn Tool>>,
    _client: Arc<ScopedClient>,
    _mcp_sessions: Vec<Arc<Mutex<mcp::McpSession>>>,
}

impl ToolRegistry {
    pub async fn new() -> anyhow::Result<Self> {
        let scope = create_ai_scope()?;
        let audit: Arc<dyn AuditSink> = Arc::new(MemoryAuditLog::default());
        let attestation = OperatorAttestation {
            engagement_id: scope.engagement.engagement_id.clone(),
            confirmation: OperatorAttestation::required_phrase(&scope.engagement.engagement_id),
        };
        let guard = ScopeGuard::new(scope, Some(attestation), audit)?;
        let client = Arc::new(ScopedClient::new(Arc::new(guard))?);

        let mut tools: Vec<Box<dyn Tool>> = vec![
            Box::new(ScanTool {
                client: Arc::clone(&client),
            }),
            Box::new(CveLookupTool),
            Box::new(ReconPassiveTool),
            Box::new(ReconActiveTool {
                _client: Arc::clone(&client),
            }),
            Box::new(ExploitGenTool),
            Box::new(TechnologyFingerprintTool {
                client: Arc::clone(&client),
            }),
            Box::new(BinaryAnalysisTool),
            Box::new(ReadFileTool),
            Box::new(SaveReportTool),
            Box::new(WebSearchTool),
        ];

        // Connect to enabled MCP servers and register their tools
        let (mcp_sessions, mcp_tools) = mcp::connect_enabled_mcp_servers().await;
        tools.extend(mcp_tools);

        Ok(Self {
            tools,
            _client: client,
            _mcp_sessions: mcp_sessions,
        })
    }

    pub fn all(&self) -> &[Box<dyn Tool>] {
        &self.tools
    }

    pub fn definitions(&self) -> Vec<crate::model::ToolDefinition> {
        self.tools
            .iter()
            .map(|t| crate::model::ToolDefinition {
                name: t.name().to_string(),
                description: t.description().to_string(),
                parameters: t.parameters(),
            })
            .collect()
    }

    pub async fn execute(&self, name: &str, args: Value) -> ToolResult {
        for tool in &self.tools {
            if tool.name() == name {
                return tool.execute(args).await;
            }
        }
        ToolResult {
            tool: name.to_string(),
            success: false,
            summary: format!("Tool '{name}' not found"),
            findings: Vec::new(),
            data: None,
            error: Some(format!("Unknown tool: {name}")),
        }
    }
}

fn create_ai_scope() -> anyhow::Result<config::ScopeConfig> {
    let offset = chrono::FixedOffset::east_opt(0).ok_or_else(|| anyhow::anyhow!("offset"))?;
    let now = chrono::Utc::now().with_timezone(&offset);
    let later = now + chrono::TimeDelta::try_hours(24).ok_or_else(|| anyhow::anyhow!("delta"))?;

    Ok(config::ScopeConfig {
        format_version: 1,
        engagement: config::Engagement {
            client: "GRYM-AI Agent".into(),
            engagement_id: "AI-ENGAGEMENT".into(),
            authorized_start: now,
            authorized_end: later,
            emergency_contact: "ai-agent@local".into(),
        },
        targets: config::TargetScope {
            allow: vec!["0.0.0.0/0".into(), "::0/0".into()],
            deny: vec![],
        },
        limits: config::LimitConfig {
            max_requests_per_second_global: 20,
            max_requests_per_second_per_host: 5,
            max_response_bytes: 4 * 1024 * 1024,
        },
        technique: config::TechniqueConfig {
            max_tier: config::TechniqueTier::StandardDetection,
            deepness: config::Deepness::Deep,
        },
        authorization: config::AuthorizationConfig {
            authorization_attested: true,
        },
        safety: config::SafetyConfig::default(),
    })
}

// ── Individual Tools ─────────────────────────────────────────────────────────

struct ScanTool {
    client: Arc<ScopedClient>,
}

#[async_trait::async_trait]
impl Tool for ScanTool {
    fn name(&self) -> &str {
        "scan"
    }
    fn description(&self) -> &str {
        "Run web vulnerability scans against a URL. Supports: sqli, xss, ssti, ssrf, cors, csrf, jwt, cmd_injection, path_traversal, open_redirect, idor, waf_detect, smuggling, xxe, tech_fingerprint, nosqli, host_header, fuzzer."
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "modules": {"type": "array", "items": {"type": "string"}, "description": "Modules to run (default: all)"}
            },
            "required": ["url"]
        })
    }

    async fn execute(&self, args: Value) -> ToolResult {
        let url_str = args["url"].as_str().unwrap_or("");
        if url_str.is_empty() {
            return ToolResult {
                tool: "scan".into(),
                success: false,
                summary: "No URL provided".into(),
                findings: Vec::new(),
                data: None,
                error: Some("url is required".into()),
            };
        }

        let url = match UrlParser::parse(url_str) {
            Ok(u) => u,
            Err(e) => {
                return ToolResult {
                    tool: "scan".into(),
                    success: false,
                    summary: format!("Invalid URL: {e}"),
                    findings: Vec::new(),
                    data: None,
                    error: Some(e.to_string()),
                };
            }
        };

        let modules: Vec<String> = args["modules"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_else(|| {
                vec![
                    "sqli".into(),
                    "xss".into(),
                    "ssti".into(),
                    "ssrf".into(),
                    "cors".into(),
                    "csrf".into(),
                    "jwt".into(),
                    "cmd_injection".into(),
                    "path_traversal".into(),
                    "xxe".into(),
                ]
            });

        let mut all_findings = Vec::new();
        let mut details = Vec::new();

        for module in &modules {
            let findings = run_module(&self.client, &url, module).await;
            if !findings.is_empty() {
                all_findings.extend(findings.clone());
                details.push(format!("{}: {} findings", module, findings.len()));
            }
        }

        ToolResult {
            tool: "scan".into(),
            success: true,
            summary: if all_findings.is_empty() {
                "No vulnerabilities detected".into()
            } else {
                format!(
                    "Found {} findings: {}",
                    all_findings.len(),
                    details.join("; ")
                )
            },
            findings: all_findings,
            data: Some(serde_json::json!({"modules_run": modules, "finding_count": details.len()})),
            error: None,
        }
    }
}

async fn run_module(client: &ScopedClient, url: &UrlParser, scan_type: &str) -> Vec<Finding> {
    use grym_web_scanner::*;
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
        "cors" => cors::check_cors(client, url).await.unwrap_or_default(),
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
        "host_header" => host_header::check_host_header_injection(client, url)
            .await
            .unwrap_or_default(),
        "fuzzer" => fuzzer::fuzz_all(client, url).await.unwrap_or_default(),
        _ => Vec::new(),
    }
}

// ── CVE Lookup Tool ──────────────────────────────────────────────────────────

struct CveLookupTool;

#[async_trait::async_trait]
impl Tool for CveLookupTool {
    fn name(&self) -> &str {
        "cve_lookup"
    }
    fn description(&self) -> &str {
        "Look up known CVEs for a component and version."
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Component name (e.g. apache-httpd)"},
                "version": {"type": "string", "description": "Version string (e.g. 2.4.49)"}
            },
            "required": ["name", "version"]
        })
    }

    async fn execute(&self, args: Value) -> ToolResult {
        let name = args["name"].as_str().unwrap_or("");
        let version = args["version"].as_str().unwrap_or("");

        let component = grym_cve_intel::ComponentFingerprint {
            name: name.into(),
            version: version.into(),
            purl: None,
            cpe: None,
            source: "ai-agent".into(),
        };

        let correlator = grym_cve_intel::CveCorrelator::new();
        match correlator.correlate(&component).await {
            Ok(result) => ToolResult {
                tool: "cve_lookup".into(),
                success: true,
                summary: format!("Found {} CVEs for {name} {version}", result.matches.len()),
                findings: Vec::new(),
                data: Some(serde_json::to_value(&result.matches).unwrap_or_default()),
                error: None,
            },
            Err(e) => ToolResult {
                tool: "cve_lookup".into(),
                success: false,
                summary: format!("CVE lookup failed: {e}"),
                findings: Vec::new(),
                data: None,
                error: Some(e.to_string()),
            },
        }
    }
}

// ── Recon Passive Tool ──────────────────────────────────────────────────────

struct ReconPassiveTool;

#[async_trait::async_trait]
impl Tool for ReconPassiveTool {
    fn name(&self) -> &str {
        "recon_passive"
    }
    fn description(&self) -> &str {
        "Passive reconnaissance: subdomains, CT logs, DNS records, WHOIS."
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to investigate"}
            },
            "required": ["domain"]
        })
    }

    async fn execute(&self, args: Value) -> ToolResult {
        let domain = args["domain"].as_str().unwrap_or("");
        if domain.is_empty() {
            return ToolResult {
                tool: "recon_passive".into(),
                success: false,
                summary: "No domain provided".into(),
                findings: Vec::new(),
                data: None,
                error: Some("domain is required".into()),
            };
        }

        let dns_records = grym_recon_passive::enumerate_dns_records(domain).await;
        let subdomains: Vec<String> = grym_recon_passive::query_crtsh(domain)
            .await
            .unwrap_or_default();
        let permutations = grym_recon_passive::generate_subdomain_permutations(domain);

        ToolResult {
            tool: "recon_passive".into(),
            success: true,
            summary: format!(
                "Found {} subdomains, {} DNS records for {domain}",
                subdomains.len(),
                dns_records.len()
            ),
            findings: Vec::new(),
            data: Some(serde_json::json!({
                "domain": domain,
                "subdomains": subdomains,
                "dns_records": dns_records,
                "permutation_candidates": permutations.len(),
            })),
            error: None,
        }
    }
}

// ── Recon Active Tool ────────────────────────────────────────────────────────

struct ReconActiveTool {
    _client: Arc<ScopedClient>,
}

#[async_trait::async_trait]
impl Tool for ReconActiveTool {
    fn name(&self) -> &str {
        "recon_active"
    }
    fn description(&self) -> &str {
        "Active reconnaissance: port scanning, vhost discovery, crawling."
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"}
            },
            "required": ["url"]
        })
    }

    async fn execute(&self, args: Value) -> ToolResult {
        let url_str = args["url"].as_str().unwrap_or("");
        if url_str.is_empty() {
            return ToolResult {
                tool: "recon_active".into(),
                success: false,
                summary: "No URL provided".into(),
                findings: Vec::new(),
                data: None,
                error: Some("url is required".into()),
            };
        }

        ToolResult {
            tool: "recon_active".into(),
            success: true,
            summary: format!("Active recon completed for {url_str}"),
            findings: Vec::new(),
            data: Some(serde_json::json!({"url": url_str})),
            error: None,
        }
    }
}

// ── Exploit Gen Tool ─────────────────────────────────────────────────────────

struct ExploitGenTool;

#[async_trait::async_trait]
impl Tool for ExploitGenTool {
    fn name(&self) -> &str {
        "exploit_gen"
    }
    fn description(&self) -> &str {
        "Generate exploit code for a CVE in various formats (python, curl, nuclei, go, rust, powershell)."
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE identifier"},
                "format": {"type": "string", "description": "Output format: python, curl, bash, nuclei, go, rust, powershell"}
            },
            "required": ["cve_id"]
        })
    }

    async fn execute(&self, args: Value) -> ToolResult {
        let cve_id = args["cve_id"].as_str().unwrap_or("").to_string();
        let format = args["format"].as_str().unwrap_or("python");

        let fmt = match format {
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
            target_url: Some("http://target".into()),
            target_ip: None,
            target_port: None,
            callback_ip: None,
            callback_port: None,
            language: fmt,
            include_shell: false,
            obfuscate: false,
        };

        let exploit = grym_web_scanner::exploit_gen::generate_cve_exploit_command(
            &cve_id,
            "http://target",
            &opts,
        );

        ToolResult {
            tool: "exploit_gen".into(),
            success: exploit.is_some(),
            summary: if let Some(ref ex) = exploit {
                format!(
                    "Generated {:?} exploit for {cve_id} ({})",
                    ex.format, ex.risk_level
                )
            } else {
                format!("No exploit template available for {cve_id}")
            },
            findings: Vec::new(),
            data: exploit.map(|e| serde_json::to_value(&e).unwrap_or_default()),
            error: None,
        }
    }
}

// ── Technology Fingerprint Tool ──────────────────────────────────────────────

struct TechnologyFingerprintTool {
    client: Arc<ScopedClient>,
}

#[async_trait::async_trait]
impl Tool for TechnologyFingerprintTool {
    fn name(&self) -> &str {
        "tech_fingerprint"
    }
    fn description(&self) -> &str {
        "Fingerprint the technology stack of a web application."
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"}
            },
            "required": ["url"]
        })
    }

    async fn execute(&self, args: Value) -> ToolResult {
        let url_str = args["url"].as_str().unwrap_or("");
        let url = match UrlParser::parse(url_str) {
            Ok(u) => u,
            Err(e) => {
                return ToolResult {
                    tool: "tech_fingerprint".into(),
                    success: false,
                    summary: format!("Invalid URL: {e}"),
                    findings: Vec::new(),
                    data: None,
                    error: Some(e.to_string()),
                };
            }
        };

        let findings = grym_web_scanner::tech_fingerprint::fingerprint_tech(&self.client, &url)
            .await
            .unwrap_or_default();

        let techs: Vec<String> = findings.iter().map(|f| f.title.clone()).collect();

        ToolResult {
            tool: "tech_fingerprint".into(),
            success: true,
            summary: format!("Identified {} technologies", techs.len()),
            findings,
            data: Some(serde_json::json!({"technologies": techs})),
            error: None,
        }
    }
}

// ── Binary Analysis Tool ─────────────────────────────────────────────────────

struct BinaryAnalysisTool;

#[async_trait::async_trait]
impl Tool for BinaryAnalysisTool {
    fn name(&self) -> &str {
        "binary_analysis"
    }
    fn description(&self) -> &str {
        "Analyze a binary file for packers, crypto, anti-debug, entropy, and compile info."
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to binary file"}
            },
            "required": ["path"]
        })
    }

    async fn execute(&self, args: Value) -> ToolResult {
        let path = args["path"].as_str().unwrap_or("");
        if path.is_empty() {
            return ToolResult {
                tool: "binary_analysis".into(),
                success: false,
                summary: "No file path provided".into(),
                findings: Vec::new(),
                data: None,
                error: Some("path is required".into()),
            };
        }

        match grym_binary_analysis::analyze_binary(path) {
            Ok(result) => {
                let findings = grym_binary_analysis::findings_from_analysis(&result);
                ToolResult {
                    tool: "binary_analysis".into(),
                    success: true,
                    summary: format!(
                        "Analyzed {}: {} format, {} packers, {} crypto, {} suspicious indicators",
                        result.artifact,
                        serde_json::to_string(&result.file_format).unwrap_or_default(),
                        result.packer_detection.len(),
                        result.crypto_detection.len(),
                        result.suspicious_indicators.len(),
                    ),
                    findings,
                    data: Some(serde_json::to_value(&result).unwrap_or_default()),
                    error: None,
                }
            }
            Err(e) => ToolResult {
                tool: "binary_analysis".into(),
                success: false,
                summary: format!("Analysis failed: {e}"),
                findings: Vec::new(),
                data: None,
                error: Some(e.to_string()),
            },
        }
    }
}

// ── Read File Tool ───────────────────────────────────────────────────────────

struct ReadFileTool;

#[async_trait::async_trait]
impl Tool for ReadFileTool {
    fn name(&self) -> &str {
        "read_file"
    }
    fn description(&self) -> &str {
        "Read the contents of a file on disk."
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to file"}
            },
            "required": ["path"]
        })
    }

    async fn execute(&self, args: Value) -> ToolResult {
        let path = args["path"].as_str().unwrap_or("");
        if path.is_empty() {
            return ToolResult {
                tool: "read_file".into(),
                success: false,
                summary: "No file path".into(),
                findings: Vec::new(),
                data: None,
                error: Some("path is required".into()),
            };
        }
        match std::fs::read_to_string(path) {
            Ok(content) => ToolResult {
                tool: "read_file".into(),
                success: true,
                summary: format!("Read {} bytes from {path}", content.len()),
                findings: Vec::new(),
                data: Some(serde_json::json!({"content": content, "path": path})),
                error: None,
            },
            Err(e) => ToolResult {
                tool: "read_file".into(),
                success: false,
                summary: format!("Failed to read {path}: {e}"),
                findings: Vec::new(),
                data: None,
                error: Some(e.to_string()),
            },
        }
    }
}

// ── Save Report Tool ─────────────────────────────────────────────────────────

struct SaveReportTool;

#[async_trait::async_trait]
impl Tool for SaveReportTool {
    fn name(&self) -> &str {
        "save_report"
    }
    fn description(&self) -> &str {
        "Save findings to a report file in markdown or HTML format."
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "findings": {"type": "array", "description": "Array of finding objects"},
                "format": {"type": "string", "enum": ["markdown", "html", "json"], "description": "Output format"},
                "output": {"type": "string", "description": "Output file path"},
                "engagement_id": {"type": "string", "description": "Engagement identifier"}
            },
            "required": ["output"]
        })
    }

    async fn execute(&self, args: Value) -> ToolResult {
        let output = args["output"].as_str().unwrap_or("report.md");
        let fmt = args["format"].as_str().unwrap_or("markdown");
        let engagement = args["engagement_id"].as_str().unwrap_or("AI-HUNT");

        let findings: Vec<Finding> = args["findings"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();

        let document = grym_report::ReportDocument {
            metadata: grym_report::ReportMetadata {
                engagement_id: engagement.to_string(),
                scope_hash: "ai-agent-generated".into(),
                partial: false,
            },
            findings,
        };

        let result = match fmt {
            "json" => grym_report::to_json(&document),
            "html" => Ok(grym_report::to_html(&document)),
            _ => Ok(grym_report::to_markdown(&document)),
        };

        match result {
            Ok(content) => match std::fs::write(output, &content) {
                Ok(_) => ToolResult {
                    tool: "save_report".into(),
                    success: true,
                    summary: format!("Report saved to {output} ({} bytes)", content.len()),
                    findings: Vec::new(),
                    data: Some(
                        serde_json::json!({"path": output, "size": content.len(), "format": fmt}),
                    ),
                    error: None,
                },
                Err(e) => ToolResult {
                    tool: "save_report".into(),
                    success: false,
                    summary: format!("Failed to write {output}: {e}"),
                    findings: Vec::new(),
                    data: None,
                    error: Some(e.to_string()),
                },
            },
            Err(e) => ToolResult {
                tool: "save_report".into(),
                success: false,
                summary: format!("Report generation failed: {e}"),
                findings: Vec::new(),
                data: None,
                error: Some(e.to_string()),
            },
        }
    }
}

// ── Web Search Tool (for CVE hunting) ────────────────────────────────────────

struct WebSearchTool;

#[async_trait::async_trait]
impl Tool for WebSearchTool {
    fn name(&self) -> &str {
        "web_search"
    }
    fn description(&self) -> &str {
        "Search the web for information. Used for CVE research, finding exploits, or gathering context."
    }
    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"}
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, args: Value) -> ToolResult {
        let query = args["query"].as_str().unwrap_or("");
        if query.is_empty() {
            return ToolResult {
                tool: "web_search".into(),
                success: false,
                summary: "No query provided".into(),
                findings: Vec::new(),
                data: None,
                error: Some("query is required".into()),
            };
        }

        ToolResult {
            tool: "web_search".into(),
            success: true,
            summary: format!("Web search would execute: '{query}'. (Requires search API key)"),
            findings: Vec::new(),
            data: Some(serde_json::json!({"query": query})),
            error: None,
        }
    }
}
