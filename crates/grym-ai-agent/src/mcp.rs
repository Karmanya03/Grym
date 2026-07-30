//! MCP (Model Context Protocol) client for Grym's ReAct agent.
//!
//! Connects to MCP servers over stdio (subprocess) or HTTP transport,
//! discovers tools via `tools/list`, and wraps them as [`Tool`] trait
//! implementations so the AI agent can call nmap, nuclei, sqlmap, etc.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command as TokioCommand};
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::tools::{Tool, ToolResult};

/// Timeout for individual MCP tool calls.
const MCP_TIMEOUT: Duration = Duration::from_secs(120);
/// Timeout for initialization and tool listing.
const INIT_TIMEOUT: Duration = Duration::from_secs(15);

// ── Re-export config types from grym-core ─────────────────────────────────────

pub use grym_core::settings::{McpServerConfig, McpTransportConfig};

// ── JSON-RPC 2.0 Types ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
}

#[derive(serde::Deserialize)]
struct JsonRpcResponse {
    id: u64,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(serde::Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(default)]
    #[allow(dead_code)]
    data: Option<Value>,
}

// ── Tool Info ─────────────────────────────────────────────────────────────────

/// A tool exposed by an MCP server, with a globally unique name.
#[derive(Clone, Debug)]
pub struct McpToolInfo {
    /// Globally unique name: `{server_name}/{tool_name}`.
    pub full_name: String,
    /// Server that provides this tool.
    pub server_name: String,
    /// Tool name within the server.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for tool arguments (from `inputSchema`).
    pub input_schema: Value,
}

// ── MCP Session ───────────────────────────────────────────────────────────────

/// A connected MCP session. Clone the [`Arc<Mutex<McpSession>>`] to share.
pub struct McpSession {
    config: McpServerConfig,
    tools: Vec<McpToolInfo>,
    #[allow(dead_code)]
    child: Option<Child>,
    child_stdin: Option<ChildStdin>,
    child_stdout: Option<BufReader<ChildStdout>>,
    http_client: Option<reqwest::Client>,
    http_url: Option<String>,
    next_id: u64,
}

impl McpSession {
    /// Connect to an MCP server and perform the initialization handshake.
    pub async fn connect(config: McpServerConfig) -> anyhow::Result<Arc<Mutex<Self>>> {
        let mut session = match &config.transport {
            McpTransportConfig::Stdio { command, args } => {
                Self::connect_stdio(&config, command, args).await?
            }
            McpTransportConfig::Http { url } => Self::connect_http(&config, url).await?,
        };

        session.initialize().await?;
        session.discover_tools().await?;

        let session = Arc::new(Mutex::new(session));
        Ok(session)
    }

    async fn connect_stdio(
        config: &McpServerConfig,
        command: &str,
        args: &[String],
    ) -> anyhow::Result<Self> {
        use std::process::Stdio;

        let mut child = TokioCommand::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn MCP server '{}': {}", config.name, e))?;

        let child_stdin = child.stdin.take().ok_or_else(|| {
            anyhow::anyhow!("Failed to open stdin for MCP server '{}'", config.name)
        })?;
        let child_stdout = child.stdout.take().ok_or_else(|| {
            anyhow::anyhow!("Failed to open stdout for MCP server '{}'", config.name)
        })?;
        let reader = BufReader::new(child_stdout);

        Ok(Self {
            config: config.clone(),
            tools: Vec::new(),
            child: Some(child),
            child_stdin: Some(child_stdin),
            child_stdout: Some(reader),
            http_client: None,
            http_url: None,
            next_id: 1,
        })
    }

    async fn connect_http(config: &McpServerConfig, url: &str) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(MCP_TIMEOUT)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {e}"))?;

        Ok(Self {
            config: config.clone(),
            tools: Vec::new(),
            child: None,
            child_stdin: None,
            child_stdout: None,
            http_client: Some(client),
            http_url: Some(url.trim_end_matches('/').to_string()),
            next_id: 1,
        })
    }
}

// ── JSON-RPC Communication ────────────────────────────────────────────────────

impl McpSession {
    /// Send a JSON-RPC request and wait for the matching response.
    async fn send_request(&mut self, method: &str, params: Option<Value>) -> anyhow::Result<Value> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };

        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| anyhow::anyhow!("Failed to serialize JSON-RPC request: {e}"))?;

        match &self.config.transport {
            McpTransportConfig::Stdio { .. } => {
                self.send_stdio(&request_bytes).await?;
                self.read_stdio_response(id).await
            }
            McpTransportConfig::Http { .. } => self.send_http(&request_bytes).await,
        }
    }

    async fn send_stdio(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let stdin = self.child_stdin.as_mut().ok_or_else(|| {
            anyhow::anyhow!("stdin not available for MCP session '{}'", self.config.name)
        })?;

        timeout(MCP_TIMEOUT, async {
            stdin.write_all(bytes).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await
        })
        .await
        .map_err(|_| anyhow::anyhow!("Timeout writing to MCP server '{}'", self.config.name))?
        .map_err(|e| anyhow::anyhow!("Failed to write to MCP server '{}': {e}", self.config.name))
    }

    async fn read_stdio_response(&mut self, expected_id: u64) -> anyhow::Result<Value> {
        let reader = self.child_stdout.as_mut().ok_or_else(|| {
            anyhow::anyhow!(
                "stdout not available for MCP session '{}'",
                self.config.name
            )
        })?;

        loop {
            let mut line = String::new();
            let n = timeout(MCP_TIMEOUT, reader.read_line(&mut line))
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Timeout waiting for response from MCP server '{}'",
                        self.config.name
                    )
                })?
                .map_err(|e| {
                    anyhow::anyhow!("Failed to read from MCP server '{}': {e}", self.config.name)
                })?;

            if n == 0 {
                anyhow::bail!("MCP server '{}' closed the connection", self.config.name);
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let response: JsonRpcResponse = serde_json::from_str(trimmed).map_err(|e| {
                anyhow::anyhow!(
                    "Invalid JSON-RPC response from '{}': {e} — raw: {trimmed}",
                    self.config.name
                )
            })?;

            if response.id != expected_id {
                continue;
            }

            if let Some(err) = response.error {
                anyhow::bail!(
                    "MCP server '{}' returned error {}: {}",
                    self.config.name,
                    err.code,
                    err.message
                );
            }

            return response.result.ok_or_else(|| {
                anyhow::anyhow!("MCP server '{}' returned empty result", self.config.name)
            });
        }
    }

    async fn send_http(&self, bytes: &[u8]) -> anyhow::Result<Value> {
        let client = self
            .http_client
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HTTP client not available"))?;
        let url = self
            .http_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HTTP URL not configured"))?;

        let resp = timeout(
            MCP_TIMEOUT,
            client
                .post(url)
                .header("Content-Type", "application/json")
                .body(bytes.to_vec())
                .send(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Timeout connecting to MCP server '{}'", self.config.name))?
        .map_err(|e| {
            anyhow::anyhow!(
                "HTTP request to MCP server '{}' failed: {e}",
                self.config.name
            )
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "MCP server '{}' returned HTTP {status}: {body}",
                self.config.name
            );
        }

        let response: JsonRpcResponse = resp.json().await.map_err(|e| {
            anyhow::anyhow!("Invalid JSON-RPC response from '{}': {e}", self.config.name)
        })?;

        if let Some(err) = response.error {
            anyhow::bail!(
                "MCP server '{}' returned error {}: {}",
                self.config.name,
                err.code,
                err.message
            );
        }

        response.result.ok_or_else(|| {
            anyhow::anyhow!("MCP server '{}' returned empty result", self.config.name)
        })
    }
}

// ── MCP Protocol Handshake ────────────────────────────────────────────────────

impl McpSession {
    /// Perform the MCP initialization handshake.
    async fn initialize(&mut self) -> anyhow::Result<()> {
        let params = serde_json::json!({
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": { "name": "grym", "version": "0.1.0" }
        });

        let _result = timeout(INIT_TIMEOUT, self.send_request("initialize", Some(params)))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "Timeout during MCP initialization for '{}'",
                    self.config.name
                )
            })??;

        // Send initialized notification (fire-and-forget)
        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        });
        let notif_bytes = serde_json::to_vec(&notification)
            .map_err(|e| anyhow::anyhow!("Serialization error: {e}"))?;

        match &self.config.transport {
            McpTransportConfig::Stdio { .. } => {
                let stdin = self
                    .child_stdin
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("stdin not available"))?;
                let _ = stdin.write_all(&notif_bytes).await;
                let _ = stdin.write_all(b"\n").await;
                let _ = stdin.flush().await;
            }
            McpTransportConfig::Http { .. } => {
                let _ = self.send_http(&notif_bytes).await;
            }
        }

        Ok(())
    }

    /// Discover tools from the MCP server via `tools/list`.
    async fn discover_tools(&mut self) -> anyhow::Result<()> {
        let result = timeout(INIT_TIMEOUT, self.send_request("tools/list", None))
            .await
            .map_err(|_| anyhow::anyhow!("Timeout listing tools from '{}'", self.config.name))??;

        let tools_array = result["tools"]
            .as_array()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "MCP server '{}' returned invalid tools/list response",
                    self.config.name
                )
            })?
            .clone();

        let server_name = self.config.name.clone();
        self.tools = tools_array
            .into_iter()
            .filter_map(|t| {
                let name = t["name"].as_str()?.to_string();
                let description = t["description"].as_str().unwrap_or("").to_string();
                let input_schema = t.get("inputSchema")?.clone();
                Some(McpToolInfo {
                    full_name: format!("{}/{}", server_name, name),
                    server_name: server_name.clone(),
                    name,
                    description,
                    input_schema,
                })
            })
            .collect();

        tracing::info!(
            "Discovered {} tools from MCP server '{}'",
            self.tools.len(),
            self.config.name
        );

        Ok(())
    }

    /// Call a tool on this MCP server.
    pub async fn call_tool(&mut self, tool_name: &str, arguments: Value) -> anyhow::Result<Value> {
        let params = serde_json::json!({
            "name": tool_name,
            "arguments": arguments,
        });
        self.send_request("tools/call", Some(params)).await
    }

    /// Get the discovered tools.
    pub fn tools(&self) -> &[McpToolInfo] {
        &self.tools
    }
}

// ── Tool Wrapper ──────────────────────────────────────────────────────────────

/// Wraps an MCP tool as a Grym [`Tool`] trait object.
pub struct McpToolWrapper {
    session: Arc<Mutex<McpSession>>,
    info: McpToolInfo,
}

#[async_trait::async_trait]
#[allow(clippy::misnamed_getters)]
impl Tool for McpToolWrapper {
    fn name(&self) -> &str {
        &self.info.full_name
    }

    fn description(&self) -> &str {
        &self.info.description
    }

    fn parameters(&self) -> Value {
        self.info.input_schema.clone()
    }

    async fn execute(&self, args: Value) -> ToolResult {
        let mut session = self.session.lock().await;

        match session.call_tool(&self.info.name, args).await {
            Ok(result) => {
                let content = result["content"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|c| c["text"].as_str())
                            .collect::<Vec<&str>>()
                            .join("\n")
                    })
                    .unwrap_or_else(|| {
                        serde_json::to_string_pretty(&result)
                            .unwrap_or_else(|e| format!("{{error: {e}}}"))
                    });

                let is_error = result["isError"].as_bool().unwrap_or(false);

                let summary = if content.len() > 500 {
                    format!("{}... ({} total chars)", &content[..500], content.len())
                } else {
                    content.clone()
                };

                ToolResult {
                    tool: self.info.full_name.clone(),
                    success: !is_error,
                    summary,
                    findings: Vec::new(),
                    data: Some(result),
                    error: if is_error { Some(content) } else { None },
                }
            }
            Err(e) => ToolResult {
                tool: self.info.full_name.clone(),
                success: false,
                summary: format!("MCP tool call failed: {e}"),
                findings: Vec::new(),
                data: None,
                error: Some(e.to_string()),
            },
        }
    }
}

// ── Connection Helper ─────────────────────────────────────────────────────────

/// Connect to all enabled MCP servers and return their session handles and tool wrappers.
pub async fn connect_enabled_mcp_servers() -> (Vec<Arc<Mutex<McpSession>>>, Vec<Box<dyn Tool>>) {
    let settings = grym_core::settings::GrymSettings::load();
    let mut sessions = Vec::new();
    let mut tools: Vec<Box<dyn Tool>> = Vec::new();

    for server_config in &settings.mcp_servers {
        if !server_config.enabled {
            continue;
        }
        match McpSession::connect(server_config.clone()).await {
            Ok(session) => {
                let tool_infos = {
                    let s = session.lock().await;
                    s.tools().to_vec()
                };
                for info in tool_infos {
                    let wrapper = McpToolWrapper {
                        session: Arc::clone(&session),
                        info,
                    };
                    tools.push(Box::new(wrapper));
                }
                sessions.push(session);
                tracing::info!("Connected to MCP server '{}'", server_config.name);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to connect to MCP server '{}': {e}",
                    server_config.name
                );
            }
        }
    }

    (sessions, tools)
}
