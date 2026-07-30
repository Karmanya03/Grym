//! Application settings: scope configuration, Ollama connection, and general preferences.
//! All settings are persisted as JSON in `~/.grym/settings.json` and can be managed
//! via the API server, TUI, or CLI — no manual file editing required.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::config::{Deepness, ScopeConfig, TechniqueTier};

/// Default Ollama endpoint.
const DEFAULT_OLLAMA_URL: &str = "http://127.0.0.1:11434";


/// Path to the settings file (`~/.grym/settings.json` on Linux/macOS,
/// `%APPDATA%/grym/settings.json` on Windows).
fn settings_path() -> PathBuf {
    let base = if cfg!(target_os = "windows") {
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    } else {
        std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".config"))
            .unwrap_or_else(|_| PathBuf::from("."))
    };
    let path = base.join("grym");
    let _ = std::fs::create_dir_all(&path);
    path.join("settings.json")
}

// ── MCP Server Configuration ─────────────────────────────────────────────────

/// Configuration for an MCP (Model Context Protocol) server connection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpServerConfig {
    /// Display name for this server.
    pub name: String,
    /// Transport configuration.
    pub transport: McpTransportConfig,
    /// Whether this server is enabled at startup.
    #[serde(default = "default_mcp_enabled")]
    pub enabled: bool,
}

const fn default_mcp_enabled() -> bool {
    true
}

/// Transport configuration for an MCP server.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum McpTransportConfig {
    /// Spawn a subprocess and communicate via stdin/stdout.
    #[serde(rename = "stdio")]
    Stdio {
        /// Command to run (e.g., "docker", "npx", "node").
        command: String,
        /// Arguments for the command.
        #[serde(default)]
        args: Vec<String>,
    },
    /// Communicate via HTTP POST to a JSON-RPC endpoint.
    #[serde(rename = "http")]
    Http {
        /// Base URL of the MCP server.
        url: String,
    },
}

/// Complete application settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrymSettings {
    /// Ollama connection settings.
    pub ollama: OllamaSettings,
    /// Last-used scope configuration (editable via API/TUI).
    pub scope: ScopeSettings,
    /// General application preferences.
    pub preferences: HashMap<String, String>,
    /// MCP server connections for the AI agent.
    #[serde(default)]
    pub mcp_servers: Vec<McpServerConfig>,
}

/// Ollama connection settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OllamaSettings {
    /// Base URL of the Ollama server.
    pub base_url: String,
    /// Whether auto-detection already succeeded.
    pub auto_detected: bool,
    /// Whether Ollama is currently reachable.
    #[serde(skip)]
    pub reachable: bool,
    /// Ollama version string, if detected.
    #[serde(skip)]
    pub version: Option<String>,
    /// Available models on this server.
    #[serde(skip)]
    pub available_models: Vec<String>,
    /// Last successful connection timestamp.
    #[serde(skip)]
    pub last_checked: Option<String>,
}

/// Scope configuration (editable without file access).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeSettings {
    /// Engagement identifier.
    pub engagement_id: String,
    /// Client name.
    pub client: String,
    /// Authorized start (ISO 8601).
    pub authorized_start: String,
    /// Authorized end (ISO 8601).
    pub authorized_end: String,
    /// Emergency contact.
    pub emergency_contact: String,
    /// Allowed targets (CIDR, domain, glob).
    pub allow: Vec<String>,
    /// Denied targets.
    pub deny: Vec<String>,
    /// Max requests per second (global).
    pub max_rps_global: u32,
    /// Max requests per second (per host).
    pub max_rps_host: u32,
    /// Max response bytes.
    pub max_response_bytes: u64,
    /// Maximum technique tier (1-4).
    pub max_tier: u8,
    /// Deepness level.
    pub deepness: String,
    /// Whether authorization is attested.
    pub authorization_attested: bool,
}

impl Default for GrymSettings {
    fn default() -> Self {
        Self {
            ollama: OllamaSettings {
                base_url: DEFAULT_OLLAMA_URL.to_string(),
                auto_detected: false,
                reachable: false,
                version: None,
                available_models: Vec::new(),
                last_checked: None,
            },
            scope: ScopeSettings::default(),
            preferences: HashMap::new(),
            mcp_servers: Vec::new(),
        }
    }
}

impl Default for ScopeSettings {
    fn default() -> Self {
        Self {
            engagement_id: "default".into(),
            client: "Default Client".into(),
            authorized_start: "2025-01-01T00:00:00Z".into(),
            authorized_end: "2025-12-31T23:59:59Z".into(),
            emergency_contact: "ops@example.com".into(),
            allow: vec!["0.0.0.0/0".into()],
            deny: Vec::new(),
            max_rps_global: 100,
            max_rps_host: 10,
            max_response_bytes: 4 * 1024 * 1024,
            max_tier: 3,
            deepness: "standard".into(),
            authorization_attested: true,
        }
    }
}

impl ScopeSettings {
    /// Convert to a `ScopeConfig` for engine consumption.
    pub fn to_scope_config(&self) -> Result<ScopeConfig, String> {
        let offset = chrono::FixedOffset::east_opt(0).ok_or("invalid offset")?;
        let start = chrono::DateTime::parse_from_rfc3339(&self.authorized_start)
            .map(|d| d.with_timezone(&offset))
            .map_err(|e| format!("invalid authorized_start: {e}"))?;
        let end = chrono::DateTime::parse_from_rfc3339(&self.authorized_end)
            .map(|d| d.with_timezone(&offset))
            .map_err(|e| format!("invalid authorized_end: {e}"))?;

        let deepness = match self.deepness.to_lowercase().as_str() {
            "quick" => Deepness::Quick,
            "standard" => Deepness::Standard,
            "deep" => Deepness::Deep,
            "paranoid" => Deepness::Paranoid,
            _ => Deepness::Standard,
        };

        let max_tier_val: u8 = self.max_tier.min(4);

        Ok(ScopeConfig {
            format_version: 1,
            engagement: crate::config::Engagement {
                client: self.client.clone(),
                engagement_id: self.engagement_id.clone(),
                authorized_start: start,
                authorized_end: end,
                emergency_contact: self.emergency_contact.clone(),
            },
            targets: crate::config::TargetScope {
                allow: self.allow.clone(),
                deny: self.deny.clone(),
            },
            limits: crate::config::LimitConfig {
                max_requests_per_second_global: self.max_rps_global,
                max_requests_per_second_per_host: self.max_rps_host,
                max_response_bytes: self.max_response_bytes as usize,
            },
            technique: crate::config::TechniqueConfig {
                max_tier: TechniqueTier::try_from(max_tier_val).map_err(|e| format!("{e}"))?,
                deepness,
            },
            authorization: crate::config::AuthorizationConfig {
                authorization_attested: self.authorization_attested,
            },
            safety: crate::config::SafetyConfig::default(),
        })
    }

    /// Populate from a `ScopeConfig`.
    pub fn from_scope_config(cfg: &ScopeConfig) -> Self {
        Self {
            engagement_id: cfg.engagement.engagement_id.clone(),
            client: cfg.engagement.client.clone(),
            authorized_start: cfg.engagement.authorized_start.to_rfc3339(),
            authorized_end: cfg.engagement.authorized_end.to_rfc3339(),
            emergency_contact: cfg.engagement.emergency_contact.clone(),
            allow: cfg.targets.allow.clone(),
            deny: cfg.targets.deny.clone(),
            max_rps_global: cfg.limits.max_requests_per_second_global,
            max_rps_host: cfg.limits.max_requests_per_second_per_host,
            max_response_bytes: cfg.limits.max_response_bytes as u64,
            max_tier: u8::from(cfg.technique.max_tier),
            deepness: serde_json::from_value::<String>(serde_json::json!(cfg.technique.deepness))
                .unwrap_or_else(|_| "standard".into()),
            authorization_attested: cfg.authorization.authorization_attested,
        }
    }
}

impl GrymSettings {
    /// Load settings from disk, or return defaults.
    pub fn load() -> Self {
        let path = settings_path();
        match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => {
                let s = Self::default();
                let _ = s.save();
                s
            }
        }
    }

    /// Save settings to disk.
    pub fn save(&self) -> Result<(), String> {
        let path = settings_path();
        let content = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, content).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Auto-detect Ollama: try connecting to the default URL,
    /// fall back to searching for a running process.
    pub async fn auto_detect_ollama(&mut self) -> bool {
        // Try default URL first
        if Self::check_ollama_url(&self.ollama.base_url).await {
            self.ollama.reachable = true;
            self.ollama.auto_detected = true;
            self.ollama.last_checked = Some(chrono::Utc::now().to_rfc3339());
            self.update_ollama_info().await;
            return true;
        }

        // Try common alternate ports (11435, 11436, 8080)
        for port in &[11435u16, 11436, 8080, 8000] {
            let url = format!("http://127.0.0.1:{port}");
            if Self::check_ollama_url(&url).await {
                self.ollama.base_url = url;
                self.ollama.reachable = true;
                self.ollama.auto_detected = true;
                self.ollama.last_checked = Some(chrono::Utc::now().to_rfc3339());
                self.update_ollama_info().await;
                return true;
            }
        }

        // Check if ollama process is running
        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = std::process::Command::new("pgrep").arg("ollama").output() {
                if output.status.success() {
                    // Process exists but we couldn't connect — leave as default
                    self.ollama.reachable = false;
                    self.ollama.auto_detected = true;
                    return false;
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = std::process::Command::new("tasklist")
                .args(["/FI", "IMAGENAME eq ollama.exe", "/NH"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("ollama.exe") {
                    self.ollama.auto_detected = true;
                }
            }
        }

        false
    }

    /// Check if a specific Ollama URL is reachable.
    pub async fn check_ollama_url(url: &str) -> bool {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .ok();
        match client {
            Some(c) => c
                .get(format!("{}/api/tags", url.trim_end_matches('/')))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false),
            None => false,
        }
    }

    /// Queries the configured Ollama server for available models and version.
    pub async fn update_ollama_info(&mut self) {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .ok();
        if let Some(c) = client {
            // Get available models
            if let Ok(resp) = c
                .get(format!(
                    "{}/api/tags",
                    self.ollama.base_url.trim_end_matches('/')
                ))
                .send()
                .await
                && let Ok(data) = resp.json::<serde_json::Value>().await
                && let Some(models) = data["models"].as_array()
            {
                self.ollama.available_models = models
                    .iter()
                    .filter_map(|m| m["name"].as_str().map(String::from))
                    .collect();
            }

            // Get version
            if let Ok(resp) = c
                .get(format!(
                    "{}/api/version",
                    self.ollama.base_url.trim_end_matches('/')
                ))
                .send()
                .await
                && let Ok(data) = resp.json::<serde_json::Value>().await
            {
                self.ollama.version = data["version"].as_str().map(String::from);
            }
        }
    }
}

/// Global cached settings, loaded once at startup.
static SETTINGS: LazyLock<std::sync::RwLock<GrymSettings>> =
    LazyLock::new(|| std::sync::RwLock::new(GrymSettings::load()));

/// Access the global settings.
pub fn global_settings() -> std::sync::RwLock<GrymSettings> {
    // LazyLock Deref gives us &RwLock<GrymSettings>, we clone the inner
    match SETTINGS.read() {
        Ok(s) => std::sync::RwLock::new(s.clone()),
        Err(_) => std::sync::RwLock::new(GrymSettings::default()),
    }
}

/// Reload settings from disk into the global cache.
pub fn reload_settings() {
    let loaded = GrymSettings::load();
    if let Ok(mut s) = SETTINGS.write() {
        *s = loaded;
    }
}

/// Save the current global settings to disk.
pub fn save_settings() -> Result<(), String> {
    let current = {
        match SETTINGS.read() {
            Ok(s) => s.clone(),
            Err(_) => return Err("settings lock poisoned".into()),
        }
    };
    current.save()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings_valid() {
        let s = GrymSettings::default();
        assert!(s.scope.to_scope_config().is_ok());
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn test_scope_settings_roundtrip() {
        let settings = ScopeSettings::default();
        let config = settings
            .to_scope_config()
            .expect("to_scope_config should succeed for default settings");
        let rt = ScopeSettings::from_scope_config(&config);
        assert_eq!(settings.engagement_id, rt.engagement_id);
        assert_eq!(settings.client, rt.client);
    }
}
