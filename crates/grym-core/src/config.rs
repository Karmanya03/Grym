//! Scope configuration and validation.

use std::{fs, path::Path};

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Parsed `scope.toml` for one explicitly authorized engagement.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScopeConfig {
    /// Schema version for forward-compatible validation.
    pub format_version: u16,
    /// Engagement metadata used in reports and audit entries.
    pub engagement: Engagement,
    /// Allow and deny target rules.
    pub targets: TargetScope,
    /// Global and per-host response limits.
    pub limits: LimitConfig,
    /// Maximum permitted technique tier and scan depth.
    pub technique: TechniqueConfig,
    /// Explicit authorization acknowledgement.
    pub authorization: AuthorizationConfig,
    /// Circuit-breaker and redirect safety limits.
    #[serde(default)]
    pub safety: SafetyConfig,
}

/// Human-readable engagement context.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Engagement {
    /// Client or asset owner.
    pub client: String,
    /// Stable identifier for this authorization.
    pub engagement_id: String,
    /// Inclusive beginning of the authorized window.
    pub authorized_start: DateTime<FixedOffset>,
    /// Inclusive end of the authorized window.
    pub authorized_end: DateTime<FixedOffset>,
    /// Contact used when a circuit breaker halts work.
    pub emergency_contact: String,
}

/// Target policy rules.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TargetScope {
    /// Rules that may be contacted after all other checks pass.
    pub allow: Vec<String>,
    /// Rules that must never be contacted. Denies always win.
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Request and response bounds.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LimitConfig {
    /// Aggregate request rate across all hosts.
    pub max_requests_per_second_global: u32,
    /// Request rate for one hostname or IP address.
    pub max_requests_per_second_per_host: u32,
    /// Maximum response body retained in memory or evidence.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
}

const fn default_max_response_bytes() -> usize {
    2 * 1024 * 1024
}

/// Technique controls selected for a scan.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TechniqueConfig {
    /// Highest technique tier that the engagement permits.
    pub max_tier: TechniqueTier,
    /// Request volume/depth preset.
    #[serde(default)]
    pub deepness: Deepness,
}

/// Proof that an operator recorded authorization in the engagement record.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AuthorizationConfig {
    /// Must be true before any non-passive session can be constructed.
    #[serde(default)]
    pub authorization_attested: bool,
}

/// Safety controls that halt or constrain transport behavior.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SafetyConfig {
    /// Maximum in-scope redirects automatically followed for safe GET requests.
    #[serde(default = "default_max_redirects")]
    pub max_redirects: u8,
    /// Percentage of 403/429 responses that opens the circuit after ten samples.
    #[serde(default = "default_block_rate_threshold")]
    pub block_rate_threshold_percent: u8,
    /// Consecutive 5xx responses that open the circuit.
    #[serde(default = "default_server_error_threshold")]
    pub server_error_threshold: u32,
}

const fn default_max_redirects() -> u8 {
    5
}

const fn default_block_rate_threshold() -> u8 {
    60
}

const fn default_server_error_threshold() -> u32 {
    5
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            max_redirects: default_max_redirects(),
            block_rate_threshold_percent: default_block_rate_threshold(),
            server_error_threshold: default_server_error_threshold(),
        }
    }
}

/// The maximum operational impact authorized for a request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "u8", into = "u8")]
pub enum TechniqueTier {
    /// No packets to targets; only passive data sources.
    Passive = 0,
    /// Read-only, safe active reconnaissance.
    SafeActive = 1,
    /// Safe signature and active detection checks.
    StandardDetection = 2,
    /// Authenticated testing with operator-provided credentials.
    Authenticated = 3,
    /// Specific, approved non-destructive validation only.
    ActiveValidation = 4,
}

impl TryFrom<u8> for TechniqueTier {
    type Error = ConfigError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Passive),
            1 => Ok(Self::SafeActive),
            2 => Ok(Self::StandardDetection),
            3 => Ok(Self::Authenticated),
            4 => Ok(Self::ActiveValidation),
            _ => Err(ConfigError::Validation(format!(
                "technique.max_tier must be between 0 and 4, received {value}"
            ))),
        }
    }
}

impl From<TechniqueTier> for u8 {
    fn from(value: TechniqueTier) -> Self {
        value as u8
    }
}

/// Scan depth presets; each module interprets them conservatively.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Deepness {
    /// Low-noise, short-running inventory pass.
    Quick,
    /// Balanced default for normal authorized work.
    #[default]
    Standard,
    /// Broader coverage without risky validation.
    Deep,
    /// Lowest-noise, highest-review profile.
    Paranoid,
}

/// Configuration load or semantic-validation error.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// File-system failure.
    #[error("unable to read scope file: {0}")]
    Io(#[from] std::io::Error),
    /// TOML parse failure.
    #[error("invalid scope TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// Valid TOML that breaks GRYM's safety invariants.
    #[error("invalid scope configuration: {0}")]
    Validation(String),
    /// Canonical serialization failed while calculating the scope hash.
    #[error("unable to serialize scope configuration: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl ScopeConfig {
    /// Loads and validates a TOML scope file before it can reach any transport.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let raw = fs::read_to_string(path)?;
        let scope = toml::from_str::<Self>(&raw)?;
        scope.validate()?;
        Ok(scope)
    }

    /// Applies fail-closed semantic checks independent of TOML syntax.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.format_version != 1 {
            return Err(ConfigError::Validation(format!(
                "unsupported format_version {}; expected 1",
                self.format_version
            )));
        }
        if self.engagement.client.trim().is_empty()
            || self.engagement.engagement_id.trim().is_empty()
            || self.engagement.emergency_contact.trim().is_empty()
        {
            return Err(ConfigError::Validation(
                "engagement client, ID, and emergency contact are required".to_owned(),
            ));
        }
        if self.engagement.authorized_start >= self.engagement.authorized_end {
            return Err(ConfigError::Validation(
                "authorized_start must be before authorized_end".to_owned(),
            ));
        }
        if self.targets.allow.is_empty() {
            return Err(ConfigError::Validation(
                "targets.allow must contain at least one explicit rule".to_owned(),
            ));
        }
        for rule in self.targets.allow.iter().chain(&self.targets.deny) {
            validate_target_rule(rule)?;
        }
        if self.limits.max_requests_per_second_global == 0
            || self.limits.max_requests_per_second_per_host == 0
        {
            return Err(ConfigError::Validation(
                "request-per-second limits must be greater than zero".to_owned(),
            ));
        }
        if self.limits.max_response_bytes == 0 {
            return Err(ConfigError::Validation(
                "limits.max_response_bytes must be greater than zero".to_owned(),
            ));
        }
        if self.safety.block_rate_threshold_percent == 0
            || self.safety.block_rate_threshold_percent > 100
        {
            return Err(ConfigError::Validation(
                "safety.block_rate_threshold_percent must be in 1..=100".to_owned(),
            ));
        }
        if self.safety.server_error_threshold == 0 {
            return Err(ConfigError::Validation(
                "safety.server_error_threshold must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }

    /// Stable SHA-256 digest embedded in audit and report output.
    pub fn hash(&self) -> Result<String, ConfigError> {
        let serialized = serde_json::to_vec(self)?;
        let digest = Sha256::digest(serialized);
        Ok(format!("sha256:{digest:x}"))
    }
}

fn validate_target_rule(rule: &str) -> Result<(), ConfigError> {
    let trimmed = rule.trim();
    if trimmed.is_empty()
        || trimmed == "*"
        || trimmed.contains("://")
        || trimmed.contains(char::is_whitespace)
    {
        return Err(ConfigError::Validation(format!(
            "target rule `{rule}` is empty, unbounded, or malformed"
        )));
    }
    if trimmed.starts_with('/') || trimmed.ends_with('/') {
        return Err(ConfigError::Validation(format!(
            "target rule `{rule}` must include a host or use the explicit `*/path` form"
        )));
    }
    Ok(())
}
