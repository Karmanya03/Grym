//! Fail-closed target authorization.

use std::{net::IpAddr, sync::Arc};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::{
    audit::{AuditError, AuditEvent, AuditSink},
    config::{ConfigError, ScopeConfig, TechniqueTier},
    redaction::redact_url,
};

/// Parsed allow or deny rule. Deny rules are evaluated before allow rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetRule {
    host: HostRule,
    path: Option<PathRule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HostRule {
    Any,
    Exact(String),
    WildcardSubdomain(String),
    Cidr(IpNet),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PathRule {
    Exact(String),
    Prefix(String),
}

impl TargetRule {
    /// Parses the compact host, wildcard, CIDR, or `*/path` configuration form.
    pub fn parse(raw: &str) -> Result<Self, ScopeError> {
        let raw = raw.trim();
        if raw.is_empty() || raw == "*" {
            return Err(ScopeError::InvalidRule(raw.to_owned()));
        }
        if let Ok(cidr) = raw.parse::<IpNet>() {
            return Ok(Self {
                host: HostRule::Cidr(cidr),
                path: None,
            });
        }

        let (host_part, path_part) = if let Some(path) = raw.strip_prefix("*/") {
            ("*", Some(format!("/{path}")))
        } else if let Some((host, path)) = raw.split_once('/') {
            (host, Some(format!("/{path}")))
        } else {
            (raw, None)
        };

        let host = if host_part == "*" {
            HostRule::Any
        } else if let Some(suffix) = host_part.strip_prefix("*.") {
            if suffix.is_empty() || suffix.contains('*') {
                return Err(ScopeError::InvalidRule(raw.to_owned()));
            }
            HostRule::WildcardSubdomain(suffix.to_ascii_lowercase())
        } else if host_part.contains('*') || host_part.is_empty() {
            return Err(ScopeError::InvalidRule(raw.to_owned()));
        } else {
            HostRule::Exact(host_part.to_ascii_lowercase())
        };

        let path = path_part.map(|path| {
            if let Some(prefix) = path.strip_suffix('*') {
                PathRule::Prefix(prefix.to_owned())
            } else {
                PathRule::Exact(path)
            }
        });
        Ok(Self { host, path })
    }

    fn matches(&self, url: &Url) -> bool {
        let Some(host) = url.host_str() else {
            return false;
        };
        let normalized_host = host.to_ascii_lowercase();
        let host_matches = match &self.host {
            HostRule::Any => true,
            HostRule::Exact(expected) => normalized_host == *expected,
            HostRule::WildcardSubdomain(suffix) => {
                normalized_host != *suffix && normalized_host.ends_with(&format!(".{suffix}"))
            }
            HostRule::Cidr(network) => normalized_host
                .parse::<IpAddr>()
                .is_ok_and(|address| network.contains(&address)),
        };
        if !host_matches {
            return false;
        }
        match &self.path {
            None => true,
            Some(PathRule::Exact(expected)) => url.path() == expected,
            Some(PathRule::Prefix(prefix)) => url.path().starts_with(prefix),
        }
    }
}

/// Reason an outbound action was denied.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    /// URL scheme cannot be sent by the scoped HTTP client.
    UnsupportedScheme,
    /// URL contains credential-bearing userinfo.
    UrlCredentialsForbidden,
    /// The engagement time window is not currently active.
    OutsideAuthorizedWindow,
    /// A deny rule matched before any allow rule.
    ExplicitlyDenied,
    /// No allow rule matched the hostname and path.
    NotAllowlisted,
    /// Requested work is above the engagement's maximum tier.
    TechniqueTierExceeded,
    /// Non-passive work lacks both config and typed session authorization.
    AuthorizationAttestationMissing,
}

/// Explicit session proof that the operator has authority for the engagement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorAttestation {
    /// Engagement ID named by the operator.
    pub engagement_id: String,
    /// Typed phrase; kept in memory only and never written to audit logs.
    pub confirmation: String,
}

impl OperatorAttestation {
    /// The exact phrase required for an engagement ID.
    pub fn required_phrase(engagement_id: &str) -> String {
        format!("I CONFIRM AUTHORIZATION FOR {engagement_id}")
    }

    fn verifies(&self, config: &ScopeConfig) -> bool {
        config.authorization.authorization_attested
            && self.engagement_id == config.engagement.engagement_id
            && self.confirmation == Self::required_phrase(&config.engagement.engagement_id)
    }
}

/// Safety policy or audit failure from Scope Guard enforcement.
#[derive(Debug, Error)]
pub enum ScopeError {
    /// Scope configuration failed semantic validation.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// A rule could not be parsed as a bounded target expression.
    #[error("invalid target rule `{0}`")]
    InvalidRule(String),
    /// The requested session did not provide a valid typed authorization attestation.
    #[error("a valid typed authorization attestation is required for this engagement")]
    AttestationRequired,
    /// An action was denied by Scope Guard.
    #[error("scope denied {target}: {reason:?}")]
    Denied {
        /// Redacted target considered by the policy.
        target: String,
        /// Policy reason for the denial.
        reason: DenialReason,
    },
    /// The mandatory audit record could not be written.
    #[error(transparent)]
    Audit(#[from] AuditError),
}

/// Central policy gate used before every outbound HTTP request.
pub struct ScopeGuard {
    config: Arc<ScopeConfig>,
    allow: Vec<TargetRule>,
    deny: Vec<TargetRule>,
    scope_hash: String,
    session_attested: bool,
    audit: Arc<dyn AuditSink>,
}

impl std::fmt::Debug for ScopeGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScopeGuard")
            .field("engagement_id", &self.config.engagement.engagement_id)
            .field("allow_rules", &self.allow.len())
            .field("deny_rules", &self.deny.len())
            .field("session_attested", &self.session_attested)
            .finish_non_exhaustive()
    }
}

impl ScopeGuard {
    /// Builds an immutable guard. Non-passive scopes require a matching typed session confirmation.
    pub fn new(
        config: ScopeConfig,
        attestation: Option<OperatorAttestation>,
        audit: Arc<dyn AuditSink>,
    ) -> Result<Self, ScopeError> {
        config.validate()?;
        let session_attested = attestation.is_some_and(|value| value.verifies(&config));
        if config.technique.max_tier > TechniqueTier::Passive && !session_attested {
            return Err(ScopeError::AttestationRequired);
        }
        let allow = config
            .targets
            .allow
            .iter()
            .map(|rule| TargetRule::parse(rule))
            .collect::<Result<Vec<_>, _>>()?;
        let deny = config
            .targets
            .deny
            .iter()
            .map(|rule| TargetRule::parse(rule))
            .collect::<Result<Vec<_>, _>>()?;
        let scope_hash = config.hash()?;
        Ok(Self {
            config: Arc::new(config),
            allow,
            deny,
            scope_hash,
            session_attested,
            audit,
        })
    }

    /// Exposes read-only configuration to schedulers and report metadata.
    pub fn config(&self) -> &ScopeConfig {
        &self.config
    }

    /// Returns the stable hash that identifies the loaded scope policy.
    pub fn scope_hash(&self) -> &str {
        &self.scope_hash
    }

    /// Evaluates and logs an outbound URL using the current clock.
    pub fn authorize_url(
        &self,
        module: &str,
        url: &Url,
        tier: TechniqueTier,
    ) -> Result<(), ScopeError> {
        self.authorize_url_at(module, url, tier, Utc::now())
    }

    /// Evaluates and logs an outbound URL at a supplied time; useful for deterministic tests.
    pub fn authorize_url_at(
        &self,
        module: &str,
        url: &Url,
        tier: TechniqueTier,
        now: DateTime<Utc>,
    ) -> Result<(), ScopeError> {
        let reason = self.denial_reason(url, tier, now);
        let target = redact_url(url);
        let event = AuditEvent {
            timestamp: now,
            engagement_id: self.config.engagement.engagement_id.clone(),
            scope_hash: self.scope_hash.clone(),
            module: module.to_owned(),
            target: target.clone(),
            technique_tier: tier,
            allowed: reason.is_none(),
            denial_reason: reason,
        };
        self.audit.record(&event)?;

        match reason {
            Some(reason) => Err(ScopeError::Denied { target, reason }),
            None => {
                tracing::debug!(module, target = %target, tier = u8::from(tier), "scope request allowed");
                Ok(())
            }
        }
    }

    fn denial_reason(
        &self,
        url: &Url,
        tier: TechniqueTier,
        now: DateTime<Utc>,
    ) -> Option<DenialReason> {
        if !matches!(url.scheme(), "http" | "https") {
            return Some(DenialReason::UnsupportedScheme);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Some(DenialReason::UrlCredentialsForbidden);
        }
        let start = self.config.engagement.authorized_start.with_timezone(&Utc);
        let end = self.config.engagement.authorized_end.with_timezone(&Utc);
        if now < start || now > end {
            return Some(DenialReason::OutsideAuthorizedWindow);
        }
        if tier > self.config.technique.max_tier {
            return Some(DenialReason::TechniqueTierExceeded);
        }
        if tier > TechniqueTier::Passive && !self.session_attested {
            return Some(DenialReason::AuthorizationAttestationMissing);
        }
        if self.deny.iter().any(|rule| rule.matches(url)) {
            return Some(DenialReason::ExplicitlyDenied);
        }
        if !self.allow.iter().any(|rule| rule.matches(url)) {
            return Some(DenialReason::NotAllowlisted);
        }
        None
    }
}
