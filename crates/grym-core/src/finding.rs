//! Versioned finding data contract shared by every module.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::redaction::redact_text;

/// A URL, host, file, or package affected by a finding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetRef {
    /// Canonical asset identifier, with sensitive URL parameters removed.
    pub identifier: String,
    /// Asset class, such as `web`, `api`, `binary`, or `mobile`.
    pub kind: String,
}

/// Evidence captured for operator review.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Evidence {
    /// Evidence source, such as `http-response` or `binary-offset`.
    pub kind: String,
    /// Human-readable, redacted summary.
    pub summary: String,
    /// Redacted raw excerpt only; never use this for unbounded bodies.
    pub excerpt: String,
}

impl Evidence {
    /// Creates evidence while applying the shared secret and PII redaction policy.
    pub fn redacted(
        kind: impl Into<String>,
        summary: impl AsRef<str>,
        excerpt: impl AsRef<str>,
    ) -> Self {
        Self {
            kind: kind.into(),
            summary: redact_text(summary.as_ref()),
            excerpt: redact_text(excerpt.as_ref()),
        }
    }
}

/// Confidence assigned by a check; reports must never omit it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Direct, non-destructive proof exists.
    Confirmed,
    /// Strong signal with limited ambiguity.
    Likely,
    /// Useful lead that requires operator review.
    Possible,
}

/// Finding severity independent of confidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational observation.
    Info,
    /// Low impact or difficult-to-exploit weakness.
    Low,
    /// Material weakness requiring remediation planning.
    Medium,
    /// High impact or low-complexity exposure.
    High,
    /// Critical, urgent exposure.
    Critical,
}

/// Normalized report record with data-driven taxonomy mappings.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Finding {
    /// Time-sortable unique identifier.
    pub id: Uuid,
    /// Concise report heading.
    pub title: String,
    /// Mapping-pack category IDs, not hardcoded enums.
    pub categories: Vec<String>,
    /// CWE identifiers.
    pub cwe_ids: Vec<u32>,
    /// ATT&CK technique identifiers.
    pub attack_techniques: Vec<String>,
    /// Optional CVSS vector.
    pub cvss_vector: Option<String>,
    /// Optional normalized CVSS score.
    pub cvss_score: Option<f32>,
    /// Report severity.
    pub severity: Severity,
    /// Affected asset.
    pub affected_asset: AssetRef,
    /// Redacted supporting material.
    pub evidence: Vec<Evidence>,
    /// Signal strength.
    pub confidence: Confidence,
    /// Stable module identifier.
    pub discovered_by: String,
    /// Discovery time in UTC.
    pub discovered_at: DateTime<Utc>,
    /// Operator-facing remediation direction.
    pub remediation: String,
    /// Primary vendor and standards references.
    pub references: Vec<String>,
}

impl Finding {
    /// Starts a complete, report-ready finding with safe defaults.
    pub fn new(
        title: impl Into<String>,
        affected_asset: AssetRef,
        severity: Severity,
        confidence: Confidence,
        discovered_by: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            title: title.into(),
            categories: Vec::new(),
            cwe_ids: Vec::new(),
            attack_techniques: Vec::new(),
            cvss_vector: None,
            cvss_score: None,
            severity,
            affected_asset,
            evidence: Vec::new(),
            confidence,
            discovered_by: discovered_by.into(),
            discovered_at: Utc::now(),
            remediation: String::new(),
            references: Vec::new(),
        }
    }
}
