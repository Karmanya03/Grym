//! Deterministic, evidence-aware report export primitives.

#![deny(unsafe_code)]

use serde::Serialize;
use thiserror::Error;
use grym_core::Finding;

/// Report-level metadata carried across every output format.
#[derive(Clone, Debug, Serialize)]
pub struct ReportMetadata {
    /// Engagement identifier.
    pub engagement_id: String,
    /// Immutable scope policy hash.
    pub scope_hash: String,
    /// Whether the report was emitted after a circuit-breaker halt.
    pub partial: bool,
}

/// Complete report input shared by every renderer.
#[derive(Clone, Debug, Serialize)]
pub struct ReportDocument {
    /// Audit-relevant report metadata.
    pub metadata: ReportMetadata,
    /// Evidence-bearing findings.
    pub findings: Vec<Finding>,
}

/// Serialization failure.
#[derive(Debug, Error)]
pub enum ReportError {
    /// JSON serialization failure.
    #[error("JSON report serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// Produces a machine-consumable JSON report.
pub fn to_json(document: &ReportDocument) -> Result<String, ReportError> {
    Ok(serde_json::to_string_pretty(document)?)
}

/// Produces a compact human-reviewable Markdown report.
pub fn to_markdown(document: &ReportDocument) -> String {
    let mut output = format!(
        "# GRYM assessment report\n\n- Engagement: `{}`\n- Scope hash: `{}`\n- Status: {}\n\n## Findings\n",
        document.metadata.engagement_id,
        document.metadata.scope_hash,
        if document.metadata.partial {
            "partial"
        } else {
            "complete"
        }
    );
    for finding in &document.findings {
        output.push_str(&format!(
            "\n### {}\n\n- Severity: `{:?}`\n- Confidence: `{:?}`\n- Asset: `{}`\n- Remediation: {}\n",
            finding.title,
            finding.severity,
            finding.confidence,
            finding.affected_asset.identifier,
            finding.remediation
        ));
    }
    output
}

/// Produces a dependency-free HTML report with escaped user-controlled values.
pub fn to_html(document: &ReportDocument) -> String {
    let items = document
        .findings
        .iter()
        .map(|finding| {
            format!(
                "<article><h2>{}</h2><dl><dt>Severity</dt><dd>{:?}</dd><dt>Confidence</dt><dd>{:?}</dd><dt>Asset</dt><dd>{}</dd></dl><p>{}</p></article>",
                html_escape(&finding.title),
                finding.severity,
                finding.confidence,
                html_escape(&finding.affected_asset.identifier),
                html_escape(&finding.remediation)
            )
        })
        .collect::<String>();
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>GRYM report</title><style>body{{font-family:system-ui;max-width:960px;margin:2rem auto;padding:0 1rem}}article{{border:1px solid #ddd;padding:1rem;margin:1rem 0}}dt{{font-weight:700}}dd{{margin:0 0 .5rem}}</style></head><body><h1>GRYM assessment report</h1><p>Engagement: <code>{}</code><br>Scope hash: <code>{}</code></p>{items}</body></html>",
        html_escape(&document.metadata.engagement_id),
        html_escape(&document.metadata.scope_hash)
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
