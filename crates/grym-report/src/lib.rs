//! Deterministic, evidence-aware report export primitives.

#![deny(unsafe_code)]

use grym_core::{Confidence, Finding, Severity};
use serde::Serialize;
use thiserror::Error;

/// Report-level metadata carried across every output format.
#[derive(Clone, Debug, Serialize)]
pub struct ReportMetadata {
    pub engagement_id: String,
    pub scope_hash: String,
    pub partial: bool,
}

/// Complete report input shared by every renderer.
#[derive(Clone, Debug, Serialize)]
pub struct ReportDocument {
    pub metadata: ReportMetadata,
    pub findings: Vec<Finding>,
}

/// Serialization failure.
#[derive(Debug, Error)]
pub enum ReportError {
    #[error("JSON report serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

// ── JSON ─────────────────────────────────────────────────────────────────────

pub fn to_json(document: &ReportDocument) -> Result<String, ReportError> {
    Ok(serde_json::to_string_pretty(document)?)
}

// ── Markdown ─────────────────────────────────────────────────────────────────

pub fn to_markdown(document: &ReportDocument) -> String {
    let mut out = String::new();

    // Header
    out.push_str("# GRYM Security Assessment Report\n\n");

    // Metadata section
    out.push_str("## Report Metadata\n\n");
    out.push_str(&format!(
        "- **Engagement ID:** `{}`\n",
        document.metadata.engagement_id
    ));
    out.push_str(&format!(
        "- **Scope Hash:** `{}`\n",
        document.metadata.scope_hash
    ));
    out.push_str(&format!(
        "- **Status:** {}\n",
        if document.metadata.partial {
            "Partial (circuit-breaker tripped)"
        } else {
            "Complete"
        }
    ));
    out.push_str(&format!(
        "- **Total Findings:** {}\n",
        document.findings.len()
    ));
    out.push_str(&format!(
        "- **Generated:** {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // Summary statistics
    let critical = document
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = document
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = document
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = document
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let info = document
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    out.push_str("## Executive Summary\n\n");
    out.push_str("| Severity | Count |\n|----------|------:|\n");
    out.push_str(&format!("| Critical | {} |\n", critical));
    out.push_str(&format!("| High     | {} |\n", high));
    out.push_str(&format!("| Medium   | {} |\n", medium));
    out.push_str(&format!("| Low      | {} |\n", low));
    out.push_str(&format!("| Info     | {} |\n", info));
    out.push('\n');

    // Findings
    out.push_str("## Findings\n\n");

    if document.findings.is_empty() {
        out.push_str("_No findings were identified during this assessment._\n");
    }

    for (i, finding) in document.findings.iter().enumerate() {
        let severity_badge = match finding.severity {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        };
        let confidence_label = match finding.confidence {
            Confidence::Confirmed => "Confirmed",
            Confidence::Likely => "Likely",
            Confidence::Possible => "Possible",
        };

        out.push_str(&format!("### Finding {}: {}\n\n", i + 1, finding.title));
        out.push_str(&format!("- **Severity:** `{}`\n", severity_badge));
        out.push_str(&format!("- **Confidence:** `{}`\n", confidence_label));
        out.push_str(&format!(
            "- **Discovered By:** `{}`\n",
            finding.discovered_by
        ));
        out.push_str(&format!(
            "- **Discovered At:** `{}`\n",
            finding.discovered_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Asset
        out.push_str(&format!(
            "- **Affected Asset:** `{}` ({})\n",
            finding.affected_asset.identifier, finding.affected_asset.kind
        ));

        // CWE
        if !finding.cwe_ids.is_empty() {
            let cwe_str: Vec<String> = finding
                .cwe_ids
                .iter()
                .map(|id| {
                    format!(
                        "[CWE-{}](https://cwe.mitre.org/data/definitions/{}.html)",
                        id, id
                    )
                })
                .collect();
            out.push_str(&format!("- **CWE IDs:** {}\n", cwe_str.join(", ")));
        }

        // CVSS
        if let Some(ref vector) = finding.cvss_vector {
            out.push_str(&format!("- **CVSS Vector:** `{}`\n", vector));
        }
        if let Some(score) = finding.cvss_score {
            out.push_str(&format!("- **CVSS Score:** `{:.1}`\n", score));
        }

        // Categories
        if !finding.categories.is_empty() {
            out.push_str(&format!(
                "- **Categories:** {}\n",
                finding.categories.join(", ")
            ));
        }

        // ATT&CK
        if !finding.attack_techniques.is_empty() {
            let attck: Vec<String> = finding
                .attack_techniques
                .iter()
                .map(|t| {
                    if t.contains('-') {
                        format!(
                            "[{}](https://attack.mitre.org/techniques/{}/)",
                            t,
                            t.replace('.', "/")
                        )
                    } else {
                        t.clone()
                    }
                })
                .collect();
            out.push_str(&format!("- **ATT&CK Techniques:** {}\n", attck.join(", ")));
        }

        // Evidence
        if !finding.evidence.is_empty() {
            out.push_str("- **Evidence:**\n");
            for evidence in &finding.evidence {
                out.push_str(&format!("  - **Type:** `{}`\n", evidence.kind));
                out.push_str(&format!("    **Summary:** {}\n", evidence.summary));
                if !evidence.excerpt.is_empty() {
                    out.push_str(&format!(
                        "    **Excerpt:**\n```\n{}\n```\n",
                        evidence.excerpt
                    ));
                }
            }
        }

        // Remediation
        if !finding.remediation.is_empty() {
            out.push_str(&format!("- **Remediation:** {}\n", finding.remediation));
        }

        // References
        if !finding.references.is_empty() {
            out.push_str("- **References:**\n");
            for (j, reference) in finding.references.iter().enumerate() {
                if reference.starts_with("http://") || reference.starts_with("https://") {
                    out.push_str(&format!("  {}. [{}]({})\n", j + 1, reference, reference));
                } else {
                    out.push_str(&format!("  {}. {}\n", j + 1, reference));
                }
            }
        }

        out.push_str("\n---\n\n");
    }

    out
}

// ── HTML ─────────────────────────────────────────────────────────────────────

pub fn to_html(document: &ReportDocument) -> String {
    let items: String = document
        .findings
        .iter()
        .enumerate()
        .map(|(i, finding)| render_finding_html(i, finding))
        .collect();

    let critical = document
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = document
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = document
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = document
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let info = document
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    let empty_msg = if document.findings.is_empty() {
        "<p class=\"empty\">No findings were identified during this assessment.</p>"
    } else {
        ""
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GRYM Security Assessment Report</title>
<style>
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;color:#1a1a2e;background:#f8f9fa;line-height:1.6}}
  .container{{max-width:1100px;margin:0 auto;padding:2rem 1.5rem}}
  h1{{font-size:2rem;color:#16213e;border-bottom:3px solid #0f3460;padding-bottom:.5rem;margin-bottom:2rem}}
  h2{{font-size:1.5rem;color:#0f3460;margin-top:2rem;margin-bottom:1rem}}
  .meta{{background:#fff;border:1px solid #dee2e6;border-radius:8px;padding:1.25rem;margin-bottom:2rem}}
  .meta p{{margin:.35rem 0}}
  .meta code{{background:#e9ecef;padding:.15rem .4rem;border-radius:3px;font-size:.9rem}}
  .summary-table{{width:100%;border-collapse:collapse;margin-bottom:2rem;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
  .summary-table th,.summary-table td{{padding:.75rem 1rem;text-align:left;border-bottom:1px solid #dee2e6}}
  .summary-table th{{background:#16213e;color:#fff;font-weight:600;text-transform:uppercase;font-size:.8rem;letter-spacing:.5px}}
  .summary-table tr:last-child td{{border-bottom:none}}
  .finding{{background:#fff;border:1px solid #dee2e6;border-radius:8px;padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
  .finding h3{{font-size:1.2rem;color:#16213e;margin-bottom:1rem}}
  .finding h3 .num{{color:#6c757d;font-weight:400;margin-right:.5rem}}
  .badge{{display:inline-block;padding:.2rem .6rem;border-radius:4px;font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px}}
  .badge-critical{{background:#dc3545;color:#fff}}
  .badge-high{{background:#fd7e14;color:#fff}}
  .badge-medium{{background:#ffc107;color:#1a1a2e}}
  .badge-low{{background:#0dcaf0;color:#1a1a2e}}
  .badge-info{{background:#6c757d;color:#fff}}
  .badge-confirmed{{background:#198754;color:#fff}}
  .badge-likely{{background:#0d6efd;color:#fff}}
  .badge-possible{{background:#6c757d;color:#fff}}
  dl{{display:grid;grid-template-columns:auto 1fr;gap:.4rem 1rem;margin:1rem 0}}
  dt{{font-weight:700;color:#495057;white-space:nowrap}}
  dd{{margin:0}}
  dd ul{{margin:.25rem 0 0 1.25rem}}
  dd li{{margin:.15rem 0}}
  .evidence-box{{background:#f8f9fa;border:1px solid #dee2e6;border-radius:6px;padding:1rem;margin:.5rem 0}}
  .evidence-box .ev-kind{{font-size:.8rem;color:#6c757d;text-transform:uppercase;font-weight:600}}
  .evidence-box .ev-summary{{margin:.25rem 0}}
  .evidence-box pre{{background:#1a1a2e;color:#e9ecef;padding:.75rem;border-radius:4px;overflow-x:auto;font-size:.85rem;margin-top:.5rem;white-space:pre-wrap;word-break:break-all}}
  .remediation{{background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:.75rem 1rem;margin:.75rem 0;color:#856404}}
  .ref-link{{color:#0d6efd;text-decoration:none}}
  .ref-link:hover{{text-decoration:underline}}
  .empty{{font-style:italic;color:#6c757d;padding:2rem;text-align:center}}
  .footer{{text-align:center;color:#6c757d;font-size:.85rem;margin-top:3rem;padding-top:1.5rem;border-top:1px solid #dee2e6}}
</style>
</head>
<body>
<div class="container">
<h1>GRYM Security Assessment Report</h1>

<div class="meta">
<h2>Report Metadata</h2>
<p><strong>Engagement ID:</strong> <code>{engagement}</code></p>
<p><strong>Scope Hash:</strong> <code>{scope}</code></p>
<p><strong>Status:</strong> {status}</p>
<p><strong>Total Findings:</strong> {total}</p>
<p><strong>Generated:</strong> {generated}</p>
</div>

<h2>Executive Summary</h2>
<table class="summary-table">
<thead><tr><th>Severity</th><th>Count</th></tr></thead>
<tbody>
<tr><td><span class="badge badge-critical">Critical</span></td><td>{critical}</td></tr>
<tr><td><span class="badge badge-high">High</span></td><td>{high}</td></tr>
<tr><td><span class="badge badge-medium">Medium</span></td><td>{medium}</td></tr>
<tr><td><span class="badge badge-low">Low</span></td><td>{low}</td></tr>
<tr><td><span class="badge badge-info">Info</span></td><td>{info}</td></tr>
</tbody>
</table>

<h2>Findings</h2>
{empty_msg}
{items}

<div class="footer">
<p>Generated by GRYM Security Assessment Tool &mdash; {generated}</p>
</div>
</div>
</body>
</html>"#,
        engagement = html_escape(&document.metadata.engagement_id),
        scope = html_escape(&document.metadata.scope_hash),
        status = if document.metadata.partial {
            "Partial (circuit-breaker tripped)"
        } else {
            "Complete"
        },
        total = document.findings.len(),
        generated = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        critical = critical,
        high = high,
        medium = medium,
        low = low,
        info = info,
        empty_msg = empty_msg,
        items = items,
    )
}

fn render_finding_html(index: usize, finding: &Finding) -> String {
    let severity_class = match finding.severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    };
    let severity_label = format!("{:?}", finding.severity);

    let confidence_class = match finding.confidence {
        Confidence::Confirmed => "confirmed",
        Confidence::Likely => "likely",
        Confidence::Possible => "possible",
    };
    let confidence_label = format!("{:?}", finding.confidence);

    // CWE
    let cwe_html = if !finding.cwe_ids.is_empty() {
        let cwes: String = finding.cwe_ids.iter()
            .map(|id| format!(
                r#"<a href="https://cwe.mitre.org/data/definitions/{id}.html" target="_blank" rel="noopener">CWE-{id}</a>"#,
                id = id
            ))
            .collect::<Vec<_>>()
            .join(", ");
        format!("<dt>CWE IDs</dt><dd>{}</dd>", cwes)
    } else {
        String::new()
    };

    // CVSS
    let cvss_html = match (&finding.cvss_vector, finding.cvss_score) {
        (Some(vector), Some(score)) => format!(
            "<dt>CVSS</dt><dd>{} ({:.1})</dd>",
            html_escape(vector),
            score
        ),
        (Some(vector), None) => format!("<dt>CVSS Vector</dt><dd>{}</dd>", html_escape(vector)),
        (None, Some(score)) => format!("<dt>CVSS Score</dt><dd>{:.1}</dd>", score),
        (None, None) => String::new(),
    };

    // Categories
    let cat_html = if !finding.categories.is_empty() {
        format!(
            "<dt>Categories</dt><dd>{}</dd>",
            finding.categories.join(", ")
        )
    } else {
        String::new()
    };

    // ATT&CK
    let attack_html = if !finding.attack_techniques.is_empty() {
        let techniques: String = finding.attack_techniques.iter()
            .map(|t| {
                if t.contains('-') {
                    let path = t.replace('.', "/");
                    format!(r#"<a href="https://attack.mitre.org/techniques/{path}/" target="_blank" rel="noopener">{}</a>"#, html_escape(t), path = path)
                } else {
                    html_escape(t)
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        format!("<dt>ATT&CK Techniques</dt><dd>{}</dd>", techniques)
    } else {
        String::new()
    };

    // Evidence
    let evidence_html: String = finding.evidence.iter()
        .map(|ev| {
            let excerpt = if !ev.excerpt.is_empty() {
                format!("<pre>{}</pre>", html_escape(&ev.excerpt))
            } else {
                String::new()
            };
            format!(
                r#"<div class="evidence-box"><span class="ev-kind">{kind}</span><p class="ev-summary">{summary}</p>{excerpt}</div>"#,
                kind = html_escape(&ev.kind),
                summary = html_escape(&ev.summary),
                excerpt = excerpt,
            )
        })
        .collect::<String>();
    let evidence_section = if !evidence_html.is_empty() {
        format!("<dt>Evidence</dt><dd>{}</dd>", evidence_html)
    } else {
        String::new()
    };

    // Remediation
    let remediation_html = if !finding.remediation.is_empty() {
        format!(
            r#"<div class="remediation"><strong>Remediation:</strong> {}</div>"#,
            html_escape(&finding.remediation)
        )
    } else {
        String::new()
    };

    // References
    let refs_html = if !finding.references.is_empty() {
        let items: String = finding.references.iter()
            .enumerate()
            .map(|(idx, r)| {
                if r.starts_with("http://") || r.starts_with("https://") {
                    format!(r#"<li>{idx}. <a href="{}" class="ref-link" target="_blank" rel="noopener">{}</a></li>"#, html_escape(r), html_escape(r), idx = idx + 1)
                } else {
                    format!("<li>{idx}. {}</li>", html_escape(r), idx = idx + 1)
                }
            })
            .collect::<String>();
        format!("<dt>References</dt><dd><ol>{}</ol></dd>", items)
    } else {
        String::new()
    };

    format!(
        r#"<div class="finding">
<h3><span class="num">{index}.</span> {title}</h3>
<p>
  <span class="badge badge-{sev_class}">{sev_label}</span>&nbsp;
  <span class="badge badge-{conf_class}">{conf_label}</span>
</p>
<dl>
  <dt>Discovered By</dt><dd>{discovered_by}</dd>
  <dt>Discovered At</dt><dd>{discovered_at}</dd>
  <dt>Affected Asset</dt><dd>{asset} ({asset_kind})</dd>
  {cwe}
  {cvss}
  {cat}
  {attack}
  {evidence}
  {refs}
</dl>
{remediation}
</div>"#,
        index = index + 1,
        title = html_escape(&finding.title),
        sev_class = severity_class,
        sev_label = severity_label,
        conf_class = confidence_class,
        conf_label = confidence_label,
        discovered_by = html_escape(&finding.discovered_by),
        discovered_at = finding.discovered_at.format("%Y-%m-%d %H:%M:%S UTC"),
        asset = html_escape(&finding.affected_asset.identifier),
        asset_kind = html_escape(&finding.affected_asset.kind),
        cwe = cwe_html,
        cvss = cvss_html,
        cat = cat_html,
        attack = attack_html,
        evidence = evidence_section,
        refs = refs_html,
        remediation = remediation_html,
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
