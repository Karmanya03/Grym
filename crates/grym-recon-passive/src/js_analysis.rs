//! JavaScript bundle analysis for endpoint discovery and secret detection.

use regex::Regex;
use serde::{Deserialize, Serialize};
use grym_core::{Confidence, Finding, AssetRef, Severity, Evidence};

/// Endpoint discovered from JS analysis.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize)]
pub struct JsEndpoint {
    pub url: String,
    pub endpoint: String,
    pub source: String,
}

/// Potential secret/API key found in JS.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, PartialOrd, Ord, Serialize)]
pub struct JsSecret {
    pub url: String,
    pub secret_type: String,
    pub context: String,
}

/// Extracts API endpoints from JS content.
pub fn extract_endpoints(js_content: &str, source_url: &str) -> Vec<JsEndpoint> {
    let mut endpoints = Vec::new();

    let patterns = [
        r#""(https?://[^"'\s]+)""#,
        r#"'(https?://[^"'\s]+)'"#,
        r#"`(https?://[^`]+)`"#,
        r#"["'](/[a-zA-Z][^"'\s]*)["']"#,
        r#"url:\s*["']([^"']+)["']"#,
        r#"path:\s*["']([^"']+)["']"#,
        r#"endpoint:\s*["']([^"']+)["']"#,
        r#"api[^:]*:\s*["']([^"']+)["']"#,
    ];

    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(js_content) {
                if let Some(m) = cap.get(1) {
                    let endpoint = m.as_str().to_string();
                    if endpoint.len() > 3 && endpoint.len() < 500 {
                        endpoints.push(JsEndpoint {
                            url: source_url.to_owned(),
                            endpoint,
                            source: "js-analysis".into(),
                        });
                    }
                }
            }
        }
    }

    endpoints.sort();
    endpoints.dedup();
    endpoints
}

/// Detects potential secrets/keys in JS content.
pub fn find_secrets(js_content: &str, source_url: &str) -> Vec<JsSecret> {
    let mut secrets = Vec::new();

    let patterns: Vec<(&str, &str)> = vec![
        (r#"AKIA[0-9A-Z]{16}"#, "AWS Access Key"),
        (r#"["']AIza[0-9A-Za-z_-]{35}["']"#, "Google API Key"),
        (r#"sk_live_[0-9a-zA-Z]+"#, "Stripe Live Secret"),
        (r#"sk_test_[0-9a-zA-Z]+"#, "Stripe Test Secret"),
        (r#"pk_live_[0-9a-zA-Z]+"#, "Stripe Live Publishable"),
        (r#"pk_test_[0-9a-zA-Z]+"#, "Stripe Test Publishable"),
        (r#"github_pat_[0-9a-zA-Z_]+"#, "GitHub PAT"),
        (r#"ghp_[0-9a-zA-Z]{36}"#, "GitHub Token"),
        (r#"gho_[0-9a-zA-Z]{36}"#, "GitHub OAuth"),
        (r#"xox[baprs]-[0-9a-zA-Z-]+"#, "Slack Token"),
        (r#"xapp-[0-9a-zA-Z-]+"#, "Slack App Token"),
        (r#"ya29\.[0-9a-zA-Z_-]+"#, "Google OAuth"),
        (r#"EAACEdEose0cBA[0-9a-zA-Z]+"#, "Facebook Access Token"),
        (r#"key-[0-9a-zA-Z]{32}"#, "API Key"),
        (r#"-----BEGIN (RSA |EC )?PRIVATE KEY-----"#, "Private Key"),
        (r#"mongodb(?:\+srv)?://[^\s"']+"#, "MongoDB URI"),
        (r#"postgresql://[^\s"']+"#, "PostgreSQL URI"),
        (r#"mysql://[^\s"']+"#, "MySQL URI"),
        (r#"redis://[^\s"']+"#, "Redis URI"),
        (r#"https://hooks\.slack\.com/[a-zA-Z0-9/]+"#, "Slack Webhook"),
        (r#"https://[^@]+:[^@]+@[^\s"']+"#, "URL with credentials"),
    ];

    for (pattern, secret_type) in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.find_iter(js_content) {
                secrets.push(JsSecret {
                    url: source_url.to_owned(),
                    secret_type: secret_type.to_string(),
                    context: cap.as_str().chars().take(100).collect(),
                });
            }
        }
    }

    secrets.sort();
    secrets.dedup();
    secrets
}

/// Converts JS analysis results to findings.
pub fn endpoints_to_findings(
    endpoints: &[JsEndpoint],
    asset: &AssetRef,
) -> Vec<Finding> {
    if endpoints.is_empty() {
        return Vec::new();
    }

    let mut finding = Finding::new(
        "API endpoints discovered via JS analysis".to_string(),
        asset.clone(),
        Severity::Info,
        Confidence::Possible,
        "grym-recon-passive",
    );
    for ep in endpoints.iter().take(20) {
        finding.evidence.push(Evidence::redacted(
            "js-endpoint",
            format!("Endpoint: {}", ep.endpoint),
            &ep.endpoint,
        ));
    }
    finding.remediation = "Review exposed endpoints for sensitive functionality without authentication.".into();
    finding.references.push("https://owasp.org/www-project-web-security-testing-guide/".into());
    vec![finding]
}

pub fn secrets_to_findings(
    secrets: &[JsSecret],
    asset: &AssetRef,
) -> Vec<Finding> {
    if secrets.is_empty() {
        return Vec::new();
    }

    let types: Vec<&str> = secrets.iter().map(|s| s.secret_type.as_str()).collect();
    let mut finding = Finding::new(
        format!("Hardcoded secrets found in JS: {}", types.join(", ")),
        asset.clone(),
        Severity::High,
        Confidence::Confirmed,
        "grym-recon-passive",
    );
    for secret in secrets.iter().take(10) {
        finding.evidence.push(Evidence::redacted(
            "js-secret",
            format!("{}: {}", secret.secret_type, secret.context),
            &secret.context,
        ));
    }
    finding.remediation = "Remove hardcoded secrets from client-side code. Use environment variables or a secrets manager.".into();
    finding.cwe_ids.push(798);
    finding.references.push("https://cwe.mitre.org/data/definitions/798.html".into());
    vec![finding]
}
