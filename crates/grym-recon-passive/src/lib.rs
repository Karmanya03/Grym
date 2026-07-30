#![deny(unsafe_code)]

mod ct_logs;
mod dns;
mod favicon;
mod js_analysis;
mod subdomains;

pub use ct_logs::*;
pub use dns::*;
pub use favicon::*;
pub use js_analysis::*;
pub use subdomains::*;

use grym_core::{AssetRef, Confidence, Evidence, Finding, HttpResponseSnapshot, Severity};
use serde::{Deserialize, Serialize};

/// One technology signal derived from passive analysis.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TechnologyFingerprint {
    pub name: String,
    pub observed_value: String,
    pub source: String,
    pub version: Option<String>,
    pub cpe: Option<String>,
}

/// Extracts conservative technology signals from response headers.
#[allow(clippy::type_complexity)]
pub fn fingerprint_headers(response: &HttpResponseSnapshot) -> Vec<TechnologyFingerprint> {
    let mut signals = Vec::new();

    let header_checks: Vec<(
        &str,
        fn(&str) -> Option<(String, String, Option<String>, Option<String>)>,
    )> = vec![
        ("server", |v| {
            let parts: Vec<&str> = v.split(['/', ' ']).collect();
            let name = parts.first().unwrap_or(&"unknown").to_string();
            let version = parts.get(1).map(|s| s.to_string());
            let cpe = version
                .as_ref()
                .map(|ver| format!("cpe:2.3:a:{name}:{name}:{ver}:*:*:*:*:*:*:*"));
            Some((name, v.to_string(), version, cpe))
        }),
        ("x-powered-by", |v| {
            let parts: Vec<&str> = v.split(['/', ' ']).collect();
            let name = parts.first().unwrap_or(&"unknown").to_string();
            let version = parts.get(1).map(|s| s.to_string());
            Some((name, v.to_string(), version, None))
        }),
        ("x-aspnet-version", |v| {
            Some((
                "ASP.NET".into(),
                v.to_string(),
                Some(v.to_string()),
                Some(format!("cpe:2.3:a:microsoft:asp.net:{}:*:*:*:*:*:*:*", v)),
            ))
        }),
        ("x-generator", |v| {
            let name = v.split(['/', ' ']).next().unwrap_or("unknown").to_string();
            Some((name, v.to_string(), None, None))
        }),
        ("via", |v| {
            Some(("Proxy/Via".into(), v.to_string(), None, None))
        }),
        ("set-cookie", |v| {
            if v.to_lowercase().contains("asp.net") {
                Some(("ASP.NET".into(), v.to_string(), None, None))
            } else if v.to_lowercase().contains("phpsessid") {
                Some(("PHP".into(), v.to_string(), None, None))
            } else if v.to_lowercase().contains("jsessionid") {
                Some(("Java/J2EE".into(), v.to_string(), None, None))
            } else if v.to_lowercase().contains("rails") {
                Some(("Ruby on Rails".into(), v.to_string(), None, None))
            } else {
                None
            }
        }),
    ];

    for (header, extract) in header_checks {
        if let Some(value) = response.headers.get(header)
            && let Some((name, observed, version, cpe)) = extract(value)
        {
            signals.push(TechnologyFingerprint {
                name,
                observed_value: observed,
                source: (*header).to_string(),
                version,
                cpe,
            });
        }
    }

    signals
}

/// Generates findings from technology fingerprints for report correlation.
pub fn fingerprints_to_findings(
    fingerprints: &[TechnologyFingerprint],
    asset: &AssetRef,
) -> Vec<Finding> {
    fingerprints
        .iter()
        .map(|fp| {
            let mut finding = Finding::new(
                format!("Technology detected: {}", fp.name),
                asset.clone(),
                Severity::Info,
                Confidence::Possible,
                "grym-recon-passive",
            );
            finding.evidence.push(Evidence::redacted(
                "http-header",
                format!("{} header: {}", fp.source, fp.observed_value),
                &fp.observed_value,
            ));
            finding.remediation =
                format!("Ensure {} is up to date and properly configured.", fp.name);
            if let Some(ref ver) = fp.version {
                finding.references.push(format!("Version: {}", ver));
            }
            finding
        })
        .collect()
}
