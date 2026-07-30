#![deny(unsafe_code)]

mod crawler;
mod parameter_discovery;
mod port_scanner;
mod vhost;

pub use crawler::*;
pub use parameter_discovery::*;
pub use port_scanner::*;
pub use vhost::*;

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, HttpResponseSnapshot, ScopedClient, ScopedClientError,
    Severity, TechniqueTier,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Read-only probe result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProbeResult {
    pub url: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub has_server_banner: bool,
    pub response_time_ms: u64,
}

/// Combined recon error.
#[derive(Debug, Error)]
pub enum ReconError {
    #[error(transparent)]
    Transport(#[from] ScopedClientError),
    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("Port scan error: {0}")]
    PortScan(String),
    #[error("Crawl error: {0}")]
    Crawl(String),
}

/// Performs one read-only HTTP probe at SafeActive tier.
pub async fn probe(client: &ScopedClient, url: Url) -> Result<ProbeResult, ReconError> {
    let start = std::time::Instant::now();
    let response: HttpResponseSnapshot = client
        .get("grym-recon-active", url, TechniqueTier::SafeActive)
        .await?;
    let elapsed = start.elapsed().as_millis() as u64;

    Ok(ProbeResult {
        url: response.url,
        status: response.status,
        content_type: response.headers.get("content-type").cloned(),
        content_length: response
            .headers
            .get("content-length")
            .and_then(|v| v.parse().ok()),
        has_server_banner: response.headers.contains_key("server"),
        response_time_ms: elapsed,
    })
}

/// Generates findings from technology probes.
pub fn probe_to_finding(probe: &ProbeResult) -> Option<Finding> {
    if probe.has_server_banner {
        let mut finding = Finding::new(
            format!("Server banner detected at {}", probe.url),
            AssetRef {
                identifier: probe.url.clone(),
                kind: "web".into(),
            },
            Severity::Info,
            Confidence::Confirmed,
            "grym-recon-active",
        );
        finding.evidence.push(Evidence::redacted(
            "http-probe",
            format!(
                "Status: {}, Response time: {}ms",
                probe.status, probe.response_time_ms
            ),
            format!(
                "URL: {} | Status: {} | Time: {}ms",
                probe.url, probe.status, probe.response_time_ms
            ),
        ));
        Some(finding)
    } else {
        None
    }
}
