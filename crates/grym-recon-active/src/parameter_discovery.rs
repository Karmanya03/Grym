//! Parameter discovery by diffing responses across injected parameter names.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use serde::{Deserialize, Serialize};
use url::Url;

/// Common parameter names for discovery.
pub fn common_parameters() -> Vec<&'static str> {
    vec![
        "id",
        "page",
        "user",
        "username",
        "email",
        "password",
        "token",
        "api_key",
        "key",
        "secret",
        "auth",
        "session",
        "debug",
        "admin",
        "test",
        "file",
        "path",
        "action",
        "cmd",
        "command",
        "exec",
        "run",
        "q",
        "query",
        "search",
        "filter",
        "sort",
        "order",
        "limit",
        "offset",
        "pageSize",
        "callback",
        "redirect",
        "return",
        "next",
        "url",
        "link",
        "type",
        "mode",
        "method",
        "lang",
        "locale",
        "format",
        "view",
        "template",
        "theme",
        "style",
        "version",
        "signature",
        "hash",
        "checksum",
        "hmac",
        "access_token",
        "refresh_token",
        "code",
        "state",
        "nonce",
        "scope",
        "grant_type",
        "client_id",
        "client_secret",
        "redirect_uri",
        "response_type",
        "assertion",
        "bearer",
    ]
}

/// Result of a parameter discovery probe.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParameterResult {
    pub parameter: String,
    pub url: String,
    pub status: u16,
    pub content_length: usize,
    pub response_diff: bool,
}

/// Discovers valid parameters by injecting common param names and checking response changes.
pub async fn discover_parameters(
    client: &ScopedClient,
    target_url: &Url,
    params: &[&str],
) -> Result<Vec<ParameterResult>, ScopedClientError> {
    let base_response = client
        .get(
            "grym-recon-active",
            target_url.clone(),
            TechniqueTier::SafeActive,
        )
        .await?;
    let base_length = base_response.body.len();
    let base_status = base_response.status;

    let mut results = Vec::new();

    for param in params {
        let mut url = target_url.clone();
        url.query_pairs_mut().append_pair(param, "1");

        if let Ok(response) = client
            .get("grym-recon-active", url, TechniqueTier::SafeActive)
            .await
        {
            let len_diff = (response.body.len() as isize - base_length as isize).abs();
            let status_diff = response.status != base_status;
            let significant_diff = len_diff > 50 || status_diff;

            if significant_diff {
                results.push(ParameterResult {
                    parameter: param.to_string(),
                    url: response.url.clone(),
                    status: response.status,
                    content_length: response.body.len(),
                    response_diff: true,
                });
            }
        }
    }

    Ok(results)
}

/// Generates findings from discovered parameters.
pub fn parameter_results_to_findings(results: &[ParameterResult]) -> Vec<Finding> {
    if results.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for param in results {
        let mut finding = Finding::new(
            format!(
                "Valid parameter discovered: {} on {}",
                param.parameter, param.url
            ),
            AssetRef {
                identifier: param.url.clone(),
                kind: "web".into(),
            },
            Severity::Info,
            Confidence::Likely,
            "grym-recon-active",
        );
        finding.categories.push("Parameter Discovery".into());
        finding.evidence.push(Evidence::redacted(
            "parameter-discovery",
            format!(
                "Parameter {} changes response (HTTP {} vs base, size {})",
                param.parameter, param.status, param.content_length
            ),
            format!(
                "{}?{}={} -> Status {}, Size {}",
                param.url, param.parameter, 1, param.status, param.content_length
            ),
        ));
        finding.remediation = "Review parameter handling for injection vulnerabilities.".into();
        findings.push(finding);
    }

    findings
}
