//! CORS misconfiguration detection.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use url::Url;

pub async fn check_cors(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let test_origins = vec![
        "https://evil.com",
        "null",
        "https://attacker.com",
        "https://evil.",
        "https://example.com",
    ];

    for origin in &test_origins {
        let Ok(response) = client
            .get(
                "grym-web-scanner",
                url.clone(),
                TechniqueTier::StandardDetection,
            )
            .await
        else {
            continue;
        };

        let acao = response.headers.get("access-control-allow-origin");
        let acac = response.headers.get("access-control-allow-credentials");

        let acao_str = acao.map(|s| s.as_str());
        let acac_str = acac.map(|s| s.as_str());

        let origin_matches = match acao_str {
            Some(v) => v == "*" || v == *origin || v == "null",
            None => false,
        };

        if origin_matches {
            let mut finding = Finding::new(
                format!(
                    "CORS misconfiguration: ACAO set to '{}' for origin '{}'",
                    acao_str.unwrap_or("?"),
                    origin
                ),
                AssetRef {
                    identifier: url.to_string(),
                    kind: "web".into(),
                },
                if acac.is_some() {
                    Severity::High
                } else {
                    Severity::Medium
                },
                Confidence::Confirmed,
                "grym-web-scanner",
            );
            finding
                .categories
                .push("A01:2025-Broken-Access-Control".into());
            finding.cwe_ids.push(942);
            finding.evidence.push(Evidence::redacted(
                "cors-header",
                format!(
                    "ACAO: {:?}, ACAC: {:?}, Origin: {}",
                    acao_str, acac_str, origin
                ),
                format!(
                    "ACAO: {} | ACAC: {} | Origin: {}",
                    acao_str.unwrap_or("none"),
                    acac_str.unwrap_or("none"),
                    origin
                ),
            ));
            finding.remediation = "Restrict Access-Control-Allow-Origin to specific trusted origins. Avoid using '*' or reflecting the Origin header without validation.".into();
            finding
                .references
                .push("https://owasp.org/www-community/attacks/CORS_Attack".into());
            findings.push(finding);
        }
    }

    Ok(findings)
}
