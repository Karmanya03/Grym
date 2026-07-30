//! HTTP Request Smuggling precondition detection via load balancer fingerprinting and header analysis.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use regex::Regex;
use url::Url;

/// Load balancer/proxy signatures that indicate potential smuggling vectors.
const LB_SIGNATURES: &[(&str, &str)] = &[
    (
        r"X-Forwarded-For",
        "Load balancer detected - potential CL.TE vector",
    ),
    (r"X-Forwarded-Host", "Load balancer/proxy routing detected"),
    (
        r"X-Forwarded-Proto",
        "Load balancer SSL termination detected",
    ),
    (r"X-Real-IP", "Nginx/load balancer routing detected"),
    (r"CF-Ray", "Cloudflare CDN in front"),
    (r"CF-Visitor", "Cloudflare CDN"),
    (r"CF-Cache-Status", "Cloudflare CDN"),
    (r"X-Akamai-Transformed", "Akamai CDN in front"),
    (r"Via", "Proxy/CDN layer detected"),
    (r"X-Cache", "Cache/proxy server detected"),
    (r"X-Served-By", "Application server routing"),
    (r"X-Cache-Hit", "Cache hit detected"),
    (r"X-Varnish", "Varnish caching proxy detected"),
    (r"Age", "Caching layer detected"),
    (r"X-Cache-Lookup", "Cache system detected"),
    (r"X-Cache-Date", "Cache timestamp present"),
    (
        r"X-HTTP-Method-Override",
        "Method override header - potential smuggling vector",
    ),
    (
        r"Access-Control-Request-Method",
        "CORS pre-flight - potential bypass vector",
    ),
];

/// Smuggling observation payloads injected via request path/params for edge-case behavior.
const SMUGGLING_PROBES: &[(&str, &str)] = &[
    ("/ HTTP/1.0\r\nHost: broken", "HTTP 1.0 path malformation"),
    ("//", "Double slash - neutral"),
    ("/./", "Dot segment"),
    ("/../", "Parent path segment"),
    ("/..;/", "IIS parent path"),
    ("/%2e%2e/", "URL-encoded parent path"),
    ("/%c0%ae%c0%ae/", "UTF-8 overlong parent path"),
    ("/%c0%af", "UTF-8 overlong slash"),
];

/// Duplicate header testing via query param name injection (URL-based simulation).
const DUPLICATE_HEADER_PARAMS: &[&str] = &[
    "Transfer-Encoding",
    "transfer_encoding",
    "TE",
    "Content-Length",
    "content_length",
    "CL",
];

pub async fn check_http_smuggling(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    // Phase 1: Passive header analysis for load balancer / proxy signatures
    let response = client
        .get("grym-web-scanner", url.clone(), TechniqueTier::SafeActive)
        .await?;

    let has_lb = LB_SIGNATURES.iter().any(|(pattern, _desc)| {
        for (header_name, header_value) in &response.headers {
            let combined = format!("{}: {}", header_name, header_value);
            if let Ok(re) = Regex::new(pattern)
                && re.is_match(&combined)
            {
                return true;
            }
        }
        false
    });

    if has_lb {
        for (pattern, description) in LB_SIGNATURES {
            for (header_name, header_value) in &response.headers {
                let combined = format!("{}: {}", header_name, header_value);
                if let Ok(re) = Regex::new(pattern)
                    && re.is_match(&combined)
                {
                    let mut f = Finding::new(
                        format!("HTTP Smuggling precondition: {}", description),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::Medium,
                        Confidence::Likely,
                        "grym-web-scanner",
                    );
                    f.categories.push("A05:2025-Injection".into());
                    f.cwe_ids.push(444);
                    f.evidence.push(Evidence::redacted(
                        "smuggling-lb",
                        format!("Header {} indicates load balancer layer", header_name),
                        combined,
                    ));
                    f.remediation =
                        "Configure the front-end and back-end to use a consistent parser for \
                             HTTP headers. Disable duplicate header forwarding."
                            .into();
                    f.references
                        .push("https://portswigger.net/web-security/request-smuggling".into());
                    findings.push(f);
                }
            }
        }
    }

    // Phase 2: Check for duplicate TE/CL handling via query parameter reflection
    let mut test_url = url.clone();
    {
        let mut pairs = test_url.query_pairs_mut();
        pairs.clear();
        for param in DUPLICATE_HEADER_PARAMS {
            pairs.append_pair(param, "chunked");
        }
    }

    if let Ok(response) = client
        .get(
            "grym-web-scanner",
            test_url,
            TechniqueTier::StandardDetection,
        )
        .await
        && (response.status == 200 || response.status == 400 || response.status == 500)
    {
        let body_lower = response.body.to_lowercase();
        if body_lower.contains("chunked") || body_lower.contains("transfer-encoding") {
            let mut f = Finding::new(
                "Duplicate Transfer-Encoding/Content-Length handling detected".to_string(),
                AssetRef {
                    identifier: url.to_string(),
                    kind: "web".into(),
                },
                Severity::High,
                Confidence::Possible,
                "grym-web-scanner",
            );
            f.categories.push("A05:2025-Injection".into());
            f.cwe_ids.push(444);
            f.evidence.push(Evidence::redacted(
                "smuggling-duplicate",
                "Server reflected TE/CL header names - potential smuggling vector",
                response.body.chars().take(200).collect::<String>(),
            ));
            f.remediation =
                "Ensure front-end and back-end servers agree on which header to honor. \
                     Reject requests with conflicting Transfer-Encoding and Content-Length headers."
                    .into();
            f.references
                .push("https://portswigger.net/web-security/request-smuggling".into());
            findings.push(f);
        }
    }

    // Phase 3: Edge-case path probing
    if response.status == 200 {
        for (path, description) in SMUGGLING_PROBES {
            let probed_url = url.join(path).ok();
            if let Some(probed) = probed_url
                && let Ok(probe_response) = client
                    .get("grym-web-scanner", probed, TechniqueTier::StandardDetection)
                    .await
            {
                if probe_response.status == 200 && path.contains("..") {
                    let mut f = Finding::new(
                        format!("Potential smuggling vector via path: {}", description),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::Low,
                        Confidence::Possible,
                        "grym-web-scanner",
                    );
                    f.categories.push("A05:2025-Injection".into());
                    f.cwe_ids.push(444);
                    f.evidence.push(Evidence::redacted(
                        "smuggling-path",
                        format!("Path '{}' returned HTTP {}", path, probe_response.status),
                        probe_response.body.chars().take(200).collect::<String>(),
                    ));
                    findings.push(f);
                }

                if probe_response.status == 400 {
                    // Some WAF/LB return 400 on malformed paths
                    let status_code = probe_response.status;
                    let path_entry = path.to_string();
                    let mut f = Finding::new(
                        format!(
                            "HTTP parsing edge case detected: {} (HTTP {})",
                            description, status_code
                        ),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::Low,
                        Confidence::Confirmed,
                        "grym-web-scanner",
                    );
                    f.categories.push("A05:2025-Injection".into());
                    f.cwe_ids.push(444);
                    f.evidence.push(Evidence::redacted(
                        "smuggling-parsing",
                        format!("Edge case '{}' triggered HTTP {}", path, status_code),
                        format!("Path: {}, Status: {}", path_entry, status_code),
                    ));
                    findings.push(f);
                }
            }
        }
    }

    // Phase 4: Verb tampering - test alternate methods via parameter injection
    let verb_params = ["method", "_method", "METHOD", "_METHOD"];
    for vp in &verb_params {
        let mut verb_url = url.clone();
        {
            let mut pairs = verb_url.query_pairs_mut();
            pairs.clear();
            pairs.append_pair(vp, "POST");
        }
        if let Ok(verb_resp) = client
            .get(
                "grym-web-scanner",
                verb_url,
                TechniqueTier::StandardDetection,
            )
            .await
            && verb_resp.status == 200
            && response.status != 200
        {
            let mut f = Finding::new(
                format!("HTTP method override allowed via '{}' parameter", vp),
                AssetRef {
                    identifier: url.to_string(),
                    kind: "web".into(),
                },
                Severity::Medium,
                Confidence::Confirmed,
                "grym-web-scanner",
            );
            f.categories.push("A01:2025-Broken-Access-Control".into());
            f.cwe_ids.push(650);
            f.evidence.push(Evidence::redacted(
                "http-method-override",
                format!(
                    "Parameter {} allowed method override (status: {})",
                    vp, verb_resp.status
                ),
                format!(
                    "Method override: {} -> POST, status: {}",
                    vp, verb_resp.status
                ),
            ));
            f.remediation =
                "Disable HTTP method override functionality unless absolutely necessary, \
                     and strictly validate allowed methods."
                    .into();
            f.references
                .push("https://owasp.org/www-project-web-security-testing-guide/".into());
            findings.push(f);
        }
    }

    Ok(findings)
}
