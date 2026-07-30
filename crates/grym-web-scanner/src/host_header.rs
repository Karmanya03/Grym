//! Host Header injection detection — query-based host override, X-Forwarded-Host,
//! Referer-based host injection, and absolute URL path injection.

use url::Url;
use grym_core::{Confidence, Finding, AssetRef, Severity, Evidence,
                ScopedClient, ScopedClientError, TechniqueTier};

const INJECTED_HOST: &str = "evil-host.invalid";

const HOST_OVERRIDE_PARAMS: &[&str] = &[
    "host",
    "x-forwarded-host",
    "x-forwarded-for",
    "x-host",
    "x-forwarded-proto",
    "_host",
    "__host",
    "hostname",
    "server",
    "server_name",
    "http_host",
    "request_host",
];

fn host_is_reflected(body: &str, headers: &std::collections::BTreeMap<String, String>, injected: &str) -> bool {
    if body.contains(injected) {
        return true;
    }
    if let Some(location) = headers.get("location") {
        if location.contains(injected) {
            return true;
        }
    }
    if let Some(server) = headers.get("server") {
        if server.contains(injected) {
            return true;
        }
    }
    false
}

fn body_links_contain_host(body: &str, injected: &str) -> bool {
    let patterns = [
        &format!("href=\"{}\"", injected),
        &format!("href='{}'", injected),
        &format!("src=\"{}\"", injected),
        &format!("src='{}'", injected),
        &format!("action=\"{}\"", injected),
        &format!("action='{}'", injected),
        &format!("http://{}", injected),
        &format!("https://{}", injected),
        &format!("//{}", injected),
    ];
    patterns.iter().any(|p| body.contains(p.as_str()))
}

pub async fn check_host_header_injection(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let baseline = client
        .get("grym-web-scanner", url.clone(), TechniqueTier::StandardDetection)
        .await?;

    for param in HOST_OVERRIDE_PARAMS {
        let mut test_url = url.clone();
        test_url.query_pairs_mut().append_pair(param, INJECTED_HOST);

        if let Ok(response) = client
            .get("grym-web-scanner", test_url, TechniqueTier::StandardDetection)
            .await
        {
            if host_is_reflected(&response.body, &response.headers, INJECTED_HOST)
                || body_links_contain_host(&response.body, INJECTED_HOST)
            {
                let detail = if response.headers.get("location").map_or(false, |l| l.contains(INJECTED_HOST)) {
                    "redirect-reflection"
                } else {
                    "body-reflection"
                };
                let mut finding = Finding::new(
                    format!("Host header injection via parameter '{}'", param),
                    AssetRef {
                        identifier: url.to_string(),
                        kind: "web".into(),
                    },
                    Severity::High,
                    Confidence::Confirmed,
                    "grym-web-scanner",
                );
                finding.categories.push("A01:2025-Broken-Access-Control".into());
                finding.cwe_ids.push(444);
                finding.cwe_ids.push(644);
                finding.evidence.push(Evidence::redacted(
                    detail,
                    format!("Injected host '{}' via parameter '{}' reflected in response", INJECTED_HOST, param),
                    format!("Parameter: {}, Injected: {}", param, INJECTED_HOST),
                ));
                finding.remediation = "Validate and sanitize the Host header server-side. Do not use the Host header, X-Forwarded-Host, or related headers to construct URLs or secrets without strict validation. Use a server-level allowlist of permitted hostnames.".into();
                finding.references.push("https://owasp.org/www-community/attacks/Host_Header_Injection".into());
                findings.push(finding);
                break;
            }
        }
    }

    if findings.is_empty() {
        let mut abs_url = url.clone();
        let path = format!("//{}{}", INJECTED_HOST, abs_url.path());
        abs_url.set_path(&path);

        if let Ok(response) = client
            .get("grym-web-scanner", abs_url, TechniqueTier::StandardDetection)
            .await
        {
            if host_is_reflected(&response.body, &response.headers, INJECTED_HOST)
                || body_links_contain_host(&response.body, INJECTED_HOST)
            {
                let mut finding = Finding::new(
                    "Host header injection via absolute URL path".to_string(),
                    AssetRef {
                        identifier: url.to_string(),
                        kind: "web".into(),
                    },
                    Severity::High,
                    Confidence::Confirmed,
                    "grym-web-scanner",
                );
                finding.categories.push("A01:2025-Broken-Access-Control".into());
                finding.cwe_ids.push(444);
                finding.cwe_ids.push(644);
                finding.evidence.push(Evidence::redacted(
                    "absolute-url-path",
                    format!("Absolute URL path '//{}/' reflected in response", INJECTED_HOST),
                    format!("Path: //{}/", INJECTED_HOST),
                ));
                finding.remediation = "Do not trust the path portion of the URL for host determination. Use the actual Host header validated against an allowlist.".into();
                finding.references.push("https://owasp.org/www-community/attacks/Host_Header_Injection".into());
                findings.push(finding);
            }
        }
    }

    if findings.is_empty() && baseline.status >= 200 && baseline.status < 300 {
        let mut ref_url = url.clone();
        ref_url.query_pairs_mut().append_pair("referer", &format!("https://{}/", INJECTED_HOST));
        ref_url.query_pairs_mut().append_pair("referrer", &format!("https://{}/", INJECTED_HOST));

        if let Ok(response) = client
            .get("grym-web-scanner", ref_url, TechniqueTier::StandardDetection)
            .await
        {
            if host_is_reflected(&response.body, &response.headers, INJECTED_HOST)
                || body_links_contain_host(&response.body, INJECTED_HOST)
            {
                let mut finding = Finding::new(
                    "Host header injection via Referer parameter".to_string(),
                    AssetRef {
                        identifier: url.to_string(),
                        kind: "web".into(),
                    },
                    Severity::High,
                    Confidence::Likely,
                    "grym-web-scanner",
                );
                finding.categories.push("A01:2025-Broken-Access-Control".into());
                finding.cwe_ids.push(444);
                finding.cwe_ids.push(644);
                finding.evidence.push(Evidence::redacted(
                    "referer-injection",
                    format!("Referer override with '{}' reflected in response", INJECTED_HOST),
                    format!("Params: referer/referrer=https://{}/", INJECTED_HOST),
                ));
                finding.remediation = "Validate Referer headers server-side and do not use them for host resolution. Use an allowlist approach for hostnames.".into();
                finding.references.push("https://owasp.org/www-community/attacks/Host_Header_Injection".into());
                findings.push(finding);
            }
        }
    }

    if baseline.status >= 200 && baseline.status < 300 {
        let hostname = url.host_str().unwrap_or("");
        if baseline.body.contains(hostname) || baseline.headers.get("location").map_or(false, |l| l.contains(hostname)) {
            let mut finding = Finding::new(
                "Host reflection in baseline response (cache poisoning indicator)".to_string(),
                AssetRef {
                    identifier: url.to_string(),
                    kind: "web".into(),
                },
                Severity::Low,
                Confidence::Possible,
                "grym-web-scanner",
            );
            finding.categories.push("A07:2025-Identification-and-Authentication-Failures".into());
            finding.cwe_ids.push(644);
            finding.evidence.push(Evidence::redacted(
                "host-reflection",
                format!("Hostname '{}' reflected in response without injection", hostname),
                format!("Host: {}", hostname),
            ));
            finding.remediation = "If the hostname is reflected in CSRF tokens, password reset links, or caching keys the application is vulnerable to cache poisoning and host header injection.".into();
            finding.references.push("https://owasp.org/www-community/attacks/Cache_Poisoning".into());
            findings.push(finding);
        }
    }

    if findings.is_empty() {
        for prefix in &["password-reset", "forgot-password", "reset", "confirm"] {
            let mut pw_url = url.clone();
            let path = format!("/{}/{}", prefix, INJECTED_HOST);
            pw_url.set_path(&path);
            if let Ok(response) = client
                .get("grym-web-scanner", pw_url, TechniqueTier::StandardDetection)
                .await
            {
                if host_is_reflected(&response.body, &response.headers, INJECTED_HOST) {
                    let mut finding = Finding::new(
                        "Password reset poisoning — host injection in reset endpoint".to_string(),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::Critical,
                        Confidence::Likely,
                        "grym-web-scanner",
                    );
                    finding.categories.push("A01:2025-Broken-Access-Control".into());
                    finding.cwe_ids.push(640);
                    finding.evidence.push(Evidence::redacted(
                        "password-reset-poisoning",
                        format!("Injected host '{}' reflected in password reset endpoint", INJECTED_HOST),
                        format!("Path: /{}/{}", prefix, INJECTED_HOST),
                    ));
                    finding.remediation = "Do not include the Host header in password reset email links. Generate reset links using a server-side base URL configuration, not the incoming Host header.".into();
                    finding.references.push("https://owasp.org/www-community/attacks/Password_Reset_Poisoning".into());
                    findings.push(finding);
                    break;
                }
            }
        }
    }

    Ok(findings)
}
