//! Open Redirect detection.

use grym_core::{
    AssetRef, Confidence, Evidence, Finding, ScopedClient, ScopedClientError, Severity,
    TechniqueTier,
};
use url::Url;

pub async fn check_open_redirect(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let redirect_params = [
        "url",
        "redirect",
        "redirect_uri",
        "return",
        "return_to",
        "return_url",
        "next",
        "next_url",
        "continue",
        "dest",
        "destination",
        "goto",
        "target",
        "link",
        "href",
        "out",
        "view",
        "page",
        "site",
        "path",
        "to",
    ];

    let test_urls = [
        "https://evil.com",
        "http://evil.com",
        "//evil.com",
        "https://attacker.net",
        "///evil.com",
        "https://evil.com/redirect",
    ];

    let base_query: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    for (param_name, _value) in &base_query {
        if !redirect_params.contains(&param_name.as_str().to_lowercase().as_str()) {
            continue;
        }

        for target in &test_urls {
            let mut test_url = url.clone();
            {
                let mut pairs = test_url.query_pairs_mut();
                pairs.clear();
                for (k, v) in &base_query {
                    let val = if k == param_name {
                        target.to_string()
                    } else {
                        v.clone()
                    };
                    pairs.append_pair(k, &val);
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
                let is_redirect = response.status >= 300 && response.status < 310;
                let location = response
                    .headers
                    .get("location")
                    .map(|v| v.to_string())
                    .unwrap_or_default();

                if is_redirect
                    && (location.contains(target.trim_start_matches("//"))
                        || location.contains("evil.com")
                        || location.contains("attacker.net"))
                {
                    let mut finding = Finding::new(
                        format!(
                            "Open Redirect in parameter '{}' (redirects to {})",
                            param_name, target
                        ),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::Medium,
                        Confidence::Confirmed,
                        "grym-web-scanner",
                    );
                    finding
                        .categories
                        .push("A01:2025-Broken-Access-Control".into());
                    finding.cwe_ids.push(601);
                    finding.evidence.push(Evidence::redacted(
                        "open-redirect",
                        format!(
                            "Parameter: {}, Target: {}, Location: {}",
                            param_name, target, location
                        ),
                        format!("Status: {}, Location: {}", response.status, location),
                    ));
                    finding.remediation = "Do not redirect to URLs based on user-controlled input. Use an allowlist of approved redirect destinations.".into();
                    finding
                        .references
                        .push("https://owasp.org/www-community/attacks/Open_redirect".into());
                    findings.push(finding);
                }
            }
        }
    }

    Ok(findings)
}
