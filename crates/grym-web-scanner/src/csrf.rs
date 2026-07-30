use grym_core::{Confidence, Evidence, Finding, AssetRef, ScopedClient, ScopedClientError, Severity, TechniqueTier};

const CSRF_HEADERS: &[&str] = &[
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
    "xsrf-token",
    "x-csrftoken",
    "xsrf-token-value",
    "csrf-token-value",
    "anti-csrf-token",
    "x-anti-csrf-token",
    "x-requested-by",
];

const WEAK_CSRF_PATTERNS: &[&str] = &[
    r"(?i)\b(token|csrf|xsrf)\s*=\s*[a-z0-9]{1,8}\b",
    r#"(?i)\b(csrf|xsrf)_(token|value)\s*[:=]\s*["\'][^"']{1,8}["\']"#,
    r#"(?i)\bcsrf\w*\s*=\s*["\']?\d{1,6}["\']?"#,
];

fn has_anti_csrf_headers(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, _)| {
        let lower = name.to_lowercase();
        CSRF_HEADERS.iter().any(|h| lower == *h)
    })
}

fn find_weak_csrf_tokens(body: &str) -> Vec<String> {
    let mut weak = Vec::new();
    for pattern in WEAK_CSRF_PATTERNS {
        if let Ok(re) = regex::Regex::new(pattern) {
            for cap in re.find_iter(body) {
                weak.push(cap.as_str().to_string());
            }
        }
    }
    weak
}

fn extract_forms(body: &str) -> Vec<(usize, String)> {
    let mut forms = Vec::new();
    let lower = body.to_lowercase();
    let mut pos = 0;
    while let Some(start) = lower[pos..].find("<form") {
        let abs_start = pos + start;
        if let Some(end) = lower[abs_start..].find("</form>") {
            let abs_end = abs_start + end + 7;
            forms.push((abs_start, body[abs_start..abs_end].to_string()));
            pos = abs_end;
        } else {
            break;
        }
    }
    forms
}

fn form_has_csrf_protection(form_body: &str) -> bool {
    let lower = form_body.to_lowercase();
    let Ok(hidden_input_re) = regex::Regex::new(r#"<input[^>]*type\s*=\s*["']?hidden["']?[^>]*>"#) else { return false };
    for cap in hidden_input_re.find_iter(&lower) {
        let input = cap.as_str();
        if CSRF_HEADERS.iter().any(|h| {
            let attr = h.replace('-', "_");
            input.contains(h) || input.contains(&attr)
        }) {
            return true;
        }
    }
    if lower.contains("csrf") || lower.contains("xsrf") {
        return true;
    }
    false
}

fn check_cookie_attributes(response_headers: &[(String, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (name, value) in response_headers {
        if name.to_lowercase() != "set-cookie" {
            continue;
        }
        let lower = value.to_lowercase();

        if lower.contains("samesite=none") {
            let mut f = Finding::new(
                "Cookie with SameSite=None — CSRF exposure risk",
                AssetRef { identifier: String::new(), kind: "web".into() },
                Severity::Medium, Confidence::Confirmed, "grym-web-scanner",
            );
            f.categories.push("A01:2025-Broken-Access-Control".into());
            f.cwe_ids.push(352);
            f.evidence.push(Evidence::redacted(
                "cookie", format!("SameSite=None cookie: {}", value), String::new(),
            ));
            f.remediation = "Set SameSite=Lax or SameSite=Strict on session cookies. \
                Avoid SameSite=None unless cross-site usage is explicitly required.".into();
            f.references.push("https://owasp.org/www-community/attacks/csrf".into());
            findings.push(f);
        }

        if !lower.contains("samesite") {
            let mut f = Finding::new(
                "Missing SameSite cookie attribute",
                AssetRef { identifier: String::new(), kind: "web".into() },
                Severity::Low, Confidence::Possible, "grym-web-scanner",
            );
            f.categories.push("A01:2025-Broken-Access-Control".into());
            f.cwe_ids.push(352);
            f.evidence.push(Evidence::redacted(
                "cookie", format!("No SameSite attribute on cookie: {}", value), String::new(),
            ));
            f.remediation = "Set SameSite=Lax or SameSite=Strict on session cookies.".into();
            f.references.push("https://owasp.org/www-community/attacks/csrf".into());
            findings.push(f);
        }
    }

    findings
}

pub async fn check_csrf(
    client: &ScopedClient,
    url: &url::Url,
) -> Result<Vec<Finding>, ScopedClientError> {
    let mut findings = Vec::new();

    let response = client
        .get("grym-web-scanner", url.clone(), TechniqueTier::StandardDetection)
        .await?;

    let body = &response.body;
    let headers: Vec<(String, String)> = response.headers.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    if !has_anti_csrf_headers(&headers) {
        let mut f = Finding::new(
            "No anti-CSRF headers found in response",
            AssetRef { identifier: url.to_string(), kind: "web".into() },
            Severity::Medium, Confidence::Possible, "grym-web-scanner",
        );
        f.categories.push("A01:2025-Broken-Access-Control".into());
        f.cwe_ids.push(352);
        f.evidence.push(Evidence::redacted(
            "csrf-headers", "Response does not include common anti-CSRF headers", String::new(),
        ));
        f.remediation = "Implement anti-CSRF tokens using Synchronizer Token Pattern \
            or Double Submit Cookie Pattern. Include headers like X-CSRF-Token.".into();
        f.references.push("https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html".into());
        findings.push(f);
    }

    let forms = extract_forms(body);
    for (_pos, form_html) in &forms {
        if !form_has_csrf_protection(form_html) {
            let mut f = Finding::new(
                "Form without CSRF protection detected",
                AssetRef { identifier: url.to_string(), kind: "web".into() },
                Severity::High, Confidence::Confirmed, "grym-web-scanner",
            );
            f.categories.push("A01:2025-Broken-Access-Control".into());
            f.cwe_ids.push(352);
            f.evidence.push(Evidence::redacted(
                "csrf-form", "Form missing CSRF token hidden input",
                form_html.chars().take(300).collect::<String>(),
            ));
            f.remediation = "Add a unique, per-session CSRF token as a hidden form field \
                and validate it server-side on state-changing requests.".into();
            f.references.push("https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html".into());
            findings.push(f);
        }
    }

    let weak_tokens = find_weak_csrf_tokens(body);
    for token in &weak_tokens {
        let mut f = Finding::new(
            format!("Weak CSRF token pattern detected: {}", token),
            AssetRef { identifier: url.to_string(), kind: "web".into() },
            Severity::High, Confidence::Likely, "grym-web-scanner",
        );
        f.categories.push("A01:2025-Broken-Access-Control".into());
        f.cwe_ids.push(352);
        f.evidence.push(Evidence::redacted(
            "csrf-weak-token", "Token appears short, numeric, or predictable",
            token.clone(),
        ));
        f.remediation = "Generate CSRF tokens using a cryptographically secure random generator. \
            Tokens should be at least 128 bits (32 hex characters).".into();
        f.references.push("https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html".into());
        findings.push(f);
    }

    findings.extend(check_cookie_attributes(&headers));

    Ok(findings)
}
