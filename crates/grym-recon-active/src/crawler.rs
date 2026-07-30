//! Basic web crawler for endpoint discovery.

use std::collections::{HashSet, VecDeque};

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

use grym_core::{Confidence, Finding, AssetRef, Severity, Evidence,
                ScopedClient, TechniqueTier};

/// Result from crawling a single page.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrawlResult {
    pub url: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub links: Vec<String>,
    pub forms: Vec<String>,
    pub scripts: Vec<String>,
    pub depth: u32,
}

/// Content discovery result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContentDiscoveryResult {
    pub url: String,
    pub status: u16,
    pub content_length: usize,
}

/// Common paths for content discovery.
pub fn common_paths() -> Vec<&'static str> {
    vec![
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/.env", "/.git/config", "/.gitignore", "/.htaccess",
        "/admin", "/admin/", "/administrator", "/backup",
        "/config", "/config/", "/config.php", "/config.json",
        "/db", "/debug", "/dump", "/error", "/errors",
        "/info.php", "/install", "/logs", "/log",
        "/phpinfo.php", "/phpmyadmin", "/pma",
        "/server-status", "/server-info",
        "/test", "/tests", "/tmp", "/temp",
        "/uploads", "/upload", "/static", "/assets",
        "/api", "/api/", "/api/v1", "/api/v2",
        "/graphql", "/swagger", "/swagger.json",
        "/swagger-ui", "/api-docs", "/openapi.json",
        "/health", "/healthz", "/metrics", "/status",
        "/actuator", "/actuator/health", "/actuator/info",
        "/.well-known/", "/.well-known/apple-app-site-association",
        "/.well-known/assetlinks.json",
    ]
}

/// Crawls a starting URL up to a maximum depth, extracting links, forms, and scripts.
pub async fn crawl(
    client: &ScopedClient,
    start_url: Url,
    max_depth: u32,
    max_pages: u32,
) -> Vec<CrawlResult> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(Url, u32)> = VecDeque::new();
    let mut results = Vec::new();

    let base_domain = start_url.host_str().unwrap_or_default().to_string();
    queue.push_back((start_url, 0));

    while let Some((url, depth)) = queue.pop_front() {
        if results.len() >= max_pages as usize {
            break;
        }
        if visited.contains(&url.to_string()) {
            continue;
        }
        visited.insert(url.to_string());

        let Ok(response) = client
            .get("grym-recon-active", url.clone(), TechniqueTier::SafeActive)
            .await
        else {
            continue;
        };

        let body = &response.body;
        let content_type = response.headers.get("content-type").cloned();

        let links = extract_links(body, &url, &base_domain);
        let forms = extract_forms(body);
        let scripts = extract_scripts(body);

        if depth < max_depth {
            for link in &links {
                if let Ok(parsed) = Url::parse(link)
                    && parsed.host_str() == Some(&base_domain) && !visited.contains(&parsed.to_string()) {
                        queue.push_back((parsed, depth + 1));
                    }
            }
        }

        results.push(CrawlResult {
            url: response.url.clone(),
            status: response.status,
            content_type,
            links,
            forms,
            scripts,
            depth,
        });
    }

    results
}

fn extract_links(body: &str, base: &Url, domain: &str) -> Vec<String> {
    let mut links = Vec::new();
    let patterns = [
        r#"href="([^"]+)""#,
        r#"href='([^']+)'"#,
        r#"src="([^"]+)""#,
        r#"src='([^']+)'"#,
        r#"action="([^"]+)""#,
        r#"action='([^']+)'"#,
    ];

    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(body) {
                if let Some(m) = cap.get(1) {
                    let raw = m.as_str();
                    if let Ok(absolute) = base.join(raw)
                        && absolute.host_str() == Some(domain) {
                            let url_str = absolute.to_string();
                            if !links.contains(&url_str) {
                                links.push(url_str);
                            }
                        }
                }
            }
        }
    }

    links
}

fn extract_forms(body: &str) -> Vec<String> {
    let mut forms = Vec::new();
    if let Ok(re) = Regex::new(r#"<form[^>]*action="([^"]*)""#) {
        for cap in re.captures_iter(body) {
            if let Some(m) = cap.get(1) {
                forms.push(m.as_str().to_string());
            }
        }
    }
    forms
}

fn extract_scripts(body: &str) -> Vec<String> {
    let mut scripts = Vec::new();
    if let Ok(re) = Regex::new(r#"<script[^>]*src="([^"]+)""#) {
        for cap in re.captures_iter(body) {
            if let Some(m) = cap.get(1) {
                let src = m.as_str();
                if !src.is_empty() && !scripts.contains(&src.to_string()) {
                    scripts.push(src.to_string());
                }
            }
        }
    }
    scripts
}

/// Performs content discovery on a base URL using common paths.
pub async fn discover_content(
    client: &ScopedClient,
    base_url: &Url,
    paths: &[&str],
) -> Vec<ContentDiscoveryResult> {
    let mut results = Vec::new();

    for path in paths {
        if let Ok(url) = base_url.join(path)
            && let Ok(response) = client
                .get("grym-recon-active", url.clone(), TechniqueTier::SafeActive)
                .await
                && (response.status < 400 || response.status == 401 || response.status == 403) {
                    results.push(ContentDiscoveryResult {
                        url: response.url.clone(),
                        status: response.status,
                        content_length: response.body.len(),
                    });
                }
    }

    results
}

/// Generates findings from crawled content.
pub fn crawl_results_to_findings(
    results: &[CrawlResult],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for page in results {
        if !page.forms.is_empty() {
            let mut finding = Finding::new(
                format!("Forms found on {}", page.url),
                AssetRef {
                    identifier: page.url.clone(),
                    kind: "web".into(),
                },
                Severity::Info,
                Confidence::Confirmed,
                "grym-recon-active",
            );
            finding.categories.push("Application Discovery".into());
            for form in &page.forms {
                finding.evidence.push(Evidence::redacted(
                    "form",
                    format!("Form action: {}", form),
                    form,
                ));
            }
            findings.push(finding);
        }
    }

    findings
}

/// Generates findings from content discovery.
pub fn content_discovery_to_findings(
    results: &[ContentDiscoveryResult],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for result in results {
        let severity = if result.status == 401 || result.status == 403 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let mut finding = Finding::new(
            format!("Exposed path: {} (HTTP {})", result.url, result.status),
            AssetRef {
                identifier: result.url.clone(),
                kind: "web".into(),
            },
            severity,
            Confidence::Confirmed,
            "grym-recon-active",
        );
        finding.categories.push("Content Discovery".into());
        finding.evidence.push(Evidence::redacted(
            "content-discovery",
            format!("Status: {}, Size: {}", result.status, result.content_length),
            format!("{} -> Status {}, Size {}", result.url, result.status, result.content_length),
        ));
        finding.remediation = "Ensure this path is properly authenticated or disabled if not needed publicly.".into();
        findings.push(finding);
    }

    findings
}
