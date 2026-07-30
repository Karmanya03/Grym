//! Virtual-host and subdomain brute-forcing via Host header manipulation.

use grym_core::{AssetRef, Confidence, Evidence, Finding, ScopedClient, Severity, TechniqueTier};
use serde::{Deserialize, Serialize};
use url::Url;

/// Result of a vhost probe.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VhostResult {
    pub hostname: String,
    pub status: u16,
    pub content_length: usize,
    pub title: Option<String>,
    pub different_from_base: bool,
}

/// Common vhost/subdomain wordlist.
pub fn common_vhosts() -> Vec<&'static str> {
    vec![
        "admin",
        "api",
        "app",
        "assets",
        "backup",
        "beta",
        "blog",
        "cdn",
        "chat",
        "cms",
        "config",
        "corp",
        "dashboard",
        "db",
        "dev",
        "docs",
        "download",
        "email",
        "exchange",
        "files",
        "forum",
        "ftp",
        "git",
        "help",
        "internal",
        "intranet",
        "jira",
        "kb",
        "ldap",
        "login",
        "mail",
        "mgt",
        "mobile",
        "monitor",
        "mx",
        "mysql",
        "ns1",
        "ns2",
        "partner",
        "partners",
        "phpmyadmin",
        "portal",
        "proxy",
        "qa",
        "redis",
        "remote",
        "report",
        "reports",
        "sap",
        "secure",
        "server",
        "service",
        "services",
        "shop",
        "smtp",
        "sql",
        "ssh",
        "stage",
        "staging",
        "static",
        "status",
        "support",
        "syslog",
        "test",
        "testing",
        "trac",
        "track",
        "upload",
        "vpn",
        "vps",
        "web",
        "webmail",
        "webservice",
        "wiki",
        "www",
        "www2",
    ]
}

/// Brute-forces virtual hosts by sending GET requests with modified Host headers.
pub async fn brute_force_vhosts(
    client: &ScopedClient,
    base_url: &Url,
    vhosts: &[&str],
) -> Vec<VhostResult> {
    let Ok(base_response) = client
        .get(
            "grym-recon-active",
            base_url.clone(),
            TechniqueTier::SafeActive,
        )
        .await
    else {
        return Vec::new();
    };
    let base_length = base_response.body.len();
    let base_status = base_response.status;

    let mut results = Vec::new();
    for vhost in vhosts {
        let mut url = base_url.clone();
        url.set_host(Some(vhost)).ok();
        let response = client
            .get("grym-recon-active", url, TechniqueTier::SafeActive)
            .await;

        if let Ok(resp) = response {
            let title = extract_title(&resp.body);
            let different = resp.status != base_status
                || (resp.body.len() as isize - base_length as isize).abs() > 100;

            results.push(VhostResult {
                hostname: vhost.to_string(),
                status: resp.status,
                content_length: resp.body.len(),
                title,
                different_from_base: different,
            });
        }
    }

    results
}

fn extract_title(body: &str) -> Option<String> {
    let re = regex::Regex::new(r#"<title>([^<]*)</title>"#).ok()?;
    re.captures(body)?
        .get(1)
        .map(|m| m.as_str().trim().to_string())
}

/// Generates findings from vhost results.
pub fn vhost_results_to_findings(results: &[VhostResult], base_url: &Url) -> Vec<Finding> {
    let interesting: Vec<&VhostResult> = results
        .iter()
        .filter(|r| r.different_from_base && r.status < 500)
        .collect();

    if interesting.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for vhost in interesting {
        let mut finding = Finding::new(
            format!(
                "Discovered virtual host: {} ({})",
                vhost.hostname,
                base_url.host_str().unwrap_or("unknown")
            ),
            AssetRef {
                identifier: format!("{} ({})", vhost.hostname, base_url),
                kind: "web".into(),
            },
            Severity::Low,
            Confidence::Likely,
            "grym-recon-active",
        );
        finding.categories.push("Active Reconnaissance".into());
        finding.evidence.push(Evidence::redacted(
            "vhost",
            format!(
                "Status: {}, Content-Length: {}, Title: {:?}",
                vhost.status, vhost.content_length, vhost.title
            ),
            format!(
                "{} -> Status {}, Length {}",
                vhost.hostname, vhost.status, vhost.content_length
            ),
        ));
        finding.references.push(base_url.to_string());
        findings.push(finding);
    }

    findings
}
