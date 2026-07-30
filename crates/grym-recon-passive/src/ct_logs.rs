//! Certificate Transparency log-based subdomain discovery.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A subdomain discovered from CT logs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CtLogEntry {
    pub domain: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
}

/// CT log query errors.
#[derive(Debug, Error)]
pub enum CtLogError {
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("Parse error: {0}")]
    Parse(String),
}

/// Queries crt.sh Certificate Transparency log for subdomains of a domain.
pub async fn query_crtsh(domain: &str) -> Result<Vec<String>, CtLogError> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);

    let client = reqwest::Client::builder()
        .user_agent("grym-recon-passive/0.1 (authorized-security-assessment)")
        .build()
        .map_err(|e| CtLogError::Http(e.to_string()))?;

    let response = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| CtLogError::Http(e.to_string()))?;

    let text = response
        .text()
        .await
        .map_err(|e| CtLogError::Parse(e.to_string()))?;

    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&text).map_err(|e| CtLogError::Parse(e.to_string()))?;

    let mut subdomains = Vec::new();
    for entry in &entries {
        if let Some(name_value) = entry.get("name_value").and_then(|v| v.as_str()) {
            for name in name_value.split('\n') {
                let name = name.trim().trim_start_matches("*.");
                if !name.is_empty() && !subdomains.contains(&name.to_lowercase()) {
                    subdomains.push(name.to_lowercase());
                }
            }
        }
    }

    if subdomains.is_empty() {
        return Err(CtLogError::Parse("No certificates found for domain".into()));
    }

    subdomains.sort();
    subdomains.dedup();
    Ok(subdomains)
}

/// Heuristic-based subdomain permutations for a given domain.
pub fn generate_subdomain_permutations(domain: &str) -> Vec<String> {
    let prefixes = [
        "www",
        "mail",
        "remote",
        "blog",
        "webmail",
        "server",
        "ns1",
        "ns2",
        "smtp",
        "secure",
        "vpn",
        "admin",
        "cdn",
        "api",
        "dev",
        "staging",
        "test",
        "portal",
        "app",
        "m",
        "mobile",
        "beta",
        "demo",
        "shop",
        "support",
        "help",
        "docs",
        "dashboard",
        "monitor",
        "backup",
        "git",
        "jenkins",
        "jira",
        "confluence",
        "wiki",
        "status",
        "static",
        "assets",
        "img",
        "css",
        "js",
        "media",
        "download",
        "downloads",
        "ftp",
        "ssh",
        "mysql",
        "db",
        "database",
        "redis",
        "cache",
        "proxy",
        "gateway",
        "router",
        "firewall",
        "auth",
        "login",
        "register",
        "signup",
        "signin",
        "logout",
        "account",
        "pay",
        "payment",
        "checkout",
        "cart",
        "orders",
        "invoice",
        "track",
        "tracking",
        "chat",
        "livechat",
        "talk",
        "phone",
        "video",
        "conf",
        "meet",
        "calendar",
        "clock",
        "time",
        "upload",
        "files",
        "cloud",
        "sync",
        "data",
        "analytics",
        "metrics",
        "logs",
        "report",
        "reports",
        "search",
        "index",
        "sitemap",
        "robots",
        "crossdomain",
        "clientaccesspolicy",
        "soap",
        "ws",
        "xmlrpc",
        "graphql",
        "rest",
        "api/v1",
        "api/v2",
        "v1",
        "v2",
        "stage",
        "prod",
        "production",
        "development",
        "release",
        "nightly",
        "build",
        "ci",
        "cd",
        "deploy",
        "internal",
        "external",
        "public",
        "private",
        "corp",
        "partner",
        "partners",
        "vendor",
        "vendors",
        "reseller",
        "wholesale",
        "retail",
        "store",
        "billing",
        "subscribe",
        "newsletter",
        "news",
        "info",
        "about",
        "contact",
        "feedback",
        "survey",
        "polls",
        "jobs",
        "careers",
        "hr",
        "intranet",
        "ldap",
        "radius",
        "vpn",
        "rdp",
        "telnet",
        "tftp",
        "sip",
        "voip",
        "fax",
        "printer",
        "print",
        "scan",
        "nagios",
        "zabbix",
        "grafana",
        "prometheus",
        "kibana",
        "elastic",
        "elasticsearch",
        "logstash",
        "solr",
        "splunk",
        "kafka",
        "rabbitmq",
        "activemq",
        "artemis",
        "mq",
        "registry",
        "docker",
        "k8s",
        "kubernetes",
        "istio",
        "terraform",
        "puppet",
        "chef",
        "ansible",
        "salt",
        "nexus",
        "artifactory",
        "maven",
        "npm",
        "pypi",
        "sonar",
        "sonarqube",
        "codeclimate",
        "coveralls",
    ];

    let domain = domain.trim_start_matches("*. ").trim_start_matches("*.");
    prefixes
        .iter()
        .map(|p| format!("{}.{}", p, domain))
        .collect()
}
