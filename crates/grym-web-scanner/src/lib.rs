#![deny(unsafe_code)]

use grym_core::{Finding, ScopedClient, ScopedClientError, TechniqueTier};
use grym_template_engine::{DetectionTemplate, TemplateError};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum WebScanError {
    #[error(transparent)]
    Transport(#[from] ScopedClientError),
    #[error(transparent)]
    Template(#[from] TemplateError),
    #[error("URL error: {0}")]
    Url(#[from] url::ParseError),
}

pub async fn scan_template(
    client: &ScopedClient,
    url: Url,
    template: &DetectionTemplate,
) -> Result<Option<Finding>, WebScanError> {
    let response = client
        .get("grym-web-scanner", url, TechniqueTier::StandardDetection)
        .await?;
    if template.matches(&response)? {
        return Ok(Some(template.to_finding(&response, "grym-web-scanner")));
    }
    Ok(None)
}

macro_rules! try_scan {
    ($client:expr, $url:expr, $mod:ident, $fn:ident) => {
        if let Ok(mut sub) = $mod::$fn($client, $url).await {
            sub
        } else {
            Vec::new()
        }
    };
}

pub async fn scan_all_vulns(client: &ScopedClient, url: &Url) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.append(&mut try_scan!(client, url, sqli, check_sqli));
    findings.append(&mut try_scan!(client, url, xss, check_xss));
    findings.append(&mut try_scan!(client, url, ssti, check_ssti));
    findings.append(&mut try_scan!(client, url, jwt, check_jwt_config));
    findings.append(&mut try_scan!(client, url, cors, check_cors));
    findings.append(&mut try_scan!(client, url, ssrf, check_ssrf));
    findings.append(&mut try_scan!(
        client,
        url,
        command_injection,
        check_command_injection
    ));
    findings.append(&mut try_scan!(
        client,
        url,
        path_traversal,
        check_path_traversal
    ));
    findings.append(&mut try_scan!(
        client,
        url,
        open_redirect,
        check_open_redirect
    ));
    findings.append(&mut try_scan!(client, url, idor, check_idor));
    findings.append(&mut try_scan!(client, url, waf_detect, detect_waf));
    findings.append(&mut try_scan!(
        client,
        url,
        http_smuggling,
        check_http_smuggling
    ));
    findings.append(&mut try_scan!(client, url, xxe, check_xxe));
    findings.append(&mut try_scan!(client, url, csrf, check_csrf));
    findings.append(&mut try_scan!(client, url, graphql, check_graphql));
    findings.append(&mut try_scan!(
        client,
        url,
        tech_fingerprint,
        fingerprint_tech
    ));
    findings.append(&mut try_scan!(
        client,
        url,
        host_header,
        check_host_header_injection
    ));
    findings.append(&mut try_scan!(client, url, nosqli, check_nosqli));
    findings.append(&mut try_scan!(client, url, fuzzer, fuzz_all));
    findings.append(&mut try_scan!(
        client,
        url,
        chain_builder,
        build_chains_from_findings
    ));
    findings
}

pub mod chain_builder;
pub mod checklist;
pub mod command_injection;
pub mod cors;
pub mod csrf;
pub mod cve_db;
pub mod exploit_gen;
pub mod fuzzer;
pub mod graphql;
pub mod host_header;
pub mod http_smuggling;
pub mod idor;
pub mod jwt;
pub mod nosqli;
pub mod open_redirect;
pub mod path_traversal;
pub mod payload_gen;
pub mod plan;
pub mod playbook;
pub mod sqli;
pub mod ssrf;
pub mod ssti;
pub mod tech_fingerprint;
pub mod waf_detect;
pub mod xss;
pub mod xxe;
