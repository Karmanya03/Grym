//! Subdomain enumeration via multiple passive sources.

use crate::{ct_logs, dns};
use grym_core::{AssetRef, Confidence, Evidence, Finding, Severity};
use serde::{Deserialize, Serialize};

/// A discovered subdomain with metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubdomainResult {
    pub hostname: String,
    pub source: String,
    pub ips: Vec<String>,
}

/// Enumerates subdomains using multiple passive techniques.
pub async fn enumerate_subdomains(domain: &str) -> Vec<SubdomainResult> {
    let mut results = Vec::new();

    // CT log enumeration
    if let Ok(subdomains) = ct_logs::query_crtsh(domain).await {
        for sd in subdomains {
            let ips = match dns::resolve_hostname(&sd).await {
                Ok(records) => records.iter().map(|r| r.value.clone()).collect(),
                Err(_) => Vec::new(),
            };
            results.push(SubdomainResult {
                hostname: sd,
                source: "ct-logs".into(),
                ips,
            });
        }
    }

    // Permutation-based enumeration
    let permutations = ct_logs::generate_subdomain_permutations(domain);
    for permutation in permutations {
        if let Ok(records) = dns::resolve_hostname(&permutation).await {
            let ips: Vec<String> = records.iter().map(|r| r.value.clone()).collect();
            if !results.iter().any(|r| r.hostname == permutation) {
                results.push(SubdomainResult {
                    hostname: permutation,
                    source: "permutation".into(),
                    ips,
                });
            }
        }
    }

    results
}

/// Generates findings from discovered subdomains.
pub fn subdomains_to_findings(subdomains: &[SubdomainResult], _domain: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for sub in subdomains {
        let mut finding = Finding::new(
            format!("Subdomain discovered: {}", sub.hostname),
            AssetRef {
                identifier: sub.hostname.clone(),
                kind: "dns".into(),
            },
            Severity::Info,
            Confidence::Confirmed,
            "grym-recon-passive",
        );
        finding.categories.push("Passive Reconnaissance".into());
        finding.evidence.push(Evidence::redacted(
            "dns-record",
            format!("Source: {}", sub.source),
            format!("{} → {:?}", sub.hostname, sub.ips),
        ));
        if !sub.ips.is_empty() {
            finding
                .references
                .push(format!("IPs: {}", sub.ips.join(", ")));
        }
        findings.push(finding);
    }

    findings
}
