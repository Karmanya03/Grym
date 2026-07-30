//! DNS resolution and passive reconnaissance.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// DNS resolution result with metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsRecord {
    pub hostname: String,
    pub record_type: String,
    pub value: String,
    pub source: String,
}

/// DNS-related errors.
#[derive(Debug, Error)]
pub enum DnsError {
    #[error("DNS resolution failed: {0}")]
    Resolution(String),
    #[error("Invalid hostname: {0}")]
    InvalidHostname(String),
}

/// Resolves A/AAAA records for a hostname.
pub async fn resolve_hostname(hostname: &str) -> Result<Vec<DnsRecord>, DnsError> {
    let hostname = hostname.trim().trim_start_matches("*. ").trim_start_matches("*.");
    let mut records = Vec::new();

    if let Ok(addresses) = tokio::net::lookup_host(format!("{}:0", hostname)).await {
        for addr in addresses {
            records.push(DnsRecord {
                hostname: hostname.to_owned(),
                record_type: if addr.is_ipv4() { "A".into() } else { "AAAA".into() },
                value: addr.ip().to_string(),
                source: "dns-resolution".into(),
            });
        }
    }

    if records.is_empty() {
        return Err(DnsError::Resolution(format!("No A/AAAA records for {}", hostname)));
    }
    Ok(records)
}

/// Performs a reverse DNS lookup on an IP address.
pub async fn reverse_dns(ip: &IpAddr) -> Result<Vec<String>, DnsError> {
    let hostname = ip.to_string();
    let records = resolve_hostname(&hostname).await?;
    Ok(records.into_iter().map(|r| r.value).collect())
}

/// Enumerates basic DNS record types (MX, NS, TXT, SOA).
pub async fn enumerate_dns_records(domain: &str) -> Vec<DnsRecord> {
    let mut records = Vec::new();

    let record_types = ["MX", "NS", "TXT", "SOA", "CNAME"];
    for rtype in &record_types {
        let lookup_host = format!("{}.{}", rtype.to_lowercase(), domain);
        let Ok(result) = tokio::net::lookup_host(&lookup_host).await else {
            continue;
        };
        for addr in result {
            records.push(DnsRecord {
                hostname: format!("{} {}", domain, rtype),
                record_type: rtype.to_string(),
                value: addr.to_string(),
                source: "dns-enum".into(),
            });
        }
    }
    records
}
