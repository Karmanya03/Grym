//! Async TCP port scanner with service fingerprinting.

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::time::timeout;

use grym_core::{AssetRef, Confidence, Evidence, Finding, Severity};

/// Common service ports organized by category.
pub const COMMON_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (111, "RPC"),
    (135, "RPC"),
    (139, "NetBIOS"),
    (143, "IMAP"),
    (161, "SNMP"),
    (389, "LDAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (465, "SMTPS"),
    (500, "IKE"),
    (514, "Syslog"),
    (587, "SMTP Submission"),
    (636, "LDAPS"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1025, "RPC"),
    (1080, "SOCKS"),
    (1433, "MSSQL"),
    (1521, "Oracle DB"),
    (1701, "L2TP"),
    (1723, "PPTP"),
    (2049, "NFS"),
    (2082, "cPanel"),
    (2083, "cPanel SSL"),
    (2181, "ZooKeeper"),
    (2375, "Docker API"),
    (2376, "Docker API SSL"),
    (27017, "MongoDB"),
    (3000, "Development"),
    (3128, "Squid Proxy"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (3690, "SVN"),
    (4369, "Erlang Port Mapper"),
    (5432, "PostgreSQL"),
    (5555, "Android ADB"),
    (5601, "Kibana"),
    (5672, "RabbitMQ"),
    (5900, "VNC"),
    (5984, "CouchDB"),
    (6379, "Redis"),
    (6443, "Kubernetes API"),
    (7474, "Neo4j"),
    (8000, "HTTP Alt"),
    (8080, "HTTP Proxy"),
    (8443, "HTTPS Alt"),
    (8500, "Consul"),
    (9000, "HTTP Alt"),
    (9092, "Kafka"),
    (9200, "Elasticsearch"),
    (11211, "Memcached"),
    (15672, "RabbitMQ Mgmt"),
    (27017, "MongoDB"),
    (50000, "SAP"),
    (50070, "Hadoop NameNode"),
];

/// Result of a single port scan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortResult {
    pub host: String,
    pub port: u16,
    pub service: String,
    pub open: bool,
}

/// Scans a set of common ports on a target host.
pub async fn scan_common_ports(
    host: &str,
    ports: &[(u16, &str)],
    timeout_ms: u64,
) -> Vec<PortResult> {
    let host_owned = host.to_owned();
    let timeout_dur = Duration::from_millis(timeout_ms);

    let mut handles = Vec::new();
    for (port, service) in ports {
        let h = host_owned.clone();
        let p = *port;
        let s = service.to_string();
        let dur = timeout_dur;

        handles.push(tokio::spawn(async move {
            let addr = format!("{}:{}", h, p);
            let socket_addr = match addr.parse::<SocketAddr>() {
                Ok(a) => a,
                Err(_) => {
                    return PortResult {
                        host: h,
                        port: p,
                        service: s,
                        open: false,
                    };
                }
            };
            match timeout(dur, TcpStream::connect(socket_addr)).await {
                Ok(Ok(_)) => PortResult {
                    host: h,
                    port: p,
                    service: s,
                    open: true,
                },
                _ => PortResult {
                    host: h,
                    port: p,
                    service: s,
                    open: false,
                },
            }
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    results.sort_by_key(|r| r.port);
    results
}

/// Generates findings from port scan results.
pub fn port_results_to_findings(results: &[PortResult]) -> Vec<Finding> {
    let open_ports: Vec<&PortResult> = results.iter().filter(|r| r.open).collect();
    if open_ports.is_empty() {
        return Vec::new();
    }

    open_ports
        .iter()
        .map(|port| {
            let mut finding = Finding::new(
                format!(
                    "Open port found: {}/{} ({})",
                    port.port, port.service, port.host
                ),
                AssetRef {
                    identifier: format!("{}:{}", port.host, port.port),
                    kind: "network".into(),
                },
                if port.port == 22 || port.port == 443 {
                    Severity::Info
                } else {
                    Severity::Low
                },
                Confidence::Confirmed,
                "grym-recon-active",
            );
            finding.categories.push("Active Reconnaissance".into());
            finding.cwe_ids.push(200);
            finding.evidence.push(Evidence::redacted(
                "port-scan",
                format!(
                    "Port {} ({}) is OPEN on {}",
                    port.port, port.service, port.host
                ),
                format!("{}:{} - {}", port.host, port.port, port.service),
            ));
            finding.remediation = format!(
                "Ensure {} service on port {} is properly secured and necessary.",
                port.service, port.port
            );
            finding
        })
        .collect()
}
