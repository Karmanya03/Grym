//! Methodology checklists for manual web application pentesting.
//!
//! Structured as phases of ordered steps, matching how engagements (and
//! certification exams) actually progress: enumeration, mapping, attack,
//! then post-exploitation. Steps carry a `checked` flag so progress can be
//! persisted per engagement by the CLI/TUI/API layers.

use serde::{Deserialize, Serialize};

/// A single checklist step.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CheckStep {
    /// Stable identifier within the checklist (e.g. "map-urls").
    pub id: String,
    /// What to do.
    pub text: String,
    /// Whether the operator marked it done.
    #[serde(default)]
    pub checked: bool,
}

/// A phase of the methodology containing ordered steps.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckPhase {
    /// Stable identifier (e.g. "enumeration").
    pub id: String,
    /// Phase title.
    pub title: String,
    /// Why this phase matters.
    pub description: String,
    /// Ordered steps.
    pub steps: Vec<CheckStep>,
}

/// A full methodology checklist.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checklist {
    /// Stable identifier (e.g. "web-pentest-standard").
    pub id: String,
    /// Checklist title.
    pub title: String,
    /// Who this checklist is for.
    pub audience: String,
    /// Phases in execution order.
    pub phases: Vec<CheckPhase>,
}

fn step(id: &str, text: &str) -> CheckStep {
    CheckStep {
        id: id.to_string(),
        text: text.to_string(),
        checked: false,
    }
}

/// Build the standard web pentest methodology checklist.
pub fn standard_web_checklist() -> Checklist {
    Checklist {
        id: "web-pentest-standard".into(),
        title: "Standard Web Application Pentest".into(),
        audience: "eWPTX / GWAPT / Burp Practitioner style engagements".into(),
        phases: vec![
            CheckPhase {
                id: "enumeration".into(),
                title: "1. Enumeration & Recon".into(),
                description: "Map the attack surface before touching anything risky.".into(),
                steps: vec![
                    step("enum-ports", "Port scan the target; note HTTP(S) services."),
                    step("enum-vhosts", "Enumerate virtual hosts and subdomains."),
                    step(
                        "enum-dirs",
                        "Content discovery: directories, files, backups, admin panels.",
                    ),
                    step(
                        "enum-params",
                        "Catalog parameters, cookies, and headers per endpoint.",
                    ),
                    step(
                        "enum-tech",
                        "Fingerprint the stack: server, framework, CMS, WAF.",
                    ),
                    step(
                        "enum-js",
                        "Review JS files for API routes, secrets, and comments.",
                    ),
                ],
            },
            CheckPhase {
                id: "mapping".into(),
                title: "2. Mapping & Baselines".into(),
                description: "Understand normal behavior so anomalies stand out.".into(),
                steps: vec![
                    step(
                        "map-roles",
                        "Register accounts at every role level available.",
                    ),
                    step(
                        "map-auth",
                        "Walk the auth flows: login, reset, 2FA, session lifecycle.",
                    ),
                    step(
                        "map-baseline",
                        "Capture baseline responses for error injection later.",
                    ),
                    step(
                        "map-dataflow",
                        "Trace where user input lands: body, URL, headers, files.",
                    ),
                ],
            },
            CheckPhase {
                id: "attack-auth".into(),
                title: "3. Authentication Attacks".into(),
                description: "Identity is the perimeter; attack it first.".into(),
                steps: vec![
                    step(
                        "auth-brute",
                        "Test lockout and rate limiting with a controlled brute force.",
                    ),
                    step("auth-default", "Try default and common credential pairs."),
                    step(
                        "auth-reset",
                        "Abuse reset flows: predictability, host header, token reuse.",
                    ),
                    step(
                        "auth-2fa",
                        "Test 2FA: brute force, response tampering, skip states.",
                    ),
                    step(
                        "auth-jwt",
                        "Attack JWTs: alg none, confusion, weak secrets, kid injection.",
                    ),
                    step(
                        "auth-session",
                        "Session fixation, non-expiring cookies, cookie flags.",
                    ),
                ],
            },
            CheckPhase {
                id: "attack-injection".into(),
                title: "4. Injection Attacks".into(),
                description: "Classic server-side injection, one class at a time.".into(),
                steps: vec![
                    step(
                        "inj-sqli",
                        "SQLi: error, union, blind boolean, time-based, OOB.",
                    ),
                    step(
                        "inj-nosql",
                        "NoSQL operator injection on JSON and query strings.",
                    ),
                    step(
                        "inj-cmd",
                        "Command injection: operators, blind timing, encoding bypass.",
                    ),
                    step(
                        "inj-ssti",
                        "SSTI: fingerprint engine, escalate along gadget chains.",
                    ),
                    step(
                        "inj-xxe",
                        "XXE: file read, SSRF pivot, OOB parameter entities.",
                    ),
                    step(
                        "inj-traversal",
                        "Path traversal: encoding layers, PHP wrappers, log poisoning.",
                    ),
                    step(
                        "inj-smuggle",
                        "Request smuggling: CL.TE, TE.CL, obfuscated TE.",
                    ),
                ],
            },
            CheckPhase {
                id: "attack-client".into(),
                title: "5. Client-Side Attacks".into(),
                description: "The browser is a victim too.".into(),
                steps: vec![
                    step(
                        "client-xss",
                        "XSS: identify context per parameter, then craft breakouts.",
                    ),
                    step(
                        "client-csrf",
                        "CSRF on state-changing actions without tokens/SameSite.",
                    ),
                    step(
                        "client-cors",
                        "CORS misconfig: wildcard origins with credentials.",
                    ),
                    step(
                        "client-openredir",
                        "Open redirects and header-based redirect abuse.",
                    ),
                    step(
                        "client-dom",
                        "DOM XSS from JS sinks reachable via URL fragments.",
                    ),
                ],
            },
            CheckPhase {
                id: "attack-access".into(),
                title: "6. Access Control".into(),
                description: "Authorization bugs are the most impactful and most missed.".into(),
                steps: vec![
                    step("ac-idor", "IDOR: swap object IDs between accounts."),
                    step(
                        "ac-vertical",
                        "Vertical escalation: low-priv user hits admin endpoints.",
                    ),
                    step("ac-methods", "HTTP method tampering and verb overrides."),
                    step(
                        "ac-api",
                        "API mass assignment: add admin=true to PATCH/PUT bodies.",
                    ),
                ],
            },
            CheckPhase {
                id: "attack-server".into(),
                title: "7. Server & Config".into(),
                description: "Misconfigurations and component-level issues.".into(),
                steps: vec![
                    step(
                        "srv-upload",
                        "File upload: extension, content-type, magic bytes, path.",
                    ),
                    step(
                        "srv-deser",
                        "Insecure deserialization probes on serialized objects.",
                    ),
                    step(
                        "srv-graphql",
                        "GraphQL: introspection, batching, unauthorized mutations.",
                    ),
                    step(
                        "srv-cve",
                        "CVE-correlate every fingerprinted component version.",
                    ),
                    step("srv-tls", "TLS/cookie/header security flags review."),
                ],
            },
            CheckPhase {
                id: "reporting".into(),
                title: "8. Reporting".into(),
                description: "An unfixed finding is an undocumented one.".into(),
                steps: vec![
                    step(
                        "rep-evidence",
                        "Capture reproducible evidence: request, response, screenshot.",
                    ),
                    step(
                        "rep-impact",
                        "Grade severity and business impact for each finding.",
                    ),
                    step(
                        "rep-retest",
                        "Save the exact requests for retest after the fix window.",
                    ),
                ],
            },
        ],
    }
}

/// Progress statistics for a checklist.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct ChecklistProgress {
    /// Total steps across all phases.
    pub total: usize,
    /// Steps marked checked.
    pub done: usize,
}

impl Checklist {
    /// Compute progress across all phases.
    pub fn progress(&self) -> ChecklistProgress {
        let total: usize = self.phases.iter().map(|p| p.steps.len()).sum();
        let done = self
            .phases
            .iter()
            .flat_map(|p| &p.steps)
            .filter(|s| s.checked)
            .count();
        ChecklistProgress { total, done }
    }

    /// Set the checked state of one step.
    pub fn set_checked(&mut self, phase_id: &str, step_id: &str, checked: bool) -> bool {
        for phase in &mut self.phases {
            if phase.id == phase_id {
                for s in &mut phase.steps {
                    if s.id == step_id {
                        s.checked = checked;
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// Render a checklist as markdown with `[x]`/`[ ]` boxes and progress bars.
pub fn to_markdown(checklist: &Checklist) -> String {
    let progress = checklist.progress();
    let mut out = String::new();
    out.push_str(&format!("# {}\n\n", checklist.title));
    out.push_str(&format!(
        "> Audience: {} — progress: {}/{} steps ({:.0}%)\n\n",
        checklist.audience,
        progress.done,
        progress.total,
        if progress.total == 0 {
            0.0
        } else {
            100.0 * progress.done as f64 / progress.total as f64
        }
    ));
    for phase in &checklist.phases {
        out.push_str(&format!("## {}\n\n", phase.title));
        out.push_str(&format!("_{}_\n\n", phase.description));
        for s in &phase.steps {
            let box_char = if s.checked { 'x' } else { ' ' };
            out.push_str(&format!("- [{}] {}\n", box_char, s.text));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_checklist_shape() {
        let cl = standard_web_checklist();
        assert!(!cl.phases.is_empty());
        let progress = cl.progress();
        assert!(progress.total >= 30);
        assert_eq!(progress.done, 0);
    }

    #[test]
    fn set_checked_updates_progress() {
        let mut cl = standard_web_checklist();
        assert!(cl.set_checked("enumeration", "enum-ports", true));
        assert!(!cl.set_checked("enumeration", "nope", true));
        let progress = cl.progress();
        assert_eq!(progress.done, 1);
        assert!(cl.progress().total > progress.done);
    }

    #[test]
    fn markdown_renders_boxes() {
        let mut cl = standard_web_checklist();
        cl.set_checked("mapping", "map-roles", true);
        let md = to_markdown(&cl);
        assert!(md.contains("- [x] Register accounts"));
        assert!(md.contains("- [ ] Port scan"));
    }
}
