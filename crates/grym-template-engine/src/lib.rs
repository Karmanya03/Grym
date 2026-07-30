//! Data-driven, non-destructive response-signature matching.

#![deny(unsafe_code)]

use grym_core::{AssetRef, Confidence, Evidence, Finding, HttpResponseSnapshot, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Serializable safe detection template.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DetectionTemplate {
    /// Stable template identifier.
    pub id: String,
    /// Operator-facing name.
    pub name: String,
    /// Data-pack OWASP/API/Mobile category ID.
    pub category: String,
    /// CWE identifiers.
    #[serde(default)]
    pub cwe: Vec<u32>,
    /// ATT&CK technique IDs.
    #[serde(default)]
    pub attack_technique: Vec<String>,
    /// Report severity.
    pub severity: Severity,
    /// Confidence assigned when all matchers succeed.
    pub confidence_on_match: Confidence,
    /// Signature-only matchers; templates do not contain active payloads.
    pub matchers: Vec<Matcher>,
    /// CVE references associated with the signature.
    #[serde(default)]
    pub cve_refs: Vec<String>,
    /// Vendor or standards links.
    #[serde(default)]
    pub references: Vec<String>,
    /// Remediation text displayed in reports.
    pub remediation: String,
}

/// Allowed safe matcher types.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Matcher {
    /// Regex matched against one response header.
    Header {
        /// Case-insensitive header name.
        part: String,
        /// Rust regular expression.
        regex: String,
    },
    /// Regex matched against the bounded response body.
    Body {
        /// Rust regular expression.
        regex: String,
    },
    /// Exact HTTP status code.
    Status {
        /// Expected status code.
        status: u16,
    },
}

/// Template parsing or validation error.
#[derive(Debug, Error)]
pub enum TemplateError {
    /// YAML did not match the template schema.
    #[error("invalid template YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    /// A regex matcher could not be compiled.
    #[error("invalid template regex: {0}")]
    Regex(#[from] regex::Error),
    /// A required safe-template invariant is absent.
    #[error("invalid detection template: {0}")]
    Validation(String),
}

impl DetectionTemplate {
    /// Parses then validates a template before it is available to a scanner.
    pub fn from_yaml(input: &str) -> Result<Self, TemplateError> {
        let template = serde_yaml::from_str::<Self>(input)?;
        template.validate()?;
        Ok(template)
    }

    /// Rejects templates that cannot be a safe, meaningful signature.
    pub fn validate(&self) -> Result<(), TemplateError> {
        if self.id.trim().is_empty()
            || self.name.trim().is_empty()
            || self.category.trim().is_empty()
        {
            return Err(TemplateError::Validation(
                "id, name, and category are required".to_owned(),
            ));
        }
        if self.matchers.is_empty() {
            return Err(TemplateError::Validation(
                "at least one non-destructive matcher is required".to_owned(),
            ));
        }
        for matcher in &self.matchers {
            match matcher {
                Matcher::Header { part, regex } => {
                    if part.trim().is_empty() {
                        return Err(TemplateError::Validation(
                            "header matcher part must not be empty".to_owned(),
                        ));
                    }
                    let _ = Regex::new(regex)?;
                }
                Matcher::Body { regex } => {
                    let _ = Regex::new(regex)?;
                }
                Matcher::Status { status } => {
                    if !(100..=599).contains(status) {
                        return Err(TemplateError::Validation(format!(
                            "invalid HTTP status matcher {status}"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns whether every safe signature matcher is satisfied by one response snapshot.
    pub fn matches(&self, response: &HttpResponseSnapshot) -> Result<bool, TemplateError> {
        self.matchers.iter().try_fold(true, |matches, matcher| {
            let current = match matcher {
                Matcher::Header { part, regex } => response
                    .headers
                    .get(&part.to_ascii_lowercase())
                    .is_some_and(|value| {
                        Regex::new(regex).is_ok_and(|expression| expression.is_match(value))
                    }),
                Matcher::Body { regex } => Regex::new(regex)?.is_match(&response.body),
                Matcher::Status { status } => response.status == *status,
            };
            Ok(matches && current)
        })
    }

    /// Converts a template match into a complete evidence-bearing finding.
    pub fn to_finding(&self, response: &HttpResponseSnapshot, module: &str) -> Finding {
        let mut finding = Finding::new(
            self.name.clone(),
            AssetRef {
                identifier: response.url.clone(),
                kind: "web".to_owned(),
            },
            self.severity,
            self.confidence_on_match,
            module,
        );
        finding.categories.push(self.category.clone());
        finding.cwe_ids.clone_from(&self.cwe);
        finding.attack_techniques.clone_from(&self.attack_technique);
        finding.references = self.references.clone();
        finding.references.extend(self.cve_refs.clone());
        finding.remediation.clone_from(&self.remediation);
        finding.evidence.push(Evidence::redacted(
            "http-response",
            format!("Template {} matched status {}", self.id, response.status),
            &response.body,
        ));
        finding
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::DetectionTemplate;
    use grym_core::HttpResponseSnapshot;

    const TEMPLATE: &str = r#"
id: TMPL-0001
name: Example server banner
category: A02:2025-Security-Misconfiguration
cwe: [16]
attack_technique: ["T1592"]
severity: medium
confidence_on_match: possible
matchers:
  - type: header
    part: server
    regex: "ExampleServer/1\\.0"
  - type: status
    status: 200
references: ["https://example.test/advisory"]
remediation: Upgrade ExampleServer.
"#;

    #[test]
    fn matches_safe_header_and_status_signatures() -> Result<(), Box<dyn std::error::Error>> {
        let template = DetectionTemplate::from_yaml(TEMPLATE)?;
        let mut headers = BTreeMap::new();
        headers.insert("server".to_owned(), "ExampleServer/1.0".to_owned());
        let response = HttpResponseSnapshot {
            url: "https://fixture.test/".to_owned(),
            status: 200,
            headers,
            body: String::new(),
        };
        assert!(template.matches(&response)?);
        Ok(())
    }
}
