//! CVE hunting mode — NVD feed ingestion, patch diff analysis, variant hypothesis, PoC generation.

use std::sync::Arc;
use tokio::sync::Mutex;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{Message, ModelTier, OllamaModel, ReasoningModel};
use crate::session::{SessionMode, SessionStore};

use anyhow::Result;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CveRecord {
    pub id: String,
    pub description: String,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub published: Option<String>,
    pub affected_products: Vec<String>,
    pub references: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VariantHypothesis {
    pub base_cve: String,
    pub hypothesis: String,
    pub affected_component: String,
    pub attack_vector: String,
    pub confidence: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NucleiTemplate {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub yaml: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HuntSession {
    pub id: String,
    pub target_description: String,
    pub cves_analyzed: Vec<CveRecord>,
    pub hypotheses: Vec<VariantHypothesis>,
    pub templates: Vec<NucleiTemplate>,
    pub poc_code: String,
    pub session_id: String,
    pub status: HuntStatus,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum HuntStatus {
    Initiated,
    AnalyzingCves,
    Hypothesizing,
    GeneratingPoc,
    Completed,
    Failed(String),
}

impl HuntSession {
    pub fn new(target_description: &str) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id: Uuid::now_v7().to_string(),
            target_description: target_description.to_string(),
            cves_analyzed: Vec::new(),
            hypotheses: Vec::new(),
            templates: Vec::new(),
            poc_code: String::new(),
            session_id: String::new(),
            status: HuntStatus::Initiated,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

pub struct CveHunter {
    model: OllamaModel,
    session_store: Arc<Mutex<SessionStore>>,
}

impl CveHunter {
    pub async fn new(tier: ModelTier) -> Result<Self> {
        let model = OllamaModel::new(tier)?;
        let session_store = Arc::new(Mutex::new(SessionStore::new()));
        Ok(Self {
            model,
            session_store,
        })
    }

    pub async fn hunt(&self, target_description: &str) -> Result<HuntSession> {
        let mut session = HuntSession::new(target_description);

        session.status = HuntStatus::AnalyzingCves;
        let cves = self.identify_cves(target_description).await?;
        session.cves_analyzed = cves;
        session.updated_at = chrono::Utc::now().to_rfc3339();

        session.status = HuntStatus::Hypothesizing;
        let hypotheses = self.hypothesize_variants(&session.cves_analyzed).await?;
        session.hypotheses = hypotheses;
        session.updated_at = chrono::Utc::now().to_rfc3339();

        session.status = HuntStatus::GeneratingPoc;
        let poc = self.generate_poc(&session.hypotheses).await?;
        session.poc_code = poc;
        session.updated_at = chrono::Utc::now().to_rfc3339();

        {
            let mut store = self.session_store.lock().await;
            let sid = store.create(SessionMode::Hunt);
            session.session_id = sid;
        }

        session.status = HuntStatus::Completed;
        session.updated_at = chrono::Utc::now().to_rfc3339();
        Ok(session)
    }

    async fn identify_cves(&self, target: &str) -> Result<Vec<CveRecord>> {
        let prompt = format!(
            "You are a CVE research analyst. Given the target: \"{target}\"\n\
             Identify up to 10 relevant CVEs. For each CVE, provide:\n\
             - id (CVE-YYYY-NNNNN)\n\
             - description (1 sentence)\n\
             - cvss_score (if known, or null)\n\
             - affected_products (comma-separated)\n\
             - references (URLs)\n\n\
             Return as JSON array of objects with keys: id, description, cvss_score, affected_products, references.\n\
             Only return valid JSON, no other text.",
        );

        let msgs = vec![Message {
            role: "user".into(),
            content: prompt,
        }];

        let response = self.model.reason(&msgs, &[]).await?;
        let cleaned = clean_json(&response.content);
        serde_json::from_str::<Vec<CveRecord>>(cleaned).or_else(|_| Ok(Vec::new()))
    }

    async fn hypothesize_variants(&self, cves: &[CveRecord]) -> Result<Vec<VariantHypothesis>> {
        let cve_summary: Vec<String> = cves
            .iter()
            .map(|c| format!("{}: {} (CVSS: {:?})", c.id, c.description, c.cvss_score))
            .collect();

        let prompt = format!(
            "Given these known CVEs:\n{}\n\n\
             For each CVE, hypothesize a likely variant that may not yet have a CVE assigned.\n\
             Consider:\n\
             - Similar products/components\n\
             - Similar attack vectors\n\
             - Similar vulnerability classes (XSS, SQLi, SSRF, buffer overflow, etc.)\n\n\
             Return as JSON array of objects with keys:\n\
             - base_cve: the original CVE\n\
             - hypothesis: description of the hypothesized variant\n\
             - affected_component: what component is affected\n\
             - attack_vector: how it could be exploited\n\
             - confidence: float 0.0 to 1.0\n\n\
             Only return valid JSON, no other text.",
            cve_summary.join("\n"),
        );

        let msgs = vec![Message {
            role: "user".into(),
            content: prompt,
        }];

        let response = self.model.reason(&msgs, &[]).await?;
        let cleaned = clean_json(&response.content);
        serde_json::from_str::<Vec<VariantHypothesis>>(cleaned).or_else(|_| Ok(Vec::new()))
    }

    async fn generate_poc(&self, hypotheses: &[VariantHypothesis]) -> Result<String> {
        let hyp_summary: Vec<String> = hypotheses
            .iter()
            .map(|h| {
                format!(
                    "{} (based on {}): {} — {} — confidence {}",
                    h.hypothesis, h.base_cve, h.affected_component, h.attack_vector, h.confidence
                )
            })
            .collect();

        let prompt = format!(
            "Given these vulnerability hypotheses:\n{}\n\n\
             Generate:\n\
             1. A Python/curl PoC script for testing each hypothesis (use comments to separate)\n\
             2. A nuclei-compatible YAML template for scanning for the most promising variant\n\n\
             The PoC should be safe (no destructive actions) and send appropriate HTTP requests.\n\n\
             Return the PoC code in a code block.",
            hyp_summary.join("\n"),
        );

        let msgs = vec![Message {
            role: "user".into(),
            content: prompt,
        }];

        let response = self.model.reason(&msgs, &[]).await?;
        Ok(response.content)
    }

    pub fn session_store(&self) -> Arc<Mutex<SessionStore>> {
        self.session_store.clone()
    }
}

fn clean_json(content: &str) -> &str {
    content
        .trim()
        .strip_prefix("```json")
        .or_else(|| content.trim().strip_prefix("```"))
        .and_then(|s| s.strip_suffix("```"))
        .unwrap_or(content.trim())
}
