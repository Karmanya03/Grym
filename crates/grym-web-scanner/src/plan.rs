//! Engagement plan generation: turn target metadata and scope limits into
//! an ordered, prioritized testing plan with suggested payload sets and the
//! matching methodology checklist.
//!
//! Pure computation over provided metadata — no network access.

use serde::{Deserialize, Serialize};

use crate::checklist;
use crate::playbook;

/// What the operator knows about the target.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TargetProfile {
    /// Base URL of the target (e.g. `http://10.10.10.5:8080`).
    pub base_url: String,
    /// Known technologies (e.g. ["php", "mysql", "wordpress"]).
    #[serde(default)]
    pub technologies: Vec<String>,
    /// Whether the operator has valid credentials.
    #[serde(default)]
    pub authenticated: bool,
    /// Notes from recon (interesting endpoints, params, hints).
    #[serde(default)]
    pub notes: Vec<String>,
    /// Engagement identifier this plan belongs to.
    #[serde(default)]
    pub engagement_id: String,
}

/// Scope limits that shape how aggressive the plan can be.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlanLimits {
    /// Maximum technique tier allowed (0-4).
    pub max_tier: u8,
    /// Deepness profile name (quick/standard/deep/paranoid).
    pub deepness: String,
}

impl Default for PlanLimits {
    fn default() -> Self {
        Self {
            max_tier: 2,
            deepness: "standard".into(),
        }
    }
}

/// One step of the generated plan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlanStep {
    /// Execution order (1-based).
    pub order: usize,
    /// Module or manual action to run.
    pub action: String,
    /// Why this step is here.
    pub rationale: String,
    /// Rough relative weight for time budgeting (1-5).
    pub weight: u8,
}

/// A generated engagement plan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EngagementPlan {
    /// Target the plan was generated for.
    pub target: String,
    /// Engagement id carried through from the profile.
    pub engagement_id: String,
    /// Ordered steps.
    pub steps: Vec<PlanStep>,
    /// Payload set ids relevant to the detected/declared stack.
    pub suggested_payload_sets: Vec<String>,
    /// The methodology checklist id this plan follows.
    pub checklist_id: String,
}

/// Generate an engagement plan from a target profile and scope limits.
pub fn generate(profile: &TargetProfile, limits: &PlanLimits) -> EngagementPlan {
    let tech: Vec<String> = profile
        .technologies
        .iter()
        .map(|t| t.to_lowercase())
        .collect();

    let has = |needle: &str| tech.iter().any(|t| t.contains(needle));

    let mut steps: Vec<PlanStep> = Vec::new();
    let mut order = 0usize;
    let mut push = |action: &str, rationale: String, weight: u8| {
        order += 1;
        steps.push(PlanStep {
            order,
            action: action.to_string(),
            rationale,
            weight,
        });
    };

    // Phase 1: always map first.
    push(
        "recon: content discovery + tech fingerprint",
        "Map the surface and fingerprint the stack before any injection work.".into(),
        3,
    );
    push(
        "waf_detect",
        "Know the WAF early — it changes payload selection for everything after.".into(),
        2,
    );

    // Phase 2: auth surface.
    if profile.authenticated {
        push(
            "authenticated session capture",
            "Capture tokens/cookies for authenticated modules; unauthenticated tests miss most access-control bugs."
                .into(),
            2,
        );
        push(
            "idor + jwt",
            "Authenticated scope makes horizontal-access and token attacks testable.".into(),
            3,
        );
    } else {
        push(
            "auth-bypass probes (manual, via playbook)",
            "No creds yet: run login-bypass payload sets before brute forcing.".into(),
            2,
        );
    }

    // Phase 3: injection, ordered by stack likelihood.
    push(
        "sqli (error -> union -> blind)",
        "Highest-yield injection class; escalate along the ladder only as needed.".into(),
        4,
    );
    if has("mongo") || has("mongodb") || has("node") {
        push(
            "nosqli",
            "Declared stack suggests MongoDB; operator injection is cheap to test.".into(),
            3,
        );
    }
    if has("php") {
        push(
            "path_traversal (php wrappers) + xxe",
            "PHP wrappers (php://filter) make file-read primitives far more powerful.".into(),
            3,
        );
    }
    if has("java") || has("tomcat") || has("spring") {
        push(
            "xxe + deserialization probes",
            "Java stacks are prime XXE/deserialization territory.".into(),
            4,
        );
    }
    if has("python") || has("django") || has("flask") {
        push(
            "ssti",
            "Python template engines (Jinja2) are common and escalatable.".into(),
            3,
        );
    }
    push(
        "xss (context per parameter) + csrf + cors",
        "Client-side trio: context identification first, then state-change abuse.".into(),
        3,
    );
    push(
        "ssrf (only where URL fetch features exist)",
        "SSRF needs a fetch primitive; target importers/previewers/webhooks.".into(),
        2,
    );
    push(
        "graphql (if endpoint found)",
        "Introspection first, then batching and mutation abuse.".into(),
        2,
    );

    // Phase 4: adjust for deepness/tier.
    if limits.deepness == "quick" {
        steps.retain(|s| s.weight <= 3);
    }
    if limits.max_tier <= 1 {
        steps.retain(|s| {
            !s.action.starts_with("sqli")
                && !s.action.starts_with("ssti")
                && !s.action.starts_with("cmd")
        });
    }
    for (i, s) in steps.iter_mut().enumerate() {
        s.order = i + 1;
    }

    // Suggested payload sets from the declared stack.
    let mut suggested: Vec<String> = vec![
        "sqli-union".into(),
        "sqli-blind".into(),
        "xss-reflected".into(),
        "auth-bypass".into(),
    ];
    if has("mongo") || has("node") {
        suggested.push("nosqli".into());
    }
    if has("php") {
        suggested.push("path-traversal".into());
        suggested.push("xxe".into());
    }
    if has("java") || has("spring") || has("tomcat") {
        suggested.push("xxe".into());
        suggested.push("deserialization".into());
    }
    if has("python") || has("flask") || has("django") || has("jinja") {
        suggested.push("ssti".into());
    }
    if has("graphql") {
        suggested.push("graphql".into());
    }
    if tech
        .iter()
        .any(|t| t.contains("waf") || t.contains("cloudflare") || t.contains("aws"))
    {
        suggested.push("waf-bypass".into());
    }

    EngagementPlan {
        target: profile.base_url.clone(),
        engagement_id: profile.engagement_id.clone(),
        steps,
        suggested_payload_sets: suggested,
        checklist_id: checklist::standard_web_checklist().id,
    }
}

/// Render a plan as markdown for the report/repo.
pub fn to_markdown(plan: &EngagementPlan) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# Engagement Plan — {}\n\n",
        if plan.target.is_empty() {
            "(unset target)"
        } else {
            &plan.target
        }
    ));
    if !plan.engagement_id.is_empty() {
        out.push_str(&format!("Engagement: `{}`\n\n", plan.engagement_id));
    }
    out.push_str("## Steps\n\n");
    out.push_str("| # | Action | Why | Weight |\n|---|--------|-----|--------|\n");
    for s in &plan.steps {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            s.order, s.action, s.rationale, s.weight
        ));
    }
    out.push_str("\n## Suggested payload sets\n\n");
    for id in &plan.suggested_payload_sets {
        let title = playbook::payload_set(id)
            .map(|s| s.title)
            .unwrap_or_else(|| id.clone());
        out.push_str(&format!("- `{id}` — {title}\n"));
    }
    out.push_str(&format!(
        "\n## Methodology\n\nFollow `{}` (see `grym checklist --show`).\n",
        plan.checklist_id
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unwrap_used, clippy::expect_used)]
    #[test]
    fn plan_orders_mapping_first() {
        let profile = TargetProfile {
            base_url: "http://localhost:8080".into(),
            technologies: vec!["php".into(), "mysql".into()],
            authenticated: true,
            notes: vec![],
            engagement_id: "lab-1".into(),
        };
        let plan = generate(&profile, &PlanLimits::default());
        let first = plan.steps.first().expect("plan must have steps");
        assert!(first.action.contains("recon") || first.action.contains("fingerprint"));
        assert!(
            plan.suggested_payload_sets
                .contains(&"path-traversal".to_string())
        );
    }

    #[allow(clippy::unwrap_used, clippy::expect_used)]
    #[test]
    fn quick_deepness_trims_heavy_steps() {
        let profile = TargetProfile {
            base_url: "http://localhost".into(),
            technologies: vec![],
            authenticated: false,
            notes: vec![],
            engagement_id: String::new(),
        };
        let plan = generate(
            &profile,
            &PlanLimits {
                max_tier: 4,
                deepness: "quick".into(),
            },
        );
        assert!(plan.steps.iter().all(|s| s.weight <= 3));
    }

    #[allow(clippy::unwrap_used, clippy::expect_used)]
    #[test]
    fn low_tier_removes_injection() {
        let profile = TargetProfile {
            base_url: "http://localhost".into(),
            technologies: vec![],
            authenticated: false,
            notes: vec![],
            engagement_id: String::new(),
        };
        let plan = generate(
            &profile,
            &PlanLimits {
                max_tier: 1,
                deepness: "standard".into(),
            },
        );
        assert!(plan.steps.iter().all(|s| !s.action.starts_with("sqli")));
    }

    #[allow(clippy::unwrap_used, clippy::expect_used)]
    #[test]
    fn markdown_renders_table() {
        let profile = TargetProfile::default();
        let plan = generate(&profile, &PlanLimits::default());
        let md = to_markdown(&plan);
        assert!(md.contains("## Steps"));
        assert!(md.contains("## Suggested payload sets"));
    }
}
