//! `grym-ai-agent` — autonomous AI-driven pentesting and CVE hunting agent.
//!
//! Provides:
//! - [`AiAgent`] — ReAct loop agent for interactive pentesting
//! - [`CveHunter`] — automated CVE variant hypothesis and PoC generation
//! - [`SessionStore`] — persistent session management

#![deny(unsafe_code)]
// Clippy lints
#![warn(clippy::unwrap_used, clippy::expect_used)]
#![warn(clippy::todo, clippy::unimplemented)]

pub mod agent;
pub mod hunt;
pub mod mcp;
pub mod model;
pub mod session;
pub mod tools;

pub use agent::{AgentConfig, AiAgent};
pub use hunt::{CveHunter, CveRecord, HuntSession, HuntStatus, NucleiTemplate, VariantHypothesis};
pub use model::{Message, ModelTier, OllamaModel, ToolCall};
pub use session::{Session, SessionMode, SessionStore, Turn};
pub use tools::{ToolRegistry, ToolResult};

use std::sync::Arc;
use tokio::sync::Mutex;

/// Global agent state holder.
pub struct AgentState {
    pub session_store: Arc<Mutex<SessionStore>>,
}

impl AgentState {
    pub fn new() -> Self {
        Self {
            session_store: Arc::new(Mutex::new(SessionStore::new())),
        }
    }
}

/// Start an interactive AI agent session for a given prompt.
pub async fn start_agent(prompt: &str, model_tier: ModelTier) -> anyhow::Result<(String, String)> {
    let config = AgentConfig {
        model_tier,
        ..Default::default()
    };
    let agent = AiAgent::new(config).await?;
    agent.run(prompt).await
}

/// Start a CVE hunt for a given target description.
pub async fn start_hunt(
    target_description: &str,
    model_tier: ModelTier,
) -> anyhow::Result<HuntSession> {
    let hunter = CveHunter::new(model_tier).await?;
    hunter.hunt(target_description).await
}

/// List all active sessions.
pub async fn list_sessions(store: Arc<Mutex<SessionStore>>) -> Vec<session::Session> {
    let guard = store.lock().await;
    guard.list().into_iter().cloned().collect()
}
