//! Session management — tracks conversation history, tool calls, and findings across turns.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::Message;
use crate::tools::ToolResult;

/// A single turn in the conversation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Turn {
    /// Monotonic turn number.
    pub turn_id: u64,
    /// User input.
    pub user_message: String,
    /// Assistant response (model output).
    pub assistant_message: Option<String>,
    /// Reasoning trace (from model).
    pub reasoning: Option<String>,
    /// Tool calls made this turn.
    pub tool_calls: Vec<MetricToolCall>,
    /// Timestamp.
    pub timestamp: String,
}

/// Record of a tool invocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricToolCall {
    pub tool: String,
    pub success: bool,
    pub duration_ms: u64,
    pub summary: String,
}

/// Full session state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub mode: SessionMode,
    pub created_at: String,
    pub updated_at: String,
    pub turns: Vec<Turn>,
    pub accumulated_findings: Vec<serde_json::Value>,
    pub metadata: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub enum SessionMode {
    #[default]
    Interactive,
    Hunt,
    Batch,
}

impl Session {
    pub fn new(mode: SessionMode) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id: Uuid::now_v7().to_string(),
            mode,
            created_at: now.clone(),
            updated_at: now,
            turns: Vec::new(),
            accumulated_findings: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn add_turn(
        &mut self,
        user_msg: String,
        assistant_msg: Option<String>,
        reasoning: Option<String>,
        tool_calls: Vec<MetricToolCall>,
        tool_results: &[ToolResult],
    ) {
        let turn = Turn {
            turn_id: (self.turns.len() + 1) as u64,
            user_message: user_msg,
            assistant_message: assistant_msg,
            reasoning,
            tool_calls,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        self.turns.push(turn);

        // Accumulate findings
        for result in tool_results {
            for finding in &result.findings {
                if let Ok(val) = serde_json::to_value(finding) {
                    self.accumulated_findings.push(val);
                }
            }
        }

        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    pub fn to_messages(&self) -> Vec<Message> {
        let mut msgs = Vec::new();
        for turn in &self.turns {
            msgs.push(Message {
                role: "user".into(),
                content: turn.user_message.clone(),
            });
            if let Some(ref assistant) = turn.assistant_message {
                msgs.push(Message {
                    role: "assistant".into(),
                    content: assistant.clone(),
                });
            }
        }
        msgs
    }

    pub fn summary(&self) -> String {
        let total_findings: usize = self.accumulated_findings.len();
        let critical = self
            .accumulated_findings
            .iter()
            .filter(|f| f.get("severity").and_then(|s| s.as_str()) == Some("critical"))
            .count();
        let high = self
            .accumulated_findings
            .iter()
            .filter(|f| f.get("severity").and_then(|s| s.as_str()) == Some("high"))
            .count();

        format!(
            "Session {} | Mode: {:?} | {} turns | {} findings (Crit:{} High:{})",
            &self.id[..8],
            self.mode,
            self.turns.len(),
            total_findings,
            critical,
            high,
        )
    }
}

/// In-memory session store with auto-cleanup of old sessions.
pub struct SessionStore {
    sessions: HashMap<String, Session>,
    max_sessions: usize,
    max_age: Duration,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions: 50,
            max_age: Duration::from_secs(86400),
        }
    }

    pub fn create(&mut self, mode: SessionMode) -> String {
        let session = Session::new(mode);
        let id = session.id.clone();
        self.sessions.insert(id.clone(), session);
        self.cleanup();
        id
    }

    pub fn get(&self, id: &str) -> Option<&Session> {
        self.sessions.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Session> {
        self.sessions.get_mut(id)
    }

    pub fn list(&self) -> Vec<&Session> {
        let mut sessions: Vec<&Session> = self.sessions.values().collect();
        sessions.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        sessions
    }

    pub fn delete(&mut self, id: &str) {
        self.sessions.remove(id);
    }

    fn cleanup(&mut self) {
        if self.sessions.len() <= self.max_sessions {
            return;
        }
        let _cutoff = Instant::now() - self.max_age;
        self.sessions.retain(|_, s| {
            // Keep sessions that are "active" — we use simple heuristic
            s.turns.len() > 1
        });
        // If still over limit, keep only the most recent max_sessions
        if self.sessions.len() > self.max_sessions {
            let mut by_updated: Vec<(String, String)> = self
                .sessions
                .iter()
                .map(|(k, v)| (k.clone(), v.updated_at.clone()))
                .collect();
            by_updated.sort_by(|a, b| b.1.cmp(&a.1));
            let keep: std::collections::HashSet<String> = by_updated
                .into_iter()
                .take(self.max_sessions)
                .map(|(k, _)| k)
                .collect();
            self.sessions.retain(|k, _| keep.contains(k));
        }
    }
}
