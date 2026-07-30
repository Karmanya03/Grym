//! ReAct loop — orchestrates LLM reasoning → tool execution → result feedback.

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::model::{Message, ModelTier, OllamaModel, ReasoningModel, ensure_models};
use crate::session::{MetricToolCall, SessionMode};
use crate::tools::ToolRegistry;

use anyhow::{Result, bail};

const MAX_ITERATIONS: usize = 25;

pub struct AiAgent {
    model: OllamaModel,
    tools: ToolRegistry,
    session_store: Arc<Mutex<crate::session::SessionStore>>,
    config: AgentConfig,
}

pub struct AgentConfig {
    pub model_tier: ModelTier,
    pub max_iterations: usize,
    pub temperature: f32,
    pub top_p: f32,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            model_tier: ModelTier::Lightweight,
            max_iterations: MAX_ITERATIONS,
            temperature: 0.3,
            top_p: 0.9,
        }
    }
}

impl AiAgent {
    pub async fn new(config: AgentConfig) -> Result<Self> {
        let model = OllamaModel::new(config.model_tier)?;
        ensure_models(model.client(), model.base_url()).await?;
        let tools = ToolRegistry::new().await?;
        let session_store = Arc::new(Mutex::new(crate::session::SessionStore::new()));
        Ok(Self {
            model,
            tools,
            session_store,
            config,
        })
    }

    pub async fn run(&self, user_query: &str) -> Result<(String, String)> {
        let session_id = {
            let mut store = self.session_store.lock().await;
            store.create(SessionMode::Interactive)
        };

        let tool_defs = self.tools.definitions();

        let mut messages = vec![Message {
            role: "user".into(),
            content: user_query.to_string(),
        }];

        let mut iteration = 0usize;
        let mut all_metric_calls = Vec::new();
        let mut all_results = Vec::new();

        let final_response = loop {
            if iteration >= self.config.max_iterations {
                bail!("Agent reached maximum iterations ({MAX_ITERATIONS})");
            }
            iteration += 1;

            let response = self.model.reason(&messages, &tool_defs).await?;

            if response.tool_calls.is_empty() {
                let content = response.content;
                break content;
            }

            messages.push(Message {
                role: "assistant".into(),
                content: response.content,
            });

            let tool_calls = response.tool_calls;
            let mut any_failure = false;

            for tc in &tool_calls {
                let start = std::time::Instant::now();
                let result = self.tools.execute(&tc.name, tc.arguments.clone()).await;

                let duration_ms = start.elapsed().as_millis() as u64;
                all_metric_calls.push(MetricToolCall {
                    tool: tc.name.clone(),
                    success: result.success,
                    duration_ms,
                    summary: result.summary.chars().take(120).collect(),
                });
                if !result.success {
                    any_failure = true;
                }
                all_results.push(result);
            }

            if any_failure {
                let failed: Vec<String> = all_metric_calls
                    .iter()
                    .filter(|m| !m.success)
                    .map(|m| format!("{}: {}", m.tool, m.summary))
                    .collect();
                messages.push(Message {
                    role: "user".into(),
                    content: format!(
                        "The following tool calls failed:\n{}\nPlease retry or adjust your approach.",
                        failed.join("\n")
                    ),
                });
            } else {
                let summaries: Vec<String> = all_metric_calls
                    .iter()
                    .map(|m| {
                        format!(
                            "[{}] {} — {} ({})",
                            if m.success { "OK" } else { "FAIL" },
                            m.tool,
                            m.summary,
                            m.duration_ms
                        )
                    })
                    .collect();
                messages.push(Message {
                    role: "user".into(),
                    content: format!(
                        "Tool execution results:\n{}\n\nContinue with your analysis or provide a final answer.",
                        summaries.join("\n")
                    ),
                });
            };
        };

        {
            let mut store = self.session_store.lock().await;
            if let Some(session) = store.get_mut(&session_id) {
                session.add_turn(
                    user_query.to_string(),
                    Some(final_response.clone()),
                    None,
                    all_metric_calls,
                    &all_results,
                );
            }
        }

        Ok((final_response, session_id))
    }

    pub fn session_store(&self) -> Arc<Mutex<crate::session::SessionStore>> {
        self.session_store.clone()
    }
}
