//! AI model abstraction with Ollama backend.
//! Supports two presets: Lightweight (2B, CPU-only) and Reasoning (8B, GPU-recommended).

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Model capability tier — affects context window, temperature, and which tasks get routed where.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq)]
pub enum ModelTier {
    /// 2B-param model (Qwen 3.5). Runs on CPU, ~3 GB RAM. Best for tool calls, classification, reasoning.
    #[default]
    Lightweight,
    /// 8B-param model (mythos-sec, Gemma-4 based, security-tuned). Needs 8 GB RAM, GPU preferred. Used for deep reasoning, CVE hunting, pentesting.
    Reasoning,
}

impl ModelTier {
    pub fn model_name(&self) -> &'static str {
        match self {
            ModelTier::Lightweight => "qwen3.5:2b",
            ModelTier::Reasoning => "supergoatscriptguy/mythos-sec:8b",
        }
    }

    pub fn context_length(&self) -> usize {
        match self {
            ModelTier::Lightweight => 16384,
            ModelTier::Reasoning => 65536,
        }
    }

    pub fn temperature(&self) -> f32 {
        match self {
            ModelTier::Lightweight => 0.3,
            ModelTier::Reasoning => 0.7,
        }
    }
}

/// A chat message in the conversation.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

/// Response from the model after reasoning.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModelResponse {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub tokens_used: usize,
    pub reasoning: Option<String>,
}

/// A tool call request extracted from the model's output.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ToolCall {
    pub name: String,
    pub arguments: serde_json::Value,
}

/// Abstract interface for any reasoning model backend.
#[async_trait::async_trait]
pub trait ReasoningModel: Send + Sync {
    /// Send prompt with conversation history, get back a structured response.
    async fn reason(
        &self,
        messages: &[Message],
        tools: &[ToolDefinition],
    ) -> anyhow::Result<ModelResponse>;

    /// Get the model's tier.
    fn tier(&self) -> ModelTier;

    /// Check if the backend is reachable.
    async fn health(&self) -> bool;
}

/// Tool definition sent to the model so it knows what it can call.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// Ollama-based model backend.
pub struct OllamaModel {
    base_url: String,
    model_name: String,
    tier: ModelTier,
    client: reqwest::Client,
}

impl OllamaModel {
    pub fn new(tier: ModelTier) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build reqwest client: {e}"))?;
        Ok(Self {
            base_url: "http://127.0.0.1:11434".into(),
            model_name: tier.model_name().to_string(),
            tier,
            client,
        })
    }

    pub fn with_url(mut self, url: &str) -> Self {
        self.base_url = url.trim_end_matches('/').to_string();
        self
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn build_system_prompt(&self, tools: &[ToolDefinition]) -> String {
        let tool_descriptions: Vec<String> = tools
            .iter()
            .map(|t| {
                format!(
                    "- `{}`: {} (parameters: {})",
                    t.name,
                    t.description,
                    serde_json::to_string(&t.parameters).unwrap_or_default()
                )
            })
            .collect();

        format!(
            r#"You are GRYM-AI, an autonomous security assessment agent.
You have access to the following tools:

{}

Rules:
1. Think step by step. Output your reasoning inside <reasoning>...</reasoning> tags.
2. To call a tool, output a JSON block: {{"tool":"TOOL_NAME","args":{{...}}}}
3. Wait for the tool result before continuing.
4. When done, summarize findings clearly.
5. Never execute destructive actions without explicit user confirmation.
6. For CVE hunting: analyze differences, hypothesize variants, generate test payloads.
7. Always cite evidence from tool outputs.
"#,
            tool_descriptions.join("\n")
        )
    }
}

#[async_trait::async_trait]
impl ReasoningModel for OllamaModel {
    async fn reason(
        &self,
        messages: &[Message],
        tools: &[ToolDefinition],
    ) -> anyhow::Result<ModelResponse> {
        let system_prompt = self.build_system_prompt(tools);
        let mut ollama_messages =
            vec![serde_json::json!({"role": "system", "content": system_prompt})];
        for msg in messages {
            ollama_messages.push(serde_json::json!({
                "role": msg.role,
                "content": msg.content,
            }));
        }

        let payload = serde_json::json!({
            "model": self.model_name,
            "messages": ollama_messages,
            "stream": false,
            "options": {
                "temperature": self.tier.temperature(),
                "num_ctx": self.tier.context_length(),
            }
        });

        let resp = self
            .client
            .post(format!("{}/api/chat", self.base_url))
            .json(&payload)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Ollama API error {status}: {body}");
        }

        let data: serde_json::Value = resp.json().await?;
        let content = data["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        let tokens_used = data["eval_count"].as_u64().unwrap_or(0) as usize;

        // Extract reasoning from  tags
        let reasoning = extract_tag(&content, "reasoning");

        // Extract tool calls from JSON blocks
        let tool_calls = extract_tool_calls(&content);

        Ok(ModelResponse {
            content,
            tool_calls,
            tokens_used,
            reasoning,
        })
    }

    fn tier(&self) -> ModelTier {
        self.tier
    }

    async fn health(&self) -> bool {
        self.client
            .get(format!("{}/api/tags", self.base_url))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

fn extract_tag(content: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    if let (Some(s), Some(e)) = (content.find(&open), content.find(&close)) {
        let inner = &content[s + open.len()..e];
        if !inner.is_empty() {
            return Some(inner.trim().to_string());
        }
    }
    None
}

pub fn extract_tool_calls(content: &str) -> Vec<ToolCall> {
    let re = regex::Regex::new(
        r#"\{"tool"\s*:\s*"([^"]+)"\s*,\s*"args"\s*:\s*(\{(?:[^{}]|(?:\{[^{}]*\}))*\})\s*\}"#,
    )
    .ok();
    let re = match re {
        Some(r) => r,
        None => return Vec::new(),
    };

    re.captures_iter(content)
        .filter_map(|cap| {
            let name = cap.get(1)?.as_str().to_string();
            let args_str = cap.get(2)?.as_str();
            let args: serde_json::Value = serde_json::from_str(args_str).ok()?;
            Some(ToolCall {
                name,
                arguments: args,
            })
        })
        .collect()
}

/// Check if Ollama has the required models. If not, return install instructions.
pub async fn ensure_models(client: &reqwest::Client, base_url: &str) -> anyhow::Result<()> {
    let resp = client.get(format!("{}/api/tags", base_url)).send().await?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "Ollama not reachable at {base_url}. Install Ollama from https://ollama.com then run:\n\
             ollama pull qwen3.5:2b\n\
             ollama pull supergoatscriptguy/mythos-sec:8b"
        );
    }

    let models: serde_json::Value = resp.json().await?;
    let available: Vec<String> = models["models"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m["name"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    for needed in &["qwen3.5:2b", "supergoatscriptguy/mythos-sec:8b"] {
        if !available.iter().any(|a| a.starts_with(needed)) {
            tracing::warn!("Model '{needed}' not found. Run: ollama pull {needed}");
        }
    }

    Ok(())
}
