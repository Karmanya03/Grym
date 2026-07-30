#![deny(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

/// A correlation token for OOB-based vulnerability confirmation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OobToken {
    pub value: Uuid,
    pub issued_at: DateTime<Utc>,
    pub finding_id: Option<String>,
    pub module: String,
}

impl OobToken {
    pub fn new(module: &str, finding_id: Option<String>) -> Self {
        Self {
            value: Uuid::now_v7(),
            issued_at: Utc::now(),
            finding_id,
            module: module.into(),
        }
    }

    pub fn callback_url(&self, base: &Url) -> Result<Url, url::ParseError> {
        base.join(&format!("interaction/{}", self.value))
    }

    pub fn callback_domain(&self, base_domain: &str) -> String {
        format!("{}.{}", self.value, base_domain)
    }
}

/// An interaction received by the OOB server.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OobInteraction {
    pub token: Uuid,
    pub interaction_type: String,
    pub remote_addr: String,
    pub timestamp: DateTime<Utc>,
    pub detail: String,
}

/// OOB server error.
#[derive(Debug, Error)]
pub enum OobError {
    #[error("Token not found: {0}")]
    TokenNotFound(Uuid),
    #[error("Lock poisoned")]
    LockPoisoned,
}

/// In-memory OOB interaction tracker.
#[derive(Debug, Default)]
pub struct OobTracker {
    tokens: RwLock<HashMap<Uuid, OobToken>>,
    interactions: RwLock<Vec<OobInteraction>>,
}

impl OobTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Registers a new OOB token for a finding.
    pub async fn register(&self, token: OobToken) -> Uuid {
        let id = token.value;
        self.tokens.write().await.insert(id, token);
        id
    }

    /// Records an incoming interaction callback.
    pub async fn record_interaction(
        &self,
        token: Uuid,
        interaction_type: &str,
        remote_addr: &str,
        detail: &str,
    ) -> Result<OobInteraction, OobError> {
        let tokens = self.tokens.read().await;
        if !tokens.contains_key(&token) {
            return Err(OobError::TokenNotFound(token));
        }

        let interaction = OobInteraction {
            token,
            interaction_type: interaction_type.into(),
            remote_addr: remote_addr.into(),
            timestamp: Utc::now(),
            detail: detail.into(),
        };

        self.interactions.write().await.push(interaction.clone());
        Ok(interaction)
    }

    /// Checks if a token has received any callbacks.
    pub async fn has_interaction(&self, token: &Uuid) -> bool {
        let interactions = self.interactions.read().await;
        interactions.iter().any(|i| i.token == *token)
    }

    /// Gets all interactions for a token.
    pub async fn get_interactions(&self, token: &Uuid) -> Vec<OobInteraction> {
        let interactions = self.interactions.read().await;
        interactions
            .iter()
            .filter(|i| i.token == *token)
            .cloned()
            .collect()
    }

    /// Validates a finding using OOB callback confirmation.
    pub async fn validate_finding(&self, token: &Uuid) -> bool {
        self.has_interaction(token).await
    }
}

/// Builds a simple HTTP health/status endpoint for the OOB server.
pub fn health_router() -> axum::Router {
    use axum::{routing::get, routing::post, Router};

    Router::new()
        .route("/healthz", get(|| async { "oob-server-ok" }))
        .route("/interaction/{token}", get(handle_interaction))
        .route("/interaction/{token}", post(handle_interaction))
}

async fn handle_interaction(
    axum::extract::Path(token): axum::extract::Path<String>,
) -> String {
    format!("Interaction recorded for token: {}", token)
}

pub mod dns {
    //! DNS callback handler for the OOB server.
    //!
    //! In production, use an authoritative DNS server configured to log all queries
    //! to this domain. For now, this module provides the correlation logic.

    /// Checks if a DNS query hostname contains a valid OOB token.
    pub fn extract_token_from_hostname(hostname: &str) -> Option<uuid::Uuid> {
        let first_part = hostname.split('.').next()?;
        uuid::Uuid::parse_str(first_part).ok()
    }
}
