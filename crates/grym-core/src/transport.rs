//! Scope-enforcing HTTP transport with bounded evidence capture.

use std::{
    collections::BTreeMap,
    num::NonZeroU32,
    sync::{Arc, Mutex},
};

use futures_util::StreamExt;
use governor::{DefaultDirectRateLimiter, DefaultKeyedRateLimiter, Quota, RateLimiter};
use reqwest::{StatusCode, redirect::Policy};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::{
    config::{SafetyConfig, TechniqueTier},
    scope::{ScopeError, ScopeGuard},
};

/// Bounded, serializable HTTP response evidence.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpResponseSnapshot {
    /// Final in-scope URL after approved redirects.
    pub url: String,
    /// HTTP status code as an integer.
    pub status: u16,
    /// Response headers normalized to lowercase names.
    pub headers: BTreeMap<String, String>,
    /// Lossy UTF-8 body, capped by `limits.max_response_bytes`.
    pub body: String,
}

/// Fail-closed transport error.
#[derive(Debug, Error)]
pub enum ScopedClientError {
    /// Scope Guard denied the current URL or could not write its audit event.
    #[error(transparent)]
    Scope(#[from] ScopeError),
    /// HTTP request or body-stream failure.
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
    /// Response body exceeded the configured evidence cap.
    #[error("response body exceeded configured {max_bytes}-byte limit")]
    ResponseTooLarge {
        /// Maximum accepted response body size.
        max_bytes: usize,
    },
    /// A redirect did not include a valid, resolvable Location header.
    #[error("invalid redirect from {from}")]
    InvalidRedirect {
        /// URL that returned the malformed redirect.
        from: String,
    },
    /// The redirect chain exceeded the engagement's configured limit.
    #[error("redirect limit exceeded for {url}")]
    RedirectLimitExceeded {
        /// Last URL evaluated.
        url: String,
    },
    /// Circuit breaker stopped new traffic after instability or WAF blocking.
    #[error("circuit breaker is open: {reason}")]
    CircuitOpen {
        /// Human-readable trigger condition.
        reason: String,
    },
    /// Reqwest client construction failed.
    #[error("unable to construct scoped HTTP client: {0}")]
    Build(reqwest::Error),
}

/// A token-bucket limiter shared across every outbound scoped request.
#[derive(Debug)]
struct RequestLimiter {
    global: Arc<DefaultDirectRateLimiter>,
    per_host: Arc<DefaultKeyedRateLimiter<String>>,
}

impl RequestLimiter {
    fn new(global: u32, per_host: u32) -> Self {
        let global_quota = Quota::per_second(NonZeroU32::new(global).unwrap_or(NonZeroU32::MIN));
        let host_quota = Quota::per_second(NonZeroU32::new(per_host).unwrap_or(NonZeroU32::MIN));
        Self {
            global: Arc::new(RateLimiter::direct(global_quota)),
            per_host: Arc::new(RateLimiter::keyed(host_quota)),
        }
    }

    async fn wait(&self, host: &str) {
        self.global.until_ready().await;
        self.per_host
            .until_key_ready(&host.to_ascii_lowercase())
            .await;
    }
}

/// Circuit-breaker state accumulated from scoped HTTP responses.
#[derive(Debug)]
struct CircuitBreaker {
    safety: SafetyConfig,
    state: Mutex<CircuitState>,
}

#[derive(Debug, Default)]
struct CircuitState {
    total: u32,
    blocked: u32,
    consecutive_server_errors: u32,
    open_reason: Option<String>,
}

impl CircuitBreaker {
    fn new(safety: SafetyConfig) -> Self {
        Self {
            safety,
            state: Mutex::new(CircuitState::default()),
        }
    }

    fn ensure_closed(&self) -> Result<(), ScopedClientError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ScopedClientError::CircuitOpen {
                reason: "circuit-breaker state lock is unavailable".to_owned(),
            })?;
        match &state.open_reason {
            Some(reason) => Err(ScopedClientError::CircuitOpen {
                reason: reason.clone(),
            }),
            None => Ok(()),
        }
    }

    fn observe(&self, status: StatusCode) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.total = state.total.saturating_add(1);
        if matches!(status.as_u16(), 403 | 429) {
            state.blocked = state.blocked.saturating_add(1);
        }
        if status.is_server_error() {
            state.consecutive_server_errors = state.consecutive_server_errors.saturating_add(1);
        } else {
            state.consecutive_server_errors = 0;
        }
        if state.consecutive_server_errors >= self.safety.server_error_threshold {
            state.open_reason = Some(format!(
                "{} consecutive 5xx responses",
                state.consecutive_server_errors
            ));
            return;
        }
        if state.total >= 10
            && state.blocked.saturating_mul(100) / state.total
                >= u32::from(self.safety.block_rate_threshold_percent)
        {
            state.open_reason = Some(format!(
                "{}% WAF-style block rate over {} responses",
                state.blocked.saturating_mul(100) / state.total,
                state.total
            ));
        }
    }
}

/// The only HTTP client intended for GRYM modules.
///
/// Redirect handling, scope authorization, audit logging, token-bucket waits,
/// bounded response capture, and circuit breaking happen inside this type.
#[derive(Debug)]
pub struct ScopedClient {
    guard: Arc<ScopeGuard>,
    client: reqwest::Client,
    limiter: RequestLimiter,
    circuit_breaker: CircuitBreaker,
}

impl ScopedClient {
    /// Creates a client that cannot perform HTTP work outside the supplied immutable scope.
    pub fn new(guard: Arc<ScopeGuard>) -> Result<Self, ScopedClientError> {
        let global_rate = guard.config().limits.max_requests_per_second_global;
        let host_rate = guard.config().limits.max_requests_per_second_per_host;
        let safety = guard.config().safety.clone();
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .user_agent("grym/0.1 (authorized-security-assessment)")
            .build()
            .map_err(ScopedClientError::Build)?;
        Ok(Self {
            guard,
            client,
            limiter: RequestLimiter::new(global_rate, host_rate),
            circuit_breaker: CircuitBreaker::new(safety),
        })
    }

    /// Gets an in-scope URL and safely follows only redirects that independently pass Scope Guard.
    pub async fn get(
        &self,
        module: &str,
        url: Url,
        tier: TechniqueTier,
    ) -> Result<HttpResponseSnapshot, ScopedClientError> {
        let mut current = url;
        for redirect_count in 0..=self.guard.config().safety.max_redirects {
            self.circuit_breaker.ensure_closed()?;
            self.guard.authorize_url(module, &current, tier)?;
            let host = current.host_str().unwrap_or_default();
            self.limiter.wait(host).await;

            let response = self.client.get(current.clone()).send().await?;
            let status = response.status();
            self.circuit_breaker.observe(status);
            if status.is_redirection() {
                if redirect_count == self.guard.config().safety.max_redirects {
                    return Err(ScopedClientError::RedirectLimitExceeded {
                        url: current.into(),
                    });
                }
                let Some(location) = response.headers().get(reqwest::header::LOCATION) else {
                    return Err(ScopedClientError::InvalidRedirect {
                        from: current.into(),
                    });
                };
                let location =
                    location
                        .to_str()
                        .map_err(|_| ScopedClientError::InvalidRedirect {
                            from: current.to_string(),
                        })?;
                current =
                    current
                        .join(location)
                        .map_err(|_| ScopedClientError::InvalidRedirect {
                            from: current.to_string(),
                        })?;
                continue;
            }
            return Self::snapshot(response, self.guard.config().limits.max_response_bytes).await;
        }
        Err(ScopedClientError::RedirectLimitExceeded {
            url: current.into(),
        })
    }

    async fn snapshot(
        response: reqwest::Response,
        max_bytes: usize,
    ) -> Result<HttpResponseSnapshot, ScopedClientError> {
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes as u64)
        {
            return Err(ScopedClientError::ResponseTooLarge { max_bytes });
        }
        let url = response.url().to_string();
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_ascii_lowercase(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>();
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if body.len().saturating_add(chunk.len()) > max_bytes {
                return Err(ScopedClientError::ResponseTooLarge { max_bytes });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpResponseSnapshot {
            url,
            status,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }
}

#[cfg(test)]
mod send_sync_tests {
    use super::*;
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn scoped_client_is_send_sync() {
        assert_send::<ScopedClient>();
        assert_sync::<ScopedClient>();
    }

    #[test]
    fn request_limiter_is_send_sync() {
        assert_send::<RequestLimiter>();
        assert_sync::<RequestLimiter>();
    }

    #[test]
    fn circuit_breaker_is_send_sync() {
        assert_send::<CircuitBreaker>();
        assert_sync::<CircuitBreaker>();
    }
}
