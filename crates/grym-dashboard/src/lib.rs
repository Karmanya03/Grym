//! Read-only service foundation; scheduling and scan execution remain host-owned.

#![deny(unsafe_code)]

use axum::{Router, routing::get};

/// Builds a health-only router for deployment probes without exposing scan control.
pub fn router() -> Router {
    Router::new().route("/healthz", get(|| async { "ok" }))
}
