//! Binary-analysis contracts; parser backends stay optional and feature-gated.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Portable binary hardening observations normalized for findings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BinaryHardeningProfile {
    /// Input artifact path supplied by the authorized operator.
    pub artifact: String,
    /// Whether executable memory protection was observed.
    pub nx_enabled: Option<bool>,
    /// Whether position-independent executable behavior was observed.
    pub pie_enabled: Option<bool>,
    /// Whether stack-canary metadata was observed.
    pub stack_canary: Option<bool>,
    /// Whether RELRO metadata was observed where applicable.
    pub relro: Option<String>,
}
