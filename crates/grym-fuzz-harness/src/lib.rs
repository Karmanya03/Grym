//! Local harness specification for operator-supplied binaries and source trees.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Inputs required to generate a local, reviewable fuzz-harness stub.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessSpec {
    /// Target function selected by an authorized operator.
    pub target_function: String,
    /// Language/runtime expected by the harness.
    pub runtime: String,
    /// Input type description inferred from a symbol or source signature.
    pub input_shape: String,
}

/// Renders a deliberately inert harness planning comment for review before generation.
pub fn planning_stub(spec: &HarnessSpec) -> String {
    format!(
        "// Review required before local harness generation\n// target: {}\n// runtime: {}\n// input: {}\n",
        spec.target_function, spec.runtime, spec.input_shape
    )
}
