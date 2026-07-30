//! Conservative timing profiles that never impair target defenses.

#![deny(unsafe_code)]

use grym_core::Deepness;
use serde::{Deserialize, Serialize};

/// Scheduler settings derived from an operator-selected depth profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestProfile {
    /// Maximum safe requests per second multiplier relative to scope limits.
    pub rate_multiplier_percent: u8,
    /// Fixed ceiling for scheduler jitter, recorded with a run seed by callers.
    pub max_jitter_millis: u32,
}

/// Produces a conservative scheduler profile without proxy manipulation or defense impairment.
pub const fn profile_for(deepness: Deepness) -> RequestProfile {
    match deepness {
        Deepness::Quick => RequestProfile {
            rate_multiplier_percent: 100,
            max_jitter_millis: 25,
        },
        Deepness::Standard => RequestProfile {
            rate_multiplier_percent: 75,
            max_jitter_millis: 150,
        },
        Deepness::Deep => RequestProfile {
            rate_multiplier_percent: 50,
            max_jitter_millis: 500,
        },
        Deepness::Paranoid => RequestProfile {
            rate_multiplier_percent: 20,
            max_jitter_millis: 2_000,
        },
    }
}
