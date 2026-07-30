//! Mobile-artifact analysis contracts; decompiler bridges are deliberately optional.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

/// A manifest or plist signal mapped by later analyzers to a Mobile Top 10 category.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MobileManifestSignal {
    /// APK or IPA artifact path supplied by the operator.
    pub artifact: String,
    /// Mobile Top 10 mapping-pack identifier.
    pub category: String,
    /// Evidence summary extracted from the package metadata.
    pub summary: String,
}
