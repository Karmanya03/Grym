//! Capability model for a future WASM-sandboxed plugin host.

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Explicit capabilities that a future WASM guest may request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCapability {
    /// Read normalized, redacted findings.
    ReadFindings,
    /// Submit a normalized finding for host-side validation.
    WriteFindings,
    /// Make a read-only request only through a host-owned `ScopedClient` handle.
    ScopedHttpRead,
}

/// Static manifest validated before a plugin is loaded into a sandbox.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PluginManifest {
    /// Stable plugin identifier.
    pub id: String,
    /// SemVer-compatible plugin version.
    pub version: String,
    /// Requested, reviewable capabilities.
    pub capabilities: Vec<PluginCapability>,
}

/// Rejects empty plugin manifests before a future runtime allocates guest resources.
pub fn validate_manifest(manifest: &PluginManifest) -> Result<(), String> {
    if manifest.id.trim().is_empty() || manifest.version.trim().is_empty() {
        return Err("plugin id and version are required".to_owned());
    }
    Ok(())
}
