//! Safety-critical GRYM primitives.
//!
//! This crate owns scope parsing, authorization, audit decisions, redaction,
//! rate limiting, and the sole HTTP transport exposed to GRYM modules.

#![deny(unsafe_code)]

pub mod audit;
pub mod config;
pub mod finding;
pub mod redaction;
pub mod scope;
pub mod transport;

pub use audit::{AuditEvent, AuditSink, FileAuditLog, MemoryAuditLog};
pub use config::{Deepness, ScopeConfig, TechniqueTier};
pub use finding::{AssetRef, Confidence, Evidence, Finding, Severity};
pub use scope::{DenialReason, OperatorAttestation, ScopeError, ScopeGuard, TargetRule};
pub use transport::{HttpResponseSnapshot, ScopedClient, ScopedClientError};
