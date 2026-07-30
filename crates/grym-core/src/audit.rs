//! Append-only audit records for scope decisions.

use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::Path,
    sync::Mutex,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{config::TechniqueTier, scope::DenialReason};

/// One decision made by the Scope Guard.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditEvent {
    /// Decision time in UTC.
    pub timestamp: DateTime<Utc>,
    /// Stable engagement identifier.
    pub engagement_id: String,
    /// SHA-256 hash of the scope configuration.
    pub scope_hash: String,
    /// Calling module identifier.
    pub module: String,
    /// Redacted outbound URL.
    pub target: String,
    /// Requested operational tier.
    pub technique_tier: TechniqueTier,
    /// Whether the action passed scope policy.
    pub allowed: bool,
    /// Optional reason for a denial.
    pub denial_reason: Option<DenialReason>,
}

/// Durable audit-sink write failure.
#[derive(Debug, Error)]
pub enum AuditError {
    /// File-system write failure.
    #[error("audit log write failed: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization failure.
    #[error("audit event serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Internal synchronization was poisoned after a prior panic.
    #[error("audit log lock is unavailable")]
    LockPoisoned,
}

/// Appends scope decisions. A failed write must fail the originating action closed.
pub trait AuditSink: Send + Sync {
    /// Records one allow or deny decision.
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError>;
}

/// JSONL audit sink suitable for engagement evidence retention.
#[derive(Debug)]
pub struct FileAuditLog {
    writer: Mutex<BufWriter<File>>,
}

impl FileAuditLog {
    /// Opens an append-only JSONL audit log and creates its parent directory if needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
        })
    }
}

impl AuditSink for FileAuditLog {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let mut writer = self.writer.lock().map_err(|_| AuditError::LockPoisoned)?;
        serde_json::to_writer(&mut *writer, event)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    }
}

/// In-memory sink for tests, embedding, and temporary dry runs.
#[derive(Debug, Default)]
pub struct MemoryAuditLog {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemoryAuditLog {
    /// Returns a point-in-time copy of recorded decisions.
    pub fn events(&self) -> Result<Vec<AuditEvent>, AuditError> {
        let events = self.events.lock().map_err(|_| AuditError::LockPoisoned)?;
        Ok(events.clone())
    }
}

impl AuditSink for MemoryAuditLog {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let mut events = self.events.lock().map_err(|_| AuditError::LockPoisoned)?;
        events.push(event.clone());
        Ok(())
    }
}
