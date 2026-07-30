//! Thread-safe in-memory finding store used behind the future durable-store adapter.

#![deny(unsafe_code)]

use std::sync::RwLock;

use grym_core::Finding;
use thiserror::Error;

/// Store access failure.
#[derive(Debug, Error)]
pub enum StorageError {
    /// A previous panic poisoned the in-memory store lock.
    #[error("finding store lock is unavailable")]
    LockPoisoned,
}

/// Minimal store contract designed for later `redb` or SQLite implementations.
pub trait FindingStore: Send + Sync {
    /// Adds one fully normalized finding.
    fn insert(&self, finding: Finding) -> Result<(), StorageError>;
    /// Returns a snapshot ordered by insertion time.
    fn all(&self) -> Result<Vec<Finding>, StorageError>;
}

/// Fast in-memory store for tests and short-lived embedded use.
#[derive(Debug, Default)]
pub struct MemoryFindingStore {
    findings: RwLock<Vec<Finding>>,
}

impl FindingStore for MemoryFindingStore {
    fn insert(&self, finding: Finding) -> Result<(), StorageError> {
        let mut findings = self
            .findings
            .write()
            .map_err(|_| StorageError::LockPoisoned)?;
        findings.push(finding);
        Ok(())
    }

    fn all(&self) -> Result<Vec<Finding>, StorageError> {
        let findings = self
            .findings
            .read()
            .map_err(|_| StorageError::LockPoisoned)?;
        Ok(findings.clone())
    }
}
