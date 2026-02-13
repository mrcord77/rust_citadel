//! Error types for the keystore.

use crate::types::{KeyId, KeyState};
use std::fmt;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Top-level keystore error
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum KeystoreError {
    KeyNotFound(KeyId),
    InvalidTransition { id: KeyId, from: KeyState, to: KeyState },
    PolicyViolation(String),
    StorageError(String),
    EnvelopeError(String),
    DuplicateKey(KeyId),
    KeyDestroyed(KeyId),
    NotActive(KeyId),
    NotDecryptable(KeyId),
    PolicyNotFound(String),
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotFound(id) => write!(f, "key not found: {}", id),
            Self::InvalidTransition { id, from, to } => {
                write!(f, "invalid transition for {}: {} → {}", id, from, to)
            }
            Self::PolicyViolation(msg) => write!(f, "policy violation: {}", msg),
            Self::StorageError(msg) => write!(f, "storage error: {}", msg),
            Self::EnvelopeError(msg) => write!(f, "envelope error: {}", msg),
            Self::DuplicateKey(id) => write!(f, "duplicate key: {}", id),
            Self::KeyDestroyed(id) => write!(f, "key destroyed: {}", id),
            Self::NotActive(id) => write!(f, "key not active: {}", id),
            Self::NotDecryptable(id) => write!(f, "key cannot decrypt: {}", id),
            Self::PolicyNotFound(id) => write!(f, "policy not found: {}", id),
        }
    }
}

impl std::error::Error for KeystoreError {}

// ---------------------------------------------------------------------------
// Specific operation errors (type-safe)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct GenerateError(pub KeystoreError);
impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}
impl std::error::Error for GenerateError {}
impl From<KeystoreError> for GenerateError {
    fn from(e: KeystoreError) -> Self { Self(e) }
}

#[derive(Debug)]
pub struct LifecycleError(pub KeystoreError);
impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}
impl std::error::Error for LifecycleError {}
impl From<KeystoreError> for LifecycleError {
    fn from(e: KeystoreError) -> Self { Self(e) }
}

#[derive(Debug)]
pub struct RotateError(pub KeystoreError);
impl fmt::Display for RotateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}
impl std::error::Error for RotateError {}
impl From<KeystoreError> for RotateError {
    fn from(e: KeystoreError) -> Self { Self(e) }
}

#[derive(Debug)]
pub struct ExpireError(pub KeystoreError);
impl fmt::Display for ExpireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}
impl std::error::Error for ExpireError {}
impl From<KeystoreError> for ExpireError {
    fn from(e: KeystoreError) -> Self { Self(e) }
}

#[derive(Debug)]
pub struct EncryptError(pub String);
impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "encrypt: {}", self.0) }
}
impl std::error::Error for EncryptError {}

#[derive(Debug)]
pub struct DecryptError(pub String);
impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "decrypt: {}", self.0) }
}
impl std::error::Error for DecryptError {}

// ---------------------------------------------------------------------------
// Expiration decision types
// ---------------------------------------------------------------------------

/// Why a key needs expiration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpirationSource {
    /// ROTATED key past its grace period.
    GracePeriodExpired,
    /// ACTIVE key past its max_lifetime.
    MaxLifetimeExceeded,
}

/// Result of checking whether a key should expire.
#[derive(Clone, Debug)]
pub enum ExpirationDecision {
    /// Key does not need expiration.
    NotNeeded,
    /// Key should be expired now.
    Required {
        reason: String,
        source: ExpirationSource,
    },
    /// Key will expire soon (warning threshold).
    Warning {
        reason: String,
        remaining: Duration,
        source: ExpirationSource,
    },
}

impl ExpirationDecision {
    pub fn is_required(&self) -> bool {
        matches!(self, Self::Required { .. })
    }

    pub fn is_warning(&self) -> bool {
        matches!(self, Self::Warning { .. })
    }

    pub fn source(&self) -> Option<&ExpirationSource> {
        match self {
            Self::Required { source, .. } => Some(source),
            Self::Warning { source, .. } => Some(source),
            Self::NotNeeded => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Destroy decision
// ---------------------------------------------------------------------------

/// Result of checking whether a key can be destroyed.
#[derive(Clone, Debug)]
pub enum DestroyDecision {
    /// Safe to destroy.
    Safe { reason: String },
    /// Blocked — key still in use.
    Blocked { reason: String },
}

impl DestroyDecision {
    pub fn is_safe(&self) -> bool {
        matches!(self, Self::Safe { .. })
    }
}

// ---------------------------------------------------------------------------
// Expiration report (bulk operations)
// ---------------------------------------------------------------------------

/// Report from bulk expiration processing.
#[derive(Clone, Debug, Default)]
pub struct ExpirationReport {
    pub expired: Vec<(KeyId, ExpirationSource)>,
    pub warnings: Vec<(KeyId, String, Duration)>,
    pub failed: Vec<(KeyId, String)>,
    pub skipped: usize,
}
