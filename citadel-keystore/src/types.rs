//! Core types: KeyId, KeyType, KeyState, KeyMetadata, KeyVersion.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Key identifiers
// ---------------------------------------------------------------------------

/// Unique key identifier (hex-encoded random bytes).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(String);

impl KeyId {
    /// Create a new random KeyId.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// Create from a specific string (for testing/deterministic use).
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

use rand_core::RngCore;

/// Policy identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyId(String);

impl PolicyId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Key classification
// ---------------------------------------------------------------------------

/// Position in the key hierarchy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// Root key — offline, protects the entire hierarchy.
    Root,
    /// Domain key — per-tenant or per-environment.
    Domain,
    /// Key-encrypting key — wraps DEKs.
    KeyEncrypting,
    /// Data-encrypting key — directly encrypts user data.
    DataEncrypting,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Root => write!(f, "ROOT"),
            KeyType::Domain => write!(f, "DOMAIN"),
            KeyType::KeyEncrypting => write!(f, "KEK"),
            KeyType::DataEncrypting => write!(f, "DEK"),
        }
    }
}

// ---------------------------------------------------------------------------
// Key lifecycle state machine
// ---------------------------------------------------------------------------

/// Key lifecycle state.
///
/// ```text
/// PENDING → ACTIVE ↔ ROTATED → EXPIRED → DESTROYED
///             │
///             └──→ REVOKED
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Generated but not yet activated.
    Pending,
    /// Active — can encrypt and decrypt.
    Active,
    /// Rotated — superseded by a new version. Can still decrypt (grace period).
    Rotated,
    /// Expired — can no longer encrypt or decrypt.
    Expired,
    /// Revoked — emergency deactivation. Cannot be reactivated.
    Revoked,
    /// Destroyed — key material has been purged.
    Destroyed,
}

impl KeyState {
    /// Whether this state allows encryption.
    pub fn can_encrypt(&self) -> bool {
        matches!(self, KeyState::Active)
    }

    /// Whether this state allows decryption.
    pub fn can_decrypt(&self) -> bool {
        matches!(self, KeyState::Active | KeyState::Rotated)
    }

    /// Valid transitions from this state.
    pub fn valid_transitions(&self) -> &[KeyState] {
        match self {
            KeyState::Pending => &[KeyState::Active, KeyState::Destroyed],
            KeyState::Active => &[KeyState::Rotated, KeyState::Revoked, KeyState::Expired],
            KeyState::Rotated => &[KeyState::Expired],
            KeyState::Expired => &[KeyState::Destroyed],
            KeyState::Revoked => &[KeyState::Destroyed],
            KeyState::Destroyed => &[],
        }
    }

    /// Check if transitioning to `target` is valid.
    pub fn can_transition_to(&self, target: KeyState) -> bool {
        self.valid_transitions().contains(&target)
    }
}

impl fmt::Display for KeyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyState::Pending => write!(f, "PENDING"),
            KeyState::Active => write!(f, "ACTIVE"),
            KeyState::Rotated => write!(f, "ROTATED"),
            KeyState::Expired => write!(f, "EXPIRED"),
            KeyState::Revoked => write!(f, "REVOKED"),
            KeyState::Destroyed => write!(f, "DESTROYED"),
        }
    }
}

// ---------------------------------------------------------------------------
// Key version (tracks rotation history)
// ---------------------------------------------------------------------------

/// A specific version of a key (created on generation or rotation).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyVersion {
    /// Version number (1, 2, 3, ...).
    pub version: u32,
    /// When this version was created.
    pub created_at: DateTime<Utc>,
    /// Serialized public key bytes (hex).
    pub public_key_hex: String,
    /// Serialized secret key bytes (hex), encrypted by parent KEK.
    /// For Root keys, this is wrapped externally.
    pub secret_key_hex: String,
}

// ---------------------------------------------------------------------------
// Key metadata
// ---------------------------------------------------------------------------

/// Complete metadata for a managed key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Unique identifier.
    pub id: KeyId,
    /// Human-readable name.
    pub name: String,
    /// Position in hierarchy.
    pub key_type: KeyType,
    /// Current lifecycle state.
    pub state: KeyState,
    /// Associated policy (if any).
    pub policy_id: Option<PolicyId>,
    /// Parent key in the hierarchy (None for root).
    pub parent_id: Option<KeyId>,
    /// When this key was first created.
    pub created_at: DateTime<Utc>,
    /// When the state last changed.
    pub updated_at: DateTime<Utc>,
    /// When the key was activated.
    pub activated_at: Option<DateTime<Utc>>,
    /// When the key was rotated (entered ROTATED state).
    pub rotated_at: Option<DateTime<Utc>>,
    /// When the key was revoked.
    pub revoked_at: Option<DateTime<Utc>>,
    /// When the key was destroyed.
    pub destroyed_at: Option<DateTime<Utc>>,
    /// All versions (current + historical).
    pub versions: Vec<KeyVersion>,
    /// Current (latest) version number.
    pub current_version: u32,
    /// Number of times this key has been used for encryption.
    pub usage_count: u64,
    /// Arbitrary metadata tags.
    pub tags: std::collections::HashMap<String, String>,
}

impl KeyMetadata {
    /// Get the current (latest) version.
    pub fn current_key_version(&self) -> Option<&KeyVersion> {
        self.versions.iter().find(|v| v.version == self.current_version)
    }

    /// Duration since activation (if activated).
    pub fn age(&self) -> Option<chrono::Duration> {
        self.activated_at.map(|a| Utc::now() - a)
    }
}
