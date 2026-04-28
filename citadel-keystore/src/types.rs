// SPDX-License-Identifier: AGPL-3.0-or-later
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
// Secret key material (typed, compile-time safe)
// ---------------------------------------------------------------------------

/// Typed representation of a stored secret key's material.
///
/// This enum makes the three distinct states of a stored secret key
/// explicit at the type level — a plain `String` cannot express these
/// invariants, and callers that mix them up produce silent bugs.
///
/// # Serialization
///
/// Serializes as a plain JSON string (backward compatible with the existing
/// `"secret_key_hex"` field on disk):
/// - `Encrypted(s)` → `s` (always starts with `"enc:"`)
/// - `Plaintext(s)` → `s` (hex string, dev/test only)
/// - `Destroyed`    → `"DESTROYED"`
///
/// Deserialization detects the variant by inspecting the string prefix.
#[derive(Clone, Debug, PartialEq)]
pub enum SecretKeyMaterial {
    /// AES-256-GCM encrypted at rest.
    /// Format: `"enc:" + hex(nonce[12]) + hex(aes_gcm_ciphertext)`.
    /// Only produced when `CITADEL_MASTER_KEY` is set.
    Encrypted(String),
    /// Plain hex-encoded secret key bytes.
    /// **Development and test use only.** Never acceptable in production.
    /// Produced only when `CITADEL_MASTER_KEY` is absent and
    /// `CITADEL_ALLOW_PLAINTEXT_KEYS=1` is set.
    Plaintext(String),
    /// Key material has been purged by `Keystore::destroy()`.
    /// The material is gone; this slot exists only to record that destruction occurred.
    Destroyed,
}

impl SecretKeyMaterial {
    /// Returns `true` if the material is AES-GCM encrypted (wrapped).
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted(_))
    }
    /// Returns `true` if the material is wrapped (alias for `is_encrypted`).
    pub fn is_wrapped(&self) -> bool {
        self.is_encrypted()
    }
    /// Returns `true` if the material is plaintext (dev/test only).
    pub fn is_plaintext(&self) -> bool {
        matches!(self, Self::Plaintext(_))
    }
    /// Returns `true` if the key has been destroyed.
    pub fn is_destroyed(&self) -> bool {
        matches!(self, Self::Destroyed)
    }

    /// Zeroize the inner key bytes (if any) and transition to `Destroyed`.
    ///
    /// Called by `Keystore::destroy()` before writing the updated metadata.
    /// Clears the heap allocation of the inner `String` so the key bytes
    /// are not recoverable from process memory after this call.
    pub fn zeroize_and_destroy(&mut self) {
        use zeroize::Zeroize;
        match self {
            Self::Encrypted(s) | Self::Plaintext(s) => s.zeroize(),
            Self::Destroyed => {}
        }
        *self = Self::Destroyed;
    }
}

impl serde::Serialize for SecretKeyMaterial {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Encrypted(v) | Self::Plaintext(v) => s.serialize_str(v),
            Self::Destroyed => s.serialize_str("DESTROYED"),
        }
    }
}

impl<'de> serde::Deserialize<'de> for SecretKeyMaterial {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        if raw == "DESTROYED" {
            Ok(Self::Destroyed)
        } else if raw.starts_with("enc:") {
            Ok(Self::Encrypted(raw))
        } else {
            // Legacy plaintext hex or unrecognized format — treat as Plaintext.
            Ok(Self::Plaintext(raw))
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
    /// Secret key material — one of three typed states:
    ///
    /// - `Encrypted(s)` → AES-GCM wrapped; `s` starts with `"enc:"`. Use when
    ///   `CITADEL_MASTER_KEY` is set.
    /// - `Plaintext(s)` → raw hex-encoded bytes. **Development only.**
    ///   Never acceptable in production.
    /// - `Destroyed`    → material has been purged.
    ///
    /// Use `KeyVersion::is_wrapped()` / `is_plaintext()` for readable checks.
    /// The JSON field name is `"secret_key_hex"` for on-disk backward compatibility.
    #[serde(rename = "secret_key_hex")]
    pub secret_key_material: SecretKeyMaterial,

    /// ID of the key that wrapped (encrypted) this secret key material, if any.
    ///
    /// - `None` = wrapped by the external system master key (`CITADEL_MASTER_KEY`).
    ///   This is the current mode — master key is outside the Citadel key hierarchy.
    /// - `Some(key_id)` = wrapped by a Citadel KEK. Required for the full
    ///   Root → Domain → KEK → DEK cryptographic hierarchy.
    ///
    /// This field is `None` in all keys created before it was added.
    /// Populated at key generation / rotation time.
    #[serde(default)]
    pub wrapping_key_id: Option<String>,

    /// The AES-GCM nonce used when wrapping this key, stored explicitly for
    /// audit and inspection purposes (hex, 24 chars = 12 bytes).
    ///
    /// This is identical to the nonce embedded inside `secret_key_material`
    /// when `is_wrapped() == true`, but exposed here so tooling can inspect
    /// it without parsing the material string.
    ///
    /// `None` for plaintext or destroyed keys.
    #[serde(default)]
    pub wrap_nonce_hex: Option<String>,
}

impl KeyVersion {
    /// Returns `true` if this version's secret key is AES-GCM wrapped at rest.
    ///
    /// Delegates to `SecretKeyMaterial::is_wrapped()` — there is no separate
    /// boolean field to avoid dual source of truth.
    pub fn is_wrapped(&self) -> bool {
        self.secret_key_material.is_wrapped()
    }

    /// Returns `true` if this version's secret key is stored as plaintext.
    ///
    /// Plaintext storage is a security violation in production.
    /// Only permitted when `CITADEL_ALLOW_PLAINTEXT_KEYS=1` is explicitly set.
    pub fn is_plaintext(&self) -> bool {
        self.secret_key_material.is_plaintext()
    }

    /// Returns `true` if this version's key material has been destroyed.
    pub fn is_destroyed(&self) -> bool {
        self.secret_key_material.is_destroyed()
    }

    /// Validate internal consistency of this key version.
    ///
    /// Checks that metadata fields are consistent with `secret_key_material`.
    /// Returns `Ok(())` if consistent, or an error string describing the violation.
    ///
    /// # Invariants checked
    ///
    /// - Wrapped keys must have a `wrap_nonce_hex`.
    /// - Plaintext/destroyed keys must not have a `wrap_nonce_hex`.
    pub fn validate(&self) -> Result<(), String> {
        match &self.secret_key_material {
            SecretKeyMaterial::Encrypted(_) => {
                if self.wrap_nonce_hex.is_none() {
                    return Err(format!(
                        "key version {} is wrapped but wrap_nonce_hex is missing",
                        self.version
                    ));
                }
            }
            SecretKeyMaterial::Plaintext(_) | SecretKeyMaterial::Destroyed => {
                if self.wrap_nonce_hex.is_some() {
                    return Err(format!(
                        "key version {} is not wrapped but wrap_nonce_hex is present",
                        self.version
                    ));
                }
            }
        }
        Ok(())
    }
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
        self.versions
            .iter()
            .find(|v| v.version == self.current_version)
    }

    /// Duration since activation (if activated).
    pub fn age(&self) -> Option<chrono::Duration> {
        self.activated_at.map(|a| Utc::now() - a)
    }
}
