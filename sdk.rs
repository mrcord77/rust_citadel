//! Citadel SDK — Public API Surface
//!
//! This module defines the **frozen** public interface for Citadel.
//! Everything else is internal implementation detail.
//!
//! # API Stability Promise
//!
//! These exports are stable across minor versions:
//! - `Citadel` — main encryption engine
//! - `PublicKey`, `SecretKey` — key types with serialization
//! - `Aad`, `Context` — typed metadata (prevents misuse)
//! - `SealError`, `OpenError` — uniform error types
//!
//! Internal modules (`wire`, `kdf`, `aead`, `kem`) are NOT part of the
//! public API and may change without notice.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

// Re-export only what customers need
pub use crate::error::DecryptionError as OpenError;
pub use crate::error::EncodingError as SealError;
pub use crate::kem::{PublicKey, SecretKey};

// ---------------------------------------------------------------------------
// Typed AAD and Context (prevents misuse)
// ---------------------------------------------------------------------------

/// Additional Authenticated Data — bound to ciphertext but not encrypted.
///
/// Use the builder methods to construct AAD for common use cases.
/// This prevents accidental misuse and standardizes behavior across deployments.
#[derive(Clone, Debug)]
pub struct Aad {
    inner: Vec<u8>,
}

impl Aad {
    /// Raw AAD from arbitrary bytes.
    ///
    /// Prefer the typed constructors when possible.
    pub fn raw(bytes: &[u8]) -> Self {
        Self {
            inner: bytes.to_vec(),
        }
    }

    /// Empty AAD (still authenticated, just zero-length).
    pub fn empty() -> Self {
        Self { inner: Vec::new() }
    }

    /// AAD for object storage (S3, GCS, etc.)
    ///
    /// Format: `storage|{bucket}|{object_id}|v{version}`
    pub fn for_storage(bucket: &str, object_id: &str, version: u64) -> Self {
        Self {
            inner: format!("storage|{}|{}|v{}", bucket, object_id, version).into_bytes(),
        }
    }

    /// AAD for database field encryption.
    ///
    /// Format: `db|{table}|{row_id}|{column}`
    pub fn for_database(table: &str, row_id: &str, column: &str) -> Self {
        Self {
            inner: format!("db|{}|{}|{}", table, row_id, column).into_bytes(),
        }
    }

    /// AAD for backup/archive encryption.
    ///
    /// Format: `backup|{system}|{timestamp_unix}`
    pub fn for_backup(system: &str, timestamp_unix: u64) -> Self {
        Self {
            inner: format!("backup|{}|{}", system, timestamp_unix).into_bytes(),
        }
    }

    /// AAD for message/envelope encryption.
    ///
    /// Format: `msg|{sender}|{recipient}|{msg_id}`
    pub fn for_message(sender: &str, recipient: &str, msg_id: &str) -> Self {
        Self {
            inner: format!("msg|{}|{}|{}", sender, recipient, msg_id).into_bytes(),
        }
    }

    /// Access the raw bytes (for internal use).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}

/// Domain separation context — distinguishes encryption purposes.
///
/// Context is bound into the key derivation, so ciphertext encrypted
/// with one context cannot be decrypted with another.
///
/// This is your primary defense against cross-protocol attacks.
#[derive(Clone, Debug)]
pub struct Context {
    inner: Vec<u8>,
}

impl Context {
    /// Raw context from arbitrary bytes.
    ///
    /// Prefer the typed constructors when possible.
    pub fn raw(bytes: &[u8]) -> Self {
        Self {
            inner: bytes.to_vec(),
        }
    }

    /// Empty context (not recommended for production).
    pub fn empty() -> Self {
        Self { inner: Vec::new() }
    }

    /// Context for a specific application.
    ///
    /// Format: `app|{app_name}|{environment}`
    pub fn for_application(app_name: &str, environment: &str) -> Self {
        Self {
            inner: format!("app|{}|{}", app_name, environment).into_bytes(),
        }
    }

    /// Context for backup/archive operations.
    ///
    /// Format: `backup|{system}|epoch{epoch}`
    pub fn for_backup(system: &str, epoch: u32) -> Self {
        Self {
            inner: format!("backup|{}|epoch{}", system, epoch).into_bytes(),
        }
    }

    /// Context for inter-service communication.
    ///
    /// Format: `service|{from}|{to}|{protocol_version}`
    pub fn for_service(from: &str, to: &str, protocol_version: &str) -> Self {
        Self {
            inner: format!("service|{}|{}|{}", from, to, protocol_version).into_bytes(),
        }
    }

    /// Context for secrets management.
    ///
    /// Format: `secrets|{namespace}|{key_id}`
    pub fn for_secrets(namespace: &str, key_id: &str) -> Self {
        Self {
            inner: format!("secrets|{}|{}", namespace, key_id).into_bytes(),
        }
    }

    /// Access the raw bytes (for internal use).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// Main SDK interface
// ---------------------------------------------------------------------------

/// Citadel encryption engine.
///
/// Provides hybrid post-quantum encryption using X25519 + ML-KEM-768.
/// Security holds if *either* primitive remains secure.
///
/// # Example
///
/// ```
/// use citadel_sdk::{Citadel, Aad, Context};
///
/// let citadel = Citadel::new();
/// let (pk, sk) = citadel.generate_keypair();
///
/// let aad = Aad::for_storage("my-bucket", "object-123", 1);
/// let ctx = Context::for_application("myapp", "prod");
///
/// let ciphertext = citadel.seal(&pk, b"secret data", &aad, &ctx)?;
/// let plaintext = citadel.open(&sk, &ciphertext, &aad, &ctx)?;
///
/// assert_eq!(plaintext, b"secret data");
/// ```
pub struct Citadel {
    inner: crate::CitadelMlKem768,
}

impl Default for Citadel {
    fn default() -> Self {
        Self::new()
    }
}

impl Citadel {
    /// Create a new Citadel instance.
    pub fn new() -> Self {
        Self {
            inner: crate::CitadelMlKem768::new(),
        }
    }

    /// Generate a new keypair.
    ///
    /// The public key can be shared freely.
    /// The secret key must be protected and should be zeroized when no longer needed.
    pub fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        self.inner.keygen()
    }

    /// Encrypt (seal) plaintext to a public key.
    ///
    /// Both `aad` and `context` are bound to the ciphertext and must match on decryption.
    ///
    /// # Arguments
    ///
    /// * `pk` — recipient's public key
    /// * `plaintext` — data to encrypt (any size)
    /// * `aad` — additional authenticated data (authenticated but not encrypted)
    /// * `context` — domain separation context (bound into key derivation)
    ///
    /// # Returns
    ///
    /// Self-describing ciphertext bytes (minimum 1154 bytes).
    pub fn seal(
        &self,
        pk: &PublicKey,
        plaintext: &[u8],
        aad: &Aad,
        context: &Context,
    ) -> Result<Vec<u8>, SealError> {
        self.inner.encrypt(pk, plaintext, aad.as_bytes(), context.as_bytes())
    }

    /// Decrypt (open) ciphertext using a secret key.
    ///
    /// Both `aad` and `context` must match exactly what was used during encryption.
    ///
    /// # Error Behavior
    ///
    /// Returns an opaque `OpenError` for ALL failure modes:
    /// - Wrong key
    /// - Wrong AAD
    /// - Wrong context
    /// - Tampered ciphertext
    /// - Malformed input
    ///
    /// This uniform behavior prevents oracle attacks.
    pub fn open(
        &self,
        sk: &SecretKey,
        ciphertext: &[u8],
        aad: &Aad,
        context: &Context,
    ) -> Result<Vec<u8>, OpenError> {
        self.inner.decrypt(sk, ciphertext, aad.as_bytes(), context.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Inspection utilities (for ops/debugging)
// ---------------------------------------------------------------------------

/// Ciphertext metadata (extracted without decryption).
#[derive(Debug, Clone)]
pub struct CiphertextInfo {
    /// Protocol version (currently 0x01)
    pub version: u8,
    /// KEM suite identifier
    pub kem_suite: &'static str,
    /// AEAD suite identifier
    pub aead_suite: &'static str,
    /// Total ciphertext length
    pub total_bytes: usize,
    /// Plaintext length (total - overhead)
    pub plaintext_bytes: usize,
}

impl fmt::Display for CiphertextInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Citadel v{} | {} + {} | {} bytes ({} plaintext)",
            self.version, self.kem_suite, self.aead_suite, self.total_bytes, self.plaintext_bytes
        )
    }
}

/// Inspect ciphertext metadata without decrypting.
///
/// Useful for logging, debugging, and operational tooling.
/// Does NOT reveal any secret information.
pub fn inspect(ciphertext: &[u8]) -> Result<CiphertextInfo, OpenError> {
    use crate::wire::{decode_wire, MIN_CIPHERTEXT_BYTES, SUITE_KEM_HYBRID_X25519_MLKEM768, SUITE_AEAD_AES256GCM};

    let parts = decode_wire(ciphertext)?;

    let kem_suite = if parts.suite_kem == SUITE_KEM_HYBRID_X25519_MLKEM768 {
        "X25519+ML-KEM-768"
    } else {
        "unknown"
    };

    let aead_suite = if parts.suite_aead == SUITE_AEAD_AES256GCM {
        "AES-256-GCM"
    } else {
        "unknown"
    };

    // Plaintext bytes = total - (header + kem_ct + nonce + tag)
    let overhead = MIN_CIPHERTEXT_BYTES;
    let plaintext_bytes = ciphertext.len().saturating_sub(overhead);

    Ok(CiphertextInfo {
        version: parts.version,
        kem_suite,
        aead_suite,
        total_bytes: ciphertext.len(),
        plaintext_bytes,
    })
}

// ---------------------------------------------------------------------------
// Version info
// ---------------------------------------------------------------------------

/// SDK version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol version (wire format).
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Minimum ciphertext size in bytes.
pub const MIN_CIPHERTEXT_BYTES: usize = crate::wire::MIN_CIPHERTEXT_BYTES;
