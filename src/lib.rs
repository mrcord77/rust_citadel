//! # Citadel Envelope
//!
//! Post-quantum hybrid encryption using X25519 + ML-KEM-768 + AES-256-GCM.
//!
//! ## Overview
//!
//! This crate provides defense-in-depth hybrid encryption:
//!
//! - **X25519**: Classical ECDH, protects if ML-KEM is broken by cryptanalysis
//! - **ML-KEM-768**: Post-quantum KEM (FIPS 203), protects against quantum computers
//! - **AES-256-GCM**: Authenticated encryption for the actual payload
//!
//! This is the same approach used by Signal, Chrome, and Cloudflare for
//! post-quantum protection.
//!
//! ## Quick Start
//!
//! ```rust
//! use citadel_envelope::HybridEnvelope;
//!
//! // Create envelope and generate keys
//! let envelope = HybridEnvelope::new();
//! let (public_key, secret_key) = envelope.keygen();
//!
//! // Encrypt
//! let plaintext = b"Hello, post-quantum world!";
//! let aad = b"metadata";  // Authenticated but not encrypted
//! let context = b"my-app-v1";  // Domain separation
//!
//! let ciphertext = envelope.encrypt(&public_key, plaintext, aad, context).unwrap();
//!
//! // Decrypt
//! let decrypted = envelope.decrypt(&secret_key, &ciphertext, aad, context).unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! ## Protocol Constraints
//!
//! The following limits are enforced to ensure interoperability:
//!
//! | Parameter | Limit | Notes |
//! |-----------|-------|-------|
//! | AAD | 64 KiB | Metadata, timestamps, etc. |
//! | Context | 256 bytes | Application identifier |
//! | Plaintext | ~4 GiB | AES-GCM practical limit |
//!
//! Exceeding these limits returns an error.
//!
//! ## Wire Format
//!
//! See [`hybrid_wire`] for the complete wire format specification.
//!
//! ## Security Properties
//!
//! 1. **Confidentiality**: Message content is encrypted
//! 2. **Integrity**: Tampering is detected via AEAD tag
//! 3. **Context Binding**: Context is bound via KDF
//! 4. **AAD Binding**: Additional data is authenticated
//! 5. **Ciphertext Binding**: KEM ciphertext is bound to AES key
//! 6. **Uniform Errors**: All failures return opaque "decryption failed"
//! 7. **Defense-in-Depth**: Secure if either X25519 OR ML-KEM is secure
//!
//! ## Feature Flags
//!
//! - `std`: Enable `std::error::Error` implementations (default: off)
//! - `kat`: Enable deterministic mode for Known Answer Tests (NEVER use in production)

#![no_std]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

// Required for no_std Vec/String support - each module re-declares for clarity
#[allow(unused_extern_crates)]
extern crate alloc;

// ============================================================================
// Modules
// ============================================================================

pub mod aead;
pub mod constraints;
pub mod error;
pub mod hybrid;
pub mod hybrid_envelope;
pub mod hybrid_wire;
pub mod kem;

// ============================================================================
// Public re-exports
// ============================================================================

// Main API
pub use hybrid_envelope::HybridEnvelope;

// Key types
pub use hybrid::{HybridPublicKey, HybridSecretKey};

// Error types
pub use error::{ConstraintError, DecryptionError, EncodingError};

// Constraints (for documentation/validation)
pub use constraints::{MAX_AAD_BYTES, MAX_CONTEXT_BYTES, MAX_PLAINTEXT_BYTES};

// ============================================================================
// Prelude (convenient imports)
// ============================================================================

/// Convenient imports for common usage
pub mod prelude {
    pub use crate::HybridEnvelope;
    pub use crate::HybridPublicKey;
    pub use crate::HybridSecretKey;
    pub use crate::DecryptionError;
    pub use crate::EncodingError;
}
