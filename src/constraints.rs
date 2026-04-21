// SPDX-License-Identifier: AGPL-3.0-or-later
//! Protocol Constraints
//!
//! This module defines hard limits that are enforced at both encryption and
//! decryption time. Changing these values is a BREAKING CHANGE that will
//! produce incompatible ciphertexts.
//!
//! # Compatibility Rules
//!
//! - MAX_AAD_BYTES: If you exceed this, encryption fails
//! - MAX_CONTEXT_BYTES: If you exceed this, encryption fails  
//! - MAX_PLAINTEXT_BYTES: If you exceed this, encryption fails
//!
//! These limits exist to:
//! 1. Prevent denial-of-service via memory exhaustion
//! 2. Ensure interoperability between implementations
//! 3. Bound the HKDF info field to a predictable size

/// Maximum additional authenticated data (AAD) size: 64 KiB
///
/// AAD is authenticated but not encrypted. It's typically used for
/// metadata like timestamps, sender IDs, or protocol version info.
/// 64 KiB is generous for any reasonable use case.
pub const MAX_AAD_BYTES: usize = 65536;

/// Maximum context size: 256 bytes
///
/// Context is used for domain separation in key derivation.
/// It should be a short, static application identifier like:
/// - "myapp-v1"
/// - "session-key"
/// - "file-encryption-2024"
///
/// 256 bytes is far more than needed for any identifier.
pub const MAX_CONTEXT_BYTES: usize = 256;

/// Maximum plaintext size: 4 GiB
///
/// This is the practical limit for AES-GCM (2^32 blocks minus some margin).
/// In practice, you should chunk larger data with fresh keys.
pub const MAX_PLAINTEXT_BYTES: usize = 0xFFFF_FFFF; // ~4 GiB

/// Minimum context size: 0 bytes (empty context allowed)
///
/// While empty context is allowed for flexibility, applications SHOULD
/// use a non-empty context for domain separation. Set this to 1 if you
/// want to require non-empty context.
pub const MIN_CONTEXT_BYTES: usize = 0;

/// Validate AAD length
#[inline]
pub const fn validate_aad_len(len: usize) -> bool {
    len <= MAX_AAD_BYTES
}

/// Validate context length
#[inline]
pub const fn validate_context_len(len: usize) -> bool {
    len >= MIN_CONTEXT_BYTES && len <= MAX_CONTEXT_BYTES
}

/// Validate plaintext length
#[inline]
pub const fn validate_plaintext_len(len: usize) -> bool {
    len <= MAX_PLAINTEXT_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constraint_values() {
        // Document the actual values for spec compliance
        assert_eq!(MAX_AAD_BYTES, 65536);
        assert_eq!(MAX_CONTEXT_BYTES, 256);
        assert_eq!(MIN_CONTEXT_BYTES, 0);
    }

    #[test]
    fn test_validation_functions() {
        // AAD
        assert!(validate_aad_len(0));
        assert!(validate_aad_len(MAX_AAD_BYTES));
        assert!(!validate_aad_len(MAX_AAD_BYTES + 1));

        // Context
        assert!(validate_context_len(0));
        assert!(validate_context_len(MAX_CONTEXT_BYTES));
        assert!(!validate_context_len(MAX_CONTEXT_BYTES + 1));

        // Plaintext
        assert!(validate_plaintext_len(0));
        assert!(validate_plaintext_len(MAX_PLAINTEXT_BYTES));
        // Can't easily test overflow in const context
    }
}
