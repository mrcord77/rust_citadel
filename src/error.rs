//! Error types for the envelope
//!
//! # Security Note
//!
//! All decryption failures return the same opaque error type to prevent
//! error oracles. An attacker should not be able to distinguish between:
//! - Invalid wire format
//! - Invalid KEM ciphertext
//! - Invalid AEAD tag
//! - Wrong key
//! - Wrong AAD
//! - Wrong context
//!
//! All of these produce `DecryptionError` with the same message.

use core::fmt;

/// Encoding error during encryption
///
/// This is returned when encryption fails due to:
/// - Constraint violations (AAD/context/plaintext too long)
/// - Internal encoding failures (should not happen)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodingError;

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "encoding failed")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncodingError {}

/// Constraint violation error
///
/// Returned when inputs exceed protocol limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintError {
    /// AAD exceeds MAX_AAD_BYTES
    AadTooLong,
    /// Context exceeds MAX_CONTEXT_BYTES
    ContextTooLong,
    /// Plaintext exceeds MAX_PLAINTEXT_BYTES  
    PlaintextTooLong,
}

impl fmt::Display for ConstraintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConstraintError::AadTooLong => write!(f, "AAD exceeds maximum length"),
            ConstraintError::ContextTooLong => write!(f, "context exceeds maximum length"),
            ConstraintError::PlaintextTooLong => write!(f, "plaintext exceeds maximum length"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConstraintError {}

impl From<ConstraintError> for EncodingError {
    fn from(_: ConstraintError) -> Self {
        EncodingError
    }
}

/// Decryption error (uniform, no oracle)
///
/// # Security
///
/// This error type intentionally provides no information about WHY
/// decryption failed. All failure modes produce the same error with
/// the same message: "decryption failed".
///
/// **Do not** add variants, additional fields, or different messages.
/// Doing so could create an error oracle that leaks information to attackers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptionError;

impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // This message MUST NOT vary based on failure reason
        write!(f, "decryption failed")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecryptionError {}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::format;

    #[test]
    fn test_decryption_error_uniformity() {
        // All DecryptionErrors must have identical string representation
        let e1 = DecryptionError;
        let e2 = DecryptionError;
        
        assert_eq!(format!("{}", e1), format!("{}", e2));
        assert_eq!(format!("{}", e1), "decryption failed");
        assert_eq!(format!("{:?}", e1), format!("{:?}", e2));
    }

    #[test]
    fn test_encoding_error() {
        let e = EncodingError;
        assert_eq!(format!("{}", e), "encoding failed");
    }

    #[test]
    fn test_constraint_errors() {
        assert_eq!(format!("{}", ConstraintError::AadTooLong), "AAD exceeds maximum length");
        assert_eq!(format!("{}", ConstraintError::ContextTooLong), "context exceeds maximum length");
        assert_eq!(format!("{}", ConstraintError::PlaintextTooLong), "plaintext exceeds maximum length");
    }

    #[test]
    fn test_constraint_to_encoding_conversion() {
        let c: EncodingError = ConstraintError::AadTooLong.into();
        assert_eq!(format!("{}", c), "encoding failed");
    }
}
