//! KEM (Key Encapsulation Mechanism) abstractions
//!
//! This module defines traits for KEM operations. Currently, only the
//! hybrid X25519 + ML-KEM-768 implementation is provided and recommended.

extern crate alloc;
use alloc::vec::Vec;

use crate::error::{DecryptionError, EncodingError};

/// Shared secret size (32 bytes for all supported KEMs)
pub const SHARED_SECRET_BYTES: usize = 32;

/// Generic public key wrapper (for trait compatibility)
#[derive(Clone)]
pub struct PublicKey {
    pub(crate) bytes: Vec<u8>,
}

impl PublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self { bytes: bytes.to_vec() }
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Generic secret key wrapper (for trait compatibility)
pub struct SecretKey {
    pub(crate) bytes: Vec<u8>,
}

impl SecretKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self { bytes: bytes.to_vec() }
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Zero the bytes on drop
        for b in &mut self.bytes {
            *b = 0;
        }
    }
}

/// KEM provider trait
///
/// This trait allows swapping KEM implementations, though currently
/// only `HybridKemProvider` (X25519 + ML-KEM-768) is recommended.
pub trait KemProvider {
    /// Generate a new keypair
    fn keygen() -> (PublicKey, SecretKey);

    /// Encapsulate to a public key
    ///
    /// Returns (shared_secret, ciphertext)
    fn encapsulate(pk: &PublicKey) -> Result<([u8; SHARED_SECRET_BYTES], Vec<u8>), EncodingError>;

    /// Decapsulate using a secret key
    ///
    /// Returns shared_secret
    fn decapsulate(sk: &SecretKey, ct: &[u8]) -> Result<[u8; SHARED_SECRET_BYTES], DecryptionError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

    #[test]
    fn test_secret_key_zeroize_on_drop() {
        let bytes = vec![0x42u8; 32];
        let ptr = bytes.as_ptr();
        
        {
            let _sk = SecretKey::from_bytes(&bytes);
            // sk goes out of scope here
        }
        
        // Note: We can't actually verify the memory is zeroed after drop
        // because the memory is deallocated. This is more of a documentation test.
        let _ = ptr;
    }
}
