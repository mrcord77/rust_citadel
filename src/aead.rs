//! AEAD: AES-256-GCM authenticated encryption
//!
//! This module provides the symmetric encryption layer using AES-256-GCM.
//! All nonce generation uses the system CSPRNG via `getrandom`.

extern crate alloc;
use alloc::vec::Vec;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;

use crate::error::{DecryptionError, EncodingError};
use crate::hybrid_wire::NONCE_BYTES;

/// AES-256 key size
pub const AES_KEY_BYTES: usize = 32;

/// AES-GCM tag size
pub const AES_TAG_BYTES: usize = 16;

/// Generate a random nonce for AES-GCM
///
/// Uses the system CSPRNG. Each encryption MUST use a fresh nonce.
pub fn nonce() -> Result<[u8; NONCE_BYTES], EncodingError> {
    let mut n = [0u8; NONCE_BYTES];
    getrandom::getrandom(&mut n).map_err(|_| EncodingError)?;
    Ok(n)
}

/// Seal (encrypt + authenticate) plaintext with AES-256-GCM
///
/// - `key`: 32-byte AES-256 key
/// - `nonce`: 12-byte nonce (must be unique per key)
/// - `plaintext`: data to encrypt
/// - `aad`: additional authenticated data (authenticated but not encrypted)
///
/// Returns ciphertext || tag (plaintext.len() + 16 bytes)
pub fn aead_seal(
    key: &[u8; AES_KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EncodingError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncodingError)?;
    let nonce = Nonce::from_slice(nonce);
    
    cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
        .map_err(|_| EncodingError)
}

/// Open (decrypt + verify) ciphertext with AES-256-GCM
///
/// - `key`: 32-byte AES-256 key
/// - `nonce`: 12-byte nonce (must match encryption)
/// - `ciphertext`: ciphertext || tag from aead_seal
/// - `aad`: additional authenticated data (must match encryption)
///
/// Returns plaintext on success, DecryptionError on any failure.
pub fn aead_open(
    key: &[u8; AES_KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| DecryptionError)?;
    let nonce = Nonce::from_slice(nonce);
    
    cipher
        .decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad })
        .map_err(|_| DecryptionError)
}

/// Seal with zeroizing key wrapper
pub fn aead_seal_z(
    key: &Zeroizing<[u8; AES_KEY_BYTES]>,
    nonce: &[u8; NONCE_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EncodingError> {
    aead_seal(&**key, nonce, plaintext, aad)
}

/// Open with zeroizing key wrapper
pub fn aead_open_z(
    key: &Zeroizing<[u8; AES_KEY_BYTES]>,
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    aead_open(&**key, nonce, ciphertext, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let key = [0x42u8; AES_KEY_BYTES];
        let nonce = [0x11u8; NONCE_BYTES];
        let plaintext = b"Hello, world!";
        let aad = b"additional data";

        let ciphertext = aead_seal(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + AES_TAG_BYTES);

        let decrypted = aead_open(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; AES_KEY_BYTES];
        let nonce = [0x11u8; NONCE_BYTES];

        let ciphertext = aead_seal(&key, &nonce, b"", b"").unwrap();
        assert_eq!(ciphertext.len(), AES_TAG_BYTES);

        let decrypted = aead_open(&key, &nonce, &ciphertext, b"").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0x42u8; AES_KEY_BYTES];
        let key2 = [0x43u8; AES_KEY_BYTES];
        let nonce = [0x11u8; NONCE_BYTES];

        let ciphertext = aead_seal(&key1, &nonce, b"secret", b"").unwrap();
        assert!(aead_open(&key2, &nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = [0x42u8; AES_KEY_BYTES];
        let nonce1 = [0x11u8; NONCE_BYTES];
        let nonce2 = [0x22u8; NONCE_BYTES];

        let ciphertext = aead_seal(&key, &nonce1, b"secret", b"").unwrap();
        assert!(aead_open(&key, &nonce2, &ciphertext, b"").is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = [0x42u8; AES_KEY_BYTES];
        let nonce = [0x11u8; NONCE_BYTES];

        let ciphertext = aead_seal(&key, &nonce, b"secret", b"aad1").unwrap();
        assert!(aead_open(&key, &nonce, &ciphertext, b"aad2").is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x42u8; AES_KEY_BYTES];
        let nonce = [0x11u8; NONCE_BYTES];

        let mut ciphertext = aead_seal(&key, &nonce, b"secret", b"").unwrap();
        ciphertext[0] ^= 0x01;
        assert!(aead_open(&key, &nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn test_nonce_generation() {
        let n1 = nonce().unwrap();
        let n2 = nonce().unwrap();
        
        // Nonces should be different (with overwhelming probability)
        assert_ne!(n1, n2);
    }
}
