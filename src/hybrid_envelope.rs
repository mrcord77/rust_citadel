// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hybrid Envelope: X25519 + ML-KEM-768 + AES-256-GCM
//!
//! Defense-in-depth post-quantum hybrid encryption.
//!
//! - If ML-KEM is broken by future cryptanalysis, X25519 still protects.
//! - If quantum computers break X25519, ML-KEM still protects.
//!
//! This is the same approach used by Signal, Chrome, and Cloudflare.
//!
//! # Example
//!
//! ```rust
//! use citadel_envelope::HybridEnvelope;
//!
//! let envelope = HybridEnvelope::new();
//! let (pk, sk) = envelope.keygen();
//!
//! let plaintext = b"Hello, post-quantum world!";
//! let aad = b"authenticated data";
//! let context = b"my-app-v1";
//!
//! let ciphertext = envelope.encrypt(&pk, plaintext, aad, context).unwrap();
//! let decrypted = envelope.decrypt(&sk, &ciphertext, aad, context).unwrap();
//!
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! # Protocol Constraints
//!
//! The following limits are enforced:
//!
//! | Parameter | Limit | Rationale |
//! |-----------|-------|-----------|
//! | AAD | 64 KiB | Metadata doesn't need to be huge |
//! | Context | 256 bytes | Application identifiers are short |
//! | Plaintext | ~4 GiB | AES-GCM practical limit |
//!
//! Exceeding these limits returns `EncodingError` on encrypt, or
//! uniform `DecryptionError` on decrypt.

extern crate alloc;
use alloc::vec::Vec;

use sha3::{Digest, Sha3_256};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aead;
use crate::constraints::{
    validate_aad_len, validate_context_len, validate_plaintext_len,
    MAX_AAD_BYTES, MAX_CONTEXT_BYTES,
};
use crate::error::{DecryptionError, EncodingError};
use crate::hybrid::{self, HybridPublicKey, HybridSecretKey};
use crate::hybrid_wire::{
    decode_hybrid_wire, encode_hybrid_wire, HYBRID_PROTOCOL_ID,
};

// ============================================================================
// Hybrid Envelope
// ============================================================================

/// Hybrid envelope engine: X25519 + ML-KEM-768 + AES-256-GCM
///
/// This is a stateless encryption engine. Create one instance and reuse
/// it for multiple operations.
///
/// # Thread Safety
///
/// `HybridEnvelope` is `Send + Sync` and can be shared across threads.
/// Each encryption generates fresh random values, so concurrent use is safe.
pub struct HybridEnvelope {
    _private: (),
}

impl Default for HybridEnvelope {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridEnvelope {
    /// Create a new hybrid envelope engine
    #[inline]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Generate a new hybrid keypair
    ///
    /// Uses the system CSPRNG. The secret key should be stored securely
    /// and the public key can be shared freely.
    #[inline]
    pub fn keygen(&self) -> (HybridPublicKey, HybridSecretKey) {
        hybrid::keygen()
    }

    /// Encrypt (seal) a message to `pk`
    ///
    /// # Arguments
    ///
    /// - `pk`: Recipient's public key
    /// - `plaintext`: The message to encrypt (max ~4 GiB)
    /// - `aad`: Additional authenticated data (max 64 KiB, authenticated but not encrypted)
    /// - `context`: Application context (max 256 bytes, bound via KDF, must match on decrypt)
    ///
    /// # Returns
    ///
    /// The ciphertext, or `EncodingError` if constraints are violated.
    ///
    /// # Constraints
    ///
    /// - `aad.len() <= 65536` (64 KiB)
    /// - `context.len() <= 256`
    /// - `plaintext.len() <= 0xFFFFFFFF` (~4 GiB)
    pub fn encrypt(
        &self,
        pk: &HybridPublicKey,
        plaintext: &[u8],
        aad: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, EncodingError> {
        // =====================================================================
        // PHASE 1: Constraint validation (fail fast, before any crypto)
        // =====================================================================
        
        if !validate_aad_len(aad.len()) {
            return Err(EncodingError);
        }
        if !validate_context_len(context.len()) {
            return Err(EncodingError);
        }
        if !validate_plaintext_len(plaintext.len()) {
            return Err(EncodingError);
        }

        // =====================================================================
        // PHASE 2: KEM encapsulation
        // =====================================================================
        
        let (shared_secret, kem_ct) = hybrid::encapsulate(pk)?;
        let shared_secret = Zeroizing::new(shared_secret);

        // =====================================================================
        // PHASE 3: Key derivation with domain separation
        // =====================================================================
        
        let ct_hash = ct_hash(&kem_ct);
        let aes_key = derive_key(shared_secret.as_slice(), &ct_hash, context)?;
        let aes_key = Zeroizing::new(aes_key);

        // =====================================================================
        // PHASE 4: Symmetric encryption
        // =====================================================================
        
        let nonce = aead::nonce()?;
        let aead_ct = aead::aead_seal(&*aes_key, &nonce, plaintext, aad)?;

        // =====================================================================
        // PHASE 5: Wire format encoding
        // =====================================================================
        
        encode_hybrid_wire(&kem_ct, &nonce, &aead_ct)
    }

    /// Decrypt (open) a message using `sk`
    ///
    /// # Arguments
    ///
    /// - `sk`: Recipient's secret key
    /// - `ciphertext`: The ciphertext from `encrypt()`
    /// - `aad`: Must match the AAD used during encryption
    /// - `context`: Must match the context used during encryption
    ///
    /// # Returns
    ///
    /// The plaintext, or a uniform `DecryptionError` for any failure.
    ///
    /// # Security
    ///
    /// All failures return the same opaque error to prevent oracle attacks.
    /// The error message is always "decryption failed" regardless of:
    /// - Constraint violations (oversized AAD/context)
    /// - Invalid wire format
    /// - Invalid KEM ciphertext  
    /// - Invalid AEAD tag
    /// - Wrong key
    /// - Wrong AAD
    /// - Wrong context
    pub fn decrypt(
        &self,
        sk: &HybridSecretKey,
        ciphertext: &[u8],
        aad: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        // =====================================================================
        // PHASE 1: Constraint validation (uniform error, no oracle)
        // =====================================================================
        
        // AAD and context constraints apply on decrypt too
        // This catches obviously invalid inputs before parsing
        // Returns uniform DecryptionError (no ConstraintError on decrypt path)
        if aad.len() > MAX_AAD_BYTES || context.len() > MAX_CONTEXT_BYTES {
            return Err(DecryptionError);
        }

        // =====================================================================
        // PHASE 2: Wire format parsing (validates header BEFORE KEM)
        // =====================================================================
        
        let parts = decode_hybrid_wire(ciphertext)?;

        // =====================================================================
        // PHASE 3: KEM decapsulation
        // =====================================================================
        
        // Zero-copy: parts.kem_ciphertext is a borrowed slice from ciphertext
        let shared_secret = hybrid::decapsulate(sk, parts.kem_ciphertext)?;
        let shared_secret = Zeroizing::new(shared_secret);

        // =====================================================================
        // PHASE 4: Key derivation with domain separation
        // =====================================================================
        
        let ct_hash = ct_hash(parts.kem_ciphertext);
        let aes_key = derive_key(shared_secret.as_slice(), &ct_hash, context)
            .map_err(|_| DecryptionError)?;
        let aes_key = Zeroizing::new(aes_key);

        // =====================================================================
        // PHASE 5: Symmetric decryption
        // =====================================================================
        
        aead::aead_open(&*aes_key, parts.nonce, parts.aead_ciphertext, aad)
    }

    /// Alias for `encrypt()`
    #[inline]
    pub fn seal(
        &self,
        pk: &HybridPublicKey,
        plaintext: &[u8],
        aad: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, EncodingError> {
        self.encrypt(pk, plaintext, aad, context)
    }

    /// Alias for `decrypt()`
    #[inline]
    pub fn open(
        &self,
        sk: &HybridSecretKey,
        ciphertext: &[u8],
        aad: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        self.decrypt(sk, ciphertext, aad, context)
    }
}

// ============================================================================
// KDF functions (hybrid-specific)
// ============================================================================

/// Hash the KEM ciphertext for binding in KDF
///
/// Uses SHA3-256 to bind the ciphertext to the derived key, preventing
/// related-key attacks.
fn ct_hash(kem_ct: &[u8]) -> [u8; 32] {
    let h = Sha3_256::digest(kem_ct);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

/// Derive AES key from shared secret
///
/// info = PROTOCOL_ID || "|aes|" || ct_hash || context
///
/// This provides domain separation:
/// - PROTOCOL_ID prevents cross-protocol attacks
/// - "|aes|" tag separates key derivation purposes
/// - ct_hash binds to the specific KEM ciphertext
/// - context allows application-specific separation
fn derive_key(
    shared_secret: &[u8],
    ct_hash: &[u8; 32],
    context: &[u8],
) -> Result<[u8; 32], EncodingError> {
    // Context length already validated by caller, but this is defense-in-depth
    // Pre-calculate exact size to avoid reallocation
    let info_len = HYBRID_PROTOCOL_ID.len() + 5 + 32 + context.len();
    let mut info = Vec::with_capacity(info_len);
    info.extend_from_slice(HYBRID_PROTOCOL_ID);
    info.extend_from_slice(b"|aes|");
    info.extend_from_slice(ct_hash);
    info.extend_from_slice(context);

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).map_err(|_| EncodingError)?;
    Ok(out)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};
    use crate::constraints::{MAX_AAD_BYTES, MAX_CONTEXT_BYTES};
    use crate::hybrid_wire::MIN_HYBRID_CIPHERTEXT_BYTES;

    #[test]
    fn test_roundtrip() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let plaintext = b"Hello, post-quantum world!";
        let aad = b"authenticated data";
        let context = b"test-context";

        let ciphertext = envelope.encrypt(&pk, plaintext, aad, context).unwrap();
        let decrypted = envelope.decrypt(&sk, &ciphertext, aad, context).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let ciphertext = envelope.encrypt(&pk, b"", b"", b"").unwrap();
        assert_eq!(ciphertext.len(), MIN_HYBRID_CIPHERTEXT_BYTES);

        let decrypted = envelope.decrypt(&sk, &ciphertext, b"", b"").unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_empty_context_allowed() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        // Empty context is explicitly allowed
        let ciphertext = envelope.encrypt(&pk, b"test", b"aad", b"").unwrap();
        let decrypted = envelope.decrypt(&sk, &ciphertext, b"aad", b"").unwrap();
        assert_eq!(decrypted, b"test");
    }

    #[test]
    fn test_wrong_aad_fails() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let ciphertext = envelope.encrypt(&pk, b"secret", b"aad1", b"ctx").unwrap();
        
        // Wrong AAD should fail
        let result = envelope.decrypt(&sk, &ciphertext, b"aad2", b"ctx");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_context_fails() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let ciphertext = envelope.encrypt(&pk, b"secret", b"aad", b"ctx1").unwrap();
        
        // Wrong context should fail (different key derived)
        let result = envelope.decrypt(&sk, &ciphertext, b"aad", b"ctx2");
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let mut ciphertext = envelope.encrypt(&pk, b"secret", b"aad", b"ctx").unwrap();
        
        // Flip last byte (in AEAD tag)
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;
        
        let result = envelope.decrypt(&sk, &ciphertext, b"aad", b"ctx");
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_x25519_ct_fails() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let mut ciphertext = envelope.encrypt(&pk, b"secret", b"aad", b"ctx").unwrap();
        
        // Flip byte in X25519 ciphertext region (byte 6 is start of KEM ct)
        ciphertext[6] ^= 0x01;
        
        let result = envelope.decrypt(&sk, &ciphertext, b"aad", b"ctx");
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_mlkem_ct_fails() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let mut ciphertext = envelope.encrypt(&pk, b"secret", b"aad", b"ctx").unwrap();
        
        // Flip byte in ML-KEM ciphertext region (starts at 6 + 32 = 38)
        ciphertext[50] ^= 0x01;
        
        let result = envelope.decrypt(&sk, &ciphertext, b"aad", b"ctx");
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let ciphertext = envelope.encrypt(&pk, b"secret", b"aad", b"ctx").unwrap();
        
        // Truncate
        let truncated = &ciphertext[..MIN_HYBRID_CIPHERTEXT_BYTES - 1];
        
        let result = envelope.decrypt(&sk, truncated, b"aad", b"ctx");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let envelope = HybridEnvelope::new();
        let (pk1, _sk1) = envelope.keygen();
        let (_pk2, sk2) = envelope.keygen();

        let ciphertext = envelope.encrypt(&pk1, b"secret", b"aad", b"ctx").unwrap();
        
        // Decrypt with wrong key - should fail
        let result = envelope.decrypt(&sk2, &ciphertext, b"aad", b"ctx");
        assert!(result.is_err());
    }

    #[test]
    fn test_uniform_error_messages() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let ct = envelope.encrypt(&pk, b"test", b"aad", b"ctx").unwrap();

        // Collect different error scenarios
        let errors: Vec<DecryptionError> = vec![
            envelope.decrypt(&sk, b"short", b"", b"").unwrap_err(),
            envelope.decrypt(&sk, &ct, b"wrong_aad", b"ctx").unwrap_err(),
            envelope.decrypt(&sk, &ct, b"aad", b"wrong_ctx").unwrap_err(),
        ];

        // All errors should have the same message (no oracle)
        let first = format!("{}", errors[0]);
        for e in &errors {
            assert_eq!(format!("{}", e), first);
        }
        assert_eq!(first, "decryption failed");
    }

    #[test]
    fn test_large_plaintext() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        // 1 MB plaintext
        let plaintext = vec![0x42u8; 1024 * 1024];
        
        let ciphertext = envelope.encrypt(&pk, &plaintext, b"aad", b"ctx").unwrap();
        let decrypted = envelope.decrypt(&sk, &ciphertext, b"aad", b"ctx").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_consistency_multiple_roundtrips() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        for i in 0..10 {
            let plaintext = format!("message {}", i).into_bytes();
            let aad = format!("aad {}", i).into_bytes();

            let ct = envelope.encrypt(&pk, &plaintext, &aad, b"ctx").unwrap();
            let pt = envelope.decrypt(&sk, &ct, &aad, b"ctx").unwrap();
            
            assert_eq!(pt, plaintext);
        }
    }

    // =========================================================================
    // Constraint enforcement tests
    // =========================================================================

    #[test]
    fn test_encrypt_rejects_oversized_aad() {
        let envelope = HybridEnvelope::new();
        let (pk, _sk) = envelope.keygen();

        let oversized_aad = vec![0u8; MAX_AAD_BYTES + 1];
        let result = envelope.encrypt(&pk, b"test", &oversized_aad, b"ctx");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_accepts_max_aad() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let max_aad = vec![0u8; MAX_AAD_BYTES];
        let ct = envelope.encrypt(&pk, b"test", &max_aad, b"ctx").unwrap();
        let pt = envelope.decrypt(&sk, &ct, &max_aad, b"ctx").unwrap();
        assert_eq!(pt, b"test");
    }

    #[test]
    fn test_encrypt_rejects_oversized_context() {
        let envelope = HybridEnvelope::new();
        let (pk, _sk) = envelope.keygen();

        let oversized_context = vec![0u8; MAX_CONTEXT_BYTES + 1];
        let result = envelope.encrypt(&pk, b"test", b"aad", &oversized_context);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_accepts_max_context() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let max_context = vec![0u8; MAX_CONTEXT_BYTES];
        let ct = envelope.encrypt(&pk, b"test", b"aad", &max_context).unwrap();
        let pt = envelope.decrypt(&sk, &ct, b"aad", &max_context).unwrap();
        assert_eq!(pt, b"test");
    }

    #[test]
    fn test_decrypt_rejects_oversized_aad() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let ct = envelope.encrypt(&pk, b"test", b"aad", b"ctx").unwrap();
        
        // Try to decrypt with oversized AAD (attacker-controlled)
        let oversized_aad = vec![0u8; MAX_AAD_BYTES + 1];
        let result = envelope.decrypt(&sk, &ct, &oversized_aad, b"ctx");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_rejects_oversized_context() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let ct = envelope.encrypt(&pk, b"test", b"aad", b"ctx").unwrap();
        
        // Try to decrypt with oversized context (attacker-controlled)
        let oversized_context = vec![0u8; MAX_CONTEXT_BYTES + 1];
        let result = envelope.decrypt(&sk, &ct, b"aad", &oversized_context);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_oversized_inputs_return_uniform_error() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let ct = envelope.encrypt(&pk, b"test", b"aad", b"ctx").unwrap();
        
        // Oversized AAD error
        let oversized_aad = vec![0u8; MAX_AAD_BYTES + 1];
        let err1 = envelope.decrypt(&sk, &ct, &oversized_aad, b"ctx").unwrap_err();
        
        // Oversized context error
        let oversized_context = vec![0u8; MAX_CONTEXT_BYTES + 1];
        let err2 = envelope.decrypt(&sk, &ct, b"aad", &oversized_context).unwrap_err();
        
        // Wrong AAD error (normal decryption failure)
        let err3 = envelope.decrypt(&sk, &ct, b"wrong", b"ctx").unwrap_err();
        
        // All should have the same error message (no oracle)
        assert_eq!(format!("{}", err1), format!("{}", err2));
        assert_eq!(format!("{}", err2), format!("{}", err3));
        assert_eq!(format!("{}", err1), "decryption failed");
    }

    // =========================================================================
    // Seal/Open alias tests
    // =========================================================================

    #[test]
    fn test_seal_open_aliases() {
        let envelope = HybridEnvelope::new();
        let (pk, sk) = envelope.keygen();

        let ct = envelope.seal(&pk, b"test", b"aad", b"ctx").unwrap();
        let pt = envelope.open(&sk, &ct, b"aad", b"ctx").unwrap();
        
        assert_eq!(pt, b"test");
    }
}
