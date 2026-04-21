// SPDX-License-Identifier: AGPL-3.0-or-later
//! Hybrid KEM: X25519 + ML-KEM-768
//!
//! Defense-in-depth: If either primitive is broken, the other still protects.
//! This is the same approach used by Signal, Chrome, and Cloudflare.
//!
//! # Key Combination
//!
//! ```text
//! combined_ikm = x25519_shared_secret[32] || mlkem_shared_secret[32]
//! shared_secret = HKDF-SHA256(combined_ikm, salt=None, info="citadel-hybrid-v1")
//! ```
//!
//! # Ciphertext Format
//!
//! ```text
//! ciphertext = x25519_ephemeral[32] || mlkem_ct[1088] = 1120 bytes
//! ```

extern crate alloc;
use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroizing;

use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
};
use rand_core::OsRng;

use crate::error::{DecryptionError, EncodingError};

// ============================================================================
// Constants
// ============================================================================

/// X25519 public key size
pub const X25519_PUBLIC_KEY_BYTES: usize = 32;

/// X25519 secret key size  
pub const X25519_SECRET_KEY_BYTES: usize = 32;

/// X25519 ciphertext (ephemeral public key)
pub const X25519_CIPHERTEXT_BYTES: usize = 32;

/// ML-KEM-768 encapsulation key size
pub const MLKEM_PUBLIC_KEY_BYTES: usize = 1184;

/// ML-KEM-768 decapsulation key size
pub const MLKEM_SECRET_KEY_BYTES: usize = 2400;

/// ML-KEM-768 ciphertext size
pub const MLKEM_CIPHERTEXT_BYTES: usize = 1088;

/// Combined hybrid public key size: X25519 + ML-KEM
pub const HYBRID_PUBLIC_KEY_BYTES: usize = X25519_PUBLIC_KEY_BYTES + MLKEM_PUBLIC_KEY_BYTES; // 1216

/// Combined hybrid secret key size: X25519 + ML-KEM
pub const HYBRID_SECRET_KEY_BYTES: usize = X25519_SECRET_KEY_BYTES + MLKEM_SECRET_KEY_BYTES; // 2432

/// Combined hybrid ciphertext size: X25519 ephemeral + ML-KEM ct
pub const HYBRID_CIPHERTEXT_BYTES: usize = X25519_CIPHERTEXT_BYTES + MLKEM_CIPHERTEXT_BYTES; // 1120

/// Final shared secret size (after HKDF)
pub const SHARED_SECRET_BYTES: usize = 32;

/// Domain separator for hybrid KDF
const HYBRID_KDF_INFO: &[u8] = b"citadel-hybrid-v1";

// ============================================================================
// Type aliases for ML-KEM
// ============================================================================

type MlKemEk = ml_kem::kem::EncapsulationKey<MlKem768Params>;
type MlKemDk = ml_kem::kem::DecapsulationKey<MlKem768Params>;
type MlKemCt = Ciphertext<MlKem768>;

// ============================================================================
// Hybrid Public Key
// ============================================================================

/// Combined X25519 + ML-KEM-768 public key
///
/// # Serialization Format
///
/// ```text
/// public_key = x25519_public[32] || mlkem_encapsulation_key[1184]
/// ```
///
/// Total: 1216 bytes
#[derive(Clone)]
pub struct HybridPublicKey {
    x25519: X25519Public,
    mlkem: MlKemEk,
}

impl HybridPublicKey {
    /// Serialize to bytes: x25519[32] || mlkem[1184]
    pub fn to_bytes(&self) -> [u8; HYBRID_PUBLIC_KEY_BYTES] {
        let mut out = [0u8; HYBRID_PUBLIC_KEY_BYTES];
        out[..X25519_PUBLIC_KEY_BYTES].copy_from_slice(self.x25519.as_bytes());
        out[X25519_PUBLIC_KEY_BYTES..].copy_from_slice(self.mlkem.as_bytes().as_slice());
        out
    }

    /// Deserialize from bytes
    ///
    /// # Errors
    ///
    /// Returns `DecryptionError` if the bytes are the wrong length.
    /// Note: This does not validate that the ML-KEM key is well-formed
    /// beyond length checking.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecryptionError> {
        if bytes.len() != HYBRID_PUBLIC_KEY_BYTES {
            return Err(DecryptionError);
        }

        // Parse X25519 public key
        let x25519_bytes: [u8; X25519_PUBLIC_KEY_BYTES] = bytes[..X25519_PUBLIC_KEY_BYTES]
            .try_into()
            .map_err(|_| DecryptionError)?;
        let x25519 = X25519Public::from(x25519_bytes);

        // Parse ML-KEM encapsulation key
        let mlkem_bytes: [u8; MLKEM_PUBLIC_KEY_BYTES] = bytes[X25519_PUBLIC_KEY_BYTES..]
            .try_into()
            .map_err(|_| DecryptionError)?;
        let mlkem = MlKemEk::from_bytes(&mlkem_bytes.into());

        Ok(Self { x25519, mlkem })
    }

    /// Get the X25519 component
    #[inline]
    pub fn x25519(&self) -> &X25519Public {
        &self.x25519
    }

    /// Get the ML-KEM encapsulation key component
    #[inline]
    pub fn mlkem(&self) -> &MlKemEk {
        &self.mlkem
    }
}

// ============================================================================
// Hybrid Secret Key
// ============================================================================

/// Combined X25519 + ML-KEM-768 secret key
///
/// # Serialization Format
///
/// ```text
/// secret_key = x25519_secret[32] || mlkem_decapsulation_key[2400]
/// ```
///
/// Total: 2432 bytes
///
/// # Security
///
/// The secret key material is zeroed on drop via the `Zeroizing` wrapper
/// when serialized. Handle the raw bytes with care.
pub struct HybridSecretKey {
    x25519: StaticSecret,
    mlkem: MlKemDk,
}

impl HybridSecretKey {
    /// Serialize to bytes: x25519[32] || mlkem[2400]
    ///
    /// # Security
    ///
    /// The returned bytes contain secret key material.
    /// The `Zeroizing` wrapper ensures the bytes are zeroed on drop.
    pub fn to_bytes(&self) -> Zeroizing<[u8; HYBRID_SECRET_KEY_BYTES]> {
        let mut out = Zeroizing::new([0u8; HYBRID_SECRET_KEY_BYTES]);
        out[..X25519_SECRET_KEY_BYTES].copy_from_slice(self.x25519.as_bytes());
        out[X25519_SECRET_KEY_BYTES..].copy_from_slice(self.mlkem.as_bytes().as_slice());
        out
    }

    /// Deserialize from bytes
    ///
    /// # Security
    ///
    /// The input bytes should be treated as sensitive and zeroed after use.
    ///
    /// # Errors
    ///
    /// Returns `DecryptionError` if the bytes are the wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecryptionError> {
        if bytes.len() != HYBRID_SECRET_KEY_BYTES {
            return Err(DecryptionError);
        }

        // Parse X25519 secret key
        let x25519_bytes: [u8; X25519_SECRET_KEY_BYTES] = bytes[..X25519_SECRET_KEY_BYTES]
            .try_into()
            .map_err(|_| DecryptionError)?;
        let x25519 = StaticSecret::from(x25519_bytes);

        // Parse ML-KEM decapsulation key
        let mlkem_bytes: [u8; MLKEM_SECRET_KEY_BYTES] = bytes[X25519_SECRET_KEY_BYTES..]
            .try_into()
            .map_err(|_| DecryptionError)?;
        let mlkem = MlKemDk::from_bytes(&mlkem_bytes.into());

        Ok(Self { x25519, mlkem })
    }

    /// Get the X25519 component
    #[inline]
    pub(crate) fn x25519(&self) -> &StaticSecret {
        &self.x25519
    }

    /// Get the ML-KEM decapsulation key component
    #[inline]
    pub(crate) fn mlkem(&self) -> &MlKemDk {
        &self.mlkem
    }
}

// ============================================================================
// Key Generation
// ============================================================================

/// Generate a new hybrid keypair
///
/// Uses the system CSPRNG (`OsRng`) for both X25519 and ML-KEM key generation.
///
/// # Panics
///
/// Panics if the system CSPRNG is unavailable.
pub fn keygen() -> (HybridPublicKey, HybridSecretKey) {
    // Generate X25519 keypair
    let x25519_secret = StaticSecret::random_from_rng(OsRng);
    let x25519_public = X25519Public::from(&x25519_secret);

    // Generate ML-KEM-768 keypair
    // Note: ml-kem returns (decapsulation_key, encapsulation_key)
    let (mlkem_dk, mlkem_ek) = MlKem768::generate(&mut OsRng);

    let public_key = HybridPublicKey {
        x25519: x25519_public,
        mlkem: mlkem_ek,
    };

    let secret_key = HybridSecretKey {
        x25519: x25519_secret,
        mlkem: mlkem_dk,
    };

    (public_key, secret_key)
}

// ============================================================================
// Encapsulation
// ============================================================================

/// Encapsulate to a hybrid public key
///
/// Generates a fresh shared secret and ciphertext. The shared secret is
/// derived by combining X25519 and ML-KEM shared secrets with HKDF.
///
/// # Returns
///
/// `(shared_secret, ciphertext)` where:
/// - `shared_secret`: 32-byte HKDF output
/// - `ciphertext`: x25519_ephemeral[32] || mlkem_ct[1088] = 1120 bytes
///
/// # Errors
///
/// Returns `EncodingError` if random number generation fails.
pub fn encapsulate(pk: &HybridPublicKey) -> Result<([u8; SHARED_SECRET_BYTES], Vec<u8>), EncodingError> {
    // X25519: Generate ephemeral keypair and compute shared secret
    let x25519_ephemeral = EphemeralSecret::random_from_rng(OsRng);
    let x25519_ephemeral_public = X25519Public::from(&x25519_ephemeral);
    let x25519_shared = x25519_ephemeral.diffie_hellman(&pk.x25519);

    // ML-KEM: Encapsulate
    let (mlkem_ct, mlkem_ss) = pk.mlkem.encapsulate(&mut OsRng).map_err(|_| EncodingError)?;

    // Combine shared secrets using HKDF
    // Input key material: x25519_ss[32] || mlkem_ss[32]
    let mut combined_ikm = Zeroizing::new([0u8; 64]);
    combined_ikm[..32].copy_from_slice(x25519_shared.as_bytes());
    combined_ikm[32..].copy_from_slice(mlkem_ss.as_slice());

    let hk = Hkdf::<Sha256>::new(None, combined_ikm.as_slice());
    let mut shared_secret = [0u8; SHARED_SECRET_BYTES];
    hk.expand(HYBRID_KDF_INFO, &mut shared_secret)
        .map_err(|_| EncodingError)?;

    // Build ciphertext: x25519_ephemeral[32] || mlkem_ct[1088]
    let mut ciphertext = Vec::with_capacity(HYBRID_CIPHERTEXT_BYTES);
    ciphertext.extend_from_slice(x25519_ephemeral_public.as_bytes());
    ciphertext.extend_from_slice(mlkem_ct.as_slice());

    debug_assert_eq!(ciphertext.len(), HYBRID_CIPHERTEXT_BYTES);
    Ok((shared_secret, ciphertext))
}

// ============================================================================
// Decapsulation
// ============================================================================

/// Decapsulate using a hybrid secret key
///
/// Parses the ciphertext and derives the shared secret by combining
/// X25519 and ML-KEM decapsulation results with HKDF.
///
/// # Arguments
///
/// - `sk`: The hybrid secret key
/// - `ciphertext`: x25519_ephemeral[32] || mlkem_ct[1088] = 1120 bytes
///
/// # Returns
///
/// 32-byte shared secret matching the encapsulator's output.
///
/// # Errors
///
/// Returns `DecryptionError` for any failure (wrong length, invalid ciphertext).
/// The error is intentionally opaque to prevent oracle attacks.
///
/// # Note on ML-KEM Implicit Rejection
///
/// ML-KEM uses implicit rejection: if the ciphertext is invalid, decapsulation
/// returns a pseudorandom value derived from the ciphertext and secret key.
/// This means decapsulation "succeeds" even with invalid ciphertexts, but
/// the shared secret will not match. This is a security feature that prevents
/// chosen-ciphertext attacks.
pub fn decapsulate(sk: &HybridSecretKey, ciphertext: &[u8]) -> Result<[u8; SHARED_SECRET_BYTES], DecryptionError> {
    if ciphertext.len() != HYBRID_CIPHERTEXT_BYTES {
        return Err(DecryptionError);
    }

    // Parse X25519 ephemeral public key
    let x25519_ephemeral_bytes: [u8; X25519_CIPHERTEXT_BYTES] = ciphertext[..X25519_CIPHERTEXT_BYTES]
        .try_into()
        .map_err(|_| DecryptionError)?;
    let x25519_ephemeral = X25519Public::from(x25519_ephemeral_bytes);

    // Parse ML-KEM ciphertext
    let mlkem_ct_bytes = &ciphertext[X25519_CIPHERTEXT_BYTES..];
    let mlkem_ct = MlKemCt::try_from(mlkem_ct_bytes).map_err(|_| DecryptionError)?;

    // X25519: Compute shared secret
    let x25519_shared = sk.x25519.diffie_hellman(&x25519_ephemeral);

    // ML-KEM: Decapsulate (implicit rejection on failure)
    let mlkem_ss = sk.mlkem.decapsulate(&mlkem_ct).map_err(|_| DecryptionError)?;

    // Combine shared secrets using HKDF
    let mut combined_ikm = Zeroizing::new([0u8; 64]);
    combined_ikm[..32].copy_from_slice(x25519_shared.as_bytes());
    combined_ikm[32..].copy_from_slice(mlkem_ss.as_slice());

    let hk = Hkdf::<Sha256>::new(None, combined_ikm.as_slice());
    let mut shared_secret = [0u8; SHARED_SECRET_BYTES];
    hk.expand(HYBRID_KDF_INFO, &mut shared_secret)
        .map_err(|_| DecryptionError)?;

    Ok(shared_secret)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_constants() {
        // Verify constant values match spec
        assert_eq!(HYBRID_PUBLIC_KEY_BYTES, 32 + 1184); // 1216
        assert_eq!(HYBRID_SECRET_KEY_BYTES, 32 + 2400); // 2432
        assert_eq!(HYBRID_CIPHERTEXT_BYTES, 32 + 1088); // 1120
        assert_eq!(SHARED_SECRET_BYTES, 32);
    }

    #[test]
    fn test_keygen() {
        let (pk, sk) = keygen();

        // Verify sizes
        assert_eq!(pk.to_bytes().len(), HYBRID_PUBLIC_KEY_BYTES);
        assert_eq!(sk.to_bytes().len(), HYBRID_SECRET_KEY_BYTES);
    }

    #[test]
    fn test_roundtrip() {
        let (pk, sk) = keygen();

        let (ss_enc, ct) = encapsulate(&pk).unwrap();
        let ss_dec = decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss_enc, ss_dec);
        assert_eq!(ct.len(), HYBRID_CIPHERTEXT_BYTES);
    }

    #[test]
    fn test_key_serialization() {
        let (pk, sk) = keygen();

        let pk_bytes = pk.to_bytes();
        let sk_bytes = sk.to_bytes();

        let pk2 = HybridPublicKey::from_bytes(&pk_bytes).unwrap();
        let sk2 = HybridSecretKey::from_bytes(sk_bytes.as_slice()).unwrap();

        // Encapsulate with original, decapsulate with deserialized
        let (ss1, ct) = encapsulate(&pk).unwrap();
        let ss2 = decapsulate(&sk2, &ct).unwrap();
        assert_eq!(ss1, ss2);

        // Encapsulate with deserialized, decapsulate with original
        let (ss3, ct2) = encapsulate(&pk2).unwrap();
        let ss4 = decapsulate(&sk, &ct2).unwrap();
        assert_eq!(ss3, ss4);
    }

    #[test]
    fn test_wrong_ciphertext_length() {
        let (_pk, sk) = keygen();

        let short_ct = vec![0u8; HYBRID_CIPHERTEXT_BYTES - 1];
        assert!(decapsulate(&sk, &short_ct).is_err());

        let long_ct = vec![0u8; HYBRID_CIPHERTEXT_BYTES + 1];
        assert!(decapsulate(&sk, &long_ct).is_err());
    }

    #[test]
    fn test_different_keys_different_secrets() {
        let (pk1, _sk1) = keygen();
        let (_pk2, sk2) = keygen();

        let (ss1, ct) = encapsulate(&pk1).unwrap();

        // Decapsulating with wrong key should give different result
        // (ML-KEM uses implicit rejection, so it won't error but will give wrong secret)
        let ss2 = decapsulate(&sk2, &ct).unwrap();

        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_encapsulation_is_randomized() {
        let (pk, _sk) = keygen();

        let (ss1, ct1) = encapsulate(&pk).unwrap();
        let (ss2, ct2) = encapsulate(&pk).unwrap();

        // Different ciphertexts
        assert_ne!(ct1, ct2);

        // Different shared secrets
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn test_public_key_wrong_length() {
        let short = vec![0u8; HYBRID_PUBLIC_KEY_BYTES - 1];
        assert!(HybridPublicKey::from_bytes(&short).is_err());

        let long = vec![0u8; HYBRID_PUBLIC_KEY_BYTES + 1];
        assert!(HybridPublicKey::from_bytes(&long).is_err());
    }

    #[test]
    fn test_secret_key_wrong_length() {
        let short = vec![0u8; HYBRID_SECRET_KEY_BYTES - 1];
        assert!(HybridSecretKey::from_bytes(&short).is_err());

        let long = vec![0u8; HYBRID_SECRET_KEY_BYTES + 1];
        assert!(HybridSecretKey::from_bytes(&long).is_err());
    }
}
