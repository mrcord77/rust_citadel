//! Hybrid KEM: X25519 + ML-KEM-768
//!
//! Combines classical ECDH (X25519) with post-quantum KEM (ML-KEM-768).
//! Security holds if *either* primitive remains secure (defense-in-depth).
//!
//! Key serialization:
//!   PublicKey  = x25519_pk[32] || mlkem_ek[1184]   (1216 bytes)
//!   SecretKey  = x25519_sk[32] || mlkem_dk[2400]   (2432 bytes)
//!
//! KEM ciphertext (on wire):
//!   x25519_ephemeral_pk[32] || mlkem_ct[1088]      (1120 bytes)
//!
//! Combined shared secret (fed to KDF):
//!   x25519_dh[32] || mlkem_ss[32]                  (64 bytes)

extern crate alloc;
use alloc::vec::Vec;

use core::convert::TryFrom;

use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Ciphertext, EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
};
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use crate::error::{DecryptionError, EncodingError};
use crate::wire::{
    KEM_CIPHERTEXT_BYTES, KEM_PUBLIC_KEY_BYTES, KEM_SECRET_KEY_BYTES,
    MLKEM_PUBLIC_KEY_BYTES, MLKEM_SECRET_KEY_BYTES,
    SHARED_SECRET_BYTES, X25519_KEY_BYTES,
};

type Ek = ml_kem::kem::EncapsulationKey<MlKem768Params>;
type Dk = ml_kem::kem::DecapsulationKey<MlKem768Params>;

/// ML-KEM typed ciphertext (for TryFrom).
type MlKemCt = Ciphertext<MlKem768>;

// ---------------------------------------------------------------------------
// Public key (hybrid)
// ---------------------------------------------------------------------------

/// Hybrid public key: X25519 public key + ML-KEM-768 encapsulation key.
#[derive(Clone)]
pub struct PublicKey {
    x25519: X25519PublicKey,
    mlkem: Ek,
}

impl PublicKey {
    pub(crate) fn from_parts(x25519: X25519PublicKey, mlkem: Ek) -> Self {
        Self { x25519, mlkem }
    }

    /// Serialize: x25519_pk[32] || mlkem_ek[1184]
    pub fn to_bytes(&self) -> [u8; KEM_PUBLIC_KEY_BYTES] {
        let mut out = [0u8; KEM_PUBLIC_KEY_BYTES];
        out[..X25519_KEY_BYTES].copy_from_slice(self.x25519.as_bytes());
        let mlkem_bytes = self.mlkem.as_bytes();
        out[X25519_KEY_BYTES..].copy_from_slice(mlkem_bytes.as_slice());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecryptionError> {
        if bytes.len() != KEM_PUBLIC_KEY_BYTES {
            return Err(DecryptionError);
        }

        let x25519_bytes: [u8; X25519_KEY_BYTES] = bytes[..X25519_KEY_BYTES]
            .try_into()
            .map_err(|_| DecryptionError)?;
        let x25519 = X25519PublicKey::from(x25519_bytes);

        let mlkem_bytes: [u8; MLKEM_PUBLIC_KEY_BYTES] = bytes[X25519_KEY_BYTES..]
            .try_into()
            .map_err(|_| DecryptionError)?;
        let mlkem = Ek::from_bytes(&mlkem_bytes.into());

        Ok(Self { x25519, mlkem })
    }

    pub(crate) fn x25519(&self) -> &X25519PublicKey {
        &self.x25519
    }

    pub(crate) fn mlkem(&self) -> &Ek {
        &self.mlkem
    }
}

// ---------------------------------------------------------------------------
// Secret key (hybrid)
// ---------------------------------------------------------------------------

/// Hybrid secret key: X25519 static secret + ML-KEM-768 decapsulation key.
pub struct SecretKey {
    x25519: StaticSecret,
    mlkem: Dk,
}

impl SecretKey {
    pub(crate) fn from_parts(x25519: StaticSecret, mlkem: Dk) -> Self {
        Self { x25519, mlkem }
    }

    /// Serialize: x25519_sk[32] || mlkem_dk[2400]
    pub fn to_bytes(&self) -> [u8; KEM_SECRET_KEY_BYTES] {
        let mut out = [0u8; KEM_SECRET_KEY_BYTES];
        out[..X25519_KEY_BYTES].copy_from_slice(&self.x25519.to_bytes());
        let mlkem_bytes = self.mlkem.as_bytes();
        out[X25519_KEY_BYTES..].copy_from_slice(mlkem_bytes.as_slice());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecryptionError> {
        if bytes.len() != KEM_SECRET_KEY_BYTES {
            return Err(DecryptionError);
        }

        let x25519_bytes: [u8; X25519_KEY_BYTES] = bytes[..X25519_KEY_BYTES]
            .try_into()
            .map_err(|_| DecryptionError)?;
        let x25519 = StaticSecret::from(x25519_bytes);

        let mlkem_bytes: [u8; MLKEM_SECRET_KEY_BYTES] = bytes[X25519_KEY_BYTES..]
            .try_into()
            .map_err(|_| DecryptionError)?;
        let mlkem = Dk::from_bytes(&mlkem_bytes.into());

        Ok(Self { x25519, mlkem })
    }

    pub(crate) fn x25519(&self) -> &StaticSecret {
        &self.x25519
    }

    pub(crate) fn mlkem(&self) -> &Dk {
        &self.mlkem
    }
}

// ---------------------------------------------------------------------------
// KEM provider trait + hybrid implementation
// ---------------------------------------------------------------------------

pub trait KemProvider {
    fn keygen() -> (PublicKey, SecretKey);
    /// Returns (combined_shared_secret, kem_ciphertext_bytes).
    fn encapsulate(pk: &PublicKey) -> Result<(Vec<u8>, Vec<u8>), EncodingError>;
    /// Returns combined_shared_secret.
    fn decapsulate(sk: &SecretKey, ct: &[u8]) -> Result<Vec<u8>, DecryptionError>;
}

/// Hybrid X25519 + ML-KEM-768 provider.
///
/// Combined shared secret = x25519_dh[32] || mlkem_ss[32] (64 bytes).
/// KEM ciphertext = x25519_ephemeral_pk[32] || mlkem_ct[1088] (1120 bytes).
pub struct HybridX25519MlKem768Provider;

impl KemProvider for HybridX25519MlKem768Provider {
    fn keygen() -> (PublicKey, SecretKey) {
        // X25519 long-term keypair
        let x25519_sk = StaticSecret::random_from_rng(OsRng);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        // ML-KEM-768 keypair (generate returns (dk, ek))
        let (mlkem_dk, mlkem_ek) = MlKem768::generate(&mut OsRng);

        (
            PublicKey::from_parts(x25519_pk, mlkem_ek),
            SecretKey::from_parts(x25519_sk, mlkem_dk),
        )
    }

    fn encapsulate(pk: &PublicKey) -> Result<(Vec<u8>, Vec<u8>), EncodingError> {
        // X25519: generate ephemeral keypair, compute DH shared secret
        let x25519_eph = EphemeralSecret::random_from_rng(OsRng);
        let x25519_eph_pk = X25519PublicKey::from(&x25519_eph);
        let x25519_ss = x25519_eph.diffie_hellman(pk.x25519());

        // ML-KEM-768: encapsulate
        let (mlkem_ct, mlkem_ss) = pk
            .mlkem()
            .encapsulate(&mut OsRng)
            .map_err(|_| EncodingError)?;

        // Combined shared secret: x25519_ss[32] || mlkem_ss[32]
        let mut combined_ss = Vec::with_capacity(SHARED_SECRET_BYTES * 2);
        combined_ss.extend_from_slice(x25519_ss.as_bytes());
        combined_ss.extend_from_slice(mlkem_ss.as_slice());

        // KEM ciphertext: x25519_ephemeral_pk[32] || mlkem_ct[1088]
        let mut kem_ct = Vec::with_capacity(KEM_CIPHERTEXT_BYTES);
        kem_ct.extend_from_slice(x25519_eph_pk.as_bytes());
        kem_ct.extend_from_slice(mlkem_ct.as_slice());

        Ok((combined_ss, kem_ct))
    }

    fn decapsulate(sk: &SecretKey, ct: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        if ct.len() != KEM_CIPHERTEXT_BYTES {
            return Err(DecryptionError);
        }

        // Parse: x25519_ephemeral_pk[32] || mlkem_ct[1088]
        let x25519_epk_bytes: [u8; X25519_KEY_BYTES] = ct[..X25519_KEY_BYTES]
            .try_into()
            .map_err(|_| DecryptionError)?;
        let x25519_epk = X25519PublicKey::from(x25519_epk_bytes);

        let mlkem_ct_bytes = &ct[X25519_KEY_BYTES..];
        let mlkem_ct = MlKemCt::try_from(mlkem_ct_bytes).map_err(|_| DecryptionError)?;

        // X25519 DH
        let x25519_ss = sk.x25519().diffie_hellman(&x25519_epk);

        // ML-KEM-768 decapsulate
        let mlkem_ss = sk
            .mlkem()
            .decapsulate(&mlkem_ct)
            .map_err(|_| DecryptionError)?;

        // Combined shared secret: x25519_ss[32] || mlkem_ss[32]
        let mut combined_ss = Vec::with_capacity(SHARED_SECRET_BYTES * 2);
        combined_ss.extend_from_slice(x25519_ss.as_bytes());
        combined_ss.extend_from_slice(mlkem_ss.as_slice());

        Ok(combined_ss)
    }
}

// ---------------------------------------------------------------------------
// Backward-compatibility alias
// ---------------------------------------------------------------------------

/// Legacy alias — now backed by the hybrid provider.
pub type MlKem768Provider = HybridX25519MlKem768Provider;
