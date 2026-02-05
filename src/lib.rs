//! # Citadel SDK
//!
//! Hybrid post-quantum encryption for long-lived data.
//!
//! ## Quick Start
//!
//! ```rust
//! use citadel_envelope::{Citadel, Aad, Context};
//!
//! let citadel = Citadel::new();
//! let (pk, sk) = citadel.generate_keypair();
//!
//! let aad = Aad::for_storage("bucket", "object-id", 1);
//! let ctx = Context::for_application("myapp", "prod");
//!
//! let ciphertext = citadel.seal(&pk, b"secret", &aad, &ctx).unwrap();
//! let plaintext = citadel.open(&sk, &ciphertext, &aad, &ctx).unwrap();
//!
//! assert_eq!(plaintext, b"secret");
//! ```
//!
//! ## Security Properties
//!
//! - **Hybrid KEM**: X25519 + ML-KEM-768 — secure if either holds
//! - **Uniform errors**: All failures produce identical error type
//! - **AAD/context binding**: Wrong metadata causes decryption failure
//! - **Stable wire format**: Versioned, self-describing
//!
//! ## What's NOT Provided
//!
//! - Key management
//! - Streaming encryption
//! - FIPS certification
//! - Constant-time guarantees

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![doc(html_root_url = "https://docs.rs/citadel-envelope/0.1.0")]

extern crate alloc;

// ---------------------------------------------------------------------------
// Internal modules (not part of public API)
// ---------------------------------------------------------------------------

mod aead;
mod error;
mod kdf;
mod kem;

// Wire module needs to be pub(crate) for CLI inspect command
// but should not be considered stable API
#[doc(hidden)]
pub mod wire;

// Legacy internal modules (hidden from docs)
#[doc(hidden)]
pub mod aad;
#[doc(hidden)]
pub mod envelope;

// ---------------------------------------------------------------------------
// Public SDK interface
// ---------------------------------------------------------------------------

mod sdk;

// Re-export the clean SDK interface
pub use sdk::{
    // Main types
    Citadel,
    Aad,
    Context,
    
    // Error types
    SealError,
    OpenError,
    
    // Key types
    PublicKey,
    SecretKey,
    
    // Inspection
    CiphertextInfo,
    inspect,
    
    // Constants
    VERSION,
    PROTOCOL_VERSION,
    MIN_CIPHERTEXT_BYTES,
};

// ---------------------------------------------------------------------------
// Legacy exports (deprecated, for backward compatibility)
// ---------------------------------------------------------------------------

#[doc(hidden)]
#[deprecated(since = "0.1.0", note = "use Citadel instead")]
pub type CitadelMlKem768 = crate::kem_engine::Citadel<crate::kem::HybridX25519MlKem768Provider>;

#[doc(hidden)]
#[deprecated(since = "0.1.0", note = "use Citadel instead")]
pub type CitadelHybrid = CitadelMlKem768;

// Internal engine (not part of public API, but needed for legacy compat)
mod kem_engine {
    use alloc::vec::Vec;
    use zeroize::Zeroizing;
    
    use crate::error::{DecryptionError, EncodingError};
    use crate::kem::{KemProvider, PublicKey, SecretKey};
    use crate::{aead, kdf, wire};

    pub struct Citadel<K: KemProvider> {
        _marker: core::marker::PhantomData<K>,
    }

    impl<K: KemProvider> Default for Citadel<K> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<K: KemProvider> Citadel<K> {
        pub fn new() -> Self {
            Self {
                _marker: core::marker::PhantomData,
            }
        }

        pub fn keygen(&self) -> (PublicKey, SecretKey) {
            K::keygen()
        }

        pub fn encrypt(
            &self,
            pk: &PublicKey,
            plaintext: &[u8],
            aad: &[u8],
            context: &[u8],
        ) -> Result<Vec<u8>, EncodingError> {
            let (ss_raw, kem_ct) = K::encapsulate(pk)?;
            let shared_secret = Zeroizing::new(ss_raw);
            let ct_hash = kdf::ct_hash(&kem_ct);
            let aes_key = Zeroizing::new(kdf::derive_key(&shared_secret, &ct_hash, context)?);
            let nonce = aead::nonce()?;
            let aead_ct = aead::aead_seal(&aes_key, &nonce, plaintext, aad)?;
            wire::encode_wire(&kem_ct, &nonce, &aead_ct)
        }

        pub fn decrypt(
            &self,
            sk: &SecretKey,
            ciphertext: &[u8],
            aad: &[u8],
            context: &[u8],
        ) -> Result<Vec<u8>, DecryptionError> {
            let parts = wire::decode_wire(ciphertext)?;
            let ss_raw = K::decapsulate(sk, parts.kem_ciphertext)?;
            let shared_secret = Zeroizing::new(ss_raw);
            let ct_hash = kdf::ct_hash(parts.kem_ciphertext);
            let aes_key = Zeroizing::new(
                kdf::derive_key(&shared_secret, &ct_hash, context)
                    .map_err(|_| DecryptionError)?,
            );
            aead::aead_open(&aes_key, parts.nonce, parts.aead_ciphertext, aad)
        }

        #[inline]
        pub fn seal(
            &self,
            pk: &PublicKey,
            plaintext: &[u8],
            aad: &[u8],
            context: &[u8],
        ) -> Result<Vec<u8>, EncodingError> {
            self.encrypt(pk, plaintext, aad, context)
        }

        #[inline]
        pub fn open(
            &self,
            sk: &SecretKey,
            ciphertext: &[u8],
            aad: &[u8],
            context: &[u8],
        ) -> Result<Vec<u8>, DecryptionError> {
            self.decrypt(sk, ciphertext, aad, context)
        }
    }
}

// Re-export internal types needed by legacy code and CLI
#[doc(hidden)]
pub use error::{DecryptionError, EncodingError};
#[doc(hidden)]
pub use kem::{HybridX25519MlKem768Provider, KemProvider, MlKem768Provider};