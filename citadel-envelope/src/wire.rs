//! Wire format (v1 structured)
//!
//! Format (v1):
//!   version[1] || suite_kem[1] || suite_aead[1] || flags[1] || kem_ct_len[2]
//!   || kem_ct[1120] || nonce[12] || aead_ct[16+]
//!
//! kem_ct = x25519_ephemeral_pk[32] || mlkem768_ciphertext[1088]

extern crate alloc;
use alloc::vec::Vec;

use crate::error::{DecryptionError, EncodingError};

/// Protocol identifier for KDF domain separation (v1 structured)
pub const PROTOCOL_ID: &[u8] = b"citadel-env-v1";

/// Version byte for v1
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Suite identifiers (on-wire)
pub const SUITE_KEM_HYBRID_X25519_MLKEM768: u8 = 0xA3;
pub const SUITE_AEAD_AES256GCM: u8 = 0xB1;

/// Flags (reserved for future use)
pub const FLAGS_V1: u8 = 0x00;

// ---------------------------------------------------------------------------
// Component sizes
// ---------------------------------------------------------------------------

/// X25519 public key / ephemeral key size
pub const X25519_KEY_BYTES: usize = 32;

/// ML-KEM-768 component sizes
pub const MLKEM_CIPHERTEXT_BYTES: usize = 1088;
pub const MLKEM_PUBLIC_KEY_BYTES: usize = 1184;
pub const MLKEM_SECRET_KEY_BYTES: usize = 2400;

// ---------------------------------------------------------------------------
// Hybrid aggregate sizes
// ---------------------------------------------------------------------------

/// Hybrid KEM ciphertext: x25519_ephemeral_pk[32] || mlkem_ct[1088]
pub const KEM_CIPHERTEXT_BYTES: usize = X25519_KEY_BYTES + MLKEM_CIPHERTEXT_BYTES; // 1120

/// Hybrid public key: x25519_pk[32] || mlkem_ek[1184]
pub const KEM_PUBLIC_KEY_BYTES: usize = X25519_KEY_BYTES + MLKEM_PUBLIC_KEY_BYTES; // 1216

/// Hybrid secret key: x25519_sk[32] || mlkem_dk[2400]
pub const KEM_SECRET_KEY_BYTES: usize = X25519_KEY_BYTES + MLKEM_SECRET_KEY_BYTES; // 2432

/// Per-KEM shared secret size (each produces 32 bytes)
pub const SHARED_SECRET_BYTES: usize = 32;

pub const NONCE_BYTES: usize = 12;
pub const AEAD_TAG_BYTES: usize = 16;
pub const AES_KEY_BYTES: usize = 32;

/// Header size: version + suite_kem + suite_aead + flags + kem_ct_len(u16)
pub const HEADER_BYTES: usize = 1 + 1 + 1 + 1 + 2; // 6

/// Minimum ciphertext size: header + kem_ct + nonce + tag
pub const MIN_CIPHERTEXT_BYTES: usize =
    HEADER_BYTES + KEM_CIPHERTEXT_BYTES + NONCE_BYTES + AEAD_TAG_BYTES; // 1154

// ---------------------------------------------------------------------------
// Compatibility aliases (keep older imports compiling)
// ---------------------------------------------------------------------------
pub const VERSION: u8 = PROTOCOL_VERSION;
pub const KEM_CT_BYTES: usize = KEM_CIPHERTEXT_BYTES;
pub const KEM_PK_BYTES: usize = KEM_PUBLIC_KEY_BYTES;
pub const KEM_SK_BYTES: usize = KEM_SECRET_KEY_BYTES;

/// Borrowed view of a parsed ciphertext.
#[derive(Debug, Clone, Copy)]
pub struct WireComponents<'a> {
    pub version: u8,
    pub suite_kem: u8,
    pub suite_aead: u8,
    pub flags: u8,
    pub kem_ct_len: u16,
    pub kem_ciphertext: &'a [u8; KEM_CIPHERTEXT_BYTES],
    pub nonce: &'a [u8; NONCE_BYTES],
    pub aead_ciphertext: &'a [u8],
}

pub fn decode_wire(data: &[u8]) -> Result<WireComponents<'_>, DecryptionError> {
    if data.len() < MIN_CIPHERTEXT_BYTES {
        return Err(DecryptionError);
    }

    let version = data[0];
    let suite_kem = data[1];
    let suite_aead = data[2];
    let flags = data[3];
    let kem_ct_len = u16::from_be_bytes([data[4], data[5]]);

    if version != PROTOCOL_VERSION {
        return Err(DecryptionError);
    }
    if suite_kem != SUITE_KEM_HYBRID_X25519_MLKEM768 || suite_aead != SUITE_AEAD_AES256GCM {
        return Err(DecryptionError);
    }
    if flags != FLAGS_V1 {
        return Err(DecryptionError);
    }
    if kem_ct_len as usize != KEM_CIPHERTEXT_BYTES {
        return Err(DecryptionError);
    }

    let kem_start = HEADER_BYTES;
    let kem_end = kem_start + KEM_CIPHERTEXT_BYTES;

    let nonce_start = kem_end;
    let nonce_end = nonce_start + NONCE_BYTES;

    let kem_ciphertext: &[u8; KEM_CIPHERTEXT_BYTES] = data[kem_start..kem_end]
        .try_into()
        .map_err(|_| DecryptionError)?;

    let nonce: &[u8; NONCE_BYTES] = data[nonce_start..nonce_end]
        .try_into()
        .map_err(|_| DecryptionError)?;

    let aead_ciphertext = &data[nonce_end..];
    if aead_ciphertext.len() < AEAD_TAG_BYTES {
        return Err(DecryptionError);
    }

    Ok(WireComponents {
        version,
        suite_kem,
        suite_aead,
        flags,
        kem_ct_len,
        kem_ciphertext,
        nonce,
        aead_ciphertext,
    })
}

pub fn encode_wire(
    kem_ct: &[u8],
    nonce: &[u8; NONCE_BYTES],
    aead_ct: &[u8],
) -> Result<Vec<u8>, EncodingError> {
    if kem_ct.len() != KEM_CIPHERTEXT_BYTES {
        return Err(EncodingError);
    }
    if aead_ct.len() < AEAD_TAG_BYTES {
        return Err(EncodingError);
    }

    let mut out = Vec::with_capacity(HEADER_BYTES + KEM_CIPHERTEXT_BYTES + NONCE_BYTES + aead_ct.len());

    out.push(PROTOCOL_VERSION);
    out.push(SUITE_KEM_HYBRID_X25519_MLKEM768);
    out.push(SUITE_AEAD_AES256GCM);
    out.push(FLAGS_V1);
    out.extend_from_slice(&(KEM_CIPHERTEXT_BYTES as u16).to_be_bytes());

    out.extend_from_slice(kem_ct);
    out.extend_from_slice(nonce);
    out.extend_from_slice(aead_ct);

    Ok(out)
}
