// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wire format for hybrid envelope (v1 structured)
//!
//! # Wire Format
//!
//! ```text
//! ciphertext =
//!     version[1]       ||  // MUST be 0x01
//!     suite_kem[1]     ||  // MUST be 0xA3 (X25519 + ML-KEM-768)
//!     suite_aead[1]    ||  // MUST be 0xB1 (AES-256-GCM)
//!     flags[1]         ||  // MUST be 0x00
//!     kem_ct_len[2]    ||  // u16 BE, MUST be 1120
//!     x25519_ct[32]    ||  // X25519 ephemeral public key
//!     mlkem_ct[1088]   ||  // ML-KEM-768 ciphertext
//!     nonce[12]        ||  // AES-GCM nonce
//!     aead_ct[>=16]        // AES-GCM ciphertext + tag
//! ```
//!
//! # Validation Order
//!
//! Decoding performs validation in this order, rejecting BEFORE any
//! cryptographic operations:
//!
//! 1. Minimum length check
//! 2. Version check
//! 3. KEM suite check
//! 4. AEAD suite check
//! 5. Flags check (reserved, must be 0)
//! 6. KEM ciphertext length check
//! 7. AEAD ciphertext minimum length check
//!
//! This ensures attackers cannot use timing differences in KEM
//! decapsulation to distinguish error types.

extern crate alloc;
use alloc::vec::Vec;

use crate::error::{DecryptionError, EncodingError};
use crate::hybrid::{HYBRID_CIPHERTEXT_BYTES, X25519_CIPHERTEXT_BYTES, MLKEM_CIPHERTEXT_BYTES};

// ============================================================================
// Protocol Constants
// ============================================================================

/// Protocol identifier for hybrid KDF domain separation
pub const HYBRID_PROTOCOL_ID: &[u8] = b"citadel-hybrid-env-v1";

/// Version byte (v1)
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Suite identifier for X25519 + ML-KEM-768 hybrid KEM
pub const SUITE_KEM_HYBRID: u8 = 0xA3;

/// Suite identifier for ML-KEM-768 only (reserved, not used in hybrid)
pub const SUITE_KEM_MLKEM768: u8 = 0xA2;

/// Suite identifier for AES-256-GCM
pub const SUITE_AEAD_AES256GCM: u8 = 0xB1;

/// Flags byte (reserved, must be 0x00)
pub const FLAGS_V1: u8 = 0x00;

// ============================================================================
// Size Constants
// ============================================================================

/// Nonce size for AES-GCM
pub const NONCE_BYTES: usize = 12;

/// Tag size for AES-GCM
pub const AEAD_TAG_BYTES: usize = 16;

/// AES-256 key size
pub const AES_KEY_BYTES: usize = 32;

/// Header size: version + suite_kem + suite_aead + flags + kem_ct_len(u16)
pub const HEADER_BYTES: usize = 6;

/// Minimum hybrid ciphertext size: header + hybrid_ct + nonce + tag
pub const MIN_HYBRID_CIPHERTEXT_BYTES: usize =
    HEADER_BYTES + HYBRID_CIPHERTEXT_BYTES + NONCE_BYTES + AEAD_TAG_BYTES; // 1154

/// Maximum hybrid ciphertext size (bounded by MAX_PLAINTEXT_BYTES + overhead)
/// This prevents allocation attacks.
pub const MAX_HYBRID_CIPHERTEXT_BYTES: usize = 
    MIN_HYBRID_CIPHERTEXT_BYTES + crate::constraints::MAX_PLAINTEXT_BYTES;

// ============================================================================
// Wire Format Components
// ============================================================================

/// Borrowed view of a parsed hybrid ciphertext
///
/// All fields are validated before construction. If you have a
/// `HybridWireComponents`, the header is guaranteed valid.
///
/// # Zero-Copy Design
///
/// All fields borrow directly from the input buffer. No allocations
/// are performed during parsing. The `kem_ciphertext` field borrows
/// the contiguous KEM ciphertext region (x25519 || mlkem).
#[derive(Debug, Clone, Copy)]
pub struct HybridWireComponents<'a> {
    /// Protocol version (always 0x01)
    pub version: u8,
    /// KEM suite (always 0xA3 for hybrid)
    pub suite_kem: u8,
    /// AEAD suite (always 0xB1 for AES-256-GCM)
    pub suite_aead: u8,
    /// Flags (always 0x00, reserved for future use)
    pub flags: u8,
    /// KEM ciphertext length (always 1120 for hybrid)
    pub kem_ct_len: u16,
    /// Combined KEM ciphertext: x25519[32] || mlkem[1088] (borrowed, zero-copy)
    pub kem_ciphertext: &'a [u8],
    /// X25519 ephemeral public key (32 bytes, view into kem_ciphertext)
    pub x25519_ciphertext: &'a [u8; X25519_CIPHERTEXT_BYTES],
    /// ML-KEM-768 ciphertext (1088 bytes, view into kem_ciphertext)
    pub mlkem_ciphertext: &'a [u8; MLKEM_CIPHERTEXT_BYTES],
    /// AES-GCM nonce (12 bytes)
    pub nonce: &'a [u8; NONCE_BYTES],
    /// AES-GCM ciphertext + tag (at least 16 bytes)
    pub aead_ciphertext: &'a [u8],
}

// ============================================================================
// Decode
// ============================================================================

/// Decode and validate hybrid wire format
///
/// # Validation
///
/// All header fields are validated BEFORE returning. This function
/// performs no cryptographic operations, so timing is uniform for
/// all invalid inputs.
///
/// # Zero-Copy
///
/// This function performs no allocations. All returned slices borrow
/// directly from the input buffer.
///
/// # Errors
///
/// Returns `DecryptionError` for any validation failure. The error
/// is intentionally opaque to prevent oracle attacks.
pub fn decode_hybrid_wire(data: &[u8]) -> Result<HybridWireComponents<'_>, DecryptionError> {
    // =========================================================================
    // PHASE 1: Length validation (before any parsing)
    // =========================================================================
    
    if data.len() < MIN_HYBRID_CIPHERTEXT_BYTES {
        return Err(DecryptionError);
    }

    // Reject absurdly large inputs early (DoS protection)
    if data.len() > MAX_HYBRID_CIPHERTEXT_BYTES {
        return Err(DecryptionError);
    }

    // =========================================================================
    // PHASE 2: Header parsing and validation (constant-time-ish)
    // =========================================================================
    
    let version = data[0];
    let suite_kem = data[1];
    let suite_aead = data[2];
    let flags = data[3];
    let kem_ct_len = u16::from_be_bytes([data[4], data[5]]);

    // Validate ALL header fields before any further processing
    // This ensures uniform timing regardless of which field is wrong
    
    let version_ok = version == PROTOCOL_VERSION;
    let suite_kem_ok = suite_kem == SUITE_KEM_HYBRID;
    let suite_aead_ok = suite_aead == SUITE_AEAD_AES256GCM;
    let flags_ok = flags == FLAGS_V1;
    let kem_len_ok = kem_ct_len as usize == HYBRID_CIPHERTEXT_BYTES;

    // Reject if ANY header field is invalid
    if !(version_ok && suite_kem_ok && suite_aead_ok && flags_ok && kem_len_ok) {
        return Err(DecryptionError);
    }

    // =========================================================================
    // PHASE 3: Parse body (zero-copy slice extraction)
    // =========================================================================
    
    // KEM ciphertext region: bytes [6..6+1120]
    let kem_start = HEADER_BYTES;
    let kem_end = kem_start + HYBRID_CIPHERTEXT_BYTES;
    let kem_ciphertext = &data[kem_start..kem_end];
    
    // X25519 component: first 32 bytes of KEM ciphertext
    let x25519_ciphertext: &[u8; X25519_CIPHERTEXT_BYTES] = 
        kem_ciphertext[..X25519_CIPHERTEXT_BYTES]
            .try_into()
            .map_err(|_| DecryptionError)?;

    // ML-KEM component: remaining 1088 bytes of KEM ciphertext
    let mlkem_ciphertext: &[u8; MLKEM_CIPHERTEXT_BYTES] = 
        kem_ciphertext[X25519_CIPHERTEXT_BYTES..]
            .try_into()
            .map_err(|_| DecryptionError)?;

    // Nonce: bytes [1126..1138]
    let nonce_start = kem_end;
    let nonce_end = nonce_start + NONCE_BYTES;
    let nonce: &[u8; NONCE_BYTES] = data[nonce_start..nonce_end]
        .try_into()
        .map_err(|_| DecryptionError)?;

    // AEAD ciphertext: remaining bytes [1138..]
    let aead_ciphertext = &data[nonce_end..];
    
    // Final validation: AEAD ciphertext must include at least the tag
    if aead_ciphertext.len() < AEAD_TAG_BYTES {
        return Err(DecryptionError);
    }

    Ok(HybridWireComponents {
        version,
        suite_kem,
        suite_aead,
        flags,
        kem_ct_len,
        kem_ciphertext,
        x25519_ciphertext,
        mlkem_ciphertext,
        nonce,
        aead_ciphertext,
    })
}

// ============================================================================
// Encode
// ============================================================================

/// Encode hybrid wire format
///
/// # Arguments
///
/// - `kem_ct`: Combined KEM ciphertext (x25519[32] || mlkem[1088], must be 1120 bytes)
/// - `nonce`: AES-GCM nonce (12 bytes)
/// - `aead_ct`: AES-GCM ciphertext + tag (at least 16 bytes)
///
/// # Errors
///
/// Returns `EncodingError` if:
/// - `kem_ct.len() != 1120`
/// - `aead_ct.len() < 16`
pub fn encode_hybrid_wire(
    kem_ct: &[u8],
    nonce: &[u8; NONCE_BYTES],
    aead_ct: &[u8],
) -> Result<Vec<u8>, EncodingError> {
    // Validate inputs
    if kem_ct.len() != HYBRID_CIPHERTEXT_BYTES {
        return Err(EncodingError);
    }
    if aead_ct.len() < AEAD_TAG_BYTES {
        return Err(EncodingError);
    }

    // Pre-allocate exact size
    let total_len = HEADER_BYTES + HYBRID_CIPHERTEXT_BYTES + NONCE_BYTES + aead_ct.len();
    let mut out = Vec::with_capacity(total_len);

    // Header
    out.push(PROTOCOL_VERSION);
    out.push(SUITE_KEM_HYBRID);
    out.push(SUITE_AEAD_AES256GCM);
    out.push(FLAGS_V1);
    out.extend_from_slice(&(HYBRID_CIPHERTEXT_BYTES as u16).to_be_bytes());

    // KEM ciphertext (x25519 || mlkem)
    out.extend_from_slice(kem_ct);

    // Nonce
    out.extend_from_slice(nonce);

    // AEAD ciphertext
    out.extend_from_slice(aead_ct);

    debug_assert_eq!(out.len(), total_len);
    
    Ok(out)
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
        assert_eq!(HYBRID_CIPHERTEXT_BYTES, 1120);
        assert_eq!(X25519_CIPHERTEXT_BYTES, 32);
        assert_eq!(MLKEM_CIPHERTEXT_BYTES, 1088);
        assert_eq!(MIN_HYBRID_CIPHERTEXT_BYTES, 6 + 1120 + 12 + 16);
        assert_eq!(MIN_HYBRID_CIPHERTEXT_BYTES, 1154);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let kem_ct = vec![0x42u8; HYBRID_CIPHERTEXT_BYTES];
        let nonce = [0x11u8; NONCE_BYTES];
        let aead_ct = vec![0x33u8; 32]; // 16 bytes plaintext + 16 bytes tag

        let encoded = encode_hybrid_wire(&kem_ct, &nonce, &aead_ct).unwrap();
        
        assert_eq!(encoded.len(), HEADER_BYTES + HYBRID_CIPHERTEXT_BYTES + NONCE_BYTES + 32);

        let decoded = decode_hybrid_wire(&encoded).unwrap();

        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.suite_kem, SUITE_KEM_HYBRID);
        assert_eq!(decoded.suite_aead, SUITE_AEAD_AES256GCM);
        assert_eq!(decoded.flags, FLAGS_V1);
        assert_eq!(decoded.kem_ct_len as usize, HYBRID_CIPHERTEXT_BYTES);
        assert_eq!(decoded.kem_ciphertext, &kem_ct[..]);
        assert_eq!(decoded.x25519_ciphertext, &[0x42u8; X25519_CIPHERTEXT_BYTES]);
        assert_eq!(decoded.mlkem_ciphertext, &[0x42u8; MLKEM_CIPHERTEXT_BYTES]);
        assert_eq!(decoded.nonce, &nonce);
        assert_eq!(decoded.aead_ciphertext, &aead_ct[..]);
    }

    #[test]
    fn test_zero_copy_kem_ciphertext() {
        let kem_ct = vec![0x42u8; HYBRID_CIPHERTEXT_BYTES];
        let nonce = [0x11u8; NONCE_BYTES];
        let aead_ct = vec![0x33u8; 32];

        let encoded = encode_hybrid_wire(&kem_ct, &nonce, &aead_ct).unwrap();
        let decoded = decode_hybrid_wire(&encoded).unwrap();

        // Verify kem_ciphertext is a slice into the original buffer
        // (no allocation occurred)
        let kem_ptr = decoded.kem_ciphertext.as_ptr();
        let buffer_kem_start = encoded[HEADER_BYTES..].as_ptr();
        assert_eq!(kem_ptr, buffer_kem_start);
        
        // Verify length
        assert_eq!(decoded.kem_ciphertext.len(), HYBRID_CIPHERTEXT_BYTES);
    }

    #[test]
    fn test_rejects_wrong_version() {
        let mut data = vec![0u8; MIN_HYBRID_CIPHERTEXT_BYTES];
        data[0] = 0x99; // Wrong version
        data[1] = SUITE_KEM_HYBRID;
        data[2] = SUITE_AEAD_AES256GCM;
        data[3] = FLAGS_V1;
        data[4..6].copy_from_slice(&(HYBRID_CIPHERTEXT_BYTES as u16).to_be_bytes());

        assert!(decode_hybrid_wire(&data).is_err());
    }

    #[test]
    fn test_rejects_wrong_kem_suite() {
        let mut data = vec![0u8; MIN_HYBRID_CIPHERTEXT_BYTES];
        data[0] = PROTOCOL_VERSION;
        data[1] = 0xA2; // ML-KEM only, not hybrid
        data[2] = SUITE_AEAD_AES256GCM;
        data[3] = FLAGS_V1;
        data[4..6].copy_from_slice(&(HYBRID_CIPHERTEXT_BYTES as u16).to_be_bytes());

        assert!(decode_hybrid_wire(&data).is_err());
    }

    #[test]
    fn test_rejects_wrong_aead_suite() {
        let mut data = vec![0u8; MIN_HYBRID_CIPHERTEXT_BYTES];
        data[0] = PROTOCOL_VERSION;
        data[1] = SUITE_KEM_HYBRID;
        data[2] = 0x99; // Unknown AEAD suite
        data[3] = FLAGS_V1;
        data[4..6].copy_from_slice(&(HYBRID_CIPHERTEXT_BYTES as u16).to_be_bytes());

        assert!(decode_hybrid_wire(&data).is_err());
    }

    #[test]
    fn test_rejects_nonzero_flags() {
        let mut data = vec![0u8; MIN_HYBRID_CIPHERTEXT_BYTES];
        data[0] = PROTOCOL_VERSION;
        data[1] = SUITE_KEM_HYBRID;
        data[2] = SUITE_AEAD_AES256GCM;
        data[3] = 0x01; // Non-zero flags
        data[4..6].copy_from_slice(&(HYBRID_CIPHERTEXT_BYTES as u16).to_be_bytes());

        assert!(decode_hybrid_wire(&data).is_err());
    }

    #[test]
    fn test_rejects_wrong_kem_length() {
        let mut data = vec![0u8; MIN_HYBRID_CIPHERTEXT_BYTES];
        data[0] = PROTOCOL_VERSION;
        data[1] = SUITE_KEM_HYBRID;
        data[2] = SUITE_AEAD_AES256GCM;
        data[3] = FLAGS_V1;
        data[4..6].copy_from_slice(&1088u16.to_be_bytes()); // Wrong length

        assert!(decode_hybrid_wire(&data).is_err());
    }

    #[test]
    fn test_rejects_truncated() {
        let data = vec![0u8; MIN_HYBRID_CIPHERTEXT_BYTES - 1];
        assert!(decode_hybrid_wire(&data).is_err());
    }

    #[test]
    fn test_rejects_empty() {
        let data = vec![];
        assert!(decode_hybrid_wire(&data).is_err());
    }

    #[test]
    fn test_encode_rejects_wrong_kem_length() {
        let kem_ct = vec![0u8; HYBRID_CIPHERTEXT_BYTES - 1]; // Too short
        let nonce = [0u8; NONCE_BYTES];
        let aead_ct = vec![0u8; 16];

        assert!(encode_hybrid_wire(&kem_ct, &nonce, &aead_ct).is_err());
    }

    #[test]
    fn test_encode_rejects_short_aead() {
        let kem_ct = vec![0u8; HYBRID_CIPHERTEXT_BYTES];
        let nonce = [0u8; NONCE_BYTES];
        let aead_ct = vec![0u8; 15]; // Too short (less than tag)

        assert!(encode_hybrid_wire(&kem_ct, &nonce, &aead_ct).is_err());
    }

    #[test]
    fn test_minimum_valid_ciphertext() {
        // Minimum: header + kem_ct + nonce + tag_only (no plaintext)
        let kem_ct = vec![0xAAu8; HYBRID_CIPHERTEXT_BYTES];
        let nonce = [0xBBu8; NONCE_BYTES];
        let aead_ct = vec![0xCCu8; AEAD_TAG_BYTES]; // Tag only, no plaintext

        let encoded = encode_hybrid_wire(&kem_ct, &nonce, &aead_ct).unwrap();
        assert_eq!(encoded.len(), MIN_HYBRID_CIPHERTEXT_BYTES);

        let decoded = decode_hybrid_wire(&encoded).unwrap();
        assert_eq!(decoded.aead_ciphertext.len(), AEAD_TAG_BYTES);
    }

    #[test]
    fn test_large_plaintext() {
        let kem_ct = vec![0xAAu8; HYBRID_CIPHERTEXT_BYTES];
        let nonce = [0xBBu8; NONCE_BYTES];
        let aead_ct = vec![0xCCu8; 1024 * 1024]; // 1 MB

        let encoded = encode_hybrid_wire(&kem_ct, &nonce, &aead_ct).unwrap();
        let decoded = decode_hybrid_wire(&encoded).unwrap();
        
        assert_eq!(decoded.aead_ciphertext.len(), 1024 * 1024);
    }
}
