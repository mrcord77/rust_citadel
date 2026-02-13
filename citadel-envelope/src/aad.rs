//! AAD + Context conventions (locked) for internal service use.
//!
//! Goals:
//! - deterministic encoding (language-agnostic)
//! - binds sender/recipient/route
//! - includes anti-replay fields (ts/seq/msg_id)
//! - separates environments/purposes via context
//!
//! Context (bytes):
//!   b"citadel|ctx|v1|" + env + b"|" + purpose
//!
//! AAD (bytes):
//!   b"citadel|aad|v1" || TLV(sender) || TLV(recipient) || TLV(route) || TLV(ts_ms) || TLV(seq) || TLV(msg_id_16)
//!
//! TLV:
//!   T: u8
//!   L: u16 big-endian
//!   V: bytes

extern crate alloc;

use alloc::vec::Vec;

use crate::error::EncodingError;

// -------------------------
// Public types / constants
// -------------------------

pub type MsgId16 = [u8; 16];

pub const CONTEXT_PREFIX: &[u8] = b"citadel|ctx|v1|";
pub const AAD_PREFIX: &[u8] = b"citadel|aad|v1";

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum AadTlvType {
    SenderId = 0x01,
    RecipientId = 0x02,
    Route = 0x03,
    TimestampUnixMs = 0x04, // u64 BE
    Sequence = 0x05,        // u64 BE
    MsgId16 = 0x06,         // 16 bytes
}

/// Build the canonical context:
/// `b"citadel|ctx|v1|" + env + b"|" + purpose`
pub fn build_context(env: &str, purpose: &str) -> Vec<u8> {
    // We intentionally do NOT validate allowed env/purpose strings here.
    // Enforce allowed values at the call site if desired.
    let env_b = env.as_bytes();
    let purpose_b = purpose.as_bytes();

    let mut out = Vec::with_capacity(CONTEXT_PREFIX.len() + env_b.len() + 1 + purpose_b.len());
    out.extend_from_slice(CONTEXT_PREFIX);
    out.extend_from_slice(env_b);
    out.push(b'|');
    out.extend_from_slice(purpose_b);
    out
}

/// Build canonical AAD with locked fields.
///
/// Requirements (policy-level):
/// - sender/recipient/route must be stable identifiers
/// - ts_ms should be current time in ms
/// - seq can be 0 if you don't have a channel sequence
/// - msg_id MUST be unique (per sender) for replay cache / dedupe
pub fn build_aad(
    sender_id: &str,
    recipient_id: &str,
    route: &str,
    ts_unix_ms: u64,
    seq: u64,
    msg_id: MsgId16,
) -> Result<Vec<u8>, EncodingError> {
    let s = sender_id.as_bytes();
    let r = recipient_id.as_bytes();
    let rt = route.as_bytes();

    // prefix + 6 TLVs, sizes conservative
    let mut out = Vec::with_capacity(
        AAD_PREFIX.len()
            + tlv_size(s.len())
            + tlv_size(r.len())
            + tlv_size(rt.len())
            + tlv_size(8)
            + tlv_size(8)
            + tlv_size(16),
    );

    out.extend_from_slice(AAD_PREFIX);

    push_tlv(&mut out, AadTlvType::SenderId, s)?;
    push_tlv(&mut out, AadTlvType::RecipientId, r)?;
    push_tlv(&mut out, AadTlvType::Route, rt)?;

    let ts = ts_unix_ms.to_be_bytes();
    push_tlv(&mut out, AadTlvType::TimestampUnixMs, &ts)?;

    let sq = seq.to_be_bytes();
    push_tlv(&mut out, AadTlvType::Sequence, &sq)?;

    push_tlv(&mut out, AadTlvType::MsgId16, &msg_id)?;

    Ok(out)
}

/// Generate a random 16-byte message id.
///
/// This is for internal convenience; you can also supply your own msg_id.
/// Uniqueness is the responsibility of the caller's replay/dedupe policy.
pub fn generate_msg_id() -> Result<MsgId16, EncodingError> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|_| EncodingError)?;
    Ok(id)
}

// -------------------------
// Internal helpers
// -------------------------

#[inline]
fn tlv_size(v_len: usize) -> usize {
    // T (1) + L (2) + V (v_len)
    1 + 2 + v_len
}

#[inline]
fn push_tlv(out: &mut Vec<u8>, t: AadTlvType, v: &[u8]) -> Result<(), EncodingError> {
    // Length must fit u16
    if v.len() > u16::MAX as usize {
        return Err(EncodingError);
    }
    out.push(t as u8);
    out.extend_from_slice(&(v.len() as u16).to_be_bytes());
    out.extend_from_slice(v);
    Ok(())
}
