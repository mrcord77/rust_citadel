//! Internal-facing wrapper with stable naming + locked AAD/context builders.

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    aad, CitadelMlKem768, DecryptionError, EncodingError, MsgId16, PublicKey, SecretKey,
};

/// Internal-friendly envelope façade.
pub struct Envelope {
    inner: CitadelMlKem768,
}

impl Default for Envelope {
    fn default() -> Self {
        Self::new()
    }
}

impl Envelope {
    /// Create a new Envelope façade.
    pub fn new() -> Self {
        Self {
            inner: CitadelMlKem768::new(),
        }
    }

    /// Generate a new keypair (public key, secret key).
    pub fn generate_keypair(&self) -> (PublicKey, SecretKey) {
        self.inner.keygen()
    }

    /// Seal plaintext to recipient public key (raw aad/context).
    pub fn seal(
        &self,
        pk: &PublicKey,
        plaintext: &[u8],
        aad: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, EncodingError> {
        self.inner.encrypt(pk, plaintext, aad, context)
    }

    /// Open ciphertext using recipient secret key (raw aad/context).
    pub fn open(
        &self,
        sk: &SecretKey,
        ciphertext: &[u8],
        aad: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        self.inner.decrypt(sk, ciphertext, aad, context)
    }

    /// Build canonical context (locked convention).
    pub fn build_context(&self, env: &str, purpose: &str) -> Vec<u8> {
        aad::build_context(env, purpose)
    }

    /// Build canonical AAD (locked convention).
    pub fn build_aad(
        &self,
        sender_id: &str,
        recipient_id: &str,
        route: &str,
        ts_unix_ms: u64,
        seq: u64,
        msg_id: MsgId16,
    ) -> Result<Vec<u8>, EncodingError> {
        aad::build_aad(sender_id, recipient_id, route, ts_unix_ms, seq, msg_id)
    }

    /// Generate a random msg_id (16 bytes).
    pub fn generate_msg_id(&self) -> Result<MsgId16, EncodingError> {
        aad::generate_msg_id()
    }

    /// Convenience: build context + aad and then seal.
    pub fn seal_internal(
        &self,
        pk: &PublicKey,
        plaintext: &[u8],
        env: &str,
        purpose: &str,
        sender_id: &str,
        recipient_id: &str,
        route: &str,
        ts_unix_ms: u64,
        seq: u64,
        msg_id: MsgId16,
    ) -> Result<Vec<u8>, EncodingError> {
        let ctx = aad::build_context(env, purpose);
        let aad_bytes = aad::build_aad(sender_id, recipient_id, route, ts_unix_ms, seq, msg_id)?;
        self.seal(pk, plaintext, &aad_bytes, &ctx)
    }

    /// Convenience: build context + aad and then open.
    pub fn open_internal(
        &self,
        sk: &SecretKey,
        ciphertext: &[u8],
        env: &str,
        purpose: &str,
        sender_id: &str,
        recipient_id: &str,
        route: &str,
        ts_unix_ms: u64,
        seq: u64,
        msg_id: MsgId16,
    ) -> Result<Vec<u8>, DecryptionError> {
        let ctx = aad::build_context(env, purpose);
        let aad_bytes = aad::build_aad(sender_id, recipient_id, route, ts_unix_ms, seq, msg_id)
            .map_err(|_| DecryptionError)?;
        self.open(sk, ciphertext, &aad_bytes, &ctx)
    }

    /// Expose the underlying engine if needed internally.
    pub fn inner(&self) -> &CitadelMlKem768 {
        &self.inner
    }
}
