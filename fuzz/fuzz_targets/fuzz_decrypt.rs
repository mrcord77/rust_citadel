// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fuzz target for decryption path
//!
//! This target exercises the full decrypt path with arbitrary ciphertexts.
//! Uses a fixed keypair so we can test the decryption logic.
//! Goal: Find panics, hangs, or timing variations in decrypt().

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use citadel_envelope::hybrid_envelope::HybridEnvelope;

/// Structured input for decrypt fuzzing
#[derive(Arbitrary, Debug)]
struct DecryptInput {
    /// Raw ciphertext bytes (potentially malformed)
    ciphertext: Vec<u8>,
    /// Additional authenticated data
    aad: Vec<u8>,
    /// Application context
    context: Vec<u8>,
}

// Generate a fixed keypair at startup (lazy_static pattern via thread_local)
thread_local! {
    static KEYPAIR: (
        citadel_envelope::hybrid::HybridPublicKey,
        citadel_envelope::hybrid::HybridSecretKey
    ) = {
        let envelope = HybridEnvelope::new();
        envelope.keygen()
    };
}

fuzz_target!(|input: DecryptInput| {
    // Truncate AAD and context to valid sizes to focus on ciphertext fuzzing
    let aad = if input.aad.len() > 65536 {
        &input.aad[..65536]
    } else {
        &input.aad
    };
    
    let context = if input.context.len() > 256 {
        &input.context[..256]
    } else {
        &input.context
    };
    
    KEYPAIR.with(|(_, sk)| {
        let envelope = HybridEnvelope::new();
        // decrypt() should never panic, regardless of input
        // It should return Ok(plaintext) or Err(DecryptionError)
        let _ = envelope.decrypt(sk, &input.ciphertext, aad, context);
    });
});
