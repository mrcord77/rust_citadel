//! Known Answer / envelope-only tests (v1 structured wire)

use citadel_envelope::{wire, CitadelMlKem768, DecryptionError};

use citadel_envelope::wire::{
    AEAD_TAG_BYTES, FLAGS_V1, HEADER_BYTES, KEM_CIPHERTEXT_BYTES, MIN_CIPHERTEXT_BYTES, NONCE_BYTES,
    PROTOCOL_VERSION, SUITE_AEAD_AES256GCM, SUITE_KEM_HYBRID_X25519_MLKEM768,
};

#[test]
fn test_wire_constants() {
    assert_eq!(KEM_CIPHERTEXT_BYTES, 1120);
    assert_eq!(NONCE_BYTES, 12);
    assert_eq!(AEAD_TAG_BYTES, 16);
    assert_eq!(HEADER_BYTES, 6);
    assert_eq!(MIN_CIPHERTEXT_BYTES, 6 + 1120 + 12 + 16);
}

#[test]
fn test_wire_format_structure() {
    let citadel = CitadelMlKem768::new();
    let (pk, _) = citadel.keygen();

    let ct = citadel.encrypt(&pk, b"test", b"", b"").unwrap();

    let parts = wire::decode_wire(&ct).unwrap();
    assert_eq!(parts.version, PROTOCOL_VERSION);
    assert_eq!(parts.suite_kem, SUITE_KEM_HYBRID_X25519_MLKEM768);
    assert_eq!(parts.suite_aead, SUITE_AEAD_AES256GCM);
    assert_eq!(parts.flags, FLAGS_V1);
    assert_eq!(parts.kem_ct_len as usize, KEM_CIPHERTEXT_BYTES);
    assert_eq!(parts.kem_ciphertext.len(), 1120);
    assert_eq!(parts.nonce.len(), 12);
    assert!(parts.aead_ciphertext.len() >= 16);
}

#[test]
fn test_minimum_ciphertext_roundtrip() {
    let citadel = CitadelMlKem768::new();
    let (pk, sk) = citadel.keygen();

    let ct = citadel.encrypt(&pk, b"", b"", b"").unwrap();
    assert_eq!(ct.len(), MIN_CIPHERTEXT_BYTES);

    let pt = citadel.decrypt(&sk, &ct, b"", b"").unwrap();
    assert!(pt.is_empty());
}

#[test]
fn test_self_consistency() {
    let citadel = CitadelMlKem768::new();
    let (pk, sk) = citadel.keygen();

    for i in 0..10 {
        let plaintext = format!("msg {}", i).into_bytes();
        let aad = format!("aad {}", i).into_bytes();

        let ct = citadel.encrypt(&pk, &plaintext, &aad, b"ctx").unwrap();
        let pt = citadel.decrypt(&sk, &ct, &aad, b"ctx").unwrap();
        assert_eq!(pt, plaintext);
    }
}

#[test]
fn test_rejects_invalid_version() {
    let citadel = CitadelMlKem768::new();
    let (pk, sk) = citadel.keygen();

    let mut ct = citadel.encrypt(&pk, b"test", b"", b"").unwrap();
    ct[0] = 0x99;
    assert!(citadel.decrypt(&sk, &ct, b"", b"").is_err());
}

#[test]
fn test_uniform_error_messages() {
    let citadel = CitadelMlKem768::new();
    let (pk, sk) = citadel.keygen();

    let ct = citadel.encrypt(&pk, b"test", b"aad", b"ctx").unwrap();

    let mut ct_bad_suite = ct.clone();
    ct_bad_suite[1] ^= 0x01; // suite_kem byte

    let errors: Vec<DecryptionError> = vec![
        citadel.decrypt(&sk, b"short", b"", b"").unwrap_err(),
        citadel.decrypt(&sk, &ct, b"wrong", b"ctx").unwrap_err(),
        citadel.decrypt(&sk, &ct, b"aad", b"wrong").unwrap_err(),
        citadel.decrypt(&sk, &ct_bad_suite, b"aad", b"ctx").unwrap_err(),
    ];

    let first = format!("{}", errors[0]);
    for e in errors {
        assert_eq!(format!("{}", e), first);
    }
}