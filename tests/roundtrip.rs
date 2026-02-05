use citadel_envelope::{CitadelMlKem768, DecryptionError};
use citadel_envelope::wire::{
    PROTOCOL_VERSION, SUITE_KEM_HYBRID_X25519_MLKEM768, SUITE_AEAD_AES256GCM,
    FLAGS_V1, KEM_CIPHERTEXT_BYTES, HEADER_BYTES, MIN_CIPHERTEXT_BYTES,
};

fn setup() -> (CitadelMlKem768, citadel_envelope::PublicKey, citadel_envelope::SecretKey) {
    let cit = CitadelMlKem768::new();
    let (pk, sk) = cit.keygen();
    (cit, pk, sk)
}

#[test]
fn roundtrip_basic() {
    let (cit, pk, sk) = setup();
    let plaintext = b"hello post-quantum world";
    let aad = b"test-aad";
    let ctx = b"test-context";

    let ct = cit.encrypt(&pk, plaintext, aad, ctx).unwrap();
    let pt = cit.decrypt(&sk, &ct, aad, ctx).unwrap();
    assert_eq!(&pt, plaintext);
}

#[test]
fn roundtrip_empty_plaintext() {
    let (cit, pk, sk) = setup();
    let ct = cit.encrypt(&pk, b"", b"aad", b"ctx").unwrap();
    let pt = cit.decrypt(&sk, &ct, b"aad", b"ctx").unwrap();
    assert_eq!(pt, b"");
}

#[test]
fn roundtrip_large_plaintext() {
    let (cit, pk, sk) = setup();
    let plaintext = vec![0xABu8; 65536];
    let ct = cit.encrypt(&pk, &plaintext, b"aad", b"ctx").unwrap();
    let pt = cit.decrypt(&sk, &ct, b"aad", b"ctx").unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn wrong_aad_fails() {
    let (cit, pk, sk) = setup();
    let ct = cit.encrypt(&pk, b"data", b"good-aad", b"ctx").unwrap();
    let result = cit.decrypt(&sk, &ct, b"bad-aad", b"ctx");
    assert_eq!(result, Err(DecryptionError));
}

#[test]
fn wrong_context_fails() {
    let (cit, pk, sk) = setup();
    let ct = cit.encrypt(&pk, b"data", b"aad", b"good-ctx").unwrap();
    let result = cit.decrypt(&sk, &ct, b"aad", b"bad-ctx");
    assert_eq!(result, Err(DecryptionError));
}

#[test]
fn wrong_key_fails() {
    let (cit, pk, _sk) = setup();
    let (_, _, sk2) = setup();
    let ct = cit.encrypt(&pk, b"data", b"aad", b"ctx").unwrap();
    let result = cit.decrypt(&sk2, &ct, b"aad", b"ctx");
    assert_eq!(result, Err(DecryptionError));
}

#[test]
fn header_version_check() {
    let (cit, pk, _sk) = setup();
    let ct = cit.encrypt(&pk, b"data", b"aad", b"ctx").unwrap();
    assert_eq!(ct[0], PROTOCOL_VERSION);
    assert_eq!(ct[1], SUITE_KEM_HYBRID_X25519_MLKEM768);
    assert_eq!(ct[2], SUITE_AEAD_AES256GCM);
    assert_eq!(ct[3], FLAGS_V1);
    let kem_ct_len = u16::from_be_bytes([ct[4], ct[5]]);
    assert_eq!(kem_ct_len as usize, KEM_CIPHERTEXT_BYTES);
}

#[test]
fn ciphertext_minimum_size() {
    let (cit, pk, _sk) = setup();
    let ct = cit.encrypt(&pk, b"", b"", b"").unwrap();
    assert!(ct.len() >= MIN_CIPHERTEXT_BYTES);
}

#[test]
fn tamper_version_fails() {
    let (cit, pk, sk) = setup();
    let mut ct = cit.encrypt(&pk, b"data", b"aad", b"ctx").unwrap();
    ct[0] = 0xFF;
    assert_eq!(cit.decrypt(&sk, &ct, b"aad", b"ctx"), Err(DecryptionError));
}

#[test]
fn tamper_suite_kem_fails() {
    let (cit, pk, sk) = setup();
    let mut ct = cit.encrypt(&pk, b"data", b"aad", b"ctx").unwrap();
    ct[1] = 0xA2; // old ML-KEM-only suite ID
    assert_eq!(cit.decrypt(&sk, &ct, b"aad", b"ctx"), Err(DecryptionError));
}

#[test]
fn tamper_kem_ciphertext_fails() {
    let (cit, pk, sk) = setup();
    let mut ct = cit.encrypt(&pk, b"data", b"aad", b"ctx").unwrap();
    ct[HEADER_BYTES + 10] ^= 0x01;
    assert_eq!(cit.decrypt(&sk, &ct, b"aad", b"ctx"), Err(DecryptionError));
}

#[test]
fn tamper_nonce_fails() {
    let (cit, pk, sk) = setup();
    let mut ct = cit.encrypt(&pk, b"data", b"aad", b"ctx").unwrap();
    let nonce_offset = HEADER_BYTES + KEM_CIPHERTEXT_BYTES;
    ct[nonce_offset] ^= 0x01;
    assert_eq!(cit.decrypt(&sk, &ct, b"aad", b"ctx"), Err(DecryptionError));
}

#[test]
fn tamper_aead_ciphertext_fails() {
    let (cit, pk, sk) = setup();
    let mut ct = cit.encrypt(&pk, b"data", b"aad", b"ctx").unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    assert_eq!(cit.decrypt(&sk, &ct, b"aad", b"ctx"), Err(DecryptionError));
}

#[test]
fn truncated_fails() {
    let (cit, pk, sk) = setup();
    let ct = cit.encrypt(&pk, b"data", b"aad", b"ctx").unwrap();
    assert_eq!(cit.decrypt(&sk, &ct[..10], b"aad", b"ctx"), Err(DecryptionError));
    assert_eq!(cit.decrypt(&sk, b"short", b"aad", b"ctx"), Err(DecryptionError));
    assert_eq!(cit.decrypt(&sk, b"", b"aad", b"ctx"), Err(DecryptionError));
}

#[test]
fn all_errors_are_uniform() {
    let (cit, pk, sk) = setup();
    let ct = cit.encrypt(&pk, b"data", b"aad", b"ctx").unwrap();

    let err1 = cit.decrypt(&sk, &ct, b"bad", b"ctx").unwrap_err();
    let err2 = cit.decrypt(&sk, &ct, b"aad", b"bad").unwrap_err();
    let err3 = cit.decrypt(&sk, b"short", b"aad", b"ctx").unwrap_err();

    let mut tampered = ct.clone();
    tampered[HEADER_BYTES] ^= 0x01;
    let err4 = cit.decrypt(&sk, &tampered, b"aad", b"ctx").unwrap_err();

    // All errors must be identical
    assert_eq!(err1, err2);
    assert_eq!(err2, err3);
    assert_eq!(err3, err4);
    assert_eq!(format!("{}", err1), "decryption failed");
}

#[test]
fn key_serialization_roundtrip() {
    let (cit, pk, sk) = setup();
    let plaintext = b"key serialization test";

    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    let pk2 = citadel_envelope::PublicKey::from_bytes(&pk_bytes).unwrap();
    let sk2 = citadel_envelope::SecretKey::from_bytes(&sk_bytes).unwrap();

    let ct = cit.encrypt(&pk2, plaintext, b"aad", b"ctx").unwrap();
    let pt = cit.decrypt(&sk2, &ct, b"aad", b"ctx").unwrap();
    assert_eq!(&pt, plaintext);
}
