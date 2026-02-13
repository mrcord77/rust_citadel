//! Comparative benchmarks: Citadel Hybrid vs RSA-2048+AES vs pure AES-256-GCM.
//!
//! Run with: `cargo bench --bench comparative`
//!
//! These benchmarks compare wall-clock performance across three encryption
//! approaches at multiple payload sizes. The goal is to show where Citadel's
//! hybrid post-quantum overhead lands relative to classical alternatives.
//!
//! NOTE: This compares apples to oranges in security properties:
//!   - Citadel: post-quantum hybrid (X25519 + ML-KEM-768) + AES-256-GCM
//!   - RSA+AES: classical public-key (RSA-2048-OAEP) + AES-256-GCM
//!   - Pure AES: symmetric only (AES-256-GCM, pre-shared key)
//!
//! The "pure AES" baseline shows the symmetric floor; all KEM-based schemes
//! add overhead on top of it.

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

// ---------------------------------------------------------------------------
// Citadel
// ---------------------------------------------------------------------------
use citadel_envelope::{Citadel, Aad, Context, KemProvider, HybridX25519MlKem768Provider};

// ---------------------------------------------------------------------------
// RSA-2048 + AES-256-GCM  (classical hybrid baseline)
// ---------------------------------------------------------------------------
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::rngs::OsRng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

/// Payload sizes to benchmark.
const PAYLOAD_SIZES: &[usize] = &[64, 1024, 65_536, 1_048_576];

// ---------------------------------------------------------------------------
// Key generation comparison
// ---------------------------------------------------------------------------

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");

    group.bench_function("citadel_hybrid", |b| {
        b.iter(|| HybridX25519MlKem768Provider::keygen());
    });

    group.bench_function("rsa_2048", |b| {
        b.iter(|| {
            let _sk = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA keygen");
        });
    });

    // AES keygen is just random bytes — included for completeness
    group.bench_function("aes_256_gcm_key", |b| {
        b.iter(|| Aes256Gcm::generate_key(OsRng));
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Encryption (seal) comparison across payload sizes
// ---------------------------------------------------------------------------

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");

    // Pre-generate keys once
    let citadel = Citadel::new();
    let (citadel_pk, _citadel_sk) = citadel.generate_keypair();

    let rsa_sk = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA keygen");
    let rsa_pk = RsaPublicKey::from(&rsa_sk);

    let aes_key = Aes256Gcm::generate_key(OsRng);
    let aes_cipher = Aes256Gcm::new(&aes_key);

    let aad = Aad::raw(b"bench-aad");
    let ctx = Context::raw(b"bench-ctx");

    for &size in PAYLOAD_SIZES {
        let plaintext = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        // --- Citadel Hybrid ---
        group.bench_with_input(
            BenchmarkId::new("citadel_hybrid", size),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    citadel.seal(&citadel_pk, pt, &aad, &ctx).unwrap();
                });
            },
        );

        // --- RSA-2048 + AES-256-GCM ---
        // Simulates: RSA-OAEP encrypt a fresh AES key, then AES-GCM encrypt payload.
        // This is the classical hybrid pattern (like TLS RSA key transport).
        group.bench_with_input(
            BenchmarkId::new("rsa2048_aes256gcm", size),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    // Generate ephemeral AES key
                    let eph_key = Aes256Gcm::generate_key(OsRng);
                    // RSA-OAEP encrypt the AES key
                    let _enc_key = rsa_pk
                        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), eph_key.as_slice())
                        .unwrap();
                    // AES-GCM encrypt the payload
                    let cipher = Aes256Gcm::new(&eph_key);
                    let nonce = Nonce::from([0u8; 12]); // fixed nonce ok for bench
                    let _ct = cipher.encrypt(&nonce, pt.as_slice()).unwrap();
                });
            },
        );

        // --- Pure AES-256-GCM (symmetric baseline) ---
        group.bench_with_input(
            BenchmarkId::new("aes256gcm_only", size),
            &plaintext,
            |b, pt| {
                let nonce = Nonce::from([0u8; 12]);
                b.iter(|| {
                    let _ct = aes_cipher.encrypt(&nonce, pt.as_slice()).unwrap();
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Decryption (open) comparison across payload sizes
// ---------------------------------------------------------------------------

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt");

    // Pre-generate keys and ciphertexts
    let citadel = Citadel::new();
    let (citadel_pk, citadel_sk) = citadel.generate_keypair();

    let rsa_sk = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA keygen");
    let rsa_pk = RsaPublicKey::from(&rsa_sk);

    let aes_key = Aes256Gcm::generate_key(OsRng);
    let aes_cipher = Aes256Gcm::new(&aes_key);

    let aad = Aad::raw(b"bench-aad");
    let ctx = Context::raw(b"bench-ctx");

    for &size in PAYLOAD_SIZES {
        let plaintext = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        // --- Citadel Hybrid ---
        let citadel_ct = citadel
            .seal(&citadel_pk, &plaintext, &aad, &ctx)
            .unwrap();
        group.bench_with_input(
            BenchmarkId::new("citadel_hybrid", size),
            &citadel_ct,
            |b, ct| {
                b.iter(|| {
                    citadel.open(&citadel_sk, ct, &aad, &ctx).unwrap();
                });
            },
        );

        // --- RSA-2048 + AES-256-GCM ---
        let eph_key = Aes256Gcm::generate_key(OsRng);
        let enc_key = rsa_pk
            .encrypt(&mut OsRng, Oaep::new::<Sha256>(), eph_key.as_slice())
            .unwrap();
        let eph_cipher = Aes256Gcm::new(&eph_key);
        let nonce_bytes = [0u8; 12];
        let nonce = Nonce::from(nonce_bytes);
        let rsa_aes_ct = eph_cipher.encrypt(&nonce, plaintext.as_slice()).unwrap();
        group.bench_with_input(
            BenchmarkId::new("rsa2048_aes256gcm", size),
            &(&enc_key, &rsa_aes_ct),
            |b, (enc_k, ct)| {
                b.iter(|| {
                    // RSA-OAEP decrypt the AES key
                    let recovered_key = rsa_sk
                        .decrypt(Oaep::new::<Sha256>(), enc_k)
                        .unwrap();
                    // AES-GCM decrypt
                    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&recovered_key);
                    let cipher = Aes256Gcm::new(key);
                    let nonce = Nonce::from(nonce_bytes);
                    let _pt = cipher.decrypt(&nonce, ct.as_slice()).unwrap();
                });
            },
        );

        // --- Pure AES-256-GCM (symmetric baseline) ---
        let aes_ct = aes_cipher.encrypt(&nonce, plaintext.as_slice()).unwrap();
        group.bench_with_input(
            BenchmarkId::new("aes256gcm_only", size),
            &aes_ct,
            |b, ct| {
                let nonce = Nonce::from(nonce_bytes);
                b.iter(|| {
                    let _pt = aes_cipher.decrypt(&nonce, ct.as_slice()).unwrap();
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Ciphertext overhead comparison
// ---------------------------------------------------------------------------

fn bench_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("overhead_bytes");
    // This isn't really a "benchmark" but criterion is a convenient way to
    // report the numbers alongside timing data.

    let citadel = Citadel::new();
    let (citadel_pk, _) = citadel.generate_keypair();

    let rsa_sk = RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA keygen");
    let rsa_pk = RsaPublicKey::from(&rsa_sk);

    let plaintext = vec![0u8; 64];
    let aad = Aad::raw(b"bench-aad");
    let ctx = Context::raw(b"bench-ctx");

    // Citadel overhead
    let citadel_ct = citadel.seal(&citadel_pk, &plaintext, &aad, &ctx).unwrap();
    let citadel_overhead = citadel_ct.len() - plaintext.len();

    // RSA+AES overhead
    let eph_key = Aes256Gcm::generate_key(OsRng);
    let enc_key = rsa_pk
        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), eph_key.as_slice())
        .unwrap();
    let eph_cipher = Aes256Gcm::new(&eph_key);
    let nonce = Nonce::from([0u8; 12]);
    let rsa_aes_ct = eph_cipher.encrypt(&nonce, plaintext.as_slice()).unwrap();
    let rsa_overhead = enc_key.len() + 12 + rsa_aes_ct.len() - plaintext.len();

    // AES overhead
    let aes_key = Aes256Gcm::generate_key(OsRng);
    let aes_cipher = Aes256Gcm::new(&aes_key);
    let aes_ct = aes_cipher.encrypt(&nonce, plaintext.as_slice()).unwrap();
    let aes_overhead = 12 + aes_ct.len() - plaintext.len();

    // Print the overhead report (visible in cargo bench output)
    println!("\n=== Ciphertext Overhead (bytes added to 64B plaintext) ===");
    println!("  Citadel Hybrid:    {} bytes  (ct total: {})", citadel_overhead, citadel_ct.len());
    println!("  RSA-2048 + AES:    {} bytes  (enc_key: {} + nonce: 12 + ct: {})", rsa_overhead, enc_key.len(), rsa_aes_ct.len());
    println!("  Pure AES-256-GCM:  {} bytes  (nonce: 12 + ct: {})", aes_overhead, aes_ct.len());
    println!();

    // Also benchmark a trivial op so criterion doesn't complain
    group.bench_function("report_printed", |b| b.iter(|| {}));
    group.finish();
}

criterion_group!(benches, bench_keygen, bench_encrypt, bench_decrypt, bench_overhead);
criterion_main!(benches);
