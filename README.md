# Citadel Envelope

Post-quantum hybrid encryption using **X25519 + ML-KEM-768 + AES-256-GCM**.

[![Crates.io](https://img.shields.io/crates/v/citadel-envelope.svg)](https://crates.io/crates/citadel-envelope)
[![Documentation](https://docs.rs/citadel-envelope/badge.svg)](https://docs.rs/citadel-envelope)
[![License](https://img.shields.io/crates/l/citadel-envelope.svg)](LICENSE)

## Overview

Citadel Envelope provides defense-in-depth hybrid encryption:

- **X25519**: Classical ECDH, protects if ML-KEM is broken by cryptanalysis
- **ML-KEM-768**: Post-quantum KEM (FIPS 203), protects against quantum computers
- **AES-256-GCM**: Authenticated encryption for the payload

This is the same approach used by Signal, Chrome, and Cloudflare.

## Features

- 🔐 **Defense-in-depth**: Secure if either X25519 OR ML-KEM is secure
- 📦 **Simple API**: `encrypt()` / `decrypt()` with context binding
- 🛡️ **No timing oracles**: Uniform error handling
- 🔒 **Constant-time**: Uses vetted primitives
- 📏 **Locked constraints**: Interoperability by design
- 🦀 **No unsafe**: Pure safe Rust
- 📚 **no_std**: Works without standard library

## Quick Start

```rust
use citadel_envelope::HybridEnvelope;

// Create envelope and generate keys
let envelope = HybridEnvelope::new();
let (public_key, secret_key) = envelope.keygen();

// Encrypt
let plaintext = b"Hello, post-quantum world!";
let aad = b"metadata";      // Authenticated but not encrypted
let context = b"my-app-v1"; // Domain separation

let ciphertext = envelope.encrypt(&public_key, plaintext, aad, context)?;

// Decrypt
let decrypted = envelope.decrypt(&secret_key, &ciphertext, aad, context)?;
assert_eq!(decrypted, plaintext);
```

## Protocol Constraints

The following limits are enforced for interoperability:

| Parameter | Limit | Notes |
|-----------|-------|-------|
| AAD | 64 KiB | Metadata, timestamps, etc. |
| Context | 256 bytes | Application identifier |
| Plaintext | ~4 GiB | AES-GCM practical limit |

## Ciphertext Overhead

| Component | Size |
|-----------|------|
| Header | 6 bytes |
| X25519 ephemeral | 32 bytes |
| ML-KEM ciphertext | 1088 bytes |
| Nonce | 12 bytes |
| Tag | 16 bytes |
| **Total overhead** | **1154 bytes** |

## Security Properties

1. **Confidentiality** — Message content is encrypted
2. **Integrity** — Tampering is detected via AEAD tag
3. **Context Binding** — Context is bound via KDF
4. **AAD Binding** — Additional data is authenticated
5. **Ciphertext Binding** — KEM ciphertext is bound to AES key
6. **Uniform Errors** — All failures return opaque "decryption failed"
7. **Defense-in-Depth** — Secure if either X25519 OR ML-KEM is secure

## Wire Format

See [SPEC.md](SPEC.md) for the complete wire format specification.

```text
ciphertext =
    version[1]       ||  // 0x01
    suite_kem[1]     ||  // 0xA3
    suite_aead[1]    ||  // 0xB1
    flags[1]         ||  // 0x00
    kem_ct_len[2]    ||  // 1120 (big-endian)
    x25519_ct[32]    ||  // Ephemeral public key
    mlkem_ct[1088]   ||  // ML-KEM ciphertext
    nonce[12]        ||  // AES-GCM nonce
    aead_ct[>=16]        // Ciphertext + tag
```

## Minimum Supported Rust Version

Rust 1.74 or later.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## References

- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM Standard
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) — X25519
- [RFC 5116](https://www.rfc-editor.org/rfc/rfc5116) — AEAD Interface
- [Signal X3DH](https://signal.org/docs/specifications/x3dh/) — Hybrid inspiration
