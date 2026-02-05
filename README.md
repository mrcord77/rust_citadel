# Citadel SDK

**Drop-in hybrid post-quantum encryption for long-lived data.**

Citadel gives you a stable, misuse-resistant way to encrypt data that will remain secure even after large-scale quantum computers exist — without redesigning your system.

## What This Solves

You have data that needs to stay encrypted for years:
- Database fields
- Backup archives  
- Configuration secrets
- Inter-service payloads

Current encryption will break when quantum computers mature. Replacing your crypto stack later is expensive and error-prone.

Citadel lets you encrypt now with hybrid security: if *either* classical (X25519) or post-quantum (ML-KEM-768) cryptography remains secure, your data stays protected.

## Quick Start

```rust
use citadel_sdk::{Citadel, Aad, Context};

let citadel = Citadel::new();
let (public_key, secret_key) = citadel.generate_keypair();

// Typed AAD and context prevent misuse
let aad = Aad::for_storage("my-bucket", "config.enc", 1);
let ctx = Context::for_application("myapp", "prod");

// Encrypt
let ciphertext = citadel.seal(&public_key, b"secret data", &aad, &ctx)?;

// Decrypt (AAD and context must match exactly)
let plaintext = citadel.open(&secret_key, &ciphertext, &aad, &ctx)?;
```

## What You Get

| Feature | Why It Matters |
|---------|----------------|
| **Hybrid KEM** | X25519 + ML-KEM-768 — secure if either holds |
| **Stable wire format** | Versioned, self-describing, documented |
| **Typed metadata** | `Aad` and `Context` types prevent accidental misuse |
| **Uniform errors** | Single opaque error type — no oracle attacks |
| **Key serialization** | Import/export keys for storage and rotation |
| **Inspection API** | Read ciphertext metadata without decrypting |

## What You Don't Get

We're honest about scope:

- ❌ Key management — you handle storage, rotation, access control
- ❌ Streaming — this is for discrete blobs, not TLS replacement
- ❌ FIPS certification — uses NIST-standardized primitives, not certified builds
- ❌ Constant-time guarantees — inherited from dependencies, not independently verified

## API Surface

```rust
// Main interface
Citadel::new() -> Citadel
Citadel::generate_keypair() -> (PublicKey, SecretKey)
Citadel::seal(pk, plaintext, aad, context) -> Result<Vec<u8>, SealError>
Citadel::open(sk, ciphertext, aad, context) -> Result<Vec<u8>, OpenError>

// Typed metadata
Aad::for_storage(bucket, object_id, version)
Aad::for_database(table, row_id, column)
Aad::for_backup(system, timestamp)
Aad::for_message(sender, recipient, msg_id)
Aad::raw(bytes)

Context::for_application(app_name, environment)
Context::for_backup(system, epoch)
Context::for_service(from, to, protocol_version)
Context::for_secrets(namespace, key_id)
Context::raw(bytes)

// Inspection
inspect(ciphertext) -> Result<CiphertextInfo, OpenError>

// Key serialization
PublicKey::to_bytes() -> [u8; 1216]
PublicKey::from_bytes(bytes) -> Result<PublicKey, OpenError>
SecretKey::to_bytes() -> [u8; 2432]
SecretKey::from_bytes(bytes) -> Result<SecretKey, OpenError>
```

## Wire Format

Self-describing, versioned, documented in [SPEC.md](./SPEC.md).

```
version[1] | kem_suite[1] | aead_suite[1] | flags[1] | kem_ct_len[2]
         | kem_ciphertext[1120] | nonce[12] | aead_ciphertext[16+]
```

Minimum ciphertext: **1154 bytes**

## Security Properties

**Provided:**
- IND-CCA2 security (hybrid)
- AAD/context binding
- Tampering detection
- Uniform failure behavior

**Not provided:**
- Forward secrecy (use ephemeral keys per message if needed)
- Authenticated sender (this is encryption, not signing)
- Deniability

See [THREAT_MODEL.md](./THREAT_MODEL.md) for full details.

## CLI

```bash
# Generate keypair
citadel keygen --output keys/

# Encrypt file
citadel seal --key keys/public.key --aad "backup|db|2026" \
             --context "myapp|prod" --input data.json --output data.enc

# Decrypt file  
citadel open --key keys/secret.key --aad "backup|db|2026" \
             --context "myapp|prod" --input data.enc --output data.json

# Inspect without decrypting
citadel inspect data.enc
```

## Installation

```toml
[dependencies]
citadel-sdk = "0.1"
```

Requires Rust 1.74+.

## License

MIT OR Apache-2.0

## Support

- **Community:** GitHub Issues (best effort)
- **Pro:** Security contact, upgrade notes, version guarantees
- **Enterprise:** SLA, custom builds, audit assistance

Contact: [your-email]

---

*Citadel is unaudited software. Use at your own risk. See [SECURITY.md](./SECURITY.md) for disclosure policy.*
