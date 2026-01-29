# Citadel Envelope — Wire Specification v1.0

This document specifies the wire format for the `citadel-envelope` crate.

**Status:** Stable  
**Version:** 1.0  
**Last Updated:** 2025-01-28

---

## Overview

Citadel Envelope provides hybrid post-quantum authenticated encryption using:

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| Classical KEM | X25519 | ~128-bit |
| Post-Quantum KEM | ML-KEM-768 (FIPS 203) | ~192-bit |
| AEAD | AES-256-GCM | 256-bit |
| KDF | HKDF-SHA256 | 256-bit |
| Ciphertext Hash | SHA3-256 | 256-bit |

**Defense-in-depth:** The hybrid construction is secure if either X25519 OR ML-KEM-768
is secure. This protects against both classical attacks (if ML-KEM is broken) and
quantum attacks (which break X25519).

This approach is used by Signal, Chrome, and Cloudflare for post-quantum protection.

---

## Protocol Constants

### Suite Identifiers

| ID | Algorithm | Status |
|----|-----------|--------|
| `0xA2` | ML-KEM-768 only | Reserved |
| `0xA3` | X25519 + ML-KEM-768 (Hybrid) | **Active** |
| `0xB1` | AES-256-GCM | **Active** |

### Size Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `HEADER_BYTES` | 6 | Wire format header |
| `X25519_CT_BYTES` | 32 | X25519 ephemeral public key |
| `MLKEM_CT_BYTES` | 1088 | ML-KEM-768 ciphertext |
| `HYBRID_CT_BYTES` | 1120 | Combined KEM ciphertext |
| `NONCE_BYTES` | 12 | AES-GCM nonce |
| `TAG_BYTES` | 16 | AES-GCM authentication tag |
| `MIN_CIPHERTEXT` | 1154 | Minimum valid ciphertext |

---

## Wire Format

### Ciphertext Structure

```text
ciphertext =
    version[1]       ||  // MUST be 0x01
    suite_kem[1]     ||  // MUST be 0xA3
    suite_aead[1]    ||  // MUST be 0xB1
    flags[1]         ||  // MUST be 0x00
    kem_ct_len[2]    ||  // u16 big-endian, MUST be 1120
    x25519_ct[32]    ||  // X25519 ephemeral public key
    mlkem_ct[1088]   ||  // ML-KEM-768 ciphertext
    nonce[12]        ||  // AES-GCM nonce (random)
    aead_ct[>=16]        // AES-GCM ciphertext + tag
```

### Header Fields

| Offset | Size | Name | Value | Description |
|--------|------|------|-------|-------------|
| 0 | 1 | version | `0x01` | Protocol version |
| 1 | 1 | suite_kem | `0xA3` | Hybrid KEM identifier |
| 2 | 1 | suite_aead | `0xB1` | AES-256-GCM identifier |
| 3 | 1 | flags | `0x00` | Reserved (must be zero) |
| 4-5 | 2 | kem_ct_len | `0x0460` | Big-endian 1120 |

### Validation Rules

Decoders MUST reject ciphertexts that fail any of these checks:

1. `len(ciphertext) < 1154` — Too short
2. `version != 0x01` — Unknown version
3. `suite_kem != 0xA3` — Unknown KEM suite
4. `suite_aead != 0xB1` — Unknown AEAD suite
5. `flags != 0x00` — Unknown flags
6. `kem_ct_len != 1120` — Wrong KEM ciphertext length
7. `len(aead_ct) < 16` — AEAD ciphertext too short for tag

All validation MUST complete before any cryptographic operations to prevent timing oracles.

---

## Key Formats

### Public Key

```text
hybrid_public_key =
    x25519_public[32]  ||  // X25519 public key
    mlkem_public[1184]     // ML-KEM-768 encapsulation key
```

**Total: 1216 bytes**

### Secret Key

```text
hybrid_secret_key =
    x25519_secret[32]  ||  // X25519 secret scalar
    mlkem_secret[2400]     // ML-KEM-768 decapsulation key
```

**Total: 2432 bytes**

---

## Cryptographic Operations

### Key Generation

1. Generate X25519 keypair using system CSPRNG
2. Generate ML-KEM-768 keypair using system CSPRNG
3. Concatenate: `pk = x25519_pk || mlkem_pk`
4. Concatenate: `sk = x25519_sk || mlkem_sk`

### Encapsulation

```
1. x25519_ephemeral, x25519_pk_ephemeral = X25519.keygen()
2. x25519_ss = X25519.dh(x25519_ephemeral, recipient_x25519_pk)
3. mlkem_ct, mlkem_ss = ML-KEM-768.encapsulate(recipient_mlkem_pk)

4. combined_ikm = x25519_ss || mlkem_ss  // 64 bytes
5. shared_secret = HKDF-SHA256(
       ikm = combined_ikm,
       salt = None,
       info = "citadel-hybrid-v1",
       len = 32
   )

6. kem_ct = x25519_pk_ephemeral || mlkem_ct  // 1120 bytes
```

### Key Derivation (AES Key)

```
ct_hash = SHA3-256(kem_ct)
info = "citadel-hybrid-env-v1" || "|aes|" || ct_hash || context
aes_key = HKDF-SHA256(
    ikm = shared_secret,
    salt = None,
    info = info,
    len = 32
)
```

### Encryption (Seal)

```
1. (shared_secret, kem_ct) = encapsulate(recipient_pk)
2. aes_key = derive_key(shared_secret, SHA3-256(kem_ct), context)
3. nonce = random(12)
4. aead_ct = AES-256-GCM.seal(aes_key, nonce, plaintext, aad)
5. ciphertext = encode_wire(kem_ct, nonce, aead_ct)
```

### Decryption (Open)

```
1. Parse and validate header (reject before KEM if invalid)
2. Extract kem_ct, nonce, aead_ct
3. shared_secret = decapsulate(sk, kem_ct)
4. aes_key = derive_key(shared_secret, SHA3-256(kem_ct), context)
5. plaintext = AES-256-GCM.open(aes_key, nonce, aead_ct, aad)
```

---

## Protocol Constraints

Applications MUST enforce these limits:

| Parameter | Limit | Rationale |
|-----------|-------|-----------|
| AAD | ≤ 65,536 bytes (64 KiB) | Prevent memory exhaustion |
| Context | ≤ 256 bytes | Domain separation identifiers are short |
| Plaintext | ≤ 4,294,967,295 bytes (~4 GiB) | AES-GCM practical limit |

Exceeding these limits MUST result in an encoding error during encryption
and MUST be rejected during decryption before any cryptographic operations.

---

## Security Properties

### Confidentiality

Message content is encrypted with AES-256-GCM.

### Integrity

Tampering is detected via the AEAD authentication tag.

### Context Binding

The application context is bound to the derived AES key via HKDF.
Decryption with a different context produces a different key and fails.

### AAD Binding

Additional authenticated data is verified by the AEAD.
Decryption with different AAD fails authentication.

### Ciphertext Binding

The KEM ciphertext is hashed (SHA3-256) and included in the AES key derivation.
This binds the key to the specific ciphertext and prevents related-key attacks.

### Uniform Errors

All decryption failures MUST return an opaque "decryption failed" error.
The error MUST NOT distinguish between:
- Invalid wire format
- Invalid KEM ciphertext
- Invalid AEAD tag
- Wrong key
- Wrong AAD
- Wrong context

This prevents error oracles that could leak information to attackers.

### Defense-in-Depth

The hybrid construction is secure if:
- X25519 is secure (protects against classical cryptanalysis of ML-KEM), OR
- ML-KEM-768 is secure (protects against quantum attacks on X25519)

An attacker must break BOTH primitives to compromise confidentiality.

---

## Compatibility

### Breaking Changes

The following changes would break compatibility with existing ciphertexts:

- Changing any constant value (version, suite IDs, sizes)
- Changing the wire format layout
- Changing the KDF info strings
- Changing constraint limits

### Non-Breaking Changes

The following changes are safe:

- Adding new suite IDs (with different values)
- Defining meaning for reserved flags bits
- Implementation optimizations

### Version Negotiation

This specification does not define version negotiation. If multiple versions
need to coexist, use different protocol identifiers at a higher layer.

---

## Test Vectors

See the `tests/hybrid_kat.rs` file for comprehensive test coverage including:

- Roundtrip encryption/decryption
- Wire format validation
- Bitflip resistance (all ciphertext positions)
- Truncation rejection
- Constraint enforcement
- Error uniformity verification

---

## References

- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM Standard
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) — X25519
- [RFC 5116](https://www.rfc-editor.org/rfc/rfc5116) — AEAD Interface
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) — HKDF
- [Signal X3DH](https://signal.org/docs/specifications/x3dh/) — Hybrid inspiration
