# Citadel

**Post-quantum encryption that enforces correct key usage — so your application cannot misuse it even if it tries.**

```rust
// Rust library
let citadel = Citadel::new();
let (pk, sk) = citadel.generate_keypair();
let encrypted = citadel.seal(&pk, b"sensitive data", &aad, &ctx)?;
let decrypted = citadel.open(&sk, &encrypted, &aad, &ctx)?;
```

```python
# REST API — any language
blob = requests.post(f"{api}/api/keys/{key_id}/encrypt",
    json={"plaintext": "sensitive data", "aad": "record-001", "context": "prod"}).json()
plaintext = requests.post(f"{api}/api/decrypt",
    json={"blob": blob, "aad": "record-001", "context": "prod"}).json()["plaintext"]
```

Behind those two lines: ML-KEM-768 + X25519 hybrid key encapsulation, AES-256-GCM encryption, automatic key rotation, tamper-proof audit logging, and adaptive threat response. All enforced. None optional.

> **Commercial use requires a license.** Contact andre.cordero36@gmail.com

---

## What problem this solves

Most encryption libraries give you primitives and let you assemble them incorrectly. Citadel gives you a constrained system where:

- Keys have enforced lifecycle states — you cannot encrypt with a revoked key
- Rotation happens automatically on schedule or under threat
- Every operation is logged in a tamper-evident audit chain
- Decryption failures are uniform — no oracle, no information leak
- Tampered ciphertext fails immediately and silently

**This is what correct failure looks like:**

```rust
// Wrong key — fails
citadel.open(&wrong_sk, &ct, &aad, &ctx) // Err(OpenError)

// Tampered ciphertext — fails
ct[100] ^= 0x01;
citadel.open(&sk, &ct, &aad, &ctx) // Err(OpenError)

// Wrong AAD — fails
citadel.open(&sk, &ct, &Aad::raw(b"wrong"), &ctx) // Err(OpenError)

// All errors are identical — no information leak
assert_eq!(err1, err2, err3, err4);
```

---

## Why post-quantum, why now

NIST finalized ML-KEM (FIPS 203) in August 2024. CNSA 2.0 mandates post-quantum adoption for national security systems by 2030. Financial regulators and healthcare compliance frameworks are actively updating requirements.

Citadel uses a hybrid construction — classical X25519 and post-quantum ML-KEM-768 in parallel. Security holds if either primitive remains secure. This is NIST's recommended approach for the transition period.

---

## Architecture

```
citadel-envelope    Hybrid encryption core (no_std compatible Rust library)
citadel-keystore    Key lifecycle management, 4-level hierarchy, threat-adaptive policies
citadel-api         HTTP server with scoped auth, rate limiting, real-time dashboard
```

Use `citadel-envelope` as a standalone Rust library, or run `citadel-api` as a sidecar service any language can call over HTTP.

---

## Key management

### 4-Level hierarchy (NIST SP 800-57)

```
Root Key
  └── Domain Key (per environment / business unit)
        └── KEK — Key Encrypting Key
              └── DEK — Data Encrypting Key (encrypts application data)
```

A compromised DEK does not expose other DEKs. Blast radius is contained at every level.

### Enforced lifecycle

```
PENDING → ACTIVE → ROTATED → EXPIRED → DESTROYED
                └── REVOKED ──────────────┘
```

Every transition is validated. You cannot encrypt with a PENDING key. You cannot destroy an ACTIVE key. The system enforces what your policy requires.

### Adaptive threat response

| Level | Effect |
|-------|--------|
| LOW | Standard rotation schedules |
| GUARDED | Slightly tighter rotation |
| ELEVATED | Compressed schedules |
| HIGH | Forced rotation, reduced usage limits |
| CRITICAL | Maximum restrictions, auto-rotate |

Events that escalate: decryption failures, failed authentication, rapid access patterns. Score decays over time.

---

## Cryptography

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| Post-quantum KEM | ML-KEM-768 | FIPS 203 |
| Classical KEM | X25519 ECDH | RFC 7748 |
| Symmetric encryption | AES-256-GCM | NIST SP 800-38D |
| Key derivation | HKDF-SHA256 | NIST SP 800-56C |

### Wire format

```
version[1] || suite_kem[1] || suite_aead[1] || flags[1] || kem_ct_len[2] ||
x25519_ephemeral_pk[32] || mlkem768_ct[1088] || nonce[12] || aead_ct[variable]
```

Self-describing and versioned. No negotiation — prevents downgrade attacks. See [SPEC.md](SPEC.md).

---

## Quick start

### Docker

```bash
git clone https://github.com/mrcord77/rust_citadel.git
cd rust_citadel
CITADEL_API_KEY=your-secret CITADEL_SEED_DEMO=true docker compose up -d
curl http://localhost:3000/health
```

Dashboard: http://localhost:3000

### Rust library

```toml
# Cargo.toml — contact andre.cordero36@gmail.com for commercial license
citadel-envelope = { git = "https://github.com/mrcord77/rust_citadel" }
```

```rust
use citadel_envelope::{Citadel, Aad, Context};

let citadel = Citadel::new();
let (pk, sk) = citadel.generate_keypair();

let aad = Aad::for_storage("my-bucket", "object-123", 1);
let ctx = Context::for_application("myapp", "prod");

let ct = citadel.seal(&pk, b"secret", &aad, &ctx)?;
let pt = citadel.open(&sk, &ct, &aad, &ctx)?;
```

---

## Test results

```
running 67 tests

citadel-envelope: 22 tests — roundtrip, tamper detection, wire format, key serialization
citadel-keystore: 45 tests — lifecycle, rotation, revocation, policy, threat escalation, audit

test result: ok. 67 passed; 0 failed
```

---

## Compliance

Mapped against NIST SP 800-57: 26 controls satisfied, 7 partial, 1 gap.

Relevant frameworks: NIST SP 800-57, CNSA 2.0, HIPAA encryption at rest, SOC 2 access controls and audit.

See [COMPLIANCE_MATRIX.md](COMPLIANCE_MATRIX.md).

---

## Security status

Citadel is **unaudited**. Uses NIST-standardized primitives via established Rust crates (`ml-kem`, `x25519-dalek`, `aes-gcm`, `hkdf`). No cryptographic algorithms were invented.

Done: comprehensive tests, fuzz testing of wire parser and decryption path, uniform error handling.

Not done: independent security audit, formal verification, FIPS validation, production deployment.

Do not use for sensitive production data without independent review. See [SECURITY.md](SECURITY.md).

---

## Licensing

**Non-commercial use** (personal, academic, research) is free.

**Commercial use** requires a paid license — this includes use within a for-profit organization, incorporation into a commercial product, or offering as a hosted service.

Commercial licensing: **andre.cordero36@gmail.com**

---

## Author

Andre Cordero — andre.cordero36@gmail.com
