# Citadel

**Post-quantum hybrid encryption and key management for production systems.**

Citadel is a complete cryptographic infrastructure library built in Rust. It implements NIST's recommended hybrid approach for the post-quantum transition — combining classical X25519 with ML-KEM-768 (FIPS 203) so that security holds even if one primitive is broken. Applications encrypt and decrypt data through a clean API. Citadel manages everything else — key generation, rotation, revocation, audit logging, and adaptive threat response.

> **Commercial use requires a license.** See [Licensing](#licensing) below or contact andre.cordero36@gmail.com.

---

## Why Citadel

**Post-quantum cryptography is not optional.** NIST finalized ML-KEM in August 2024. CNSA 2.0 mandates PQC adoption by 2030 for national security systems. Financial regulators, healthcare, and defense contractors are actively preparing now.

Citadel gives you:

- **Production-ready PQC** — ML-KEM-768 + X25519 hybrid, AES-256-GCM, HKDF — all NIST-standardized
- **Complete key management** — 4-level hierarchy, lifecycle state machine, policy-driven rotation
- **Adaptive threat intelligence** — automatic policy tightening in response to security events
- **Integrity-chained audit log** — tamper-evident log of every cryptographic operation
- **REST API + dashboard** — drop-in encryption service, no cryptography expertise required
- **67 passing tests** — roundtrip, tamper detection, key lifecycle, threat escalation, all verified

---

## Architecture

```
citadel-envelope    Hybrid encryption core (X25519 + ML-KEM-768 + AES-256-GCM)
citadel-keystore    Key lifecycle management, 4-level hierarchy, threat-adaptive policies  
citadel-api         HTTP server, scoped API key auth, rate limiting, real-time dashboard
```

```
Your Application              Citadel                         Database
       |                         |                               |
       |-- POST /encrypt ------->|                               |
       |                         |-- hybrid KEM (X25519+ML-KEM)  |
       |                         |-- derive AES-256 key (HKDF)   |
       |                         |-- encrypt with AES-256-GCM    |
       |<-- encrypted blob ------|                               |
       |                                                         |
       |-- store blob ------------------------------------------>|
```

Your application never touches raw key material. The encrypted blob is self-describing — it includes the wrapped key, algorithm identifiers, and ciphertext. Store it anywhere. Decrypt by sending it back to Citadel with the same AAD and context.

---

## Quick Start

### Docker

```bash
git clone https://github.com/mrcord77/rust_citadel.git
cd rust_citadel

# Generate an API key hash
echo -n "your-secret-key" | sha256sum | cut -d' ' -f1

# Start
CITADEL_API_KEY_HASH=<paste-hash> docker compose up -d

# Verify
curl http://localhost:3000/health
# {"status":"ok","version":"0.2.0"}
```

Dashboard: http://localhost:3000

### From Source

Requires Rust 1.75+.

```bash
cargo build --release -p citadel-api
CITADEL_API_KEY="your-secret-key" CITADEL_SEED_DEMO=true ./target/release/citadel-api
```

---

## Usage

### Python

```python
import requests

api = "http://localhost:3000"
headers = {"Authorization": "Bearer your-secret-key"}

# Encrypt
r = requests.post(f"{api}/api/keys/{dek_id}/encrypt", headers=headers, json={
    "plaintext": "sensitive data",
    "aad": "record-001",          # binds ciphertext to this record
    "context": "patient-records"  # domain separation
})
blob = r.json()

# Decrypt
r = requests.post(f"{api}/api/decrypt", headers=headers, json={
    "blob": blob,
    "aad": "record-001",
    "context": "patient-records"
})
plaintext = r.json()["plaintext"]
```

See [citadel_example.py](citadel_example.py) for a complete example with AAD binding, key rotation, and threat-aware behavior.

---

## Cryptography

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| Key encapsulation (post-quantum) | ML-KEM-768 | FIPS 203 |
| Key encapsulation (classical) | X25519 ECDH | RFC 7748 |
| Data encryption | AES-256-GCM | NIST SP 800-38D |
| Key derivation | HKDF-SHA256 | NIST SP 800-56C |

Hybrid construction: both shared secrets are concatenated and fed through HKDF. Security holds if **either** X25519 or ML-KEM-768 remains secure — defense in depth against both classical and quantum adversaries.

### Wire Format

```
version[1] || suite_kem[1] || suite_aead[1] || flags[1] || kem_ct_len[2] ||
x25519_ephemeral_pk[32] || mlkem768_ct[1088] || nonce[12] || aead_ct[variable]
```

Self-describing, versioned, no negotiation. Prevents downgrade attacks. See [SPEC.md](SPEC.md).

### Security Properties

- **Uniform errors** — All decryption failures return identical errors. No decryption oracle.
- **Zeroization** — Shared secrets and AES keys zeroed on drop via `Zeroizing<T>`
- **Constant-time comparison** — API key verification via `subtle` crate prevents timing attacks
- **Integrity-chained audit log** — SHA-256 hash chain detects log tampering
- **Rate limiting** — Per-IP token bucket with automatic threat escalation

---

## Key Management

### 4-Level Hierarchy

```
Root Key
  └── Domain Key (per environment / business unit)
        └── KEK — Key Encrypting Key
              └── DEK — Data Encrypting Key (encrypts application data)
```

Follows NIST SP 800-57. A compromised DEK does not expose other DEKs. Blast radius is contained at every level.

### Key Lifecycle

```
PENDING → ACTIVE → ROTATED → EXPIRED → DESTROYED
                └── REVOKED ──────────────┘
```

Every transition is validated, audited, and policy-enforced.

### Adaptive Threat System

Citadel monitors security events and automatically tightens key policies:

| Level | Response |
|-------|----------|
| LOW | Standard crypto-periods |
| GUARDED | Slightly tighter rotation |
| ELEVATED | Compressed rotation schedules |
| HIGH | Forced rotation, reduced usage limits |
| CRITICAL | Maximum restrictions, auto-rotate on |

Score decays over time. Events that escalate: decryption failures, failed authentication, rapid access patterns, external advisories.

---

## API

| Endpoint | Method | Scope | Description |
|----------|--------|-------|-------------|
| `/health` | GET | — | Health check |
| `/api/status` | GET | read | Threat level, key counts |
| `/api/metrics` | GET | read | Security metrics |
| `/api/keys` | GET | read | List all keys |
| `/api/keys` | POST | manage | Generate new key |
| `/api/keys/:id/activate` | POST | manage | Activate a pending key |
| `/api/keys/:id/rotate` | POST | manage | Rotate to new version |
| `/api/keys/:id/revoke` | POST | manage | Permanently revoke |
| `/api/keys/:id/destroy` | POST | manage | Destroy key material |
| `/api/keys/:id/encrypt` | POST | encrypt | Encrypt data |
| `/api/decrypt` | POST | encrypt | Decrypt data |
| `/api/threat` | GET | read | Threat intelligence |
| `/api/auth/keys` | POST | admin | Create API key |

---

## Compliance

Mapped against NIST SP 800-57: 26 controls satisfied, 7 partial, 1 gap.

Relevant frameworks: NIST SP 800-57, CNSA 2.0, HIPAA, SOC 2.

See [COMPLIANCE_MATRIX.md](COMPLIANCE_MATRIX.md) for the full mapping.

---

## Security

Citadel is **unaudited software**. The implementation uses NIST-standardized primitives via established Rust crates (`ml-kem`, `x25519-dalek`, `aes-gcm`, `hkdf`). No cryptographic algorithms were invented — the value is in correct composition and key management.

What has been done:
- 67-test suite including known-answer tests and tamper detection
- Fuzz testing of wire format parser and full decryption path
- Uniform error handling to prevent decryption oracles

What has NOT been done:
- Independent security audit
- Formal verification  
- FIPS validation
- Production deployment

**Do not use for sensitive data without independent review.**

---

## Documentation

| Document | Description |
|----------|-------------|
| [SPEC.md](SPEC.md) | Wire format specification |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Security goals and attacker model |
| [COMPLIANCE_MATRIX.md](COMPLIANCE_MATRIX.md) | NIST 800-57 control mapping |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Production deployment guide |
| [API_FREEZE.md](API_FREEZE.md) | API stability guarantees |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting |

---

## Licensing

Citadel is source-available software.

**Non-commercial use** (personal, academic, research) is free under the terms of the [LICENSE](LICENSE) file.

**Commercial use** requires a paid license. This includes incorporating Citadel into a product or service, using it within a for-profit organization, or offering it as a hosted service.

To obtain a commercial license:

**andre.cordero36@gmail.com**

---

## Author

Andre Cordero — andre.cordero36@gmail.com
