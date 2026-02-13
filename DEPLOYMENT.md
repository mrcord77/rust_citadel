# Citadel Production Deployment Guide

## What Changed (Tier 1 Security Hardening)

Three security gaps closed in this release:

| Gap | Before | After |
|-----|--------|-------|
| **TLS** | Plaintext HTTP, API key and encrypted data in cleartext on the wire | Caddy reverse proxy with automatic Let's Encrypt TLS |
| **Rate limiting** | None — any client could brute-force or DoS the server | Per-IP sliding window token bucket (20 rps default, 50 burst) |
| **API key storage** | Plaintext string comparison in memory | SHA-256 hash with constant-time comparison via `subtle` |

### Why SHA-256 instead of argon2?

API keys are high-entropy random strings (not passwords). Password hashing algorithms like argon2/bcrypt are designed to slow down brute-force attacks on **low-entropy** inputs. For a 256-bit random API key, SHA-256 is the correct choice — it's what Stripe, GitHub, and AWS use. The constant-time comparison via `subtle::ConstantTimeEq` prevents timing side-channels.

---

## Quick Start (Local Dev)

Nothing changes for local development. The old workflow still works:

```bash
CITADEL_API_KEY=dev-secret CITADEL_SEED_DEMO=true cargo run -p citadel-api
```

The plaintext key is automatically hashed at startup. You'll see a warning reminding you to use `CITADEL_API_KEY_HASH` in production.

---

## Production Deployment

### 1. Generate an API Key

```bash
# Generate a random key and its hash in one step:
cargo run --bin hash-apikey -- --generate

# Output:
#   Generated API key (save this — it cannot be recovered):
#     a1b2c3d4e5f6...  (64 hex chars)
#   SHA-256 hash (set as CITADEL_API_KEY_HASH):
#     9f86d08...        (64 hex chars)
```

Or hash an existing key:

```bash
echo -n "your-existing-api-key" | sha256sum | cut -d' ' -f1
```

Save the plaintext key for clients. Set the **hash** as `CITADEL_API_KEY_HASH`.

### 2. Configure TLS with Caddy

Edit `Caddyfile` for your environment:

**Option A — Real domain with Let's Encrypt (recommended):**
```
citadel.yourdomain.com {
    reverse_proxy citadel:3000
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        -Server
    }
}
```

**Option B — Self-signed cert for internal/staging:**
```
:443 {
    tls internal
    reverse_proxy citadel:3000
    # ... same headers ...
}
```

### 3. Launch

```bash
export CITADEL_API_KEY_HASH="9f86d081884c..."  # from step 1
export CITADEL_DOMAIN="citadel.yourdomain.com"  # for real TLS
export CITADEL_LOG_FORMAT=json                   # structured logging

docker compose -f docker-compose-production.yml up -d
```

Dashboard: `https://citadel.yourdomain.com`
API: `https://citadel.yourdomain.com/api/status`

### 4. Verify

```bash
# Health check (no auth required)
curl -k https://localhost/health

# Authenticated API call
curl -k https://localhost/api/status \
  -H "Authorization: Bearer your-plaintext-key"

# Rate limit test (should get 429 after burst)
for i in $(seq 1 60); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -k https://localhost/api/status \
    -H "Authorization: Bearer your-plaintext-key"
done
```

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `CITADEL_PORT` | `3000` | Internal listen port |
| `CITADEL_DATA_DIR` | `./citadel-data` | Key material and audit log directory |
| `CITADEL_API_KEY_HASH` | — | SHA-256 hex hash of API key (production) |
| `CITADEL_API_KEY` | — | Plaintext API key (dev only, hashed at startup) |
| `CITADEL_SEED_DEMO` | `false` | Seed demo keys on first run |
| `CITADEL_LOG_FORMAT` | `pretty` | `json` for structured logging, `pretty` for dev |
| `CITADEL_RATE_LIMIT_RPS` | `20` | Requests per second per IP |
| `CITADEL_RATE_LIMIT_BURST` | `50` | Burst capacity per IP |
| `CITADEL_DOMAIN` | — | Domain for Caddy TLS (production only) |

---

## Rate Limiting Behavior

The rate limiter uses a per-IP sliding window token bucket:

- Each IP starts with `BURST` tokens
- Tokens replenish at `RPS` per second
- When tokens are exhausted, requests get `429 Too Many Requests` with `Retry-After: 1`
- Rate limit violations are automatically recorded as `RapidAccessPattern` threat events
- Stale buckets are cleaned up every 60 seconds

The rate limiter runs in-memory (no Redis needed). For multi-instance deployments behind a load balancer, each instance maintains its own counters — effective per-IP rate is `RPS × instance_count`.

---

## Structured Logging

With `CITADEL_LOG_FORMAT=json`, output looks like:

```json
{"timestamp":"2026-02-12T10:30:00Z","level":"INFO","target":"citadel_api","message":"starting Citadel API Server v0.1.0","port":3000,"rate_rps":20.0,"rate_burst":50}
{"timestamp":"2026-02-12T10:30:01Z","level":"WARN","target":"citadel_api","message":"rate limit exceeded","ip":"192.168.1.50","path":"/api/keys"}
{"timestamp":"2026-02-12T10:30:01Z","level":"WARN","target":"citadel_api","message":"invalid API key","ip":"10.0.0.5","path":"/api/status"}
```

Feed this into ELK, Datadog, CloudWatch, or any JSON log aggregator.

---

## Architecture (Production)

```
Internet
    │
    ▼
┌──────────────┐
│   Caddy       │  :443 (TLS termination)
│   (reverse    │  :80  (→ redirect to HTTPS)
│    proxy)     │
└──────┬───────┘
       │ plaintext HTTP (internal Docker network only)
       ▼
┌──────────────┐
│  Citadel API  │  :3000 (not exposed to host)
│  ┌──────────┐ │
│  │ Rate     │ │  Per-IP token bucket
│  │ Limiter  │ │
│  ├──────────┤ │
│  │ Auth     │ │  SHA-256 + constant-time compare
│  │ (hashed) │ │
│  ├──────────┤ │
│  │ Keystore │ │  Hybrid PQ encryption engine
│  └──────────┘ │
└──────────────┘
       │
       ▼
  citadel-data/    (volume: keys + audit log)
```

---

## Migration from Pre-Hardening

If you have an existing deployment with `CITADEL_API_KEY`:

1. Your existing setup **still works** — `CITADEL_API_KEY` is supported but deprecated
2. Generate the hash: `echo -n "your-current-key" | sha256sum | cut -d' ' -f1`
3. Set `CITADEL_API_KEY_HASH` to the output
4. Remove `CITADEL_API_KEY` from your environment
5. Switch to `docker-compose-production.yml` when ready for TLS

No key material migration is needed — the data directory is unchanged.

---

## What's Next (Tier 2)

After Tier 1 is deployed, the next priorities are:

1. **Multiple API keys with scopes** — per-client keys with permissions (read-only, encrypt-only, admin)
2. **Backup/recovery procedures** — documented key material backup with encryption-at-rest
3. **Key export/import** — portable key bundles for server migration
