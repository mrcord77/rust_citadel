# Citadel Quick Start

## Option 1: Docker (recommended)

```bash
# One command to start
docker compose up -d

# With API key authentication
CITADEL_API_KEY=my-secret docker compose up -d

# Check it's running
curl http://localhost:3000/health
```

## Option 2: Run directly

```bash
# Build
cargo build --release -p citadel-api

# Run with persistence and auth
CITADEL_DATA_DIR=./citadel-data \
CITADEL_API_KEY=my-secret \
CITADEL_SEED_DEMO=true \
./target/release/citadel-api
```

## Option 3: Development mode

```bash
# No auth, in-memory demo keys
CITADEL_SEED_DEMO=true cargo run -p citadel-api
```

## Using the API

### Without authentication (dev mode)

```bash
# Encrypt
curl -X POST http://localhost:3000/api/keys/{KEY_ID}/encrypt \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"hello world","aad":"my-app","context":"prod"}'

# Decrypt (pass the full blob from encrypt response)
curl -X POST http://localhost:3000/api/decrypt \
  -H "Content-Type: application/json" \
  -d '{"blob":{...},"aad":"my-app","context":"prod"}'
```

### With authentication

Add the `Authorization` header to every API call:

```bash
curl -X POST http://localhost:3000/api/keys/{KEY_ID}/encrypt \
  -H "Authorization: Bearer my-secret" \
  -H "Content-Type: application/json" \
  -d '{"plaintext":"hello world","aad":"my-app","context":"prod"}'
```

### PowerShell (Windows)

```powershell
$headers = @{
    "Authorization" = "Bearer my-secret"
    "Content-Type"  = "application/json"
}

# List keys
(Invoke-WebRequest http://localhost:3000/api/keys -Headers $headers).Content | ConvertFrom-Json

# Encrypt
$body = '{"plaintext":"secret data","aad":"demo","context":"prod"}'
$enc = Invoke-WebRequest -Method POST -Uri "http://localhost:3000/api/keys/$keyId/encrypt" -Headers $headers -Body $body
$blob = ($enc.Content | ConvertFrom-Json)

# Decrypt
$decBody = @{ blob = $blob; aad = "demo"; context = "prod" } | ConvertTo-Json -Depth 5
$dec = Invoke-WebRequest -Method POST -Uri "http://localhost:3000/api/decrypt" -Headers $headers -Body $decBody
($dec.Content | ConvertFrom-Json).plaintext
```

### Python

```python
import requests

BASE = "http://localhost:3000"
HEADERS = {"Authorization": "Bearer my-secret"}

# List keys
keys = requests.get(f"{BASE}/api/keys", headers=HEADERS).json()

# Encrypt
key_id = keys[0]["id"]
resp = requests.post(f"{BASE}/api/keys/{key_id}/encrypt", headers=HEADERS, json={
    "plaintext": "secret data",
    "aad": "my-app|user|42",
    "context": "prod"
})
blob = resp.json()

# Decrypt
resp = requests.post(f"{BASE}/api/decrypt", headers=HEADERS, json={
    "blob": blob,
    "aad": "my-app|user|42",
    "context": "prod"
})
print(resp.json()["plaintext"])  # "secret data"
```

### JavaScript / Node.js

```javascript
const BASE = "http://localhost:3000";
const HEADERS = {
  "Authorization": "Bearer my-secret",
  "Content-Type": "application/json"
};

// List keys
const keys = await fetch(`${BASE}/api/keys`, { headers: HEADERS }).then(r => r.json());

// Encrypt
const keyId = keys[0].id;
const encResp = await fetch(`${BASE}/api/keys/${keyId}/encrypt`, {
  method: "POST", headers: HEADERS,
  body: JSON.stringify({ plaintext: "secret data", aad: "my-app", context: "prod" })
}).then(r => r.json());

// Decrypt
const decResp = await fetch(`${BASE}/api/decrypt`, {
  method: "POST", headers: HEADERS,
  body: JSON.stringify({ blob: encResp, aad: "my-app", context: "prod" })
}).then(r => r.json());

console.log(decResp.plaintext); // "secret data"
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (no auth) |
| GET | `/` | Dashboard (no auth) |
| GET | `/api/status` | Server status + threat level |
| GET | `/api/keys` | List all keys |
| POST | `/api/keys` | Create a new key |
| GET | `/api/keys/:id` | Get key details |
| POST | `/api/keys/:id/activate` | Activate a pending key |
| POST | `/api/keys/:id/rotate` | Rotate a key |
| POST | `/api/keys/:id/revoke` | Revoke a key |
| POST | `/api/keys/:id/destroy` | Destroy a key |
| POST | `/api/keys/:id/encrypt` | Encrypt data |
| POST | `/api/decrypt` | Decrypt data |
| GET | `/api/threat` | Current threat level |
| POST | `/api/threat/event` | Report a threat event |
| POST | `/api/threat/reset` | Reset threat score |
| GET | `/api/policies` | View adapted policies |
| POST | `/api/expire` | Expire overdue keys |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CITADEL_PORT` | 3000 | Listen port |
| `CITADEL_DATA_DIR` | ./citadel-data | Where keys and audit logs are stored |
| `CITADEL_API_KEY` | *(none)* | API key for auth (empty = no auth) |
| `CITADEL_SEED_DEMO` | false | Create demo keys on first run |

## Data Persistence

Keys are stored as JSON files in `$CITADEL_DATA_DIR/keys/`.
Audit logs append to `$CITADEL_DATA_DIR/citadel-audit.jsonl`.

In Docker, mount a volume to `/data` to persist across container restarts:

```bash
docker run -v citadel-data:/data -p 3000:3000 citadel
```
