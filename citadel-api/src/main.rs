//! Citadel API Server v0.2.0
//!
//! HTTP interface to the keystore + adaptive threat system.
//! Serves the dashboard and exposes REST endpoints.
//!
//! Configuration (environment variables):
//!   CITADEL_PORT              - Listen port (default: 3000)
//!   CITADEL_DATA_DIR          - Persistent data directory (default: ./citadel-data)
//!   CITADEL_API_KEY           - Bootstrap admin key, plaintext (dev only)
//!   CITADEL_API_KEY_HASH      - Bootstrap admin key, SHA-256 hex (production)
//!   CITADEL_SEED_DEMO         - Set to "true" to seed demo keys on first run
//!   CITADEL_LOG_FORMAT        - "json" for structured logging, "pretty" for dev
//!   CITADEL_RATE_LIMIT_RPS    - Requests per second per IP (default: 20)
//!   CITADEL_RATE_LIMIT_BURST  - Burst capacity per IP (default: 50)
//!
//! API Key Scopes:
//!   read    - GET endpoints (status, metrics, keys list, threat, policies)
//!   encrypt - encrypt/decrypt operations
//!   manage  - key lifecycle (generate, activate, rotate, revoke, destroy)
//!   admin   - all of the above + API key management
//!
//! Bootstrap:
//!   On first run, CITADEL_API_KEY or CITADEL_API_KEY_HASH creates the initial
//!   admin key. After that, manage keys via POST /api/auth/keys.

use axum::{
    extract::{ConnectInfo, Path, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse},
    routing::{delete, get, post},
    Json, Router,
};
use citadel_keystore::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, RwLock};
use tower_http::cors::{Any, CorsLayer};

// ---------------------------------------------------------------------------
// Scopes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Scope {
    Read,
    Encrypt,
    Manage,
    Admin,
}

impl Scope {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Scope::Read),
            "encrypt" => Some(Scope::Encrypt),
            "manage" => Some(Scope::Manage),
            "admin" => Some(Scope::Admin),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Encrypt => "encrypt",
            Scope::Manage => "manage",
            Scope::Admin => "admin",
        }
    }
}

fn has_scope(granted: &[Scope], required: &Scope) -> bool {
    if granted.contains(&Scope::Admin) {
        return true;
    }
    granted.contains(required)
}

fn required_scope(path: &str, method: &str) -> Option<Scope> {
    if path == "/" || path == "/health" {
        return None;
    }
    if path == "/api/auth/whoami" {
        return Some(Scope::Read);
    }
    if path.starts_with("/api/auth/") {
        return Some(Scope::Admin);
    }
    if path.ends_with("/encrypt") || path == "/api/decrypt" {
        return Some(Scope::Encrypt);
    }
    if method == "POST" || method == "DELETE" {
        return Some(Scope::Manage);
    }
    Some(Scope::Read)
}

// ---------------------------------------------------------------------------
// API Key Store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiKeyEntry {
    id: String,
    name: String,
    key_hash: String,
    scopes: Vec<Scope>,
    created_at: String,
    active: bool,
    #[serde(default)]
    last_used: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiKeyStore {
    keys: Vec<ApiKeyEntry>,
}

#[derive(Serialize)]
struct ApiKeyInfo {
    id: String,
    name: String,
    scopes: Vec<Scope>,
    created_at: String,
    active: bool,
    last_used: Option<String>,
}

impl ApiKeyStore {
    fn new() -> Self {
        Self { keys: Vec::new() }
    }

    fn load(path: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_else(|e| {
                tracing::error!("failed to parse api-keys.json: {}", e);
                Self::new()
            }),
            Err(_) => Self::new(),
        }
    }

    fn save(&self, path: &str) -> Result<(), String> {
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialize: {}", e))?;
        std::fs::write(path, data)
            .map_err(|e| format!("write {}: {}", path, e))
    }

    fn authenticate(&self, provided_hash: &[u8; 32]) -> Option<&ApiKeyEntry> {
        let provided_hex = hex::encode(provided_hash);
        self.keys.iter().find(|k| {
            k.active && {
                let stored = k.key_hash.as_bytes();
                let provided = provided_hex.as_bytes();
                stored.len() == provided.len() && stored.ct_eq(provided).into()
            }
        })
    }

    fn add(&mut self, entry: ApiKeyEntry) {
        self.keys.push(entry);
    }

    fn deactivate(&mut self, id: &str) -> bool {
        if let Some(entry) = self.keys.iter_mut().find(|k| k.id == id) {
            entry.active = false;
            true
        } else {
            false
        }
    }

    fn touch(&mut self, id: &str) {
        if let Some(entry) = self.keys.iter_mut().find(|k| k.id == id) {
            entry.last_used = Some(chrono::Utc::now().to_rfc3339());
        }
    }

    fn list_info(&self) -> Vec<ApiKeyInfo> {
        self.keys.iter().map(|k| ApiKeyInfo {
            id: k.id.clone(),
            name: k.name.clone(),
            scopes: k.scopes.clone(),
            created_at: k.created_at.clone(),
            active: k.active,
            last_used: k.last_used.clone(),
        }).collect()
    }
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

struct AppState {
    keystore: Keystore,
    api_keys: RwLock<ApiKeyStore>,
    api_keys_path: String,
    rate_limiter: RateLimiter,
}

type Shared = Arc<AppState>;

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
    rps: f64,
    burst: u32,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    fn new(rps: f64, burst: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            rps,
            burst,
        }
    }

    async fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().await;
        let now = Instant::now();
        let bucket = buckets.entry(ip).or_insert(TokenBucket {
            tokens: self.burst as f64,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rps).min(self.burst as f64);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

async fn cleanup_rate_limiter(limiter: &RateLimiter) {
    let mut buckets = limiter.buckets.lock().await;
    let now = Instant::now();
    buckets.retain(|_, bucket| {
        now.duration_since(bucket.last_refill).as_secs() < 300
    });
}

// ---------------------------------------------------------------------------
// Crypto utilities
// ---------------------------------------------------------------------------

fn hash_api_key(key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.finalize().into()
}

fn generate_api_key() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("failed to generate random bytes");
    hex::encode(buf)
}

fn generate_key_id() -> String {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).expect("failed to generate random bytes");
    format!("ck_{}", hex::encode(buf))
}

// ---------------------------------------------------------------------------
// Auth context — injected into request extensions
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct AuthContext {
    key_id: String,
    key_name: String,
    scopes: Vec<Scope>,
}

// ---------------------------------------------------------------------------
// Rate limiting middleware
// ---------------------------------------------------------------------------

async fn rate_limit_middleware(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    if req.uri().path() == "/health" {
        return next.run(req).await.into_response();
    }

    if !state.rate_limiter.check(addr.ip()).await {
        state.keystore.record_threat_event(
            ThreatEvent::new(ThreatEventKind::RapidAccessPattern, 0.3)
                .with_detail(format!("rate limit exceeded: {}", addr.ip())),
        );
        tracing::warn!(ip = %addr.ip(), path = %req.uri().path(), "rate limit exceeded");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "1")],
            Json(ApiError { error: "rate limit exceeded".into() }),
        ).into_response();
    }

    next.run(req).await.into_response()
}

// ---------------------------------------------------------------------------
// Authentication middleware
// ---------------------------------------------------------------------------

async fn auth_middleware(
    State(state): State<Shared>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> impl IntoResponse {
    let path = req.uri().path().to_string();
    let method = req.method().to_string();

    let required = required_scope(&path, &method);
    if required.is_none() {
        return next.run(req).await.into_response();
    }
    let required = required.unwrap();

    let store = state.api_keys.read().await;
    if store.keys.is_empty() {
        return next.run(req).await.into_response();
    }

    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match auth_header {
        Some(val) if val.starts_with("Bearer ") => {
            let provided = &val[7..];
            let provided_hash = hash_api_key(provided);

            match store.authenticate(&provided_hash) {
                Some(entry) => {
                    if !has_scope(&entry.scopes, &required) {
                        tracing::warn!(
                            ip = %addr.ip(), key_id = %entry.id,
                            required = %required.as_str(),
                            "insufficient scope"
                        );
                        return (
                            StatusCode::FORBIDDEN,
                            Json(ApiError {
                                error: format!(
                                    "insufficient scope: requires '{}' permission",
                                    required.as_str()
                                ),
                            }),
                        ).into_response();
                    }

                    let ctx = AuthContext {
                        key_id: entry.id.clone(),
                        key_name: entry.name.clone(),
                        scopes: entry.scopes.clone(),
                    };
                    let key_id = entry.id.clone();
                    drop(store);

                    // Update last_used (async, non-blocking)
                    let state2 = state.clone();
                    tokio::spawn(async move {
                        let mut s = state2.api_keys.write().await;
                        s.touch(&key_id);
                        let _ = s.save(&state2.api_keys_path);
                    });

                    req.extensions_mut().insert(ctx);
                    next.run(req).await.into_response()
                }
                None => {
                    drop(store);
                    state.keystore.record_threat_event(
                        ThreatEvent::new(ThreatEventKind::AuthFailure, 0.5)
                            .with_detail(format!("invalid API key from {}", addr.ip())),
                    );
                    tracing::warn!(ip = %addr.ip(), path = %path, "invalid API key");
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(ApiError { error: "authentication failed".into() }),
                    ).into_response()
                }
            }
        }
        _ => {
            drop(store);
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiError { error: "missing Authorization header (use: Bearer <api-key>)".into() }),
            ).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GenerateKeyReq {
    name: String,
    key_type: String,
    policy_id: Option<String>,
}

#[derive(Deserialize)]
struct EncryptReq {
    plaintext: String,
    aad: String,
    context: String,
}

#[derive(Deserialize)]
struct DecryptReq {
    blob: EncryptedBlob,
    aad: String,
    context: String,
}

#[derive(Deserialize)]
struct ThreatEventReq {
    kind: String,
    severity: f64,
    detail: Option<String>,
}

#[derive(Deserialize)]
struct RevokeReq {
    reason: String,
}

#[derive(Deserialize)]
struct CreateApiKeyReq {
    name: String,
    scopes: Vec<String>,
}

#[derive(Serialize)]
struct StatusResponse {
    threat_level: u32,
    threat_name: &'static str,
    threat_color: &'static str,
    threat_score: f64,
    total_keys: usize,
    active_keys: usize,
}

#[derive(Serialize, Clone)]
struct ApiError { error: String }

#[derive(Serialize)]
struct KeyResponse {
    id: String,
    name: String,
    key_type: String,
    state: String,
    version: u32,
    usage_count: u64,
    created_at: String,
    updated_at: String,
    policy_id: Option<String>,
    parent_id: Option<String>,
}

#[derive(Serialize)]
struct ThreatHistoryEntry {
    timestamp: String,
    level: u32,
    level_name: String,
    reason: String,
}

#[derive(Serialize)]
struct PolicyAdaptationResponse {
    policy_name: String,
    threat_level: u32,
    base_rotation_age_days: Option<f64>,
    effective_rotation_age_days: Option<f64>,
    base_grace_period_days: f64,
    effective_grace_period_days: f64,
    base_max_lifetime_days: Option<f64>,
    effective_max_lifetime_days: Option<f64>,
    base_usage_limit: Option<u64>,
    effective_usage_limit: Option<u64>,
    auto_rotate_forced: bool,
}

fn err(msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (StatusCode::BAD_REQUEST, Json(ApiError { error: msg.into() }))
}
fn err500(msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error: msg.into() }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_key_type(s: &str) -> Option<KeyType> {
    match s.to_lowercase().as_str() {
        "root" => Some(KeyType::Root),
        "domain" => Some(KeyType::Domain),
        "kek" | "keyencrypting" => Some(KeyType::KeyEncrypting),
        "dek" | "dataencrypting" => Some(KeyType::DataEncrypting),
        _ => None,
    }
}

fn parse_threat_kind(s: &str) -> Option<ThreatEventKind> {
    match s {
        "DecryptionFailure" => Some(ThreatEventKind::DecryptionFailure),
        "RapidAccessPattern" => Some(ThreatEventKind::RapidAccessPattern),
        "AnomalousAccess" => Some(ThreatEventKind::AnomalousAccess),
        "ExternalAdvisory" => Some(ThreatEventKind::ExternalAdvisory),
        "AuthFailure" => Some(ThreatEventKind::AuthFailure),
        "KeyEnumeration" => Some(ThreatEventKind::KeyEnumeration),
        "ManualEscalation" => Some(ThreatEventKind::ManualEscalation),
        "ManualDeescalation" => Some(ThreatEventKind::ManualDeescalation),
        _ => None,
    }
}

fn key_to_response(meta: &KeyMetadata) -> KeyResponse {
    let ver = meta.versions.last().map(|v| v.version).unwrap_or(0);
    KeyResponse {
        id: meta.id.to_string(), name: meta.name.clone(),
        key_type: format!("{:?}", meta.key_type), state: format!("{}", meta.state),
        version: ver, usage_count: meta.usage_count,
        created_at: meta.created_at.to_rfc3339(), updated_at: meta.updated_at.to_rfc3339(),
        policy_id: meta.policy_id.as_ref().map(|p| p.as_str().to_string()),
        parent_id: meta.parent_id.as_ref().map(|p| p.to_string()),
    }
}

fn lname(level: ThreatLevel) -> &'static str {
    match level {
        ThreatLevel::Low => "LOW", ThreatLevel::Guarded => "GUARDED",
        ThreatLevel::Elevated => "ELEVATED", ThreatLevel::High => "HIGH",
        ThreatLevel::Critical => "CRITICAL",
    }
}

// ---------------------------------------------------------------------------
// Routes — crypto key management
// ---------------------------------------------------------------------------

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok", "version": "0.2.0"}))
}

async fn get_status(State(state): State<Shared>) -> Json<StatusResponse> {
    let ks = &state.keystore;
    let level = ks.threat_level();
    let all = ks.list_keys().await.unwrap_or_default();
    let active = all.iter().filter(|k| k.state == KeyState::Active).count();
    Json(StatusResponse {
        threat_level: level.value(), threat_name: lname(level), threat_color: level.color(),
        threat_score: ks.threat_score(), total_keys: all.len(), active_keys: active,
    })
}

async fn get_metrics(State(state): State<Shared>) -> impl IntoResponse {
    match state.keystore.security_metrics().await {
        Ok(m) => (StatusCode::OK, Json(serde_json::to_value(m).unwrap())).into_response(),
        Err(e) => err500(e.to_string()).into_response(),
    }
}

async fn list_keys_handler(State(state): State<Shared>) -> impl IntoResponse {
    match state.keystore.list_keys().await {
        Ok(keys) => Json(keys.iter().map(key_to_response).collect::<Vec<_>>()).into_response(),
        Err(e) => err500(e.to_string()).into_response(),
    }
}

async fn get_key(State(state): State<Shared>, Path(id): Path<String>) -> impl IntoResponse {
    match state.keystore.get(&KeyId::new(&id)).await {
        Ok(m) => Json(key_to_response(&m)).into_response(),
        Err(e) => err(e.to_string()).into_response(),
    }
}

async fn generate_key(State(state): State<Shared>, Json(req): Json<GenerateKeyReq>) -> impl IntoResponse {
    let kt = match parse_key_type(&req.key_type) {
        Some(kt) => kt,
        None => return err(format!("invalid key_type: {}", req.key_type)).into_response(),
    };
    let policy = req.policy_id.map(|p| PolicyId::new(&p));
    match state.keystore.generate(&req.name, kt, policy, None).await {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({"key_id": id.to_string()}))).into_response(),
        Err(e) => err(e.to_string()).into_response(),
    }
}

async fn activate_key(State(state): State<Shared>, Path(id): Path<String>) -> impl IntoResponse {
    match state.keystore.activate(&KeyId::new(&id)).await {
        Ok(()) => Json(serde_json::json!({"status": "activated"})).into_response(),
        Err(e) => err(e.to_string()).into_response(),
    }
}

async fn rotate_key(State(state): State<Shared>, Path(id): Path<String>) -> impl IntoResponse {
    match state.keystore.rotate(&KeyId::new(&id)).await {
        Ok(new_id) => Json(serde_json::json!({"status": "rotated", "new_key_id": new_id.to_string()})).into_response(),
        Err(e) => err(e.to_string()).into_response(),
    }
}

async fn revoke_key(State(state): State<Shared>, Path(id): Path<String>, Json(req): Json<RevokeReq>) -> impl IntoResponse {
    match state.keystore.revoke(&KeyId::new(&id), &req.reason).await {
        Ok(()) => Json(serde_json::json!({"status": "revoked"})).into_response(),
        Err(e) => err(e.to_string()).into_response(),
    }
}

async fn destroy_key(State(state): State<Shared>, Path(id): Path<String>) -> impl IntoResponse {
    match state.keystore.destroy(&KeyId::new(&id)).await {
        Ok(()) => Json(serde_json::json!({"status": "destroyed"})).into_response(),
        Err(e) => err(e.to_string()).into_response(),
    }
}

async fn encrypt_data(State(state): State<Shared>, Path(id): Path<String>, Json(req): Json<EncryptReq>) -> impl IntoResponse {
    let aad = citadel_envelope::Aad::raw(req.aad.as_bytes());
    let ctx = citadel_envelope::Context::raw(req.context.as_bytes());
    match state.keystore.encrypt(&KeyId::new(&id), req.plaintext.as_bytes(), &aad, &ctx).await {
        Ok(blob) => (StatusCode::OK, Json(blob)).into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("policy") || msg.contains("compliance") {
                (StatusCode::FORBIDDEN, Json(ApiError { error: msg })).into_response()
            } else {
                err(msg).into_response()
            }
        }
    }
}

async fn decrypt_data(State(state): State<Shared>, Json(req): Json<DecryptReq>) -> impl IntoResponse {
    let aad = citadel_envelope::Aad::raw(req.aad.as_bytes());
    let ctx = citadel_envelope::Context::raw(req.context.as_bytes());
    match state.keystore.decrypt(&req.blob, &aad, &ctx).await {
        Ok(pt) => Json(serde_json::json!({"plaintext": String::from_utf8_lossy(&pt)})).into_response(),
        Err(e) => err(e.to_string()).into_response(),
    }
}

async fn get_threat(State(state): State<Shared>) -> impl IntoResponse {
    let ks = &state.keystore;
    let level = ks.threat_level();
    let score = ks.threat_score();
    let history: Vec<ThreatHistoryEntry> = ks.threat_history().iter().map(|(ts, lv, reason)| ThreatHistoryEntry {
        timestamp: ts.to_rfc3339(), level: lv.value(),
        level_name: lname(*lv).to_string(), reason: reason.clone(),
    }).collect();
    Json(serde_json::json!({
        "score": score, "level": level.value(), "name": lname(level),
        "color": level.color(), "history": history,
    }))
}

async fn post_threat_event(State(state): State<Shared>, Json(req): Json<ThreatEventReq>) -> impl IntoResponse {
    let kind = match parse_threat_kind(&req.kind) {
        Some(k) => k,
        None => return err(format!("unknown threat kind: {}", req.kind)).into_response(),
    };
    let mut event = ThreatEvent::new(kind, req.severity);
    if let Some(d) = req.detail { event = event.with_detail(d); }
    state.keystore.record_threat_event(event);
    let level = state.keystore.threat_level();
    Json(serde_json::json!({
        "status": "recorded", "score": state.keystore.threat_score(),
        "level": level.value(), "name": lname(level),
    })).into_response()
}

async fn reset_threat(State(state): State<Shared>) -> impl IntoResponse {
    state.keystore.record_threat_event(ThreatEvent::new(ThreatEventKind::ManualDeescalation, 0.0));
    let level = state.keystore.threat_level();
    Json(serde_json::json!({
        "status": "reset", "score": state.keystore.threat_score(),
        "level": level.value(), "name": lname(level),
    }))
}

async fn get_policies(State(state): State<Shared>) -> impl IntoResponse {
    let ks = &state.keystore;
    let mut out = Vec::new();
    for id in &["default-dek", "default-kek"] {
        let pid = PolicyId::new(*id);
        if let Some(s) = ks.policy_adaptation_summary(&pid) {
            out.push(PolicyAdaptationResponse {
                policy_name: s.policy_name, threat_level: s.threat_level.value(),
                base_rotation_age_days: s.base_rotation_age.map(|d| d.as_secs() as f64 / 86400.0),
                effective_rotation_age_days: s.effective_rotation_age.map(|d| d.as_secs() as f64 / 86400.0),
                base_grace_period_days: s.base_grace_period.as_secs() as f64 / 86400.0,
                effective_grace_period_days: s.effective_grace_period.as_secs() as f64 / 86400.0,
                base_max_lifetime_days: s.base_max_lifetime.map(|d| d.as_secs() as f64 / 86400.0),
                effective_max_lifetime_days: s.effective_max_lifetime.map(|d| d.as_secs() as f64 / 86400.0),
                base_usage_limit: s.base_usage_limit, effective_usage_limit: s.effective_usage_limit,
                auto_rotate_forced: s.auto_rotate_forced,
            });
        }
    }
    Json(out)
}

async fn expire_due(State(state): State<Shared>) -> impl IntoResponse {
    match state.keystore.expire_due_keys().await {
        Ok(report) => Json(serde_json::json!({
            "expired": report.expired.len(),
            "warnings": report.warnings.len(),
            "skipped": report.skipped,
        })).into_response(),
        Err(e) => err500(e.to_string()).into_response(),
    }
}

async fn dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

// ---------------------------------------------------------------------------
// Routes — API key management (admin scope)
// ---------------------------------------------------------------------------

async fn list_api_keys(State(state): State<Shared>) -> impl IntoResponse {
    let store = state.api_keys.read().await;
    Json(store.list_info())
}

async fn create_api_key(State(state): State<Shared>, Json(req): Json<CreateApiKeyReq>) -> impl IntoResponse {
    if req.name.is_empty() || req.name.len() > 100 {
        return err("name must be 1-100 characters").into_response();
    }

    let mut scopes = Vec::new();
    for s in &req.scopes {
        match Scope::from_str(s) {
            Some(scope) => { if !scopes.contains(&scope) { scopes.push(scope); } }
            None => return err(format!("invalid scope '{}' — valid: read, encrypt, manage, admin", s)).into_response(),
        }
    }
    if scopes.is_empty() {
        return err("at least one scope required").into_response();
    }

    let plaintext_key = generate_api_key();
    let key_hash = hash_api_key(&plaintext_key);
    let key_id = generate_key_id();

    let entry = ApiKeyEntry {
        id: key_id.clone(),
        name: req.name.clone(),
        key_hash: hex::encode(key_hash),
        scopes: scopes.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
        active: true,
        last_used: None,
    };

    let mut store = state.api_keys.write().await;
    store.add(entry);
    if let Err(e) = store.save(&state.api_keys_path) {
        return err500(format!("failed to save: {}", e)).into_response();
    }

    tracing::info!(key_id = %key_id, name = %req.name, scopes = ?scopes, "created API key");

    (StatusCode::CREATED, Json(serde_json::json!({
        "key_id": key_id,
        "name": req.name,
        "api_key": plaintext_key,
        "scopes": scopes,
        "warning": "Save this API key now. It cannot be retrieved again."
    }))).into_response()
}

async fn revoke_api_key(State(state): State<Shared>, Path(id): Path<String>) -> impl IntoResponse {
    let mut store = state.api_keys.write().await;

    let target = store.keys.iter().find(|k| k.id == id);
    match target {
        None => return err(format!("API key '{}' not found", id)).into_response(),
        Some(entry) => {
            if !entry.active {
                return err(format!("API key '{}' already revoked", id)).into_response();
            }
            if entry.scopes.contains(&Scope::Admin) {
                let other_admins = store.keys.iter()
                    .filter(|k| k.id != id && k.active && k.scopes.contains(&Scope::Admin))
                    .count();
                if other_admins == 0 {
                    return err("cannot revoke the last admin key").into_response();
                }
            }
        }
    }

    store.deactivate(&id);
    if let Err(e) = store.save(&state.api_keys_path) {
        return err500(format!("failed to save: {}", e)).into_response();
    }

    tracing::info!(key_id = %id, "revoked API key");
    Json(serde_json::json!({"status": "revoked", "key_id": id})).into_response()
}

async fn whoami(req: Request) -> impl IntoResponse {
    match req.extensions().get::<AuthContext>() {
        Some(ctx) => Json(serde_json::json!({
            "key_id": ctx.key_id, "key_name": ctx.key_name, "scopes": ctx.scopes,
        })).into_response(),
        None => Json(serde_json::json!({
            "key_id": null, "key_name": "anonymous", "scopes": ["admin"],
            "note": "no API keys configured — dev mode"
        })).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

fn create_keystore(data_dir: &str) -> Keystore {
    let keys_dir = format!("{}/keys", data_dir);
    let audit_path = format!("{}/citadel-audit.jsonl", data_dir);
    std::fs::create_dir_all(&keys_dir).expect("failed to create data directory");
    let storage = Arc::new(FileBackend::new(&keys_dir).expect("failed to init file storage"));
    let file_sink: Arc<dyn AuditSinkSync> = Arc::new(FileAuditSink::new(&audit_path));
    let audit: Arc<dyn AuditSinkSync> = Arc::new(IntegrityChainSink::new(file_sink));
    let mut ks = Keystore::new(storage, audit);
    ks.register_policy(KeyPolicy::default_dek());
    ks.register_policy(KeyPolicy::default_kek());
    ks
}

async fn seed_demo_keys(ks: &Keystore) {
    let root = ks.generate("root-master", KeyType::Root, None, None).await.unwrap();
    ks.activate(&root).await.unwrap();
    let domain = ks.generate("production", KeyType::Domain, None, Some(root.clone())).await.unwrap();
    ks.activate(&domain).await.unwrap();
    let kek = ks.generate("prod-kek-01", KeyType::KeyEncrypting, Some(PolicyId::new("default-kek")), Some(domain.clone())).await.unwrap();
    ks.activate(&kek).await.unwrap();
    for i in 1..=4 {
        let dek = ks.generate(&format!("prod-dek-{:02}", i), KeyType::DataEncrypting, Some(PolicyId::new("default-dek")), Some(kek.clone())).await.unwrap();
        ks.activate(&dek).await.unwrap();
        let aad = citadel_envelope::Aad::raw(b"demo");
        let ctx = citadel_envelope::Context::raw(b"seed");
        for _ in 0..i { let _ = ks.encrypt(&dek, b"demo payload", &aad, &ctx).await; }
    }
    let old = ks.generate("prod-dek-legacy", KeyType::DataEncrypting, Some(PolicyId::new("default-dek")), Some(kek.clone())).await.unwrap();
    ks.activate(&old).await.unwrap();
    let _ = ks.rotate(&old).await;
    let _ = ks.generate("prod-dek-staged", KeyType::DataEncrypting, Some(PolicyId::new("default-dek")), Some(kek.clone())).await.unwrap();
    tracing::info!("Seeded 9 demo keys across 4-level hierarchy");
}

fn resolve_bootstrap_hash() -> Option<[u8; 32]> {
    if let Ok(hex_hash) = std::env::var("CITADEL_API_KEY_HASH") {
        let hex_hash = hex_hash.trim();
        if hex_hash.is_empty() { return None; }
        if hex_hash.len() != 64 {
            tracing::error!("CITADEL_API_KEY_HASH must be 64 hex characters");
            std::process::exit(1);
        }
        let mut hash = [0u8; 32];
        match hex::decode_to_slice(hex_hash, &mut hash) {
            Ok(()) => return Some(hash),
            Err(e) => { tracing::error!("CITADEL_API_KEY_HASH invalid hex: {}", e); std::process::exit(1); }
        }
    }
    if let Ok(pt) = std::env::var("CITADEL_API_KEY") {
        let pt = pt.trim();
        if pt.is_empty() { return None; }
        tracing::warn!("using CITADEL_API_KEY (plaintext) — use CITADEL_API_KEY_HASH for production");
        return Some(hash_api_key(pt));
    }
    None
}

fn bootstrap_api_keys(data_dir: &str) -> (ApiKeyStore, String) {
    let path = format!("{}/api-keys.json", data_dir);
    let mut store = ApiKeyStore::load(&path);

    if !store.keys.is_empty() {
        let active = store.keys.iter().filter(|k| k.active).count();
        let admins = store.keys.iter().filter(|k| k.active && k.scopes.contains(&Scope::Admin)).count();
        tracing::info!(total = store.keys.len(), active, admins, "loaded API keys");
        return (store, path);
    }

    if let Some(hash_bytes) = resolve_bootstrap_hash() {
        let entry = ApiKeyEntry {
            id: "ck_bootstrap".to_string(),
            name: "bootstrap-admin".to_string(),
            key_hash: hex::encode(hash_bytes),
            scopes: vec![Scope::Admin],
            created_at: chrono::Utc::now().to_rfc3339(),
            active: true,
            last_used: None,
        };
        store.add(entry);
        if let Err(e) = store.save(&path) {
            tracing::error!("failed to save bootstrap key: {}", e);
        }
        tracing::info!("created bootstrap admin key from environment");
    } else {
        tracing::warn!("no API keys configured — dev mode (all endpoints open)");
    }

    (store, path)
}

#[tokio::main]
async fn main() {
    let log_format = std::env::var("CITADEL_LOG_FORMAT").unwrap_or_else(|_| "pretty".into());
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "citadel_api=info,tower_http=info".into());
    if log_format == "json" {
        tracing_subscriber::fmt().json().with_env_filter(env_filter).with_target(true).with_thread_ids(true).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    let port: u16 = std::env::var("CITADEL_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(3000);
    let data_dir = std::env::var("CITADEL_DATA_DIR").unwrap_or_else(|_| "./citadel-data".into());
    let seed_demo = std::env::var("CITADEL_SEED_DEMO").map(|v| v == "true").unwrap_or(false);
    let rate_rps: f64 = std::env::var("CITADEL_RATE_LIMIT_RPS").ok().and_then(|v| v.parse().ok()).unwrap_or(20.0);
    let rate_burst: u32 = std::env::var("CITADEL_RATE_LIMIT_BURST").ok().and_then(|v| v.parse().ok()).unwrap_or(50);

    let (api_key_store, api_keys_path) = bootstrap_api_keys(&data_dir);

    let keys_dir = format!("{}/keys", data_dir);
    let is_fresh = !std::path::Path::new(&keys_dir).exists()
        || std::fs::read_dir(&keys_dir).map(|mut d| d.next().is_none()).unwrap_or(true);
    let ks = create_keystore(&data_dir);

    if seed_demo && is_fresh {
        tracing::info!("Fresh data directory — seeding demo keys");
        seed_demo_keys(&ks).await;
    } else if !is_fresh {
        let count = ks.list_keys().await.map(|k| k.len()).unwrap_or(0);
        tracing::info!(keys = count, dir = %keys_dir, "loaded crypto keys");
    }

    let state: Shared = Arc::new(AppState {
        keystore: ks,
        api_keys: RwLock::new(api_key_store),
        api_keys_path,
        rate_limiter: RateLimiter::new(rate_rps, rate_burst),
    });

    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop { interval.tick().await; cleanup_rate_limiter(&cleanup_state.rate_limiter).await; }
    });

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/health", get(health))
        .route("/api/status", get(get_status))
        .route("/api/metrics", get(get_metrics))
        .route("/api/keys", get(list_keys_handler).post(generate_key))
        .route("/api/keys/:id", get(get_key))
        .route("/api/keys/:id/activate", post(activate_key))
        .route("/api/keys/:id/rotate", post(rotate_key))
        .route("/api/keys/:id/revoke", post(revoke_key))
        .route("/api/keys/:id/destroy", post(destroy_key))
        .route("/api/keys/:id/encrypt", post(encrypt_data))
        .route("/api/decrypt", post(decrypt_data))
        .route("/api/threat", get(get_threat))
        .route("/api/threat/event", post(post_threat_event))
        .route("/api/threat/reset", post(reset_threat))
        .route("/api/policies", get(get_policies))
        .route("/api/expire", post(expire_due))
        .route("/api/auth/keys", get(list_api_keys).post(create_api_key))
        .route("/api/auth/keys/:id", delete(revoke_api_key))
        .route("/api/auth/whoami", get(whoami))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit_middleware))
        .layer(cors)
        .with_state(state);

    tracing::info!(port, rate_rps, rate_burst, "starting Citadel API Server v0.2.0");
    tracing::info!(data_dir = %data_dir, "data directory");
    tracing::info!("  Dashboard: http://0.0.0.0:{}", port);
    tracing::info!("  API:       http://0.0.0.0:{}/api/", port);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}
