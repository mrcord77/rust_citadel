//! Audit logging: every key operation emits a structured event.

use crate::types::{KeyId, KeyState, KeyType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

/// What happened.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuditAction {
    KeyGenerated,
    KeyActivated,
    KeyRotated { new_version: u32 },
    KeyExpired { reason: String },
    KeyRevoked { reason: String },
    KeyDestroyed,
    EncryptionPerformed { key_version: u32 },
    DecryptionPerformed { key_version: u32 },
    DecryptionFailed { key_version: u32 },
    PolicyRegistered { policy_id: String },
    PolicyEvaluated { verdict: String },
    ExpirationCheckRun { expired_count: usize, warning_count: usize },
}

/// A structured audit event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When it happened.
    pub timestamp: DateTime<Utc>,
    /// Which key was involved.
    pub key_id: Option<KeyId>,
    /// What type of key.
    pub key_type: Option<KeyType>,
    /// What state the key was in.
    pub key_state: Option<KeyState>,
    /// What happened.
    pub action: AuditAction,
    /// Who or what triggered this.
    pub actor: String,
    /// Success or failure.
    pub success: bool,
    /// Additional context.
    pub detail: Option<String>,
    /// Monotonic sequence number (populated by integrity chain sink).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    /// SHA-256 hash of the previous event's JSON (populated by integrity chain sink).
    /// First event in chain has prev_hash = SHA-256("citadel-audit-genesis").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
}

impl AuditEvent {
    /// Create a new audit event for a key operation.
    pub fn key_event(
        key_id: &KeyId,
        key_type: KeyType,
        key_state: KeyState,
        action: AuditAction,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            key_id: Some(key_id.clone()),
            key_type: Some(key_type),
            key_state: Some(key_state),
            action,
            actor: "system".into(),
            success: true,
            detail: None,
            sequence: None,
            prev_hash: None,
        }
    }

    /// Create a system-level audit event (no specific key).
    pub fn system_event(action: AuditAction) -> Self {
        Self {
            timestamp: Utc::now(),
            key_id: None,
            key_type: None,
            key_state: None,
            action,
            actor: "system".into(),
            success: true,
            detail: None,
            sequence: None,
            prev_hash: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = actor.into();
        self
    }

    pub fn with_failure(mut self) -> Self {
        self.success = false;
        self
    }
}

// ---------------------------------------------------------------------------
// Audit sink trait
// ---------------------------------------------------------------------------

/// Where audit events go. Implement this for your SIEM/log system.
///
/// Synchronous to avoid the `async_trait` dependency.
/// For async sinks, use interior mutability (e.g., channel-based).
pub trait AuditSinkSync: Send + Sync {
    fn record(&self, event: AuditEvent);
}

// ---------------------------------------------------------------------------
// Built-in sinks
// ---------------------------------------------------------------------------

/// Logs events via the `tracing` crate.
pub struct TracingAuditSink;

impl AuditSinkSync for TracingAuditSink {
    fn record(&self, event: AuditEvent) {
        tracing::info!(
            timestamp = %event.timestamp,
            key_id = ?event.key_id,
            action = ?event.action,
            actor = %event.actor,
            success = event.success,
            detail = ?event.detail,
            "audit"
        );
    }
}

/// Collects events in memory (for testing and the API layer).
pub struct InMemoryAuditSink {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl InMemoryAuditSink {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().await.clone()
    }

    pub async fn events_for_key(&self, key_id: &KeyId) -> Vec<AuditEvent> {
        self.events
            .lock()
            .await
            .iter()
            .filter(|e| e.key_id.as_ref() == Some(key_id))
            .cloned()
            .collect()
    }

    pub async fn len(&self) -> usize {
        self.events.lock().await.len()
    }
}

impl Default for InMemoryAuditSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSinkSync for InMemoryAuditSink {
    fn record(&self, event: AuditEvent) {
        // Use try_lock to avoid blocking â€” best effort for in-memory sink
        if let Ok(mut events) = self.events.try_lock() {
            events.push(event);
        }
    }
}

/// Writes JSON events to a file (append-only).
pub struct FileAuditSink {
    path: std::path::PathBuf,
}

impl FileAuditSink {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl AuditSinkSync for FileAuditSink {
    fn record(&self, event: AuditEvent) {
        use std::io::Write;
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut file) => {
                match serde_json::to_string(&event) {
                    Ok(json) => {
                        if let Err(e) = writeln!(file, "{}", json) {
                            eprintln!("[audit] write error: {}", e);
                        }
                    }
                    Err(e) => eprintln!("[audit] serialize error: {}", e),
                }
            }
            Err(e) => {
                eprintln!(
                    "[audit] cannot open {:?}: {} (cwd: {:?})",
                    self.path,
                    e,
                    std::env::current_dir().unwrap_or_default()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Integrity chain sink (tamper-evident audit log)
// ---------------------------------------------------------------------------

/// Wraps any `AuditSinkSync` and adds a SHA-256 hash chain.
///
/// Each event gets a monotonic `sequence` number and a `prev_hash`
/// containing the SHA-256 hex digest of the previous event's JSON.
/// Verifiers can replay the log and recompute hashes to detect
/// any insertion, deletion, or modification of events.
///
/// The genesis hash is `SHA-256("citadel-audit-genesis")`.
pub struct IntegrityChainSink {
    inner: Arc<dyn AuditSinkSync>,
    state: std::sync::Mutex<ChainState>,
}

struct ChainState {
    sequence: u64,
    prev_hash: String,
}

impl IntegrityChainSink {
    pub fn new(inner: Arc<dyn AuditSinkSync>) -> Self {
        use sha2::{Sha256, Digest};
        let genesis = format!("{:x}", Sha256::digest(b"citadel-audit-genesis"));
        Self {
            inner,
            state: std::sync::Mutex::new(ChainState {
                sequence: 0,
                prev_hash: genesis,
            }),
        }
    }
}

impl AuditSinkSync for IntegrityChainSink {
    fn record(&self, mut event: AuditEvent) {
        use sha2::{Sha256, Digest};

        let mut state = self.state.lock().unwrap();

        // Stamp the event with chain metadata
        event.sequence = Some(state.sequence);
        event.prev_hash = Some(state.prev_hash.clone());

        // Compute this event's hash for the next link
        // Hash is computed over the complete event JSON (including sequence + prev_hash)
        if let Ok(json) = serde_json::to_string(&event) {
            state.prev_hash = format!("{:x}", Sha256::digest(json.as_bytes()));
        }
        state.sequence += 1;

        drop(state); // Release lock before forwarding
        self.inner.record(event);
    }
}
