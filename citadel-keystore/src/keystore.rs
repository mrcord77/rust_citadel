//! Main keystore: key lifecycle management with policy, audit, and envelope integration.

use crate::audit::{AuditAction, AuditEvent, AuditSinkSync};
use crate::error::*;
use crate::policy::{self, KeyPolicy};
use crate::storage::StorageBackend;
use crate::threat::{PolicyAdapter, SecurityMetrics, ThreatAssessor, ThreatConfig, ThreatEvent, ThreatEventKind, ThreatLevel};
use crate::types::*;

use chrono::Utc;
use citadel_envelope::{Aad, Citadel, Context};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Encrypted blob (output of convenience encrypt)
// ---------------------------------------------------------------------------

/// A ciphertext with metadata about which key encrypted it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptedBlob {
    /// Which key ID was used.
    pub key_id: String,
    /// Which version of that key.
    pub key_version: u32,
    /// The ciphertext bytes (hex-encoded for JSON safety).
    pub ciphertext_hex: String,
    /// When this blob was created.
    pub encrypted_at: chrono::DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Keystore
// ---------------------------------------------------------------------------

pub struct Keystore {
    storage: Arc<dyn StorageBackend>,
    audit: Arc<dyn AuditSinkSync>,
    policies: HashMap<String, KeyPolicy>,
    envelope: Citadel,
    threat: Mutex<ThreatAssessor>,
}

impl Keystore {
    /// Create a new keystore with the given storage backend and audit sink.
    pub fn new(
        storage: Arc<dyn StorageBackend>,
        audit: Arc<dyn AuditSinkSync>,
    ) -> Self {
        Self {
            storage,
            audit: audit.clone(),
            policies: HashMap::new(),
            envelope: Citadel::new(),
            threat: Mutex::new(ThreatAssessor::new(ThreatConfig::default()).with_audit(audit)),
        }
    }

    /// Create with custom threat configuration.
    pub fn with_threat_config(
        storage: Arc<dyn StorageBackend>,
        audit: Arc<dyn AuditSinkSync>,
        threat_config: ThreatConfig,
    ) -> Self {
        Self {
            storage,
            audit: audit.clone(),
            policies: HashMap::new(),
            envelope: Citadel::new(),
            threat: Mutex::new(ThreatAssessor::new(threat_config).with_audit(audit)),
        }
    }

    // -----------------------------------------------------------------------
    // Policy management
    // -----------------------------------------------------------------------

    /// Register a policy.
    pub fn register_policy(&mut self, policy: KeyPolicy) {
        self.audit.record(AuditEvent::system_event(
            AuditAction::PolicyRegistered {
                policy_id: policy.id.as_str().to_string(),
            },
        ));
        self.policies.insert(policy.id.as_str().to_string(), policy);
    }

    /// Get a registered policy.
    pub fn get_policy(&self, id: &PolicyId) -> Option<&KeyPolicy> {
        self.policies.get(id.as_str())
    }

    // -----------------------------------------------------------------------
    // Key generation
    // -----------------------------------------------------------------------

    /// Generate a new key, returning its ID.
    pub async fn generate(
        &self,
        name: impl Into<String>,
        key_type: KeyType,
        policy_id: Option<PolicyId>,
        parent_id: Option<KeyId>,
    ) -> Result<KeyId, GenerateError> {
        let id = KeyId::generate();
        let now = Utc::now();

        // Generate actual cryptographic keypair
        let (pk, sk) = self.envelope.generate_keypair();

        let version = KeyVersion {
            version: 1,
            created_at: now,
            public_key_hex: hex::encode(pk.to_bytes()),
            secret_key_hex: hex::encode(sk.to_bytes()),
        };

        let meta = KeyMetadata {
            id: id.clone(),
            name: name.into(),
            key_type,
            state: KeyState::Pending,
            policy_id,
            parent_id,
            created_at: now,
            updated_at: now,
            activated_at: None,
            rotated_at: None,
            revoked_at: None,
            destroyed_at: None,
            versions: vec![version],
            current_version: 1,
            usage_count: 0,
            tags: HashMap::new(),
        };

        self.storage.put(&meta).map_err(|e| GenerateError(e))?;
        self.audit.record(AuditEvent::key_event(
            &id, key_type, KeyState::Pending, AuditAction::KeyGenerated,
        ));

        Ok(id)
    }

    // -----------------------------------------------------------------------
    // Key retrieval
    // -----------------------------------------------------------------------

    /// Get key metadata.
    pub async fn get(&self, id: &KeyId) -> Result<KeyMetadata, KeystoreError> {
        self.storage
            .get(id)?
            .ok_or_else(|| KeystoreError::KeyNotFound(id.clone()))
    }

    /// List all keys.
    pub async fn list_keys(&self) -> Result<Vec<KeyMetadata>, KeystoreError> {
        self.storage.list()
    }

    /// List keys in a specific state.
    pub async fn list_by_state(&self, state: KeyState) -> Result<Vec<KeyMetadata>, KeystoreError> {
        self.storage.list_by_state(state)
    }

    // -----------------------------------------------------------------------
    // State transitions
    // -----------------------------------------------------------------------

    /// Activate a PENDING key.
    pub async fn activate(&self, id: &KeyId) -> Result<(), LifecycleError> {
        let mut meta = self.get(id).await.map_err(LifecycleError)?;
        self.transition(&mut meta, KeyState::Active)?;
        meta.activated_at = Some(Utc::now());
        self.storage.put(&meta).map_err(LifecycleError)?;
        self.audit.record(AuditEvent::key_event(
            id, meta.key_type, meta.state, AuditAction::KeyActivated,
        ));
        Ok(())
    }

    /// Rotate an ACTIVE key: generates a new version, moves old to ROTATED.
    pub async fn rotate(&self, id: &KeyId) -> Result<KeyId, RotateError> {
        let mut meta = self.get(id).await.map_err(RotateError)?;

        if meta.state != KeyState::Active {
            return Err(RotateError(KeystoreError::NotActive(id.clone())));
        }

        // Generate new keypair for the new version
        let (pk, sk) = self.envelope.generate_keypair();
        let new_version_num = meta.current_version + 1;
        let now = Utc::now();

        let new_version = KeyVersion {
            version: new_version_num,
            created_at: now,
            public_key_hex: hex::encode(pk.to_bytes()),
            secret_key_hex: hex::encode(sk.to_bytes()),
        };

        // Old key enters ROTATED state
        meta.state = KeyState::Rotated;
        meta.rotated_at = Some(now);
        meta.updated_at = now;
        meta.versions.push(new_version);
        meta.current_version = new_version_num;

        self.storage.put(&meta).map_err(RotateError)?;
        self.audit.record(AuditEvent::key_event(
            id,
            meta.key_type,
            meta.state,
            AuditAction::KeyRotated { new_version: new_version_num },
        ));

        // If we want a separate active key, the caller creates a new one.
        // For simplicity, the same KeyId keeps its history and the latest version is ACTIVE-ready.
        // Let's re-activate with the new version.
        meta.state = KeyState::Active;
        meta.activated_at = Some(now);
        meta.rotated_at = None;
        meta.updated_at = now;
        self.storage.put(&meta).map_err(RotateError)?;

        Ok(id.clone())
    }

    /// Revoke a key (emergency deactivation).
    pub async fn revoke(&self, id: &KeyId, reason: impl Into<String>) -> Result<(), LifecycleError> {
        let mut meta = self.get(id).await.map_err(LifecycleError)?;
        let reason = reason.into();

        if meta.state != KeyState::Active {
            return Err(LifecycleError(KeystoreError::InvalidTransition {
                id: id.clone(),
                from: meta.state,
                to: KeyState::Revoked,
            }));
        }

        meta.state = KeyState::Revoked;
        meta.revoked_at = Some(Utc::now());
        meta.updated_at = Utc::now();
        self.storage.put(&meta).map_err(LifecycleError)?;
        self.audit.record(AuditEvent::key_event(
            id,
            meta.key_type,
            meta.state,
            AuditAction::KeyRevoked { reason },
        ));
        Ok(())
    }

    /// Expire a key (ROTATED past grace period, or ACTIVE past max_lifetime).
    pub async fn expire(&self, id: &KeyId) -> Result<ExpirationSource, ExpireError> {
        let mut meta = self.get(id).await.map_err(ExpireError)?;
        let decision = self.check_expiration(&meta);

        match decision {
            ExpirationDecision::Required { reason, source } => {
                meta.state = KeyState::Expired;
                meta.updated_at = Utc::now();
                self.storage.put(&meta).map_err(ExpireError)?;
                self.audit.record(AuditEvent::key_event(
                    id,
                    meta.key_type,
                    meta.state,
                    AuditAction::KeyExpired { reason },
                ));
                Ok(source)
            }
            _ => Err(ExpireError(KeystoreError::InvalidTransition {
                id: id.clone(),
                from: meta.state,
                to: KeyState::Expired,
            })),
        }
    }

    /// Destroy a key (purge material). Only EXPIRED or REVOKED keys can be destroyed.
    pub async fn destroy(&self, id: &KeyId) -> Result<(), LifecycleError> {
        let mut meta = self.get(id).await.map_err(LifecycleError)?;

        if !meta.state.can_transition_to(KeyState::Destroyed) {
            return Err(LifecycleError(KeystoreError::InvalidTransition {
                id: id.clone(),
                from: meta.state,
                to: KeyState::Destroyed,
            }));
        }

        // Purge key material from all versions
        for version in &mut meta.versions {
            version.public_key_hex = String::from("DESTROYED");
            version.secret_key_hex = String::from("DESTROYED");
        }

        meta.state = KeyState::Destroyed;
        meta.destroyed_at = Some(Utc::now());
        meta.updated_at = Utc::now();
        self.storage.put(&meta).map_err(LifecycleError)?;
        self.audit.record(AuditEvent::key_event(
            id, meta.key_type, meta.state, AuditAction::KeyDestroyed,
        ));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Expiration checks
    // -----------------------------------------------------------------------

    /// Check if a specific key should expire.
    pub async fn should_expire(&self, id: &KeyId) -> Result<ExpirationDecision, KeystoreError> {
        let meta = self.get(id).await?;
        Ok(self.check_expiration(&meta))
    }

    /// Internal expiration check logic.
    fn check_expiration(&self, meta: &KeyMetadata) -> ExpirationDecision {
        match meta.state {
            // ROTATED keys: check grace period
            KeyState::Rotated => {
                if let Some(rotated_at) = meta.rotated_at {
                    let grace = self.grace_period_for(meta);
                    let elapsed = Utc::now() - rotated_at;
                    let grace_chrono = chrono::Duration::from_std(grace)
                        .unwrap_or(chrono::Duration::MAX);

                    if elapsed >= grace_chrono {
                        return ExpirationDecision::Required {
                            reason: format!("rotated {}s ago, grace period {}s", 
                                elapsed.num_seconds(), grace.as_secs()),
                            source: ExpirationSource::GracePeriodExpired,
                        };
                    }

                    // Warn at 90%
                    let warn_secs = (grace.as_secs() as f64 * 0.9) as i64;
                    if elapsed.num_seconds() >= warn_secs {
                        let remaining = grace_chrono - elapsed;
                        return ExpirationDecision::Warning {
                            reason: format!("grace period expiring soon"),
                            remaining: remaining.to_std().unwrap_or(Duration::ZERO),
                            source: ExpirationSource::GracePeriodExpired,
                        };
                    }
                }
                ExpirationDecision::NotNeeded
            }

            // ACTIVE keys: check max_lifetime
            KeyState::Active => {
                if let Some(max_lifetime) = self.max_lifetime_for(meta) {
                    if let Some(activated_at) = meta.activated_at {
                        let elapsed = Utc::now() - activated_at;
                        let max_chrono = chrono::Duration::from_std(max_lifetime)
                            .unwrap_or(chrono::Duration::MAX);

                        if elapsed >= max_chrono {
                            return ExpirationDecision::Required {
                                reason: format!("active for {}s, max lifetime {}s",
                                    elapsed.num_seconds(), max_lifetime.as_secs()),
                                source: ExpirationSource::MaxLifetimeExceeded,
                            };
                        }

                        // Warn at 90%
                        let warn_secs = (max_lifetime.as_secs() as f64 * 0.9) as i64;
                        if elapsed.num_seconds() >= warn_secs {
                            let remaining = max_chrono - elapsed;
                            return ExpirationDecision::Warning {
                                reason: format!("max lifetime expiring soon"),
                                remaining: remaining.to_std().unwrap_or(Duration::ZERO),
                                source: ExpirationSource::MaxLifetimeExceeded,
                            };
                        }
                    }
                }
                ExpirationDecision::NotNeeded
            }

            _ => ExpirationDecision::NotNeeded,
        }
    }

    /// Process all keys that need expiration (bulk operation).
    pub async fn expire_due_keys(&self) -> Result<ExpirationReport, KeystoreError> {
        let mut report = ExpirationReport::default();

        // Check ROTATED keys (grace period)
        let rotated = self.storage.list_by_state(KeyState::Rotated)?;
        for meta in &rotated {
            match self.check_expiration(meta) {
                ExpirationDecision::Required { .. } => {
                    match self.expire(&meta.id).await {
                        Ok(src) => report.expired.push((meta.id.clone(), src)),
                        Err(e) => report.failed.push((meta.id.clone(), e.to_string())),
                    }
                }
                ExpirationDecision::Warning { reason, remaining, .. } => {
                    report.warnings.push((meta.id.clone(), reason, remaining));
                }
                ExpirationDecision::NotNeeded => {
                    report.skipped += 1;
                }
            }
        }

        // Check ACTIVE keys (max_lifetime)
        let active = self.storage.list_by_state(KeyState::Active)?;
        for meta in &active {
            match self.check_expiration(meta) {
                ExpirationDecision::Required { .. } => {
                    match self.expire(&meta.id).await {
                        Ok(src) => report.expired.push((meta.id.clone(), src)),
                        Err(e) => report.failed.push((meta.id.clone(), e.to_string())),
                    }
                }
                ExpirationDecision::Warning { reason, remaining, .. } => {
                    report.warnings.push((meta.id.clone(), reason, remaining));
                }
                ExpirationDecision::NotNeeded => {
                    report.skipped += 1;
                }
            }
        }

        self.audit.record(AuditEvent::system_event(
            AuditAction::ExpirationCheckRun {
                expired_count: report.expired.len(),
                warning_count: report.warnings.len(),
            },
        ));

        Ok(report)
    }

    // -----------------------------------------------------------------------
    // Policy evaluation
    // -----------------------------------------------------------------------

    /// Evaluate policy for a key.
    pub async fn evaluate_policy(&self, id: &KeyId) -> Result<policy::PolicyVerdict, KeystoreError> {
        let meta = self.get(id).await?;
        let policy = match &meta.policy_id {
            Some(pid) => self.policies.get(pid.as_str())
                .ok_or_else(|| KeystoreError::PolicyNotFound(pid.as_str().to_string()))?,
            None => return Ok(policy::PolicyVerdict::Compliant),
        };

        let verdict = policy::evaluate(policy, &meta);
        self.audit.record(
            AuditEvent::key_event(
                id, meta.key_type, meta.state,
                AuditAction::PolicyEvaluated { verdict: format!("{:?}", verdict) },
            ),
        );
        Ok(verdict)
    }

    /// Check all keys and return those needing rotation.
    pub async fn check_rotation_due(&self) -> Result<Vec<(KeyId, String)>, KeystoreError> {
        let active = self.storage.list_by_state(KeyState::Active)?;
        let mut due = Vec::new();

        for meta in active {
            if let Some(pid) = &meta.policy_id {
                if let Some(policy) = self.policies.get(pid.as_str()) {
                    let verdict = policy::evaluate(policy, &meta);
                    if let policy::PolicyVerdict::RotationNeeded { reason } = verdict {
                        due.push((meta.id.clone(), reason));
                    }
                }
            }
        }
        Ok(due)
    }

    // -----------------------------------------------------------------------
    // Convenience encrypt/decrypt (uses envelope)
    // -----------------------------------------------------------------------

    /// Encrypt data using the current active version of a key.
    ///
    /// **Enforcement gate**: Before encryption proceeds, the key is evaluated
    /// against its threat-adapted policy. If the adapted policy returns
    /// `RotationNeeded` or `UsageLimitExceeded`, encryption is **blocked**
    /// and a typed error is returned. The caller must rotate the key first.
    ///
    /// `Warning` verdicts are logged but allowed through — they are advisory.
    pub async fn encrypt(
        &self,
        key_id: &KeyId,
        plaintext: &[u8],
        aad: &Aad,
        context: &Context,
    ) -> Result<EncryptedBlob, EncryptError> {
        let mut meta = self.get(key_id).await
            .map_err(|e| EncryptError(e.to_string()))?;

        if !meta.state.can_encrypt() {
            return Err(EncryptError(format!("key {} is {}, cannot encrypt", key_id, meta.state)));
        }

        // ── Enforcement gate: evaluate threat-adapted policy ───────────
        if let Some(adapted) = self.effective_policy_for(&meta) {
            let verdict = policy::evaluate(&adapted, &meta);
            match &verdict {
                policy::PolicyVerdict::RotationNeeded { reason } => {
                    self.audit.record(AuditEvent::key_event(
                        key_id, meta.key_type, meta.state,
                        AuditAction::PolicyEvaluated {
                            verdict: format!("BLOCKED: {}", reason),
                        },
                    ));
                    return Err(EncryptError(format!(
                        "policy violation: {}. Rotate key before encrypting.", reason
                    )));
                }
                policy::PolicyVerdict::UsageLimitExceeded { count, limit } => {
                    self.audit.record(AuditEvent::key_event(
                        key_id, meta.key_type, meta.state,
                        AuditAction::PolicyEvaluated {
                            verdict: format!("BLOCKED: usage {}/{}", count, limit),
                        },
                    ));
                    return Err(EncryptError(format!(
                        "policy violation: usage {}/{} exceeded. Rotate key before encrypting.",
                        count, limit
                    )));
                }
                policy::PolicyVerdict::Warning { reason } => {
                    // Advisory only — log but allow through
                    self.audit.record(AuditEvent::key_event(
                        key_id, meta.key_type, meta.state,
                        AuditAction::PolicyEvaluated {
                            verdict: format!("WARNING: {}", reason),
                        },
                    ));
                }
                policy::PolicyVerdict::Compliant => {}
            }
        }
        // ── End enforcement gate ───────────────────────────────────────

        let version = meta.current_key_version()
            .ok_or_else(|| EncryptError("no current version".into()))?;

        let pk = citadel_envelope::PublicKey::from_bytes(
            &hex::decode(&version.public_key_hex)
                .map_err(|e| EncryptError(format!("decode pk: {}", e)))?
        ).map_err(|_| EncryptError("parse public key failed".into()))?;

        let ciphertext = self.envelope.seal(&pk, plaintext, aad, context)
            .map_err(|e| EncryptError(format!("seal: {}", e)))?;

        // Increment usage count
        meta.usage_count += 1;
        meta.updated_at = Utc::now();
        self.storage.put(&meta).map_err(|e| EncryptError(e.to_string()))?;

        self.audit.record(AuditEvent::key_event(
            key_id, meta.key_type, meta.state,
            AuditAction::EncryptionPerformed { key_version: meta.current_version },
        ));

        Ok(EncryptedBlob {
            key_id: key_id.as_str().to_string(),
            key_version: meta.current_version,
            ciphertext_hex: hex::encode(&ciphertext),
            encrypted_at: Utc::now(),
        })
    }

    /// Decrypt an EncryptedBlob.
    pub async fn decrypt(
        &self,
        blob: &EncryptedBlob,
        aad: &Aad,
        context: &Context,
    ) -> Result<Vec<u8>, DecryptError> {
        let key_id = KeyId::new(&blob.key_id);
        let meta = self.get(&key_id).await
            .map_err(|e| DecryptError(e.to_string()))?;

        if !meta.state.can_decrypt() {
            return Err(DecryptError(format!("key {} is {}, cannot decrypt", key_id, meta.state)));
        }

        // Find the version that encrypted this blob
        let version = meta.versions.iter()
            .find(|v| v.version == blob.key_version)
            .ok_or_else(|| DecryptError(format!("version {} not found", blob.key_version)))?;

        let sk = citadel_envelope::SecretKey::from_bytes(
            &hex::decode(&version.secret_key_hex)
                .map_err(|e| DecryptError(format!("decode sk: {}", e)))?
        ).map_err(|_| DecryptError("parse secret key failed".into()))?;

        let ciphertext = hex::decode(&blob.ciphertext_hex)
            .map_err(|e| DecryptError(format!("decode ct: {}", e)))?;

        let plaintext = self.envelope.open(&sk, &ciphertext, aad, context)
            .map_err(|_| {
                // ── Measured threat event: emit DecryptionFailure ──────
                // This is no longer modeled — the system observes real failures.
                self.record_threat_event(ThreatEvent::new(
                    ThreatEventKind::DecryptionFailure, 3.0,
                ).with_detail(format!("key={}, version={}", blob.key_id, blob.key_version)));

                self.audit.record(AuditEvent::key_event(
                    &key_id, meta.key_type, meta.state,
                    AuditAction::DecryptionFailed { key_version: blob.key_version },
                ));

                DecryptError("decryption failed".into())
            })?;

        self.audit.record(AuditEvent::key_event(
            &key_id, meta.key_type, meta.state,
            AuditAction::DecryptionPerformed { key_version: blob.key_version },
        ));

        Ok(plaintext)
    }

    // -----------------------------------------------------------------------
    // Helper methods
    // -----------------------------------------------------------------------

    fn transition(&self, meta: &mut KeyMetadata, target: KeyState) -> Result<(), LifecycleError> {
        if !meta.state.can_transition_to(target) {
            return Err(LifecycleError(KeystoreError::InvalidTransition {
                id: meta.id.clone(),
                from: meta.state,
                to: target,
            }));
        }
        meta.state = target;
        meta.updated_at = Utc::now();
        Ok(())
    }

    /// Snapshot the current threat level (short lock).
    fn current_threat_level(&self) -> ThreatLevel {
        self.threat.lock().unwrap().current_level()
    }

    /// Get the effective (threat-adapted) policy for a key.
    fn effective_policy_for(&self, meta: &KeyMetadata) -> Option<KeyPolicy> {
        let level = self.current_threat_level();
        meta.policy_id
            .as_ref()
            .and_then(|pid| self.policies.get(pid.as_str()))
            .map(|base| PolicyAdapter::adapt(base, level))
    }

    fn grace_period_for(&self, meta: &KeyMetadata) -> Duration {
        self.effective_policy_for(meta)
            .map(|p| p.rotation_grace_period)
            .unwrap_or(Duration::from_secs(7 * 86400))
    }

    fn max_lifetime_for(&self, meta: &KeyMetadata) -> Option<Duration> {
        self.effective_policy_for(meta)
            .and_then(|p| p.max_lifetime)
    }

    // -----------------------------------------------------------------------
    // Threat assessment API
    // -----------------------------------------------------------------------

    /// Record a threat event and recompute the threat level.
    pub fn record_threat_event(&self, event: ThreatEvent) {
        self.threat.lock().unwrap().record_event(event);
    }

    /// Record multiple threat events.
    pub fn record_threat_events(&self, events: Vec<ThreatEvent>) {
        self.threat.lock().unwrap().record_events(events);
    }

    /// Get the current threat level.
    pub fn threat_level(&self) -> ThreatLevel {
        self.current_threat_level()
    }

    /// Get the raw threat score.
    pub fn threat_score(&self) -> f64 {
        self.threat.lock().unwrap().raw_score()
    }

    /// Get comprehensive security metrics for the dashboard.
    pub async fn security_metrics(&self) -> Result<SecurityMetrics, KeystoreError> {
        let level = self.current_threat_level();
        let all_keys = self.storage.list()?;
        let total = all_keys.len();
        let mut compliant = 0;

        for meta in &all_keys {
            if let Some(pid) = &meta.policy_id {
                if let Some(base_policy) = self.policies.get(pid.as_str()) {
                    let adapted = PolicyAdapter::adapt(base_policy, level);
                    let verdict = policy::evaluate(&adapted, meta);
                    if matches!(verdict, policy::PolicyVerdict::Compliant | policy::PolicyVerdict::Warning { .. }) {
                        compliant += 1;
                    }
                } else {
                    compliant += 1;
                }
            } else {
                compliant += 1;
            }
        }

        Ok(self.threat.lock().unwrap().security_metrics(total, compliant))
    }

    /// Get threat level transition history (owned copy).
    pub fn threat_history(&self) -> Vec<(chrono::DateTime<Utc>, ThreatLevel, String)> {
        self.threat.lock().unwrap().level_history().to_vec()
    }

    /// Get adaptation summary for a specific policy at the current threat level.
    pub fn policy_adaptation_summary(&self, policy_id: &PolicyId) -> Option<crate::threat::AdaptationSummary> {
        let level = self.current_threat_level();
        self.policies
            .get(policy_id.as_str())
            .map(|base| PolicyAdapter::summarize(base, level))
    }

    /// Evaluate policy using threat-adapted parameters.
    pub async fn evaluate_adaptive_policy(&self, id: &KeyId) -> Result<policy::PolicyVerdict, KeystoreError> {
        let level = self.current_threat_level();
        let meta = self.get(id).await?;
        let adapted_policy = match &meta.policy_id {
            Some(pid) => {
                let base = self.policies.get(pid.as_str())
                    .ok_or_else(|| KeystoreError::PolicyNotFound(pid.as_str().to_string()))?;
                PolicyAdapter::adapt(base, level)
            }
            None => return Ok(policy::PolicyVerdict::Compliant),
        };

        let verdict = policy::evaluate(&adapted_policy, &meta);
        self.audit.record(
            AuditEvent::key_event(
                id, meta.key_type, meta.state,
                AuditAction::PolicyEvaluated {
                    verdict: format!("{:?} (threat:{})", verdict, level.label()),
                },
            ),
        );
        Ok(verdict)
    }

    /// Check all keys using threat-adapted policies and return those needing rotation.
    pub async fn check_adaptive_rotation_due(&self) -> Result<Vec<(KeyId, String)>, KeystoreError> {
        let level = self.current_threat_level();
        let active = self.storage.list_by_state(KeyState::Active)?;
        let mut due = Vec::new();

        for meta in active {
            if let Some(pid) = &meta.policy_id {
                if let Some(base_policy) = self.policies.get(pid.as_str()) {
                    let adapted = PolicyAdapter::adapt(base_policy, level);
                    let verdict = policy::evaluate(&adapted, &meta);
                    if let policy::PolicyVerdict::RotationNeeded { reason } = verdict {
                        due.push((meta.id.clone(), format!("{} [threat:{}]", reason, level.label())));
                    }
                }
            }
        }
        Ok(due)
    }
}
