//! # Citadel Keystore
//!
//! Post-quantum key lifecycle management.
//!
//! Provides a four-level key hierarchy (Root â†’ Domain â†’ KEK â†’ DEK),
//! policy-driven rotation, audit logging, and pluggable storage backends.
//!
//! Built on top of `citadel-envelope` for hybrid X25519 + ML-KEM-768 encryption.
//!
//! ## Quick Start
//!
//! ```ignore
//! use citadel_keystore::*;
//! use citadel_envelope::{Aad, Context};
//! use std::sync::Arc;
//!
//! # tokio_test::block_on(async {
//! let storage = Arc::new(InMemoryBackend::new());
//! let audit = Arc::new(InMemoryAuditSink::new());
//! let mut ks = Keystore::new(storage, audit);
//!
//! // Register a policy
//! ks.register_policy(KeyPolicy::default_dek());
//!
//! // Generate and activate a key
//! let key_id = ks.generate("my-dek", KeyType::DataEncrypting, None, None).await.unwrap();
//! ks.activate(&key_id).await.unwrap();
//!
//! // Encrypt
//! let aad = Aad::raw(b"context");
//! let ctx = Context::raw(b"purpose");
//! let blob = ks.encrypt(&key_id, b"secret data", &aad, &ctx).await.unwrap();
//!
//! // Decrypt
//! let plaintext = ks.decrypt(&blob, &aad, &ctx).await.unwrap();
//! assert_eq!(plaintext, b"secret data");
//! # });
//! ```

pub mod audit;
pub mod error;
pub mod keystore;
pub mod policy;
pub mod storage;
pub mod threat;
pub mod types;

// Re-export main types for convenience
pub use audit::{AuditEvent, AuditSinkSync, FileAuditSink, InMemoryAuditSink, IntegrityChainSink, TracingAuditSink};
pub use error::{
    DecryptError, DestroyDecision, EncryptError, ExpirationDecision, ExpirationReport,
    ExpirationSource, ExpireError, GenerateError, KeystoreError, LifecycleError, RotateError,
};
pub use keystore::{EncryptedBlob, Keystore};
pub use policy::{KeyPolicy, PolicyVerdict, RotationTrigger};
pub use storage::{FileBackend, InMemoryBackend, StorageBackend};
pub use threat::{
    AdaptationSummary, PolicyAdapter, SecurityMetrics, ThreatAssessor, ThreatConfig,
    ThreatEvent, ThreatEventKind, ThreatLevel,
};
pub use types::{KeyId, KeyMetadata, KeyState, KeyType, KeyVersion, PolicyId};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_envelope::{Aad, Context};
    use std::sync::Arc;
    use std::time::Duration;

    fn test_keystore() -> Keystore {
        let storage = Arc::new(InMemoryBackend::new());
        let audit = Arc::new(InMemoryAuditSink::new());
        Keystore::new(storage, audit)
    }

    fn test_keystore_with_audit() -> (Keystore, Arc<InMemoryAuditSink>) {
        let storage = Arc::new(InMemoryBackend::new());
        let audit = Arc::new(InMemoryAuditSink::new());
        let ks = Keystore::new(storage.clone(), audit.clone());
        (ks, audit)
    }

    // === Key Generation ===

    #[tokio::test]
    async fn test_generate_key() {
        let ks = test_keystore();
        let id = ks.generate("test-key", KeyType::DataEncrypting, None, None).await.unwrap();
        let meta = ks.get(&id).await.unwrap();

        assert_eq!(meta.name, "test-key");
        assert_eq!(meta.key_type, KeyType::DataEncrypting);
        assert_eq!(meta.state, KeyState::Pending);
        assert_eq!(meta.current_version, 1);
        assert_eq!(meta.usage_count, 0);
        assert_eq!(meta.versions.len(), 1);
    }

    #[tokio::test]
    async fn test_generate_all_key_types() {
        let ks = test_keystore();
        for kt in [KeyType::Root, KeyType::Domain, KeyType::KeyEncrypting, KeyType::DataEncrypting] {
            let id = ks.generate(format!("{:?}", kt), kt, None, None).await.unwrap();
            let meta = ks.get(&id).await.unwrap();
            assert_eq!(meta.key_type, kt);
        }
    }

    #[tokio::test]
    async fn test_generate_with_parent() {
        let ks = test_keystore();
        let parent = ks.generate("parent", KeyType::KeyEncrypting, None, None).await.unwrap();
        let child = ks.generate("child", KeyType::DataEncrypting, None, Some(parent.clone())).await.unwrap();
        let meta = ks.get(&child).await.unwrap();
        assert_eq!(meta.parent_id, Some(parent));
    }

    // === Activation ===

    #[tokio::test]
    async fn test_activate_pending_key() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();
        let meta = ks.get(&id).await.unwrap();
        assert_eq!(meta.state, KeyState::Active);
        assert!(meta.activated_at.is_some());
    }

    #[tokio::test]
    async fn test_activate_non_pending_fails() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();
        // Already active, can't activate again
        let result = ks.activate(&id).await;
        assert!(result.is_err());
    }

    // === Rotation ===

    #[tokio::test]
    async fn test_rotate_active_key() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();
        ks.rotate(&id).await.unwrap();

        let meta = ks.get(&id).await.unwrap();
        assert_eq!(meta.state, KeyState::Active); // Re-activated with new version
        assert_eq!(meta.current_version, 2);
        assert_eq!(meta.versions.len(), 2);
    }

    #[tokio::test]
    async fn test_rotate_preserves_old_versions() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();
        ks.rotate(&id).await.unwrap();
        ks.rotate(&id).await.unwrap();

        let meta = ks.get(&id).await.unwrap();
        assert_eq!(meta.current_version, 3);
        assert_eq!(meta.versions.len(), 3);
        assert_eq!(meta.versions[0].version, 1);
        assert_eq!(meta.versions[1].version, 2);
        assert_eq!(meta.versions[2].version, 3);
    }

    #[tokio::test]
    async fn test_rotate_non_active_fails() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        // Still PENDING
        let result = ks.rotate(&id).await;
        assert!(result.is_err());
    }

    // === Revocation ===

    #[tokio::test]
    async fn test_revoke_active_key() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();
        ks.revoke(&id, "security incident").await.unwrap();

        let meta = ks.get(&id).await.unwrap();
        assert_eq!(meta.state, KeyState::Revoked);
        assert!(meta.revoked_at.is_some());
    }

    // === Destruction ===

    #[tokio::test]
    async fn test_destroy_revoked_key() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();
        ks.revoke(&id, "test").await.unwrap();
        ks.destroy(&id).await.unwrap();

        let meta = ks.get(&id).await.unwrap();
        assert_eq!(meta.state, KeyState::Destroyed);
        assert!(meta.destroyed_at.is_some());
        // Key material should be purged
        assert_eq!(meta.versions[0].secret_key_hex, "DESTROYED");
        assert_eq!(meta.versions[0].public_key_hex, "DESTROYED");
    }

    #[tokio::test]
    async fn test_destroy_active_key_fails() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();
        let result = ks.destroy(&id).await;
        assert!(result.is_err());
    }

    // === State Machine ===

    #[tokio::test]
    async fn test_state_machine_valid_transitions() {
        assert!(KeyState::Pending.can_transition_to(KeyState::Active));
        assert!(KeyState::Pending.can_transition_to(KeyState::Destroyed));
        assert!(KeyState::Active.can_transition_to(KeyState::Rotated));
        assert!(KeyState::Active.can_transition_to(KeyState::Revoked));
        assert!(KeyState::Active.can_transition_to(KeyState::Expired));
        assert!(KeyState::Rotated.can_transition_to(KeyState::Expired));
        assert!(KeyState::Expired.can_transition_to(KeyState::Destroyed));
        assert!(KeyState::Revoked.can_transition_to(KeyState::Destroyed));
    }

    #[tokio::test]
    async fn test_state_machine_invalid_transitions() {
        assert!(!KeyState::Pending.can_transition_to(KeyState::Rotated));
        assert!(!KeyState::Active.can_transition_to(KeyState::Pending));
        assert!(!KeyState::Rotated.can_transition_to(KeyState::Active));
        assert!(!KeyState::Expired.can_transition_to(KeyState::Active));
        assert!(!KeyState::Destroyed.can_transition_to(KeyState::Active));
    }

    // === Encrypt / Decrypt ===

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();

        let aad = Aad::raw(b"test-aad");
        let ctx = Context::raw(b"test-ctx");
        let plaintext = b"hello from citadel keystore";

        let blob = ks.encrypt(&id, plaintext, &aad, &ctx).await.unwrap();
        assert_eq!(blob.key_version, 1);

        let decrypted = ks.decrypt(&blob, &aad, &ctx).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_encrypt_increments_usage_count() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();

        let aad = Aad::raw(b"aad");
        let ctx = Context::raw(b"ctx");

        for i in 1..=5 {
            ks.encrypt(&id, b"data", &aad, &ctx).await.unwrap();
            let meta = ks.get(&id).await.unwrap();
            assert_eq!(meta.usage_count, i);
        }
    }

    #[tokio::test]
    async fn test_encrypt_with_pending_key_fails() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();

        let aad = Aad::raw(b"aad");
        let ctx = Context::raw(b"ctx");
        let result = ks.encrypt(&id, b"data", &aad, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_decrypt_with_wrong_aad_fails() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();

        let aad = Aad::raw(b"correct-aad");
        let ctx = Context::raw(b"ctx");
        let blob = ks.encrypt(&id, b"data", &aad, &ctx).await.unwrap();

        let wrong_aad = Aad::raw(b"wrong-aad");
        let result = ks.decrypt(&blob, &wrong_aad, &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_decrypt_after_rotation_uses_correct_version() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();

        let aad = Aad::raw(b"aad");
        let ctx = Context::raw(b"ctx");

        // Encrypt with version 1
        let blob_v1 = ks.encrypt(&id, b"version one", &aad, &ctx).await.unwrap();
        assert_eq!(blob_v1.key_version, 1);

        // Rotate to version 2
        ks.rotate(&id).await.unwrap();

        // Encrypt with version 2
        let blob_v2 = ks.encrypt(&id, b"version two", &aad, &ctx).await.unwrap();
        assert_eq!(blob_v2.key_version, 2);

        // Both should decrypt correctly
        let pt1 = ks.decrypt(&blob_v1, &aad, &ctx).await.unwrap();
        let pt2 = ks.decrypt(&blob_v2, &aad, &ctx).await.unwrap();
        assert_eq!(pt1, b"version one");
        assert_eq!(pt2, b"version two");
    }

    // === Policy Evaluation ===

    #[tokio::test]
    async fn test_policy_compliant() {
        let mut ks = test_keystore();
        let policy = KeyPolicy::default_dek();
        let pid = policy.id.clone();
        ks.register_policy(policy);

        let id = ks.generate("key", KeyType::DataEncrypting, Some(pid), None).await.unwrap();
        ks.activate(&id).await.unwrap();

        let verdict = ks.evaluate_policy(&id).await.unwrap();
        assert!(matches!(verdict, PolicyVerdict::Compliant));
    }

    #[tokio::test]
    async fn test_policy_usage_limit() {
        let mut ks = test_keystore();
        let policy = KeyPolicy {
            id: PolicyId::new("limited"),
            name: "Limited".into(),
            applies_to: vec![KeyType::DataEncrypting],
            rotation_triggers: vec![],
            rotation_grace_period: Duration::from_secs(86400),
            max_lifetime: None,
            max_usage_count: Some(10),
            auto_rotate: false,
            min_versions_retained: 1,
        };
        let pid = policy.id.clone();
        ks.register_policy(policy);

        let id = ks.generate("key", KeyType::DataEncrypting, Some(pid), None).await.unwrap();
        ks.activate(&id).await.unwrap();

        let aad = Aad::raw(b"aad");
        let ctx = Context::raw(b"ctx");

        // Use it 10 times
        for _ in 0..10 {
            ks.encrypt(&id, b"data", &aad, &ctx).await.unwrap();
        }

        let verdict = ks.evaluate_policy(&id).await.unwrap();
        assert!(verdict.needs_rotation());
    }

    // === Audit ===

    #[tokio::test]
    async fn test_audit_events_generated() {
        let (ks, audit) = test_keystore_with_audit();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();

        let events = audit.events().await;
        assert!(events.len() >= 2); // generate + activate
    }

    #[tokio::test]
    async fn test_audit_tracks_encryption() {
        let (ks, audit) = test_keystore_with_audit();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();

        let aad = Aad::raw(b"aad");
        let ctx = Context::raw(b"ctx");
        ks.encrypt(&id, b"data", &aad, &ctx).await.unwrap();

        let events = audit.events_for_key(&id).await;
        let has_encrypt = events.iter().any(|e| matches!(e.action, crate::audit::AuditAction::EncryptionPerformed { .. }));
        assert!(has_encrypt);
    }

    // === List Operations ===

    #[tokio::test]
    async fn test_list_keys() {
        let ks = test_keystore();
        for i in 0..5 {
            ks.generate(format!("key-{}", i), KeyType::DataEncrypting, None, None).await.unwrap();
        }
        let keys = ks.list_keys().await.unwrap();
        assert_eq!(keys.len(), 5);
    }

    #[tokio::test]
    async fn test_list_by_state() {
        let ks = test_keystore();
        let id1 = ks.generate("key1", KeyType::DataEncrypting, None, None).await.unwrap();
        let id2 = ks.generate("key2", KeyType::DataEncrypting, None, None).await.unwrap();
        let _id3 = ks.generate("key3", KeyType::DataEncrypting, None, None).await.unwrap();

        ks.activate(&id1).await.unwrap();
        ks.activate(&id2).await.unwrap();

        let active = ks.list_by_state(KeyState::Active).await.unwrap();
        let pending = ks.list_by_state(KeyState::Pending).await.unwrap();
        assert_eq!(active.len(), 2);
        assert_eq!(pending.len(), 1);
    }

    // === Encrypted Blob Serialization ===

    #[tokio::test]
    async fn test_encrypted_blob_serialization() {
        let ks = test_keystore();
        let id = ks.generate("key", KeyType::DataEncrypting, None, None).await.unwrap();
        ks.activate(&id).await.unwrap();

        let aad = Aad::raw(b"aad");
        let ctx = Context::raw(b"ctx");
        let blob = ks.encrypt(&id, b"secret", &aad, &ctx).await.unwrap();

        // Serialize to JSON and back
        let json = serde_json::to_string(&blob).unwrap();
        let restored: EncryptedBlob = serde_json::from_str(&json).unwrap();

        let decrypted = ks.decrypt(&restored, &aad, &ctx).await.unwrap();
        assert_eq!(decrypted, b"secret");
    }

    // === Full Lifecycle ===

    #[tokio::test]
    async fn test_full_lifecycle() {
        let ks = test_keystore();
        let id = ks.generate("lifecycle-key", KeyType::DataEncrypting, None, None).await.unwrap();

        // PENDING â†’ ACTIVE
        ks.activate(&id).await.unwrap();
        assert_eq!(ks.get(&id).await.unwrap().state, KeyState::Active);

        // Encrypt something
        let aad = Aad::raw(b"aad");
        let ctx = Context::raw(b"ctx");
        let blob = ks.encrypt(&id, b"important data", &aad, &ctx).await.unwrap();

        // ACTIVE â†’ ROTATED â†’ ACTIVE (via rotate)
        ks.rotate(&id).await.unwrap();
        assert_eq!(ks.get(&id).await.unwrap().state, KeyState::Active);
        assert_eq!(ks.get(&id).await.unwrap().current_version, 2);

        // Old blob still decrypts
        let pt = ks.decrypt(&blob, &aad, &ctx).await.unwrap();
        assert_eq!(pt, b"important data");

        // ACTIVE â†’ REVOKED
        ks.revoke(&id, "end of life").await.unwrap();
        assert_eq!(ks.get(&id).await.unwrap().state, KeyState::Revoked);

        // REVOKED â†’ DESTROYED
        ks.destroy(&id).await.unwrap();
        assert_eq!(ks.get(&id).await.unwrap().state, KeyState::Destroyed);
    }

    // === Key Not Found ===

    #[tokio::test]
    async fn test_get_nonexistent_key() {
        let ks = test_keystore();
        let result = ks.get(&KeyId::new("does-not-exist")).await;
        assert!(result.is_err());
    }

    // =======================================================================
    // Adaptive Threat Level Tests
    // =======================================================================

    #[test]
    fn test_threat_level_basics() {
        let assessor = ThreatAssessor::new(ThreatConfig::default());
        assert_eq!(assessor.current_level(), ThreatLevel::Low);
        assert_eq!(assessor.raw_score(), 0.0);
    }

    #[test]
    fn test_threat_level_escalation() {
        let mut assessor = ThreatAssessor::new(ThreatConfig {
            thresholds: [5.0, 15.0, 30.0, 50.0],
            ..Default::default()
        });

        // Fire events to push score above threshold[0] = 5.0
        for _ in 0..3 {
            assessor.record_event(ThreatEvent::new(ThreatEventKind::DecryptionFailure, 3.0));
        }
        // Score ~ 9.0, should be Guarded
        assert!(assessor.current_level() >= ThreatLevel::Guarded);

        // Push to Elevated (>15)
        for _ in 0..5 {
            assessor.record_event(ThreatEvent::new(ThreatEventKind::RapidAccessPattern, 4.0));
        }
        assert!(assessor.current_level() >= ThreatLevel::Elevated);
    }

    #[test]
    fn test_threat_manual_escalation() {
        let mut assessor = ThreatAssessor::new(ThreatConfig::default());
        assert_eq!(assessor.current_level(), ThreatLevel::Low);

        assessor.record_event(ThreatEvent::new(ThreatEventKind::ManualEscalation, 0.0));
        assert_eq!(assessor.current_level(), ThreatLevel::Guarded);

        assessor.record_event(ThreatEvent::new(ThreatEventKind::ManualEscalation, 0.0));
        assert_eq!(assessor.current_level(), ThreatLevel::Elevated);

        // De-escalate returns to computed level
        assessor.record_event(ThreatEvent::new(ThreatEventKind::ManualDeescalation, 0.0));
        // Computed score is ~0, so should drop back to Low
        assert_eq!(assessor.current_level(), ThreatLevel::Low);
    }

    #[test]
    fn test_threat_level_display() {
        assert_eq!(ThreatLevel::Low.label(), "LOW");
        assert_eq!(ThreatLevel::Critical.label(), "CRITICAL");
        assert_eq!(ThreatLevel::Critical.value(), 5);
        assert!(ThreatLevel::Critical.color().starts_with('#'));
    }

    #[test]
    fn test_threat_event_with_detail() {
        let event = ThreatEvent::new(ThreatEventKind::ExternalAdvisory, 8.0)
            .with_detail("CVE-2026-1234 published");
        assert_eq!(event.detail.unwrap(), "CVE-2026-1234 published");
        assert_eq!(event.severity, 8.0);
    }

    #[test]
    fn test_threat_severity_clamping() {
        let event = ThreatEvent::new(ThreatEventKind::DecryptionFailure, 999.0);
        assert_eq!(event.severity, 10.0); // Clamped to max

        let event2 = ThreatEvent::new(ThreatEventKind::DecryptionFailure, -5.0);
        assert_eq!(event2.severity, 0.0); // Clamped to min
    }

    // === Policy Adapter Tests ===

    #[test]
    fn test_policy_adapter_low_threat_no_change() {
        let base = KeyPolicy::default_dek();
        let adapted = PolicyAdapter::adapt(&base, ThreatLevel::Low);

        // At Low, everything stays the same
        assert_eq!(adapted.rotation_grace_period, base.rotation_grace_period);
        assert_eq!(adapted.max_lifetime, base.max_lifetime);
        assert_eq!(adapted.auto_rotate, base.auto_rotate);
    }

    #[test]
    fn test_policy_adapter_critical_compresses_everything() {
        let base = KeyPolicy::default_dek();
        let adapted = PolicyAdapter::adapt(&base, ThreatLevel::Critical);

        // Grace period should be 10% of original
        let expected_grace = Duration::from_secs(
            (base.rotation_grace_period.as_secs() as f64 * 0.1) as u64
        );
        assert_eq!(adapted.rotation_grace_period, expected_grace);

        // Max lifetime should be 25% of original
        let expected_lifetime = base.max_lifetime.map(|d| {
            Duration::from_secs((d.as_secs() as f64 * 0.25) as u64)
        });
        assert_eq!(adapted.max_lifetime, expected_lifetime);

        // Auto-rotate forced on
        assert!(adapted.auto_rotate);

        // Name reflects threat level
        assert!(adapted.name.contains("CRITICAL"));
    }

    #[test]
    fn test_policy_adapter_elevated_forces_auto_rotate() {
        let mut base = KeyPolicy::default_dek();
        base.auto_rotate = false;
        let adapted = PolicyAdapter::adapt(&base, ThreatLevel::Elevated);
        assert!(adapted.auto_rotate);
    }

    #[test]
    fn test_policy_adapter_guarded_does_not_force_auto_rotate() {
        let mut base = KeyPolicy::default_dek();
        base.auto_rotate = false;
        let adapted = PolicyAdapter::adapt(&base, ThreatLevel::Guarded);
        assert!(!adapted.auto_rotate); // Only forced at Level 3+
    }

    #[test]
    fn test_policy_adapter_scales_usage_limit() {
        let mut base = KeyPolicy::default_dek();
        base.max_usage_count = Some(1000);
        let adapted = PolicyAdapter::adapt(&base, ThreatLevel::High);
        // High = 0.4Ã— factor
        assert_eq!(adapted.max_usage_count, Some(400));
    }

    #[test]
    fn test_policy_adaptation_summary() {
        let base = KeyPolicy::default_dek();
        let summary = PolicyAdapter::summarize(&base, ThreatLevel::Critical);
        assert_eq!(summary.threat_level, ThreatLevel::Critical);
        assert!(summary.auto_rotate_forced);
        // Effective grace should be shorter than base
        assert!(summary.effective_grace_period < summary.base_grace_period);
    }

    // === Keystore + Threat Integration Tests ===

    #[tokio::test]
    async fn test_keystore_threat_level_starts_low() {
        let ks = test_keystore();
        assert_eq!(ks.threat_level(), ThreatLevel::Low);
    }

    #[tokio::test]
    async fn test_keystore_record_threat_event() {
        let ks = test_keystore();
        ks.record_threat_event(
            ThreatEvent::new(ThreatEventKind::DecryptionFailure, 3.0)
        );
        assert!(ks.threat_score() > 0.0);
    }

    #[tokio::test]
    async fn test_keystore_threat_escalation_tightens_policy() {
        let mut ks = test_keystore();
        ks.register_policy(KeyPolicy::default_dek());

        let id = ks.generate(
            "threat-test-key", KeyType::DataEncrypting,
            Some(PolicyId::new("default-dek")), None,
        ).await.unwrap();
        ks.activate(&id).await.unwrap();

        // At Low, get base grace period
        let base_grace = ks.policy_adaptation_summary(&PolicyId::new("default-dek"))
            .unwrap().effective_grace_period;

        // Escalate to Critical
        for _ in 0..20 {
            ks.record_threat_event(
                ThreatEvent::new(ThreatEventKind::ExternalAdvisory, 8.0)
            );
        }
        assert!(ks.threat_level() >= ThreatLevel::High);

        // Grace period should now be shorter
        let adapted_grace = ks.policy_adaptation_summary(&PolicyId::new("default-dek"))
            .unwrap().effective_grace_period;
        assert!(adapted_grace < base_grace,
            "Expected grace period to shrink: base={:?}, adapted={:?}", base_grace, adapted_grace);
    }

    #[tokio::test]
    async fn test_security_metrics() {
        let ks = test_keystore();
        let metrics = ks.security_metrics().await.unwrap();

        assert_eq!(metrics.threat_level, ThreatLevel::Low);
        assert!(metrics.overall > 0.0);
        assert!(metrics.quantum_resistance > 80.0);
        assert!(metrics.classical_security > 90.0);
        assert_eq!(metrics.key_hygiene, 100.0); // No keys = 100% compliant
    }

    #[tokio::test]
    async fn test_threat_history_tracks_transitions() {
        let ks = test_keystore();
        // Initial history has one entry
        assert_eq!(ks.threat_history().len(), 1);

        // Escalate manually
        ks.record_threat_event(ThreatEvent::new(ThreatEventKind::ManualEscalation, 0.0));
        // Should have a new transition entry
        assert!(ks.threat_history().len() >= 2);
    }

    #[tokio::test]
    async fn test_adaptive_policy_evaluation() {
        let mut ks = test_keystore();

        let mut dek_policy = KeyPolicy::default_dek();
        dek_policy.max_usage_count = Some(1000);
        ks.register_policy(dek_policy);

        let id = ks.generate(
            "adaptive-eval-key", KeyType::DataEncrypting,
            Some(PolicyId::new("default-dek")), None,
        ).await.unwrap();
        ks.activate(&id).await.unwrap();

        // Evaluate at Low â€” should be compliant
        let verdict = ks.evaluate_adaptive_policy(&id).await.unwrap();
        assert!(matches!(verdict, PolicyVerdict::Compliant));
    }
}
