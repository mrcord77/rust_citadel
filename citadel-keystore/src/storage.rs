//! Storage backends: where key metadata and material live.

use crate::error::KeystoreError;
use crate::types::{KeyId, KeyMetadata, KeyState};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

// ---------------------------------------------------------------------------
// Storage trait
// ---------------------------------------------------------------------------

/// Backend for persisting key metadata.
///
/// Implement this for your infrastructure:
/// - InMemoryBackend (testing)
/// - FileBackend (development)
/// - Your database (production)
/// - HSM wrapper (compliance)
pub trait StorageBackend: Send + Sync {
    fn get(&self, id: &KeyId) -> Result<Option<KeyMetadata>, KeystoreError>;
    fn put(&self, meta: &KeyMetadata) -> Result<(), KeystoreError>;
    fn delete(&self, id: &KeyId) -> Result<(), KeystoreError>;
    fn list(&self) -> Result<Vec<KeyMetadata>, KeystoreError>;
    fn list_by_state(&self, state: KeyState) -> Result<Vec<KeyMetadata>, KeystoreError>;
    fn list_by_parent(&self, parent_id: &KeyId) -> Result<Vec<KeyMetadata>, KeystoreError>;
}

// ---------------------------------------------------------------------------
// In-memory backend
// ---------------------------------------------------------------------------

/// In-memory storage (for testing and ephemeral use).
pub struct InMemoryBackend {
    keys: RwLock<HashMap<String, KeyMetadata>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryBackend {
    fn get(&self, id: &KeyId) -> Result<Option<KeyMetadata>, KeystoreError> {
        let keys = self.keys.read().unwrap();
        Ok(keys.get(id.as_str()).cloned())
    }

    fn put(&self, meta: &KeyMetadata) -> Result<(), KeystoreError> {
        let mut keys = self.keys.write().unwrap();
        keys.insert(meta.id.as_str().to_string(), meta.clone());
        Ok(())
    }

    fn delete(&self, id: &KeyId) -> Result<(), KeystoreError> {
        let mut keys = self.keys.write().unwrap();
        keys.remove(id.as_str());
        Ok(())
    }

    fn list(&self) -> Result<Vec<KeyMetadata>, KeystoreError> {
        let keys = self.keys.read().unwrap();
        Ok(keys.values().cloned().collect())
    }

    fn list_by_state(&self, state: KeyState) -> Result<Vec<KeyMetadata>, KeystoreError> {
        let keys = self.keys.read().unwrap();
        Ok(keys.values().filter(|k| k.state == state).cloned().collect())
    }

    fn list_by_parent(&self, parent_id: &KeyId) -> Result<Vec<KeyMetadata>, KeystoreError> {
        let keys = self.keys.read().unwrap();
        Ok(keys
            .values()
            .filter(|k| k.parent_id.as_ref() == Some(parent_id))
            .cloned()
            .collect())
    }
}

// ---------------------------------------------------------------------------
// File backend
// ---------------------------------------------------------------------------

/// File-based storage (one JSON file per key).
///
/// Directory layout:
/// ```text
/// keys/
///   {key_id}.json
/// ```
pub struct FileBackend {
    dir: PathBuf,
}

impl FileBackend {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, KeystoreError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .map_err(|e| KeystoreError::StorageError(format!("create dir: {}", e)))?;
        Ok(Self { dir })
    }

    fn key_path(&self, id: &KeyId) -> PathBuf {
        self.dir.join(format!("{}.json", id.as_str()))
    }

    fn read_key_file(&self, path: &Path) -> Result<KeyMetadata, KeystoreError> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| KeystoreError::StorageError(format!("read: {}", e)))?;
        serde_json::from_str(&data)
            .map_err(|e| KeystoreError::StorageError(format!("parse: {}", e)))
    }
}

impl StorageBackend for FileBackend {
    fn get(&self, id: &KeyId) -> Result<Option<KeyMetadata>, KeystoreError> {
        let path = self.key_path(id);
        if !path.exists() {
            return Ok(None);
        }
        self.read_key_file(&path).map(Some)
    }

    fn put(&self, meta: &KeyMetadata) -> Result<(), KeystoreError> {
        let path = self.key_path(&meta.id);
        let json = serde_json::to_string_pretty(meta)
            .map_err(|e| KeystoreError::StorageError(format!("serialize: {}", e)))?;
        // Atomic write: write to temp, then rename
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &json)
            .map_err(|e| KeystoreError::StorageError(format!("write: {}", e)))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| KeystoreError::StorageError(format!("rename: {}", e)))?;
        Ok(())
    }

    fn delete(&self, id: &KeyId) -> Result<(), KeystoreError> {
        let path = self.key_path(id);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| KeystoreError::StorageError(format!("delete: {}", e)))?;
        }
        Ok(())
    }

    fn list(&self) -> Result<Vec<KeyMetadata>, KeystoreError> {
        let mut keys = Vec::new();
        let entries = std::fs::read_dir(&self.dir)
            .map_err(|e| KeystoreError::StorageError(format!("readdir: {}", e)))?;
        for entry in entries {
            let entry = entry.map_err(|e| KeystoreError::StorageError(format!("entry: {}", e)))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                keys.push(self.read_key_file(&path)?);
            }
        }
        Ok(keys)
    }

    fn list_by_state(&self, state: KeyState) -> Result<Vec<KeyMetadata>, KeystoreError> {
        Ok(self.list()?.into_iter().filter(|k| k.state == state).collect())
    }

    fn list_by_parent(&self, parent_id: &KeyId) -> Result<Vec<KeyMetadata>, KeystoreError> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|k| k.parent_id.as_ref() == Some(parent_id))
            .collect())
    }
}
