//! In-memory [`VaultStore`] for the browser. Ciphertext rows live in a map
//! while unlocked; the host persists the [`KVSnapshot`] to IndexedDB via JS.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::Mutex;

use serde::Serialize;
use uuid::Uuid;
use vault_crypto::{EncryptedItemV1, RecoveryKitWrapV1, RootKeyWrapV1};
use vault_storage::{
    ITEM_MAX_ENCRYPTED_RECORD_BYTES, ITEM_MAX_OBJECTS, KV_SNAPSHOT_SCHEMA_VERSION, KVSnapshot,
    RECOVERY_WRAP_MAX_ENCODED_BYTES, ROOT_WRAP_MAX_ENCODED_BYTES, StorageError, VaultStore,
};

#[derive(Default)]
struct State {
    root_key_wrap: Option<RootKeyWrapV1>,
    recovery_kit_wrap: Option<RecoveryKitWrapV1>,
    items: BTreeMap<Uuid, EncryptedItemV1>,
}

/// A `VaultStore` backed by process memory. Not durable on its own; pair with
/// host-side IndexedDB persistence of the snapshot.
pub struct MemStore {
    state: Mutex<State>,
}

impl MemStore {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
        }
    }

    pub fn from_snapshot(snapshot: KVSnapshot) -> Result<Self, StorageError> {
        if snapshot.schema_version != KV_SNAPSHOT_SCHEMA_VERSION {
            return Err(StorageError::UnsupportedSchemaVersion(i64::from(
                snapshot.schema_version,
            )));
        }
        validate_item_count(snapshot.items.len())?;
        if let Some(wrapped) = snapshot.root_key_wrap.as_ref() {
            validate_encoded_bound(wrapped, ROOT_WRAP_MAX_ENCODED_BYTES)?;
        }
        if let Some(wrapped) = snapshot.recovery_kit_wrap.as_ref() {
            validate_encoded_bound(wrapped, RECOVERY_WRAP_MAX_ENCODED_BYTES)?;
        }

        let mut items = BTreeMap::new();
        for item in snapshot.items {
            validate_encrypted_item(&item)?;
            if items.insert(item.object_id, item).is_some() {
                return Err(StorageError::InconsistentEncryptedRow);
            }
        }
        Ok(Self {
            state: Mutex::new(State {
                root_key_wrap: snapshot.root_key_wrap,
                recovery_kit_wrap: snapshot.recovery_kit_wrap,
                items,
            }),
        })
    }

    pub fn to_snapshot(&self) -> KVSnapshot {
        let state = self.state.lock().expect("memstore poisoned");
        KVSnapshot {
            schema_version: KV_SNAPSHOT_SCHEMA_VERSION,
            root_key_wrap: state.root_key_wrap.clone(),
            recovery_kit_wrap: state.recovery_kit_wrap.clone(),
            items: state.items.values().cloned().collect(),
        }
    }
}

impl Default for MemStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultStore for MemStore {
    fn initialize_root_wrap(&self, wrapped: &RootKeyWrapV1) -> Result<(), StorageError> {
        let mut state = self.state.lock().expect("memstore poisoned");
        if state.root_key_wrap.is_some() {
            return Err(StorageError::AlreadyInitialized);
        }
        state.root_key_wrap = Some(wrapped.clone());
        Ok(())
    }

    fn load_root_wrap(&self) -> Result<RootKeyWrapV1, StorageError> {
        self.state
            .lock()
            .expect("memstore poisoned")
            .root_key_wrap
            .clone()
            .ok_or(StorageError::NotInitialized)
    }

    fn replace_root_wrap(&self, wrapped: &RootKeyWrapV1) -> Result<(), StorageError> {
        let mut state = self.state.lock().expect("memstore poisoned");
        if state.root_key_wrap.is_none() {
            return Err(StorageError::NotInitialized);
        }
        state.root_key_wrap = Some(wrapped.clone());
        Ok(())
    }

    fn is_initialized(&self) -> Result<bool, StorageError> {
        Ok(self
            .state
            .lock()
            .expect("memstore poisoned")
            .root_key_wrap
            .is_some())
    }

    fn store_recovery_wrap(&self, wrapped: &RecoveryKitWrapV1) -> Result<(), StorageError> {
        self.state
            .lock()
            .expect("memstore poisoned")
            .recovery_kit_wrap = Some(wrapped.clone());
        Ok(())
    }

    fn load_recovery_wrap(&self) -> Result<Option<RecoveryKitWrapV1>, StorageError> {
        Ok(self
            .state
            .lock()
            .expect("memstore poisoned")
            .recovery_kit_wrap
            .clone())
    }

    fn has_recovery_wrap(&self) -> Result<bool, StorageError> {
        Ok(self
            .state
            .lock()
            .expect("memstore poisoned")
            .recovery_kit_wrap
            .is_some())
    }

    fn insert_item(&self, item: &EncryptedItemV1) -> Result<(), StorageError> {
        let mut state = self.state.lock().expect("memstore poisoned");
        if state.items.contains_key(&item.object_id) {
            return Err(StorageError::StaleRevision);
        }
        state.items.insert(item.object_id, item.clone());
        Ok(())
    }

    fn update_item_if_revision(
        &self,
        item: &EncryptedItemV1,
        expected_revision: u64,
    ) -> Result<(), StorageError> {
        let mut state = self.state.lock().expect("memstore poisoned");
        let current = state
            .items
            .get(&item.object_id)
            .ok_or(StorageError::ItemNotFound)?;
        if current.revision != expected_revision || item.revision <= current.revision {
            return Err(StorageError::StaleRevision);
        }
        state.items.insert(item.object_id, item.clone());
        Ok(())
    }

    fn update_item_with_history_if_revision(
        &self,
        item: &EncryptedItemV1,
        expected_revision: u64,
    ) -> Result<(), StorageError> {
        // History retention is a SQLite/native-storage concern; the browser store
        // applies the same revision guard without archiving prior revisions.
        self.update_item_if_revision(item, expected_revision)
    }

    fn load_item(&self, object_id: Uuid) -> Result<EncryptedItemV1, StorageError> {
        self.state
            .lock()
            .expect("memstore poisoned")
            .items
            .get(&object_id)
            .cloned()
            .ok_or(StorageError::ItemNotFound)
    }

    fn list_item_ids(&self) -> Result<Vec<Uuid>, StorageError> {
        Ok(self
            .state
            .lock()
            .expect("memstore poisoned")
            .items
            .keys()
            .copied()
            .collect())
    }

    fn validate_record_bounds(&self) -> Result<(), StorageError> {
        let state = self.state.lock().expect("memstore poisoned");
        validate_item_count(state.items.len())?;
        if let Some(wrapped) = state.root_key_wrap.as_ref() {
            validate_encoded_bound(wrapped, ROOT_WRAP_MAX_ENCODED_BYTES)?;
        }
        if let Some(wrapped) = state.recovery_kit_wrap.as_ref() {
            validate_encoded_bound(wrapped, RECOVERY_WRAP_MAX_ENCODED_BYTES)?;
        }
        for item in state.items.values() {
            validate_encrypted_item(item)?;
        }
        Ok(())
    }
}

fn validate_item_count(count: usize) -> Result<(), StorageError> {
    let count = u64::try_from(count).map_err(|_| StorageError::InconsistentEncryptedRow)?;
    if count > ITEM_MAX_OBJECTS {
        return Err(StorageError::InconsistentEncryptedRow);
    }
    Ok(())
}

fn validate_encrypted_item(item: &EncryptedItemV1) -> Result<(), StorageError> {
    i64::try_from(item.revision).map_err(|_| StorageError::RevisionOutOfRange)?;
    validate_encoded_bound(item, ITEM_MAX_ENCRYPTED_RECORD_BYTES)
}

fn validate_encoded_bound<T: Serialize>(value: &T, max_bytes: usize) -> Result<(), StorageError> {
    let mut writer = BoundedWriter::new(max_bytes);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(()),
        Err(_) if writer.exceeded => Err(StorageError::InconsistentEncryptedRow),
        Err(error) => Err(StorageError::Serialization(error)),
    }
}

struct BoundedWriter {
    max_bytes: usize,
    written: usize,
    exceeded: bool,
}

impl BoundedWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            written: 0,
            exceeded: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.max_bytes.saturating_sub(self.written) {
            self.exceeded = true;
            return Err(io::Error::other("encoded record exceeds storage bound"));
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_item(object_id: Uuid) -> EncryptedItemV1 {
        EncryptedItemV1 {
            format_version: 1,
            payload_schema_version: 1,
            algorithm: "XChaCha20Poly1305".to_owned(),
            object_id,
            key_id: Uuid::new_v4(),
            revision: 1,
            key_nonce: [0; 24],
            wrapped_item_key: vec![0; 48],
            payload_nonce: [0; 24],
            ciphertext: vec![0; 32],
        }
    }

    fn sample_root_wrap() -> RootKeyWrapV1 {
        RootKeyWrapV1 {
            format_version: 1,
            algorithm: "XChaCha20Poly1305+Argon2id".to_owned(),
            argon2_memory_kib: 64 * 1024,
            argon2_iterations: 3,
            argon2_parallelism: 1,
            salt: [0; 16],
            nonce: [0; 24],
            ciphertext: vec![0; 48],
        }
    }

    fn sample_recovery_wrap() -> RecoveryKitWrapV1 {
        RecoveryKitWrapV1 {
            format_version: 1,
            algorithm: "XChaCha20Poly1305+HKDF-SHA256".to_owned(),
            salt: [0; 16],
            nonce: [0; 24],
            ciphertext: vec![0; 48],
        }
    }

    fn snapshot_with_items(items: Vec<EncryptedItemV1>) -> KVSnapshot {
        KVSnapshot {
            schema_version: KV_SNAPSHOT_SCHEMA_VERSION,
            root_key_wrap: Some(sample_root_wrap()),
            recovery_kit_wrap: None,
            items,
        }
    }

    #[test]
    fn snapshot_rejects_duplicate_object_ids() {
        let id = Uuid::new_v4();
        let snapshot = snapshot_with_items(vec![sample_item(id), sample_item(id)]);

        assert!(matches!(
            MemStore::from_snapshot(snapshot),
            Err(StorageError::InconsistentEncryptedRow)
        ));
    }

    #[test]
    fn snapshot_rejects_excessive_item_count() {
        let item = sample_item(Uuid::nil());
        let items =
            vec![item; usize::try_from(ITEM_MAX_OBJECTS).expect("item bound fits usize") + 1];
        let snapshot = snapshot_with_items(items);

        assert!(matches!(
            MemStore::from_snapshot(snapshot),
            Err(StorageError::InconsistentEncryptedRow)
        ));
    }

    #[test]
    fn snapshot_rejects_oversized_root_and_recovery_wraps() {
        let mut root = sample_root_wrap();
        root.algorithm = "\0".repeat(ROOT_WRAP_MAX_ENCODED_BYTES / 6 + 1);
        let root_snapshot = KVSnapshot {
            schema_version: KV_SNAPSHOT_SCHEMA_VERSION,
            root_key_wrap: Some(root),
            recovery_kit_wrap: None,
            items: Vec::new(),
        };
        assert!(matches!(
            MemStore::from_snapshot(root_snapshot),
            Err(StorageError::InconsistentEncryptedRow)
        ));

        let mut recovery = sample_recovery_wrap();
        recovery.algorithm = "\0".repeat(RECOVERY_WRAP_MAX_ENCODED_BYTES / 6 + 1);
        let recovery_snapshot = KVSnapshot {
            schema_version: KV_SNAPSHOT_SCHEMA_VERSION,
            root_key_wrap: None,
            recovery_kit_wrap: Some(recovery),
            items: Vec::new(),
        };
        assert!(matches!(
            MemStore::from_snapshot(recovery_snapshot),
            Err(StorageError::InconsistentEncryptedRow)
        ));
    }

    #[test]
    fn snapshot_rejects_oversized_encrypted_item() {
        let mut item = sample_item(Uuid::new_v4());
        item.algorithm = "\0".repeat(ITEM_MAX_ENCRYPTED_RECORD_BYTES / 6 + 1);
        let snapshot = snapshot_with_items(vec![item]);

        assert!(matches!(
            MemStore::from_snapshot(snapshot),
            Err(StorageError::InconsistentEncryptedRow)
        ));
    }

    #[test]
    fn snapshot_rejects_revision_outside_sqlite_storage_range() {
        let mut item = sample_item(Uuid::new_v4());
        item.revision = u64::MAX;
        let snapshot = snapshot_with_items(vec![item]);

        assert!(matches!(
            MemStore::from_snapshot(snapshot),
            Err(StorageError::RevisionOutOfRange)
        ));
    }
}
