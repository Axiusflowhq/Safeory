//! In-memory [`VaultStore`] for the browser. Ciphertext rows live in a map
//! while unlocked; the host persists the [`KVSnapshot`] to IndexedDB via JS.

use std::collections::BTreeMap;
use std::sync::Mutex;

use uuid::Uuid;
use vault_crypto::{EncryptedItemV1, RecoveryKitWrapV1, RootKeyWrapV1};
use vault_storage::{KV_SNAPSHOT_SCHEMA_VERSION, KVSnapshot, StorageError, VaultStore};

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
        let mut items = BTreeMap::new();
        for item in snapshot.items {
            items.insert(item.object_id, item);
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
        // History retention is a desktop-native concern; the browser store
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
        Ok(())
    }
}
