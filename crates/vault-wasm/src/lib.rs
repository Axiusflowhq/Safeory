#![forbid(unsafe_code)]

//! Browser/WASM vault session (ADR 0002/0003).
//!
//! The full crypto core (`vault-crypto`) runs here in WebAssembly. Keys live in
//! WASM linear memory and are zeroized on lock; only ciphertext envelopes and
//! redacted projections cross the JS/TS boundary. Persistence is a
//! [`VaultStore`] over an in-memory map; the host (web app / extension) loads
//! and saves the ciphertext [`KVSnapshot`] to IndexedDB via plain JS, so no
//! Rust storage dependency (rusqlite) is pulled into the WASM build.

mod store;

pub use store::MemStore;

use std::{cell::RefCell, collections::BTreeMap};
use thiserror::Error;
use uuid::Uuid;
use vault_crypto::{
    AccountRootKey, CryptoError, EncryptedItemV1, RecoverySecret, SessionResumeSecret,
    SessionResumeWrapV1, decrypt_item, decrypt_item_state, encrypt_item, encrypt_item_state,
    recovery_secret_matches_root_key, unwrap_root_key, unwrap_root_key_with_recovery_secret,
    unwrap_root_key_with_session_resume_secret, wrap_root_key, wrap_root_key_with_recovery_secret,
    wrap_root_key_with_session_resume_secret,
};
use vault_models::{
    EMERGENCY_CARD_ID, EmergencyCard, VaultItem, VaultItemState, VaultItemValidationError,
    carry_forward_trusted_identity_retirements,
    reminders::{Deadline, deadline_for_item},
    validate_emergency_card, validate_trusted_devices_unpaired,
    validate_trusted_identity_continuity, validate_vault_item,
};
use vault_sharing::{
    PairingChallengeV1, PairingProofV1, PairingVerifierState, SharingError,
    create_pairing_challenge, verify_pairing_proof,
};
use vault_storage::{KV_SNAPSHOT_SCHEMA_VERSION, KVSnapshot, StorageError, VaultStore};

// Password-generation alphabets mirror vault-core::generate_strong_password.
const PASSWORD_LOWERCASE: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const PASSWORD_UPPERCASE: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const PASSWORD_DIGITS: &[u8] = b"23456789";
const PASSWORD_SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}:,.?";
const PASSWORD_ALL: &[u8] =
    b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+[]{}:,.?";
const PASSWORD_MIN_LENGTH: usize = 12;
const PASSWORD_MAX_LENGTH: usize = 128;
const SESSION_RESUME_BINDING_VERSION: u16 = 1;
const SESSION_RESUME_MARKER_ID: Uuid = Uuid::from_bytes([
    0x53, 0x41, 0x46, 0x45, 0x4f, 0x52, 0x59, 0x2d, 0x52, 0x45, 0x53, 0x55, 0x4d, 0x45, 0x00, 0x01,
]);
const SESSION_RESUME_MARKER_TITLE: &str = "Safeory session resume state";
const SESSION_RESUME_MARKER_BODY: &str = "generation";
const MAX_PENDING_TRUSTED_DEVICE_PAIRINGS: usize = 16;

#[derive(Error, Debug)]
pub enum WasmVaultError {
    #[error("cryptographic operation failed")]
    Crypto(#[from] CryptoError),
    #[error("vault storage operation failed")]
    Storage(#[from] StorageError),
    #[error("master passphrase must contain at least 12 characters")]
    PassphraseTooShort,
    #[error("vault is locked")]
    Locked,
    #[error("vault snapshot has an unsupported schema version {0}")]
    UnsupportedSnapshotVersion(u32),
    #[error("item was not found")]
    ItemNotFound,
    #[error("item revision is exhausted")]
    RevisionExhausted,
    #[error("generated password length must be between 12 and 128 characters")]
    InvalidGeneratedPasswordLength,
    #[error("secure random generation failed")]
    RandomGeneration,
    #[error("emergency card record is inconsistent")]
    InconsistentEmergencyCard,
    #[error("vault item exceeds supported size limits")]
    ItemTooLarge,
    #[error("legacy disposition is not supported for this item")]
    InvalidLegacyDisposition,
    #[error("account closure plans are supported only for credential records")]
    InvalidAccountClosurePlan,
    #[error("trusted-person access policy is invalid")]
    InvalidAccessPolicy,
    #[error("trusted-person principal is invalid")]
    InvalidTrustedPrincipal,
    #[error("reserved vault record must be changed through its dedicated operation")]
    ReservedSystemItem,
    #[error("trusted-device pairing operation failed")]
    Sharing(#[from] SharingError),
    #[error("trusted-device pairing challenge is missing or already consumed")]
    PairingChallengeUnavailable,
    #[error("attachment references are managed by attachment operations")]
    AttachmentReferencesManagedSeparately,
    #[error("session resume credential is unavailable or stale")]
    InvalidSessionResume,
}

#[derive(serde::Serialize)]
struct SessionResumeSnapshotBinding<'a> {
    version: u16,
    root_key_wrap: &'a vault_crypto::RootKeyWrapV1,
    generation_marker: &'a EncryptedItemV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeadlineEntry {
    pub deadline: Deadline,
    pub revision: u64,
}

/// An unlocked (or locked) browser vault. The root key is held only while
/// unlocked and is dropped (zeroized) on `lock`.
pub struct BrowserVault {
    store: MemStore,
    root_key: Option<AccountRootKey>,
    pending_pairings: RefCell<BTreeMap<Uuid, PendingTrustedDevicePairing>>,
}

struct PendingTrustedDevicePairing {
    package: PairingChallengeV1,
    state: PairingVerifierState,
}

impl BrowserVault {
    /// Start from a fresh, empty store (new vault).
    pub fn new_empty() -> Self {
        Self {
            store: MemStore::new(),
            root_key: None,
            pending_pairings: RefCell::new(BTreeMap::new()),
        }
    }

    /// Load from a ciphertext snapshot previously produced by `to_snapshot`.
    pub fn from_snapshot(snapshot: KVSnapshot) -> Result<Self, WasmVaultError> {
        if snapshot.schema_version != KV_SNAPSHOT_SCHEMA_VERSION {
            return Err(WasmVaultError::UnsupportedSnapshotVersion(
                snapshot.schema_version,
            ));
        }
        Ok(Self {
            store: MemStore::from_snapshot(snapshot)?,
            root_key: None,
            pending_pairings: RefCell::new(BTreeMap::new()),
        })
    }

    pub fn is_initialized(&self) -> bool {
        self.store.is_initialized().unwrap_or(false)
    }

    /// Create a new vault in an empty store and unlock it.
    pub fn create(&mut self, passphrase: &str) -> Result<(), WasmVaultError> {
        if passphrase.chars().count() < 12 {
            return Err(WasmVaultError::PassphraseTooShort);
        }
        let root_key = AccountRootKey::generate()?;
        let wrapped = wrap_root_key(passphrase, &root_key)?;
        self.store.initialize_root_wrap(&wrapped)?;
        self.root_key = Some(root_key);
        Ok(())
    }

    /// Unlock an initialized store with the master passphrase.
    pub fn unlock(&mut self, passphrase: &str) -> Result<(), WasmVaultError> {
        let wrapped = self.store.load_root_wrap()?;
        let root_key = unwrap_root_key(passphrase, &wrapped)?;
        self.root_key = Some(root_key);
        Ok(())
    }

    /// Lock the vault, dropping (zeroizing) the root key.
    pub fn lock(&mut self) {
        self.root_key = None;
        self.pending_pairings.get_mut().clear();
    }

    pub fn is_unlocked(&self) -> bool {
        self.root_key.is_some()
    }

    /// Create a fresh, short-lived browser reload credential for the current
    /// unlocked root key. The returned secret is not the master passphrase or
    /// recovery secret and must be cleared by the host on explicit lock.
    pub fn create_session_resume(&self) -> Result<(String, SessionResumeWrapV1), WasmVaultError> {
        let secret = SessionResumeSecret::generate()?;
        let root_key = self.root_key()?;
        let (current, next_marker) = self.prepare_next_session_resume_marker(root_key)?;
        let snapshot_binding = self.session_resume_snapshot_binding_for(&next_marker)?;
        let wrapped =
            wrap_root_key_with_session_resume_secret(&secret, root_key, &snapshot_binding)?;
        match current {
            Some(current) => self
                .store
                .update_item_if_revision(&next_marker, current.revision)?,
            None => self.store.insert_item(&next_marker)?,
        }
        Ok((secret.to_hex(), wrapped))
    }

    /// Resume an initialized browser vault from a session-scoped credential.
    /// Authentication failure leaves the vault locked.
    pub fn unlock_with_session_resume(
        &mut self,
        secret: &SessionResumeSecret,
        wrapped: &SessionResumeWrapV1,
    ) -> Result<(), WasmVaultError> {
        let snapshot_binding = self.session_resume_snapshot_binding()?;
        let root_key =
            unwrap_root_key_with_session_resume_secret(secret, wrapped, &snapshot_binding)?;
        self.validate_session_resume_marker(&root_key)?;
        self.root_key = Some(root_key);
        Ok(())
    }

    fn session_resume_snapshot_binding(&self) -> Result<Vec<u8>, WasmVaultError> {
        let marker =
            self.store
                .load_item(SESSION_RESUME_MARKER_ID)
                .map_err(|error| match error {
                    StorageError::ItemNotFound => WasmVaultError::InvalidSessionResume,
                    other => WasmVaultError::Storage(other),
                })?;
        self.session_resume_snapshot_binding_for(&marker)
    }

    fn session_resume_snapshot_binding_for(
        &self,
        marker: &EncryptedItemV1,
    ) -> Result<Vec<u8>, WasmVaultError> {
        let root_wrap = self.store.load_root_wrap()?;
        let binding = SessionResumeSnapshotBinding {
            version: SESSION_RESUME_BINDING_VERSION,
            root_key_wrap: &root_wrap,
            generation_marker: marker,
        };
        Ok(serde_json::to_vec(&binding).map_err(StorageError::from)?)
    }

    fn prepare_next_session_resume_marker(
        &self,
        root_key: &AccountRootKey,
    ) -> Result<(Option<EncryptedItemV1>, EncryptedItemV1), WasmVaultError> {
        let current = match self.store.load_item(SESSION_RESUME_MARKER_ID) {
            Ok(current) => {
                self.validate_session_resume_marker_record(root_key, &current)?;
                Some(current)
            }
            Err(StorageError::ItemNotFound) => None,
            Err(error) => return Err(error.into()),
        };
        let revision = match current.as_ref() {
            Some(current) => current
                .revision
                .checked_add(1)
                .ok_or(WasmVaultError::RevisionExhausted)?,
            None => 0,
        };
        let marker = session_resume_marker_item();
        let encrypted = encrypt_item(root_key, &marker, revision)?;
        Ok((current, encrypted))
    }

    fn validate_session_resume_marker(
        &self,
        root_key: &AccountRootKey,
    ) -> Result<(), WasmVaultError> {
        let marker =
            self.store
                .load_item(SESSION_RESUME_MARKER_ID)
                .map_err(|error| match error {
                    StorageError::ItemNotFound => WasmVaultError::InvalidSessionResume,
                    other => WasmVaultError::Storage(other),
                })?;
        self.validate_session_resume_marker_record(root_key, &marker)
    }

    fn validate_session_resume_marker_record(
        &self,
        root_key: &AccountRootKey,
        marker: &EncryptedItemV1,
    ) -> Result<(), WasmVaultError> {
        let item =
            decrypt_item(root_key, marker).map_err(|_| WasmVaultError::InvalidSessionResume)?;
        if item != session_resume_marker_item() {
            return Err(WasmVaultError::InvalidSessionResume);
        }
        Ok(())
    }

    fn root_key(&self) -> Result<&AccountRootKey, WasmVaultError> {
        self.root_key.as_ref().ok_or(WasmVaultError::Locked)
    }

    /// Insert a new item at revision 0.
    pub fn put_item(&self, item: &VaultItem) -> Result<(), WasmVaultError> {
        ensure_mutable_user_item_id(item.id)?;
        if !item.attachments.is_empty() {
            return Err(WasmVaultError::AttachmentReferencesManagedSeparately);
        }
        validate_item(item)?;
        let encrypted = encrypt_item(self.root_key()?, item, 0)?;
        self.store.insert_item(&encrypted)?;
        Ok(())
    }

    /// Fetch and decrypt an active item by id.
    pub fn get_item(&self, id: Uuid) -> Result<VaultItem, WasmVaultError> {
        ensure_user_item_id(id)?;
        let encrypted = self.store.load_item(id)?;
        Ok(decrypt_item(self.root_key()?, &encrypted)?)
    }

    /// List all active items (decrypted) with their revisions.
    pub fn list_items(&self) -> Result<Vec<(VaultItem, u64)>, WasmVaultError> {
        let root = self.root_key()?;
        let mut out = Vec::new();
        for id in self.store.list_item_ids()? {
            if id == EMERGENCY_CARD_ID || id == SESSION_RESUME_MARKER_ID {
                continue; // the singleton card is hidden from normal lists (matches vault-core)
            }
            let encrypted = self.store.load_item(id)?;
            if let VaultItemState::Active { item } = decrypt_item_state(root, &encrypted)? {
                out.push((item, encrypted.revision));
            }
        }
        Ok(out)
    }

    /// Derive redacted deadline metadata while keeping full item plaintext
    /// inside WASM. Active records are decrypted and projected one at a time.
    pub fn list_deadlines(
        &self,
        today: (i32, u32, u32),
    ) -> Result<Vec<DeadlineEntry>, WasmVaultError> {
        let root = self.root_key()?;
        let mut out = Vec::new();
        for id in self.store.list_item_ids()? {
            if id == EMERGENCY_CARD_ID || id == SESSION_RESUME_MARKER_ID {
                continue;
            }
            let encrypted = self.store.load_item(id)?;
            if let VaultItemState::Active { item } = decrypt_item_state(root, &encrypted)?
                && let Some(deadline) = deadline_for_item(&item, today)
            {
                out.push(DeadlineEntry {
                    deadline,
                    revision: encrypted.revision,
                });
            }
        }
        out.sort_by(|a, b| {
            a.deadline
                .days_until
                .cmp(&b.deadline.days_until)
                .then_with(|| a.deadline.title.cmp(&b.deadline.title))
                .then_with(|| a.deadline.item_id.cmp(&b.deadline.item_id))
        });
        Ok(out)
    }

    /// Update an item with stale-revision protection; returns the new revision.
    pub fn update_item(
        &self,
        item: &VaultItem,
        expected_revision: u64,
    ) -> Result<u64, WasmVaultError> {
        ensure_mutable_user_item_id(item.id)?;
        validate_item(item)?;
        let current = self.store.load_item(item.id)?;
        if current.revision != expected_revision {
            return Err(WasmVaultError::Storage(StorageError::StaleRevision));
        }
        let current_item = match decrypt_item_state(self.root_key()?, &current)? {
            VaultItemState::Active { item } => item,
            VaultItemState::Trashed { .. } | VaultItemState::Tombstone { .. } => {
                return Err(WasmVaultError::ItemNotFound);
            }
        };
        if item.attachments != current_item.attachments {
            return Err(WasmVaultError::AttachmentReferencesManagedSeparately);
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(WasmVaultError::RevisionExhausted)?;
        let encrypted = encrypt_item(self.root_key()?, item, revision)?;
        self.store
            .update_item_if_revision(&encrypted, expected_revision)?;
        Ok(revision)
    }

    /// Move an item to trash (encrypted state change), returning new revision.
    pub fn trash_item(
        &self,
        id: Uuid,
        expected_revision: u64,
        deleted_at_ms: u64,
    ) -> Result<u64, WasmVaultError> {
        ensure_mutable_user_item_id(id)?;
        let item = self.get_item(id)?;
        let current = self.store.load_item(id)?;
        if current.revision != expected_revision {
            return Err(WasmVaultError::Storage(StorageError::StaleRevision));
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(WasmVaultError::RevisionExhausted)?;
        let encrypted = encrypt_item_state(
            self.root_key()?,
            &VaultItemState::Trashed {
                item,
                deleted_at_ms,
            },
            revision,
        )?;
        self.store
            .update_item_if_revision(&encrypted, expected_revision)?;
        Ok(revision)
    }

    /// Fetch the Emergency Card singleton, if present. Mirrors vault-core:
    /// returns None when the record is absent or not active.
    pub fn get_emergency_card(&self) -> Result<Option<(EmergencyCard, u64)>, WasmVaultError> {
        let root = self.root_key()?; // auth check first: a locked vault must not reveal presence
        let encrypted = match self.store.load_item(EMERGENCY_CARD_ID) {
            Ok(value) => value,
            Err(StorageError::ItemNotFound) => return Ok(None),
            Err(other) => return Err(other.into()),
        };
        match decrypt_item_state(root, &encrypted)? {
            VaultItemState::Active { item } => {
                let card = item
                    .parse_emergency_card()
                    .ok_or(WasmVaultError::InconsistentEmergencyCard)?;
                Ok(Some((card, encrypted.revision)))
            }
            VaultItemState::Trashed { .. } | VaultItemState::Tombstone { .. } => Ok(None),
        }
    }

    /// Set the Emergency Card singleton (create at revision 1, else CAS update).
    pub fn set_emergency_card(&self, card: &EmergencyCard) -> Result<u64, WasmVaultError> {
        validate_emergency_card(card).map_err(map_validation_error)?;
        let root = self.root_key()?; // auth check first
        match self.store.load_item(EMERGENCY_CARD_ID) {
            Err(StorageError::ItemNotFound) => {
                validate_trusted_devices_unpaired(card).map_err(map_validation_error)?;
                let item = VaultItem::emergency_card(card);
                let encrypted = encrypt_item(root, &item, 1)?;
                self.store.insert_item(&encrypted)?;
                self.pending_pairings.borrow_mut().clear();
                Ok(1)
            }
            Ok(current) => {
                let VaultItemState::Active { mut item } = decrypt_item_state(root, &current)?
                else {
                    return Err(WasmVaultError::ItemNotFound);
                };
                let previous_card = item
                    .parse_emergency_card()
                    .ok_or(WasmVaultError::InvalidTrustedPrincipal)?;
                let mut next_card = card.clone();
                carry_forward_trusted_identity_retirements(&previous_card, &mut next_card);
                validate_emergency_card(&next_card).map_err(map_validation_error)?;
                validate_trusted_identity_continuity(&previous_card, &next_card)
                    .map_err(map_validation_error)?;
                let replacement = VaultItem::emergency_card(&next_card);
                item.fields.insert(
                    "card".to_owned(),
                    replacement
                        .fields
                        .get("card")
                        .expect("emergency card constructor always stores card content")
                        .clone(),
                );
                validate_item(&item)?;
                let revision = current
                    .revision
                    .checked_add(1)
                    .ok_or(WasmVaultError::RevisionExhausted)?;
                let encrypted = encrypt_item(root, &item, revision)?;
                self.store
                    .update_item_if_revision(&encrypted, current.revision)?;
                self.pending_pairings.borrow_mut().clear();
                Ok(revision)
            }
            Err(other) => Err(other.into()),
        }
    }

    pub fn create_trusted_device_pairing_challenge(
        &self,
        principal_id: Uuid,
        device_id: Uuid,
    ) -> Result<PairingChallengeV1, WasmVaultError> {
        let (card, _) = self
            .get_emergency_card()?
            .ok_or(WasmVaultError::PairingChallengeUnavailable)?;
        let device = card
            .principals
            .iter()
            .find(|principal| principal.id == principal_id)
            .and_then(|principal| {
                principal
                    .devices
                    .iter()
                    .find(|device| device.id == device_id)
            })
            .ok_or(WasmVaultError::PairingChallengeUnavailable)?;
        if device.signing_public_key_hex.is_some() {
            return Err(WasmVaultError::InvalidTrustedPrincipal);
        }
        let encryption_public = decode_hex_32(&device.encryption_public_key_hex)
            .ok_or(WasmVaultError::InvalidTrustedPrincipal)?;
        let (package, state) =
            create_pairing_challenge(principal_id, device_id, &encryption_public)?;
        let mut pending = self.pending_pairings.borrow_mut();
        pending.retain(|_, existing| {
            existing.package.principal_id != principal_id || existing.package.device_id != device_id
        });
        if pending.len() >= MAX_PENDING_TRUSTED_DEVICE_PAIRINGS {
            return Err(WasmVaultError::PairingChallengeUnavailable);
        }
        pending.insert(
            package.request_id,
            PendingTrustedDevicePairing {
                package: package.clone(),
                state,
            },
        );
        Ok(package)
    }

    pub fn complete_trusted_device_pairing(
        &self,
        proof: &PairingProofV1,
    ) -> Result<u64, WasmVaultError> {
        let pending = self
            .pending_pairings
            .borrow_mut()
            .remove(&proof.request_id)
            .ok_or(WasmVaultError::PairingChallengeUnavailable)?;
        let signing_public = verify_pairing_proof(&pending.package, &pending.state, proof)?;
        let root = self.root_key()?;
        let current = self.store.load_item(EMERGENCY_CARD_ID)?;
        let VaultItemState::Active { mut item } = decrypt_item_state(root, &current)? else {
            return Err(WasmVaultError::ItemNotFound);
        };
        let mut card = item
            .parse_emergency_card()
            .ok_or(WasmVaultError::InvalidTrustedPrincipal)?;
        let device = card
            .principals
            .iter_mut()
            .find(|principal| principal.id == proof.principal_id)
            .and_then(|principal| {
                principal
                    .devices
                    .iter_mut()
                    .find(|device| device.id == proof.device_id)
            })
            .ok_or(WasmVaultError::PairingChallengeUnavailable)?;
        if device.signing_public_key_hex.is_some()
            || decode_hex_32(&device.encryption_public_key_hex) != Some(proof.encryption_public)
        {
            return Err(WasmVaultError::InvalidTrustedPrincipal);
        }
        device.signing_public_key_hex = Some(encode_hex_32(&signing_public));
        validate_emergency_card(&card).map_err(map_validation_error)?;
        let replacement = VaultItem::emergency_card(&card);
        item.fields.insert(
            "card".to_owned(),
            replacement
                .fields
                .get("card")
                .expect("emergency card constructor always stores card content")
                .clone(),
        );
        validate_item(&item)?;
        let revision = current
            .revision
            .checked_add(1)
            .ok_or(WasmVaultError::RevisionExhausted)?;
        let encrypted = encrypt_item(root, &item, revision)?;
        self.store
            .update_item_if_revision(&encrypted, current.revision)?;
        Ok(revision)
    }

    #[cfg(test)]
    fn set_emergency_card_access_policy(
        &self,
        policy: vault_models::AccessPolicy,
        expected_revision: u64,
    ) -> Result<u64, WasmVaultError> {
        let root = self.root_key()?;
        let current = self.store.load_item(EMERGENCY_CARD_ID)?;
        if current.revision != expected_revision {
            return Err(WasmVaultError::Storage(StorageError::StaleRevision));
        }
        let VaultItemState::Active { mut item } = decrypt_item_state(root, &current)? else {
            return Err(WasmVaultError::ItemNotFound);
        };
        item.access_policy = policy;
        let card = item
            .parse_emergency_card()
            .ok_or(WasmVaultError::InconsistentEmergencyCard)?;
        validate_emergency_card(&card).map_err(map_validation_error)?;
        validate_item(&item)?;
        let revision = expected_revision
            .checked_add(1)
            .ok_or(WasmVaultError::RevisionExhausted)?;
        let encrypted = encrypt_item(root, &item, revision)?;
        self.store
            .update_item_if_revision(&encrypted, expected_revision)?;
        Ok(revision)
    }

    /// Install a recovery kit wrap for the current root key.
    pub fn install_recovery_kit(&self, secret: &RecoverySecret) -> Result<(), WasmVaultError> {
        let wrapped = wrap_root_key_with_recovery_secret(secret, self.root_key()?)?;
        self.store.store_recovery_wrap(&wrapped)?;
        Ok(())
    }

    pub fn has_recovery_kit(&self) -> Result<bool, WasmVaultError> {
        Ok(self.store.has_recovery_wrap()?)
    }

    /// Verify a recovery secret against the installed kit (read-only).
    pub fn verify_recovery_kit(&self, secret: &RecoverySecret) -> Result<bool, WasmVaultError> {
        let Some(wrapped) = self.store.load_recovery_wrap()? else {
            return Ok(false);
        };
        Ok(recovery_secret_matches_root_key(
            secret,
            &wrapped,
            self.root_key()?,
        )?)
    }

    /// Unlock using a recovery kit secret instead of the master passphrase.
    pub fn unlock_with_recovery_kit(
        &mut self,
        secret: &RecoverySecret,
    ) -> Result<(), WasmVaultError> {
        let wrapped = self
            .store
            .load_recovery_wrap()?
            .ok_or(StorageError::NotInitialized)?;
        let root_key = unwrap_root_key_with_recovery_secret(secret, &wrapped)?;
        self.root_key = Some(root_key);
        Ok(())
    }

    /// Generate a fresh recovery secret (hex-encoded for the printable kit).
    pub fn generate_recovery_secret() -> Result<String, WasmVaultError> {
        Ok(RecoverySecret::generate()?.to_hex())
    }

    /// Export the current ciphertext store as a snapshot for persistence.
    pub fn to_snapshot(&self) -> KVSnapshot {
        self.store.to_snapshot()
    }
}

fn session_resume_marker_item() -> VaultItem {
    let mut item = VaultItem::secure_note(SESSION_RESUME_MARKER_TITLE, SESSION_RESUME_MARKER_BODY);
    item.id = SESSION_RESUME_MARKER_ID;
    item
}

fn ensure_user_item_id(id: Uuid) -> Result<(), WasmVaultError> {
    if id == SESSION_RESUME_MARKER_ID {
        return Err(WasmVaultError::ItemNotFound);
    }
    Ok(())
}

fn ensure_mutable_user_item_id(id: Uuid) -> Result<(), WasmVaultError> {
    ensure_user_item_id(id)?;
    if id == EMERGENCY_CARD_ID {
        return Err(WasmVaultError::ReservedSystemItem);
    }
    Ok(())
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let encoded = value.as_bytes();
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let high = hex_nibble(encoded[index * 2])?;
        let low = hex_nibble(encoded[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Some(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_hex_32(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn validate_item(item: &VaultItem) -> Result<(), WasmVaultError> {
    validate_vault_item(item).map_err(map_validation_error)
}

fn map_validation_error(error: VaultItemValidationError) -> WasmVaultError {
    match error {
        VaultItemValidationError::InvalidLegacyDisposition => {
            WasmVaultError::InvalidLegacyDisposition
        }
        VaultItemValidationError::InvalidAccountClosurePlan => {
            WasmVaultError::InvalidAccountClosurePlan
        }
        VaultItemValidationError::InvalidAccessPolicy => WasmVaultError::InvalidAccessPolicy,
        VaultItemValidationError::InvalidTrustedPrincipal => {
            WasmVaultError::InvalidTrustedPrincipal
        }
        VaultItemValidationError::TooLarge => WasmVaultError::ItemTooLarge,
    }
}

/// Generate a strong password; mirrors `vault-core::generate_strong_password`
/// (>= 12 chars, one of each class, Fisher-Yates shuffle over a CSPRNG).
pub fn generate_strong_password(length: usize) -> Result<String, WasmVaultError> {
    if !(PASSWORD_MIN_LENGTH..=PASSWORD_MAX_LENGTH).contains(&length) {
        return Err(WasmVaultError::InvalidGeneratedPasswordLength);
    }
    let mut source = RandomSource::new();
    let mut password = Vec::with_capacity(length);
    password.push(sample_from(&mut source, PASSWORD_LOWERCASE)?);
    password.push(sample_from(&mut source, PASSWORD_UPPERCASE)?);
    password.push(sample_from(&mut source, PASSWORD_DIGITS)?);
    password.push(sample_from(&mut source, PASSWORD_SYMBOLS)?);
    while password.len() < length {
        password.push(sample_from(&mut source, PASSWORD_ALL)?);
    }
    for index in (1..password.len()).rev() {
        let other = sample_index(&mut source, index + 1)?;
        password.swap(index, other);
    }
    String::from_utf8(password).map_err(|_| WasmVaultError::RandomGeneration)
}

struct RandomSource {
    bytes: [u8; 64],
    position: usize,
}

impl RandomSource {
    fn new() -> Self {
        Self {
            bytes: [0; 64],
            position: 64,
        }
    }

    fn next(&mut self) -> Result<u8, WasmVaultError> {
        if self.position == self.bytes.len() {
            getrandom::fill(&mut self.bytes).map_err(|_| WasmVaultError::RandomGeneration)?;
            self.position = 0;
        }
        let byte = self.bytes[self.position];
        self.position += 1;
        Ok(byte)
    }
}

fn sample_from(source: &mut RandomSource, alphabet: &[u8]) -> Result<u8, WasmVaultError> {
    Ok(alphabet[sample_index(source, alphabet.len())?])
}

fn sample_index(source: &mut RandomSource, upper_bound: usize) -> Result<usize, WasmVaultError> {
    debug_assert!((1..=256).contains(&upper_bound));
    let acceptance_limit = 256 - (256 % upper_bound);
    loop {
        let byte = usize::from(source.next()?);
        if byte < acceptance_limit {
            return Ok(byte % upper_bound);
        }
    }
}

impl Default for BrowserVault {
    fn default() -> Self {
        Self::new_empty()
    }
}

mod bindings;

#[cfg(test)]
mod tests {
    use super::*;
    use vault_models::{MAX_FIELD_VALUE_CHARS, MAX_ITEM_NOTES_CHARS, VaultItem};

    fn sample_item(title: &str) -> VaultItem {
        VaultItem::secure_note(title, "body")
    }

    #[test]
    fn create_unlock_put_get_lock_round_trip() {
        let mut vault = BrowserVault::new_empty();
        assert!(!vault.is_initialized());
        vault.create("correct horse battery").expect("create");
        assert!(vault.is_initialized());
        assert!(vault.is_unlocked());

        let item = sample_item("Bank password");
        let id = item.id;
        vault.put_item(&item).expect("put");

        let listed = vault.list_items().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0.id, id);

        let fetched = vault.get_item(id).expect("get");
        assert_eq!(fetched.title, "Bank password");

        vault.lock();
        assert!(!vault.is_unlocked());
        assert!(vault.get_item(id).is_err());
    }

    #[test]
    fn snapshot_persists_ciphertext_and_reopens() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let item = sample_item("Insurance policy");
        let id = item.id;
        vault.put_item(&item).expect("put");
        let snapshot = vault.to_snapshot();

        // Snapshot must be ciphertext-bearing (has a root wrap + one item),
        // and must reopen and decrypt with the passphrase after a fresh load.
        assert!(snapshot.root_key_wrap.is_some());
        assert_eq!(snapshot.items.len(), 1);

        let mut restored = BrowserVault::from_snapshot(snapshot).expect("from_snapshot");
        assert!(
            restored.get_item(id).is_err(),
            "locked vault must not decrypt"
        );
        restored.unlock("correct horse battery").expect("unlock");
        assert_eq!(
            restored.get_item(id).expect("get").title,
            "Insurance policy"
        );
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let snapshot = vault.to_snapshot();
        let mut restored = BrowserVault::from_snapshot(snapshot).expect("from_snapshot");
        assert!(restored.unlock("wrong passphrase!!").is_err());
        assert!(!restored.is_unlocked());
    }

    #[test]
    fn deadlines_are_sorted_redacted_candidates_with_receipt_status_semantics() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");

        let mut document =
            VaultItem::document("Passport", "P-SECRET", "Gov", "2026-09-25", "private note");
        let document_id = document.id;
        vault.put_item(&document).expect("put document");
        document.title = "Passport".to_owned();
        assert_eq!(vault.update_item(&document, 0).expect("revise document"), 1);

        let insurance =
            VaultItem::insurance("Policy", "Insurer", "Home", "N-SECRET", "2026-09-20", "");
        vault.put_item(&insurance).expect("put insurance");

        let refund = VaultItem::receipt(
            "Refund",
            "Store",
            "2026-09-01",
            "100",
            "USD",
            "R-SECRET",
            "refund_pending",
            "2026-09-21",
            "2026-09-19",
            "",
        );
        vault.put_item(&refund).expect("put refund");

        let completed = VaultItem::receipt(
            "Completed",
            "Store",
            "2026-09-01",
            "100",
            "USD",
            "R-DONE",
            "refunded",
            "2026-09-18",
            "2026-09-19",
            "",
        );
        vault.put_item(&completed).expect("put completed receipt");

        let deadlines = vault.list_deadlines((2026, 9, 19)).expect("list deadlines");
        assert_eq!(deadlines.len(), 3);
        assert_eq!(
            deadlines
                .iter()
                .map(|entry| entry.deadline.title.as_str())
                .collect::<Vec<_>>(),
            vec!["Refund", "Policy", "Passport"]
        );
        assert_eq!(deadlines[0].deadline.label, "Refund due");
        assert_eq!(deadlines[0].deadline.days_until, 0);
        let revised = deadlines
            .iter()
            .find(|entry| entry.deadline.item_id == document_id)
            .expect("document deadline");
        assert_eq!(revised.revision, 1);
    }

    #[test]
    fn deadlines_require_unlock_and_omit_trashed_records() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let item = VaultItem::document("Old passport", "P", "Gov", "2026-09-19", "");
        let id = item.id;
        vault.put_item(&item).expect("put");
        vault.trash_item(id, 0, 1).expect("trash");
        assert!(
            vault
                .list_deadlines((2026, 9, 19))
                .expect("list")
                .is_empty()
        );

        vault.lock();
        assert!(matches!(
            vault.list_deadlines((2026, 9, 19)),
            Err(WasmVaultError::Locked)
        ));
    }

    #[test]
    fn stale_revision_update_is_rejected() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let item = sample_item("Vehicle");
        let id = item.id;
        vault.put_item(&item).expect("put");

        let mut edited = vault.get_item(id).expect("get");
        edited.title = "Vehicle (updated)".to_string();
        let rev = vault.update_item(&edited, 0).expect("update");
        assert_eq!(rev, 1);

        // Replaying the same update at the old revision must fail.
        assert!(vault.update_item(&edited, 0).is_err());
    }

    #[test]
    fn short_passphrase_is_rejected() {
        let mut vault = BrowserVault::new_empty();
        assert!(vault.create("short").is_err());
        assert!(!vault.is_initialized());
    }

    #[test]
    fn emergency_card_round_trip_and_revision() {
        use vault_models::EmergencyCard;
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");

        // Absent initially.
        assert!(vault.get_emergency_card().expect("get").is_none());

        // Create at revision 1.
        let mut card = EmergencyCard::empty();
        card.instructions = "Call my sister".to_string();
        card.principals.push(vault_models::TrustedPrincipal {
            id: Uuid::new_v4(),
            name: "Ada".to_owned(),
            relation: "Sibling".to_owned(),
            devices: vec![vault_models::TrustedDevice {
                id: Uuid::new_v4(),
                label: "Phone".to_owned(),
                encryption_public_key_hex:
                    "3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                signing_public_key_hex: None,
            }],
        });
        let rev = vault.set_emergency_card(&card).expect("set");
        assert_eq!(rev, 1);

        // Read back.
        let (loaded, rev) = vault.get_emergency_card().expect("get").expect("present");
        assert_eq!(loaded.instructions, "Call my sister");
        assert_eq!(loaded.principals, card.principals);
        assert_eq!(rev, 1);

        // CAS update bumps revision.
        let mut updated = loaded;
        updated.instructions = "Call my lawyer".to_string();
        let rev2 = vault.set_emergency_card(&updated).expect("update");
        assert_eq!(rev2, 2);
        let (loaded2, _) = vault.get_emergency_card().expect("get").expect("present");
        assert_eq!(loaded2.instructions, "Call my lawyer");

        let mut rebound = loaded2.clone();
        rebound.principals[0].devices[0].encryption_public_key_hex =
            "4444444444444444444444444444444444444444444444444444444444444444".to_owned();
        assert!(matches!(
            vault.set_emergency_card(&rebound),
            Err(WasmVaultError::InvalidTrustedPrincipal)
        ));
        let (still_bound, rev_after_reject) =
            vault.get_emergency_card().expect("get").expect("present");
        assert_eq!(rev_after_reject, 2);
        assert_eq!(still_bound, loaded2);

        let removed_principal = still_bound.principals[0].clone();
        let mut removed = still_bound.clone();
        removed.principals.clear();
        let rev3 = vault
            .set_emergency_card(&removed)
            .expect("remove principal and retire its ids");
        assert_eq!(rev3, 3);
        let (retired, _) = vault.get_emergency_card().expect("get").expect("present");
        assert!(
            retired
                .retired_principal_ids
                .contains(&removed_principal.id)
        );
        assert!(
            retired
                .retired_device_ids
                .contains(&removed_principal.devices[0].id)
        );

        let mut revived = retired.clone();
        revived.principals.push(removed_principal);
        assert!(matches!(
            vault.set_emergency_card(&revived),
            Err(WasmVaultError::InvalidTrustedPrincipal)
        ));
        let (_, rev_after_revive_reject) =
            vault.get_emergency_card().expect("get").expect("present");
        assert_eq!(rev_after_revive_reject, 3);

        // The singleton must not appear in the normal item list.
        assert!(vault.list_items().expect("list").is_empty());
    }

    #[test]
    fn emergency_card_reserved_id_rejects_generic_mutations() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let card = EmergencyCard::empty();
        let raw = VaultItem::emergency_card(&card);

        assert!(matches!(
            vault.put_item(&raw),
            Err(WasmVaultError::ReservedSystemItem)
        ));
        assert_eq!(vault.set_emergency_card(&card).expect("create card"), 1);

        let mut generic = vault
            .get_item(EMERGENCY_CARD_ID)
            .expect("load emergency singleton");
        generic.fields.insert("card".to_owned(), "{}".to_owned());
        assert!(matches!(
            vault.update_item(&generic, 1),
            Err(WasmVaultError::ReservedSystemItem)
        ));
        assert!(matches!(
            vault.trash_item(EMERGENCY_CARD_ID, 1, 42),
            Err(WasmVaultError::ReservedSystemItem)
        ));

        let (stored, revision) = vault
            .get_emergency_card()
            .expect("load card")
            .expect("card present");
        assert_eq!(revision, 1);
        assert_eq!(stored, card);
    }

    #[test]
    fn trusted_device_pairing_is_persisted_and_lock_cancels_pending_challenges() {
        use vault_sharing::{DeviceKeyPair, DeviceSigningKeyPair, answer_pairing_challenge};

        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let principal_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let encryption_key = DeviceKeyPair::generate().expect("recipient key");
        let signing_key = DeviceSigningKeyPair::generate().expect("signing key");
        let mut card = EmergencyCard::empty();
        card.principals.push(vault_models::TrustedPrincipal {
            id: principal_id,
            name: "Ada".to_owned(),
            relation: "Sibling".to_owned(),
            devices: vec![vault_models::TrustedDevice {
                id: device_id,
                label: "Phone".to_owned(),
                encryption_public_key_hex: encode_hex_32(&encryption_key.public_bytes()),
                signing_public_key_hex: None,
            }],
        });
        assert_eq!(vault.set_emergency_card(&card).expect("store card"), 1);

        let cancelled = vault
            .create_trusted_device_pairing_challenge(principal_id, device_id)
            .expect("create cancelled challenge");
        let cancelled_proof = answer_pairing_challenge(&cancelled, &encryption_key, &signing_key)
            .expect("answer cancelled challenge");
        vault.lock();
        vault.unlock("correct horse battery").expect("unlock");
        assert!(matches!(
            vault.complete_trusted_device_pairing(&cancelled_proof),
            Err(WasmVaultError::PairingChallengeUnavailable)
        ));

        let generic_cancelled = vault
            .create_trusted_device_pairing_challenge(principal_id, device_id)
            .expect("create generic-cancelled challenge");
        let generic_cancelled_proof =
            answer_pairing_challenge(&generic_cancelled, &encryption_key, &signing_key)
                .expect("answer generic-cancelled challenge");
        let (mut edited_card, _) = vault
            .get_emergency_card()
            .expect("load card")
            .expect("card present");
        edited_card.instructions = "Generic edit cancels pending pairing".to_owned();
        assert_eq!(
            vault
                .set_emergency_card(&edited_card)
                .expect("generic card edit"),
            2
        );
        assert!(matches!(
            vault.complete_trusted_device_pairing(&generic_cancelled_proof),
            Err(WasmVaultError::PairingChallengeUnavailable)
        ));

        let challenge = vault
            .create_trusted_device_pairing_challenge(principal_id, device_id)
            .expect("create challenge");
        let proof = answer_pairing_challenge(&challenge, &encryption_key, &signing_key)
            .expect("answer challenge");
        assert_eq!(
            vault
                .complete_trusted_device_pairing(&proof)
                .expect("complete pairing"),
            3
        );
        let (stored, revision) = vault
            .get_emergency_card()
            .expect("load card")
            .expect("card present");
        assert_eq!(revision, 3);
        assert_eq!(
            stored.principals[0].devices[0].signing_public_key_hex,
            Some(encode_hex_32(&signing_key.public_bytes()))
        );

        let signing_public_key_hex = encode_hex_32(&signing_key.public_bytes());
        let mut revoked = stored;
        revoked.principals[0].devices.clear();
        assert_eq!(
            vault
                .set_emergency_card(&revoked)
                .expect("revoke paired device"),
            4
        );
        let (revoked, _) = vault
            .get_emergency_card()
            .expect("load revoked card")
            .expect("card present");
        assert!(
            revoked
                .retired_signing_public_key_hexes
                .contains(&signing_public_key_hex)
        );

        let replacement_device_id = Uuid::new_v4();
        let replacement_encryption_key = DeviceKeyPair::generate().expect("replacement key");
        let mut replacement = revoked;
        replacement.principals[0]
            .devices
            .push(vault_models::TrustedDevice {
                id: replacement_device_id,
                label: "Replacement phone".to_owned(),
                encryption_public_key_hex: encode_hex_32(
                    &replacement_encryption_key.public_bytes(),
                ),
                signing_public_key_hex: None,
            });
        assert_eq!(
            vault
                .set_emergency_card(&replacement)
                .expect("add replacement device"),
            5
        );
        let replacement_challenge = vault
            .create_trusted_device_pairing_challenge(principal_id, replacement_device_id)
            .expect("create replacement-device challenge");
        let reused_signing_proof = answer_pairing_challenge(
            &replacement_challenge,
            &replacement_encryption_key,
            &signing_key,
        )
        .expect("answer with retired signing key");
        assert!(matches!(
            vault.complete_trusted_device_pairing(&reused_signing_proof),
            Err(WasmVaultError::InvalidTrustedPrincipal)
        ));
        let (unchanged, revision) = vault
            .get_emergency_card()
            .expect("load unchanged card")
            .expect("card present");
        assert_eq!(revision, 5);
        assert!(
            unchanged.principals[0].devices[0]
                .signing_public_key_hex
                .is_none()
        );
    }

    #[test]
    fn emergency_card_update_preserves_hidden_access_policy() {
        use vault_models::{AccessPolicy, EmergencyCard, EmergencyContact};

        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");

        let mut card = EmergencyCard::empty();
        card.instructions = "Original instructions".to_owned();
        assert_eq!(vault.set_emergency_card(&card).expect("create card"), 1);

        let mut policy = AccessPolicy::new(false);
        policy.set_private_forever();
        assert_eq!(
            vault
                .set_emergency_card_access_policy(policy.clone(), 1)
                .expect("set hidden policy"),
            2
        );

        card.contacts.push(EmergencyContact {
            name: "Ada".to_owned(),
            relation: "Sibling".to_owned(),
            phone: "+1-555-0100".to_owned(),
            email: "ada@example.test".to_owned(),
            notes: "Call first".to_owned(),
        });
        card.instructions = "Updated instructions".to_owned();
        assert_eq!(vault.set_emergency_card(&card).expect("update card"), 3);

        let stored = vault
            .get_item(EMERGENCY_CARD_ID)
            .expect("reload emergency item");
        assert_eq!(stored.access_policy, policy);
        assert_eq!(stored.parse_emergency_card(), Some(card));
    }

    #[test]
    fn emergency_card_requires_unlock() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        vault.lock();
        assert!(vault.get_emergency_card().is_err());
        assert!(
            vault
                .set_emergency_card(&vault_models::EmergencyCard::empty())
                .is_err()
        );
    }

    #[test]
    fn recovery_kit_lifecycle_and_unlock() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let item = sample_item("Secret doc");
        let id = item.id;
        vault.put_item(&item).expect("put");

        assert!(!vault.has_recovery_kit().expect("has"));

        let secret_hex = BrowserVault::generate_recovery_secret().expect("gen secret");
        let secret = RecoverySecret::from_hex(&secret_hex).expect("parse secret");
        vault.install_recovery_kit(&secret).expect("install");
        assert!(vault.has_recovery_kit().expect("has"));
        assert!(vault.verify_recovery_kit(&secret).expect("verify"));

        // Wrong secret must not verify.
        let wrong = RecoverySecret::generate().expect("wrong");
        assert!(!vault.verify_recovery_kit(&wrong).expect("verify wrong"));

        // Persist, then unlock a fresh instance via the recovery kit.
        let snapshot = vault.to_snapshot();
        let mut restored = BrowserVault::from_snapshot(snapshot).expect("from_snapshot");
        assert!(restored.unlock_with_recovery_kit(&secret).is_ok());
        assert_eq!(restored.get_item(id).expect("get").title, "Secret doc");
    }

    #[test]
    fn recovery_unlock_fails_closed_on_wrong_secret() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let secret = RecoverySecret::generate().expect("gen");
        vault.install_recovery_kit(&secret).expect("install");
        let snapshot = vault.to_snapshot();

        let mut restored = BrowserVault::from_snapshot(snapshot).expect("from_snapshot");
        let wrong = RecoverySecret::generate().expect("wrong");
        assert!(restored.unlock_with_recovery_kit(&wrong).is_err());
        assert!(!restored.is_unlocked());
    }

    #[test]
    fn session_resume_round_trip_survives_snapshot_reload() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let item = sample_item("Reload me");
        let id = item.id;
        vault.put_item(&item).expect("put");
        let (secret_hex, wrapped) = vault.create_session_resume().expect("resume material");
        let snapshot = vault.to_snapshot();

        let mut restored = BrowserVault::from_snapshot(snapshot).expect("restore");
        assert!(!restored.is_unlocked());
        let secret = SessionResumeSecret::from_hex(&secret_hex).expect("secret");
        restored
            .unlock_with_session_resume(&secret, &wrapped)
            .expect("resume");
        assert_eq!(restored.get_item(id).expect("get").title, "Reload me");
        assert_eq!(restored.list_items().expect("list").len(), 1);
    }

    #[test]
    fn session_resume_rotation_rejects_previous_credential() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let (first_secret_hex, first_wrap) = vault
            .create_session_resume()
            .expect("first resume material");
        let first_snapshot = vault.to_snapshot();

        let mut resumed = BrowserVault::from_snapshot(first_snapshot).expect("restore first");
        let first_secret = SessionResumeSecret::from_hex(&first_secret_hex).expect("first secret");
        resumed
            .unlock_with_session_resume(&first_secret, &first_wrap)
            .expect("first resume");

        let (second_secret_hex, second_wrap) = resumed
            .create_session_resume()
            .expect("rotated resume material");
        resumed.lock();
        assert!(
            resumed
                .unlock_with_session_resume(&first_secret, &first_wrap)
                .is_err(),
            "a consumed credential must fail after rotation"
        );
        assert!(!resumed.is_unlocked());

        let second_secret =
            SessionResumeSecret::from_hex(&second_secret_hex).expect("second secret");
        resumed
            .unlock_with_session_resume(&second_secret, &second_wrap)
            .expect("rotated credential resumes");
    }

    #[test]
    fn updated_snapshot_rejects_cross_tab_reinserted_stale_resume_payload() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let (first_secret_hex, first_wrap) = vault
            .create_session_resume()
            .expect("first resume material");
        let first_snapshot = vault.to_snapshot();

        let mut resumed = BrowserVault::from_snapshot(first_snapshot).expect("restore first");
        let first_secret = SessionResumeSecret::from_hex(&first_secret_hex).expect("first secret");
        resumed
            .unlock_with_session_resume(&first_secret, &first_wrap)
            .expect("first resume");
        let (second_secret_hex, second_wrap) = resumed
            .create_session_resume()
            .expect("rotated resume material");
        let updated_snapshot_json =
            serde_json::to_vec(&resumed.to_snapshot()).expect("serialize updated snapshot");

        let updated_snapshot =
            serde_json::from_slice(&updated_snapshot_json).expect("parse updated snapshot");
        let mut other_tab = BrowserVault::from_snapshot(updated_snapshot).expect("other tab");
        assert!(
            other_tab
                .unlock_with_session_resume(&first_secret, &first_wrap)
                .is_err(),
            "reinserted stale payload must not unlock an updated snapshot"
        );
        assert!(!other_tab.is_unlocked());

        let latest_snapshot =
            serde_json::from_slice(&updated_snapshot_json).expect("parse latest snapshot");
        let mut latest_tab = BrowserVault::from_snapshot(latest_snapshot).expect("latest tab");
        let second_secret =
            SessionResumeSecret::from_hex(&second_secret_hex).expect("second secret");
        latest_tab
            .unlock_with_session_resume(&second_secret, &second_wrap)
            .expect("current payload unlocks updated snapshot");
    }

    #[test]
    fn legacy_snapshot_without_generation_requires_normal_unlock_before_reissue() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let legacy_snapshot = vault.to_snapshot();

        let mut restored = BrowserVault::from_snapshot(legacy_snapshot).expect("restore legacy");
        let random_secret = SessionResumeSecret::generate().expect("random secret");
        let (_, unrelated_wrap) = vault.create_session_resume().expect("unrelated wrap");
        assert!(
            restored
                .unlock_with_session_resume(&random_secret, &unrelated_wrap)
                .is_err()
        );
        assert!(!restored.is_unlocked());

        restored
            .unlock("correct horse battery")
            .expect("normal unlock after upgrade");
        let (secret_hex, wrapped) = restored
            .create_session_resume()
            .expect("issue generation-bound credential");
        let upgraded_snapshot = restored.to_snapshot();
        let mut reloaded = BrowserVault::from_snapshot(upgraded_snapshot).expect("reload upgraded");
        let secret = SessionResumeSecret::from_hex(&secret_hex).expect("resume secret");
        reloaded
            .unlock_with_session_resume(&secret, &wrapped)
            .expect("upgraded resume works");
    }

    #[test]
    fn session_resume_wrong_secret_fails_closed() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let (_, wrapped) = vault.create_session_resume().expect("resume material");
        let snapshot = vault.to_snapshot();

        let mut restored = BrowserVault::from_snapshot(snapshot).expect("restore");
        let wrong = SessionResumeSecret::generate().expect("wrong secret");
        assert!(
            restored
                .unlock_with_session_resume(&wrong, &wrapped)
                .is_err()
        );
        assert!(!restored.is_unlocked());
    }

    #[test]
    fn session_resume_from_replaced_vault_fails_closed() {
        let mut old_vault = BrowserVault::new_empty();
        old_vault
            .create("correct horse battery")
            .expect("create old");
        let (secret_hex, wrapped) = old_vault.create_session_resume().expect("resume material");

        let mut replacement = BrowserVault::new_empty();
        replacement
            .create("different horse battery")
            .expect("create replacement");
        let replacement_snapshot = replacement.to_snapshot();
        let mut restored =
            BrowserVault::from_snapshot(replacement_snapshot).expect("restore replacement");
        let secret = SessionResumeSecret::from_hex(&secret_hex).expect("secret");

        assert!(
            restored
                .unlock_with_session_resume(&secret, &wrapped)
                .is_err()
        );
        assert!(!restored.is_unlocked());
    }

    #[test]
    fn generated_password_meets_class_and_length_rules() {
        let pw = generate_strong_password(24).expect("gen");
        assert_eq!(pw.chars().count(), 24);
        let has = |set: &[u8]| pw.bytes().any(|b| set.contains(&b));
        assert!(has(PASSWORD_LOWERCASE));
        assert!(has(PASSWORD_UPPERCASE));
        assert!(has(PASSWORD_DIGITS));
        assert!(has(PASSWORD_SYMBOLS));

        assert!(generate_strong_password(11).is_err());
        assert!(generate_strong_password(129).is_err());
    }

    #[test]
    fn browser_rejects_oversized_items_before_persistence() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let mut item = sample_item("Oversized");
        item.fields.insert(
            "body".to_owned(),
            "x".repeat(MAX_FIELD_VALUE_CHARS.saturating_add(1)),
        );

        assert!(matches!(
            vault.put_item(&item),
            Err(WasmVaultError::ItemTooLarge)
        ));
        assert!(vault.list_items().expect("list").is_empty());
    }

    #[test]
    fn browser_rejects_client_managed_attachment_references() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let mut item = sample_item("Attachment owner");
        item.attachments.push(Uuid::new_v4());

        assert!(matches!(
            vault.put_item(&item),
            Err(WasmVaultError::AttachmentReferencesManagedSeparately)
        ));
        assert!(vault.list_items().expect("list").is_empty());
    }

    #[test]
    fn browser_rejects_oversized_emergency_card() {
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let mut card = EmergencyCard::empty();
        card.instructions = "x".repeat(MAX_ITEM_NOTES_CHARS.saturating_add(1));

        assert!(matches!(
            vault.set_emergency_card(&card),
            Err(WasmVaultError::ItemTooLarge)
        ));
        assert!(vault.get_emergency_card().expect("card").is_none());
    }
}
