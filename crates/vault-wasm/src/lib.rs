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

use thiserror::Error;
use uuid::Uuid;
use vault_crypto::{
    AccountRootKey, CryptoError, RecoverySecret, decrypt_item, decrypt_item_state, encrypt_item,
    encrypt_item_state, recovery_secret_matches_root_key, unwrap_root_key,
    unwrap_root_key_with_recovery_secret, wrap_root_key, wrap_root_key_with_recovery_secret,
};
use vault_models::{
    EMERGENCY_CARD_ID, EmergencyCard, VaultItem, VaultItemState, VaultItemValidationError,
    reminders::{Deadline, deadline_for_item},
    validate_emergency_card, validate_vault_item,
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
    #[error("attachment references are managed by attachment operations")]
    AttachmentReferencesManagedSeparately,
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
}

impl BrowserVault {
    /// Start from a fresh, empty store (new vault).
    pub fn new_empty() -> Self {
        Self {
            store: MemStore::new(),
            root_key: None,
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
    }

    pub fn is_unlocked(&self) -> bool {
        self.root_key.is_some()
    }

    fn root_key(&self) -> Result<&AccountRootKey, WasmVaultError> {
        self.root_key.as_ref().ok_or(WasmVaultError::Locked)
    }

    /// Insert a new item at revision 0.
    pub fn put_item(&self, item: &VaultItem) -> Result<(), WasmVaultError> {
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
        let encrypted = self.store.load_item(id)?;
        Ok(decrypt_item(self.root_key()?, &encrypted)?)
    }

    /// List all active items (decrypted) with their revisions.
    pub fn list_items(&self) -> Result<Vec<(VaultItem, u64)>, WasmVaultError> {
        let root = self.root_key()?;
        let mut out = Vec::new();
        for id in self.store.list_item_ids()? {
            if id == EMERGENCY_CARD_ID {
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
            if id == EMERGENCY_CARD_ID {
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
        let item = VaultItem::emergency_card(card);
        match self.store.load_item(EMERGENCY_CARD_ID) {
            Err(StorageError::ItemNotFound) => {
                let encrypted = encrypt_item(root, &item, 1)?;
                self.store.insert_item(&encrypted)?;
                Ok(1)
            }
            Ok(current) => {
                let revision = current
                    .revision
                    .checked_add(1)
                    .ok_or(WasmVaultError::RevisionExhausted)?;
                let encrypted = encrypt_item(root, &item, revision)?;
                self.store
                    .update_item_if_revision(&encrypted, current.revision)?;
                Ok(revision)
            }
            Err(other) => Err(other.into()),
        }
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
        let rev = vault.set_emergency_card(&card).expect("set");
        assert_eq!(rev, 1);

        // Read back.
        let (loaded, rev) = vault.get_emergency_card().expect("get").expect("present");
        assert_eq!(loaded.instructions, "Call my sister");
        assert_eq!(rev, 1);

        // CAS update bumps revision.
        let mut updated = loaded;
        updated.instructions = "Call my lawyer".to_string();
        let rev2 = vault.set_emergency_card(&updated).expect("update");
        assert_eq!(rev2, 2);
        let (loaded2, _) = vault.get_emergency_card().expect("get").expect("present");
        assert_eq!(loaded2.instructions, "Call my lawyer");

        // The singleton must not appear in the normal item list.
        assert!(vault.list_items().expect("list").is_empty());
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
