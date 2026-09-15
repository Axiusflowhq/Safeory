#![forbid(unsafe_code)]

pub mod reminders;

use std::path::Path;
use thiserror::Error;
use uuid::Uuid;
use vault_crypto::{
    AccountRootKey, CryptoError, RecoverySecret, decrypt_item_state, encrypt_item,
    encrypt_item_state, unwrap_root_key, unwrap_root_key_with_recovery_secret, wrap_root_key,
    wrap_root_key_with_recovery_secret,
};
use vault_models::{EMERGENCY_CARD_ID, EmergencyCard, VaultItem, VaultItemState};
use vault_storage::{StorageError, VaultStorage};

const PASSWORD_LOWERCASE: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const PASSWORD_UPPERCASE: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const PASSWORD_DIGITS: &[u8] = b"23456789";
const PASSWORD_SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}:,.?";
const PASSWORD_ALL: &[u8] =
    b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+[]{}:,.?";
const PASSWORD_MIN_LENGTH: usize = 12;
const PASSWORD_MAX_LENGTH: usize = 128;
const MAX_ITEM_TITLE_CHARS: usize = 256;
const MAX_ITEM_FIELDS: usize = 32;
const MAX_ITEM_LINKS: usize = 64;
const MAX_FIELD_NAME_CHARS: usize = 64;
const MAX_FIELD_VALUE_CHARS: usize = 100_000;
const MAX_ITEM_NOTES_CHARS: usize = 100_000;
const MAX_CARD_ITEMS: usize = 128;
const MAX_CARD_CONTACTS: usize = 32;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("cryptographic operation failed")]
    Crypto(#[from] CryptoError),
    #[error("vault storage operation failed")]
    Storage(#[from] StorageError),
    #[error("master passphrase must contain at least 12 characters")]
    PassphraseTooShort,
    #[error("item revision is exhausted")]
    RevisionExhausted,
    #[error("generated password length must be between 12 and 128 characters")]
    InvalidGeneratedPasswordLength,
    #[error("secure random generation failed")]
    RandomGeneration,
    #[error("vault item exceeds supported size limits")]
    ItemTooLarge,
    #[error("vault item is not active")]
    ItemNotActive,
    #[error("vault item is not in trash")]
    ItemNotTrashed,
}

pub fn generate_strong_password(length: usize) -> Result<String, VaultError> {
    if !(PASSWORD_MIN_LENGTH..=PASSWORD_MAX_LENGTH).contains(&length) {
        return Err(VaultError::InvalidGeneratedPasswordLength);
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

    String::from_utf8(password).map_err(|_| VaultError::RandomGeneration)
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

    fn next(&mut self) -> Result<u8, VaultError> {
        if self.position == self.bytes.len() {
            getrandom::fill(&mut self.bytes).map_err(|_| VaultError::RandomGeneration)?;
            self.position = 0;
        }
        let byte = self.bytes[self.position];
        self.position += 1;
        Ok(byte)
    }
}

fn sample_from(source: &mut RandomSource, alphabet: &[u8]) -> Result<u8, VaultError> {
    Ok(alphabet[sample_index(source, alphabet.len())?])
}

fn sample_index(source: &mut RandomSource, upper_bound: usize) -> Result<usize, VaultError> {
    debug_assert!((1..=256).contains(&upper_bound));
    let acceptance_limit = 256 - (256 % upper_bound);
    loop {
        let byte = usize::from(source.next()?);
        if byte < acceptance_limit {
            return Ok(byte % upper_bound);
        }
    }
}

pub struct VaultSession {
    storage: VaultStorage,
    root_key: AccountRootKey,
}

impl VaultSession {
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, VaultError> {
        if passphrase.chars().count() < 12 {
            return Err(VaultError::PassphraseTooShort);
        }
        let storage = VaultStorage::open(path)?;
        let root_key = AccountRootKey::generate()?;
        let wrapped = wrap_root_key(passphrase, &root_key)?;
        storage.initialize_root_wrap(&wrapped)?;
        Ok(Self { storage, root_key })
    }

    pub fn unlock(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, VaultError> {
        let storage = VaultStorage::open(path)?;
        let wrapped = storage.load_root_wrap()?;
        let root_key = unwrap_root_key(passphrase, &wrapped)?;
        Ok(Self { storage, root_key })
    }

    pub fn put_item(&self, item: &VaultItem, revision: u64) -> Result<(), VaultError> {
        validate_item(item)?;
        let encrypted = encrypt_item(&self.root_key, item, revision)?;
        self.storage.upsert_item(&encrypted)?;
        Ok(())
    }

    pub fn update_item(&self, item: &VaultItem, expected_revision: u64) -> Result<u64, VaultError> {
        validate_item(item)?;
        let (state, current_revision) = self.get_state_with_revision(item.id)?;
        if current_revision != expected_revision {
            return Err(VaultError::Storage(StorageError::StaleRevision));
        }
        if !matches!(state, VaultItemState::Active { .. }) {
            return Err(VaultError::ItemNotActive);
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(VaultError::RevisionExhausted)?;
        let encrypted = encrypt_item(&self.root_key, item, revision)?;
        self.storage
            .update_item_if_revision(&encrypted, expected_revision)?;
        Ok(revision)
    }

    pub fn get_item(&self, id: Uuid) -> Result<VaultItem, VaultError> {
        Ok(self.get_item_with_revision(id)?.0)
    }

    pub fn get_item_with_revision(&self, id: Uuid) -> Result<(VaultItem, u64), VaultError> {
        let (state, revision) = self.get_state_with_revision(id)?;
        match state {
            VaultItemState::Active { item } => Ok((item, revision)),
            VaultItemState::Trashed { .. } | VaultItemState::Tombstone { .. } => {
                Err(VaultError::ItemNotActive)
            }
        }
    }

    pub fn list_items(&self) -> Result<Vec<VaultItem>, VaultError> {
        Ok(self
            .list_items_with_revisions()?
            .into_iter()
            .map(|(item, _revision)| item)
            .collect())
    }

    pub fn list_items_with_revisions(&self) -> Result<Vec<(VaultItem, u64)>, VaultError> {
        let mut items = Vec::new();
        for id in self.storage.list_item_ids()? {
            let (state, revision) = self.get_state_with_revision(id)?;
            if let VaultItemState::Active { item } = state {
                items.push((item, revision));
            }
        }
        Ok(items)
    }

    pub fn trash_item(
        &self,
        id: Uuid,
        expected_revision: u64,
        deleted_at_ms: u64,
    ) -> Result<u64, VaultError> {
        let (state, current_revision) = self.get_state_with_revision(id)?;
        if current_revision != expected_revision {
            return Err(VaultError::Storage(StorageError::StaleRevision));
        }
        let VaultItemState::Active { item } = state else {
            return Err(VaultError::ItemNotActive);
        };
        let revision = expected_revision
            .checked_add(1)
            .ok_or(VaultError::RevisionExhausted)?;
        let encrypted = encrypt_item_state(
            &self.root_key,
            &VaultItemState::Trashed {
                item,
                deleted_at_ms,
            },
            revision,
        )?;
        self.storage
            .update_item_if_revision(&encrypted, expected_revision)?;
        Ok(revision)
    }

    pub fn list_trashed_items_with_revisions(
        &self,
    ) -> Result<Vec<(VaultItem, u64, u64)>, VaultError> {
        let mut items = Vec::new();
        for id in self.storage.list_item_ids()? {
            let (state, revision) = self.get_state_with_revision(id)?;
            if let VaultItemState::Trashed {
                item,
                deleted_at_ms,
            } = state
            {
                items.push((item, revision, deleted_at_ms));
            }
        }
        items.sort_by(|left, right| {
            right
                .2
                .cmp(&left.2)
                .then_with(|| left.0.id.cmp(&right.0.id))
        });
        Ok(items)
    }

    pub fn restore_item(&self, id: Uuid, expected_revision: u64) -> Result<u64, VaultError> {
        let (state, current_revision) = self.get_state_with_revision(id)?;
        if current_revision != expected_revision {
            return Err(VaultError::Storage(StorageError::StaleRevision));
        }
        let VaultItemState::Trashed { item, .. } = state else {
            return Err(VaultError::ItemNotTrashed);
        };
        validate_item(&item)?;
        let revision = expected_revision
            .checked_add(1)
            .ok_or(VaultError::RevisionExhausted)?;
        let encrypted =
            encrypt_item_state(&self.root_key, &VaultItemState::Active { item }, revision)?;
        self.storage
            .update_item_if_revision(&encrypted, expected_revision)?;
        Ok(revision)
    }

    pub fn purge_item(&self, id: Uuid, expected_revision: u64) -> Result<u64, VaultError> {
        let (state, current_revision) = self.get_state_with_revision(id)?;
        if current_revision != expected_revision {
            return Err(VaultError::Storage(StorageError::StaleRevision));
        }
        let VaultItemState::Trashed { deleted_at_ms, .. } = state else {
            return Err(VaultError::ItemNotTrashed);
        };
        let revision = expected_revision
            .checked_add(1)
            .ok_or(VaultError::RevisionExhausted)?;
        let encrypted = encrypt_item_state(
            &self.root_key,
            &VaultItemState::Tombstone { id, deleted_at_ms },
            revision,
        )?;
        self.storage
            .update_item_if_revision(&encrypted, expected_revision)?;
        Ok(revision)
    }

    pub fn is_initialized(path: impl AsRef<Path>) -> Result<bool, VaultError> {
        let storage = VaultStorage::open(path)?;
        Ok(storage.is_initialized()?)
    }

    pub fn change_passphrase(&self, new_passphrase: &str) -> Result<(), VaultError> {
        if new_passphrase.chars().count() < 12 {
            return Err(VaultError::PassphraseTooShort);
        }
        let wrapped = wrap_root_key(new_passphrase, &self.root_key)?;
        self.storage.replace_root_wrap(&wrapped)?;
        Ok(())
    }

    pub fn get_emergency_card(&self) -> Result<Option<(EmergencyCard, u64)>, VaultError> {
        let (state, revision) = match self.get_state_with_revision(EMERGENCY_CARD_ID) {
            Ok(value) => value,
            Err(VaultError::Storage(StorageError::ItemNotFound)) => return Ok(None),
            Err(other) => return Err(other),
        };
        match state {
            VaultItemState::Active { item } => {
                let Some(card) = item.parse_emergency_card() else {
                    return Err(VaultError::Storage(StorageError::InconsistentEncryptedRow));
                };
                Ok(Some((card, revision)))
            }
            VaultItemState::Trashed { .. } | VaultItemState::Tombstone { .. } => Ok(None),
        }
    }

    pub fn set_emergency_card(&self, card: &EmergencyCard) -> Result<u64, VaultError> {
        validate_emergency_card(card)?;
        let item = VaultItem::emergency_card(card);
        match self.get_state_with_revision(EMERGENCY_CARD_ID) {
            Err(VaultError::Storage(StorageError::ItemNotFound)) => {
                self.put_item(&item, 1)?;
                Ok(1)
            }
            Ok((_, revision)) => self.update_item(&item, revision),
            Err(other) => Err(other),
        }
    }

    pub fn install_recovery_kit(&self, secret: &RecoverySecret) -> Result<(), VaultError> {
        let wrapped = wrap_root_key_with_recovery_secret(secret, &self.root_key)?;
        self.storage.store_recovery_wrap(&wrapped)?;
        Ok(())
    }

    pub fn has_recovery_kit(&self) -> Result<bool, VaultError> {
        Ok(self.storage.has_recovery_wrap()?)
    }

    pub fn unlock_with_recovery_kit(
        path: impl AsRef<Path>,
        secret: &RecoverySecret,
    ) -> Result<Self, VaultError> {
        let storage = VaultStorage::open(path)?;
        let wrapped = storage
            .load_recovery_wrap()?
            .ok_or(StorageError::NotInitialized)?;
        let root_key = unwrap_root_key_with_recovery_secret(secret, &wrapped)?;
        Ok(Self { storage, root_key })
    }

    fn get_state_with_revision(&self, id: Uuid) -> Result<(VaultItemState, u64), VaultError> {
        let encrypted = self.storage.load_item(id)?;
        let revision = encrypted.revision;
        Ok((decrypt_item_state(&self.root_key, &encrypted)?, revision))
    }
}

fn validate_item(item: &VaultItem) -> Result<(), VaultError> {
    if item.title.chars().count() > MAX_ITEM_TITLE_CHARS
        || item.fields.len() > MAX_ITEM_FIELDS
        || item.links.len() > MAX_ITEM_LINKS
        || item.fields.iter().any(|(name, value)| {
            name.chars().count() > MAX_FIELD_NAME_CHARS
                || value.chars().count() > MAX_FIELD_VALUE_CHARS
        })
        || item
            .notes
            .as_ref()
            .is_some_and(|notes| notes.chars().count() > MAX_ITEM_NOTES_CHARS)
    {
        return Err(VaultError::ItemTooLarge);
    }
    Ok(())
}

fn validate_emergency_card(card: &EmergencyCard) -> Result<(), VaultError> {
    if card.selected_item_ids.len() > MAX_CARD_ITEMS
        || card.contacts.len() > MAX_CARD_CONTACTS
        || card.instructions.chars().count() > MAX_ITEM_NOTES_CHARS
    {
        return Err(VaultError::ItemTooLarge);
    }
    for contact in &card.contacts {
        if contact.name.chars().count() > MAX_ITEM_TITLE_CHARS
            || contact.relation.chars().count() > MAX_ITEM_TITLE_CHARS
            || contact.phone.chars().count() > MAX_ITEM_TITLE_CHARS
            || contact.notes.chars().count() > MAX_ITEM_NOTES_CHARS
        {
            return Err(VaultError::ItemTooLarge);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::tempdir;

    const TEST_PASSPHRASE: &str = "a deliberately long local test passphrase";
    const TEST_SECRET_TITLE: &str = "Executor-only details";
    const TEST_SECRET_BODY: &str = "The document code is 8M2Z-PRIVATE";

    #[test]
    fn generated_password_uses_all_required_character_classes() {
        let password = generate_strong_password(20).expect("generate password");
        assert_eq!(password.len(), 20);
        assert!(
            password
                .bytes()
                .any(|byte| PASSWORD_LOWERCASE.contains(&byte))
        );
        assert!(
            password
                .bytes()
                .any(|byte| PASSWORD_UPPERCASE.contains(&byte))
        );
        assert!(password.bytes().any(|byte| PASSWORD_DIGITS.contains(&byte)));
        assert!(
            password
                .bytes()
                .any(|byte| PASSWORD_SYMBOLS.contains(&byte))
        );
    }

    #[test]
    fn generated_password_rejects_unbounded_lengths() {
        assert!(matches!(
            generate_strong_password(PASSWORD_MIN_LENGTH - 1),
            Err(VaultError::InvalidGeneratedPasswordLength)
        ));
        assert!(matches!(
            generate_strong_password(PASSWORD_MAX_LENGTH + 1),
            Err(VaultError::InvalidGeneratedPasswordLength)
        ));
    }

    #[test]
    fn oversized_item_is_rejected_before_persistence() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note(
            "bounded note",
            "x".repeat(MAX_FIELD_VALUE_CHARS.saturating_add(1)),
        );

        assert!(matches!(
            session.put_item(&item, 1),
            Err(VaultError::ItemTooLarge)
        ));
        assert!(session.get_item(item.id).is_err());
    }

    #[test]
    fn oversized_update_does_not_replace_existing_revision() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let mut item = VaultItem::secure_note("bounded note", "original body");
        session.put_item(&item, 1).expect("store original");
        item.fields.insert(
            "body".to_owned(),
            "x".repeat(MAX_FIELD_VALUE_CHARS.saturating_add(1)),
        );

        assert!(matches!(
            session.update_item(&item, 1),
            Err(VaultError::ItemTooLarge)
        ));
        let (restored, revision) = session
            .get_item_with_revision(item.id)
            .expect("load original after rejected update");
        assert_eq!(revision, 1);
        assert_eq!(
            restored.fields.get("body").map(String::as_str),
            Some("original body")
        );
    }

    #[test]
    fn ownership_items_round_trip_with_links_preserved() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let receipt = VaultItem::document("MacBook invoice", "INV-1", "Apple", "", "");
        session.put_item(&receipt, 1).expect("store receipt");
        let mut macbook = VaultItem::possession(
            "MacBook",
            "Apple",
            "Pro 14",
            "SN123",
            "2024-01-15",
            "199900",
            "Amazon",
            "2027-01-15",
            "",
        );
        macbook.links.push(receipt.id);
        session.put_item(&macbook, 1).expect("store possession");
        let vehicle = VaultItem::vehicle(
            "Family Car",
            "Toyota",
            "Innova",
            "2021",
            "KA01AB1234",
            "VIN123",
            "2026-10-02",
            "",
        );
        session.put_item(&vehicle, 1).expect("store vehicle");

        let (restored, _) = session
            .get_item_with_revision(macbook.id)
            .expect("load possession");
        assert_eq!(restored.links, vec![receipt.id]);
        assert_eq!(
            restored.fields.get("warranty_expiry").map(String::as_str),
            Some("2027-01-15")
        );
        assert_eq!(session.list_items().expect("list").len(), 3);
    }

    #[test]
    fn excessive_links_are_rejected_before_persistence() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let mut item = VaultItem::secure_note("linked", "body");
        item.links = (0..65).map(|_| Uuid::new_v4()).collect();
        assert!(matches!(
            session.put_item(&item, 1),
            Err(VaultError::ItemTooLarge)
        ));
    }

    #[test]
    fn encrypted_item_survives_process_restart_without_plaintext_at_rest() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let item_id_file = dir.path().join("item-id.txt");
        let test_binary = std::env::current_exe().expect("current test binary");

        let create_status = Command::new(&test_binary)
            .args(["--exact", "tests::process_restart_helper", "--nocapture"])
            .env("SAFEORY_TEST_PHASE", "create")
            .env("SAFEORY_TEST_DB", &database)
            .env("SAFEORY_TEST_ID", &item_id_file)
            .status()
            .expect("launch create process");
        assert!(create_status.success());

        for entry in fs::read_dir(dir.path()).expect("list vault directory") {
            let path = entry.expect("directory entry").path();
            if path == item_id_file || !path.is_file() {
                continue;
            }
            let bytes = fs::read(&path).expect("read persisted vault artifact");
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains(TEST_SECRET_TITLE));
            assert!(!text.contains(TEST_SECRET_BODY));
            assert!(!text.contains(TEST_PASSPHRASE));
        }

        let unlock_status = Command::new(&test_binary)
            .args(["--exact", "tests::process_restart_helper", "--nocapture"])
            .env("SAFEORY_TEST_PHASE", "unlock")
            .env("SAFEORY_TEST_DB", &database)
            .env("SAFEORY_TEST_ID", &item_id_file)
            .status()
            .expect("launch unlock process");
        assert!(unlock_status.success());
    }

    #[test]
    fn process_restart_helper() {
        let Ok(phase) = std::env::var("SAFEORY_TEST_PHASE") else {
            return;
        };
        let database = std::env::var_os("SAFEORY_TEST_DB").expect("test database path");
        let item_id_file = std::env::var_os("SAFEORY_TEST_ID").expect("test item id path");

        match phase.as_str() {
            "create" => {
                let session =
                    VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
                let item = VaultItem::secure_note(TEST_SECRET_TITLE, TEST_SECRET_BODY);
                fs::write(&item_id_file, item.id.to_string()).expect("persist test item id");
                session.put_item(&item, 1).expect("persist encrypted item");
            }
            "unlock" => {
                let item_id = fs::read_to_string(&item_id_file)
                    .expect("read test item id")
                    .parse::<Uuid>()
                    .expect("parse test item id");
                let session =
                    VaultSession::unlock(&database, TEST_PASSPHRASE).expect("unlock after restart");
                let restored = session.get_item(item_id).expect("decrypt item");
                assert_eq!(restored.id, item_id);
                assert_eq!(restored.title, TEST_SECRET_TITLE);
                assert_eq!(
                    restored.fields.get("body").map(String::as_str),
                    Some(TEST_SECRET_BODY)
                );
            }
            other => panic!("unknown restart-test phase: {other}"),
        }
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        drop(VaultSession::create(&database, "correct phrase").expect("create vault"));

        assert!(VaultSession::unlock(&database, "wrong phrase").is_err());
    }

    #[test]
    fn short_master_passphrase_is_rejected_before_initialization() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");

        assert!(matches!(
            VaultSession::create(&database, "too short"),
            Err(VaultError::PassphraseTooShort)
        ));
        assert!(!database.exists());
    }

    #[test]
    fn item_update_reencrypts_and_replaces_the_previous_revision() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let mut item = VaultItem::secure_note("original", "first body");
        session.put_item(&item, 1).expect("store original");

        item.title = "updated".to_owned();
        item.fields
            .insert("body".to_owned(), "second body".to_owned());
        session.update_item(&item, 1).expect("update item");

        let restored = session.get_item(item.id).expect("load updated item");
        assert_eq!(restored.title, "updated");
        assert_eq!(
            restored.fields.get("body").map(String::as_str),
            Some("second body")
        );
    }

    #[test]
    fn stale_expected_revision_cannot_overwrite_a_newer_edit() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let original = VaultItem::secure_note("original", "body");
        session.put_item(&original, 1).expect("store original");

        let mut first_editor = session.get_item(original.id).expect("first editor");
        let mut stale_editor = session.get_item(original.id).expect("stale editor");
        first_editor.title = "first edit".to_owned();
        stale_editor.title = "stale edit".to_owned();

        assert_eq!(
            session.update_item(&first_editor, 1).expect("first update"),
            2
        );
        assert!(matches!(
            session.update_item(&stale_editor, 1),
            Err(VaultError::Storage(StorageError::StaleRevision))
        ));
        assert_eq!(
            session.get_item(original.id).expect("current item").title,
            "first edit"
        );
    }

    #[test]
    fn trash_restore_and_tombstone_preserve_monotonic_revision() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("trash lifecycle", "private body");
        session.put_item(&item, 1).expect("store item");

        let trashed_revision = session
            .trash_item(item.id, 1, 1_700_000_000_000)
            .expect("move to trash");
        assert_eq!(trashed_revision, 2);
        assert!(matches!(
            session.get_item(item.id),
            Err(VaultError::ItemNotActive)
        ));
        assert!(session.list_items().expect("list active").is_empty());
        let trashed = session
            .list_trashed_items_with_revisions()
            .expect("list trash");
        assert_eq!(trashed.len(), 1);
        assert_eq!(trashed[0].0.title, "trash lifecycle");
        assert_eq!(trashed[0].1, 2);
        assert_eq!(trashed[0].2, 1_700_000_000_000);

        let restored_revision = session
            .restore_item(item.id, trashed_revision)
            .expect("restore item");
        assert_eq!(restored_revision, 3);
        assert_eq!(
            session.get_item(item.id).expect("restored item").fields["body"],
            "private body"
        );

        let second_trash_revision = session
            .trash_item(item.id, restored_revision, 1_700_000_000_100)
            .expect("trash again");
        assert_eq!(second_trash_revision, 4);
        let tombstone_revision = session
            .purge_item(item.id, second_trash_revision)
            .expect("delete forever");
        assert_eq!(tombstone_revision, 5);
        assert!(matches!(
            session.get_item(item.id),
            Err(VaultError::ItemNotActive)
        ));
        assert!(
            session
                .list_trashed_items_with_revisions()
                .expect("trash after purge")
                .is_empty()
        );
        assert!(matches!(
            session.restore_item(item.id, tombstone_revision),
            Err(VaultError::ItemNotTrashed)
        ));
    }

    #[test]
    fn stale_lifecycle_transitions_are_rejected_by_cas() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("cas lifecycle", "body");
        session.put_item(&item, 1).expect("store item");

        assert_eq!(session.trash_item(item.id, 1, 10).expect("trash"), 2);
        assert!(matches!(
            session.trash_item(item.id, 1, 11),
            Err(VaultError::Storage(StorageError::StaleRevision))
        ));
        assert_eq!(session.restore_item(item.id, 2).expect("restore"), 3);
        assert!(matches!(
            session.restore_item(item.id, 2),
            Err(VaultError::Storage(StorageError::StaleRevision))
        ));

        assert_eq!(
            session.trash_item(item.id, 3, 12).expect("trash for purge"),
            4
        );
        assert_eq!(session.purge_item(item.id, 4).expect("purge"), 5);
        assert!(matches!(
            session.purge_item(item.id, 4),
            Err(VaultError::Storage(StorageError::StaleRevision))
        ));
    }

    #[test]
    fn emergency_card_round_trip_rev_1_to_2() {
        use vault_models::{EmergencyCard, EmergencyContact};

        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        assert!(session.get_emergency_card().expect("load empty").is_none());

        let selected = vec![Uuid::new_v4(), Uuid::new_v4()];
        let card = EmergencyCard {
            selected_item_ids: selected.clone(),
            contacts: vec![EmergencyContact {
                name: "Ada".to_owned(),
                relation: "Sibling".to_owned(),
                phone: "+1-555-0100".to_owned(),
                notes: "Call first".to_owned(),
            }],
            instructions: "Follow the printed steps".to_owned(),
        };
        assert_eq!(session.set_emergency_card(&card).expect("set rev 1"), 1);
        let (restored, rev) = session
            .get_emergency_card()
            .expect("load card")
            .expect("card present");
        assert_eq!(rev, 1);
        assert_eq!(restored, card);

        let mut updated = card.clone();
        updated.instructions = "Updated instructions".to_owned();
        updated.selected_item_ids.push(Uuid::new_v4());
        assert_eq!(session.set_emergency_card(&updated).expect("set rev 2"), 2);
        let (restored2, rev2) = session
            .get_emergency_card()
            .expect("load updated")
            .expect("card present");
        assert_eq!(rev2, 2);
        assert_eq!(restored2, updated);
    }

    #[test]
    fn oversized_emergency_card_is_rejected() {
        use vault_models::{EmergencyCard, EmergencyContact};

        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");

        let too_many_items = EmergencyCard {
            selected_item_ids: (0..129).map(|_| Uuid::new_v4()).collect(),
            contacts: Vec::new(),
            instructions: String::new(),
        };
        assert!(matches!(
            session.set_emergency_card(&too_many_items),
            Err(VaultError::ItemTooLarge)
        ));

        let too_many_contacts = EmergencyCard {
            selected_item_ids: Vec::new(),
            contacts: (0..33)
                .map(|index| EmergencyContact {
                    name: format!("Contact {index}"),
                    relation: "Friend".to_owned(),
                    phone: "123".to_owned(),
                    notes: String::new(),
                })
                .collect(),
            instructions: String::new(),
        };
        assert!(matches!(
            session.set_emergency_card(&too_many_contacts),
            Err(VaultError::ItemTooLarge)
        ));
    }

    #[test]
    fn corrupt_emergency_card_json_returns_error() {
        use vault_models::EmergencyCard;

        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        session
            .set_emergency_card(&EmergencyCard::empty())
            .expect("set card");
        let mut corrupted = VaultItem::emergency_card(&EmergencyCard::empty());
        corrupted
            .fields
            .insert("card".to_owned(), "not-valid-json{".to_owned());
        session.update_item(&corrupted, 1).expect("corrupt card");
        assert!(matches!(
            session.get_emergency_card(),
            Err(VaultError::Storage(StorageError::InconsistentEncryptedRow))
        ));
    }

    #[test]
    fn recovery_kit_install_has_and_unlock_round_trip() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        assert!(!session.has_recovery_kit().expect("initially no kit"));
        let secret = RecoverySecret::generate().expect("recovery secret");
        session.install_recovery_kit(&secret).expect("install kit");
        assert!(session.has_recovery_kit().expect("kit present"));

        let item = VaultItem::secure_note("kit note", "kit body");
        session.put_item(&item, 1).expect("store item");
        drop(session);

        let restored =
            VaultSession::unlock_with_recovery_kit(&database, &secret).expect("unlock with kit");
        assert_eq!(
            restored.get_item(item.id).expect("load item").title,
            "kit note"
        );
        assert!(restored.has_recovery_kit().expect("kit still present"));
    }

    #[test]
    fn recovery_kit_wrong_secret_fails_to_unlock() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let secret = RecoverySecret::generate().expect("recovery secret");
        session.install_recovery_kit(&secret).expect("install kit");
        drop(session);

        let wrong = RecoverySecret::generate().expect("wrong secret");
        assert!(VaultSession::unlock_with_recovery_kit(&database, &wrong).is_err());
    }

    #[test]
    fn recovery_kit_missing_unlock_fails_with_not_initialized() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        drop(VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault"));
        let secret = RecoverySecret::generate().expect("recovery secret");
        assert!(matches!(
            VaultSession::unlock_with_recovery_kit(&database, &secret),
            Err(VaultError::Storage(StorageError::NotInitialized))
        ));
    }
}
