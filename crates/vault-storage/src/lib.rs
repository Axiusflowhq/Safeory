#![forbid(unsafe_code)]

use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;
use vault_crypto::{EncryptedItemV1, RecoveryKitWrapV1, RootKeyWrapV1};

const CURRENT_SCHEMA_VERSION: i64 = 2;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("encrypted metadata serialization failed")]
    Serialization(#[from] serde_json::Error),
    #[error("vault has already been initialized")]
    AlreadyInitialized,
    #[error("vault has not been initialized")]
    NotInitialized,
    #[error("item was not found")]
    ItemNotFound,
    #[error("item revision exceeds SQLite integer range")]
    RevisionOutOfRange,
    #[error("encrypted row metadata does not match its authenticated envelope")]
    InconsistentEncryptedRow,
    #[error("item write was rejected because its revision is not newer")]
    StaleRevision,
    #[error("unsupported local database schema version {0}")]
    UnsupportedSchemaVersion(i64),
}

pub struct VaultStorage {
    connection: Connection,
}

impl VaultStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;

        let schema_table_exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations')",
            [],
            |row| row.get(0),
        )?;
        let schema_version: i64 = if schema_table_exists {
            connection.query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |row| row.get(0),
            )?
        } else {
            0
        };
        if schema_version > CURRENT_SCHEMA_VERSION {
            return Err(StorageError::UnsupportedSchemaVersion(schema_version));
        }

        if schema_version < 1 {
            connection.execute_batch(
                "
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                root_key_wrap BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS encrypted_items (
                object_id TEXT PRIMARY KEY NOT NULL,
                revision INTEGER NOT NULL,
                encrypted_record BLOB NOT NULL
            );

            INSERT OR IGNORE INTO schema_migrations(version) VALUES (1);
            ",
            )?;
        }

        if schema_version < 2 {
            connection.execute_batch(
                "
            CREATE TABLE IF NOT EXISTS recovery_kit (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                kit_wrap BLOB NOT NULL
            );
            INSERT OR IGNORE INTO schema_migrations(version) VALUES (2);
            ",
            )?;
        }
        Ok(Self { connection })
    }

    pub fn initialize_root_wrap(&self, wrapped: &RootKeyWrapV1) -> Result<(), StorageError> {
        let encoded = serde_json::to_vec(wrapped)?;
        let changed = self.connection.execute(
            "INSERT OR IGNORE INTO vault_meta(singleton, root_key_wrap) VALUES (1, ?1)",
            params![encoded],
        )?;
        if changed != 1 {
            return Err(StorageError::AlreadyInitialized);
        }
        Ok(())
    }

    pub fn load_root_wrap(&self) -> Result<RootKeyWrapV1, StorageError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT root_key_wrap FROM vault_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let bytes = bytes.ok_or(StorageError::NotInitialized)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn replace_root_wrap(&self, wrapped: &RootKeyWrapV1) -> Result<(), StorageError> {
        let encoded = serde_json::to_vec(wrapped)?;
        let changed = self.connection.execute(
            "UPDATE vault_meta SET root_key_wrap = ?1 WHERE singleton = 1",
            params![encoded],
        )?;
        if changed != 1 {
            return Err(StorageError::NotInitialized);
        }
        Ok(())
    }

    pub fn is_initialized(&self) -> Result<bool, StorageError> {
        let initialized: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_meta WHERE singleton = 1)",
            [],
            |row| row.get(0),
        )?;
        Ok(initialized)
    }

    pub fn store_recovery_wrap(&self, wrapped: &RecoveryKitWrapV1) -> Result<(), StorageError> {
        let encoded = serde_json::to_vec(wrapped)?;
        self.connection.execute(
            "INSERT OR REPLACE INTO recovery_kit(singleton, kit_wrap) VALUES (1, ?1)",
            params![encoded],
        )?;
        Ok(())
    }

    pub fn load_recovery_wrap(&self) -> Result<Option<RecoveryKitWrapV1>, StorageError> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT kit_wrap FROM recovery_kit WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    pub fn has_recovery_wrap(&self) -> Result<bool, StorageError> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM recovery_kit WHERE singleton = 1)",
            [],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    pub fn upsert_item(&self, item: &EncryptedItemV1) -> Result<(), StorageError> {
        let encoded = serde_json::to_vec(item)?;
        let revision =
            i64::try_from(item.revision).map_err(|_| StorageError::RevisionOutOfRange)?;
        let changed = self.connection.execute(
            "
            INSERT INTO encrypted_items(object_id, revision, encrypted_record)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(object_id) DO UPDATE SET
                revision = excluded.revision,
                encrypted_record = excluded.encrypted_record
            WHERE excluded.revision > encrypted_items.revision
            ",
            params![item.object_id.to_string(), revision, encoded],
        )?;
        if changed != 1 {
            return Err(StorageError::StaleRevision);
        }
        Ok(())
    }

    pub fn update_item_if_revision(
        &self,
        item: &EncryptedItemV1,
        expected_revision: u64,
    ) -> Result<(), StorageError> {
        let encoded = serde_json::to_vec(item)?;
        let revision =
            i64::try_from(item.revision).map_err(|_| StorageError::RevisionOutOfRange)?;
        let expected_revision =
            i64::try_from(expected_revision).map_err(|_| StorageError::RevisionOutOfRange)?;
        let changed = self.connection.execute(
            "
            UPDATE encrypted_items
            SET revision = ?1, encrypted_record = ?2
            WHERE object_id = ?3 AND revision = ?4
            ",
            params![
                revision,
                encoded,
                item.object_id.to_string(),
                expected_revision
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::StaleRevision);
        }
        Ok(())
    }

    pub fn load_item(&self, object_id: Uuid) -> Result<EncryptedItemV1, StorageError> {
        let row: Option<(i64, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT revision, encrypted_record FROM encrypted_items WHERE object_id = ?1",
                params![object_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (stored_revision, bytes) = row.ok_or(StorageError::ItemNotFound)?;
        let encrypted: EncryptedItemV1 = serde_json::from_slice(&bytes)?;
        let stored_revision =
            u64::try_from(stored_revision).map_err(|_| StorageError::InconsistentEncryptedRow)?;
        if encrypted.object_id != object_id || encrypted.revision != stored_revision {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        Ok(encrypted)
    }

    pub fn list_item_ids(&self) -> Result<Vec<Uuid>, StorageError> {
        let mut statement = self
            .connection
            .prepare("SELECT object_id FROM encrypted_items ORDER BY object_id ASC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for row in rows {
            let raw = row?;
            let id = Uuid::parse_str(&raw).map_err(|_| StorageError::InconsistentEncryptedRow)?;
            ids.push(id);
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use vault_crypto::{AccountRootKey, encrypt_item};
    use vault_models::VaultItem;

    #[test]
    fn rejects_transplanted_encrypted_record() {
        let dir = tempdir().expect("temp directory");
        let storage = VaultStorage::open(dir.path().join("vault.sqlite3")).expect("open storage");
        let root = AccountRootKey::generate().expect("root key");
        let first = VaultItem::secure_note("first", "one");
        let second = VaultItem::secure_note("second", "two");
        let first_encrypted = encrypt_item(&root, &first, 1).expect("encrypt first");
        let second_encrypted = encrypt_item(&root, &second, 1).expect("encrypt second");
        storage.upsert_item(&first_encrypted).expect("store first");
        storage
            .upsert_item(&second_encrypted)
            .expect("store second");

        let second_bytes = serde_json::to_vec(&second_encrypted).expect("serialize second");
        storage
            .connection
            .execute(
                "UPDATE encrypted_items SET encrypted_record = ?1 WHERE object_id = ?2",
                params![second_bytes, first.id.to_string()],
            )
            .expect("tamper row");

        assert!(matches!(
            storage.load_item(first.id),
            Err(StorageError::InconsistentEncryptedRow)
        ));
    }

    #[test]
    fn stale_revision_is_reported_as_failure() {
        let dir = tempdir().expect("temp directory");
        let storage = VaultStorage::open(dir.path().join("vault.sqlite3")).expect("open storage");
        let root = AccountRootKey::generate().expect("root key");
        let item = VaultItem::secure_note("item", "value");
        let current = encrypt_item(&root, &item, 2).expect("encrypt current");
        let stale = encrypt_item(&root, &item, 1).expect("encrypt stale");
        storage.upsert_item(&current).expect("store current");

        assert!(matches!(
            storage.upsert_item(&stale),
            Err(StorageError::StaleRevision)
        ));
    }

    #[test]
    fn newer_database_schema_is_rejected() {
        let dir = tempdir().expect("temp directory");
        let path = dir.path().join("vault.sqlite3");
        {
            let storage = VaultStorage::open(&path).expect("open storage");
            storage
                .connection
                .execute("INSERT INTO schema_migrations(version) VALUES (3)", [])
                .expect("simulate newer schema");
        }

        assert!(matches!(
            VaultStorage::open(&path),
            Err(StorageError::UnsupportedSchemaVersion(3))
        ));
    }

    #[test]
    fn newer_database_schema_is_rejected_without_bootstrap_mutation() {
        let dir = tempdir().expect("temp directory");
        let path = dir.path().join("vault.sqlite3");
        {
            let connection = Connection::open(&path).expect("open raw database");
            connection
                .execute_batch(
                    "
                    CREATE TABLE schema_migrations (
                        version INTEGER PRIMARY KEY NOT NULL
                    );
                    INSERT INTO schema_migrations(version) VALUES (3);
                    CREATE TABLE future_only (value TEXT NOT NULL);
                    ",
                )
                .expect("create future schema");
        }

        assert!(matches!(
            VaultStorage::open(&path),
            Err(StorageError::UnsupportedSchemaVersion(3))
        ));

        let connection = Connection::open(&path).expect("reopen raw database");
        for table in ["vault_meta", "encrypted_items"] {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                    params![table],
                    |row| row.get(0),
                )
                .expect("check table");
            assert!(!exists, "old binary created {table} before rejecting v3");
        }
    }

    #[test]
    fn active_rollback_journal_does_not_contain_item_plaintext() {
        const SECRET_TITLE: &str = "Journal inspection secret title";
        const SECRET_BODY: &str = "Journal inspection secret body 4D92";

        let dir = tempdir().expect("temp directory");
        let path = dir.path().join("vault.sqlite3");
        let journal_path = dir.path().join("vault.sqlite3-journal");
        let storage = VaultStorage::open(&path).expect("open storage");
        let root = AccountRootKey::generate().expect("root key");
        let item = VaultItem::secure_note(SECRET_TITLE, SECRET_BODY);
        let current = encrypt_item(&root, &item, 1).expect("encrypt current");
        let replacement = encrypt_item(&root, &item, 2).expect("encrypt replacement");
        storage.upsert_item(&current).expect("store current");

        let replacement_bytes = serde_json::to_vec(&replacement).expect("serialize replacement");
        storage
            .connection
            .execute_batch("BEGIN IMMEDIATE")
            .expect("begin transaction");
        storage
            .connection
            .execute(
                "UPDATE encrypted_items SET revision = ?1, encrypted_record = ?2 WHERE object_id = ?3",
                params![2_i64, replacement_bytes, item.id.to_string()],
            )
            .expect("update encrypted row");

        assert!(journal_path.exists(), "expected SQLite rollback journal");
        let journal = fs::read(&journal_path).expect("read rollback journal");
        let journal_text = String::from_utf8_lossy(&journal);
        assert!(!journal_text.contains(SECRET_TITLE));
        assert!(!journal_text.contains(SECRET_BODY));

        storage
            .connection
            .execute_batch("ROLLBACK")
            .expect("rollback transaction");
    }

    #[test]
    fn v1_database_migrates_to_v2_with_recovery_table() {
        use vault_crypto::{RecoverySecret, wrap_root_key_with_recovery_secret};

        let dir = tempdir().expect("temp directory");
        let path = dir.path().join("vault.sqlite3");
        let root = AccountRootKey::generate().expect("root key");
        let item = VaultItem::secure_note("migrated", "preserved body");
        let encrypted = encrypt_item(&root, &item, 1).expect("encrypt item");
        let encoded = serde_json::to_vec(&encrypted).expect("serialize item");
        {
            let connection = Connection::open(&path).expect("open raw database");
            connection
                .execute_batch(
                    "
                    CREATE TABLE schema_migrations (
                        version INTEGER PRIMARY KEY NOT NULL
                    );
                    CREATE TABLE vault_meta (
                        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                        root_key_wrap BLOB NOT NULL
                    );
                    CREATE TABLE encrypted_items (
                        object_id TEXT PRIMARY KEY NOT NULL,
                        revision INTEGER NOT NULL,
                        encrypted_record BLOB NOT NULL
                    );
                    INSERT INTO schema_migrations(version) VALUES (1);
                    ",
                )
                .expect("create v1 schema");
            connection
                .execute(
                    "INSERT INTO encrypted_items(object_id, revision, encrypted_record) VALUES (?1, ?2, ?3)",
                    params![item.id.to_string(), 1_i64, encoded],
                )
                .expect("seed v1 item");
        }

        let storage = VaultStorage::open(&path).expect("migrate to v2");
        let restored = storage.load_item(item.id).expect("load migrated item");
        assert_eq!(restored.object_id, item.id);
        assert_eq!(restored.revision, 1);

        assert!(!storage.has_recovery_wrap().expect("check recovery wrap"));
        assert!(storage.load_recovery_wrap().expect("load").is_none());

        let secret = RecoverySecret::generate().expect("recovery secret");
        let wrapped =
            wrap_root_key_with_recovery_secret(&secret, &root).expect("wrap recovery kit");
        storage
            .store_recovery_wrap(&wrapped)
            .expect("store recovery wrap");
        assert!(storage.has_recovery_wrap().expect("has recovery wrap"));
        let loaded = storage
            .load_recovery_wrap()
            .expect("load recovery wrap")
            .expect("recovery wrap present");
        assert_eq!(loaded.ciphertext, wrapped.ciphertext);
        assert_eq!(loaded.salt, wrapped.salt);

        let version: i64 = storage
            .connection
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |row| row.get(0),
            )
            .expect("read schema version");
        assert_eq!(version, 2);
    }

    #[test]
    fn fresh_database_supports_recovery_wrap_round_trip() {
        use vault_crypto::{RecoverySecret, wrap_root_key_with_recovery_secret};

        let dir = tempdir().expect("temp directory");
        let storage = VaultStorage::open(dir.path().join("vault.sqlite3")).expect("open storage");
        assert!(!storage.has_recovery_wrap().expect("initially empty"));
        let root = AccountRootKey::generate().expect("root key");
        let secret = RecoverySecret::generate().expect("recovery secret");
        let wrapped =
            wrap_root_key_with_recovery_secret(&secret, &root).expect("wrap recovery kit");
        storage
            .store_recovery_wrap(&wrapped)
            .expect("store recovery wrap");
        assert!(storage.has_recovery_wrap().expect("has wrap"));
        let loaded = storage
            .load_recovery_wrap()
            .expect("load wrap")
            .expect("present");
        assert_eq!(loaded.ciphertext, wrapped.ciphertext);
    }
}
