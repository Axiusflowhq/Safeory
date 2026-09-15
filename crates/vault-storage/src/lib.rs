#![forbid(unsafe_code)]

use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, backup::Backup, params,
};
use std::{path::Path, time::Duration};
use thiserror::Error;
use uuid::Uuid;
use vault_crypto::{
    ATTACHMENT_MAX_CHUNK_CIPHERTEXT_BYTES, ATTACHMENT_MAX_CHUNKS,
    ATTACHMENT_MAX_ENCRYPTED_RECORD_BYTES, ATTACHMENT_MAX_OBJECTS, EncryptedItemV1,
    RecoveryKitWrapV1, RootKeyWrapV1,
};

const CURRENT_SCHEMA_VERSION: i64 = 3;
/// Resource ceiling for local encrypted item rows. This is intentionally far
/// above normal product use while keeping validation/list allocations bounded.
pub const ITEM_MAX_OBJECTS: u64 = 65_536;
/// The current core permits up to 32 large string fields plus notes; because
/// `EncryptedItemV1` is JSON-encoded and its ciphertext is a byte array, the
/// encoded envelope can be several times larger than plaintext. 128 MiB keeps
/// all currently-valid item shapes representable while bounding hostile rows.
pub const ITEM_MAX_ENCRYPTED_RECORD_BYTES: usize = 128 * 1024 * 1024;
/// Root/recovery wraps contain fixed-size cryptographic material; 16 KiB is a
/// deliberately generous serialization ceiling for backwards-compatible v1.
pub const ROOT_WRAP_MAX_ENCODED_BYTES: usize = 16 * 1024;
pub const RECOVERY_WRAP_MAX_ENCODED_BYTES: usize = 16 * 1024;

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
    #[error("attachment was not found")]
    AttachmentNotFound,
    #[error("vault has reached the attachment object limit")]
    AttachmentObjectLimitReached,
    #[error("revision exceeds SQLite integer range")]
    RevisionOutOfRange,
    #[error("encrypted row metadata does not match its authenticated envelope")]
    InconsistentEncryptedRow,
    #[error("encrypted row write was rejected because its revision is stale")]
    StaleRevision,
    #[error("database integrity check failed")]
    IntegrityCheckFailed,
    #[error("unsupported local database schema version {0}")]
    UnsupportedSchemaVersion(i64),
}

pub struct VaultStorage {
    connection: Connection,
    path: std::path::PathBuf,
}

impl VaultStorage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        let connection = Connection::open(&path)?;
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

        if schema_version < 3 {
            connection.execute_batch(
                "
            CREATE TABLE IF NOT EXISTS encrypted_attachments (
                attachment_id TEXT PRIMARY KEY NOT NULL,
                revision INTEGER NOT NULL,
                encrypted_record BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS attachment_chunks (
                attachment_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                ciphertext BLOB NOT NULL,
                PRIMARY KEY (attachment_id, chunk_index),
                FOREIGN KEY (attachment_id) REFERENCES encrypted_attachments(attachment_id) ON DELETE CASCADE
            );

            INSERT OR IGNORE INTO schema_migrations(version) VALUES (3);
            ",
            )?;
        }
        Ok(Self { connection, path })
    }

    pub fn initialize_root_wrap(&self, wrapped: &RootKeyWrapV1) -> Result<(), StorageError> {
        let encoded = serde_json::to_vec(wrapped)?;
        if encoded.len() > ROOT_WRAP_MAX_ENCODED_BYTES {
            return Err(StorageError::InconsistentEncryptedRow);
        }
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
        let max_encoded = i64::try_from(ROOT_WRAP_MAX_ENCODED_BYTES)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let row: Option<(i64, Option<Vec<u8>>)> = self
            .connection
            .query_row(
                "SELECT length(root_key_wrap), CASE WHEN length(root_key_wrap) <= ?1 THEN root_key_wrap ELSE NULL END FROM vault_meta WHERE singleton = 1",
                params![max_encoded],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (encoded_len, bytes) = row.ok_or(StorageError::NotInitialized)?;
        validate_encoded_blob_length(encoded_len, ROOT_WRAP_MAX_ENCODED_BYTES)?;
        let bytes = bytes.ok_or(StorageError::InconsistentEncryptedRow)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn replace_root_wrap(&self, wrapped: &RootKeyWrapV1) -> Result<(), StorageError> {
        let encoded = serde_json::to_vec(wrapped)?;
        if encoded.len() > ROOT_WRAP_MAX_ENCODED_BYTES {
            return Err(StorageError::InconsistentEncryptedRow);
        }
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
        if encoded.len() > RECOVERY_WRAP_MAX_ENCODED_BYTES {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        self.connection.execute(
            "INSERT OR REPLACE INTO recovery_kit(singleton, kit_wrap) VALUES (1, ?1)",
            params![encoded],
        )?;
        Ok(())
    }

    pub fn load_recovery_wrap(&self) -> Result<Option<RecoveryKitWrapV1>, StorageError> {
        let max_encoded = i64::try_from(RECOVERY_WRAP_MAX_ENCODED_BYTES)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let row: Option<(i64, Option<Vec<u8>>)> = self
            .connection
            .query_row(
                "SELECT length(kit_wrap), CASE WHEN length(kit_wrap) <= ?1 THEN kit_wrap ELSE NULL END FROM recovery_kit WHERE singleton = 1",
                params![max_encoded],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((encoded_len, bytes)) = row else {
            return Ok(None);
        };
        validate_encoded_blob_length(encoded_len, RECOVERY_WRAP_MAX_ENCODED_BYTES)?;
        let bytes = bytes.ok_or(StorageError::InconsistentEncryptedRow)?;
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
        if encoded.len() > ITEM_MAX_ENCRYPTED_RECORD_BYTES {
            return Err(StorageError::InconsistentEncryptedRow);
        }
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
        if encoded.len() > ITEM_MAX_ENCRYPTED_RECORD_BYTES {
            return Err(StorageError::InconsistentEncryptedRow);
        }
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
        let max_encoded = i64::try_from(ITEM_MAX_ENCRYPTED_RECORD_BYTES)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let row: Option<(i64, i64, Option<Vec<u8>>)> = self
            .connection
            .query_row(
                "SELECT revision, length(encrypted_record), CASE WHEN length(encrypted_record) <= ?2 THEN encrypted_record ELSE NULL END FROM encrypted_items WHERE object_id = ?1",
                params![object_id.to_string(), max_encoded],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (stored_revision, encrypted_record_len, bytes) =
            row.ok_or(StorageError::ItemNotFound)?;
        validate_encoded_blob_length(encrypted_record_len, ITEM_MAX_ENCRYPTED_RECORD_BYTES)?;
        let bytes = bytes.ok_or(StorageError::InconsistentEncryptedRow)?;
        let encrypted: EncryptedItemV1 = serde_json::from_slice(&bytes)?;
        let stored_revision =
            u64::try_from(stored_revision).map_err(|_| StorageError::InconsistentEncryptedRow)?;
        if encrypted.object_id != object_id || encrypted.revision != stored_revision {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        Ok(encrypted)
    }

    pub fn list_item_ids(&self) -> Result<Vec<Uuid>, StorageError> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM encrypted_items", [], |row| row.get(0))?;
        let count = u64::try_from(count).map_err(|_| StorageError::InconsistentEncryptedRow)?;
        if count > ITEM_MAX_OBJECTS {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        let row_limit = i64::try_from(ITEM_MAX_OBJECTS + 1)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let mut statement = self
            .connection
            .prepare("SELECT object_id FROM encrypted_items ORDER BY object_id ASC LIMIT ?1")?;
        let rows = statement.query_map(params![row_limit], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::with_capacity(
            usize::try_from(count).map_err(|_| StorageError::InconsistentEncryptedRow)?,
        );
        for row in rows {
            let raw = row?;
            let id = Uuid::parse_str(&raw).map_err(|_| StorageError::InconsistentEncryptedRow)?;
            ids.push(id);
        }
        if u64::try_from(ids.len()).map_err(|_| StorageError::InconsistentEncryptedRow)?
            > ITEM_MAX_OBJECTS
        {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        Ok(ids)
    }

    pub fn validate_record_bounds(&self) -> Result<(), StorageError> {
        let item_count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM encrypted_items", [], |row| row.get(0))?;
        let item_count =
            u64::try_from(item_count).map_err(|_| StorageError::InconsistentEncryptedRow)?;
        if item_count > ITEM_MAX_OBJECTS {
            return Err(StorageError::InconsistentEncryptedRow);
        }

        let max_item_record = i64::try_from(ITEM_MAX_ENCRYPTED_RECORD_BYTES)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let max_root_wrap = i64::try_from(ROOT_WRAP_MAX_ENCODED_BYTES)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let max_recovery_wrap = i64::try_from(RECOVERY_WRAP_MAX_ENCODED_BYTES)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let oversized_item: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM encrypted_items WHERE length(encrypted_record) > ?1)",
            params![max_item_record],
            |row| row.get(0),
        )?;
        let oversized_root_wrap: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_meta WHERE length(root_key_wrap) > ?1)",
            params![max_root_wrap],
            |row| row.get(0),
        )?;
        let oversized_recovery_wrap: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM recovery_kit WHERE length(kit_wrap) > ?1)",
            params![max_recovery_wrap],
            |row| row.get(0),
        )?;
        if oversized_item || oversized_root_wrap || oversized_recovery_wrap {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        Ok(())
    }

    pub fn insert_attachment(
        &self,
        attachment_id: Uuid,
        revision: u64,
        encrypted_record: &[u8],
    ) -> Result<(), StorageError> {
        if encrypted_record.len() > ATTACHMENT_MAX_ENCRYPTED_RECORD_BYTES {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        let revision = i64::try_from(revision).map_err(|_| StorageError::RevisionOutOfRange)?;
        let changed = self.connection.execute(
            "
            INSERT INTO encrypted_attachments(attachment_id, revision, encrypted_record)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(attachment_id) DO NOTHING
            ",
            params![attachment_id.to_string(), revision, encrypted_record],
        )?;
        if changed != 1 {
            return Err(StorageError::StaleRevision);
        }
        Ok(())
    }

    pub fn update_attachment_if_revision(
        &self,
        attachment_id: Uuid,
        revision: u64,
        expected_revision: u64,
        encrypted_record: &[u8],
    ) -> Result<(), StorageError> {
        if encrypted_record.len() > ATTACHMENT_MAX_ENCRYPTED_RECORD_BYTES {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        let revision = i64::try_from(revision).map_err(|_| StorageError::RevisionOutOfRange)?;
        let expected_revision =
            i64::try_from(expected_revision).map_err(|_| StorageError::RevisionOutOfRange)?;
        let changed = self.connection.execute(
            "
            UPDATE encrypted_attachments
            SET revision = ?1, encrypted_record = ?2
            WHERE attachment_id = ?3 AND revision = ?4 AND ?1 > revision
            ",
            params![
                revision,
                encrypted_record,
                attachment_id.to_string(),
                expected_revision
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::StaleRevision);
        }
        Ok(())
    }

    pub fn load_attachment(&self, attachment_id: Uuid) -> Result<(u64, Vec<u8>), StorageError> {
        let fetch_limit = i64::try_from(ATTACHMENT_MAX_ENCRYPTED_RECORD_BYTES + 1)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let row: Option<(i64, i64, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT revision, length(encrypted_record), substr(encrypted_record, 1, ?2) FROM encrypted_attachments WHERE attachment_id = ?1",
                params![attachment_id.to_string(), fetch_limit],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (stored_revision, encrypted_record_len, encrypted_record) =
            row.ok_or(StorageError::AttachmentNotFound)?;
        if encrypted_record_len < 0
            || usize::try_from(encrypted_record_len)
                .map_err(|_| StorageError::InconsistentEncryptedRow)?
                > ATTACHMENT_MAX_ENCRYPTED_RECORD_BYTES
        {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        let stored_revision =
            u64::try_from(stored_revision).map_err(|_| StorageError::InconsistentEncryptedRow)?;
        Ok((stored_revision, encrypted_record))
    }

    pub fn list_attachment_ids(&self) -> Result<Vec<Uuid>, StorageError> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM encrypted_attachments", [], |row| {
                    row.get(0)
                })?;
        let count = u64::try_from(count).map_err(|_| StorageError::InconsistentEncryptedRow)?;
        if count > ATTACHMENT_MAX_OBJECTS {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        let row_limit = i64::try_from(ATTACHMENT_MAX_OBJECTS + 1)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let mut statement = self.connection.prepare(
            "SELECT attachment_id FROM encrypted_attachments ORDER BY attachment_id ASC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![row_limit], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::with_capacity(
            usize::try_from(count).map_err(|_| StorageError::InconsistentEncryptedRow)?,
        );
        for row in rows {
            let raw = row?;
            let id = Uuid::parse_str(&raw).map_err(|_| StorageError::InconsistentEncryptedRow)?;
            ids.push(id);
        }
        if u64::try_from(ids.len()).map_err(|_| StorageError::InconsistentEncryptedRow)?
            > ATTACHMENT_MAX_OBJECTS
        {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        Ok(ids)
    }

    pub fn insert_attachment_chunk(
        &self,
        attachment_id: Uuid,
        chunk_index: u32,
        ciphertext: &[u8],
    ) -> Result<(), StorageError> {
        if u64::from(chunk_index) >= ATTACHMENT_MAX_CHUNKS
            || ciphertext.len() > ATTACHMENT_MAX_CHUNK_CIPHERTEXT_BYTES
        {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        self.connection.execute(
            "INSERT INTO attachment_chunks(attachment_id, chunk_index, ciphertext) VALUES (?1, ?2, ?3)",
            params![attachment_id.to_string(), i64::from(chunk_index), ciphertext],
        )?;
        Ok(())
    }

    pub fn list_attachment_chunk_indexes(
        &self,
        attachment_id: Uuid,
    ) -> Result<Vec<u32>, StorageError> {
        let row_limit = i64::try_from(ATTACHMENT_MAX_CHUNKS + 1)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let mut statement = self.connection.prepare(
            "SELECT chunk_index FROM attachment_chunks WHERE attachment_id = ?1 ORDER BY chunk_index ASC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![attachment_id.to_string(), row_limit], |row| {
            row.get::<_, i64>(0)
        })?;
        let mut indexes = Vec::with_capacity(
            usize::try_from(ATTACHMENT_MAX_CHUNKS)
                .map_err(|_| StorageError::InconsistentEncryptedRow)?,
        );
        for row in rows {
            let chunk_index =
                u32::try_from(row?).map_err(|_| StorageError::InconsistentEncryptedRow)?;
            if u64::from(chunk_index) >= ATTACHMENT_MAX_CHUNKS {
                return Err(StorageError::InconsistentEncryptedRow);
            }
            indexes.push(chunk_index);
        }
        if u64::try_from(indexes.len()).map_err(|_| StorageError::InconsistentEncryptedRow)?
            > ATTACHMENT_MAX_CHUNKS
        {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        Ok(indexes)
    }

    pub fn load_attachment_chunk(
        &self,
        attachment_id: Uuid,
        chunk_index: u32,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        if u64::from(chunk_index) >= ATTACHMENT_MAX_CHUNKS {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        let fetch_limit = i64::try_from(ATTACHMENT_MAX_CHUNK_CIPHERTEXT_BYTES + 1)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let row: Option<(i64, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT length(ciphertext), substr(ciphertext, 1, ?3) FROM attachment_chunks WHERE attachment_id = ?1 AND chunk_index = ?2",
                params![attachment_id.to_string(), i64::from(chunk_index), fetch_limit],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((ciphertext_len, ciphertext)) = row else {
            return Ok(None);
        };
        if ciphertext_len < 0
            || usize::try_from(ciphertext_len)
                .map_err(|_| StorageError::InconsistentEncryptedRow)?
                > ATTACHMENT_MAX_CHUNK_CIPHERTEXT_BYTES
        {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        Ok(Some(ciphertext))
    }

    pub fn list_attachment_chunks(
        &self,
        attachment_id: Uuid,
    ) -> Result<Vec<(u32, Vec<u8>)>, StorageError> {
        let indexes = self.list_attachment_chunk_indexes(attachment_id)?;
        let mut chunks = Vec::with_capacity(indexes.len());
        for chunk_index in indexes {
            let ciphertext = self
                .load_attachment_chunk(attachment_id, chunk_index)?
                .ok_or(StorageError::InconsistentEncryptedRow)?;
            chunks.push((chunk_index, ciphertext));
        }
        Ok(chunks)
    }

    pub fn delete_attachment_chunks(&self, attachment_id: Uuid) -> Result<usize, StorageError> {
        Ok(self.connection.execute(
            "DELETE FROM attachment_chunks WHERE attachment_id = ?1",
            params![attachment_id.to_string()],
        )?)
    }

    pub fn attachment_storage_bytes(&self) -> Result<u64, StorageError> {
        let total: i64 = self.connection.query_row(
            "
            SELECT
                COALESCE((SELECT SUM(length(encrypted_record)) FROM encrypted_attachments), 0) +
                COALESCE((SELECT SUM(length(ciphertext)) FROM attachment_chunks), 0)
            ",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(total).map_err(|_| StorageError::InconsistentEncryptedRow)
    }

    pub fn insert_attachment_and_update_item_if_revision(
        &self,
        item: &EncryptedItemV1,
        expected_item_revision: u64,
        attachment_id: Uuid,
        attachment_revision: u64,
        encrypted_record: &[u8],
        chunks: &[(u32, Vec<u8>)],
    ) -> Result<(), StorageError> {
        if encrypted_record.len() > ATTACHMENT_MAX_ENCRYPTED_RECORD_BYTES
            || u64::try_from(chunks.len()).map_err(|_| StorageError::InconsistentEncryptedRow)?
                > ATTACHMENT_MAX_CHUNKS
            || chunks.iter().any(|(chunk_index, ciphertext)| {
                u64::from(*chunk_index) >= ATTACHMENT_MAX_CHUNKS
                    || ciphertext.len() > ATTACHMENT_MAX_CHUNK_CIPHERTEXT_BYTES
            })
        {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        let encoded_item = serde_json::to_vec(item)?;
        if encoded_item.len() > ITEM_MAX_ENCRYPTED_RECORD_BYTES {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        let item_revision =
            i64::try_from(item.revision).map_err(|_| StorageError::RevisionOutOfRange)?;
        let expected_item_revision =
            i64::try_from(expected_item_revision).map_err(|_| StorageError::RevisionOutOfRange)?;
        let attachment_revision =
            i64::try_from(attachment_revision).map_err(|_| StorageError::RevisionOutOfRange)?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;

        let attachment_count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM encrypted_attachments", [], |row| {
                row.get(0)
            })?;
        let attachment_count =
            u64::try_from(attachment_count).map_err(|_| StorageError::InconsistentEncryptedRow)?;
        if attachment_count >= ATTACHMENT_MAX_OBJECTS {
            return Err(StorageError::AttachmentObjectLimitReached);
        }

        let changed = transaction.execute(
            "
            INSERT INTO encrypted_attachments(attachment_id, revision, encrypted_record)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(attachment_id) DO NOTHING
            ",
            params![
                attachment_id.to_string(),
                attachment_revision,
                encrypted_record
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::StaleRevision);
        }

        for (chunk_index, ciphertext) in chunks {
            transaction.execute(
                "INSERT INTO attachment_chunks(attachment_id, chunk_index, ciphertext) VALUES (?1, ?2, ?3)",
                params![
                    attachment_id.to_string(),
                    i64::from(*chunk_index),
                    ciphertext
                ],
            )?;
        }

        let changed = transaction.execute(
            "
            UPDATE encrypted_items
            SET revision = ?1, encrypted_record = ?2
            WHERE object_id = ?3 AND revision = ?4 AND ?1 > revision
            ",
            params![
                item_revision,
                encoded_item,
                item.object_id.to_string(),
                expected_item_revision
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::StaleRevision);
        }

        transaction.commit()?;
        Ok(())
    }

    pub fn tombstone_attachments_and_update_item_if_revision(
        &self,
        item: &EncryptedItemV1,
        expected_item_revision: u64,
        tombstones: &[(Uuid, u64, u64, Vec<u8>)],
    ) -> Result<(), StorageError> {
        let encoded_item = serde_json::to_vec(item)?;
        if encoded_item.len() > ITEM_MAX_ENCRYPTED_RECORD_BYTES {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        let item_revision =
            i64::try_from(item.revision).map_err(|_| StorageError::RevisionOutOfRange)?;
        let expected_item_revision =
            i64::try_from(expected_item_revision).map_err(|_| StorageError::RevisionOutOfRange)?;
        let transaction = self.connection.unchecked_transaction()?;

        let changed = transaction.execute(
            "
            UPDATE encrypted_items
            SET revision = ?1, encrypted_record = ?2
            WHERE object_id = ?3 AND revision = ?4 AND ?1 > revision
            ",
            params![
                item_revision,
                encoded_item,
                item.object_id.to_string(),
                expected_item_revision
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::StaleRevision);
        }

        for (attachment_id, revision, expected_revision, encrypted_record) in tombstones {
            if encrypted_record.len() > ATTACHMENT_MAX_ENCRYPTED_RECORD_BYTES {
                return Err(StorageError::InconsistentEncryptedRow);
            }
            let revision =
                i64::try_from(*revision).map_err(|_| StorageError::RevisionOutOfRange)?;
            let expected_revision =
                i64::try_from(*expected_revision).map_err(|_| StorageError::RevisionOutOfRange)?;
            let changed = transaction.execute(
                "
                UPDATE encrypted_attachments
                SET revision = ?1, encrypted_record = ?2
                WHERE attachment_id = ?3 AND revision = ?4 AND ?1 > revision
                ",
                params![
                    revision,
                    encrypted_record,
                    attachment_id.to_string(),
                    expected_revision
                ],
            )?;
            if changed != 1 {
                return Err(StorageError::StaleRevision);
            }
            transaction.execute(
                "DELETE FROM attachment_chunks WHERE attachment_id = ?1",
                params![attachment_id.to_string()],
            )?;
        }

        transaction.commit()?;
        Ok(())
    }

    pub fn validate_integrity(&self) -> Result<(), StorageError> {
        let result: String = self
            .connection
            .query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))?;
        if result != "ok" {
            return Err(StorageError::IntegrityCheckFailed);
        }
        Ok(())
    }

    pub fn backup_to(&self, path: impl AsRef<Path>) -> Result<(), StorageError> {
        let mut destination = Connection::open(path)?;
        let backup = Backup::new(&self.connection, &mut destination)?;
        backup.run_to_completion(64, Duration::from_millis(10), None)?;
        Ok(())
    }

    pub fn replace_from_database(&self, path: impl AsRef<Path>) -> Result<(), StorageError> {
        let connection = Connection::open(&self.path)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute(
            "ATTACH DATABASE ?1 AS safeory_restore",
            params![path.as_ref().to_string_lossy().as_ref()],
        )?;
        let transaction = connection.unchecked_transaction()?;
        let max_record = i64::try_from(ATTACHMENT_MAX_ENCRYPTED_RECORD_BYTES)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let max_chunk = i64::try_from(ATTACHMENT_MAX_CHUNK_CIPHERTEXT_BYTES)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let max_chunks = i64::try_from(ATTACHMENT_MAX_CHUNKS)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let max_objects = i64::try_from(ATTACHMENT_MAX_OBJECTS)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let max_item_objects =
            i64::try_from(ITEM_MAX_OBJECTS).map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let max_item_record = i64::try_from(ITEM_MAX_ENCRYPTED_RECORD_BYTES)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let max_root_wrap = i64::try_from(ROOT_WRAP_MAX_ENCODED_BYTES)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let max_recovery_wrap = i64::try_from(RECOVERY_WRAP_MAX_ENCODED_BYTES)
            .map_err(|_| StorageError::InconsistentEncryptedRow)?;
        let too_many_items: bool = transaction.query_row(
            "SELECT COUNT(*) > ?1 FROM safeory_restore.encrypted_items",
            params![max_item_objects],
            |row| row.get(0),
        )?;
        let oversized_item: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM safeory_restore.encrypted_items WHERE length(encrypted_record) > ?1)",
            params![max_item_record],
            |row| row.get(0),
        )?;
        let oversized_root_wrap: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM safeory_restore.vault_meta WHERE length(root_key_wrap) > ?1)",
            params![max_root_wrap],
            |row| row.get(0),
        )?;
        let oversized_recovery_wrap: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM safeory_restore.recovery_kit WHERE length(kit_wrap) > ?1)",
            params![max_recovery_wrap],
            |row| row.get(0),
        )?;
        let too_many_attachments: bool = transaction.query_row(
            "SELECT COUNT(*) > ?1 FROM safeory_restore.encrypted_attachments",
            params![max_objects],
            |row| row.get(0),
        )?;
        let oversized_record: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM safeory_restore.encrypted_attachments WHERE length(encrypted_record) > ?1)",
            params![max_record],
            |row| row.get(0),
        )?;
        let invalid_chunk: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM safeory_restore.attachment_chunks WHERE chunk_index < 0 OR chunk_index >= ?1 OR length(ciphertext) > ?2)",
            params![max_chunks, max_chunk],
            |row| row.get(0),
        )?;
        let too_many_chunks: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM (SELECT attachment_id FROM safeory_restore.attachment_chunks GROUP BY attachment_id HAVING COUNT(*) > ?1))",
            params![max_chunks],
            |row| row.get(0),
        )?;
        if too_many_items
            || oversized_item
            || oversized_root_wrap
            || oversized_recovery_wrap
            || too_many_attachments
            || oversized_record
            || invalid_chunk
            || too_many_chunks
        {
            return Err(StorageError::InconsistentEncryptedRow);
        }
        transaction.execute("DELETE FROM vault_meta", [])?;
        transaction.execute(
            "INSERT INTO vault_meta(singleton, root_key_wrap) SELECT singleton, root_key_wrap FROM safeory_restore.vault_meta",
            [],
        )?;
        transaction.execute("DELETE FROM encrypted_items", [])?;
        transaction.execute(
            "INSERT INTO encrypted_items(object_id, revision, encrypted_record) SELECT object_id, revision, encrypted_record FROM safeory_restore.encrypted_items",
            [],
        )?;
        transaction.execute("DELETE FROM attachment_chunks", [])?;
        transaction.execute("DELETE FROM encrypted_attachments", [])?;
        transaction.execute(
            "INSERT INTO encrypted_attachments(attachment_id, revision, encrypted_record) SELECT attachment_id, revision, encrypted_record FROM safeory_restore.encrypted_attachments",
            [],
        )?;
        transaction.execute(
            "INSERT INTO attachment_chunks(attachment_id, chunk_index, ciphertext) SELECT attachment_id, chunk_index, ciphertext FROM safeory_restore.attachment_chunks",
            [],
        )?;
        transaction.execute("DELETE FROM recovery_kit", [])?;
        transaction.execute(
            "INSERT INTO recovery_kit(singleton, kit_wrap) SELECT singleton, kit_wrap FROM safeory_restore.recovery_kit",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

fn validate_encoded_blob_length(encoded_len: i64, max: usize) -> Result<(), StorageError> {
    if encoded_len < 0
        || usize::try_from(encoded_len).map_err(|_| StorageError::InconsistentEncryptedRow)? > max
    {
        return Err(StorageError::InconsistentEncryptedRow);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use vault_crypto::{
        AccountRootKey, RecoverySecret, encrypt_item, wrap_root_key,
        wrap_root_key_with_recovery_secret,
    };
    use vault_models::VaultItem;

    fn seed_zero_blob_attachment_rows(storage: &VaultStorage, count: u64) {
        let transaction = storage
            .connection
            .unchecked_transaction()
            .expect("start attachment seed transaction");
        for index in 0..count {
            let attachment_id = Uuid::from_u128(u128::from(index) + 1);
            transaction
                .execute(
                    "INSERT INTO encrypted_attachments(attachment_id, revision, encrypted_record) VALUES (?1, 1, zeroblob(0))",
                    params![attachment_id.to_string()],
                )
                .expect("seed zero-blob attachment row");
        }
        transaction.commit().expect("commit attachment seed rows");
    }

    fn seed_zero_blob_item_rows(storage: &VaultStorage, count: u64) {
        let transaction = storage
            .connection
            .unchecked_transaction()
            .expect("start item seed transaction");
        for index in 0..count {
            let object_id = Uuid::from_u128(u128::from(index) + 1);
            transaction
                .execute(
                    "INSERT INTO encrypted_items(object_id, revision, encrypted_record) VALUES (?1, 1, zeroblob(0))",
                    params![object_id.to_string()],
                )
                .expect("seed zero-blob item row");
        }
        transaction.commit().expect("commit item seed rows");
    }

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
                .execute("INSERT INTO schema_migrations(version) VALUES (4)", [])
                .expect("simulate newer schema");
        }

        assert!(matches!(
            VaultStorage::open(&path),
            Err(StorageError::UnsupportedSchemaVersion(4))
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
                    INSERT INTO schema_migrations(version) VALUES (4);
                    CREATE TABLE future_only (value TEXT NOT NULL);
                    ",
                )
                .expect("create future schema");
        }

        assert!(matches!(
            VaultStorage::open(&path),
            Err(StorageError::UnsupportedSchemaVersion(4))
        ));

        let connection = Connection::open(&path).expect("reopen raw database");
        for table in [
            "vault_meta",
            "encrypted_items",
            "recovery_kit",
            "encrypted_attachments",
            "attachment_chunks",
        ] {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                    params![table],
                    |row| row.get(0),
                )
                .expect("check table");
            assert!(
                !exists,
                "current binary created {table} before rejecting v4"
            );
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
    fn v1_database_migrates_to_v3_with_recovery_and_attachment_tables() {
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

        let storage = VaultStorage::open(&path).expect("migrate to v3");
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
        assert_eq!(version, 3);

        let attachment_id = Uuid::new_v4();
        storage
            .insert_attachment(attachment_id, 1, b"opaque-envelope")
            .expect("insert attachment after migration");
        storage
            .insert_attachment_chunk(attachment_id, 0, b"chunk-zero")
            .expect("insert attachment chunk after migration");
        assert_eq!(
            storage
                .list_attachment_chunks(attachment_id)
                .expect("list attachment chunks"),
            vec![(0, b"chunk-zero".to_vec())]
        );
    }

    #[test]
    fn v2_database_migrates_to_v3_and_preserves_existing_items() {
        let dir = tempdir().expect("temp directory");
        let path = dir.path().join("vault.sqlite3");
        let root = AccountRootKey::generate().expect("root key");
        let item = VaultItem::secure_note("v2 item", "preserved");
        let encrypted = encrypt_item(&root, &item, 7).expect("encrypt item");
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
                    CREATE TABLE recovery_kit (
                        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                        kit_wrap BLOB NOT NULL
                    );
                    INSERT INTO schema_migrations(version) VALUES (1);
                    INSERT INTO schema_migrations(version) VALUES (2);
                    ",
                )
                .expect("create v2 schema");
            connection
                .execute(
                    "INSERT INTO encrypted_items(object_id, revision, encrypted_record) VALUES (?1, ?2, ?3)",
                    params![item.id.to_string(), 7_i64, encoded],
                )
                .expect("seed v2 item");
        }

        let storage = VaultStorage::open(&path).expect("migrate v2 to v3");
        let restored = storage.load_item(item.id).expect("load preserved item");
        assert_eq!(restored.object_id, item.id);
        assert_eq!(restored.revision, 7);

        let version: i64 = storage
            .connection
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |row| row.get(0),
            )
            .expect("read schema version");
        assert_eq!(version, 3);

        let attachment_id = Uuid::new_v4();
        storage
            .insert_attachment(attachment_id, 1, b"v3-envelope")
            .expect("insert v3 attachment");
        storage
            .insert_attachment_chunk(attachment_id, 0, b"v3-chunk")
            .expect("insert v3 chunk");
    }

    #[test]
    fn attachment_rows_are_cas_safe_and_parent_delete_cascades_chunks() {
        let dir = tempdir().expect("temp directory");
        let storage = VaultStorage::open(dir.path().join("vault.sqlite3")).expect("open storage");
        let attachment_id = Uuid::new_v4();

        storage
            .insert_attachment(attachment_id, 1, b"env-one")
            .expect("insert attachment");
        storage
            .insert_attachment_chunk(attachment_id, 1, b"chunk-one")
            .expect("insert second chunk");
        storage
            .insert_attachment_chunk(attachment_id, 0, b"chunk-zero")
            .expect("insert first chunk");

        assert_eq!(
            storage
                .list_attachment_chunks(attachment_id)
                .expect("list chunks"),
            vec![(0, b"chunk-zero".to_vec()), (1, b"chunk-one".to_vec())]
        );
        assert_eq!(
            storage.attachment_storage_bytes().expect("storage bytes"),
            (b"env-one".len() + b"chunk-zero".len() + b"chunk-one".len()) as u64
        );
        assert_eq!(
            storage.list_attachment_ids().expect("list attachment ids"),
            vec![attachment_id]
        );
        assert_eq!(
            storage
                .delete_attachment_chunks(attachment_id)
                .expect("delete chunks"),
            2
        );
        assert!(
            storage
                .list_attachment_chunks(attachment_id)
                .expect("list deleted chunks")
                .is_empty()
        );
        storage
            .insert_attachment_chunk(attachment_id, 0, b"chunk-zero")
            .expect("restore first chunk");
        storage
            .insert_attachment_chunk(attachment_id, 1, b"chunk-one")
            .expect("restore second chunk");

        storage
            .update_attachment_if_revision(attachment_id, 2, 1, b"env-two")
            .expect("advance attachment revision");
        assert!(matches!(
            storage.update_attachment_if_revision(attachment_id, 3, 1, b"stale"),
            Err(StorageError::StaleRevision)
        ));
        assert_eq!(
            storage
                .load_attachment(attachment_id)
                .expect("load attachment"),
            (2, b"env-two".to_vec())
        );

        storage
            .connection
            .execute(
                "DELETE FROM encrypted_attachments WHERE attachment_id = ?1",
                params![attachment_id.to_string()],
            )
            .expect("physically delete attachment in storage-only cascade test");
        assert!(matches!(
            storage.load_attachment(attachment_id),
            Err(StorageError::AttachmentNotFound)
        ));
        assert!(
            storage
                .list_attachment_chunks(attachment_id)
                .expect("list cascaded chunks")
                .is_empty()
        );
        assert_eq!(storage.attachment_storage_bytes().expect("empty bytes"), 0);
    }

    #[test]
    fn attachment_item_mutation_is_atomic_across_stale_parent_cas() {
        let dir = tempdir().expect("temp directory");
        let storage = VaultStorage::open(dir.path().join("vault.sqlite3")).expect("open storage");
        let root = AccountRootKey::generate().expect("root key");
        let mut item = VaultItem::secure_note("with attachment", "body");
        let current = encrypt_item(&root, &item, 1).expect("encrypt current item");
        storage.upsert_item(&current).expect("store current item");

        let attachment_id = Uuid::new_v4();
        item.attachments.push(attachment_id);
        let with_attachment = encrypt_item(&root, &item, 2).expect("encrypt linked item");
        let chunks = vec![(0, b"chunk-a".to_vec()), (1, b"chunk-b".to_vec())];
        storage
            .insert_attachment_and_update_item_if_revision(
                &with_attachment,
                1,
                attachment_id,
                1,
                b"attachment-envelope",
                &chunks,
            )
            .expect("atomically link attachment");
        assert_eq!(
            storage
                .load_item(item.id)
                .expect("load linked item")
                .revision,
            2
        );

        let orphan_candidate = Uuid::new_v4();
        let mut stale_parent = item.clone();
        stale_parent.attachments.push(orphan_candidate);
        let stale_parent = encrypt_item(&root, &stale_parent, 3).expect("encrypt stale parent");
        assert!(matches!(
            storage.insert_attachment_and_update_item_if_revision(
                &stale_parent,
                1,
                orphan_candidate,
                1,
                b"must-rollback",
                &[(0, b"must-rollback-chunk".to_vec())],
            ),
            Err(StorageError::StaleRevision)
        ));
        assert!(matches!(
            storage.load_attachment(orphan_candidate),
            Err(StorageError::AttachmentNotFound)
        ));
        assert!(
            storage
                .list_attachment_chunks(orphan_candidate)
                .expect("rolled-back chunks")
                .is_empty()
        );

        let second_attachment = Uuid::new_v4();
        item.attachments.push(second_attachment);
        let with_two_attachments = encrypt_item(&root, &item, 3).expect("encrypt second link");
        storage
            .insert_attachment_and_update_item_if_revision(
                &with_two_attachments,
                2,
                second_attachment,
                1,
                b"second-envelope",
                &[(0, b"second-chunk".to_vec())],
            )
            .expect("atomically link second attachment");

        item.attachments.clear();
        let without_attachments = encrypt_item(&root, &item, 4).expect("encrypt unlinked item");
        let stale_tombstones = vec![
            (attachment_id, 2, 1, b"first-tombstone".to_vec()),
            (second_attachment, 2, 0, b"second-tombstone".to_vec()),
        ];
        assert!(matches!(
            storage.tombstone_attachments_and_update_item_if_revision(
                &without_attachments,
                3,
                &stale_tombstones,
            ),
            Err(StorageError::StaleRevision)
        ));
        assert_eq!(
            storage
                .load_item(item.id)
                .expect("parent CAS rolled back")
                .revision,
            3
        );
        assert_eq!(
            storage
                .load_attachment(attachment_id)
                .expect("first tombstone rolled back"),
            (1, b"attachment-envelope".to_vec())
        );
        assert_eq!(
            storage
                .list_attachment_chunks(attachment_id)
                .expect("first chunks rolled back"),
            chunks
        );

        let tombstones = vec![
            (attachment_id, 2, 1, b"first-tombstone".to_vec()),
            (second_attachment, 2, 1, b"second-tombstone".to_vec()),
        ];
        storage
            .tombstone_attachments_and_update_item_if_revision(&without_attachments, 3, &tombstones)
            .expect("atomically tombstone attachments");
        assert_eq!(
            storage
                .load_item(item.id)
                .expect("load unlinked item")
                .revision,
            4
        );
        assert_eq!(
            storage
                .load_attachment(attachment_id)
                .expect("load first tombstone"),
            (2, b"first-tombstone".to_vec())
        );
        assert_eq!(
            storage
                .load_attachment(second_attachment)
                .expect("load second tombstone"),
            (2, b"second-tombstone".to_vec())
        );
        assert!(
            storage
                .list_attachment_chunks(attachment_id)
                .expect("first tombstone chunks")
                .is_empty()
        );
        assert!(
            storage
                .list_attachment_chunks(second_attachment)
                .expect("second tombstone chunks")
                .is_empty()
        );
    }

    #[test]
    fn attachment_commit_rejects_global_object_limit_before_parent_mutation() {
        let dir = tempdir().expect("temp directory");
        let storage = VaultStorage::open(dir.path().join("vault.sqlite3")).expect("open storage");
        let root = AccountRootKey::generate().expect("root key");
        let item = VaultItem::secure_note("owner", "body");
        let current = encrypt_item(&root, &item, 1).expect("encrypt current item");
        storage.upsert_item(&current).expect("store current item");
        seed_zero_blob_attachment_rows(&storage, ATTACHMENT_MAX_OBJECTS);

        let candidate_attachment = Uuid::from_u128(u128::from(ATTACHMENT_MAX_OBJECTS) + 10_000);
        let mut linked_item = item.clone();
        linked_item.attachments.push(candidate_attachment);
        let linked_item = encrypt_item(&root, &linked_item, 2).expect("encrypt linked item");

        assert!(matches!(
            storage.insert_attachment_and_update_item_if_revision(
                &linked_item,
                1,
                candidate_attachment,
                1,
                b"candidate-record",
                &[],
            ),
            Err(StorageError::AttachmentObjectLimitReached)
        ));
        assert_eq!(
            storage
                .load_item(item.id)
                .expect("parent remains unchanged")
                .revision,
            1
        );
        assert!(matches!(
            storage.load_attachment(candidate_attachment),
            Err(StorageError::AttachmentNotFound)
        ));
        let attachment_count: i64 = storage
            .connection
            .query_row("SELECT COUNT(*) FROM encrypted_attachments", [], |row| {
                row.get(0)
            })
            .expect("count attachment rows after rejected commit");
        assert_eq!(attachment_count, ATTACHMENT_MAX_OBJECTS as i64);
    }

    #[test]
    fn replace_from_database_replaces_attachment_rows_and_chunks() {
        let dir = tempdir().expect("temp directory");
        let current_path = dir.path().join("current.sqlite3");
        let restore_path = dir.path().join("restore.sqlite3");
        let current = VaultStorage::open(&current_path).expect("open current storage");
        let old_attachment = Uuid::new_v4();
        current
            .insert_attachment(old_attachment, 1, b"old-envelope")
            .expect("insert old attachment");
        current
            .insert_attachment_chunk(old_attachment, 0, b"old-chunk")
            .expect("insert old chunk");

        let restored_attachment = Uuid::new_v4();
        {
            let restore = VaultStorage::open(&restore_path).expect("open restore storage");
            restore
                .insert_attachment(restored_attachment, 4, b"restored-envelope")
                .expect("insert restored attachment");
            restore
                .insert_attachment_chunk(restored_attachment, 0, b"restored-zero")
                .expect("insert restored chunk zero");
            restore
                .insert_attachment_chunk(restored_attachment, 1, b"restored-one")
                .expect("insert restored chunk one");
        }

        current
            .replace_from_database(&restore_path)
            .expect("replace from restore database");

        assert!(matches!(
            current.load_attachment(old_attachment),
            Err(StorageError::AttachmentNotFound)
        ));
        assert_eq!(
            current
                .load_attachment(restored_attachment)
                .expect("load restored attachment"),
            (4, b"restored-envelope".to_vec())
        );
        assert_eq!(
            current
                .list_attachment_chunks(restored_attachment)
                .expect("load restored chunks"),
            vec![
                (0, b"restored-zero".to_vec()),
                (1, b"restored-one".to_vec())
            ]
        );
    }

    #[test]
    fn bounded_attachment_reads_reject_oversized_tampered_blobs_and_chunk_counts() {
        let dir = tempdir().expect("temp directory");
        let storage = VaultStorage::open(dir.path().join("vault.sqlite3")).expect("open storage");
        let attachment_id = Uuid::new_v4();
        storage
            .insert_attachment(attachment_id, 1, b"bounded-record")
            .expect("insert attachment");

        let oversized_record = i64::try_from(ATTACHMENT_MAX_ENCRYPTED_RECORD_BYTES + 1)
            .expect("record limit fits sqlite integer");
        storage
            .connection
            .execute(
                "UPDATE encrypted_attachments SET encrypted_record = zeroblob(?1) WHERE attachment_id = ?2",
                params![oversized_record, attachment_id.to_string()],
            )
            .expect("tamper oversized attachment record");
        assert!(matches!(
            storage.load_attachment(attachment_id),
            Err(StorageError::InconsistentEncryptedRow)
        ));

        storage
            .connection
            .execute(
                "UPDATE encrypted_attachments SET encrypted_record = ?1 WHERE attachment_id = ?2",
                params![b"bounded-record".as_slice(), attachment_id.to_string()],
            )
            .expect("restore bounded attachment record");
        let oversized_chunk = i64::try_from(ATTACHMENT_MAX_CHUNK_CIPHERTEXT_BYTES + 1)
            .expect("chunk limit fits sqlite integer");
        storage
            .connection
            .execute(
                "INSERT INTO attachment_chunks(attachment_id, chunk_index, ciphertext) VALUES (?1, 0, zeroblob(?2))",
                params![attachment_id.to_string(), oversized_chunk],
            )
            .expect("tamper oversized attachment chunk");
        assert!(matches!(
            storage.list_attachment_chunks(attachment_id),
            Err(StorageError::InconsistentEncryptedRow)
        ));

        storage
            .connection
            .execute(
                "DELETE FROM attachment_chunks WHERE attachment_id = ?1",
                params![attachment_id.to_string()],
            )
            .expect("clear oversized chunk");
        for chunk_index in 0..=ATTACHMENT_MAX_CHUNKS {
            storage
                .connection
                .execute(
                    "INSERT INTO attachment_chunks(attachment_id, chunk_index, ciphertext) VALUES (?1, ?2, ?3)",
                    params![
                        attachment_id.to_string(),
                        i64::try_from(chunk_index).expect("chunk index fits sqlite integer"),
                        b"x".as_slice()
                    ],
                )
                .expect("tamper extra chunk row");
        }
        assert!(matches!(
            storage.list_attachment_chunks(attachment_id),
            Err(StorageError::InconsistentEncryptedRow)
        ));
    }

    #[test]
    fn list_attachment_ids_rejects_excessive_rows_before_materializing_ids() {
        let dir = tempdir().expect("temp directory");
        let storage = VaultStorage::open(dir.path().join("vault.sqlite3")).expect("open storage");
        seed_zero_blob_attachment_rows(&storage, ATTACHMENT_MAX_OBJECTS + 1);

        assert!(matches!(
            storage.list_attachment_ids(),
            Err(StorageError::InconsistentEncryptedRow)
        ));
    }

    #[test]
    fn replace_from_database_rejects_oversized_attachment_blob_before_mutation() {
        let dir = tempdir().expect("temp directory");
        let current_path = dir.path().join("current.sqlite3");
        let restore_path = dir.path().join("restore.sqlite3");
        let current = VaultStorage::open(&current_path).expect("open current storage");
        let current_attachment = Uuid::new_v4();
        current
            .insert_attachment(current_attachment, 1, b"current-record")
            .expect("insert current attachment");

        let restore_attachment = Uuid::new_v4();
        {
            let restore = VaultStorage::open(&restore_path).expect("open restore storage");
            restore
                .insert_attachment(restore_attachment, 1, b"restore-record")
                .expect("insert restore attachment");
        }
        let restore = Connection::open(&restore_path).expect("open raw restore database");
        let oversized_record = i64::try_from(ATTACHMENT_MAX_ENCRYPTED_RECORD_BYTES + 1)
            .expect("record limit fits sqlite integer");
        restore
            .execute(
                "UPDATE encrypted_attachments SET encrypted_record = zeroblob(?1) WHERE attachment_id = ?2",
                params![oversized_record, restore_attachment.to_string()],
            )
            .expect("tamper restore record");
        drop(restore);

        assert!(matches!(
            current.replace_from_database(&restore_path),
            Err(StorageError::InconsistentEncryptedRow)
        ));
        assert_eq!(
            current
                .load_attachment(current_attachment)
                .expect("current attachment remains after rejected restore"),
            (1, b"current-record".to_vec())
        );
        assert!(matches!(
            current.load_attachment(restore_attachment),
            Err(StorageError::AttachmentNotFound)
        ));
    }

    #[test]
    fn replace_from_database_rejects_excessive_attachment_rows_before_mutation() {
        let dir = tempdir().expect("temp directory");
        let current_path = dir.path().join("current.sqlite3");
        let restore_path = dir.path().join("restore.sqlite3");
        let current = VaultStorage::open(&current_path).expect("open current storage");
        let current_attachment = Uuid::new_v4();
        current
            .insert_attachment(current_attachment, 7, b"current-record")
            .expect("insert current attachment");

        {
            let restore = VaultStorage::open(&restore_path).expect("open restore storage");
            seed_zero_blob_attachment_rows(&restore, ATTACHMENT_MAX_OBJECTS + 1);
        }

        assert!(matches!(
            current.replace_from_database(&restore_path),
            Err(StorageError::InconsistentEncryptedRow)
        ));
        assert_eq!(
            current
                .load_attachment(current_attachment)
                .expect("live attachment survives rejected restore"),
            (7, b"current-record".to_vec())
        );
        assert_eq!(
            current
                .list_attachment_ids()
                .expect("list live attachments"),
            vec![current_attachment]
        );
    }

    #[test]
    fn list_item_ids_rejects_excessive_rows_before_materializing_ids() {
        let dir = tempdir().expect("temp directory");
        let storage = VaultStorage::open(dir.path().join("vault.sqlite3")).expect("open storage");
        seed_zero_blob_item_rows(&storage, ITEM_MAX_OBJECTS + 1);

        assert!(matches!(
            storage.list_item_ids(),
            Err(StorageError::InconsistentEncryptedRow)
        ));
        assert!(matches!(
            storage.validate_record_bounds(),
            Err(StorageError::InconsistentEncryptedRow)
        ));
    }

    #[test]
    fn core_wrap_loaders_reject_oversized_rows_before_materializing_blobs() {
        let dir = tempdir().expect("temp directory");
        let storage = VaultStorage::open(dir.path().join("vault.sqlite3")).expect("open storage");
        let root = AccountRootKey::generate().expect("root key");
        let root_wrap =
            wrap_root_key("a deliberately long test passphrase", &root).expect("wrap root key");
        storage
            .initialize_root_wrap(&root_wrap)
            .expect("initialize root wrap");

        let oversized_root = i64::try_from(ROOT_WRAP_MAX_ENCODED_BYTES + 1)
            .expect("root wrap bound fits sqlite integer");
        storage
            .connection
            .execute(
                "UPDATE vault_meta SET root_key_wrap = zeroblob(?1) WHERE singleton = 1",
                params![oversized_root],
            )
            .expect("tamper oversized root wrap");
        assert!(matches!(
            storage.load_root_wrap(),
            Err(StorageError::InconsistentEncryptedRow)
        ));
        assert!(matches!(
            storage.validate_record_bounds(),
            Err(StorageError::InconsistentEncryptedRow)
        ));

        storage
            .replace_root_wrap(&root_wrap)
            .expect("restore bounded root wrap");
        let recovery_secret = RecoverySecret::generate().expect("recovery secret");
        let recovery_wrap =
            wrap_root_key_with_recovery_secret(&recovery_secret, &root).expect("wrap recovery key");
        storage
            .store_recovery_wrap(&recovery_wrap)
            .expect("store recovery wrap");
        let oversized_recovery = i64::try_from(RECOVERY_WRAP_MAX_ENCODED_BYTES + 1)
            .expect("recovery wrap bound fits sqlite integer");
        storage
            .connection
            .execute(
                "UPDATE recovery_kit SET kit_wrap = zeroblob(?1) WHERE singleton = 1",
                params![oversized_recovery],
            )
            .expect("tamper oversized recovery wrap");
        assert!(matches!(
            storage.load_recovery_wrap(),
            Err(StorageError::InconsistentEncryptedRow)
        ));
        assert!(matches!(
            storage.validate_record_bounds(),
            Err(StorageError::InconsistentEncryptedRow)
        ));
    }

    #[test]
    fn replace_from_database_rejects_oversized_wraps_before_mutation() {
        let dir = tempdir().expect("temp directory");
        let current_path = dir.path().join("current.sqlite3");
        let restore_path = dir.path().join("restore.sqlite3");
        let current = VaultStorage::open(&current_path).expect("open current storage");
        let current_root = AccountRootKey::generate().expect("current root key");
        let current_wrap = wrap_root_key("a deliberately long current passphrase", &current_root)
            .expect("wrap current root key");
        current
            .initialize_root_wrap(&current_wrap)
            .expect("initialize current root wrap");

        let restore = VaultStorage::open(&restore_path).expect("open restore storage");
        let restore_root = AccountRootKey::generate().expect("restore root key");
        let restore_wrap = wrap_root_key("a deliberately long restore passphrase", &restore_root)
            .expect("wrap restore root key");
        restore
            .initialize_root_wrap(&restore_wrap)
            .expect("initialize restore root wrap");

        let oversized_root = i64::try_from(ROOT_WRAP_MAX_ENCODED_BYTES + 1)
            .expect("root wrap bound fits sqlite integer");
        restore
            .connection
            .execute(
                "UPDATE vault_meta SET root_key_wrap = zeroblob(?1) WHERE singleton = 1",
                params![oversized_root],
            )
            .expect("tamper restore root wrap");
        drop(restore);
        assert!(matches!(
            current.replace_from_database(&restore_path),
            Err(StorageError::InconsistentEncryptedRow)
        ));
        assert_eq!(
            current
                .load_root_wrap()
                .expect("current root wrap remains")
                .ciphertext,
            current_wrap.ciphertext
        );

        let restore = VaultStorage::open(&restore_path).expect("reopen restore storage");
        restore
            .replace_root_wrap(&restore_wrap)
            .expect("restore bounded candidate root wrap");
        let secret = RecoverySecret::generate().expect("candidate recovery secret");
        let recovery_wrap = wrap_root_key_with_recovery_secret(&secret, &restore_root)
            .expect("wrap candidate recovery key");
        restore
            .store_recovery_wrap(&recovery_wrap)
            .expect("store candidate recovery wrap");
        let oversized_recovery = i64::try_from(RECOVERY_WRAP_MAX_ENCODED_BYTES + 1)
            .expect("recovery wrap bound fits sqlite integer");
        restore
            .connection
            .execute(
                "UPDATE recovery_kit SET kit_wrap = zeroblob(?1) WHERE singleton = 1",
                params![oversized_recovery],
            )
            .expect("tamper restore recovery wrap");
        drop(restore);
        assert!(matches!(
            current.replace_from_database(&restore_path),
            Err(StorageError::InconsistentEncryptedRow)
        ));
        assert_eq!(
            current
                .load_root_wrap()
                .expect("current root wrap still remains")
                .ciphertext,
            current_wrap.ciphertext
        );
    }

    #[test]
    fn oversized_item_blob_is_rejected_before_load_and_restore_mutation() {
        let dir = tempdir().expect("temp directory");
        let current_path = dir.path().join("current.sqlite3");
        let restore_path = dir.path().join("restore.sqlite3");
        let current = VaultStorage::open(&current_path).expect("open current storage");
        let root = AccountRootKey::generate().expect("root key");
        let current_item = VaultItem::secure_note("current", "body");
        let current_encrypted =
            encrypt_item(&root, &current_item, 7).expect("encrypt current item");
        current
            .upsert_item(&current_encrypted)
            .expect("store current item");

        let restore = VaultStorage::open(&restore_path).expect("open restore storage");
        let restore_item = VaultItem::secure_note("restore", "body");
        let restore_encrypted =
            encrypt_item(&root, &restore_item, 1).expect("encrypt restore item");
        restore
            .upsert_item(&restore_encrypted)
            .expect("store restore item");
        let oversized_record = i64::try_from(ITEM_MAX_ENCRYPTED_RECORD_BYTES + 1)
            .expect("item record bound fits sqlite integer");
        restore
            .connection
            .execute(
                "UPDATE encrypted_items SET encrypted_record = zeroblob(?1) WHERE object_id = ?2",
                params![oversized_record, restore_item.id.to_string()],
            )
            .expect("tamper oversized item record");
        assert!(matches!(
            restore.load_item(restore_item.id),
            Err(StorageError::InconsistentEncryptedRow)
        ));
        assert!(matches!(
            restore.validate_record_bounds(),
            Err(StorageError::InconsistentEncryptedRow)
        ));
        drop(restore);

        assert!(matches!(
            current.replace_from_database(&restore_path),
            Err(StorageError::InconsistentEncryptedRow)
        ));
        assert_eq!(
            current
                .load_item(current_item.id)
                .expect("live item survives rejected restore")
                .revision,
            7
        );
        assert!(matches!(
            current.load_item(restore_item.id),
            Err(StorageError::ItemNotFound)
        ));
    }

    #[test]
    fn replace_from_database_rejects_excessive_item_rows_before_mutation() {
        let dir = tempdir().expect("temp directory");
        let current_path = dir.path().join("current.sqlite3");
        let restore_path = dir.path().join("restore.sqlite3");
        let current = VaultStorage::open(&current_path).expect("open current storage");
        let root = AccountRootKey::generate().expect("root key");
        let current_item = VaultItem::secure_note("current", "body");
        let current_encrypted =
            encrypt_item(&root, &current_item, 3).expect("encrypt current item");
        current
            .upsert_item(&current_encrypted)
            .expect("store current item");

        {
            let restore = VaultStorage::open(&restore_path).expect("open restore storage");
            seed_zero_blob_item_rows(&restore, ITEM_MAX_OBJECTS + 1);
        }

        assert!(matches!(
            current.replace_from_database(&restore_path),
            Err(StorageError::InconsistentEncryptedRow)
        ));
        assert_eq!(
            current
                .load_item(current_item.id)
                .expect("live item survives rejected restore")
                .revision,
            3
        );
    }

    #[test]
    fn fresh_database_supports_recovery_wrap_round_trip() {
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
