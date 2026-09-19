#![forbid(unsafe_code)]

pub mod reminders;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};
use thiserror::Error;
use uuid::Uuid;
use vault_crypto::{
    ATTACHMENT_CHUNK_SIZE, ATTACHMENT_MAX_FILENAME_CHARS, ATTACHMENT_MAX_PLAINTEXT_BYTES,
    AccountRootKey, AttachmentCipherContext, AttachmentManifestV1, CryptoError,
    EncryptedAttachmentV1, EncryptedItemV1, RecoveryKitWrapV1, RecoverySecret, decrypt_item,
    decrypt_item_state, encrypt_item, encrypt_item_state, open_attachment_manifest,
    recovery_secret_matches_root_key, seal_attachment_manifest, unwrap_root_key,
    unwrap_root_key_with_recovery_secret, wrap_root_key, wrap_root_key_with_recovery_secret,
};
use vault_models::{
    AccessPolicy, AccountClosurePlan, EMERGENCY_CARD_ID, EmergencyCard, ItemKind,
    LegacyDisposition, VaultItem, VaultItemState, VaultItemValidationError,
    carry_forward_trusted_identity_retirements,
    validate_emergency_card as validate_emergency_card_model, validate_trusted_devices_unpaired,
    validate_trusted_identity_continuity, validate_vault_item,
};
#[cfg(test)]
use vault_models::{MAX_FIELD_VALUE_CHARS, MAX_ITEM_NOTES_CHARS, MAX_ITEM_TITLE_CHARS};
use vault_sharing::{
    PairingChallengeV1, PairingProofV1, PairingVerifierState, SharingError,
    create_pairing_challenge, verify_pairing_proof,
};
use vault_storage::{RestoreSourceFingerprint, StorageError, VaultStorage};

const PASSWORD_LOWERCASE: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const PASSWORD_UPPERCASE: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const PASSWORD_DIGITS: &[u8] = b"23456789";
const PASSWORD_SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}:,.?";
const PASSWORD_ALL: &[u8] =
    b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+[]{}:,.?";
const PASSWORD_MIN_LENGTH: usize = 12;
const PASSWORD_MAX_LENGTH: usize = 128;
const MAX_ITEM_ATTACHMENTS: usize = 16;
const MAX_ATTACHMENT_STORAGE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PENDING_TRUSTED_DEVICE_PAIRINGS: usize = 16;

#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentSummary {
    pub id: Uuid,
    pub revision: u64,
    pub filename: String,
    pub plaintext_size: u64,
}

pub struct AttachmentImportSource {
    file: File,
    filename: String,
    plaintext_size: u64,
}

impl AttachmentImportSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, VaultError> {
        let path = path.as_ref();
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(VaultError::InvalidAttachmentSource);
        }
        let plaintext_size = metadata.len();
        if plaintext_size > ATTACHMENT_MAX_PLAINTEXT_BYTES {
            return Err(VaultError::AttachmentTooLarge);
        }
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| {
                !name.is_empty() && name.chars().count() <= ATTACHMENT_MAX_FILENAME_CHARS
            })
            .ok_or(VaultError::InvalidAttachmentSource)?
            .to_owned();
        Ok(Self {
            file,
            filename,
            plaintext_size,
        })
    }

    fn validate_open_handle(&self) -> Result<(), VaultError> {
        let metadata = self.file.metadata()?;
        if !metadata.file_type().is_file() || metadata.len() != self.plaintext_size {
            return Err(VaultError::InvalidAttachmentSource);
        }
        Ok(())
    }
}

pub struct AttachmentImportPlan {
    summary: AttachmentSummary,
    expected_item_revision: u64,
    item_revision: u64,
    encrypted_item: EncryptedItemV1,
    encrypted_record: Vec<u8>,
    encryptor: AttachmentCipherContext,
}

pub struct PreparedAttachmentImport {
    summary: AttachmentSummary,
    expected_item_revision: u64,
    item_revision: u64,
    encrypted_item: EncryptedItemV1,
    encrypted_record: Vec<u8>,
    chunks: Vec<(u32, Vec<u8>)>,
}

impl AttachmentImportPlan {
    pub fn encrypt_source<F>(
        self,
        mut source: AttachmentImportSource,
        mut cancelled: F,
    ) -> Result<PreparedAttachmentImport, VaultError>
    where
        F: FnMut() -> bool,
    {
        if source.filename != self.summary.filename
            || source.plaintext_size != self.summary.plaintext_size
        {
            return Err(VaultError::InvalidAttachmentSource);
        }
        source.validate_open_handle()?;
        if cancelled() {
            return Err(VaultError::AttachmentOperationCancelled);
        }

        let chunk_count = attachment_chunk_count(self.summary.plaintext_size);
        let mut chunks = Vec::with_capacity(
            usize::try_from(chunk_count).map_err(|_| VaultError::AttachmentTooLarge)?,
        );
        let mut bytes_read = 0u64;
        for index in 0..chunk_count {
            if cancelled() {
                return Err(VaultError::AttachmentOperationCancelled);
            }
            let remaining = self
                .summary
                .plaintext_size
                .checked_sub(bytes_read)
                .ok_or(VaultError::InconsistentAttachment)?;
            let len = usize::try_from(remaining.min(ATTACHMENT_CHUNK_SIZE))
                .map_err(|_| VaultError::AttachmentTooLarge)?;
            let mut plaintext = vec![0u8; len];
            source.file.read_exact(&mut plaintext).map_err(|error| {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    VaultError::InvalidAttachmentSource
                } else {
                    VaultError::AttachmentIo(error)
                }
            })?;
            bytes_read = bytes_read
                .checked_add(u64::try_from(len).map_err(|_| VaultError::AttachmentTooLarge)?)
                .ok_or(VaultError::AttachmentTooLarge)?;
            let ciphertext = self.encryptor.encrypt_chunk(index, &plaintext)?;
            let index = u32::try_from(index).map_err(|_| VaultError::AttachmentTooLarge)?;
            chunks.push((index, ciphertext));
            if cancelled() {
                return Err(VaultError::AttachmentOperationCancelled);
            }
        }

        let mut extra = [0u8; 1];
        if bytes_read != self.summary.plaintext_size || source.file.read(&mut extra)? != 0 {
            return Err(VaultError::InvalidAttachmentSource);
        }
        source.validate_open_handle()?;
        if cancelled() {
            return Err(VaultError::AttachmentOperationCancelled);
        }

        Ok(PreparedAttachmentImport {
            summary: self.summary,
            expected_item_revision: self.expected_item_revision,
            item_revision: self.item_revision,
            encrypted_item: self.encrypted_item,
            encrypted_record: self.encrypted_record,
            chunks,
        })
    }
}

pub struct AttachmentExportPlan {
    plaintext_size: u64,
    context: AttachmentCipherContext,
    chunks: Vec<(u32, Vec<u8>)>,
}

pub struct VaultBackupPlan {
    source_path: PathBuf,
    recovery_secret: RecoverySecret,
    wrapped_root_key: RecoveryKitWrapV1,
}

impl VaultBackupPlan {
    pub fn write_validated_to<F>(
        self,
        path: impl AsRef<Path>,
        mut cancelled: F,
    ) -> Result<(), VaultError>
    where
        F: FnMut() -> bool,
    {
        if cancelled() {
            return Err(VaultError::OperationCancelled);
        }
        let source_storage = VaultStorage::open(&self.source_path)?;
        source_storage.backup_to(&path)?;
        if cancelled() {
            return Err(VaultError::OperationCancelled);
        }
        let backup_storage = VaultStorage::open(&path)?;
        backup_storage.validate_integrity()?;
        backup_storage.validate_record_bounds()?;
        if cancelled() {
            return Err(VaultError::OperationCancelled);
        }
        let root_key =
            unwrap_root_key_with_recovery_secret(&self.recovery_secret, &self.wrapped_root_key)?;
        validate_storage_contents_with_cancel(&backup_storage, &root_key, &mut cancelled)?;
        let _ = backup_storage.load_recovery_wrap()?;
        if cancelled() {
            return Err(VaultError::OperationCancelled);
        }
        Ok(())
    }
}

pub struct PreparedVaultRestore {
    backup_path: PathBuf,
    root_key: AccountRootKey,
    source_fingerprint: RestoreSourceFingerprint,
}

pub struct LockedVaultRestore {
    backup_path: PathBuf,
    source_fingerprint: RestoreSourceFingerprint,
}

impl PreparedVaultRestore {
    /// Rewraps the already-authenticated restore candidate under a new master
    /// passphrase before installation. Callers must only use this on a staged
    /// candidate copy, never on the user's source backup file.
    pub fn rewrap_candidate_master_passphrase(
        mut self,
        new_passphrase: &str,
    ) -> Result<Self, VaultError> {
        if new_passphrase.chars().count() < 12 {
            return Err(VaultError::PassphraseTooShort);
        }
        let wrapped = wrap_root_key(new_passphrase, &self.root_key)?;
        self.source_fingerprint = VaultStorage::rewrap_restore_source_if_fingerprint(
            &self.backup_path,
            &self.source_fingerprint,
            &wrapped,
        )?;
        Ok(self)
    }

    pub fn install_to(self, live_path: impl AsRef<Path>) -> Result<VaultSession, VaultError> {
        let storage = VaultStorage::open(live_path)?;
        storage
            .replace_from_database_if_fingerprint(&self.backup_path, &self.source_fingerprint)?;
        Ok(VaultSession {
            storage,
            root_key: self.root_key,
            pending_pairings: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn into_locked_install(self) -> LockedVaultRestore {
        let Self {
            backup_path,
            root_key,
            source_fingerprint,
        } = self;
        drop(root_key);
        LockedVaultRestore {
            backup_path,
            source_fingerprint,
        }
    }
}

impl LockedVaultRestore {
    pub fn install_to(self, live_path: impl AsRef<Path>) -> Result<(), VaultError> {
        let storage = VaultStorage::open(live_path)?;
        storage
            .replace_from_database_if_fingerprint(&self.backup_path, &self.source_fingerprint)?;
        Ok(())
    }
}

impl AttachmentExportPlan {
    pub fn write_to_path<F>(
        self,
        output_path: impl AsRef<Path>,
        mut cancelled: F,
    ) -> Result<(), VaultError>
    where
        F: FnMut() -> bool,
    {
        if cancelled() {
            return Err(VaultError::AttachmentOperationCancelled);
        }
        let output_path = output_path.as_ref();
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    VaultError::AttachmentOutputExists
                } else {
                    VaultError::AttachmentIo(error)
                }
            })?;
        let export_result = (|| -> Result<(), VaultError> {
            let mut total_plaintext = 0u64;
            for (expected_index, (stored_index, ciphertext)) in self.chunks.iter().enumerate() {
                let expected_index = u32::try_from(expected_index)
                    .map_err(|_| VaultError::InconsistentAttachment)?;
                if *stored_index != expected_index {
                    return Err(VaultError::InconsistentAttachment);
                }
                if cancelled() {
                    return Err(VaultError::AttachmentOperationCancelled);
                }
                let plaintext = self
                    .context
                    .decrypt_chunk(u64::from(*stored_index), ciphertext)?;
                if cancelled() {
                    return Err(VaultError::AttachmentOperationCancelled);
                }
                total_plaintext = total_plaintext
                    .checked_add(
                        u64::try_from(plaintext.len())
                            .map_err(|_| VaultError::InconsistentAttachment)?,
                    )
                    .ok_or(VaultError::InconsistentAttachment)?;
                output.write_all(&plaintext)?;
            }
            if total_plaintext != self.plaintext_size {
                return Err(VaultError::InconsistentAttachment);
            }
            if cancelled() {
                return Err(VaultError::AttachmentOperationCancelled);
            }
            output.sync_all()?;
            if cancelled() {
                return Err(VaultError::AttachmentOperationCancelled);
            }
            Ok(())
        })();
        drop(output);
        if export_result.is_err() {
            let _ = fs::remove_file(output_path);
        }
        export_result
    }
}

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
    #[error("attachment references are managed by attachment operations")]
    AttachmentReferencesManagedSeparately,
    #[error("attachment source must be a regular file with a valid filename")]
    InvalidAttachmentSource,
    #[error("attachment exceeds the supported file-size limit")]
    AttachmentTooLarge,
    #[error("item has reached the attachment limit")]
    AttachmentLimitReached,
    #[error("vault has reached the attachment storage limit")]
    AttachmentStorageLimitReached,
    #[error("attachment is not owned by this active item")]
    AttachmentNotOwned,
    #[error("attachment data is inconsistent")]
    InconsistentAttachment,
    #[error("attachment output already exists")]
    AttachmentOutputExists,
    #[error("attachment operation was cancelled")]
    AttachmentOperationCancelled,
    #[error("vault operation was cancelled")]
    OperationCancelled,
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
    #[error("trusted-device pairing state is unavailable")]
    PairingStateUnavailable,
    #[error("version history is not available for this item")]
    HistoryNotAvailable,
    #[error("attachment file operation failed")]
    AttachmentIo(#[from] std::io::Error),
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
    pending_pairings: Mutex<BTreeMap<Uuid, PendingTrustedDevicePairing>>,
}

struct PendingTrustedDevicePairing {
    package: PairingChallengeV1,
    state: PairingVerifierState,
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
        Ok(Self {
            storage,
            root_key,
            pending_pairings: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn unlock(path: impl AsRef<Path>, passphrase: &str) -> Result<Self, VaultError> {
        let storage = VaultStorage::open(path)?;
        let wrapped = storage.load_root_wrap()?;
        let root_key = unwrap_root_key(passphrase, &wrapped)?;
        Ok(Self {
            storage,
            root_key,
            pending_pairings: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn put_item(&self, item: &VaultItem, revision: u64) -> Result<(), VaultError> {
        if item.id == EMERGENCY_CARD_ID {
            return Err(VaultError::ReservedSystemItem);
        }
        if !item.attachments.is_empty() {
            return Err(VaultError::AttachmentReferencesManagedSeparately);
        }
        validate_item(item)?;
        let encrypted = encrypt_item(&self.root_key, item, revision)?;
        self.storage.insert_item(&encrypted)?;
        Ok(())
    }

    pub fn update_item(&self, item: &VaultItem, expected_revision: u64) -> Result<u64, VaultError> {
        if item.id == EMERGENCY_CARD_ID {
            return Err(VaultError::ReservedSystemItem);
        }
        validate_item(item)?;
        let (state, current_revision) = self.get_state_with_revision(item.id)?;
        if current_revision != expected_revision {
            return Err(VaultError::Storage(StorageError::StaleRevision));
        }
        let VaultItemState::Active { item: current } = state else {
            return Err(VaultError::ItemNotActive);
        };
        if item.attachments != current.attachments {
            return Err(VaultError::AttachmentReferencesManagedSeparately);
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or(VaultError::RevisionExhausted)?;
        let encrypted = encrypt_item(&self.root_key, item, revision)?;
        if item.id == EMERGENCY_CARD_ID {
            self.storage
                .update_item_if_revision(&encrypted, expected_revision)?;
        } else {
            self.storage
                .update_item_with_history_if_revision(&encrypted, expected_revision)?;
        }
        Ok(revision)
    }

    pub fn add_attachment_from_path(
        &self,
        owner_item_id: Uuid,
        expected_item_revision: u64,
        path: impl AsRef<Path>,
    ) -> Result<(AttachmentSummary, u64), VaultError> {
        let source = AttachmentImportSource::open(path)?;
        let plan =
            self.prepare_attachment_import(owner_item_id, expected_item_revision, &source)?;
        let prepared = plan.encrypt_source(source, || false)?;
        self.commit_attachment_import(prepared)
    }

    pub fn prepare_attachment_import(
        &self,
        owner_item_id: Uuid,
        expected_item_revision: u64,
        source: &AttachmentImportSource,
    ) -> Result<AttachmentImportPlan, VaultError> {
        if owner_item_id == EMERGENCY_CARD_ID {
            return Err(VaultError::AttachmentNotOwned);
        }
        let (state, current_revision) = self.get_state_with_revision(owner_item_id)?;
        if current_revision != expected_item_revision {
            return Err(VaultError::Storage(StorageError::StaleRevision));
        }
        let VaultItemState::Active { mut item } = state else {
            return Err(VaultError::ItemNotActive);
        };
        if item.attachments.len() >= MAX_ITEM_ATTACHMENTS {
            return Err(VaultError::AttachmentLimitReached);
        }

        let attachment_id = Uuid::new_v4();
        let chunk_count = attachment_chunk_count(source.plaintext_size);
        let manifest = AttachmentManifestV1::Active {
            attachment_id,
            owner_item_id,
            filename: source.filename.clone(),
            plaintext_size: source.plaintext_size,
            chunk_size: ATTACHMENT_CHUNK_SIZE,
            chunk_count,
        };
        let (encrypted_attachment, encryptor) =
            seal_attachment_manifest(&self.root_key, &manifest, 1)?;
        let encryptor = encryptor.ok_or(VaultError::InconsistentAttachment)?;
        let encrypted_record =
            serde_json::to_vec(&encrypted_attachment).map_err(CryptoError::Serialization)?;
        item.attachments.push(attachment_id);
        validate_item(&item)?;
        let item_revision = expected_item_revision
            .checked_add(1)
            .ok_or(VaultError::RevisionExhausted)?;
        let encrypted_item = encrypt_item(&self.root_key, &item, item_revision)?;

        Ok(AttachmentImportPlan {
            summary: AttachmentSummary {
                id: attachment_id,
                revision: 1,
                filename: source.filename.clone(),
                plaintext_size: source.plaintext_size,
            },
            expected_item_revision,
            item_revision,
            encrypted_item,
            encrypted_record,
            encryptor,
        })
    }

    pub fn commit_attachment_import(
        &self,
        prepared: PreparedAttachmentImport,
    ) -> Result<(AttachmentSummary, u64), VaultError> {
        let added_bytes = prepared.chunks.iter().try_fold(
            u64::try_from(prepared.encrypted_record.len())
                .map_err(|_| VaultError::AttachmentTooLarge)?,
            |total, (_, chunk)| {
                total
                    .checked_add(
                        u64::try_from(chunk.len()).map_err(|_| VaultError::AttachmentTooLarge)?,
                    )
                    .ok_or(VaultError::AttachmentTooLarge)
            },
        )?;
        let total_attachment_storage = self
            .storage
            .attachment_storage_bytes()?
            .checked_add(added_bytes)
            .ok_or(VaultError::AttachmentStorageLimitReached)?;
        validate_attachment_storage_bytes(total_attachment_storage)?;

        match self.storage.insert_attachment_and_update_item_if_revision(
            &prepared.encrypted_item,
            prepared.expected_item_revision,
            prepared.summary.id,
            prepared.summary.revision,
            &prepared.encrypted_record,
            &prepared.chunks,
        ) {
            Ok(()) => {}
            Err(StorageError::AttachmentObjectLimitReached) => {
                return Err(VaultError::AttachmentStorageLimitReached);
            }
            Err(error) => return Err(VaultError::Storage(error)),
        }
        Ok((prepared.summary, prepared.item_revision))
    }

    pub fn list_attachments(
        &self,
        owner_item_id: Uuid,
    ) -> Result<Vec<AttachmentSummary>, VaultError> {
        let (state, _revision) = self.get_state_with_revision(owner_item_id)?;
        let VaultItemState::Active { item } = state else {
            return Err(VaultError::ItemNotActive);
        };
        let mut summaries = Vec::with_capacity(item.attachments.len());
        for attachment_id in item.attachments {
            let (revision, encrypted_record) = self.storage.load_attachment(attachment_id)?;
            let encrypted = decode_attachment_record(attachment_id, revision, &encrypted_record)?;
            let (manifest, _context) = open_attachment_manifest(&self.root_key, &encrypted)?;
            let AttachmentManifestV1::Active {
                owner_item_id: manifest_owner,
                filename,
                plaintext_size,
                ..
            } = manifest
            else {
                return Err(VaultError::InconsistentAttachment);
            };
            if manifest_owner != owner_item_id {
                return Err(VaultError::AttachmentNotOwned);
            }
            summaries.push(AttachmentSummary {
                id: attachment_id,
                revision,
                filename,
                plaintext_size,
            });
        }
        Ok(summaries)
    }

    pub fn export_attachment_to(
        &self,
        owner_item_id: Uuid,
        attachment_id: Uuid,
        output_path: impl AsRef<Path>,
    ) -> Result<(), VaultError> {
        let plan = self.prepare_attachment_export(owner_item_id, attachment_id)?;
        plan.write_to_path(output_path, || false)
    }

    pub fn prepare_attachment_export(
        &self,
        owner_item_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<AttachmentExportPlan, VaultError> {
        let (state, _revision) = self.get_state_with_revision(owner_item_id)?;
        let VaultItemState::Active { item } = state else {
            return Err(VaultError::ItemNotActive);
        };
        if !item.attachments.contains(&attachment_id) {
            return Err(VaultError::AttachmentNotOwned);
        }

        let (revision, encrypted_record) = self.storage.load_attachment(attachment_id)?;
        let encrypted = decode_attachment_record(attachment_id, revision, &encrypted_record)?;
        let (manifest, context) = open_attachment_manifest(&self.root_key, &encrypted)?;
        let AttachmentManifestV1::Active {
            owner_item_id: manifest_owner,
            plaintext_size,
            chunk_count,
            ..
        } = manifest
        else {
            return Err(VaultError::InconsistentAttachment);
        };
        if manifest_owner != owner_item_id {
            return Err(VaultError::AttachmentNotOwned);
        }
        let context = context.ok_or(VaultError::InconsistentAttachment)?;
        let chunks = self.storage.list_attachment_chunks(attachment_id)?;
        if chunks.len()
            != usize::try_from(chunk_count).map_err(|_| VaultError::InconsistentAttachment)?
        {
            return Err(VaultError::InconsistentAttachment);
        }
        for (expected_index, (stored_index, _)) in chunks.iter().enumerate() {
            let expected_index =
                u32::try_from(expected_index).map_err(|_| VaultError::InconsistentAttachment)?;
            if *stored_index != expected_index {
                return Err(VaultError::InconsistentAttachment);
            }
        }
        Ok(AttachmentExportPlan {
            plaintext_size,
            context,
            chunks,
        })
    }

    pub fn delete_attachment(
        &self,
        owner_item_id: Uuid,
        attachment_id: Uuid,
        expected_item_revision: u64,
        expected_attachment_revision: u64,
        deleted_at_ms: u64,
    ) -> Result<u64, VaultError> {
        let (state, current_item_revision) = self.get_state_with_revision(owner_item_id)?;
        if current_item_revision != expected_item_revision {
            return Err(VaultError::Storage(StorageError::StaleRevision));
        }
        let VaultItemState::Active { mut item } = state else {
            return Err(VaultError::ItemNotActive);
        };
        let Some(position) = item
            .attachments
            .iter()
            .position(|candidate| *candidate == attachment_id)
        else {
            return Err(VaultError::AttachmentNotOwned);
        };
        let (stored_revision, encrypted_record) = self.storage.load_attachment(attachment_id)?;
        if stored_revision != expected_attachment_revision {
            return Err(VaultError::Storage(StorageError::StaleRevision));
        }
        let encrypted =
            decode_attachment_record(attachment_id, stored_revision, &encrypted_record)?;
        let (manifest, _context) = open_attachment_manifest(&self.root_key, &encrypted)?;
        if !matches!(
            manifest,
            AttachmentManifestV1::Active { owner_item_id: owner, .. } if owner == owner_item_id
        ) {
            return Err(VaultError::AttachmentNotOwned);
        }

        item.attachments.remove(position);
        let item_revision = expected_item_revision
            .checked_add(1)
            .ok_or(VaultError::RevisionExhausted)?;
        let attachment_revision = expected_attachment_revision
            .checked_add(1)
            .ok_or(VaultError::RevisionExhausted)?;
        let encrypted_item = encrypt_item(&self.root_key, &item, item_revision)?;
        let tombstone_manifest = AttachmentManifestV1::Tombstone {
            attachment_id,
            owner_item_id,
            deleted_at_ms,
        };
        let (tombstone, context) =
            seal_attachment_manifest(&self.root_key, &tombstone_manifest, attachment_revision)?;
        if context.is_some() {
            return Err(VaultError::InconsistentAttachment);
        }
        let tombstone_record =
            serde_json::to_vec(&tombstone).map_err(CryptoError::Serialization)?;
        self.storage
            .tombstone_attachments_and_update_item_with_history_if_revision(
                &encrypted_item,
                expected_item_revision,
                &[(
                    attachment_id,
                    attachment_revision,
                    expected_attachment_revision,
                    tombstone_record,
                )],
            )?;
        Ok(item_revision)
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

    pub fn list_item_history_revisions(
        &self,
        id: Uuid,
        expected_current_revision: u64,
    ) -> Result<Vec<u64>, VaultError> {
        let current_revision = self.history_owner_revision(id, expected_current_revision)?;
        let revisions = self.storage.list_item_history_revisions(id)?;
        if revisions
            .iter()
            .any(|revision| *revision >= current_revision)
        {
            return Err(VaultError::Storage(StorageError::InconsistentEncryptedRow));
        }
        Ok(revisions)
    }

    pub fn get_item_history(
        &self,
        id: Uuid,
        expected_current_revision: u64,
        historical_revision: u64,
    ) -> Result<VaultItem, VaultError> {
        let current_revision = self.history_owner_revision(id, expected_current_revision)?;
        if historical_revision >= current_revision {
            return Err(VaultError::HistoryNotAvailable);
        }
        let encrypted = match self.storage.load_item_history(id, historical_revision) {
            Ok(encrypted) => encrypted,
            Err(StorageError::ItemNotFound) => return Err(VaultError::HistoryNotAvailable),
            Err(error) => return Err(VaultError::Storage(error)),
        };
        let item = decrypt_item(&self.root_key, &encrypted)?;
        validate_item(&item)?;
        Ok(item)
    }

    pub fn set_legacy_disposition(
        &self,
        id: Uuid,
        expected_revision: u64,
        disposition: LegacyDisposition,
    ) -> Result<u64, VaultError> {
        if id == EMERGENCY_CARD_ID {
            return Err(VaultError::InvalidLegacyDisposition);
        }
        let (mut item, current_revision) = self.get_item_with_revision(id)?;
        if current_revision != expected_revision {
            return Err(VaultError::Storage(StorageError::StaleRevision));
        }
        item.legacy_disposition = disposition;
        self.update_item(&item, expected_revision)
    }

    pub fn set_account_closure_plan(
        &self,
        id: Uuid,
        expected_revision: u64,
        plan: AccountClosurePlan,
    ) -> Result<u64, VaultError> {
        if id == EMERGENCY_CARD_ID {
            return Err(VaultError::InvalidAccountClosurePlan);
        }
        let (mut item, current_revision) = self.get_item_with_revision(id)?;
        if current_revision != expected_revision {
            return Err(VaultError::Storage(StorageError::StaleRevision));
        }
        if item.kind != ItemKind::Password {
            return Err(VaultError::InvalidAccountClosurePlan);
        }
        item.account_closure_plan = plan;
        self.update_item(&item, expected_revision)
    }

    pub fn set_access_policy(
        &self,
        id: Uuid,
        expected_revision: u64,
        policy: AccessPolicy,
    ) -> Result<u64, VaultError> {
        let (mut item, current_revision) = self.get_item_with_revision(id)?;
        if current_revision != expected_revision {
            return Err(VaultError::Storage(StorageError::StaleRevision));
        }
        item.access_policy = policy;
        if id == EMERGENCY_CARD_ID {
            let card = item
                .parse_emergency_card()
                .ok_or(VaultError::InvalidTrustedPrincipal)?;
            validate_emergency_card(&card)?;
            validate_item(&item)?;
            let revision = expected_revision
                .checked_add(1)
                .ok_or(VaultError::RevisionExhausted)?;
            let encrypted = encrypt_item(&self.root_key, &item, revision)?;
            self.storage
                .update_item_if_revision(&encrypted, expected_revision)?;
            return Ok(revision);
        }
        self.update_item(&item, expected_revision)
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
        if id == EMERGENCY_CARD_ID {
            return Err(VaultError::ReservedSystemItem);
        }
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
        if id == EMERGENCY_CARD_ID {
            return Err(VaultError::ReservedSystemItem);
        }
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
        if id == EMERGENCY_CARD_ID {
            return Err(VaultError::ReservedSystemItem);
        }
        let (state, current_revision) = self.get_state_with_revision(id)?;
        if current_revision != expected_revision {
            return Err(VaultError::Storage(StorageError::StaleRevision));
        }
        let VaultItemState::Trashed {
            item,
            deleted_at_ms,
        } = state
        else {
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
        let mut tombstones = Vec::with_capacity(item.attachments.len());
        for attachment_id in item.attachments {
            let (attachment_revision, encrypted_record) =
                self.storage.load_attachment(attachment_id)?;
            let encrypted_attachment =
                decode_attachment_record(attachment_id, attachment_revision, &encrypted_record)?;
            let (manifest, _context) =
                open_attachment_manifest(&self.root_key, &encrypted_attachment)?;
            if !matches!(
                manifest,
                AttachmentManifestV1::Active { owner_item_id, .. } if owner_item_id == id
            ) {
                return Err(VaultError::InconsistentAttachment);
            }
            let tombstone_revision = attachment_revision
                .checked_add(1)
                .ok_or(VaultError::RevisionExhausted)?;
            let manifest = AttachmentManifestV1::Tombstone {
                attachment_id,
                owner_item_id: id,
                deleted_at_ms,
            };
            let (tombstone, context) =
                seal_attachment_manifest(&self.root_key, &manifest, tombstone_revision)?;
            if context.is_some() {
                return Err(VaultError::InconsistentAttachment);
            }
            tombstones.push((
                attachment_id,
                tombstone_revision,
                attachment_revision,
                serde_json::to_vec(&tombstone).map_err(CryptoError::Serialization)?,
            ));
        }
        self.storage
            .purge_item_and_tombstone_attachments_if_revision(
                &encrypted,
                expected_revision,
                &tombstones,
            )?;
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
        match self.get_state_with_revision(EMERGENCY_CARD_ID) {
            Err(VaultError::Storage(StorageError::ItemNotFound)) => {
                validate_trusted_devices_unpaired(card)
                    .map_err(|_| VaultError::InvalidTrustedPrincipal)?;
                let item = VaultItem::emergency_card(card);
                let encrypted = encrypt_item(&self.root_key, &item, 1)?;
                self.storage.insert_item(&encrypted)?;
                if let Ok(mut pending) = self.pending_pairings.lock() {
                    pending.clear();
                }
                Ok(1)
            }
            Ok((VaultItemState::Active { mut item }, revision)) => {
                let previous_card = item
                    .parse_emergency_card()
                    .ok_or(VaultError::InvalidTrustedPrincipal)?;
                let mut next_card = card.clone();
                carry_forward_trusted_identity_retirements(&previous_card, &mut next_card);
                validate_emergency_card(&next_card)?;
                validate_trusted_identity_continuity(&previous_card, &next_card)
                    .map_err(|_| VaultError::InvalidTrustedPrincipal)?;
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
                let next_revision = revision
                    .checked_add(1)
                    .ok_or(VaultError::RevisionExhausted)?;
                let encrypted = encrypt_item(&self.root_key, &item, next_revision)?;
                self.storage.update_item_if_revision(&encrypted, revision)?;
                if let Ok(mut pending) = self.pending_pairings.lock() {
                    pending.clear();
                }
                Ok(next_revision)
            }
            Ok((VaultItemState::Trashed { .. } | VaultItemState::Tombstone { .. }, _)) => {
                Err(VaultError::ItemNotActive)
            }
            Err(other) => Err(other),
        }
    }

    /// Start a one-shot dual-key possession proof for an existing unpaired
    /// trusted device. The hidden verifier nonce remains only in this unlocked
    /// session; dropping the session cancels all pending pairings.
    pub fn create_trusted_device_pairing_challenge(
        &self,
        principal_id: Uuid,
        device_id: Uuid,
    ) -> Result<PairingChallengeV1, VaultError> {
        let (card, _) = self
            .get_emergency_card()?
            .ok_or(VaultError::PairingChallengeUnavailable)?;
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
            .ok_or(VaultError::PairingChallengeUnavailable)?;
        if device.signing_public_key_hex.is_some() {
            return Err(VaultError::InvalidTrustedPrincipal);
        }
        let encryption_public = decode_hex_32(&device.encryption_public_key_hex)
            .ok_or(VaultError::InvalidTrustedPrincipal)?;
        let (package, state) =
            create_pairing_challenge(principal_id, device_id, &encryption_public)?;
        let mut pending = self
            .pending_pairings
            .lock()
            .map_err(|_| VaultError::PairingStateUnavailable)?;
        pending.retain(|_, existing| {
            existing.package.principal_id != principal_id || existing.package.device_id != device_id
        });
        if pending.len() >= MAX_PENDING_TRUSTED_DEVICE_PAIRINGS {
            return Err(VaultError::PairingStateUnavailable);
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

    /// Consume one pending pairing challenge and, after verifying possession of
    /// both the X25519 recipient key and Ed25519 signing key, install the signing
    /// verification key on that exact trusted-device UUID.
    pub fn complete_trusted_device_pairing(
        &self,
        proof: &PairingProofV1,
    ) -> Result<u64, VaultError> {
        let pending = self
            .pending_pairings
            .lock()
            .map_err(|_| VaultError::PairingStateUnavailable)?
            .remove(&proof.request_id)
            .ok_or(VaultError::PairingChallengeUnavailable)?;
        let signing_public = verify_pairing_proof(&pending.package, &pending.state, proof)?;

        let (VaultItemState::Active { mut item }, revision) =
            self.get_state_with_revision(EMERGENCY_CARD_ID)?
        else {
            return Err(VaultError::ItemNotActive);
        };
        let mut card = item
            .parse_emergency_card()
            .ok_or(VaultError::InvalidTrustedPrincipal)?;
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
            .ok_or(VaultError::PairingChallengeUnavailable)?;
        if device.signing_public_key_hex.is_some()
            || decode_hex_32(&device.encryption_public_key_hex) != Some(proof.encryption_public)
        {
            return Err(VaultError::InvalidTrustedPrincipal);
        }
        device.signing_public_key_hex = Some(encode_hex_32(&signing_public));
        validate_emergency_card(&card)?;
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
        let next_revision = revision
            .checked_add(1)
            .ok_or(VaultError::RevisionExhausted)?;
        let encrypted = encrypt_item(&self.root_key, &item, next_revision)?;
        self.storage.update_item_if_revision(&encrypted, revision)?;
        Ok(next_revision)
    }

    pub fn install_recovery_kit(&self, secret: &RecoverySecret) -> Result<(), VaultError> {
        let wrapped = wrap_root_key_with_recovery_secret(secret, &self.root_key)?;
        self.storage.store_recovery_wrap(&wrapped)?;
        Ok(())
    }

    pub fn has_recovery_kit(&self) -> Result<bool, VaultError> {
        Ok(self.storage.has_recovery_wrap()?)
    }

    pub fn verify_recovery_kit(&self, secret: &RecoverySecret) -> Result<bool, VaultError> {
        let Some(wrapped) = self.storage.load_recovery_wrap()? else {
            return Ok(false);
        };
        recovery_secret_matches_root_key(secret, &wrapped, &self.root_key).map_err(Into::into)
    }

    pub fn validate_persisted_state(&self) -> Result<(), VaultError> {
        self.storage.validate_integrity()?;
        self.storage.validate_record_bounds()?;
        validate_storage_contents(&self.storage, &self.root_key)?;
        let _ = self.storage.load_recovery_wrap()?;
        Ok(())
    }

    pub fn prepare_database_backup(
        &self,
        source_path: impl AsRef<Path>,
    ) -> Result<VaultBackupPlan, VaultError> {
        let recovery_secret = RecoverySecret::generate()?;
        let wrapped_root_key =
            wrap_root_key_with_recovery_secret(&recovery_secret, &self.root_key)?;
        Ok(VaultBackupPlan {
            source_path: source_path.as_ref().to_path_buf(),
            recovery_secret,
            wrapped_root_key,
        })
    }

    pub fn backup_database_to(&self, path: impl AsRef<Path>) -> Result<(), VaultError> {
        self.storage.backup_to(&path)?;
        let backup_storage = VaultStorage::open(&path)?;
        backup_storage.validate_integrity()?;
        backup_storage.validate_record_bounds()?;
        validate_storage_contents(&backup_storage, &self.root_key)?;
        let _ = backup_storage.load_recovery_wrap()?;
        Ok(())
    }

    pub fn replace_with_backup(
        &mut self,
        path: impl AsRef<Path>,
        passphrase: &str,
    ) -> Result<(), VaultError> {
        let prepared = Self::prepare_restore(path, passphrase)?;
        self.commit_prepared_restore(prepared)
    }

    pub fn prepare_restore(
        path: impl AsRef<Path>,
        passphrase: &str,
    ) -> Result<PreparedVaultRestore, VaultError> {
        Self::prepare_restore_with_cancel(path, passphrase, || false)
    }

    pub fn prepare_restore_with_cancel<F>(
        path: impl AsRef<Path>,
        passphrase: &str,
        mut cancelled: F,
    ) -> Result<PreparedVaultRestore, VaultError>
    where
        F: FnMut() -> bool,
    {
        let backup_path = path.as_ref().to_path_buf();
        let storage = VaultStorage::open(&backup_path)?;
        storage.validate_integrity()?;
        storage.validate_record_bounds()?;
        if cancelled() {
            return Err(VaultError::OperationCancelled);
        }
        let wrapped = storage.load_root_wrap()?;
        let root_key = unwrap_root_key(passphrase, &wrapped)?;
        if cancelled() {
            return Err(VaultError::OperationCancelled);
        }
        finish_restore_preparation(backup_path, storage, root_key, &mut cancelled)
    }

    pub fn prepare_restore_with_recovery_kit(
        path: impl AsRef<Path>,
        secret: &RecoverySecret,
    ) -> Result<PreparedVaultRestore, VaultError> {
        Self::prepare_restore_with_recovery_kit_with_cancel(path, secret, || false)
    }

    pub fn prepare_restore_with_recovery_kit_with_cancel<F>(
        path: impl AsRef<Path>,
        secret: &RecoverySecret,
        mut cancelled: F,
    ) -> Result<PreparedVaultRestore, VaultError>
    where
        F: FnMut() -> bool,
    {
        let backup_path = path.as_ref().to_path_buf();
        let storage = VaultStorage::open(&backup_path)?;
        storage.validate_integrity()?;
        storage.validate_record_bounds()?;
        if cancelled() {
            return Err(VaultError::OperationCancelled);
        }
        // A restore candidate must remain a complete vault even when the
        // recovery wrap is the credential used to authenticate it.
        let _ = storage.load_root_wrap()?;
        let recovery_wrap = storage
            .load_recovery_wrap()?
            .ok_or(StorageError::NotInitialized)?;
        let root_key = unwrap_root_key_with_recovery_secret(secret, &recovery_wrap)?;
        if cancelled() {
            return Err(VaultError::OperationCancelled);
        }
        finish_restore_preparation(backup_path, storage, root_key, &mut cancelled)
    }

    pub fn commit_prepared_restore(
        &mut self,
        prepared: PreparedVaultRestore,
    ) -> Result<(), VaultError> {
        self.storage.replace_from_database_if_fingerprint(
            &prepared.backup_path,
            &prepared.source_fingerprint,
        )?;
        self.root_key = prepared.root_key;
        Ok(())
    }

    pub fn install_backup(
        live_path: impl AsRef<Path>,
        backup_path: impl AsRef<Path>,
        passphrase: &str,
    ) -> Result<Self, VaultError> {
        Self::prepare_restore(backup_path, passphrase)?.install_to(live_path)
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
        Ok(Self {
            storage,
            root_key,
            pending_pairings: Mutex::new(BTreeMap::new()),
        })
    }

    fn get_state_with_revision(&self, id: Uuid) -> Result<(VaultItemState, u64), VaultError> {
        let encrypted = self.storage.load_item(id)?;
        let revision = encrypted.revision;
        Ok((decrypt_item_state(&self.root_key, &encrypted)?, revision))
    }

    fn history_owner_revision(
        &self,
        id: Uuid,
        expected_current_revision: u64,
    ) -> Result<u64, VaultError> {
        if id == EMERGENCY_CARD_ID {
            return Err(VaultError::HistoryNotAvailable);
        }
        let (state, current_revision) = self.get_state_with_revision(id)?;
        if current_revision != expected_current_revision {
            return Err(VaultError::Storage(StorageError::StaleRevision));
        }
        match state {
            VaultItemState::Active { .. } => Ok(current_revision),
            VaultItemState::Trashed { .. } | VaultItemState::Tombstone { .. } => {
                Err(VaultError::HistoryNotAvailable)
            }
        }
    }
}

fn finish_restore_preparation<F>(
    backup_path: PathBuf,
    storage: VaultStorage,
    root_key: AccountRootKey,
    cancelled: &mut F,
) -> Result<PreparedVaultRestore, VaultError>
where
    F: FnMut() -> bool,
{
    validate_storage_contents_with_cancel(&storage, &root_key, cancelled)?;
    let _ = storage.load_recovery_wrap()?;
    let source_fingerprint = storage.restore_source_fingerprint()?;
    if cancelled() {
        return Err(VaultError::OperationCancelled);
    }
    drop(storage);
    Ok(PreparedVaultRestore {
        backup_path,
        root_key,
        source_fingerprint,
    })
}

fn validate_storage_contents(
    storage: &VaultStorage,
    root_key: &AccountRootKey,
) -> Result<(), VaultError> {
    validate_storage_contents_with_cancel(storage, root_key, &mut || false)
}

fn validate_storage_contents_with_cancel<F>(
    storage: &VaultStorage,
    root_key: &AccountRootKey,
    cancelled: &mut F,
) -> Result<(), VaultError>
where
    F: FnMut() -> bool,
{
    if cancelled() {
        return Err(VaultError::OperationCancelled);
    }
    validate_attachment_storage_bytes(storage.attachment_storage_bytes()?)?;
    let mut referenced_attachments = BTreeMap::<Uuid, Uuid>::new();
    let mut seen_attachment_refs = BTreeSet::new();
    let mut current_items = BTreeMap::<Uuid, (u64, bool)>::new();
    for id in storage.list_item_ids()? {
        if cancelled() {
            return Err(VaultError::OperationCancelled);
        }
        let encrypted = storage.load_item(id)?;
        let current_revision = encrypted.revision;
        let state = decrypt_item_state(root_key, &encrypted)?;
        if cancelled() {
            return Err(VaultError::OperationCancelled);
        }
        let is_tombstone = matches!(&state, VaultItemState::Tombstone { .. });
        if current_items
            .insert(id, (current_revision, is_tombstone))
            .is_some()
        {
            return Err(VaultError::Storage(StorageError::InconsistentEncryptedRow));
        }
        match state {
            VaultItemState::Active { item } | VaultItemState::Trashed { item, .. } => {
                validate_item(&item)?;
                if item.id == EMERGENCY_CARD_ID && item.parse_emergency_card().is_none() {
                    return Err(VaultError::Storage(StorageError::InconsistentEncryptedRow));
                }
                for attachment_id in &item.attachments {
                    if !seen_attachment_refs.insert(*attachment_id)
                        || referenced_attachments
                            .insert(*attachment_id, item.id)
                            .is_some()
                    {
                        return Err(VaultError::InconsistentAttachment);
                    }
                }
            }
            VaultItemState::Tombstone { .. } => {}
        }
    }

    for (id, historical_revision) in storage.list_item_history_keys()? {
        if cancelled() {
            return Err(VaultError::OperationCancelled);
        }
        let Some((current_revision, current_is_tombstone)) = current_items.get(&id) else {
            return Err(VaultError::Storage(StorageError::InconsistentEncryptedRow));
        };
        if id == EMERGENCY_CARD_ID
            || *current_is_tombstone
            || historical_revision >= *current_revision
        {
            return Err(VaultError::Storage(StorageError::InconsistentEncryptedRow));
        }
        let encrypted = storage.load_item_history(id, historical_revision)?;
        let historical_item = decrypt_item(root_key, &encrypted)?;
        validate_item(&historical_item)?;
    }

    let mut stored_attachment_ids = BTreeSet::new();
    for attachment_id in storage.list_attachment_ids()? {
        if cancelled() {
            return Err(VaultError::OperationCancelled);
        }
        if !stored_attachment_ids.insert(attachment_id) {
            return Err(VaultError::InconsistentAttachment);
        }
        let (revision, encrypted_record) = storage.load_attachment(attachment_id)?;
        let encrypted = decode_attachment_record(attachment_id, revision, &encrypted_record)?;
        let (manifest, context) = open_attachment_manifest(root_key, &encrypted)?;
        if cancelled() {
            return Err(VaultError::OperationCancelled);
        }
        let chunk_indexes = storage.list_attachment_chunk_indexes(attachment_id)?;
        match manifest {
            AttachmentManifestV1::Active {
                owner_item_id,
                plaintext_size,
                chunk_count,
                ..
            } => {
                if referenced_attachments.get(&attachment_id) != Some(&owner_item_id) {
                    return Err(VaultError::InconsistentAttachment);
                }
                if chunk_indexes.len()
                    != usize::try_from(chunk_count)
                        .map_err(|_| VaultError::InconsistentAttachment)?
                {
                    return Err(VaultError::InconsistentAttachment);
                }
                let context = context.ok_or(VaultError::InconsistentAttachment)?;
                let mut total_plaintext = 0u64;
                for (expected_index, stored_index) in chunk_indexes.iter().enumerate() {
                    if cancelled() {
                        return Err(VaultError::OperationCancelled);
                    }
                    let expected_index = u32::try_from(expected_index)
                        .map_err(|_| VaultError::InconsistentAttachment)?;
                    if *stored_index != expected_index {
                        return Err(VaultError::InconsistentAttachment);
                    }
                    let ciphertext = storage
                        .load_attachment_chunk(attachment_id, *stored_index)?
                        .ok_or(VaultError::InconsistentAttachment)?;
                    let plaintext = context.decrypt_chunk(u64::from(*stored_index), &ciphertext)?;
                    if cancelled() {
                        return Err(VaultError::OperationCancelled);
                    }
                    total_plaintext = total_plaintext
                        .checked_add(
                            u64::try_from(plaintext.len())
                                .map_err(|_| VaultError::InconsistentAttachment)?,
                        )
                        .ok_or(VaultError::InconsistentAttachment)?;
                }
                if total_plaintext != plaintext_size {
                    return Err(VaultError::InconsistentAttachment);
                }
            }
            AttachmentManifestV1::Tombstone { .. } => {
                if referenced_attachments.contains_key(&attachment_id)
                    || context.is_some()
                    || !chunk_indexes.is_empty()
                {
                    return Err(VaultError::InconsistentAttachment);
                }
            }
        }
    }

    if referenced_attachments
        .keys()
        .any(|id| !stored_attachment_ids.contains(id))
    {
        return Err(VaultError::InconsistentAttachment);
    }
    if cancelled() {
        return Err(VaultError::OperationCancelled);
    }
    Ok(())
}

fn validate_attachment_storage_bytes(total: u64) -> Result<(), VaultError> {
    if total > MAX_ATTACHMENT_STORAGE_BYTES {
        return Err(VaultError::AttachmentStorageLimitReached);
    }
    Ok(())
}

fn attachment_chunk_count(plaintext_size: u64) -> u64 {
    if plaintext_size == 0 {
        0
    } else {
        plaintext_size.div_ceil(ATTACHMENT_CHUNK_SIZE)
    }
}

fn decode_attachment_record(
    attachment_id: Uuid,
    revision: u64,
    encrypted_record: &[u8],
) -> Result<EncryptedAttachmentV1, VaultError> {
    let encrypted: EncryptedAttachmentV1 =
        serde_json::from_slice(encrypted_record).map_err(CryptoError::Serialization)?;
    if encrypted.attachment_id != attachment_id || encrypted.revision != revision {
        return Err(VaultError::InconsistentAttachment);
    }
    Ok(encrypted)
}

fn validate_item(item: &VaultItem) -> Result<(), VaultError> {
    match validate_vault_item(item) {
        Ok(()) => Ok(()),
        Err(VaultItemValidationError::InvalidLegacyDisposition) => {
            Err(VaultError::InvalidLegacyDisposition)
        }
        Err(VaultItemValidationError::InvalidAccountClosurePlan) => {
            Err(VaultError::InvalidAccountClosurePlan)
        }
        Err(VaultItemValidationError::InvalidAccessPolicy) => Err(VaultError::InvalidAccessPolicy),
        Err(VaultItemValidationError::InvalidTrustedPrincipal) => {
            Err(VaultError::InvalidTrustedPrincipal)
        }
        Err(VaultItemValidationError::TooLarge) => Err(VaultError::ItemTooLarge),
    }
}

fn validate_emergency_card(card: &EmergencyCard) -> Result<(), VaultError> {
    match validate_emergency_card_model(card) {
        Ok(()) => Ok(()),
        Err(VaultItemValidationError::InvalidTrustedPrincipal) => {
            Err(VaultError::InvalidTrustedPrincipal)
        }
        Err(VaultItemValidationError::TooLarge) => Err(VaultError::ItemTooLarge),
        Err(
            VaultItemValidationError::InvalidLegacyDisposition
            | VaultItemValidationError::InvalidAccountClosurePlan
            | VaultItemValidationError::InvalidAccessPolicy,
        ) => Err(VaultError::InvalidTrustedPrincipal),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
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
            "Electronics",
            "Home office",
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
    fn item_history_is_browse_only_revision_fenced_and_creation_is_create_only() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let mut item = VaultItem::secure_note("original", "first body");
        let id = item.id;
        session.put_item(&item, 1).expect("store original");

        let mut replacement = item.clone();
        replacement.title = "replacement through create".to_owned();
        assert!(matches!(
            session.put_item(&replacement, 2),
            Err(VaultError::Storage(StorageError::StaleRevision))
        ));
        assert!(
            session
                .list_item_history_revisions(id, 1)
                .expect("empty initial history")
                .is_empty()
        );

        item.title = "updated".to_owned();
        item.fields
            .insert("body".to_owned(), "second body".to_owned());
        let current_revision = session.update_item(&item, 1).expect("update item");
        assert_eq!(current_revision, 2);
        assert_eq!(
            session
                .list_item_history_revisions(id, current_revision)
                .expect("list history"),
            vec![1]
        );
        let historical = session
            .get_item_history(id, current_revision, 1)
            .expect("fetch historical revision");
        assert_eq!(historical.title, "original");
        assert_eq!(historical.fields["body"], "first body");
        assert!(matches!(
            session.list_item_history_revisions(id, 1),
            Err(VaultError::Storage(StorageError::StaleRevision))
        ));
        assert!(matches!(
            session.get_item_history(id, current_revision, current_revision),
            Err(VaultError::HistoryNotAvailable)
        ));
        assert!(matches!(
            session.get_item_history(id, current_revision, 0),
            Err(VaultError::HistoryNotAvailable)
        ));
    }

    #[test]
    fn active_metadata_mutations_archive_prior_snapshots() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let mut credential = VaultItem::password(
            "Primary email",
            "owner@example.test",
            "secret",
            "https://example.test",
            "",
        );
        let id = credential.id;
        session.put_item(&credential, 1).expect("store credential");

        let revision = session
            .set_legacy_disposition(id, 1, LegacyDisposition::PrivateForever)
            .expect("set legacy disposition");
        assert_eq!(revision, 2);
        let revision = session
            .set_account_closure_plan(
                id,
                revision,
                AccountClosurePlan {
                    disposition: vault_models::AccountClosureDisposition::ReviewManually,
                    instructions: "Review before closing.".to_owned(),
                },
            )
            .expect("set closure plan");
        assert_eq!(revision, 3);
        credential = session.get_item(id).expect("load credential for link edit");
        credential.links.push(Uuid::new_v4());
        let revision = session
            .update_item(&credential, revision)
            .expect("update links");
        assert_eq!(revision, 4);

        assert_eq!(
            session
                .list_item_history_revisions(id, revision)
                .expect("list metadata history"),
            vec![3, 2, 1]
        );
        let original = session
            .get_item_history(id, revision, 1)
            .expect("original snapshot");
        assert_eq!(original.legacy_disposition, LegacyDisposition::Unspecified);
        assert_eq!(original.account_closure_plan, AccountClosurePlan::default());
        assert!(original.links.is_empty());
        let after_legacy = session
            .get_item_history(id, revision, 2)
            .expect("legacy snapshot");
        assert_eq!(
            after_legacy.legacy_disposition,
            LegacyDisposition::PrivateForever
        );
        assert_eq!(
            after_legacy.account_closure_plan,
            AccountClosurePlan::default()
        );
        assert!(after_legacy.links.is_empty());
    }

    #[test]
    fn trash_and_restore_do_not_archive_and_purge_clears_history() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let mut item = VaultItem::secure_note("history lifecycle", "body");
        let id = item.id;
        session.put_item(&item, 1).expect("store item");
        item.title = "edited".to_owned();
        let edited_revision = session.update_item(&item, 1).expect("edit item");
        assert_eq!(edited_revision, 2);

        let trashed_revision = session
            .trash_item(id, edited_revision, 10)
            .expect("trash item");
        assert_eq!(trashed_revision, 3);
        assert!(matches!(
            session.list_item_history_revisions(id, trashed_revision),
            Err(VaultError::HistoryNotAvailable)
        ));
        assert_eq!(
            session
                .storage
                .list_item_history_revisions(id)
                .expect("history remains encrypted while trashed"),
            vec![1]
        );
        let restored_revision = session
            .restore_item(id, trashed_revision)
            .expect("restore item");
        assert_eq!(restored_revision, 4);
        assert_eq!(
            session
                .list_item_history_revisions(id, restored_revision)
                .expect("history unchanged after restore"),
            vec![1]
        );

        let second_trash_revision = session
            .trash_item(id, restored_revision, 11)
            .expect("trash before purge");
        let tombstone_revision = session
            .purge_item(id, second_trash_revision)
            .expect("purge item");
        assert_eq!(tombstone_revision, 6);
        assert!(
            session
                .storage
                .list_item_history_revisions(id)
                .expect("history cleared by purge")
                .is_empty()
        );
        assert!(matches!(
            session.list_item_history_revisions(id, tombstone_revision),
            Err(VaultError::HistoryNotAvailable)
        ));
    }

    #[test]
    fn emergency_card_history_is_excluded() {
        use vault_models::EmergencyContact;

        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let first = EmergencyCard::empty();
        assert_eq!(session.set_emergency_card(&first).expect("create card"), 1);
        let updated = EmergencyCard {
            selected_item_ids: Vec::new(),
            contacts: vec![EmergencyContact {
                name: "Ada".to_owned(),
                relation: "Sibling".to_owned(),
                phone: "+1-555-0100".to_owned(),
                email: String::new(),
                notes: String::new(),
            }],
            principals: Vec::new(),
            retired_principal_ids: BTreeSet::new(),
            retired_device_ids: BTreeSet::new(),
            retired_signing_public_key_hexes: BTreeSet::new(),
            instructions: "Call first.".to_owned(),
        };
        assert_eq!(
            session.set_emergency_card(&updated).expect("update card"),
            2
        );
        assert!(
            session
                .storage
                .list_item_history_revisions(EMERGENCY_CARD_ID)
                .expect("no emergency history")
                .is_empty()
        );
        assert!(matches!(
            session.list_item_history_revisions(EMERGENCY_CARD_ID, 2),
            Err(VaultError::HistoryNotAvailable)
        ));
        assert!(matches!(
            session.get_item_history(EMERGENCY_CARD_ID, 2, 1),
            Err(VaultError::HistoryNotAvailable)
        ));

        let forced_current =
            encrypt_item(&session.root_key, &VaultItem::emergency_card(&updated), 3)
                .expect("encrypt forced emergency revision");
        session
            .storage
            .update_item_with_history_if_revision(&forced_current, 2)
            .expect("force excluded emergency history");
        assert!(matches!(
            session.validate_persisted_state(),
            Err(VaultError::Storage(StorageError::InconsistentEncryptedRow))
        ));
    }

    #[test]
    fn encrypted_backup_restore_preserves_item_history() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let backup = dir.path().join("history-backup.sqlite3");
        let mut session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let mut item = VaultItem::secure_note("revision one", "first");
        let id = item.id;
        session.put_item(&item, 1).expect("store item");
        item.title = "revision two".to_owned();
        let backup_revision = session.update_item(&item, 1).expect("first edit");
        session
            .backup_database_to(&backup)
            .expect("backup with history");

        item.title = "revision three".to_owned();
        session
            .update_item(&item, backup_revision)
            .expect("mutate live item");
        session
            .replace_with_backup(&backup, TEST_PASSPHRASE)
            .expect("restore backup with history");

        assert_eq!(
            session
                .list_item_history_revisions(id, backup_revision)
                .expect("restored history revisions"),
            vec![1]
        );
        assert_eq!(
            session
                .get_item_history(id, backup_revision, 1)
                .expect("restored historical item")
                .title,
            "revision one"
        );
    }

    #[test]
    fn legacy_disposition_is_cas_safe_and_survives_lifecycle_transitions() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let mut item = VaultItem::secure_note("legacy plan", "private body");
        item.links.push(Uuid::new_v4());
        let id = item.id;
        session.put_item(&item, 1).expect("store item");

        let revision = session
            .set_legacy_disposition(id, 1, LegacyDisposition::PrivateForever)
            .expect("set legacy disposition");
        assert_eq!(revision, 2);
        let (updated, loaded_revision) = session
            .get_item_with_revision(id)
            .expect("load updated item");
        assert_eq!(loaded_revision, 2);
        assert_eq!(
            updated.legacy_disposition,
            LegacyDisposition::PrivateForever
        );
        assert_eq!(
            updated.fields.get("body").map(String::as_str),
            Some("private body")
        );
        assert_eq!(updated.links, item.links);

        assert!(matches!(
            session.set_legacy_disposition(id, 1, LegacyDisposition::SelectedForLegacy),
            Err(VaultError::Storage(StorageError::StaleRevision))
        ));

        let trashed_revision = session.trash_item(id, revision, 42).expect("trash item");
        let trashed = session
            .list_trashed_items_with_revisions()
            .expect("list trash")
            .into_iter()
            .find(|(candidate, _, _)| candidate.id == id)
            .expect("trashed item");
        assert_eq!(
            trashed.0.legacy_disposition,
            LegacyDisposition::PrivateForever
        );
        let restored_revision = session
            .restore_item(id, trashed_revision)
            .expect("restore item");
        let (restored, revision) = session
            .get_item_with_revision(id)
            .expect("load restored item");
        assert_eq!(revision, restored_revision);
        assert_eq!(
            restored.legacy_disposition,
            LegacyDisposition::PrivateForever
        );

        let destroy_revision = session
            .set_legacy_disposition(id, restored_revision, LegacyDisposition::DestroyOnDeath)
            .expect("record destroy-on-death intent");
        assert!(session.get_item(id).is_ok());
        let second_trash_revision = session
            .trash_item(id, destroy_revision, 43)
            .expect("trash item again");
        let tombstone_revision = session
            .purge_item(id, second_trash_revision)
            .expect("purge item");
        assert!(matches!(
            session
                .get_state_with_revision(id)
                .expect("load tombstone state"),
            (VaultItemState::Tombstone { id: tombstone_id, .. }, revision)
                if tombstone_id == id && revision == tombstone_revision
        ));

        assert!(matches!(
            session.set_legacy_disposition(
                EMERGENCY_CARD_ID,
                1,
                LegacyDisposition::SelectedForLegacy
            ),
            Err(VaultError::InvalidLegacyDisposition)
        ));
    }

    #[test]
    fn encrypted_backup_restore_preserves_legacy_disposition() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let backup = dir.path().join("legacy-plan-backup.sqlite3");
        let mut session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("legacy backup", "body");
        let id = item.id;
        session.put_item(&item, 1).expect("store item");
        let backup_revision = session
            .set_legacy_disposition(id, 1, LegacyDisposition::SelectedForLegacy)
            .expect("set backed-up disposition");
        session
            .backup_database_to(&backup)
            .expect("create validated backup");

        let mutated_revision = session
            .set_legacy_disposition(id, backup_revision, LegacyDisposition::PrivateForever)
            .expect("mutate live disposition");
        assert_eq!(mutated_revision, backup_revision + 1);
        assert_eq!(
            session
                .get_item(id)
                .expect("load mutated item")
                .legacy_disposition,
            LegacyDisposition::PrivateForever
        );

        session
            .replace_with_backup(&backup, TEST_PASSPHRASE)
            .expect("restore validated backup");
        let (restored, restored_revision) = session
            .get_item_with_revision(id)
            .expect("load restored legacy item");
        assert_eq!(restored_revision, backup_revision);
        assert_eq!(
            restored.legacy_disposition,
            LegacyDisposition::SelectedForLegacy
        );
    }

    #[test]
    fn account_closure_plan_is_credential_only_cas_safe_and_survives_lifecycle() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let mut credential = VaultItem::password(
            "Primary email",
            "owner@example.test",
            "secret",
            "https://example.test",
            "private note",
        );
        credential.links.push(Uuid::new_v4());
        credential.legacy_disposition = LegacyDisposition::SelectedForLegacy;
        let id = credential.id;
        session.put_item(&credential, 1).expect("store credential");

        let plan = AccountClosurePlan {
            disposition: vault_models::AccountClosureDisposition::CloseAccount,
            instructions: "Export statements and close manually.".to_owned(),
        };
        let revision = session
            .set_account_closure_plan(id, 1, plan.clone())
            .expect("set closure plan");
        assert_eq!(revision, 2);
        let updated = session.get_item(id).expect("load updated credential");
        assert_eq!(updated.account_closure_plan, plan);
        assert_eq!(updated.links, credential.links);
        assert_eq!(
            updated.legacy_disposition,
            LegacyDisposition::SelectedForLegacy
        );
        assert_eq!(
            updated.fields.get("password").map(String::as_str),
            Some("secret")
        );

        assert!(matches!(
            session.set_account_closure_plan(id, 1, AccountClosurePlan::default()),
            Err(VaultError::Storage(StorageError::StaleRevision))
        ));

        let note = VaultItem::secure_note("not an account", "body");
        session.put_item(&note, 1).expect("store note");
        assert!(matches!(
            session.set_account_closure_plan(note.id, 1, plan.clone()),
            Err(VaultError::InvalidAccountClosurePlan)
        ));

        let oversized = AccountClosurePlan {
            disposition: vault_models::AccountClosureDisposition::ReviewManually,
            instructions: "x".repeat(MAX_ITEM_NOTES_CHARS + 1),
        };
        assert!(matches!(
            session.set_account_closure_plan(id, revision, oversized),
            Err(VaultError::ItemTooLarge)
        ));

        let trashed_revision = session
            .trash_item(id, revision, 42)
            .expect("trash credential");
        let trashed = session
            .list_trashed_items_with_revisions()
            .expect("list trash")
            .into_iter()
            .find(|(candidate, _, _)| candidate.id == id)
            .expect("trashed credential");
        assert_eq!(trashed.0.account_closure_plan, plan);
        let restored_revision = session
            .restore_item(id, trashed_revision)
            .expect("restore credential");
        let (restored, current_revision) = session
            .get_item_with_revision(id)
            .expect("load restored credential");
        assert_eq!(current_revision, restored_revision);
        assert_eq!(restored.account_closure_plan, plan);
    }

    #[test]
    fn access_policy_is_cas_safe_validated_and_survives_lifecycle() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("continuity", "private body");
        let id = item.id;
        session.put_item(&item, 1).expect("store item");

        let trustee = Uuid::new_v4();
        let mut policy = AccessPolicy::default();
        policy
            .add_grant(
                vault_models::AccessGrant::new(
                    trustee,
                    "record",
                    vault_models::Permission::Download,
                    vault_models::AccessCondition::Emergency,
                    vault_models::WaitPeriod::OneDay,
                    vault_models::GrantDuration::SevenDays,
                    0,
                    BTreeSet::new(),
                )
                .expect("valid grant"),
            )
            .expect("add grant");

        let revision = session
            .set_access_policy(id, 1, policy.clone())
            .expect("persist access policy");
        assert_eq!(revision, 2);
        assert_eq!(
            session.get_item(id).expect("load item").access_policy,
            policy
        );
        assert!(matches!(
            session.set_access_policy(id, 1, AccessPolicy::default()),
            Err(VaultError::Storage(StorageError::StaleRevision))
        ));

        let mut invalid = AccessPolicy::default();
        invalid.grants.push(vault_models::AccessGrant {
            trustee_id: trustee,
            what: String::new(),
            permission: vault_models::Permission::View,
            condition: vault_models::AccessCondition::Emergency,
            wait_period: vault_models::WaitPeriod::Immediate,
            duration: vault_models::GrantDuration::UntilRevoked,
            approvals_required: 0,
            approver_ids: BTreeSet::new(),
        });
        assert!(matches!(
            session.set_access_policy(id, revision, invalid),
            Err(VaultError::InvalidAccessPolicy)
        ));

        let trashed_revision = session.trash_item(id, revision, 42).expect("trash item");
        let trashed = session
            .list_trashed_items_with_revisions()
            .expect("list trash")
            .into_iter()
            .find(|(candidate, _, _)| candidate.id == id)
            .expect("trashed item");
        assert_eq!(trashed.0.access_policy, policy);
        let restored_revision = session
            .restore_item(id, trashed_revision)
            .expect("restore item");
        let (restored, current_revision) = session
            .get_item_with_revision(id)
            .expect("load restored item");
        assert_eq!(current_revision, restored_revision);
        assert_eq!(restored.access_policy, policy);
    }

    #[test]
    fn encrypted_backup_restore_preserves_account_closure_plan() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let backup = dir.path().join("closure-plan-backup.sqlite3");
        let mut session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let credential = VaultItem::password(
            "Broker account",
            "owner",
            "secret",
            "https://broker.example",
            "",
        );
        let id = credential.id;
        session.put_item(&credential, 1).expect("store credential");
        let backed_up = AccountClosurePlan {
            disposition: vault_models::AccountClosureDisposition::ReviewManually,
            instructions: "Review tax records before deciding.".to_owned(),
        };
        let backup_revision = session
            .set_account_closure_plan(id, 1, backed_up.clone())
            .expect("set backed-up closure plan");
        session
            .backup_database_to(&backup)
            .expect("create validated backup");

        session
            .set_account_closure_plan(
                id,
                backup_revision,
                AccountClosurePlan {
                    disposition: vault_models::AccountClosureDisposition::KeepOpen,
                    instructions: "Keep open.".to_owned(),
                },
            )
            .expect("mutate live closure plan");
        session
            .replace_with_backup(&backup, TEST_PASSPHRASE)
            .expect("restore validated backup");
        let restored = session.get_item(id).expect("load restored credential");
        assert_eq!(restored.account_closure_plan, backed_up);
    }

    #[test]
    fn attachment_storage_budget_accepts_limit_and_rejects_one_byte_over() {
        assert!(validate_attachment_storage_bytes(MAX_ATTACHMENT_STORAGE_BYTES).is_ok());
        assert!(matches!(
            validate_attachment_storage_bytes(MAX_ATTACHMENT_STORAGE_BYTES + 1),
            Err(VaultError::AttachmentStorageLimitReached)
        ));
    }

    #[test]
    fn attachment_round_trip_trash_restore_delete_and_export() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let source_path = dir.path().join("evidence.bin");
        let export_path = dir.path().join("restored-evidence.bin");
        let bytes = vec![0x5A; ATTACHMENT_CHUNK_SIZE as usize + 37];
        fs::write(&source_path, &bytes).expect("write source attachment");

        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("attachment owner", "body");
        session.put_item(&item, 1).expect("store owner");
        let (summary, item_revision) = session
            .add_attachment_from_path(item.id, 1, &source_path)
            .expect("add attachment");
        assert_eq!(item_revision, 2);
        assert_eq!(summary.filename, "evidence.bin");
        assert_eq!(summary.plaintext_size, bytes.len() as u64);
        assert_eq!(summary.revision, 1);
        assert_eq!(
            session
                .get_item(item.id)
                .expect("owner with attachment")
                .attachments,
            vec![summary.id]
        );
        let listed = session.list_attachments(item.id).expect("list attachment");
        assert_eq!(listed.len(), 1);
        assert!(listed[0] == summary);

        session
            .export_attachment_to(item.id, summary.id, &export_path)
            .expect("export attachment");
        assert_eq!(fs::read(&export_path).expect("read export"), bytes);
        assert!(
            fs::read_dir(dir.path())
                .expect("list export directory")
                .all(|entry| !entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .contains("safeory.tmp"))
        );
        assert!(matches!(
            session.export_attachment_to(item.id, summary.id, &export_path),
            Err(VaultError::AttachmentOutputExists)
        ));

        let trashed_revision = session
            .trash_item(item.id, item_revision, 100)
            .expect("trash owner");
        assert!(matches!(
            session.list_attachments(item.id),
            Err(VaultError::ItemNotActive)
        ));
        let restored_revision = session
            .restore_item(item.id, trashed_revision)
            .expect("restore owner");
        let listed_after_restore = session
            .list_attachments(item.id)
            .expect("attachment after restore");
        assert_eq!(listed_after_restore.len(), 1);
        assert!(listed_after_restore[0] == summary);

        let deleted_item_revision = session
            .delete_attachment(
                item.id,
                summary.id,
                restored_revision,
                summary.revision,
                200,
            )
            .expect("delete attachment");
        assert_eq!(deleted_item_revision, restored_revision + 1);
        assert!(
            session
                .list_attachments(item.id)
                .expect("empty attachment list")
                .is_empty()
        );
        let (stored_revision, record) = session
            .storage
            .load_attachment(summary.id)
            .expect("attachment tombstone remains");
        assert_eq!(stored_revision, 2);
        let encrypted = decode_attachment_record(summary.id, stored_revision, &record)
            .expect("decode tombstone");
        let (manifest, context) =
            open_attachment_manifest(&session.root_key, &encrypted).expect("open tombstone");
        assert!(matches!(
            manifest,
            AttachmentManifestV1::Tombstone {
                attachment_id,
                owner_item_id,
                deleted_at_ms: 200,
            } if attachment_id == summary.id && owner_item_id == item.id
        ));
        assert!(context.is_none());
        assert!(
            session
                .storage
                .list_attachment_chunks(summary.id)
                .expect("chunks removed")
                .is_empty()
        );
        session
            .validate_persisted_state()
            .expect("attachment lifecycle state validates");
    }

    #[test]
    fn historical_attachment_references_are_metadata_only() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let source_path = dir.path().join("history-attachment.bin");
        fs::write(&source_path, b"historical attachment bytes").expect("write attachment source");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("attachment history", "body");
        let id = item.id;
        session.put_item(&item, 1).expect("store owner");
        let (summary, with_attachment_revision) = session
            .add_attachment_from_path(id, 1, &source_path)
            .expect("add attachment");
        assert_eq!(with_attachment_revision, 2);
        let without_attachment_revision = session
            .delete_attachment(
                id,
                summary.id,
                with_attachment_revision,
                summary.revision,
                99,
            )
            .expect("delete attachment");
        assert_eq!(without_attachment_revision, 3);

        assert_eq!(
            session
                .list_item_history_revisions(id, without_attachment_revision)
                .expect("list attachment history"),
            vec![2, 1]
        );
        let historical = session
            .get_item_history(id, without_attachment_revision, 2)
            .expect("fetch historical attachment reference");
        assert_eq!(historical.attachments, vec![summary.id]);
        assert!(
            session
                .get_item(id)
                .expect("current owner")
                .attachments
                .is_empty()
        );
        assert!(
            session
                .storage
                .list_attachment_chunks(summary.id)
                .expect("deleted attachment chunks")
                .is_empty()
        );
        session
            .validate_persisted_state()
            .expect("historical attachment reference is not live ownership");
    }

    #[test]
    fn persisted_history_validation_rejects_non_active_snapshots() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("owner", "body");
        session.put_item(&item, 1).expect("store owner");

        let trashed = encrypt_item_state(
            &session.root_key,
            &VaultItemState::Trashed {
                item: item.clone(),
                deleted_at_ms: 42,
            },
            2,
        )
        .expect("encrypt trashed state");
        session
            .storage
            .update_item_if_revision(&trashed, 1)
            .expect("install trashed current state");
        let active = encrypt_item(&session.root_key, &item, 3).expect("encrypt active state");
        session
            .storage
            .update_item_with_history_if_revision(&active, 2)
            .expect("archive non-active state");

        assert!(matches!(
            session.validate_persisted_state(),
            Err(VaultError::Crypto(CryptoError::InconsistentRecord))
        ));
    }

    #[test]
    fn persisted_history_validation_rejects_tombstone_owner() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let mut item = VaultItem::secure_note("owner", "body");
        let id = item.id;
        session.put_item(&item, 1).expect("store owner");
        item.title = "edited".to_owned();
        session
            .update_item(&item, 1)
            .expect("archive first revision");
        let tombstone = encrypt_item_state(
            &session.root_key,
            &VaultItemState::Tombstone {
                id,
                deleted_at_ms: 50,
            },
            3,
        )
        .expect("encrypt tombstone");
        session
            .storage
            .update_item_if_revision(&tombstone, 2)
            .expect("install tombstone without purge cleanup");
        assert!(matches!(
            session.validate_persisted_state(),
            Err(VaultError::Storage(StorageError::InconsistentEncryptedRow))
        ));
    }

    #[test]
    fn persisted_history_validation_authenticates_ciphertext() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("owner", "body");

        let mut tampered = encrypt_item(&session.root_key, &item, 1).expect("encrypt item");
        tampered.ciphertext[0] ^= 1;
        session
            .storage
            .insert_item(&tampered)
            .expect("seed tampered current envelope");
        let current = encrypt_item(&session.root_key, &item, 2).expect("encrypt current item");
        session
            .storage
            .update_item_with_history_if_revision(&current, 1)
            .expect("archive tampered envelope");

        assert!(matches!(
            session.validate_persisted_state(),
            Err(VaultError::Crypto(CryptoError::Authentication))
        ));
    }

    #[test]
    fn failed_attachment_export_removes_selected_partial_without_temp_sibling() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let source_path = dir.path().join("source.bin");
        let export_path = dir.path().join("failed-export.bin");
        fs::write(&source_path, b"payload").expect("write source attachment");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("attachment owner", "body");
        session.put_item(&item, 1).expect("store owner");
        let (summary, _) = session
            .add_attachment_from_path(item.id, 1, &source_path)
            .expect("add attachment");
        let original_chunks = session
            .storage
            .list_attachment_chunks(summary.id)
            .expect("load original chunk");
        assert_eq!(original_chunks.len(), 1);
        let ciphertext_len = original_chunks[0].1.len();
        session
            .storage
            .delete_attachment_chunks(summary.id)
            .expect("remove original chunk");
        session
            .storage
            .insert_attachment_chunk(summary.id, 0, &vec![0; ciphertext_len])
            .expect("insert same-size invalid ciphertext");

        assert!(
            session
                .export_attachment_to(item.id, summary.id, &export_path)
                .is_err()
        );
        assert!(!export_path.exists());
        assert!(
            fs::read_dir(dir.path())
                .expect("list export directory")
                .all(|entry| !entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .contains("safeory.tmp"))
        );
    }

    #[test]
    fn cancelled_attachment_export_removes_partial_output() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let source_path = dir.path().join("cancel-export-source.bin");
        let export_path = dir.path().join("cancel-export.bin");
        fs::write(
            &source_path,
            vec![0xA7; ATTACHMENT_CHUNK_SIZE as usize + 17],
        )
        .expect("write source attachment");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("attachment owner", "body");
        session.put_item(&item, 1).expect("store owner");
        let (summary, _) = session
            .add_attachment_from_path(item.id, 1, &source_path)
            .expect("add attachment");
        let plan = session
            .prepare_attachment_export(item.id, summary.id)
            .expect("prepare export");
        let checks = Cell::new(0usize);

        let result = plan.write_to_path(&export_path, || {
            let next = checks.get() + 1;
            checks.set(next);
            next >= 4
        });

        assert!(matches!(
            result,
            Err(VaultError::AttachmentOperationCancelled)
        ));
        assert!(checks.get() >= 4);
        assert!(!export_path.exists());
    }

    #[test]
    fn cancelled_attachment_export_after_final_sync_removes_output() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let source_path = dir.path().join("cancel-after-sync-source.bin");
        let export_path = dir.path().join("cancel-after-sync.bin");
        fs::write(&source_path, vec![0x5C; 17]).expect("write source attachment");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("attachment owner", "body");
        session.put_item(&item, 1).expect("store owner");
        let (summary, _) = session
            .add_attachment_from_path(item.id, 1, &source_path)
            .expect("add attachment");
        let plan = session
            .prepare_attachment_export(item.id, summary.id)
            .expect("prepare export");
        let checks = Cell::new(0usize);

        let result = plan.write_to_path(&export_path, || {
            let next = checks.get() + 1;
            checks.set(next);
            next >= 5
        });

        assert!(matches!(
            result,
            Err(VaultError::AttachmentOperationCancelled)
        ));
        assert_eq!(checks.get(), 5);
        assert!(!export_path.exists());
    }

    #[test]
    fn normal_item_updates_cannot_add_or_remove_attachment_references() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let source_path = dir.path().join("receipt.txt");
        fs::write(&source_path, b"receipt").expect("write source");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("owner", "body");
        session.put_item(&item, 1).expect("store owner");
        let (summary, item_revision) = session
            .add_attachment_from_path(item.id, 1, &source_path)
            .expect("add attachment");

        let mut editor = session.get_item(item.id).expect("editor item");
        editor.attachments.clear();
        assert!(matches!(
            session.update_item(&editor, item_revision),
            Err(VaultError::AttachmentReferencesManagedSeparately)
        ));
        let mut forged = VaultItem::secure_note("forged", "body");
        forged.attachments.push(summary.id);
        assert!(matches!(
            session.put_item(&forged, 1),
            Err(VaultError::AttachmentReferencesManagedSeparately)
        ));
        assert_eq!(
            session
                .get_item(item.id)
                .expect("unchanged item")
                .attachments,
            vec![summary.id]
        );
    }

    #[test]
    fn stale_attachment_add_fails_without_creating_attachment_rows() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let source_path = dir.path().join("small.txt");
        fs::write(&source_path, b"small").expect("write source");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("owner", "body");
        session.put_item(&item, 1).expect("store owner");

        assert!(matches!(
            session.add_attachment_from_path(item.id, 0, &source_path),
            Err(VaultError::Storage(StorageError::StaleRevision))
        ));
        assert!(
            session
                .storage
                .list_attachment_ids()
                .expect("no attachment rows")
                .is_empty()
        );
        assert!(
            session
                .get_item(item.id)
                .expect("owner")
                .attachments
                .is_empty()
        );
    }

    #[test]
    fn cancelled_attachment_import_creates_no_rows() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let source_path = dir.path().join("cancel-import.bin");
        fs::write(
            &source_path,
            vec![0x5C; ATTACHMENT_CHUNK_SIZE as usize + 11],
        )
        .expect("write source attachment");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("owner", "body");
        session.put_item(&item, 1).expect("store owner");
        let source = AttachmentImportSource::open(&source_path).expect("open attachment source");
        let plan = session
            .prepare_attachment_import(item.id, 1, &source)
            .expect("prepare attachment import");
        let checks = Cell::new(0usize);

        let result = plan.encrypt_source(source, || {
            let next = checks.get() + 1;
            checks.set(next);
            next >= 3
        });

        assert!(matches!(
            result,
            Err(VaultError::AttachmentOperationCancelled)
        ));
        assert!(
            session
                .storage
                .list_attachment_ids()
                .expect("no attachment rows")
                .is_empty()
        );
        assert!(
            session
                .get_item(item.id)
                .expect("owner")
                .attachments
                .is_empty()
        );
    }

    #[test]
    fn attachment_creation_rejects_oversized_sparse_source_before_reading() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let source_path = dir.path().join("oversized.bin");
        let source = File::create(&source_path).expect("create sparse source");
        source
            .set_len(ATTACHMENT_MAX_PLAINTEXT_BYTES + 1)
            .expect("size sparse source");
        drop(source);
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("owner", "body");
        session.put_item(&item, 1).expect("store owner");

        assert!(matches!(
            session.add_attachment_from_path(item.id, 1, &source_path),
            Err(VaultError::AttachmentTooLarge)
        ));
        assert!(
            session
                .storage
                .list_attachment_ids()
                .expect("no attachment rows")
                .is_empty()
        );
    }

    #[test]
    fn purging_owner_tombstones_attachments_and_removes_chunks() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let source_path = dir.path().join("purge.dat");
        fs::write(&source_path, vec![0x33; 4096]).expect("write source");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("owner", "body");
        session.put_item(&item, 1).expect("store owner");
        let (summary, item_revision) = session
            .add_attachment_from_path(item.id, 1, &source_path)
            .expect("add attachment");
        let trashed_revision = session
            .trash_item(item.id, item_revision, 321)
            .expect("trash owner");
        session
            .purge_item(item.id, trashed_revision)
            .expect("purge owner");

        let (attachment_revision, record) = session
            .storage
            .load_attachment(summary.id)
            .expect("attachment tombstone");
        assert_eq!(attachment_revision, 2);
        let encrypted = decode_attachment_record(summary.id, attachment_revision, &record)
            .expect("decode tombstone");
        let (manifest, context) =
            open_attachment_manifest(&session.root_key, &encrypted).expect("open tombstone");
        assert!(matches!(manifest, AttachmentManifestV1::Tombstone { .. }));
        assert!(context.is_none());
        assert!(
            session
                .storage
                .list_attachment_chunks(summary.id)
                .expect("no chunks")
                .is_empty()
        );
        session
            .validate_persisted_state()
            .expect("purged state validates");
    }

    #[test]
    fn persisted_state_detects_missing_attachment_chunks() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let source_path = dir.path().join("chunked.dat");
        fs::write(&source_path, vec![0x44; ATTACHMENT_CHUNK_SIZE as usize + 1])
            .expect("write source");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("owner", "body");
        session.put_item(&item, 1).expect("store owner");
        let (summary, _) = session
            .add_attachment_from_path(item.id, 1, &source_path)
            .expect("add attachment");
        session
            .storage
            .delete_attachment_chunks(summary.id)
            .expect("tamper chunks");

        assert!(matches!(
            session.validate_persisted_state(),
            Err(VaultError::InconsistentAttachment)
        ));
    }

    #[test]
    fn encrypted_backup_restore_preserves_attachment_bytes() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let backup = dir.path().join("backup.sqlite3");
        let source_path = dir.path().join("backup-source.dat");
        let export_path = dir.path().join("backup-restored.dat");
        let bytes = vec![0x77; ATTACHMENT_CHUNK_SIZE as usize + 19];
        fs::write(&source_path, &bytes).expect("write source");
        let mut session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let item = VaultItem::secure_note("owner", "body");
        session.put_item(&item, 1).expect("store owner");
        let (summary, item_revision) = session
            .add_attachment_from_path(item.id, 1, &source_path)
            .expect("add attachment");
        session
            .backup_database_to(&backup)
            .expect("validated encrypted backup");

        session
            .delete_attachment(item.id, summary.id, item_revision, summary.revision, 999)
            .expect("delete live attachment after backup");
        assert!(
            session
                .list_attachments(item.id)
                .expect("live attachment deleted")
                .is_empty()
        );
        session
            .replace_with_backup(&backup, TEST_PASSPHRASE)
            .expect("restore backup");
        let restored_attachments = session
            .list_attachments(item.id)
            .expect("attachment restored");
        assert_eq!(restored_attachments.len(), 1);
        assert!(restored_attachments[0] == summary);
        session
            .export_attachment_to(item.id, summary.id, &export_path)
            .expect("export restored attachment");
        assert_eq!(fs::read(export_path).expect("read restored bytes"), bytes);
    }

    #[test]
    fn locked_restore_install_uses_ciphertext_only_capability() {
        let dir = tempdir().expect("temp directory");
        let source_database = dir.path().join("locked-restore-source.sqlite3");
        let target_database = dir.path().join("locked-restore-target.sqlite3");
        let source =
            VaultSession::create(&source_database, TEST_PASSPHRASE).expect("create source vault");
        let item = VaultItem::secure_note("locked install source", "source body");
        source.put_item(&item, 1).expect("store source item");
        let target =
            VaultSession::create(&target_database, TEST_PASSPHRASE).expect("create target vault");
        target
            .put_item(&VaultItem::secure_note("target marker", "target body"), 1)
            .expect("store target marker");

        let prepared = VaultSession::prepare_restore(&source_database, TEST_PASSPHRASE)
            .expect("prepare restore");
        let locked_install = prepared.into_locked_install();
        let _: () = locked_install
            .install_to(&target_database)
            .expect("install ciphertext-only restore");
        drop(target);
        drop(source);

        let restored =
            VaultSession::unlock(&target_database, TEST_PASSPHRASE).expect("unlock restored vault");
        assert_eq!(
            restored
                .get_item(item.id)
                .expect("restored source item")
                .title,
            "locked install source"
        );
    }

    #[test]
    fn prepared_restore_rejects_replaced_candidate_without_mutating_live_vault() {
        let dir = tempdir().expect("temp directory");
        let source_database = dir.path().join("prepared-source.sqlite3");
        let replacement_database = dir.path().join("prepared-replacement.sqlite3");
        let candidate = dir.path().join("prepared-candidate.sqlite3");
        let replacement = dir.path().join("prepared-replacement-backup.sqlite3");
        let live_database = dir.path().join("prepared-live.sqlite3");

        let source =
            VaultSession::create(&source_database, TEST_PASSPHRASE).expect("create source vault");
        let source_item = VaultItem::secure_note("authenticated source", "source body");
        source.put_item(&source_item, 1).expect("store source item");
        source
            .backup_database_to(&candidate)
            .expect("backup authenticated candidate");
        drop(source);

        let replacement_session = VaultSession::create(&replacement_database, TEST_PASSPHRASE)
            .expect("create replacement vault");
        replacement_session
            .put_item(
                &VaultItem::secure_note("replacement source", "replacement body"),
                1,
            )
            .expect("store replacement item");
        replacement_session
            .backup_database_to(&replacement)
            .expect("backup replacement candidate");
        drop(replacement_session);

        let mut live =
            VaultSession::create(&live_database, TEST_PASSPHRASE).expect("create live vault");
        let live_item = VaultItem::secure_note("live marker", "must survive failed restore");
        live.put_item(&live_item, 1).expect("store live marker");

        let prepared = VaultSession::prepare_restore(&candidate, TEST_PASSPHRASE)
            .expect("prepare authenticated restore");
        fs::copy(&replacement, &candidate).expect("replace prepared candidate");

        assert!(matches!(
            live.commit_prepared_restore(prepared),
            Err(VaultError::Storage(StorageError::RestoreSourceChanged))
        ));
        assert!(
            live.get_item(live_item.id)
                .expect("live marker remains after rejected restore")
                == live_item
        );
        assert!(live.get_item(source_item.id).is_err());
    }

    #[test]
    fn locked_restore_rejects_replaced_candidate_without_mutating_target() {
        let dir = tempdir().expect("temp directory");
        let source_database = dir.path().join("locked-fenced-source.sqlite3");
        let replacement_database = dir.path().join("locked-fenced-replacement.sqlite3");
        let candidate = dir.path().join("locked-fenced-candidate.sqlite3");
        let replacement = dir.path().join("locked-fenced-replacement-backup.sqlite3");
        let target_database = dir.path().join("locked-fenced-target.sqlite3");

        let source =
            VaultSession::create(&source_database, TEST_PASSPHRASE).expect("create source vault");
        source
            .put_item(&VaultItem::secure_note("source", "body"), 1)
            .expect("store source item");
        source
            .backup_database_to(&candidate)
            .expect("backup authenticated candidate");
        drop(source);

        let replacement_session = VaultSession::create(&replacement_database, TEST_PASSPHRASE)
            .expect("create replacement vault");
        replacement_session
            .put_item(&VaultItem::secure_note("replacement", "body"), 1)
            .expect("store replacement item");
        replacement_session
            .backup_database_to(&replacement)
            .expect("backup replacement candidate");
        drop(replacement_session);

        let target =
            VaultSession::create(&target_database, TEST_PASSPHRASE).expect("create target vault");
        let target_item = VaultItem::secure_note("target marker", "must remain");
        target
            .put_item(&target_item, 1)
            .expect("store target marker");
        drop(target);

        let locked_restore = VaultSession::prepare_restore(&candidate, TEST_PASSPHRASE)
            .expect("prepare authenticated restore")
            .into_locked_install();
        fs::copy(&replacement, &candidate).expect("replace prepared candidate");

        assert!(matches!(
            locked_restore.install_to(&target_database),
            Err(VaultError::Storage(StorageError::RestoreSourceChanged))
        ));
        let target = VaultSession::unlock(&target_database, TEST_PASSPHRASE)
            .expect("unlock target after rejected restore");
        assert!(
            target
                .get_item(target_item.id)
                .expect("target marker survives rejected restore")
                == target_item
        );
    }

    #[test]
    fn rewrap_rejects_replaced_candidate_before_changing_its_root_wrap() {
        const NEW_PASSPHRASE: &str = "a different master passphrase after restore";

        let dir = tempdir().expect("temp directory");
        let source_database = dir.path().join("rewrap-fenced-source.sqlite3");
        let replacement_database = dir.path().join("rewrap-fenced-replacement.sqlite3");
        let candidate = dir.path().join("rewrap-fenced-candidate.sqlite3");
        let replacement = dir.path().join("rewrap-fenced-replacement-backup.sqlite3");

        let source =
            VaultSession::create(&source_database, TEST_PASSPHRASE).expect("create source vault");
        source
            .put_item(&VaultItem::secure_note("source", "body"), 1)
            .expect("store source item");
        source
            .backup_database_to(&candidate)
            .expect("backup authenticated candidate");
        drop(source);

        let replacement_session = VaultSession::create(&replacement_database, TEST_PASSPHRASE)
            .expect("create replacement vault");
        let replacement_item = VaultItem::secure_note("replacement", "body");
        replacement_session
            .put_item(&replacement_item, 1)
            .expect("store replacement item");
        replacement_session
            .backup_database_to(&replacement)
            .expect("backup replacement candidate");
        drop(replacement_session);

        let prepared = VaultSession::prepare_restore(&candidate, TEST_PASSPHRASE)
            .expect("prepare authenticated restore");
        fs::copy(&replacement, &candidate).expect("replace prepared candidate");

        assert!(matches!(
            prepared.rewrap_candidate_master_passphrase(NEW_PASSPHRASE),
            Err(VaultError::Storage(StorageError::RestoreSourceChanged))
        ));
        let replacement_after_failure = VaultSession::unlock(&candidate, TEST_PASSPHRASE)
            .expect("original replacement passphrase remains valid");
        assert!(
            replacement_after_failure
                .get_item(replacement_item.id)
                .expect("replacement item remains readable")
                == replacement_item
        );
        drop(replacement_after_failure);
        assert!(VaultSession::unlock(&candidate, NEW_PASSPHRASE).is_err());
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
                email: "ada@example.test".to_owned(),
                notes: "Call first".to_owned(),
            }],
            principals: Vec::new(),
            retired_principal_ids: BTreeSet::new(),
            retired_device_ids: BTreeSet::new(),
            retired_signing_public_key_hexes: BTreeSet::new(),
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
    fn emergency_card_reserved_id_rejects_generic_mutation_paths() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let card = EmergencyCard::empty();
        let raw = VaultItem::emergency_card(&card);

        assert!(matches!(
            session.put_item(&raw, 1),
            Err(VaultError::ReservedSystemItem)
        ));
        assert_eq!(session.set_emergency_card(&card).expect("create card"), 1);

        let mut generic = session
            .get_item(EMERGENCY_CARD_ID)
            .expect("load emergency singleton");
        generic.fields.insert("card".to_owned(), "{}".to_owned());
        assert!(matches!(
            session.update_item(&generic, 1),
            Err(VaultError::ReservedSystemItem)
        ));
        assert!(matches!(
            session.trash_item(EMERGENCY_CARD_ID, 1, 42),
            Err(VaultError::ReservedSystemItem)
        ));
        assert!(matches!(
            session.restore_item(EMERGENCY_CARD_ID, 1),
            Err(VaultError::ReservedSystemItem)
        ));
        assert!(matches!(
            session.purge_item(EMERGENCY_CARD_ID, 1),
            Err(VaultError::ReservedSystemItem)
        ));

        let (stored, revision) = session
            .get_emergency_card()
            .expect("load card")
            .expect("card present");
        assert_eq!(revision, 1);
        assert_eq!(stored, card);
    }

    #[test]
    fn trusted_device_pairing_persists_signing_key_and_consumes_challenge_once() {
        use vault_sharing::{DeviceKeyPair, DeviceSigningKeyPair, answer_pairing_challenge};

        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
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
        assert_eq!(session.set_emergency_card(&card).expect("store card"), 1);

        let challenge = session
            .create_trusted_device_pairing_challenge(principal_id, device_id)
            .expect("create challenge");
        let proof = answer_pairing_challenge(&challenge, &encryption_key, &signing_key)
            .expect("answer challenge");
        let mut edited_card = card.clone();
        edited_card.instructions = "Generic card edit cancels pending pairings".to_owned();
        assert_eq!(
            session
                .set_emergency_card(&edited_card)
                .expect("edit card while pairing is pending"),
            2
        );
        assert!(matches!(
            session.complete_trusted_device_pairing(&proof),
            Err(VaultError::PairingChallengeUnavailable)
        ));

        let challenge = session
            .create_trusted_device_pairing_challenge(principal_id, device_id)
            .expect("create replacement challenge");
        let proof = answer_pairing_challenge(&challenge, &encryption_key, &signing_key)
            .expect("answer replacement challenge");
        assert_eq!(
            session
                .complete_trusted_device_pairing(&proof)
                .expect("complete pairing"),
            3
        );
        let (stored, revision) = session
            .get_emergency_card()
            .expect("load card")
            .expect("card present");
        assert_eq!(revision, 3);
        assert_eq!(
            stored.principals[0].devices[0].signing_public_key_hex,
            Some(encode_hex_32(&signing_key.public_bytes()))
        );
        assert!(matches!(
            session.complete_trusted_device_pairing(&proof),
            Err(VaultError::PairingChallengeUnavailable)
        ));

        let signing_public_key_hex = encode_hex_32(&signing_key.public_bytes());
        let mut revoked = stored.clone();
        revoked.principals[0].devices.clear();
        assert_eq!(
            session
                .set_emergency_card(&revoked)
                .expect("revoke paired device"),
            4
        );
        let (revoked, _) = session
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
            session
                .set_emergency_card(&replacement)
                .expect("add replacement device"),
            5
        );
        let replacement_challenge = session
            .create_trusted_device_pairing_challenge(principal_id, replacement_device_id)
            .expect("create replacement-device challenge");
        let reused_signing_proof = answer_pairing_challenge(
            &replacement_challenge,
            &replacement_encryption_key,
            &signing_key,
        )
        .expect("answer with retired signing key");
        assert!(matches!(
            session.complete_trusted_device_pairing(&reused_signing_proof),
            Err(VaultError::InvalidTrustedPrincipal)
        ));
        let (unchanged, revision) = session
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

        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");

        let mut card = EmergencyCard::empty();
        card.instructions = "Original instructions".to_owned();
        assert_eq!(session.set_emergency_card(&card).expect("create card"), 1);

        let mut policy = AccessPolicy::new(false);
        policy.set_private_forever();
        assert_eq!(
            session
                .set_access_policy(EMERGENCY_CARD_ID, 1, policy.clone())
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
        assert_eq!(session.set_emergency_card(&card).expect("update card"), 3);

        let stored = session
            .get_item(EMERGENCY_CARD_ID)
            .expect("load encrypted card item");
        assert_eq!(stored.access_policy, policy);
        assert_eq!(stored.parse_emergency_card(), Some(card));
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
            principals: Vec::new(),
            retired_principal_ids: BTreeSet::new(),
            retired_device_ids: BTreeSet::new(),
            retired_signing_public_key_hexes: BTreeSet::new(),
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
                    email: String::new(),
                    notes: String::new(),
                })
                .collect(),
            principals: Vec::new(),
            retired_principal_ids: BTreeSet::new(),
            retired_device_ids: BTreeSet::new(),
            retired_signing_public_key_hexes: BTreeSet::new(),
            instructions: String::new(),
        };
        assert!(matches!(
            session.set_emergency_card(&too_many_contacts),
            Err(VaultError::ItemTooLarge)
        ));

        let oversized_email = EmergencyCard {
            selected_item_ids: Vec::new(),
            contacts: vec![EmergencyContact {
                name: "Ada".to_owned(),
                relation: "Sibling".to_owned(),
                phone: String::new(),
                email: "x".repeat(MAX_ITEM_TITLE_CHARS + 1),
                notes: String::new(),
            }],
            principals: Vec::new(),
            retired_principal_ids: BTreeSet::new(),
            retired_device_ids: BTreeSet::new(),
            retired_signing_public_key_hexes: BTreeSet::new(),
            instructions: String::new(),
        };
        assert!(matches!(
            session.set_emergency_card(&oversized_email),
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
        let encrypted =
            encrypt_item(&session.root_key, &corrupted, 2).expect("encrypt corrupt row");
        session
            .storage
            .update_item_if_revision(&encrypted, 1)
            .expect("inject corrupt storage row");
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
    fn recovery_kit_verification_is_read_only_and_handles_missing_or_wrong_keys() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let secret = RecoverySecret::generate().expect("recovery secret");
        let wrong = RecoverySecret::generate().expect("wrong recovery secret");

        assert!(!session.verify_recovery_kit(&secret).expect("missing kit"));
        session
            .install_recovery_kit(&secret)
            .expect("install recovery kit");
        assert!(
            session
                .verify_recovery_kit(&secret)
                .expect("verify correct key")
        );
        assert!(
            !session
                .verify_recovery_kit(&wrong)
                .expect("verify wrong key")
        );
        assert!(session.has_recovery_kit().expect("kit remains installed"));

        let foreign_root = AccountRootKey::generate().expect("foreign root key");
        let foreign_secret = RecoverySecret::generate().expect("foreign recovery secret");
        let foreign_wrap = wrap_root_key_with_recovery_secret(&foreign_secret, &foreign_root)
            .expect("foreign recovery wrap");
        session
            .storage
            .store_recovery_wrap(&foreign_wrap)
            .expect("transplant foreign recovery wrap");
        assert!(
            !session
                .verify_recovery_kit(&foreign_secret)
                .expect("foreign wrap must not verify against this vault")
        );
    }

    #[test]
    fn recovery_kit_rotation_replaces_current_wrap_but_not_historical_backup() {
        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("vault.sqlite3");
        let historical_backup = dir.path().join("historical.sqlite3");
        let session = VaultSession::create(&database, TEST_PASSPHRASE).expect("create vault");
        let old_secret = RecoverySecret::generate().expect("old recovery secret");
        session
            .install_recovery_kit(&old_secret)
            .expect("install old recovery kit");
        session
            .backup_database_to(&historical_backup)
            .expect("create historical backup");

        let new_secret = RecoverySecret::generate().expect("new recovery secret");
        session
            .install_recovery_kit(&new_secret)
            .expect("replace recovery kit");
        drop(session);

        assert!(VaultSession::unlock_with_recovery_kit(&database, &old_secret).is_err());
        drop(
            VaultSession::unlock_with_recovery_kit(&database, &new_secret)
                .expect("new recovery key unlocks current vault"),
        );
        drop(
            VaultSession::unlock_with_recovery_kit(&historical_backup, &old_secret)
                .expect("old recovery key still unlocks historical backup"),
        );
        assert!(VaultSession::unlock_with_recovery_kit(&historical_backup, &new_secret).is_err());
    }

    #[test]
    fn recovery_kit_can_prepare_staged_backup_restore_with_a_new_master_passphrase() {
        const NEW_PASSPHRASE: &str = "a new passphrase after disaster recovery";

        let dir = tempdir().expect("temp directory");
        let database = dir.path().join("source.sqlite3");
        let backup = dir.path().join("backup.sqlite3");
        let candidate = dir.path().join("candidate.sqlite3");
        let target = dir.path().join("target.sqlite3");
        let source = VaultSession::create(&database, TEST_PASSPHRASE).expect("create source");
        let secret = RecoverySecret::generate().expect("recovery secret");
        source
            .install_recovery_kit(&secret)
            .expect("install recovery kit");
        let item = VaultItem::secure_note("recovery restore", "body");
        source.put_item(&item, 1).expect("store item");
        source
            .backup_database_to(&backup)
            .expect("create encrypted backup");
        drop(source);

        let original_backup = fs::read(&backup).expect("read source backup");
        fs::copy(&backup, &candidate).expect("stage candidate copy");
        let prepared = VaultSession::prepare_restore_with_recovery_kit(&candidate, &secret)
            .expect("authenticate candidate with recovery kit")
            .rewrap_candidate_master_passphrase(NEW_PASSPHRASE)
            .expect("rewrap staged candidate");
        let restored = prepared
            .install_to(&target)
            .expect("install recovered backup");
        assert!(restored.get_item(item.id).expect("load item") == item);
        drop(restored);

        assert!(VaultSession::unlock(&target, TEST_PASSPHRASE).is_err());
        drop(
            VaultSession::unlock(&target, NEW_PASSPHRASE)
                .expect("new master passphrase unlocks recovered vault"),
        );
        drop(
            VaultSession::unlock_with_recovery_kit(&target, &secret)
                .expect("recovery key remains usable after restore"),
        );
        assert_eq!(
            fs::read(&backup).expect("read unchanged source backup"),
            original_backup
        );
    }

    #[test]
    fn recovery_restore_requires_the_backup_recovery_wrap_and_matching_secret() {
        let dir = tempdir().expect("temp directory");
        let without_kit = dir.path().join("without-kit.sqlite3");
        let with_kit = dir.path().join("with-kit.sqlite3");
        let secret = RecoverySecret::generate().expect("recovery secret");
        let wrong = RecoverySecret::generate().expect("wrong recovery secret");

        drop(VaultSession::create(&without_kit, TEST_PASSPHRASE).expect("create vault"));
        assert!(matches!(
            VaultSession::prepare_restore_with_recovery_kit(&without_kit, &secret),
            Err(VaultError::Storage(StorageError::NotInitialized))
        ));

        let session = VaultSession::create(&with_kit, TEST_PASSPHRASE).expect("create vault");
        session
            .install_recovery_kit(&secret)
            .expect("install recovery kit");
        drop(session);
        assert!(VaultSession::prepare_restore_with_recovery_kit(&with_kit, &wrong).is_err());
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
