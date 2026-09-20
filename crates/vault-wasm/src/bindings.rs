//! `wasm-bindgen` boundary. Methods take/return JSON strings so rich Rust
//! types cross cleanly. Only ciphertext snapshots and explicitly
//! decrypted-on-request plaintext cross to JS; the root key never does.

use vault_storage::ITEM_MAX_ENCRYPTED_RECORD_BYTES;
use wasm_bindgen::prelude::*;

use vault_crypto::{
    AccountSecret, EncryptedAttachmentV1, RecoverySecret, RemoteAccountRootWrapV1,
    SessionResumeSecret, SessionResumeWrapV1,
};
use vault_sharing::{
    DeviceKeyPair, DeviceSigningKeyPair, PairingChallengeV1, PairingProofV1,
    answer_pairing_challenge,
};

use crate::{BrowserVault, DeadlineEntry, WasmVaultError, generate_strong_password};

const SESSION_RESUME_PAYLOAD_VERSION: u16 = 2;
const READABLE_EXPORT_FORMAT_VERSION: u16 = 1;
const REMOTE_ROOT_WRAP_MAX_JSON_BYTES: usize = 4 * 1024;

fn js_err(e: WasmVaultError) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn ser_err() -> JsValue {
    JsValue::from_str("serialization failed")
}

const DEVICE_IDENTITY_PRIVATE_BYTES: usize = 64;

#[derive(serde::Serialize)]
struct DeviceRegistrationPayload {
    format_version: u16,
    device_id: uuid::Uuid,
    encryption_public_key_hex: String,
    signing_public_key_hex: String,
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

/// Long-lived recipient device identity used by the browser secure-key-store
/// adapter. Secret material is exported only as a short-lived Uint8Array so the
/// host can immediately wrap it with a non-extractable Web Crypto key.
#[wasm_bindgen]
pub struct WasmDeviceIdentity {
    device_id: uuid::Uuid,
    encryption: DeviceKeyPair,
    signing: DeviceSigningKeyPair,
}

#[wasm_bindgen]
impl WasmDeviceIdentity {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate(device_id: &str) -> Result<WasmDeviceIdentity, JsValue> {
        let device_id = parse_uuid(device_id)?;
        let encryption =
            DeviceKeyPair::generate().map_err(|_| js_err(WasmVaultError::RandomGeneration))?;
        let signing = DeviceSigningKeyPair::generate()
            .map_err(|_| js_err(WasmVaultError::RandomGeneration))?;
        Ok(Self {
            device_id,
            encryption,
            signing,
        })
    }

    #[wasm_bindgen(js_name = fromPrivateKeyBytes)]
    pub fn from_private_key_bytes(
        device_id: &str,
        private_key_bytes: &[u8],
    ) -> Result<WasmDeviceIdentity, JsValue> {
        if private_key_bytes.len() != DEVICE_IDENTITY_PRIVATE_BYTES {
            return Err(JsValue::from_str("device private-key material is invalid"));
        }
        let device_id = parse_uuid(device_id)?;
        let mut encryption_bytes = [0u8; 32];
        encryption_bytes.copy_from_slice(&private_key_bytes[..32]);
        let mut signing_bytes = [0u8; 32];
        signing_bytes.copy_from_slice(&private_key_bytes[32..]);
        let encryption = DeviceKeyPair::from_secret_bytes(encryption_bytes);
        let signing = DeviceSigningKeyPair::from_secret_bytes(signing_bytes)
            .map_err(|_| JsValue::from_str("device signing key is invalid"))?;
        encryption_bytes.fill(0);
        signing_bytes.fill(0);
        Ok(Self {
            device_id,
            encryption,
            signing,
        })
    }

    #[wasm_bindgen(js_name = registrationJson)]
    pub fn registration_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&DeviceRegistrationPayload {
            format_version: 1,
            device_id: self.device_id,
            encryption_public_key_hex: hex(&self.encryption.public_bytes()),
            signing_public_key_hex: hex(&self.signing.public_bytes()),
        })
        .map_err(|_| ser_err())
    }

    #[wasm_bindgen(js_name = exportPrivateKeyBytes)]
    pub fn export_private_key_bytes(&self) -> js_sys::Uint8Array {
        let encryption = self.encryption.secret_bytes();
        let signing = self.signing.secret_bytes();
        let mut output = [0u8; DEVICE_IDENTITY_PRIVATE_BYTES];
        output[..32].copy_from_slice(encryption.as_ref());
        output[32..].copy_from_slice(signing.as_ref());
        let js_output = js_sys::Uint8Array::from(output.as_slice());
        output.fill(0);
        js_output
    }

    #[wasm_bindgen(js_name = answerPairingChallengeJson)]
    pub fn answer_pairing_challenge_json(&self, challenge_json: &str) -> Result<String, JsValue> {
        let challenge: PairingChallengeV1 =
            serde_json::from_str(challenge_json).map_err(|_| ser_err())?;
        if challenge.device_id != self.device_id {
            return Err(JsValue::from_str(
                "pairing challenge targets a different device",
            ));
        }
        let proof = answer_pairing_challenge(&challenge, &self.encryption, &self.signing)
            .map_err(|error| js_err(WasmVaultError::Sharing(error)))?;
        serde_json::to_string(&proof).map_err(|_| ser_err())
    }
}

#[wasm_bindgen]
pub struct WasmVault {
    inner: BrowserVault,
}

#[wasm_bindgen]
impl WasmVault {
    /// New empty vault (not yet initialized).
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: BrowserVault::new_empty(),
        }
    }

    /// Load from a previously saved snapshot JSON.
    #[wasm_bindgen(js_name = fromSnapshotJson)]
    pub fn from_snapshot_json(snapshot_json: &str) -> Result<WasmVault, JsValue> {
        let snapshot = serde_json::from_str(snapshot_json).map_err(|_| ser_err())?;
        let inner = BrowserVault::from_snapshot(snapshot).map_err(js_err)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(js_name = isInitialized)]
    pub fn is_initialized(&self) -> bool {
        self.inner.is_initialized()
    }

    #[wasm_bindgen(js_name = isUnlocked)]
    pub fn is_unlocked(&self) -> bool {
        self.inner.is_unlocked()
    }

    /// Create + unlock a new vault. Rejects passphrases under 12 chars.
    pub fn create(&mut self, passphrase: &str) -> Result<(), JsValue> {
        self.inner.create(passphrase).map_err(js_err)
    }

    pub fn unlock(&mut self, passphrase: &str) -> Result<(), JsValue> {
        self.inner.unlock(passphrase).map_err(js_err)
    }

    #[wasm_bindgen(js_name = verifyMasterPassphrase)]
    pub fn verify_master_passphrase(&self, passphrase: &str) -> Result<(), JsValue> {
        self.inner
            .verify_master_passphrase(passphrase)
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = exportRemoteAccountRootWrapJson)]
    pub fn export_remote_account_root_wrap_json(
        &self,
        passphrase: &str,
        account_secret_code: &str,
        account_id: &str,
    ) -> Result<String, JsValue> {
        let secret = AccountSecret::from_code(account_secret_code)
            .map_err(|error| js_err(WasmVaultError::Crypto(error)))?;
        let wrapped = self
            .inner
            .export_remote_account_root_wrap(passphrase, &secret, parse_uuid(account_id)?)
            .map_err(js_err)?;
        serde_json::to_string(&wrapped).map_err(|_| ser_err())
    }

    #[wasm_bindgen(js_name = initializeFromRemoteAccountRootWrapJson)]
    pub fn initialize_from_remote_account_root_wrap_json(
        &mut self,
        passphrase: &str,
        account_secret_code: &str,
        account_id: &str,
        wrapped_json: &str,
    ) -> Result<(), JsValue> {
        if wrapped_json.len() > REMOTE_ROOT_WRAP_MAX_JSON_BYTES {
            return Err(JsValue::from_str(
                "remote account root wrap exceeds the supported size",
            ));
        }
        let secret = AccountSecret::from_code(account_secret_code)
            .map_err(|error| js_err(WasmVaultError::Crypto(error)))?;
        let wrapped: RemoteAccountRootWrapV1 =
            serde_json::from_str(wrapped_json).map_err(|_| ser_err())?;
        self.inner
            .initialize_from_remote_account_root_wrap(
                passphrase,
                &secret,
                parse_uuid(account_id)?,
                &wrapped,
            )
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = changePassphrase)]
    pub fn change_passphrase(
        &mut self,
        current_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .change_passphrase(current_passphrase, new_passphrase)
            .map_err(js_err)
    }

    pub fn lock(&mut self) {
        self.inner.lock();
    }

    /// Return a JSON object containing an opaque, session-scoped reload secret
    /// and its encrypted root-key wrap. Neither value is the master passphrase,
    /// recovery secret, or raw root key.
    #[wasm_bindgen(js_name = createSessionResumeJson)]
    pub fn create_session_resume_json(&self) -> Result<String, JsValue> {
        let (secret, wrapped) = self.inner.create_session_resume().map_err(js_err)?;
        serde_json::to_string(&SessionResumePayload {
            format_version: SESSION_RESUME_PAYLOAD_VERSION,
            secret,
            wrapped,
        })
        .map_err(|_| ser_err())
    }

    /// Resume this loaded ciphertext snapshot from an opaque tab-session
    /// credential previously returned by `createSessionResumeJson`.
    #[wasm_bindgen(js_name = unlockWithSessionResumeJson)]
    pub fn unlock_with_session_resume_json(&mut self, payload_json: &str) -> Result<(), JsValue> {
        let payload: SessionResumePayload =
            serde_json::from_str(payload_json).map_err(|_| ser_err())?;
        if payload.format_version != SESSION_RESUME_PAYLOAD_VERSION {
            return Err(js_err(WasmVaultError::InvalidSessionResume));
        }
        let secret = SessionResumeSecret::from_hex(&payload.secret)
            .map_err(|error| js_err(WasmVaultError::Crypto(error)))?;
        self.inner
            .unlock_with_session_resume(&secret, &payload.wrapped)
            .map_err(js_err)
    }

    /// Serialize the ciphertext store for IndexedDB persistence.
    #[wasm_bindgen(js_name = snapshotJson)]
    pub fn snapshot_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner.to_snapshot()).map_err(|_| ser_err())
    }

    /// Insert a new item (JSON-encoded `VaultItem`) at revision 0.
    #[wasm_bindgen(js_name = putItemJson)]
    pub fn put_item_json(&self, item_json: &str) -> Result<(), JsValue> {
        let item = serde_json::from_str(item_json).map_err(|_| ser_err())?;
        self.inner.put_item(&item).map_err(js_err)
    }

    /// Get an active item as JSON by id (UUID string).
    #[wasm_bindgen(js_name = getItemJson)]
    pub fn get_item_json(&self, id: &str) -> Result<String, JsValue> {
        let id = parse_uuid(id)?;
        let item = self.inner.get_item(id).map_err(js_err)?;
        serde_json::to_string(&item).map_err(|_| ser_err())
    }

    /// Return an encrypted item record for sync, or null when it is absent.
    #[wasm_bindgen(js_name = getEncryptedItemJson)]
    pub fn get_encrypted_item_json(&self, id: &str) -> Result<JsValue, JsValue> {
        let id = parse_uuid(id)?;
        match self.inner.get_encrypted_item(id).map_err(js_err)? {
            Some(item) => Ok(JsValue::from_str(
                &serde_json::to_string(&item).map_err(|_| ser_err())?,
            )),
            None => Ok(JsValue::NULL),
        }
    }

    /// List opaque IDs for every sync-eligible encrypted item.
    #[wasm_bindgen(js_name = listEncryptedItemIdsJson)]
    pub fn list_encrypted_item_ids_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner.list_encrypted_item_ids().map_err(js_err)?)
            .map_err(|_| ser_err())
    }

    /// Return the authenticated opaque-routing tombstone bit for one item.
    #[wasm_bindgen(js_name = encryptedItemIsTombstone)]
    pub fn encrypted_item_is_tombstone(&self, id: &str) -> Result<bool, JsValue> {
        self.inner
            .encrypted_item_is_tombstone(parse_uuid(id)?)
            .map_err(js_err)
    }

    /// Compare-and-swap an already-encrypted item accepted by the sync layer.
    #[wasm_bindgen(js_name = applyEncryptedItemJson)]
    pub fn apply_encrypted_item_json(
        &self,
        next_json: &str,
        expected_json: Option<String>,
    ) -> Result<(), JsValue> {
        if next_json.len() > ITEM_MAX_ENCRYPTED_RECORD_BYTES
            || expected_json
                .as_ref()
                .is_some_and(|value| value.len() > ITEM_MAX_ENCRYPTED_RECORD_BYTES)
        {
            return Err(JsValue::from_str(
                "encrypted sync item exceeds supported bounds",
            ));
        }
        let next = serde_json::from_str(next_json).map_err(|_| ser_err())?;
        let expected = expected_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| ser_err())?;
        self.inner
            .apply_encrypted_item(&next, expected.as_ref())
            .map_err(js_err)
    }

    /// List active items as redacted JSON summaries.
    ///
    /// Secret-bearing fields and notes never cross the WASM boundary here;
    /// callers must explicitly fetch one item with `getItemJson` when opening
    /// its detail/editor surface.
    #[wasm_bindgen(js_name = listItemsJson)]
    pub fn list_items_json(&self) -> Result<String, JsValue> {
        let items = self.inner.list_items().map_err(js_err)?;
        let projected: Vec<ListEntry> = items
            .into_iter()
            .map(|(item, revision)| ListEntry {
                item: ListItemSummary {
                    id: item.id,
                    kind: item.kind,
                    title: item.title,
                },
                revision,
            })
            .collect();
        serde_json::to_string(&projected).map_err(|_| ser_err())
    }

    /// Export the complete active vault as explicit plaintext JSON. This is a
    /// deliberate disclosure boundary for user-initiated portable export: all
    /// active item fields and the Emergency Card may cross to JS, but root-key,
    /// passphrase, recovery-secret, and session-resume material never do.
    #[wasm_bindgen(js_name = exportReadableJson)]
    pub fn export_readable_json(&self) -> Result<String, JsValue> {
        readable_export_json(&self.inner).map_err(js_err)
    }

    /// List redacted local deadline metadata for an explicitly supplied local
    /// calendar date. Full record fields remain inside WASM.
    #[wasm_bindgen(js_name = listDeadlinesJson)]
    pub fn list_deadlines_json(&self, today_ymd: &str) -> Result<String, JsValue> {
        let today = vault_models::reminders::parse_ymd(today_ymd)
            .ok_or_else(|| JsValue::from_str("invalid local date"))?;
        let deadlines = self.inner.list_deadlines(today).map_err(js_err)?;
        deadline_entries_json(deadlines).map_err(|_| ser_err())
    }

    /// List only the non-secret credential metadata needed for matching and
    /// selection. Passwords and notes remain inside WASM until an explicit
    /// credential fetch/fill request.
    #[wasm_bindgen(js_name = listCredentialsJson)]
    pub fn list_credentials_json(&self) -> Result<String, JsValue> {
        let items = self.inner.list_items().map_err(js_err)?;
        let projected: Vec<CredentialListEntry> = items
            .into_iter()
            .filter(|(item, _)| item.kind == vault_models::ItemKind::Password)
            .map(|(item, revision)| CredentialListEntry {
                id: item.id,
                title: item.title,
                username: item.fields.get("username").cloned().unwrap_or_default(),
                website: item.fields.get("website").cloned().unwrap_or_default(),
                revision,
            })
            .collect();
        serde_json::to_string(&projected).map_err(|_| ser_err())
    }

    /// Update an item; returns the new revision.
    #[wasm_bindgen(js_name = updateItemJson)]
    pub fn update_item_json(
        &self,
        item_json: &str,
        expected_revision: u64,
    ) -> Result<u64, JsValue> {
        let item = serde_json::from_str(item_json).map_err(|_| ser_err())?;
        self.inner
            .update_item(&item, expected_revision)
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = beginAttachmentImportJson)]
    pub fn begin_attachment_import_json(
        &self,
        owner_item_id: &str,
        expected_item_revision: u64,
        filename: &str,
        plaintext_size: u64,
    ) -> Result<String, JsValue> {
        let owner_item_id = parse_uuid(owner_item_id)?;
        let summary = self
            .inner
            .begin_attachment_import(
                owner_item_id,
                expected_item_revision,
                filename,
                plaintext_size,
            )
            .map_err(js_err)?;
        serde_json::to_string(&summary).map_err(|_| ser_err())
    }

    #[wasm_bindgen(js_name = encryptAttachmentImportChunk)]
    pub fn encrypt_attachment_import_chunk(
        &self,
        attachment_id: &str,
        index: u32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        let attachment_id = parse_uuid(attachment_id)?;
        self.inner
            .encrypt_attachment_import_chunk(attachment_id, index, plaintext)
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = cancelAttachmentImport)]
    pub fn cancel_attachment_import(&self, attachment_id: &str) -> Result<(), JsValue> {
        let attachment_id = parse_uuid(attachment_id)?;
        self.inner.cancel_attachment_import(attachment_id);
        Ok(())
    }

    #[wasm_bindgen(js_name = commitAttachmentImportJson)]
    pub fn commit_attachment_import_json(&self, attachment_id: &str) -> Result<String, JsValue> {
        let attachment_id = parse_uuid(attachment_id)?;
        let committed = self
            .inner
            .commit_attachment_import(attachment_id)
            .map_err(js_err)?;
        let encrypted_record_json =
            serde_json::to_string(&committed.encrypted_attachment).map_err(|_| ser_err())?;
        serde_json::to_string(&AttachmentImportCommitPayload {
            summary: committed.summary,
            item_revision: committed.item_revision,
            encrypted_record_json,
        })
        .map_err(|_| ser_err())
    }

    #[wasm_bindgen(js_name = describeAttachmentJson)]
    pub fn describe_attachment_json(
        &self,
        owner_item_id: &str,
        attachment_id: &str,
        encrypted_record_json: &str,
    ) -> Result<String, JsValue> {
        let owner_item_id = parse_uuid(owner_item_id)?;
        let attachment_id = parse_uuid(attachment_id)?;
        let encrypted: EncryptedAttachmentV1 =
            serde_json::from_str(encrypted_record_json).map_err(|_| ser_err())?;
        let summary = self
            .inner
            .describe_attachment(owner_item_id, attachment_id, &encrypted)
            .map_err(js_err)?;
        serde_json::to_string(&summary).map_err(|_| ser_err())
    }

    #[wasm_bindgen(js_name = decryptAttachmentChunk)]
    pub fn decrypt_attachment_chunk(
        &self,
        owner_item_id: &str,
        attachment_id: &str,
        encrypted_record_json: &str,
        index: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        let owner_item_id = parse_uuid(owner_item_id)?;
        let attachment_id = parse_uuid(attachment_id)?;
        let encrypted: EncryptedAttachmentV1 =
            serde_json::from_str(encrypted_record_json).map_err(|_| ser_err())?;
        self.inner
            .decrypt_attachment_chunk(owner_item_id, attachment_id, &encrypted, index, ciphertext)
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = deleteAttachmentJson)]
    pub fn delete_attachment_json(
        &self,
        owner_item_id: &str,
        attachment_id: &str,
        expected_item_revision: u64,
        expected_attachment_revision: u64,
        encrypted_record_json: &str,
        deleted_at_ms: u64,
    ) -> Result<String, JsValue> {
        let owner_item_id = parse_uuid(owner_item_id)?;
        let attachment_id = parse_uuid(attachment_id)?;
        let encrypted: EncryptedAttachmentV1 =
            serde_json::from_str(encrypted_record_json).map_err(|_| ser_err())?;
        let committed = self
            .inner
            .delete_attachment(
                owner_item_id,
                attachment_id,
                expected_item_revision,
                expected_attachment_revision,
                &encrypted,
                deleted_at_ms,
            )
            .map_err(js_err)?;
        let encrypted_record_json =
            serde_json::to_string(&committed.tombstone).map_err(|_| ser_err())?;
        serde_json::to_string(&AttachmentDeleteCommitPayload {
            item_revision: committed.item_revision,
            attachment_revision: committed.attachment_revision,
            encrypted_record_json,
        })
        .map_err(|_| ser_err())
    }

    /// Trash an item; returns the new revision.
    #[wasm_bindgen(js_name = trashItem)]
    pub fn trash_item(
        &self,
        id: &str,
        expected_revision: u64,
        deleted_at_ms: u64,
    ) -> Result<u64, JsValue> {
        let id = parse_uuid(id)?;
        self.inner
            .trash_item(id, expected_revision, deleted_at_ms)
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = listTrashedItemsJson)]
    pub fn list_trashed_items_json(&self) -> Result<String, JsValue> {
        let items = self.inner.list_trashed_items().map_err(js_err)?;
        serde_json::to_string(&items).map_err(|_| ser_err())
    }

    #[wasm_bindgen(js_name = restoreItem)]
    pub fn restore_item(&self, id: &str, expected_revision: u64) -> Result<u64, JsValue> {
        let id = parse_uuid(id)?;
        self.inner
            .restore_item(id, expected_revision)
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = trashedAttachmentIdsJson)]
    pub fn trashed_attachment_ids_json(
        &self,
        id: &str,
        expected_revision: u64,
    ) -> Result<String, JsValue> {
        let id = parse_uuid(id)?;
        let ids = self
            .inner
            .trashed_attachment_ids(id, expected_revision)
            .map_err(js_err)?;
        serde_json::to_string(&ids).map_err(|_| ser_err())
    }

    #[wasm_bindgen(js_name = purgeItemJson)]
    pub fn purge_item_json(
        &self,
        id: &str,
        expected_revision: u64,
        attachment_records_json: &str,
    ) -> Result<String, JsValue> {
        let id = parse_uuid(id)?;
        let attachments: Vec<EncryptedAttachmentV1> =
            serde_json::from_str(attachment_records_json).map_err(|_| ser_err())?;
        let committed = self
            .inner
            .purge_item(id, expected_revision, &attachments)
            .map_err(js_err)?;
        let attachments = committed
            .attachments
            .into_iter()
            .map(|attachment| {
                let encrypted_record_json =
                    serde_json::to_string(&attachment.tombstone).map_err(|_| ser_err())?;
                Ok(ItemPurgeAttachmentPayload {
                    id: attachment.id,
                    expected_revision: attachment.expected_revision,
                    attachment_revision: attachment.attachment_revision,
                    chunk_count: attachment.chunk_count,
                    encrypted_record_json,
                })
            })
            .collect::<Result<Vec<_>, JsValue>>()?;
        serde_json::to_string(&ItemPurgeCommitPayload {
            item_revision: committed.item_revision,
            attachments,
        })
        .map_err(|_| ser_err())
    }

    /// Get the Emergency Card as `{ card, revision }` JSON, or `null`.
    #[wasm_bindgen(js_name = getEmergencyCardJson)]
    pub fn get_emergency_card_json(&self) -> Result<JsValue, JsValue> {
        match self.inner.get_emergency_card().map_err(js_err)? {
            Some((card, revision)) => {
                let payload = EmergencyCardEntry { card, revision };
                let json = serde_json::to_string(&payload).map_err(|_| ser_err())?;
                Ok(JsValue::from_str(&json))
            }
            None => Ok(JsValue::NULL),
        }
    }

    /// Set the Emergency Card (JSON-encoded `EmergencyCard`); returns revision.
    #[wasm_bindgen(js_name = setEmergencyCardJson)]
    pub fn set_emergency_card_json(&self, card_json: &str) -> Result<u64, JsValue> {
        let card = serde_json::from_str(card_json).map_err(|_| ser_err())?;
        self.inner.set_emergency_card(&card).map_err(js_err)
    }

    /// Create an owner-side one-shot trusted-device pairing challenge. The
    /// hidden verifier state remains only inside this unlocked WASM session.
    #[wasm_bindgen(js_name = createTrustedDevicePairingChallengeJson)]
    pub fn create_trusted_device_pairing_challenge_json(
        &self,
        principal_id: &str,
        device_id: &str,
    ) -> Result<String, JsValue> {
        let principal_id = parse_uuid(principal_id)?;
        let device_id = parse_uuid(device_id)?;
        let challenge = self
            .inner
            .create_trusted_device_pairing_challenge(principal_id, device_id)
            .map_err(js_err)?;
        serde_json::to_string(&challenge).map_err(|_| ser_err())
    }

    /// Verify a recipient pairing proof against the pending one-shot challenge
    /// and persist the Ed25519 signing-key binding on success.
    #[wasm_bindgen(js_name = completeTrustedDevicePairingJson)]
    pub fn complete_trusted_device_pairing_json(&self, proof_json: &str) -> Result<u64, JsValue> {
        let proof: PairingProofV1 = serde_json::from_str(proof_json).map_err(|_| ser_err())?;
        self.inner
            .complete_trusted_device_pairing(&proof)
            .map_err(js_err)
    }

    /// Install a recovery kit from a hex-encoded secret.
    #[wasm_bindgen(js_name = installRecoveryKit)]
    pub fn install_recovery_kit(&self, secret_hex: &str) -> Result<(), JsValue> {
        let secret = parse_secret(secret_hex)?;
        self.inner.install_recovery_kit(&secret).map_err(js_err)
    }

    #[wasm_bindgen(js_name = hasRecoveryKit)]
    pub fn has_recovery_kit(&self) -> Result<bool, JsValue> {
        self.inner.has_recovery_kit().map_err(js_err)
    }

    /// Verify a recovery secret against the installed kit (read-only).
    #[wasm_bindgen(js_name = verifyRecoveryKit)]
    pub fn verify_recovery_kit(&self, secret_hex: &str) -> Result<bool, JsValue> {
        let secret = parse_secret(secret_hex)?;
        self.inner.verify_recovery_kit(&secret).map_err(js_err)
    }

    /// Unlock using a recovery kit secret instead of the master passphrase.
    #[wasm_bindgen(js_name = unlockWithRecoveryKit)]
    pub fn unlock_with_recovery_kit(&mut self, secret_hex: &str) -> Result<(), JsValue> {
        let secret = parse_secret(secret_hex)?;
        self.inner.unlock_with_recovery_kit(&secret).map_err(js_err)
    }

    /// Generate a fresh recovery secret (hex) for the printable kit.
    #[wasm_bindgen(js_name = generateRecoverySecret)]
    pub fn generate_recovery_secret() -> Result<String, JsValue> {
        BrowserVault::generate_recovery_secret().map_err(js_err)
    }

    /// Generate a fresh checksummed Account Secret for cloud bootstrap.
    #[wasm_bindgen(js_name = generateAccountSecret)]
    pub fn generate_account_secret() -> Result<String, JsValue> {
        BrowserVault::generate_account_secret().map_err(js_err)
    }

    #[wasm_bindgen(js_name = validateAccountSecret)]
    pub fn validate_account_secret(code: &str) -> bool {
        BrowserVault::validate_account_secret(code)
    }

    /// Generate a strong password (12..=128 chars, all character classes).
    #[wasm_bindgen(js_name = generatePassword)]
    pub fn generate_password(length: usize) -> Result<String, JsValue> {
        generate_strong_password(length).map_err(js_err)
    }
}

impl Default for WasmVault {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(serde::Serialize)]
struct ListEntry {
    item: ListItemSummary,
    revision: u64,
}

#[derive(serde::Serialize)]
struct ListItemSummary {
    id: uuid::Uuid,
    kind: vault_models::ItemKind,
    title: String,
}

#[derive(serde::Serialize)]
struct CredentialListEntry {
    id: uuid::Uuid,
    title: String,
    username: String,
    website: String,
    revision: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct DeadlineListEntry {
    item_id: uuid::Uuid,
    kind: vault_models::ItemKind,
    title: String,
    label: &'static str,
    date: String,
    days_until: i64,
    revision: u64,
}

#[derive(serde::Serialize)]
struct EmergencyCardEntry {
    card: vault_models::EmergencyCard,
    revision: u64,
}

#[derive(serde::Serialize)]
struct ReadableVaultExport {
    format: &'static str,
    format_version: u16,
    items: Vec<ReadableItemEntry>,
    emergency_card: Option<EmergencyCardEntry>,
}

#[derive(serde::Serialize)]
struct ReadableItemEntry {
    item: vault_models::VaultItem,
    revision: u64,
}

#[derive(serde::Serialize)]
struct AttachmentImportCommitPayload {
    summary: crate::BrowserAttachmentSummary,
    item_revision: u64,
    encrypted_record_json: String,
}

#[derive(serde::Serialize)]
struct AttachmentDeleteCommitPayload {
    item_revision: u64,
    attachment_revision: u64,
    encrypted_record_json: String,
}

#[derive(serde::Serialize)]
struct ItemPurgeAttachmentPayload {
    id: uuid::Uuid,
    expected_revision: u64,
    attachment_revision: u64,
    chunk_count: u64,
    encrypted_record_json: String,
}

#[derive(serde::Serialize)]
struct ItemPurgeCommitPayload {
    item_revision: u64,
    attachments: Vec<ItemPurgeAttachmentPayload>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionResumePayload {
    format_version: u16,
    secret: String,
    wrapped: SessionResumeWrapV1,
}

fn deadline_entries_json(entries: Vec<DeadlineEntry>) -> Result<String, serde_json::Error> {
    let projected: Vec<DeadlineListEntry> = entries
        .into_iter()
        .map(|entry| DeadlineListEntry {
            item_id: entry.deadline.item_id,
            kind: entry.deadline.kind,
            title: entry.deadline.title,
            label: entry.deadline.label,
            date: entry.deadline.date,
            days_until: entry.deadline.days_until,
            revision: entry.revision,
        })
        .collect();
    serde_json::to_string(&projected)
}

fn readable_export_json(vault: &BrowserVault) -> Result<String, WasmVaultError> {
    let items = vault
        .list_items()?
        .into_iter()
        .map(|(item, revision)| ReadableItemEntry { item, revision })
        .collect();
    let emergency_card = vault
        .get_emergency_card()?
        .map(|(card, revision)| EmergencyCardEntry { card, revision });
    let payload = ReadableVaultExport {
        format: "safeory-readable-export",
        format_version: READABLE_EXPORT_FORMAT_VERSION,
        items,
        emergency_card,
    };
    serde_json::to_string(&payload)
        .map_err(vault_storage::StorageError::from)
        .map_err(WasmVaultError::from)
}

fn parse_uuid(s: &str) -> Result<uuid::Uuid, JsValue> {
    uuid::Uuid::parse_str(s).map_err(|_| JsValue::from_str("invalid item id"))
}

fn parse_secret(hex: &str) -> Result<RecoverySecret, JsValue> {
    RecoverySecret::from_hex(hex).map_err(|_| JsValue::from_str("invalid recovery secret"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_models::{EmergencyCard, VaultItem};

    #[test]
    fn deadline_projection_excludes_secret_fields_and_notes() {
        const SECRET: &str = "SECRET-SENTINEL-MUST-NOT-CROSS";
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let mut item = VaultItem::document("Passport", SECRET, "Issuer", "2026-09-20", SECRET);
        item.fields
            .insert("private_extra".to_owned(), SECRET.to_owned());
        vault.put_item(&item).expect("put");

        let json = deadline_entries_json(
            vault
                .list_deadlines((2026, 9, 19))
                .expect("deadline projection"),
        )
        .expect("serialize deadline projection");
        assert!(!json.contains(SECRET));

        let rows: Vec<serde_json::Value> = serde_json::from_str(&json).expect("parse projection");
        let object = rows[0].as_object().expect("deadline object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "date",
                "daysUntil",
                "itemId",
                "kind",
                "label",
                "revision",
                "title",
            ]
        );
    }

    #[test]
    fn readable_export_is_explicit_full_plaintext_and_requires_unlock() {
        const SECRET: &str = "READABLE-EXPORT-SECRET";
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let item = VaultItem::secure_note("Export me", SECRET);
        let item_id = item.id;
        vault.put_item(&item).expect("put");
        let mut card = EmergencyCard::empty();
        card.selected_item_ids.push(item_id);
        card.instructions = "Call the executor".to_owned();
        vault.set_emergency_card(&card).expect("set emergency card");
        let recovery_secret_hex =
            BrowserVault::generate_recovery_secret().expect("recovery secret");
        let recovery_secret = RecoverySecret::from_hex(&recovery_secret_hex).expect("parse secret");
        vault
            .install_recovery_kit(&recovery_secret)
            .expect("install recovery kit");

        let json = readable_export_json(&vault).expect("readable export");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse export");
        assert_eq!(value["format"], "safeory-readable-export");
        assert_eq!(value["format_version"], READABLE_EXPORT_FORMAT_VERSION);
        assert_eq!(value["items"].as_array().expect("items").len(), 1);
        assert_eq!(value["items"][0]["item"]["id"], item_id.to_string());
        assert!(json.contains(SECRET));
        assert_eq!(
            value["emergency_card"]["card"]["instructions"],
            "Call the executor"
        );
        assert!(!json.contains(&recovery_secret_hex));

        vault.lock();
        assert!(matches!(
            readable_export_json(&vault),
            Err(WasmVaultError::Locked)
        ));
    }
}
