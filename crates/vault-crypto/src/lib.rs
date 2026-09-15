#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;
use vault_models::{AccountClosurePlan, ItemKind, LegacyDisposition, VaultItem, VaultItemState};
use zeroize::Zeroizing;

const FORMAT_VERSION: u16 = 1;
const LEGACY_ITEM_PAYLOAD_SCHEMA_VERSION: u16 = 1;
const LIFECYCLE_ITEM_PAYLOAD_SCHEMA_VERSION: u16 = 2;
const ATTACHMENT_ITEM_PAYLOAD_SCHEMA_VERSION: u16 = 3;
const LEGACY_DISPOSITION_ITEM_PAYLOAD_SCHEMA_VERSION: u16 = 4;
const ITEM_PAYLOAD_SCHEMA_VERSION: u16 = 5;
const ATTACHMENT_PAYLOAD_SCHEMA_VERSION: u16 = 1;
const ALGORITHM: &str = "xchacha20poly1305";
const ITEM_WRAP_INFO: &[u8] = b"lifevault:v1:item-wrap";
const ATTACHMENT_WRAP_INFO: &[u8] = b"safeory:v1:attachment-wrap";
const ROOT_WRAP_AAD: &[u8] = b"lifevault:root-wrap:v1";
const RECOVERY_WRAP_INFO: &[u8] = b"safeory:v1:recovery-wrap";
const RECOVERY_WRAP_AAD: &[u8] = b"safeory:recovery-wrap:v1";

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum PreSubscriptionItemKind {
    SecureNote,
    Password,
    Insurance,
    Financial,
    Property,
    Document,
    Receipt,
    Vehicle,
    Possession,
    EmergencyInstruction,
}

impl From<PreSubscriptionItemKind> for ItemKind {
    fn from(kind: PreSubscriptionItemKind) -> Self {
        match kind {
            PreSubscriptionItemKind::SecureNote => Self::SecureNote,
            PreSubscriptionItemKind::Password => Self::Password,
            PreSubscriptionItemKind::Insurance => Self::Insurance,
            PreSubscriptionItemKind::Financial => Self::Financial,
            PreSubscriptionItemKind::Property => Self::Property,
            PreSubscriptionItemKind::Document => Self::Document,
            PreSubscriptionItemKind::Receipt => Self::Receipt,
            PreSubscriptionItemKind::Vehicle => Self::Vehicle,
            PreSubscriptionItemKind::Possession => Self::Possession,
            PreSubscriptionItemKind::EmergencyInstruction => Self::EmergencyInstruction,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreDispositionVaultItem {
    id: Uuid,
    kind: PreSubscriptionItemKind,
    title: String,
    #[serde(default)]
    links: Vec<Uuid>,
    #[serde(default)]
    attachments: Vec<Uuid>,
    fields: BTreeMap<String, String>,
    #[serde(deserialize_with = "deserialize_present_optional_string")]
    notes: Option<String>,
}

fn deserialize_present_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

impl From<PreDispositionVaultItem> for VaultItem {
    fn from(item: PreDispositionVaultItem) -> Self {
        Self {
            id: item.id,
            kind: item.kind.into(),
            title: item.title,
            links: item.links,
            attachments: item.attachments,
            legacy_disposition: LegacyDisposition::Unspecified,
            account_closure_plan: AccountClosurePlan::default(),
            fields: item.fields,
            notes: item.notes,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreClosureVaultItem {
    id: Uuid,
    kind: PreSubscriptionItemKind,
    title: String,
    links: Vec<Uuid>,
    attachments: Vec<Uuid>,
    legacy_disposition: LegacyDisposition,
    fields: BTreeMap<String, String>,
    #[serde(deserialize_with = "deserialize_present_optional_string")]
    notes: Option<String>,
}

impl From<PreClosureVaultItem> for VaultItem {
    fn from(item: PreClosureVaultItem) -> Self {
        Self {
            id: item.id,
            kind: item.kind.into(),
            title: item.title,
            links: item.links,
            attachments: item.attachments,
            legacy_disposition: item.legacy_disposition,
            account_closure_plan: AccountClosurePlan::default(),
            fields: item.fields,
            notes: item.notes,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum PreClosureVaultItemState {
    Active {
        item: PreClosureVaultItem,
    },
    Trashed {
        item: PreClosureVaultItem,
        deleted_at_ms: u64,
    },
    Tombstone {
        id: Uuid,
        deleted_at_ms: u64,
    },
}

impl From<PreClosureVaultItemState> for VaultItemState {
    fn from(state: PreClosureVaultItemState) -> Self {
        match state {
            PreClosureVaultItemState::Active { item } => Self::Active { item: item.into() },
            PreClosureVaultItemState::Trashed {
                item,
                deleted_at_ms,
            } => Self::Trashed {
                item: item.into(),
                deleted_at_ms,
            },
            PreClosureVaultItemState::Tombstone { id, deleted_at_ms } => {
                Self::Tombstone { id, deleted_at_ms }
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum PreDispositionVaultItemState {
    Active {
        item: PreDispositionVaultItem,
    },
    Trashed {
        item: PreDispositionVaultItem,
        deleted_at_ms: u64,
    },
    Tombstone {
        id: Uuid,
        deleted_at_ms: u64,
    },
}

impl From<PreDispositionVaultItemState> for VaultItemState {
    fn from(state: PreDispositionVaultItemState) -> Self {
        match state {
            PreDispositionVaultItemState::Active { item } => Self::Active { item: item.into() },
            PreDispositionVaultItemState::Trashed {
                item,
                deleted_at_ms,
            } => Self::Trashed {
                item: item.into(),
                deleted_at_ms,
            },
            PreDispositionVaultItemState::Tombstone { id, deleted_at_ms } => {
                Self::Tombstone { id, deleted_at_ms }
            }
        }
    }
}

pub const ATTACHMENT_CHUNK_SIZE: u64 = 1024 * 1024;
pub const ATTACHMENT_MAX_CHUNKS: u64 = 64;
/// Global V1 object ceiling: enough for 1,024 items at the current 16 attachments per item.
pub const ATTACHMENT_MAX_OBJECTS: u64 = 16 * 1024;
pub const ATTACHMENT_MAX_FILENAME_CHARS: usize = 255;
pub const ATTACHMENT_MAX_PLAINTEXT_BYTES: u64 = 64 * 1024 * 1024;
pub const ATTACHMENT_MAX_MANIFEST_PLAINTEXT_BYTES: usize = 4 * 1024;
pub const ATTACHMENT_MAX_MANIFEST_CIPHERTEXT_BYTES: usize =
    ATTACHMENT_MAX_MANIFEST_PLAINTEXT_BYTES + 16;
pub const ATTACHMENT_MAX_CHUNK_CIPHERTEXT_BYTES: usize = 1024 * 1024 + 16;
pub const ATTACHMENT_MAX_ENCRYPTED_RECORD_BYTES: usize = 32 * 1024;

pub const ARGON2_MEMORY_KIB: u32 = 65_536;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_MIN_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_MAX_MEMORY_KIB: u32 = 512 * 1024;
const ARGON2_MIN_ITERATIONS: u32 = 2;
const ARGON2_MAX_ITERATIONS: u32 = 10;
const ARGON2_MIN_PARALLELISM: u32 = 1;
const ARGON2_MAX_PARALLELISM: u32 = 4;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("cryptographic random source failed")]
    Random,
    #[error("invalid KDF parameters")]
    InvalidKdfParameters,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("authenticated encryption failed")]
    Encryption,
    #[error("authentication failed or key is incorrect")]
    Authentication,
    #[error("unsupported encrypted format")]
    UnsupportedFormat,
    #[error("encrypted record is inconsistent")]
    InconsistentRecord,
    #[error("invalid recovery secret encoding")]
    InvalidEncoding,
    #[error("serialization failed")]
    Serialization(#[from] serde_json::Error),
}

pub struct AccountRootKey(Zeroizing<[u8; 32]>);

impl AccountRootKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| CryptoError::Random)?;
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// High-entropy recovery secret used to wrap the [`AccountRootKey`] for the
/// printable recovery kit.
///
/// The secret is already high-entropy (256 bits from a CSPRNG), so HKDF-SHA256
/// — not Argon2 — is the correct KDF when deriving the wrapping key.
///
/// - Print/QR-friendly encoding of the secret is UI-layer work (out of scope here).
/// - Recovery secret theft == vault theft; the holder can unwrap the root key.
/// - The server must never see the secret (or the unwrapped root key).
pub struct RecoverySecret(Zeroizing<[u8; 32]>);

impl RecoverySecret {
    /// Generates a fresh 256-bit recovery secret from the OS CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| CryptoError::Random)?;
        Ok(Self(bytes))
    }

    /// Rebuilds a recovery secret from raw 32 bytes, e.g. one reconstructed
    /// from threshold shares by `vault-emergency`. Bytes are zeroized on drop.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for byte in self.as_bytes().iter() {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0F) as usize] as char);
        }
        out
    }

    pub fn from_hex(s: &str) -> Result<Self, CryptoError> {
        fn nibble(value: u8) -> Result<u8, CryptoError> {
            match value {
                b'0'..=b'9' => Ok(value - b'0'),
                b'a'..=b'f' => Ok(value - b'a' + 10),
                b'A'..=b'F' => Ok(value - b'A' + 10),
                _ => Err(CryptoError::InvalidEncoding),
            }
        }

        let bytes = s.as_bytes();
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidEncoding);
        }
        let mut out = Zeroizing::new([0u8; 32]);
        for (index, slot) in out.iter_mut().enumerate() {
            let hi = nibble(bytes[index * 2])?;
            let lo = nibble(bytes[index * 2 + 1])?;
            *slot = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RootKeyWrapV1 {
    pub format_version: u16,
    pub algorithm: String,
    pub argon2_memory_kib: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Recovery-kit envelope holding the [`AccountRootKey`] wrapped under a
/// [`RecoverySecret`]-derived KEK (HKDF-SHA256 + XChaCha20Poly1305).
///
/// - Print/QR-friendly encoding of the secret is UI-layer work (out of scope here).
/// - Recovery secret theft == vault theft; this envelope plus the secret unwraps the root key.
/// - The server must never see the secret; it only ever stores this opaque envelope.
#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryKitWrapV1 {
    pub format_version: u16,
    pub algorithm: String,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedItemV1 {
    pub format_version: u16,
    pub payload_schema_version: u16,
    pub algorithm: String,
    pub object_id: Uuid,
    pub key_id: Uuid,
    pub revision: u64,
    pub key_nonce: [u8; 24],
    pub wrapped_item_key: Vec<u8>,
    pub payload_nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AttachmentManifestV1 {
    Active {
        attachment_id: Uuid,
        owner_item_id: Uuid,
        filename: String,
        plaintext_size: u64,
        chunk_size: u64,
        chunk_count: u64,
    },
    Tombstone {
        attachment_id: Uuid,
        owner_item_id: Uuid,
        deleted_at_ms: u64,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedAttachmentV1 {
    pub format_version: u16,
    pub payload_schema_version: u16,
    pub algorithm: String,
    pub attachment_id: Uuid,
    pub key_id: Uuid,
    pub revision: u64,
    pub key_nonce: [u8; 24],
    pub wrapped_file_key: Vec<u8>,
    pub nonce_prefix: [u8; 16],
    pub manifest_ciphertext: Vec<u8>,
}

pub struct AttachmentCipherContext {
    file_key: Zeroizing<[u8; 32]>,
    nonce_prefix: [u8; 16],
    attachment_id: Uuid,
    owner_item_id: Uuid,
    revision: u64,
    plaintext_size: u64,
    chunk_size: u64,
    chunk_count: u64,
}

impl AttachmentCipherContext {
    pub fn encrypt_chunk(&self, index: u64, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let expected = self.expected_chunk_len(index)?;
        if plaintext.len() != expected {
            return Err(CryptoError::InconsistentRecord);
        }
        let cipher = XChaCha20Poly1305::new((&*self.file_key).into());
        let nonce = attachment_nonce(&self.nonce_prefix, index);
        let aad = attachment_chunk_aad(
            self.attachment_id,
            self.revision,
            self.owner_item_id,
            index,
            self.chunk_count,
            self.plaintext_size,
        );
        cipher
            .encrypt(
                nonce_ref(&nonce)?,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Encryption)
    }

    pub fn decrypt_chunk(&self, index: u64, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let expected = self.expected_chunk_len(index)?;
        let expected_ciphertext = expected
            .checked_add(16)
            .ok_or(CryptoError::InconsistentRecord)?;
        if ciphertext.len() != expected_ciphertext
            || ciphertext.len() > ATTACHMENT_MAX_CHUNK_CIPHERTEXT_BYTES
        {
            return Err(CryptoError::InconsistentRecord);
        }
        let cipher = XChaCha20Poly1305::new((&*self.file_key).into());
        let nonce = attachment_nonce(&self.nonce_prefix, index);
        let aad = attachment_chunk_aad(
            self.attachment_id,
            self.revision,
            self.owner_item_id,
            index,
            self.chunk_count,
            self.plaintext_size,
        );
        let plaintext = cipher
            .decrypt(
                nonce_ref(&nonce)?,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Authentication)?;
        if plaintext.len() != expected {
            return Err(CryptoError::InconsistentRecord);
        }
        Ok(plaintext)
    }

    fn expected_chunk_len(&self, index: u64) -> Result<usize, CryptoError> {
        if index >= self.chunk_count || self.chunk_count == 0 {
            return Err(CryptoError::InconsistentRecord);
        }
        let start = index
            .checked_mul(self.chunk_size)
            .ok_or(CryptoError::InconsistentRecord)?;
        let remaining = self
            .plaintext_size
            .checked_sub(start)
            .ok_or(CryptoError::InconsistentRecord)?;
        let len = remaining.min(self.chunk_size);
        usize::try_from(len).map_err(|_| CryptoError::InconsistentRecord)
    }
}

pub fn wrap_root_key(
    passphrase: &str,
    root_key: &AccountRootKey,
) -> Result<RootKeyWrapV1, CryptoError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut salt).map_err(|_| CryptoError::Random)?;
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Random)?;

    let kek = derive_kek(
        passphrase,
        &salt,
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
    )?;
    let cipher = XChaCha20Poly1305::new((&*kek).into());
    let ciphertext = cipher
        .encrypt(
            nonce_ref(&nonce)?,
            Payload {
                msg: root_key.as_bytes(),
                aad: ROOT_WRAP_AAD,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;

    Ok(RootKeyWrapV1 {
        format_version: FORMAT_VERSION,
        algorithm: ALGORITHM.to_owned(),
        argon2_memory_kib: ARGON2_MEMORY_KIB,
        argon2_iterations: ARGON2_ITERATIONS,
        argon2_parallelism: ARGON2_PARALLELISM,
        salt,
        nonce,
        ciphertext,
    })
}

pub fn unwrap_root_key(
    passphrase: &str,
    wrapped: &RootKeyWrapV1,
) -> Result<AccountRootKey, CryptoError> {
    ensure_supported(wrapped.format_version, &wrapped.algorithm)?;
    let kek = derive_kek(
        passphrase,
        &wrapped.salt,
        wrapped.argon2_memory_kib,
        wrapped.argon2_iterations,
        wrapped.argon2_parallelism,
    )?;
    let cipher = XChaCha20Poly1305::new((&*kek).into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce_ref(&wrapped.nonce)?,
                Payload {
                    msg: &wrapped.ciphertext,
                    aad: ROOT_WRAP_AAD,
                },
            )
            .map_err(|_| CryptoError::Authentication)?,
    );
    if plaintext.len() != 32 {
        return Err(CryptoError::InconsistentRecord);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&plaintext);
    Ok(AccountRootKey(bytes))
}

/// Wraps the [`AccountRootKey`] under a [`RecoverySecret`]-derived KEK.
///
/// The secret is already high-entropy, so HKDF-SHA256 (not Argon2) derives a
/// 32-byte KEK with `salt` as HKDF salt, the secret bytes as IKM, and
/// [`RECOVERY_WRAP_INFO`] as `info`. The root key bytes are then sealed with
/// XChaCha20Poly1305 under [`RECOVERY_WRAP_AAD`], using a fresh 16-byte salt
/// and 24-byte nonce per wrap.
///
/// - Print/QR-friendly encoding of the secret is UI-layer work (out of scope here).
/// - Recovery secret theft == vault theft; whoever holds the secret unwraps this envelope.
/// - The server must never see the secret, only this opaque envelope.
pub fn wrap_root_key_with_recovery_secret(
    secret: &RecoverySecret,
    root_key: &AccountRootKey,
) -> Result<RecoveryKitWrapV1, CryptoError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut salt).map_err(|_| CryptoError::Random)?;
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Random)?;

    let kek = derive_recovery_kek(secret, &salt)?;
    let cipher = XChaCha20Poly1305::new((&*kek).into());
    let ciphertext = cipher
        .encrypt(
            nonce_ref(&nonce)?,
            Payload {
                msg: root_key.as_bytes(),
                aad: RECOVERY_WRAP_AAD,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;

    Ok(RecoveryKitWrapV1 {
        format_version: FORMAT_VERSION,
        algorithm: ALGORITHM.to_owned(),
        salt,
        nonce,
        ciphertext,
    })
}

/// Unwraps the [`AccountRootKey`] from a [`RecoveryKitWrapV1`] envelope using
/// the [`RecoverySecret`].
///
/// Re-derives the KEK with HKDF-SHA256 over the envelope salt and decrypts
/// with [`RECOVERY_WRAP_AAD`]. The envelope version/algorithm is checked first
/// via `ensure_supported`, and a decrypted payload that is not 32 bytes is
/// rejected as [`CryptoError::InconsistentRecord`].
///
/// - Print/QR-friendly encoding of the secret is UI-layer work (out of scope here).
/// - Recovery secret theft == vault theft; treat the secret like the root key itself.
/// - The server must never see the secret; decryption happens client-side only.
pub fn unwrap_root_key_with_recovery_secret(
    secret: &RecoverySecret,
    wrapped: &RecoveryKitWrapV1,
) -> Result<AccountRootKey, CryptoError> {
    ensure_supported(wrapped.format_version, &wrapped.algorithm)?;
    let kek = derive_recovery_kek(secret, &wrapped.salt)?;
    let cipher = XChaCha20Poly1305::new((&*kek).into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce_ref(&wrapped.nonce)?,
                Payload {
                    msg: &wrapped.ciphertext,
                    aad: RECOVERY_WRAP_AAD,
                },
            )
            .map_err(|_| CryptoError::Authentication)?,
    );
    if plaintext.len() != 32 {
        return Err(CryptoError::InconsistentRecord);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&plaintext);
    Ok(AccountRootKey(bytes))
}

/// Verifies that `secret` opens `wrapped` to the exact expected account root.
/// Authentication failure is a normal mismatch; malformed or unsupported
/// recovery envelopes remain errors so corrupt stored state fails closed.
pub fn recovery_secret_matches_root_key(
    secret: &RecoverySecret,
    wrapped: &RecoveryKitWrapV1,
    expected_root: &AccountRootKey,
) -> Result<bool, CryptoError> {
    match unwrap_root_key_with_recovery_secret(secret, wrapped) {
        Ok(candidate) => Ok(candidate.as_bytes() == expected_root.as_bytes()),
        Err(CryptoError::Authentication) => Ok(false),
        Err(error) => Err(error),
    }
}

pub fn encrypt_item(
    root_key: &AccountRootKey,
    item: &VaultItem,
    revision: u64,
) -> Result<EncryptedItemV1, CryptoError> {
    encrypt_item_state(
        root_key,
        &VaultItemState::Active { item: item.clone() },
        revision,
    )
}

pub fn encrypt_item_state(
    root_key: &AccountRootKey,
    state: &VaultItemState,
    revision: u64,
) -> Result<EncryptedItemV1, CryptoError> {
    let object_id = state_object_id(state);
    let plaintext = Zeroizing::new(serde_json::to_vec(state)?);
    encrypt_payload(
        root_key,
        object_id,
        &plaintext,
        revision,
        ITEM_PAYLOAD_SCHEMA_VERSION,
    )
}

fn encrypt_payload(
    root_key: &AccountRootKey,
    object_id: Uuid,
    plaintext: &[u8],
    revision: u64,
    payload_schema_version: u16,
) -> Result<EncryptedItemV1, CryptoError> {
    let key_id = Uuid::new_v4();
    let mut item_key = Zeroizing::new([0u8; 32]);
    let mut key_nonce = [0u8; 24];
    let mut payload_nonce = [0u8; 24];
    getrandom::fill(item_key.as_mut()).map_err(|_| CryptoError::Random)?;
    getrandom::fill(&mut key_nonce).map_err(|_| CryptoError::Random)?;
    getrandom::fill(&mut payload_nonce).map_err(|_| CryptoError::Random)?;

    let wrap_key = derive_item_wrap_key(root_key)?;
    let wrap_cipher = XChaCha20Poly1305::new((&*wrap_key).into());
    let key_aad = item_key_aad(object_id, key_id, revision);
    let wrapped_item_key = wrap_cipher
        .encrypt(
            nonce_ref(&key_nonce)?,
            Payload {
                msg: &*item_key,
                aad: &key_aad,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;

    let item_cipher = XChaCha20Poly1305::new((&*item_key).into());
    let payload_aad = item_payload_aad(object_id, revision, payload_schema_version);
    let ciphertext = item_cipher
        .encrypt(
            nonce_ref(&payload_nonce)?,
            Payload {
                msg: plaintext,
                aad: &payload_aad,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;

    Ok(EncryptedItemV1 {
        format_version: FORMAT_VERSION,
        payload_schema_version,
        algorithm: ALGORITHM.to_owned(),
        object_id,
        key_id,
        revision,
        key_nonce,
        wrapped_item_key,
        payload_nonce,
        ciphertext,
    })
}

pub fn decrypt_item(
    root_key: &AccountRootKey,
    encrypted: &EncryptedItemV1,
) -> Result<VaultItem, CryptoError> {
    match decrypt_item_state(root_key, encrypted)? {
        VaultItemState::Active { item } => Ok(item),
        VaultItemState::Trashed { .. } | VaultItemState::Tombstone { .. } => {
            Err(CryptoError::InconsistentRecord)
        }
    }
}

pub fn decrypt_item_state(
    root_key: &AccountRootKey,
    encrypted: &EncryptedItemV1,
) -> Result<VaultItemState, CryptoError> {
    ensure_supported(encrypted.format_version, &encrypted.algorithm)?;
    if encrypted.payload_schema_version != ITEM_PAYLOAD_SCHEMA_VERSION
        && encrypted.payload_schema_version != LEGACY_DISPOSITION_ITEM_PAYLOAD_SCHEMA_VERSION
        && encrypted.payload_schema_version != ATTACHMENT_ITEM_PAYLOAD_SCHEMA_VERSION
        && encrypted.payload_schema_version != LIFECYCLE_ITEM_PAYLOAD_SCHEMA_VERSION
        && encrypted.payload_schema_version != LEGACY_ITEM_PAYLOAD_SCHEMA_VERSION
    {
        return Err(CryptoError::UnsupportedFormat);
    }
    let wrap_key = derive_item_wrap_key(root_key)?;
    let wrap_cipher = XChaCha20Poly1305::new((&*wrap_key).into());
    let key_aad = item_key_aad(encrypted.object_id, encrypted.key_id, encrypted.revision);
    let unwrapped = Zeroizing::new(
        wrap_cipher
            .decrypt(
                nonce_ref(&encrypted.key_nonce)?,
                Payload {
                    msg: &encrypted.wrapped_item_key,
                    aad: &key_aad,
                },
            )
            .map_err(|_| CryptoError::Authentication)?,
    );
    if unwrapped.len() != 32 {
        return Err(CryptoError::InconsistentRecord);
    }
    let mut item_key = Zeroizing::new([0u8; 32]);
    item_key.copy_from_slice(&unwrapped);

    let item_cipher = XChaCha20Poly1305::new((&*item_key).into());
    let payload_aad = item_payload_aad(
        encrypted.object_id,
        encrypted.revision,
        encrypted.payload_schema_version,
    );
    let plaintext = Zeroizing::new(
        item_cipher
            .decrypt(
                nonce_ref(&encrypted.payload_nonce)?,
                Payload {
                    msg: &encrypted.ciphertext,
                    aad: &payload_aad,
                },
            )
            .map_err(|_| CryptoError::Authentication)?,
    );
    let state = match encrypted.payload_schema_version {
        LEGACY_ITEM_PAYLOAD_SCHEMA_VERSION => VaultItemState::Active {
            item: serde_json::from_slice::<PreDispositionVaultItem>(&plaintext)?.into(),
        },
        LIFECYCLE_ITEM_PAYLOAD_SCHEMA_VERSION | ATTACHMENT_ITEM_PAYLOAD_SCHEMA_VERSION => {
            serde_json::from_slice::<PreDispositionVaultItemState>(&plaintext)?.into()
        }
        LEGACY_DISPOSITION_ITEM_PAYLOAD_SCHEMA_VERSION => {
            serde_json::from_slice::<PreClosureVaultItemState>(&plaintext)?.into()
        }
        ITEM_PAYLOAD_SCHEMA_VERSION => serde_json::from_slice(&plaintext)?,
        _ => return Err(CryptoError::UnsupportedFormat),
    };
    if state_object_id(&state) != encrypted.object_id {
        return Err(CryptoError::InconsistentRecord);
    }
    Ok(state)
}

pub fn seal_attachment_manifest(
    root_key: &AccountRootKey,
    manifest: &AttachmentManifestV1,
    revision: u64,
) -> Result<(EncryptedAttachmentV1, Option<AttachmentCipherContext>), CryptoError> {
    validate_attachment_manifest(manifest)?;
    let attachment_id = attachment_manifest_id(manifest);
    let owner_item_id = attachment_manifest_owner(manifest);
    let key_id = Uuid::new_v4();
    let mut file_key = Zeroizing::new([0u8; 32]);
    let mut key_nonce = [0u8; 24];
    let mut nonce_prefix = [0u8; 16];
    getrandom::fill(file_key.as_mut()).map_err(|_| CryptoError::Random)?;
    getrandom::fill(&mut key_nonce).map_err(|_| CryptoError::Random)?;
    getrandom::fill(&mut nonce_prefix).map_err(|_| CryptoError::Random)?;

    let wrap_key = derive_attachment_wrap_key(root_key)?;
    let wrap_cipher = XChaCha20Poly1305::new((&*wrap_key).into());
    let key_aad = attachment_key_aad(attachment_id, key_id, revision);
    let wrapped_file_key = wrap_cipher
        .encrypt(
            nonce_ref(&key_nonce)?,
            Payload {
                msg: &*file_key,
                aad: &key_aad,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;

    let manifest_plaintext = Zeroizing::new(serde_json::to_vec(manifest)?);
    if manifest_plaintext.len() > ATTACHMENT_MAX_MANIFEST_PLAINTEXT_BYTES {
        return Err(CryptoError::InconsistentRecord);
    }
    let manifest_cipher = XChaCha20Poly1305::new((&*file_key).into());
    let manifest_nonce = attachment_nonce(&nonce_prefix, u64::MAX);
    let manifest_aad =
        attachment_manifest_aad(attachment_id, revision, ATTACHMENT_PAYLOAD_SCHEMA_VERSION);
    let manifest_ciphertext = manifest_cipher
        .encrypt(
            nonce_ref(&manifest_nonce)?,
            Payload {
                msg: &manifest_plaintext,
                aad: &manifest_aad,
            },
        )
        .map_err(|_| CryptoError::Encryption)?;

    let context = match manifest {
        AttachmentManifestV1::Active {
            plaintext_size,
            chunk_size,
            chunk_count,
            ..
        } => Some(AttachmentCipherContext {
            file_key,
            nonce_prefix,
            attachment_id,
            owner_item_id,
            revision,
            plaintext_size: *plaintext_size,
            chunk_size: *chunk_size,
            chunk_count: *chunk_count,
        }),
        AttachmentManifestV1::Tombstone { .. } => None,
    };

    Ok((
        EncryptedAttachmentV1 {
            format_version: FORMAT_VERSION,
            payload_schema_version: ATTACHMENT_PAYLOAD_SCHEMA_VERSION,
            algorithm: ALGORITHM.to_owned(),
            attachment_id,
            key_id,
            revision,
            key_nonce,
            wrapped_file_key,
            nonce_prefix,
            manifest_ciphertext,
        },
        context,
    ))
}

pub fn open_attachment_manifest(
    root_key: &AccountRootKey,
    encrypted: &EncryptedAttachmentV1,
) -> Result<(AttachmentManifestV1, Option<AttachmentCipherContext>), CryptoError> {
    ensure_supported(encrypted.format_version, &encrypted.algorithm)?;
    if encrypted.payload_schema_version != ATTACHMENT_PAYLOAD_SCHEMA_VERSION {
        return Err(CryptoError::UnsupportedFormat);
    }
    if encrypted.wrapped_file_key.len() != 48
        || encrypted.manifest_ciphertext.len() < 16
        || encrypted.manifest_ciphertext.len() > ATTACHMENT_MAX_MANIFEST_CIPHERTEXT_BYTES
    {
        return Err(CryptoError::InconsistentRecord);
    }

    let wrap_key = derive_attachment_wrap_key(root_key)?;
    let wrap_cipher = XChaCha20Poly1305::new((&*wrap_key).into());
    let key_aad = attachment_key_aad(
        encrypted.attachment_id,
        encrypted.key_id,
        encrypted.revision,
    );
    let unwrapped = Zeroizing::new(
        wrap_cipher
            .decrypt(
                nonce_ref(&encrypted.key_nonce)?,
                Payload {
                    msg: &encrypted.wrapped_file_key,
                    aad: &key_aad,
                },
            )
            .map_err(|_| CryptoError::Authentication)?,
    );
    if unwrapped.len() != 32 {
        return Err(CryptoError::InconsistentRecord);
    }
    let mut file_key = Zeroizing::new([0u8; 32]);
    file_key.copy_from_slice(&unwrapped);

    let manifest_cipher = XChaCha20Poly1305::new((&*file_key).into());
    let manifest_nonce = attachment_nonce(&encrypted.nonce_prefix, u64::MAX);
    let manifest_aad = attachment_manifest_aad(
        encrypted.attachment_id,
        encrypted.revision,
        encrypted.payload_schema_version,
    );
    let plaintext = Zeroizing::new(
        manifest_cipher
            .decrypt(
                nonce_ref(&manifest_nonce)?,
                Payload {
                    msg: &encrypted.manifest_ciphertext,
                    aad: &manifest_aad,
                },
            )
            .map_err(|_| CryptoError::Authentication)?,
    );
    if plaintext.len() > ATTACHMENT_MAX_MANIFEST_PLAINTEXT_BYTES {
        return Err(CryptoError::InconsistentRecord);
    }
    let manifest: AttachmentManifestV1 = serde_json::from_slice(&plaintext)?;
    validate_attachment_manifest(&manifest)?;
    if attachment_manifest_id(&manifest) != encrypted.attachment_id {
        return Err(CryptoError::InconsistentRecord);
    }

    let owner_item_id = attachment_manifest_owner(&manifest);
    let context = match &manifest {
        AttachmentManifestV1::Active {
            plaintext_size,
            chunk_size,
            chunk_count,
            ..
        } => Some(AttachmentCipherContext {
            file_key,
            nonce_prefix: encrypted.nonce_prefix,
            attachment_id: encrypted.attachment_id,
            owner_item_id,
            revision: encrypted.revision,
            plaintext_size: *plaintext_size,
            chunk_size: *chunk_size,
            chunk_count: *chunk_count,
        }),
        AttachmentManifestV1::Tombstone { .. } => None,
    };
    Ok((manifest, context))
}

fn state_object_id(state: &VaultItemState) -> Uuid {
    match state {
        VaultItemState::Active { item } | VaultItemState::Trashed { item, .. } => item.id,
        VaultItemState::Tombstone { id, .. } => *id,
    }
}

fn derive_kek(
    passphrase: &str,
    salt: &[u8; 16],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if !(ARGON2_MIN_MEMORY_KIB..=ARGON2_MAX_MEMORY_KIB).contains(&memory_kib)
        || !(ARGON2_MIN_ITERATIONS..=ARGON2_MAX_ITERATIONS).contains(&iterations)
        || !(ARGON2_MIN_PARALLELISM..=ARGON2_MAX_PARALLELISM).contains(&parallelism)
    {
        return Err(CryptoError::InvalidKdfParameters);
    }
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|_| CryptoError::InvalidKdfParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, output.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(output)
}

fn derive_item_wrap_key(root_key: &AccountRootKey) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, root_key.as_bytes());
    let mut output = Zeroizing::new([0u8; 32]);
    hk.expand(ITEM_WRAP_INFO, output.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(output)
}

fn derive_attachment_wrap_key(
    root_key: &AccountRootKey,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, root_key.as_bytes());
    let mut output = Zeroizing::new([0u8; 32]);
    hk.expand(ATTACHMENT_WRAP_INFO, output.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(output)
}

fn derive_recovery_kek(
    secret: &RecoverySecret,
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), secret.as_bytes().as_slice());
    let mut output = Zeroizing::new([0u8; 32]);
    hk.expand(RECOVERY_WRAP_INFO, output.as_mut())
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(output)
}

fn ensure_supported(version: u16, algorithm: &str) -> Result<(), CryptoError> {
    if version != FORMAT_VERSION || algorithm != ALGORITHM {
        return Err(CryptoError::UnsupportedFormat);
    }
    Ok(())
}

fn nonce_ref(nonce: &[u8; 24]) -> Result<&XNonce, CryptoError> {
    nonce
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InconsistentRecord)
}

fn item_key_aad(object_id: Uuid, key_id: Uuid, revision: u64) -> Vec<u8> {
    format!("lifevault:item-key:v1:{object_id}:{key_id}:{revision}").into_bytes()
}

fn item_payload_aad(object_id: Uuid, revision: u64, schema_version: u16) -> Vec<u8> {
    format!("lifevault:item-payload:v1:{schema_version}:{object_id}:{revision}").into_bytes()
}

fn attachment_key_aad(attachment_id: Uuid, key_id: Uuid, revision: u64) -> Vec<u8> {
    format!("safeory:attachment-key:v1:{attachment_id}:{key_id}:{revision}").into_bytes()
}

fn attachment_manifest_aad(attachment_id: Uuid, revision: u64, schema_version: u16) -> Vec<u8> {
    format!("safeory:attachment-manifest:v1:{schema_version}:{attachment_id}:{revision}")
        .into_bytes()
}

fn attachment_chunk_aad(
    attachment_id: Uuid,
    revision: u64,
    owner_item_id: Uuid,
    chunk_index: u64,
    chunk_count: u64,
    plaintext_size: u64,
) -> Vec<u8> {
    format!(
        "safeory:attachment-chunk:v1:{attachment_id}:{revision}:{owner_item_id}:{chunk_index}:{chunk_count}:{plaintext_size}"
    )
    .into_bytes()
}

fn attachment_nonce(prefix: &[u8; 16], slot: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(prefix);
    nonce[16..].copy_from_slice(&slot.to_be_bytes());
    nonce
}

fn attachment_manifest_id(manifest: &AttachmentManifestV1) -> Uuid {
    match manifest {
        AttachmentManifestV1::Active { attachment_id, .. }
        | AttachmentManifestV1::Tombstone { attachment_id, .. } => *attachment_id,
    }
}

fn attachment_manifest_owner(manifest: &AttachmentManifestV1) -> Uuid {
    match manifest {
        AttachmentManifestV1::Active { owner_item_id, .. }
        | AttachmentManifestV1::Tombstone { owner_item_id, .. } => *owner_item_id,
    }
}

fn validate_attachment_manifest(manifest: &AttachmentManifestV1) -> Result<(), CryptoError> {
    if let AttachmentManifestV1::Active {
        filename,
        plaintext_size,
        chunk_size,
        chunk_count,
        ..
    } = manifest
    {
        if filename.is_empty()
            || filename.chars().count() > ATTACHMENT_MAX_FILENAME_CHARS
            || *plaintext_size > ATTACHMENT_MAX_PLAINTEXT_BYTES
            || *chunk_size != ATTACHMENT_CHUNK_SIZE
            || *chunk_count > ATTACHMENT_MAX_CHUNKS
        {
            return Err(CryptoError::InconsistentRecord);
        }
        let expected_count = if *plaintext_size == 0 {
            0
        } else {
            plaintext_size
                .checked_add(chunk_size - 1)
                .ok_or(CryptoError::InconsistentRecord)?
                / chunk_size
        };
        if *chunk_count != expected_count {
            return Err(CryptoError::InconsistentRecord);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_passphrase_cannot_unwrap_root_key() {
        let root = AccountRootKey::generate().expect("root key");
        let wrapped = wrap_root_key("correct passphrase", &root).expect("wrap");
        assert!(unwrap_root_key("wrong", &wrapped).is_err());
    }

    #[test]
    fn recovery_secret_verification_requires_the_expected_root() {
        let root = AccountRootKey::generate().expect("root key");
        let other_root = AccountRootKey::generate().expect("other root key");
        let secret = RecoverySecret::generate().expect("recovery secret");
        let wrong_secret = RecoverySecret::generate().expect("wrong recovery secret");
        let wrapped = wrap_root_key_with_recovery_secret(&secret, &root).expect("wrap root");

        assert!(
            recovery_secret_matches_root_key(&secret, &wrapped, &root)
                .expect("matching recovery key")
        );
        assert!(
            !recovery_secret_matches_root_key(&wrong_secret, &wrapped, &root)
                .expect("wrong recovery key")
        );
        assert!(
            !recovery_secret_matches_root_key(&secret, &wrapped, &other_root)
                .expect("transplanted recovery wrap")
        );

        let mut malformed = wrapped;
        malformed.format_version += 1;
        assert!(matches!(
            recovery_secret_matches_root_key(&secret, &malformed, &root),
            Err(CryptoError::UnsupportedFormat)
        ));
    }

    #[test]
    fn item_ciphertext_rejects_tampering() {
        let root = AccountRootKey::generate().expect("root key");
        let item = VaultItem::secure_note("private", "secret");
        let mut encrypted = encrypt_item(&root, &item, 1).expect("encrypt");
        encrypted.ciphertext[0] ^= 0x01;
        assert!(decrypt_item(&root, &encrypted).is_err());
    }

    #[test]
    fn untrusted_kdf_parameters_are_bounded_before_work() {
        let root = AccountRootKey::generate().expect("root key");
        let mut wrapped = wrap_root_key("correct passphrase", &root).expect("wrap");
        wrapped.argon2_memory_kib = ARGON2_MAX_MEMORY_KIB + 1;

        assert!(matches!(
            unwrap_root_key("correct passphrase", &wrapped),
            Err(CryptoError::InvalidKdfParameters)
        ));
    }

    #[test]
    fn newer_item_payload_schema_is_rejected() {
        let root = AccountRootKey::generate().expect("root key");
        let item = VaultItem::secure_note("private", "secret");
        let mut encrypted = encrypt_item(&root, &item, 1).expect("encrypt");
        encrypted.payload_schema_version += 1;

        assert!(matches!(
            decrypt_item(&root, &encrypted),
            Err(CryptoError::UnsupportedFormat)
        ));
    }

    #[test]
    fn legacy_v1_item_payload_decodes_as_active() {
        let root = AccountRootKey::generate().expect("root key");
        let object_id = Uuid::new_v4();
        let plaintext = serde_json::to_vec(&serde_json::json!({
            "id": object_id,
            "kind": "secure_note",
            "title": "legacy",
            "fields": {"body": "still readable"},
            "notes": null
        }))
        .expect("serialize legacy item");
        let encrypted = encrypt_payload(
            &root,
            object_id,
            &plaintext,
            7,
            LEGACY_ITEM_PAYLOAD_SCHEMA_VERSION,
        )
        .expect("encrypt legacy payload");

        let state = decrypt_item_state(&root, &encrypted).expect("decode legacy payload");
        assert!(matches!(
            state,
            VaultItemState::Active { item: restored }
                if restored.id == object_id
                    && restored.title == "legacy"
                    && restored.links.is_empty()
                    && restored.attachments.is_empty()
                    && restored.legacy_disposition == LegacyDisposition::Unspecified
                    && restored.account_closure_plan == AccountClosurePlan::default()
        ));
    }

    #[test]
    fn lifecycle_v2_item_payload_decodes_with_empty_attachments() {
        let root = AccountRootKey::generate().expect("root key");
        let object_id = Uuid::new_v4();
        let plaintext = serde_json::to_vec(&serde_json::json!({
            "state": "active",
            "item": {
                "id": object_id,
                "kind": "secure_note",
                "title": "pre-attachment",
                "links": [],
                "fields": {"body": "still readable"},
                "notes": null
            }
        }))
        .expect("serialize lifecycle v2 payload");
        let encrypted = encrypt_payload(
            &root,
            object_id,
            &plaintext,
            4,
            LIFECYCLE_ITEM_PAYLOAD_SCHEMA_VERSION,
        )
        .expect("encrypt lifecycle v2 payload");

        let state = decrypt_item_state(&root, &encrypted).expect("decode lifecycle v2 payload");
        assert!(matches!(
            state,
            VaultItemState::Active { item }
                if item.id == object_id
                    && item.attachments.is_empty()
                    && item.account_closure_plan == AccountClosurePlan::default()
        ));
    }

    #[test]
    fn pre_legacy_disposition_v3_payload_decodes_as_unspecified() {
        let root = AccountRootKey::generate().expect("root key");
        let object_id = Uuid::new_v4();
        let plaintext = serde_json::to_vec(&serde_json::json!({
            "state": "active",
            "item": {
                "id": object_id,
                "kind": "secure_note",
                "title": "pre-legacy-disposition",
                "links": [],
                "attachments": [],
                "fields": {"body": "still readable"},
                "notes": null
            }
        }))
        .expect("serialize item payload v3");
        let encrypted = encrypt_payload(
            &root,
            object_id,
            &plaintext,
            5,
            ATTACHMENT_ITEM_PAYLOAD_SCHEMA_VERSION,
        )
        .expect("encrypt item payload v3");

        let state = decrypt_item_state(&root, &encrypted).expect("decode item payload v3");
        assert!(matches!(
            state,
            VaultItemState::Active { item }
                if item.id == object_id
                    && item.legacy_disposition == LegacyDisposition::Unspecified
                    && item.account_closure_plan == AccountClosurePlan::default()
        ));
    }

    #[test]
    fn pre_legacy_disposition_v3_trashed_payload_decodes_as_unspecified() {
        let root = AccountRootKey::generate().expect("root key");
        let object_id = Uuid::new_v4();
        let plaintext = serde_json::to_vec(&serde_json::json!({
            "state": "trashed",
            "item": {
                "id": object_id,
                "kind": "secure_note",
                "title": "pre-legacy-disposition trash",
                "links": [],
                "attachments": [],
                "fields": {"body": "still readable"},
                "notes": null
            },
            "deleted_at_ms": 42
        }))
        .expect("serialize trashed item payload v3");
        let encrypted = encrypt_payload(
            &root,
            object_id,
            &plaintext,
            5,
            ATTACHMENT_ITEM_PAYLOAD_SCHEMA_VERSION,
        )
        .expect("encrypt trashed item payload v3");

        let state = decrypt_item_state(&root, &encrypted).expect("decode trashed item payload v3");
        assert!(matches!(
            state,
            VaultItemState::Trashed {
                item,
                deleted_at_ms: 42
            } if item.id == object_id
                && item.legacy_disposition == LegacyDisposition::Unspecified
                && item.account_closure_plan == AccountClosurePlan::default()
        ));
    }

    #[test]
    fn legacy_disposition_v4_payload_decodes_with_default_closure_plan() {
        let root = AccountRootKey::generate().expect("root key");
        let object_id = Uuid::new_v4();
        let plaintext = serde_json::to_vec(&serde_json::json!({
            "state": "active",
            "item": {
                "id": object_id,
                "kind": "password",
                "title": "pre-account-closure",
                "links": [],
                "attachments": [],
                "legacy_disposition": "selected_for_legacy",
                "fields": {
                    "username": "user",
                    "password": "secret",
                    "website": "https://example.test"
                },
                "notes": null
            }
        }))
        .expect("serialize item payload v4");
        let encrypted = encrypt_payload(
            &root,
            object_id,
            &plaintext,
            6,
            LEGACY_DISPOSITION_ITEM_PAYLOAD_SCHEMA_VERSION,
        )
        .expect("encrypt item payload v4");

        let state = decrypt_item_state(&root, &encrypted).expect("decode item payload v4");
        assert!(matches!(
            state,
            VaultItemState::Active { item }
                if item.id == object_id
                    && item.legacy_disposition == LegacyDisposition::SelectedForLegacy
                    && item.account_closure_plan == AccountClosurePlan::default()
        ));
    }

    #[test]
    fn new_item_writes_use_account_closure_payload_v5() {
        let root = AccountRootKey::generate().expect("root key");
        let mut item =
            VaultItem::password("account plan", "user", "secret", "https://example.test", "");
        item.legacy_disposition = LegacyDisposition::PrivateForever;
        item.account_closure_plan = AccountClosurePlan {
            disposition: vault_models::AccountClosureDisposition::CloseAccount,
            instructions: "Export statements, then close manually.".to_owned(),
        };

        let encrypted = encrypt_item(&root, &item, 1).expect("encrypt item payload v5");
        assert_eq!(
            encrypted.payload_schema_version,
            ITEM_PAYLOAD_SCHEMA_VERSION
        );
        assert_eq!(ITEM_PAYLOAD_SCHEMA_VERSION, 5);
        let restored = decrypt_item(&root, &encrypted).expect("decrypt item payload v5");
        assert_eq!(
            restored.legacy_disposition,
            LegacyDisposition::PrivateForever
        );
        assert_eq!(restored.account_closure_plan, item.account_closure_plan);
    }

    #[test]
    fn subscription_uses_existing_strict_payload_v5_shape() {
        let root = AccountRootKey::generate().expect("root key");
        let item = VaultItem::subscription(
            "Streaming",
            "Example Media",
            "Family",
            "19.99",
            "USD",
            "monthly",
            "2026-10-15",
            "local tracking only",
        );

        let encrypted = encrypt_item(&root, &item, 1).expect("encrypt subscription payload");
        assert_eq!(
            encrypted.payload_schema_version,
            ITEM_PAYLOAD_SCHEMA_VERSION
        );
        assert_eq!(ITEM_PAYLOAD_SCHEMA_VERSION, 5);
        let restored = decrypt_item(&root, &encrypted).expect("decrypt subscription payload");
        assert_eq!(restored.kind, ItemKind::Subscription);
        assert_eq!(restored.fields, item.fields);
        assert_eq!(restored.notes, item.notes);
    }

    #[test]
    fn legacy_item_payload_schemas_reject_subscription_kind() {
        let root = AccountRootKey::generate().expect("root key");
        for schema_version in [
            LEGACY_ITEM_PAYLOAD_SCHEMA_VERSION,
            LIFECYCLE_ITEM_PAYLOAD_SCHEMA_VERSION,
            ATTACHMENT_ITEM_PAYLOAD_SCHEMA_VERSION,
            LEGACY_DISPOSITION_ITEM_PAYLOAD_SCHEMA_VERSION,
        ] {
            let object_id = Uuid::new_v4();
            let item = match schema_version {
                LEGACY_ITEM_PAYLOAD_SCHEMA_VERSION => serde_json::json!({
                    "id": object_id,
                    "kind": "subscription",
                    "title": "impossible legacy subscription",
                    "fields": {},
                    "notes": null
                }),
                LIFECYCLE_ITEM_PAYLOAD_SCHEMA_VERSION => serde_json::json!({
                    "state": "active",
                    "item": {
                        "id": object_id,
                        "kind": "subscription",
                        "title": "impossible legacy subscription",
                        "links": [],
                        "fields": {},
                        "notes": null
                    }
                }),
                ATTACHMENT_ITEM_PAYLOAD_SCHEMA_VERSION => serde_json::json!({
                    "state": "active",
                    "item": {
                        "id": object_id,
                        "kind": "subscription",
                        "title": "impossible legacy subscription",
                        "links": [],
                        "attachments": [],
                        "fields": {},
                        "notes": null
                    }
                }),
                LEGACY_DISPOSITION_ITEM_PAYLOAD_SCHEMA_VERSION => serde_json::json!({
                    "state": "active",
                    "item": {
                        "id": object_id,
                        "kind": "subscription",
                        "title": "impossible legacy subscription",
                        "links": [],
                        "attachments": [],
                        "legacy_disposition": "unspecified",
                        "fields": {},
                        "notes": null
                    }
                }),
                _ => unreachable!(),
            };
            let plaintext = serde_json::to_vec(&item).expect("serialize legacy payload");
            let encrypted = encrypt_payload(&root, object_id, &plaintext, 1, schema_version)
                .expect("encrypt legacy payload");

            assert!(
                decrypt_item_state(&root, &encrypted).is_err(),
                "legacy schema {schema_version} unexpectedly accepted subscription"
            );
        }
    }

    #[test]
    fn legacy_disposition_payload_v4_requires_a_valid_disposition() {
        let root = AccountRootKey::generate().expect("root key");
        let object_id = Uuid::new_v4();
        let missing = serde_json::to_vec(&serde_json::json!({
            "state": "active",
            "item": {
                "id": object_id,
                "kind": "secure_note",
                "title": "missing disposition",
                "links": [],
                "attachments": [],
                "fields": {"body": "body"},
                "notes": null
            }
        }))
        .expect("serialize missing disposition payload");
        let missing = encrypt_payload(
            &root,
            object_id,
            &missing,
            1,
            LEGACY_DISPOSITION_ITEM_PAYLOAD_SCHEMA_VERSION,
        )
        .expect("encrypt missing disposition payload");
        assert!(matches!(
            decrypt_item_state(&root, &missing),
            Err(CryptoError::Serialization(_))
        ));

        let unknown = serde_json::to_vec(&serde_json::json!({
            "state": "active",
            "item": {
                "id": object_id,
                "kind": "secure_note",
                "title": "unknown disposition",
                "links": [],
                "attachments": [],
                "legacy_disposition": "release_to_everyone",
                "fields": {"body": "body"},
                "notes": null
            }
        }))
        .expect("serialize unknown disposition payload");
        let unknown = encrypt_payload(
            &root,
            object_id,
            &unknown,
            1,
            LEGACY_DISPOSITION_ITEM_PAYLOAD_SCHEMA_VERSION,
        )
        .expect("encrypt unknown disposition payload");
        assert!(matches!(
            decrypt_item_state(&root, &unknown),
            Err(CryptoError::Serialization(_))
        ));

        let unexpected_field = serde_json::to_vec(&serde_json::json!({
            "state": "active",
            "item": {
                "id": object_id,
                "kind": "secure_note",
                "title": "unexpected field",
                "links": [],
                "attachments": [],
                "legacy_disposition": "unspecified",
                "fields": {"body": "body"},
                "notes": null,
                "future_policy": {"unexpected": true}
            }
        }))
        .expect("serialize unexpected-field payload");
        let unexpected_field = encrypt_payload(
            &root,
            object_id,
            &unexpected_field,
            1,
            LEGACY_DISPOSITION_ITEM_PAYLOAD_SCHEMA_VERSION,
        )
        .expect("encrypt unexpected-field payload");
        assert!(matches!(
            decrypt_item_state(&root, &unexpected_field),
            Err(CryptoError::Serialization(_))
        ));

        for (label, item) in [
            (
                "missing links",
                serde_json::json!({
                    "id": object_id,
                    "kind": "secure_note",
                    "title": "missing links",
                    "attachments": [],
                    "legacy_disposition": "unspecified",
                    "fields": {"body": "body"},
                    "notes": null
                }),
            ),
            (
                "missing attachments",
                serde_json::json!({
                    "id": object_id,
                    "kind": "secure_note",
                    "title": "missing attachments",
                    "links": [],
                    "legacy_disposition": "unspecified",
                    "fields": {"body": "body"},
                    "notes": null
                }),
            ),
            (
                "missing notes",
                serde_json::json!({
                    "id": object_id,
                    "kind": "secure_note",
                    "title": "missing notes",
                    "links": [],
                    "attachments": [],
                    "legacy_disposition": "unspecified",
                    "fields": {"body": "body"}
                }),
            ),
        ] {
            let plaintext = serde_json::to_vec(&serde_json::json!({
                "state": "active",
                "item": item
            }))
            .expect("serialize structurally incomplete payload");
            let encrypted = encrypt_payload(
                &root,
                object_id,
                &plaintext,
                1,
                LEGACY_DISPOSITION_ITEM_PAYLOAD_SCHEMA_VERSION,
            )
            .expect("encrypt structurally incomplete payload");
            assert!(
                matches!(
                    decrypt_item_state(&root, &encrypted),
                    Err(CryptoError::Serialization(_))
                ),
                "{label} must fail closed"
            );
        }
    }

    #[test]
    fn item_payload_v5_requires_a_valid_account_closure_plan() {
        let root = AccountRootKey::generate().expect("root key");
        let object_id = Uuid::new_v4();
        let base_item = serde_json::json!({
            "id": object_id,
            "kind": "password",
            "title": "closure plan",
            "links": [],
            "attachments": [],
            "legacy_disposition": "unspecified",
            "fields": {
                "username": "user",
                "password": "secret",
                "website": "https://example.test"
            },
            "notes": null
        });

        let missing = serde_json::to_vec(&serde_json::json!({
            "state": "active",
            "item": base_item.clone()
        }))
        .expect("serialize missing closure plan payload");
        let missing = encrypt_payload(&root, object_id, &missing, 1, ITEM_PAYLOAD_SCHEMA_VERSION)
            .expect("encrypt missing closure plan payload");
        assert!(matches!(
            decrypt_item_state(&root, &missing),
            Err(CryptoError::Serialization(_))
        ));

        for account_closure_plan in [
            serde_json::json!({
                "disposition": "delete_without_review",
                "instructions": "bad enum"
            }),
            serde_json::json!({
                "disposition": "close_account",
                "instructions": "unexpected field",
                "future_action": true
            }),
        ] {
            let mut item = base_item.clone();
            item.as_object_mut()
                .expect("base item is object")
                .insert("account_closure_plan".to_owned(), account_closure_plan);
            let plaintext = serde_json::to_vec(&serde_json::json!({
                "state": "active",
                "item": item
            }))
            .expect("serialize invalid closure plan payload");
            let encrypted =
                encrypt_payload(&root, object_id, &plaintext, 1, ITEM_PAYLOAD_SCHEMA_VERSION)
                    .expect("encrypt invalid closure plan payload");
            assert!(matches!(
                decrypt_item_state(&root, &encrypted),
                Err(CryptoError::Serialization(_))
            ));
        }
    }

    #[test]
    fn item_payload_schema_version_is_authenticated() {
        let root = AccountRootKey::generate().expect("root key");
        let item = VaultItem::secure_note("schema binding", "body");
        let mut encrypted = encrypt_item(&root, &item, 1).expect("encrypt current payload");
        encrypted.payload_schema_version = LEGACY_DISPOSITION_ITEM_PAYLOAD_SCHEMA_VERSION;

        assert!(matches!(
            decrypt_item_state(&root, &encrypted),
            Err(CryptoError::Authentication)
        ));
    }

    fn active_attachment_manifest(
        attachment_id: Uuid,
        owner_item_id: Uuid,
        plaintext_size: u64,
    ) -> AttachmentManifestV1 {
        let chunk_count = if plaintext_size == 0 {
            0
        } else {
            plaintext_size.div_ceil(ATTACHMENT_CHUNK_SIZE)
        };
        AttachmentManifestV1::Active {
            attachment_id,
            owner_item_id,
            filename: "evidence.pdf".to_owned(),
            plaintext_size,
            chunk_size: ATTACHMENT_CHUNK_SIZE,
            chunk_count,
        }
    }

    fn replace_manifest_ciphertext_unchecked(
        root: &AccountRootKey,
        encrypted: &mut EncryptedAttachmentV1,
        manifest: &AttachmentManifestV1,
    ) {
        let wrap_key = derive_attachment_wrap_key(root).expect("derive attachment wrap key");
        let wrap_cipher = XChaCha20Poly1305::new((&*wrap_key).into());
        let key_aad = attachment_key_aad(
            encrypted.attachment_id,
            encrypted.key_id,
            encrypted.revision,
        );
        let file_key = wrap_cipher
            .decrypt(
                nonce_ref(&encrypted.key_nonce).expect("key nonce"),
                Payload {
                    msg: &encrypted.wrapped_file_key,
                    aad: &key_aad,
                },
            )
            .expect("unwrap file key");
        let mut file_key_bytes = Zeroizing::new([0u8; 32]);
        file_key_bytes.copy_from_slice(&file_key);
        let cipher = XChaCha20Poly1305::new((&*file_key_bytes).into());
        let nonce = attachment_nonce(&encrypted.nonce_prefix, u64::MAX);
        let aad = attachment_manifest_aad(
            encrypted.attachment_id,
            encrypted.revision,
            encrypted.payload_schema_version,
        );
        let plaintext = serde_json::to_vec(manifest).expect("serialize unchecked manifest");
        encrypted.manifest_ciphertext = cipher
            .encrypt(
                nonce_ref(&nonce).expect("manifest nonce"),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .expect("encrypt unchecked manifest");
    }

    fn round_trip_attachment_bytes(bytes: &[u8]) {
        let root = AccountRootKey::generate().expect("root key");
        let attachment_id = Uuid::new_v4();
        let owner_item_id = Uuid::new_v4();
        let manifest = active_attachment_manifest(
            attachment_id,
            owner_item_id,
            u64::try_from(bytes.len()).expect("test size fits u64"),
        );
        let (encrypted, encryptor) =
            seal_attachment_manifest(&root, &manifest, 1).expect("seal manifest");
        let encryptor = encryptor.expect("active encryptor");
        let mut ciphertexts = Vec::new();
        for (index, chunk) in bytes.chunks(ATTACHMENT_CHUNK_SIZE as usize).enumerate() {
            ciphertexts.push(
                encryptor
                    .encrypt_chunk(index as u64, chunk)
                    .expect("encrypt chunk"),
            );
        }

        let (opened, decryptor) =
            open_attachment_manifest(&root, &encrypted).expect("open manifest");
        assert!(opened == manifest);
        let decryptor = decryptor.expect("active decryptor");
        let mut restored = Vec::new();
        for (index, ciphertext) in ciphertexts.iter().enumerate() {
            restored.extend(
                decryptor
                    .decrypt_chunk(index as u64, ciphertext)
                    .expect("decrypt chunk"),
            );
        }
        assert_eq!(restored, bytes);
    }

    #[test]
    fn attachment_round_trips_zero_one_boundary_and_multiple_chunks() {
        round_trip_attachment_bytes(&[]);
        round_trip_attachment_bytes(&[0x42]);
        round_trip_attachment_bytes(&vec![0xA5; ATTACHMENT_CHUNK_SIZE as usize]);
        round_trip_attachment_bytes(&vec![0x5A; ATTACHMENT_CHUNK_SIZE as usize + 17]);
    }

    #[test]
    fn attachment_chunk_tampering_and_reordering_fail_authentication() {
        let root = AccountRootKey::generate().expect("root key");
        let manifest =
            active_attachment_manifest(Uuid::new_v4(), Uuid::new_v4(), ATTACHMENT_CHUNK_SIZE + 8);
        let (encrypted, encryptor) =
            seal_attachment_manifest(&root, &manifest, 9).expect("seal manifest");
        let encryptor = encryptor.expect("active encryptor");
        let first_plain = vec![0x11; ATTACHMENT_CHUNK_SIZE as usize];
        let second_plain = vec![0x22; 8];
        let first = encryptor
            .encrypt_chunk(0, &first_plain)
            .expect("encrypt first");
        let mut second = encryptor
            .encrypt_chunk(1, &second_plain)
            .expect("encrypt second");
        second[0] ^= 1;

        let (_, decryptor) = open_attachment_manifest(&root, &encrypted).expect("open manifest");
        let decryptor = decryptor.expect("active decryptor");
        assert!(decryptor.decrypt_chunk(1, &second).is_err());
        assert!(decryptor.decrypt_chunk(1, &first).is_err());
        assert!(decryptor.decrypt_chunk(2, &first).is_err());
    }

    #[test]
    fn attachment_manifest_tampering_and_wrong_root_fail() {
        let root = AccountRootKey::generate().expect("root key");
        let wrong_root = AccountRootKey::generate().expect("wrong root key");
        let manifest = active_attachment_manifest(Uuid::new_v4(), Uuid::new_v4(), 12);
        let (mut encrypted, _) =
            seal_attachment_manifest(&root, &manifest, 2).expect("seal manifest");

        assert!(open_attachment_manifest(&wrong_root, &encrypted).is_err());
        encrypted.manifest_ciphertext[0] ^= 1;
        assert!(open_attachment_manifest(&root, &encrypted).is_err());
    }

    #[test]
    fn attachment_open_rejects_authenticated_manifest_resource_violations() {
        let root = AccountRootKey::generate().expect("root key");
        let attachment_id = Uuid::new_v4();
        let owner_item_id = Uuid::new_v4();
        let valid = active_attachment_manifest(attachment_id, owner_item_id, 1);
        let (base, _) = seal_attachment_manifest(&root, &valid, 1).expect("seal valid manifest");

        let oversized_filename = AttachmentManifestV1::Active {
            attachment_id,
            owner_item_id,
            filename: "x".repeat(ATTACHMENT_MAX_FILENAME_CHARS + 1),
            plaintext_size: 1,
            chunk_size: ATTACHMENT_CHUNK_SIZE,
            chunk_count: 1,
        };
        let mut encrypted = base.clone();
        replace_manifest_ciphertext_unchecked(&root, &mut encrypted, &oversized_filename);
        assert!(matches!(
            open_attachment_manifest(&root, &encrypted),
            Err(CryptoError::InconsistentRecord)
        ));

        let oversized_plaintext = AttachmentManifestV1::Active {
            attachment_id,
            owner_item_id,
            filename: "evidence.bin".to_owned(),
            plaintext_size: ATTACHMENT_MAX_PLAINTEXT_BYTES + 1,
            chunk_size: ATTACHMENT_CHUNK_SIZE,
            chunk_count: ATTACHMENT_MAX_CHUNKS + 1,
        };
        let mut encrypted = base.clone();
        replace_manifest_ciphertext_unchecked(&root, &mut encrypted, &oversized_plaintext);
        assert!(matches!(
            open_attachment_manifest(&root, &encrypted),
            Err(CryptoError::InconsistentRecord)
        ));

        let oversized_count = AttachmentManifestV1::Active {
            attachment_id,
            owner_item_id,
            filename: "evidence.bin".to_owned(),
            plaintext_size: ATTACHMENT_MAX_PLAINTEXT_BYTES,
            chunk_size: ATTACHMENT_CHUNK_SIZE,
            chunk_count: ATTACHMENT_MAX_CHUNKS + 1,
        };
        let mut encrypted = base;
        replace_manifest_ciphertext_unchecked(&root, &mut encrypted, &oversized_count);
        assert!(matches!(
            open_attachment_manifest(&root, &encrypted),
            Err(CryptoError::InconsistentRecord)
        ));
    }

    #[test]
    fn attachment_open_and_chunk_decrypt_reject_oversized_ciphertexts() {
        let root = AccountRootKey::generate().expect("root key");
        let manifest = active_attachment_manifest(Uuid::new_v4(), Uuid::new_v4(), 1);
        let (mut encrypted, _) =
            seal_attachment_manifest(&root, &manifest, 1).expect("seal manifest");
        encrypted.manifest_ciphertext = vec![0; ATTACHMENT_MAX_MANIFEST_CIPHERTEXT_BYTES + 1];
        assert!(matches!(
            open_attachment_manifest(&root, &encrypted),
            Err(CryptoError::InconsistentRecord)
        ));

        let (encrypted, _) =
            seal_attachment_manifest(&root, &manifest, 1).expect("seal manifest again");
        let (_, decryptor) =
            open_attachment_manifest(&root, &encrypted).expect("open valid manifest");
        let decryptor = decryptor.expect("active decryptor");
        let oversized_chunk = vec![0; ATTACHMENT_MAX_CHUNK_CIPHERTEXT_BYTES + 1];
        assert!(matches!(
            decryptor.decrypt_chunk(0, &oversized_chunk),
            Err(CryptoError::InconsistentRecord)
        ));
    }

    #[test]
    fn maximum_v1_manifest_fits_bounded_encrypted_record() {
        let root = AccountRootKey::generate().expect("root key");
        let manifest = AttachmentManifestV1::Active {
            attachment_id: Uuid::new_v4(),
            owner_item_id: Uuid::new_v4(),
            filename: "\u{1}".repeat(ATTACHMENT_MAX_FILENAME_CHARS),
            plaintext_size: ATTACHMENT_MAX_PLAINTEXT_BYTES,
            chunk_size: ATTACHMENT_CHUNK_SIZE,
            chunk_count: ATTACHMENT_MAX_CHUNKS,
        };
        let (encrypted, _) =
            seal_attachment_manifest(&root, &manifest, 1).expect("seal maximum manifest");
        assert!(encrypted.manifest_ciphertext.len() <= ATTACHMENT_MAX_MANIFEST_CIPHERTEXT_BYTES);
        let encoded = serde_json::to_vec(&encrypted).expect("serialize encrypted attachment");
        assert!(encoded.len() <= ATTACHMENT_MAX_ENCRYPTED_RECORD_BYTES);
    }

    #[test]
    fn attachment_chunk_aad_binds_owner_size_and_count() {
        let root = AccountRootKey::generate().expect("root key");
        let attachment_id = Uuid::new_v4();
        let owner_item_id = Uuid::new_v4();
        let manifest = active_attachment_manifest(attachment_id, owner_item_id, 4);
        let (encrypted, encryptor) =
            seal_attachment_manifest(&root, &manifest, 3).expect("seal manifest");
        let encryptor = encryptor.expect("active encryptor");
        let ciphertext = encryptor.encrypt_chunk(0, b"data").expect("encrypt chunk");
        let (_, decryptor) = open_attachment_manifest(&root, &encrypted).expect("open manifest");
        let decryptor = decryptor.expect("active decryptor");

        let wrong_owner = AttachmentCipherContext {
            file_key: Zeroizing::new(*decryptor.file_key),
            nonce_prefix: decryptor.nonce_prefix,
            attachment_id,
            owner_item_id: Uuid::new_v4(),
            revision: decryptor.revision,
            plaintext_size: decryptor.plaintext_size,
            chunk_size: decryptor.chunk_size,
            chunk_count: decryptor.chunk_count,
        };
        assert!(wrong_owner.decrypt_chunk(0, &ciphertext).is_err());

        let wrong_size = AttachmentCipherContext {
            file_key: Zeroizing::new(*decryptor.file_key),
            nonce_prefix: decryptor.nonce_prefix,
            attachment_id,
            owner_item_id,
            revision: decryptor.revision,
            plaintext_size: 3,
            chunk_size: decryptor.chunk_size,
            chunk_count: decryptor.chunk_count,
        };
        assert!(wrong_size.decrypt_chunk(0, &ciphertext).is_err());
    }

    #[test]
    fn attachment_tombstone_has_no_chunk_context() {
        let root = AccountRootKey::generate().expect("root key");
        let manifest = AttachmentManifestV1::Tombstone {
            attachment_id: Uuid::new_v4(),
            owner_item_id: Uuid::new_v4(),
            deleted_at_ms: 123,
        };
        let (encrypted, context) =
            seal_attachment_manifest(&root, &manifest, 2).expect("seal tombstone");
        assert!(context.is_none());
        let (restored, context) =
            open_attachment_manifest(&root, &encrypted).expect("open tombstone");
        assert!(restored == manifest);
        assert!(context.is_none());
    }

    #[test]
    fn tombstone_inner_id_must_match_envelope_object_id() {
        let root = AccountRootKey::generate().expect("root key");
        let envelope_id = Uuid::new_v4();
        let state = VaultItemState::Tombstone {
            id: Uuid::new_v4(),
            deleted_at_ms: 42,
        };
        let plaintext = serde_json::to_vec(&state).expect("serialize tombstone");
        let encrypted = encrypt_payload(
            &root,
            envelope_id,
            &plaintext,
            3,
            ITEM_PAYLOAD_SCHEMA_VERSION,
        )
        .expect("encrypt mismatched tombstone");

        assert!(matches!(
            decrypt_item_state(&root, &encrypted),
            Err(CryptoError::InconsistentRecord)
        ));
    }

    #[test]
    fn recovery_kit_round_trip() {
        let root = AccountRootKey::generate().expect("root key");
        let secret = RecoverySecret::generate().expect("recovery secret");
        let wrapped = wrap_root_key_with_recovery_secret(&secret, &root).expect("wrap");
        assert_eq!(wrapped.format_version, FORMAT_VERSION);
        assert_eq!(wrapped.algorithm, ALGORITHM);
        let restored = unwrap_root_key_with_recovery_secret(&secret, &wrapped).expect("unwrap");
        assert_eq!(restored.as_bytes(), root.as_bytes());
    }

    #[test]
    fn recovery_kit_wrong_secret_fails() {
        let root = AccountRootKey::generate().expect("root key");
        let secret = RecoverySecret::generate().expect("recovery secret");
        let wrong = RecoverySecret::generate().expect("wrong secret");
        let wrapped = wrap_root_key_with_recovery_secret(&secret, &root).expect("wrap");
        assert!(unwrap_root_key_with_recovery_secret(&wrong, &wrapped).is_err());
    }

    #[test]
    fn recovery_kit_tampered_ciphertext_fails() {
        let root = AccountRootKey::generate().expect("root key");
        let secret = RecoverySecret::generate().expect("recovery secret");
        let mut wrapped = wrap_root_key_with_recovery_secret(&secret, &root).expect("wrap");
        wrapped.ciphertext[0] ^= 0x01;
        assert!(unwrap_root_key_with_recovery_secret(&secret, &wrapped).is_err());
    }

    #[test]
    fn recovery_kit_tampered_salt_fails() {
        let root = AccountRootKey::generate().expect("root key");
        let secret = RecoverySecret::generate().expect("recovery secret");
        let mut wrapped = wrap_root_key_with_recovery_secret(&secret, &root).expect("wrap");
        wrapped.salt[0] ^= 0x01;
        assert!(unwrap_root_key_with_recovery_secret(&secret, &wrapped).is_err());
    }

    #[test]
    fn recovery_and_passphrase_wraps_are_domain_separated() {
        let root = AccountRootKey::generate().expect("root key");
        let secret = RecoverySecret::generate().expect("recovery secret");

        let passphrase_wrapped = wrap_root_key("correct passphrase", &root).expect("wrap");
        let transplanted_recovery = RecoveryKitWrapV1 {
            format_version: passphrase_wrapped.format_version,
            algorithm: passphrase_wrapped.algorithm.clone(),
            salt: passphrase_wrapped.salt,
            nonce: passphrase_wrapped.nonce,
            ciphertext: passphrase_wrapped.ciphertext.clone(),
        };
        assert!(unwrap_root_key_with_recovery_secret(&secret, &transplanted_recovery).is_err());

        let recovery_wrapped = wrap_root_key_with_recovery_secret(&secret, &root).expect("wrap");
        let transplanted_root = RootKeyWrapV1 {
            format_version: recovery_wrapped.format_version,
            algorithm: recovery_wrapped.algorithm.clone(),
            argon2_memory_kib: ARGON2_MEMORY_KIB,
            argon2_iterations: ARGON2_ITERATIONS,
            argon2_parallelism: ARGON2_PARALLELISM,
            salt: recovery_wrapped.salt,
            nonce: recovery_wrapped.nonce,
            ciphertext: recovery_wrapped.ciphertext.clone(),
        };
        assert!(unwrap_root_key("correct passphrase", &transplanted_root).is_err());
    }

    #[test]
    fn recovery_secret_hex_round_trip() {
        let secret = RecoverySecret::from_bytes([0xAB; 32]);
        let hex = secret.to_hex();
        assert_eq!(hex, "ab".repeat(32));
        let restored = RecoverySecret::from_hex(&hex).expect("decode hex");
        assert_eq!(restored.as_bytes(), secret.as_bytes());
    }

    #[test]
    fn recovery_secret_from_hex_accepts_uppercase() {
        let secret = RecoverySecret::generate().expect("recovery secret");
        let lower = secret.to_hex();
        let upper = lower.to_uppercase();
        let restored = RecoverySecret::from_hex(&upper).expect("decode uppercase");
        assert_eq!(restored.as_bytes(), secret.as_bytes());
    }

    #[test]
    fn recovery_secret_from_hex_rejects_invalid_inputs() {
        assert!(matches!(
            RecoverySecret::from_hex(""),
            Err(CryptoError::InvalidEncoding)
        ));
        let valid = RecoverySecret::from_bytes([0x01; 32]).to_hex();
        assert_eq!(valid.len(), 64);
        assert!(matches!(
            RecoverySecret::from_hex(&valid[..63]),
            Err(CryptoError::InvalidEncoding)
        ));
        let long = format!("{valid}00");
        assert_eq!(long.len(), 66);
        // 65 chars must also be rejected.
        assert!(matches!(
            RecoverySecret::from_hex(&long[..65]),
            Err(CryptoError::InvalidEncoding)
        ));
        assert!(matches!(
            RecoverySecret::from_hex(&long),
            Err(CryptoError::InvalidEncoding)
        ));
        let mut non_hex = valid.clone();
        non_hex.replace_range(0..2, "zz");
        assert!(matches!(
            RecoverySecret::from_hex(&non_hex),
            Err(CryptoError::InvalidEncoding)
        ));
    }
}
