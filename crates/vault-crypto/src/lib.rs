#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;
use vault_models::{VaultItem, VaultItemState};
use zeroize::Zeroizing;

const FORMAT_VERSION: u16 = 1;
const LEGACY_ITEM_PAYLOAD_SCHEMA_VERSION: u16 = 1;
const ITEM_PAYLOAD_SCHEMA_VERSION: u16 = 2;
const ALGORITHM: &str = "xchacha20poly1305";
const ITEM_WRAP_INFO: &[u8] = b"lifevault:v1:item-wrap";
const ROOT_WRAP_AAD: &[u8] = b"lifevault:root-wrap:v1";
const RECOVERY_WRAP_INFO: &[u8] = b"safeory:v1:recovery-wrap";
const RECOVERY_WRAP_AAD: &[u8] = b"safeory:recovery-wrap:v1";

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
        let mut out = [0u8; 32];
        for (index, slot) in out.iter_mut().enumerate() {
            let hi = nibble(bytes[index * 2])?;
            let lo = nibble(bytes[index * 2 + 1])?;
            *slot = (hi << 4) | lo;
        }
        Ok(Self(Zeroizing::new(out)))
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
    let state = if encrypted.payload_schema_version == LEGACY_ITEM_PAYLOAD_SCHEMA_VERSION {
        VaultItemState::Active {
            item: serde_json::from_slice(&plaintext)?,
        }
    } else {
        serde_json::from_slice(&plaintext)?
    };
    if state_object_id(&state) != encrypted.object_id {
        return Err(CryptoError::InconsistentRecord);
    }
    Ok(state)
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
        let item = VaultItem::secure_note("legacy", "still readable");
        let plaintext = serde_json::to_vec(&item).expect("serialize legacy item");
        let encrypted = encrypt_payload(
            &root,
            item.id,
            &plaintext,
            7,
            LEGACY_ITEM_PAYLOAD_SCHEMA_VERSION,
        )
        .expect("encrypt legacy payload");

        let state = decrypt_item_state(&root, &encrypted).expect("decode legacy payload");
        assert!(matches!(
            state,
            VaultItemState::Active { item: restored }
                if restored.id == item.id && restored.title == "legacy"
        ));
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
