import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const safeoryRoot = path.resolve(scriptDir, "..");
const provenance = JSON.parse(
  fs.readFileSync(
    path.join(safeoryRoot, "docs", "provenance", "foundation-seed.json"),
    "utf8",
  ),
);
const expectedCommit = provenance.sources?.sdk?.commit;

function fail(message) {
  console.error(`prepare-safeory-sdk-adapter-proof: ${message}`);
  process.exit(1);
}

function replaceExact(file, before, after) {
  const body = fs.readFileSync(file, "utf8").replaceAll("\r\n", "\n");
  const count = body.split(before).length - 1;
  if (count !== 1) {
    fail(
      `expected exactly one source fragment in ${path.relative(checkout, file)}, found ${count}`,
    );
  }
  fs.writeFileSync(file, body.replace(before, after));
}

function lines(...values) {
  return values.join("\n") + "\n";
}

const checkoutArg = process.argv[2];
if (!checkoutArg) {
  fail(
    "usage: node scripts/prepare-safeory-sdk-adapter-proof.mjs <prepared-sdk-checkout>",
  );
}

const checkout = path.resolve(checkoutArg);
const cipherClient = path.join(
  checkout,
  "crates",
  "bitwarden-vault",
  "src",
  "cipher",
  "cipher_client",
  "mod.rs",
);
const errorFile = path.join(
  checkout,
  "crates",
  "bitwarden-vault",
  "src",
  "error.rs",
);
const sealedBlob = path.join(
  checkout,
  "crates",
  "bitwarden-vault",
  "src",
  "cipher",
  "blob",
  "sealed.rs",
);
const createClient = path.join(
  checkout,
  "crates",
  "bitwarden-vault",
  "src",
  "cipher",
  "cipher_client",
  "create.rs",
);
const editClient = path.join(
  checkout,
  "crates",
  "bitwarden-vault",
  "src",
  "cipher",
  "cipher_client",
  "edit.rs",
);
const getClient = path.join(
  checkout,
  "crates",
  "bitwarden-vault",
  "src",
  "cipher",
  "cipher_client",
  "get.rs",
);
const cipherModel = path.join(
  checkout,
  "crates",
  "bitwarden-vault",
  "src",
  "cipher",
  "cipher.rs",
);
const blobEncryption = path.join(
  checkout,
  "crates",
  "bitwarden-vault",
  "src",
  "cipher",
  "blob",
  "encryption.rs",
);
const blobMod = path.join(
  checkout,
  "crates",
  "bitwarden-vault",
  "src",
  "cipher",
  "blob",
  "mod.rs",
);

if (
  !fs.existsSync(cipherClient) ||
  !fs.existsSync(errorFile) ||
  !fs.existsSync(sealedBlob) ||
  !fs.existsSync(createClient) ||
  !fs.existsSync(editClient) ||
  !fs.existsSync(getClient) ||
  !fs.existsSync(cipherModel) ||
  !fs.existsSync(blobEncryption) ||
  !fs.existsSync(blobMod)
) {
  fail(`prepared Bitwarden SDK checkout is missing: ${checkout}`);
}

const actualCommit = execFileSync(
  "git",
  ["-C", checkout, "rev-parse", "HEAD"],
  { encoding: "utf8" },
).trim();
if (actualCommit !== expectedCommit) {
  fail(`checkout is ${actualCommit}; expected pinned commit ${expectedCommit}`);
}
if (fs.existsSync(path.join(checkout, "bitwarden_license"))) {
  fail("SDK must be cleaned before Safeory adapter preparation");
}

replaceExact(
  errorFile,
  `    #[error("Client User Id has not been set")]
    MissingUserId,
`,
  `    #[error("Client User Id has not been set")]
    MissingUserId,
    #[error("Cipher blob encryption failed: {0}")]
    Blob(String),
`,
);
replaceExact(
  errorFile,
  `    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum VaultParseError {
`,
  `    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error("Cipher blob decryption failed: {0}")]
    Blob(String),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum VaultParseError {
`,
);

replaceExact(
  cipherClient,
  `use super::EncryptionContext;
use crate::{
`,
  `use super::EncryptionContext;
use crate::cipher::blob::{
    decrypt_blob_cipher, decrypt_blob_cipher_list, encrypt_blob_cipher, is_blob_encrypted,
};
use crate::{
`,
);

replaceExact(
  cipherClient,
  lines(
    "    Cipher, CipherError, CipherListView, CipherView, DecryptError, EncryptError,",
  ),
  lines(
    "    Cipher, CipherError, CipherListView, CipherType, CipherView, DecryptError, EncryptError,",
  ),
);

replaceExact(
  cipherClient,
  `        let cipher = key_store.encrypt(cipher_view)?;
        Ok(EncryptionContext {
`,
  `        let cipher = if matches!(cipher_view.r#type, CipherType::SecureNote)
            && self.should_use_blob_encryption(cipher_view.organization_id)
        {
            let mut ctx = key_store.context();
            encrypt_blob_cipher(&mut cipher_view, &mut ctx)
                .map_err(|error| EncryptError::Blob(error.to_string()))?
        } else {
            key_store.encrypt(cipher_view)?
        };
        Ok(EncryptionContext {
`,
);

replaceExact(
  cipherClient,
  `        let user_id = self
            .client
            .internal
            .get_user_id()
            .ok_or(EncryptError::MissingUserId)?;
        let key_store = self.client.internal.get_key_store();
        let enable_cipher_key = self
            .client
            .internal
            .get_flags()
            .await
            .enable_cipher_key_encryption;

        let mut ctx = key_store.context();

        let prepared_views: Vec<CipherView> = cipher_views
            .into_iter()
            .map(|mut cv| {
                if cv.key.is_none() && enable_cipher_key {
                    let key = cv.key_identifier();
                    cv.generate_cipher_key(&mut ctx, key)?;
                }
                Ok(cv)
            })
            .collect::<Result<Vec<_>, bitwarden_crypto::CryptoError>>()?;

        let ciphers: Vec<Cipher> = key_store.encrypt_list(&prepared_views)?;

        Ok(ciphers
            .into_iter()
            .map(|cipher| EncryptionContext {
                cipher,
                encrypted_for: user_id,
            })
            .collect())
`,
  `        let mut contexts = Vec::with_capacity(cipher_views.len());
        for cipher_view in cipher_views {
            contexts.push(self.encrypt(cipher_view).await?);
        }
        Ok(contexts)
`,
);

replaceExact(
  cipherClient,
  `    pub async fn decrypt(&self, cipher: Cipher) -> Result<CipherView, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        if self.is_strict_decrypt().await {
`,
  `    pub async fn decrypt(&self, cipher: Cipher) -> Result<CipherView, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        if is_blob_encrypted(&cipher) {
            let mut ctx = key_store.context();
            return decrypt_blob_cipher(&cipher, &mut ctx)
                .map_err(|error| DecryptError::Blob(error.to_string()));
        }
        if self.is_strict_decrypt().await {
`,
);

replaceExact(
  cipherClient,
  `    pub async fn decrypt_list(
        &self,
        ciphers: Vec<Cipher>,
    ) -> Result<Vec<CipherListView>, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        if self.is_strict_decrypt().await {
            let strict: Vec<StrictDecrypt<Cipher>> =
                ciphers.into_iter().map(StrictDecrypt).collect();
            Ok(key_store.decrypt_list(&strict)?)
        } else {
            Ok(key_store.decrypt_list(&ciphers)?)
        }
    }
`,
  `    pub async fn decrypt_list(
        &self,
        ciphers: Vec<Cipher>,
    ) -> Result<Vec<CipherListView>, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let use_strict_decryption = self.is_strict_decrypt().await;
        let mut views = Vec::with_capacity(ciphers.len());
        for cipher in ciphers {
            if is_blob_encrypted(&cipher) {
                let mut ctx = key_store.context();
                views.push(
                    decrypt_blob_cipher_list(&cipher, &mut ctx)
                        .map_err(|error| DecryptError::Blob(error.to_string()))?,
                );
            } else if use_strict_decryption {
                views.push(key_store.decrypt(&StrictDecrypt(cipher))?);
            } else {
                views.push(key_store.decrypt(&cipher)?);
            }
        }
        Ok(views)
    }
`,
);

replaceExact(
  cipherClient,
  `    pub async fn decrypt_list_with_failures(
        &self,
        ciphers: Vec<Cipher>,
    ) -> DecryptCipherListResult {
        let key_store = self.client.internal.get_key_store();
        if self.is_strict_decrypt().await {
            let strict: Vec<StrictDecrypt<Cipher>> =
                ciphers.into_iter().map(StrictDecrypt).collect();
            let (successes, failures) = key_store.decrypt_list_with_failures(&strict);
            DecryptCipherListResult {
                successes,
                failures: failures.into_iter().map(|f| f.0.clone()).collect(),
            }
        } else {
            let (successes, failures) = key_store.decrypt_list_with_failures(&ciphers);
            DecryptCipherListResult {
                successes,
                failures: failures.into_iter().cloned().collect(),
            }
        }
    }
`,
  `    pub async fn decrypt_list_with_failures(
        &self,
        ciphers: Vec<Cipher>,
    ) -> DecryptCipherListResult {
        let key_store = self.client.internal.get_key_store();
        let use_strict_decryption = self.is_strict_decrypt().await;
        let mut successes = Vec::with_capacity(ciphers.len());
        let mut failures = Vec::new();
        for cipher in ciphers {
            let result = if is_blob_encrypted(&cipher) {
                let mut ctx = key_store.context();
                decrypt_blob_cipher_list(&cipher, &mut ctx).map_err(|_| ())
            } else if use_strict_decryption {
                key_store
                    .decrypt(&StrictDecrypt(cipher.clone()))
                    .map_err(|_| ())
            } else {
                key_store.decrypt(&cipher).map_err(|_| ())
            };
            match result {
                Ok(view) => successes.push(view),
                Err(()) => failures.push(cipher),
            }
        }
        DecryptCipherListResult {
            successes,
            failures,
        }
    }
`,
);

replaceExact(
  cipherClient,
  `    pub async fn decrypt_list_full_with_failures(
        &self,
        ciphers: Vec<Cipher>,
    ) -> DecryptCipherResult {
        let key_store = self.client.internal.get_key_store();
        if self.is_strict_decrypt().await {
            let strict: Vec<StrictDecrypt<Cipher>> =
                ciphers.into_iter().map(StrictDecrypt).collect();
            let (successes, failures) = key_store.decrypt_list_with_failures(&strict);
            return DecryptCipherResult {
                successes,
                failures: failures.into_iter().map(|f| f.0.clone()).collect(),
            };
        }
        let (successes, failures) = key_store.decrypt_list_with_failures(&ciphers);

        DecryptCipherResult {
            successes,
            failures: failures.into_iter().cloned().collect(),
        }
    }
`,
  `    pub async fn decrypt_list_full_with_failures(
        &self,
        ciphers: Vec<Cipher>,
    ) -> DecryptCipherResult {
        let mut successes = Vec::with_capacity(ciphers.len());
        let mut failures = Vec::new();
        for cipher in ciphers {
            match self.decrypt(cipher.clone()).await {
                Ok(view) => successes.push(view),
                Err(_) => failures.push(cipher),
            }
        }
        DecryptCipherResult {
            successes,
            failures,
        }
    }
`,
);

replaceExact(
  sealedBlob,
  `    #[error("CBOR encoding error")]
    CborEncoding,
    #[error("CBOR decoding error")]
    CborDecoding,
`,
  `    #[error("JSON encoding error")]
    JsonEncoding,
    #[error("JSON decoding error")]
    JsonDecoding,
    #[error("CBOR encoding error")]
    CborEncoding,
    #[error("CBOR decoding error")]
    CborDecoding,
`,
);

replaceExact(
  sealedBlob,
  `    /// Serializes this container into an opaque base64-encoded CBOR string.
    pub(super) fn to_opaque_string(&self) -> Result<String, SealedCipherBlobError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)
            .map_err(|_| SealedCipherBlobError::CborEncoding)?;
        Ok(B64::from(buf).to_string())
    }

    /// Deserializes a \`SealedCipherBlob\` from an opaque base64-encoded CBOR string.
    pub(super) fn from_opaque_string(s: &str) -> Result<Self, SealedCipherBlobError> {
        let bytes = B64::try_from(s)
            .map_err(|_| SealedCipherBlobError::Base64Decoding)?
            .into_bytes();
        ciborium::de::from_reader(bytes.as_slice()).map_err(|_| SealedCipherBlobError::CborDecoding)
    }
`,
  `    /// Serializes this container using the JSON shape accepted by the server's opaque cipher Data field.
    pub(super) fn to_opaque_string(&self) -> Result<String, SealedCipherBlobError> {
        serde_json::to_string(self).map_err(|_| SealedCipherBlobError::JsonEncoding)
    }

    /// Deserializes the server-compatible JSON container while retaining read compatibility with
    /// the SDK's earlier base64-encoded CBOR representation.
    pub(super) fn from_opaque_string(s: &str) -> Result<Self, SealedCipherBlobError> {
        if s.trim_start().starts_with('{') {
            return serde_json::from_str(s).map_err(|_| SealedCipherBlobError::JsonDecoding);
        }

        let bytes = B64::try_from(s)
            .map_err(|_| SealedCipherBlobError::Base64Decoding)?
            .into_bytes();
        ciborium::de::from_reader(bytes.as_slice()).map_err(|_| SealedCipherBlobError::CborDecoding)
    }
`,
);

replaceExact(
  blobEncryption,
  lines(
    "use crate::cipher::{",
    "    attachment,",
    "    cipher::{Cipher, CipherView},",
    "};",
  ),
  lines(
    '#[cfg(feature = "wasm")]',
    "use crate::cipher::field;",
    "use crate::cipher::{",
    "    attachment,",
    "    cipher::{",
    "        Cipher, CipherListView, CipherListViewType, CipherType, CipherView, CopyableCipherFields,",
    "    },",
    "};",
  ),
);
replaceExact(
  blobEncryption,
  lines(
    '    #[error("Cipher does not contain blob data")]',
    "    NoBlobData,",
    "}",
    "",
    "/// Returns `true` if the cipher's `data` field contains a valid sealed blob.",
    "pub(crate) fn is_blob_encrypted(cipher: &Cipher) -> bool {",
    "    cipher",
    "        .data",
    "        .as_ref()",
    "        .is_some_and(|s| SealedCipherBlob::from_opaque_string(s).is_ok())",
    "}",
  ),
  lines(
    '    #[error("Cipher does not contain blob data")]',
    "    NoBlobData,",
    '    #[error("Blob list projection only supports SecureNote carriers")]',
    "    UnsupportedListType,",
    "}",
    "",
    "/// Returns `true` if raw cipher data contains a valid sealed blob.",
    "pub(crate) fn is_blob_data(data: &str) -> bool {",
    "    SealedCipherBlob::from_opaque_string(data).is_ok()",
    "}",
    "",
    "/// Returns `true` if the cipher's `data` field contains a valid sealed blob.",
    "pub(crate) fn is_blob_encrypted(cipher: &Cipher) -> bool {",
    "    cipher.data.as_deref().is_some_and(is_blob_data)",
    "}",
  ),
);
replaceExact(
  blobEncryption,
  lines(
    "    blob.apply_to_cipher_view(&mut view, ctx, cipher_key)?;",
    "",
    "    Ok(view)",
    "}",
  ),
  lines(
    "    blob.apply_to_cipher_view(&mut view, ctx, cipher_key)?;",
    "",
    "    Ok(view)",
    "}",
    "",
    "/// Decrypts the selected Safeory blob carrier directly into a list/search projection.",
    "pub(crate) fn decrypt_blob_cipher_list(",
    "    cipher: &Cipher,",
    "    ctx: &mut KeyStoreContext<KeySlotIds>,",
    ") -> Result<CipherListView, BlobEncryptionError> {",
    "    let view = decrypt_blob_cipher(cipher, ctx)?;",
    "    if view.r#type != CipherType::SecureNote {",
    "        return Err(BlobEncryptionError::UnsupportedListType);",
    "    }",
    "",
    "    let attachment_count = view",
    "        .attachments",
    "        .as_ref()",
    "        .map(|attachments| attachments.len() as u32)",
    "        .unwrap_or(0);",
    "    let has_old_attachments = view.attachments.as_ref().is_some_and(|attachments| {",
    "        attachments",
    "            .iter()",
    "            .any(|attachment| attachment.key.is_none())",
    "    });",
    "    let copyable_fields = if view.notes.is_some() {",
    "        vec![CopyableCipherFields::SecureNotes]",
    "    } else {",
    "        Vec::new()",
    "    };",
    '    #[cfg(feature = "wasm")]',
    "    let attachment_names = view.attachments.as_ref().map(|attachments| {",
    "        attachments",
    "            .iter()",
    "            .filter_map(|attachment| attachment.file_name.clone())",
    "            .collect()",
    "    });",
    "",
    "    Ok(CipherListView {",
    "        id: view.id,",
    "        organization_id: view.organization_id,",
    "        folder_id: view.folder_id,",
    "        collection_ids: view.collection_ids,",
    "        key: view.key,",
    "        name: view.name,",
    "        subtitle: String::new(),",
    "        r#type: CipherListViewType::SecureNote,",
    "        favorite: view.favorite,",
    "        reprompt: view.reprompt,",
    "        organization_use_totp: view.organization_use_totp,",
    "        edit: view.edit,",
    "        permissions: view.permissions,",
    "        view_password: view.view_password,",
    "        attachments: attachment_count,",
    "        has_old_attachments,",
    "        creation_date: view.creation_date,",
    "        deleted_date: view.deleted_date,",
    "        revision_date: view.revision_date,",
    "        archived_date: view.archived_date,",
    "        copyable_fields,",
    "        local_data: view.local_data,",
    '        #[cfg(feature = "wasm")]',
    "        notes: view.notes,",
    '        #[cfg(feature = "wasm")]',
    "        fields: view",
    "            .fields",
    "            .map(|fields| fields.into_iter().map(field::FieldListView::from).collect()),",
    '        #[cfg(feature = "wasm")]',
    "        attachment_names,",
    "    })",
    "}",
  ),
);
replaceExact(
  blobMod,
  lines(
    "pub(crate) use encryption::{",
    "    BlobEncryptionError, decrypt_blob_cipher, encrypt_blob_cipher, is_blob_encrypted,",
    "    is_legacy_cipher,",
    "};",
  ),
  lines(
    "pub(crate) use encryption::{",
    "    BlobEncryptionError, decrypt_blob_cipher, decrypt_blob_cipher_list, encrypt_blob_cipher,",
    "    is_blob_data, is_blob_encrypted, is_legacy_cipher,",
    "};",
  ),
);

replaceExact(
  cipherModel,
  lines(
    "    fn try_from(cipher: CipherDetailsResponseModel) -> Result<Self, Self::Error> {",
    "        Ok(Self {",
  ),
  lines(
    "    fn try_from(cipher: CipherDetailsResponseModel) -> Result<Self, Self::Error> {",
    "        let is_blob = cipher",
    "            .data",
    "            .as_deref()",
    "            .is_some_and(crate::cipher::blob::is_blob_data);",
    "        let name = match EncString::try_from_optional(cipher.name)? {",
    "            Some(name) => name,",
    "            None if is_blob => EncString::Cose_Encrypt0_B64 { data: Vec::new() },",
    '            None => return Err(MissingFieldError("name").into()),',
    "        };",
    "",
    "        Ok(Self {",
  ),
);
replaceExact(
  cipherModel,
  lines(
    "            name: require!(EncString::try_from_optional(cipher.name)?),",
  ),
  lines("            name,"),
);

replaceExact(
  cipherModel,
  lines(
    "impl PartialCipher for CipherResponseModel {",
    "    fn merge_with_cipher(self, cipher: Option<Cipher>) -> Result<Cipher, VaultParseError> {",
    "        Ok(Cipher {",
  ),
  lines(
    "impl PartialCipher for CipherResponseModel {",
    "    fn merge_with_cipher(self, cipher: Option<Cipher>) -> Result<Cipher, VaultParseError> {",
    "        let is_blob = self",
    "            .data",
    "            .as_deref()",
    "            .is_some_and(crate::cipher::blob::is_blob_data);",
    "        let fallback_name = cipher.as_ref().map(|existing| existing.name.clone());",
    "        let name = match self.name {",
    "            Some(name) => name.parse()?,",
    "            None if is_blob => {",
    "                fallback_name.unwrap_or_else(|| EncString::Cose_Encrypt0_B64 { data: Vec::new() })",
    "            }",
    '            None => return Err(MissingFieldError("name").into()),',
    "        };",
    "        let local_data = cipher",
    "            .as_ref()",
    "            .and_then(|existing| existing.local_data.clone());",
    "",
    "        Ok(Cipher {",
  ),
);
replaceExact(
  cipherModel,
  lines(
    "            collection_ids: cipher",
    "                .as_ref()",
    "                .map(|c| c.collection_ids.clone())",
    "                .unwrap_or_default(),",
    "            local_data: cipher.and_then(|c| c.local_data),",
  ),
  lines(
    "            collection_ids: cipher",
    "                .as_ref()",
    "                .map(|c| c.collection_ids.clone())",
    "                .unwrap_or_default(),",
    "            local_data,",
  ),
);
replaceExact(
  cipherModel,
  lines("            name: require!(self.name).parse()?,"),
  lines("            name,"),
);

replaceExact(
  createClient,
  lines("    key_management::KeySlotIds, require,"),
  lines(
    "    key_management::{BLOB_SECURITY_VERSION, KeySlotIds},",
    "    require,",
  ),
);
replaceExact(
  createClient,
  lines("use super::CiphersClient;", "use crate::{"),
  lines(
    "use super::CiphersClient;",
    "use crate::cipher::blob::{decrypt_blob_cipher, encrypt_blob_cipher, is_blob_encrypted};",
    "use crate::{",
  ),
);
replaceExact(
  createClient,
  lines(
    "    Cipher, CipherRepromptType, CipherView, FieldView, FolderId, VaultParseError,",
  ),
  lines(
    "    Cipher, CipherRepromptType, CipherType, CipherView, FieldView, FolderId, VaultParseError,",
  ),
);
replaceExact(
  createClient,
  lines(
    "    #[error(transparent)]",
    "    Repository(#[from] RepositoryError),",
    "}",
  ),
  lines(
    "    #[error(transparent)]",
    "    Repository(#[from] RepositoryError),",
    '    #[error("Cipher blob operation failed: {0}")]',
    "    Blob(String),",
    "}",
  ),
);
replaceExact(
  createClient,
  lines(
    "    let cipher: Cipher = key_store.encrypt(view)?;",
    "    let mut cipher_request: CipherRequestModel = cipher.try_into()?;",
  ),
  lines(
    "    let use_blob = matches!(view.r#type, CipherType::SecureNote)",
    "        && view.organization_id.is_none()",
    "        && key_store.context().get_security_state_version() >= BLOB_SECURITY_VERSION;",
    "    let cipher: Cipher = if use_blob {",
    "        let mut view = view;",
    "        let mut ctx = key_store.context();",
    "        encrypt_blob_cipher(&mut view, &mut ctx)",
    "            .map_err(|error| CreateCipherError::Blob(error.to_string()))?",
    "    } else {",
    "        key_store.encrypt(view)?",
    "    };",
    "    let mut cipher_request: CipherRequestModel = cipher.try_into()?;",
  ),
);
replaceExact(
  createClient,
  lines("    Ok(key_store.decrypt(&cipher)?)", "}"),
  lines(
    "    if is_blob_encrypted(&cipher) {",
    "        let mut ctx = key_store.context();",
    "        decrypt_blob_cipher(&cipher, &mut ctx)",
    "            .map_err(|error| CreateCipherError::Blob(error.to_string()))",
    "    } else {",
    "        Ok(key_store.decrypt(&cipher)?)",
    "    }",
    "}",
  ),
);

replaceExact(
  editClient,
  lines("    key_management::KeySlotIds, require,"),
  lines(
    "    key_management::{BLOB_SECURITY_VERSION, KeySlotIds},",
    "    require,",
  ),
);
replaceExact(
  editClient,
  lines("use super::CiphersClient;", "use crate::{"),
  lines(
    "use super::CiphersClient;",
    "use crate::cipher::blob::{decrypt_blob_cipher, encrypt_blob_cipher, is_blob_encrypted};",
    "use crate::{",
  ),
);
replaceExact(
  editClient,
  lines("    #[error(transparent)]", "    Uuid(#[from] uuid::Error),", "}"),
  lines(
    "    #[error(transparent)]",
    "    Uuid(#[from] uuid::Error),",
    '    #[error("Cipher blob operation failed: {0}")]',
    "    Blob(String),",
    "}",
  ),
);
replaceExact(
  editClient,
  lines(
    "    let original_cipher = repository.get(cipher_id).await?.ok_or(ItemNotFoundError)?;",
    "    let original_cipher_view: CipherView = if use_strict_decryption {",
    "        key_store.decrypt(&StrictDecrypt(original_cipher.clone()))?",
    "    } else {",
    "        key_store.decrypt(&original_cipher)?",
    "    };",
  ),
  lines(
    "    let original_cipher = repository.get(cipher_id).await?.ok_or(ItemNotFoundError)?;",
    "    let original_is_blob = is_blob_encrypted(&original_cipher);",
    "    let original_cipher_view: CipherView = if original_is_blob {",
    "        let mut ctx = key_store.context();",
    "        decrypt_blob_cipher(&original_cipher, &mut ctx)",
    "            .map_err(|error| EditCipherError::Blob(error.to_string()))?",
    "    } else if use_strict_decryption {",
    "        key_store.decrypt(&StrictDecrypt(original_cipher.clone()))?",
    "    } else {",
    "        key_store.decrypt(&original_cipher)?",
    "    };",
  ),
);
replaceExact(
  editClient,
  lines(
    "    let cipher: Cipher = key_store.encrypt(view)?;",
    "    let mut cipher_request: CipherRequestModel = cipher.try_into()?;",
  ),
  lines(
    "    let use_blob = original_is_blob",
    "        || (matches!(view.r#type, CipherType::SecureNote)",
    "            && view.organization_id.is_none()",
    "            && key_store.context().get_security_state_version() >= BLOB_SECURITY_VERSION);",
    "    let cipher: Cipher = if use_blob {",
    "        let mut view = view;",
    "        let mut ctx = key_store.context();",
    "        encrypt_blob_cipher(&mut view, &mut ctx)",
    "            .map_err(|error| EditCipherError::Blob(error.to_string()))?",
    "    } else {",
    "        key_store.encrypt(view)?",
    "    };",
    "    let mut cipher_request: CipherRequestModel = cipher.try_into()?;",
  ),
);
replaceExact(
  editClient,
  lines(
    "    if use_strict_decryption {",
    "        Ok(key_store.decrypt(&StrictDecrypt(cipher))?)",
    "    } else {",
    "        Ok(key_store.decrypt(&cipher)?)",
    "    }",
    "}",
  ),
  lines(
    "    if is_blob_encrypted(&cipher) {",
    "        let mut ctx = key_store.context();",
    "        decrypt_blob_cipher(&cipher, &mut ctx)",
    "            .map_err(|error| EditCipherError::Blob(error.to_string()))",
    "    } else if use_strict_decryption {",
    "        Ok(key_store.decrypt(&StrictDecrypt(cipher))?)",
    "    } else {",
    "        Ok(key_store.decrypt(&cipher)?)",
    "    }",
    "}",
  ),
);

replaceExact(
  getClient,
  lines("use super::CiphersClient;", "use crate::{"),
  lines(
    "use super::CiphersClient;",
    "use crate::cipher::blob::{decrypt_blob_cipher, decrypt_blob_cipher_list, is_blob_encrypted};",
    "use crate::{",
  ),
);
replaceExact(
  getClient,
  lines(
    "    #[error(transparent)]",
    "    Repository(#[from] RepositoryError),",
    "}",
  ),
  lines(
    "    #[error(transparent)]",
    "    Repository(#[from] RepositoryError),",
    '    #[error("Cipher blob operation failed: {0}")]',
    "    Blob(String),",
    "}",
  ),
);
replaceExact(
  getClient,
  lines(
    "    let cipher = repository.get(id).await?.ok_or(ItemNotFoundError)?;",
    "",
    "    if use_strict_decryption {",
    "        Ok(store.decrypt(&StrictDecrypt(cipher))?)",
    "    } else {",
    "        Ok(store.decrypt(&cipher)?)",
    "    }",
  ),
  lines(
    "    let cipher = repository.get(id).await?.ok_or(ItemNotFoundError)?;",
    "",
    "    if is_blob_encrypted(&cipher) {",
    "        let mut ctx = store.context();",
    "        decrypt_blob_cipher(&cipher, &mut ctx)",
    "            .map_err(|error| GetCipherError::Blob(error.to_string()))",
    "    } else if use_strict_decryption {",
    "        Ok(store.decrypt(&StrictDecrypt(cipher))?)",
    "    } else {",
    "        Ok(store.decrypt(&cipher)?)",
    "    }",
  ),
);
replaceExact(
  getClient,
  `    let ciphers = repository.list().await?;
    if use_strict_decryption {
        let strict: Vec<StrictDecrypt<Cipher>> = ciphers.into_iter().map(StrictDecrypt).collect();
        let (successes, failures) = store.decrypt_list_with_failures(&strict);
        Ok(DecryptCipherListResult {
            successes,
            failures: failures.into_iter().map(|f| f.0.clone()).collect(),
        })
    } else {
        let (successes, failures) = store.decrypt_list_with_failures(&ciphers);
        Ok(DecryptCipherListResult {
            successes,
            failures: failures.into_iter().cloned().collect(),
        })
    }
`,
  `    let ciphers = repository.list().await?;
    let mut successes = Vec::with_capacity(ciphers.len());
    let mut failures = Vec::new();
    for cipher in ciphers {
        let result = if is_blob_encrypted(&cipher) {
            let mut ctx = store.context();
            decrypt_blob_cipher_list(&cipher, &mut ctx).map_err(|_| ())
        } else if use_strict_decryption {
            store
                .decrypt(&StrictDecrypt(cipher.clone()))
                .map_err(|_| ())
        } else {
            store.decrypt(&cipher).map_err(|_| ())
        };
        match result {
            Ok(view) => successes.push(view),
            Err(()) => failures.push(cipher),
        }
    }
    Ok(DecryptCipherListResult {
        successes,
        failures,
    })
`,
);
replaceExact(
  getClient,
  `    let ciphers = repository.list().await?;
    if use_strict_decryption {
        let strict: Vec<StrictDecrypt<Cipher>> = ciphers.into_iter().map(StrictDecrypt).collect();
        let (successes, failures) = store.decrypt_list_with_failures(&strict);
        Ok(DecryptCipherResult {
            successes,
            failures: failures.into_iter().map(|f| f.0.clone()).collect(),
        })
    } else {
        let (successes, failures) = store.decrypt_list_with_failures(&ciphers);
        Ok(DecryptCipherResult {
            successes,
            failures: failures.into_iter().cloned().collect(),
        })
    }
`,
  `    let ciphers = repository.list().await?;
    let mut successes = Vec::with_capacity(ciphers.len());
    let mut failures = Vec::new();
    for cipher in ciphers {
        let result = if is_blob_encrypted(&cipher) {
            let mut ctx = store.context();
            decrypt_blob_cipher(&cipher, &mut ctx).map_err(|_| ())
        } else if use_strict_decryption {
            store
                .decrypt(&StrictDecrypt(cipher.clone()))
                .map_err(|_| ())
        } else {
            store.decrypt(&cipher).map_err(|_| ())
        };
        match result {
            Ok(view) => successes.push(view),
            Err(()) => failures.push(cipher),
        }
    }
    Ok(DecryptCipherResult {
        successes,
        failures,
    })
`,
);

console.log(
  "prepare-safeory-sdk-adapter-proof: wired SecureNote blob create/edit/sync/state paths and server-compatible JSON blob containers",
);
