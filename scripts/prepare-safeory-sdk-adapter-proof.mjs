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

if (
  !fs.existsSync(cipherClient) ||
  !fs.existsSync(errorFile) ||
  !fs.existsSync(sealedBlob)
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
use crate::cipher::blob::{decrypt_blob_cipher, encrypt_blob_cipher, is_blob_encrypted};
use crate::{
`,
);

replaceExact(
  cipherClient,
  `        let cipher = key_store.encrypt(cipher_view)?;
        Ok(EncryptionContext {
`,
  `        let cipher = if self.should_use_blob_encryption(cipher_view.organization_id) {
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

console.log(
  "prepare-safeory-sdk-adapter-proof: wired public blob cipher paths and server-compatible JSON blob containers",
);
