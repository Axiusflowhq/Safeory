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
let failed = false;

function fail(message) {
  failed = true;
  console.error(`check-safeory-sdk-adapter-proof: ${message}`);
}

const checkoutArg = process.argv[2];
if (!checkoutArg) {
  console.error(
    "usage: node scripts/check-safeory-sdk-adapter-proof.mjs <adapted-sdk-checkout>",
  );
  process.exit(2);
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

try {
  const actualCommit = execFileSync(
    "git",
    ["-C", checkout, "rev-parse", "HEAD"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  ).trim();
  if (actualCommit !== expectedCommit) {
    fail(
      `checkout is ${actualCommit}; expected pinned commit ${expectedCommit}`,
    );
  }
} catch (error) {
  fail(`could not resolve checkout commit: ${error.message}`);
}

for (const [file, requirements] of [
  [
    cipherClient,
    [
      "encrypt_blob_cipher",
      "is_blob_encrypted",
      "decrypt_blob_cipher_list",
      "matches!(cipher_view.r#type, CipherType::SecureNote)",
      "encrypt_blob_cipher(&mut cipher_view, &mut ctx)",
      "if is_blob_encrypted(&cipher)",
      "decrypt_blob_cipher(&cipher, &mut ctx)",
      "contexts.push(self.encrypt(cipher_view).await?)",
      "match self.decrypt(cipher.clone()).await",
      "decrypt_blob_cipher_list(&cipher, &mut ctx)",
    ],
  ],
  [
    errorFile,
    [
      "Cipher blob encryption failed: {0}",
      "Cipher blob decryption failed: {0}",
      "Blob(String)",
    ],
  ],
  [
    sealedBlob,
    [
      "serde_json::to_string(self)",
      "s.trim_start().starts_with('{')",
      "serde_json::from_str(s)",
      "B64::try_from(s)",
      "JsonEncoding",
      "JsonDecoding",
    ],
  ],
  [
    createClient,
    [
      "BLOB_SECURITY_VERSION",
      "matches!(view.r#type, CipherType::SecureNote)",
      "encrypt_blob_cipher(&mut view, &mut ctx)",
      "CreateCipherError::Blob(error.to_string())",
      "if is_blob_encrypted(&cipher)",
      "decrypt_blob_cipher(&cipher, &mut ctx)",
    ],
  ],
  [
    editClient,
    [
      "BLOB_SECURITY_VERSION",
      "let original_is_blob = is_blob_encrypted(&original_cipher)",
      "let use_blob = original_is_blob",
      "matches!(view.r#type, CipherType::SecureNote)",
      "encrypt_blob_cipher(&mut view, &mut ctx)",
      "EditCipherError::Blob(error.to_string())",
      "if is_blob_encrypted(&cipher)",
      "decrypt_blob_cipher(&cipher, &mut ctx)",
    ],
  ],
  [
    getClient,
    [
      "decrypt_blob_cipher, decrypt_blob_cipher_list, is_blob_encrypted",
      "GetCipherError::Blob(error.to_string())",
      "decrypt_blob_cipher_list(&cipher, &mut ctx)",
      "decrypt_blob_cipher(&cipher, &mut ctx)",
    ],
  ],
  [
    cipherModel,
    [
      "is_some_and(crate::cipher::blob::is_blob_data)",
      "None if is_blob => EncString::Cose_Encrypt0_B64 { data: Vec::new() }",
      "let fallback_name = cipher.as_ref().map(|existing| existing.name.clone())",
      "let local_data = cipher",
    ],
  ],
  [
    blobEncryption,
    [
      "pub(crate) fn is_blob_data(data: &str) -> bool",
      "Blob list projection only supports SecureNote carriers",
      "pub(crate) fn decrypt_blob_cipher_list(",
      "CipherListViewType::SecureNote",
      "CopyableCipherFields::SecureNotes",
    ],
  ],
]) {
  if (!fs.existsSync(file)) {
    fail(`adapted SDK source is missing: ${path.relative(checkout, file)}`);
    continue;
  }
  const body = fs.readFileSync(file, "utf8");
  for (const requirement of requirements) {
    if (!body.includes(requirement)) {
      fail(
        `${path.relative(checkout, file)} is missing adapter fragment: ${requirement}`,
      );
    }
  }
}

if (failed) process.exit(1);
console.log(
  "check-safeory-sdk-adapter-proof: OK (SecureNote blob create/edit/sync/state paths + server-compatible JSON container present)",
);
