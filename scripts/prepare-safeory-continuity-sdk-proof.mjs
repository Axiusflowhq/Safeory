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
  console.error(`prepare-safeory-continuity-sdk-proof: ${message}`);
  process.exit(1);
}

function replaceExact(file, before, after) {
  const body = fs.readFileSync(file, "utf8").replaceAll("\r\n", "\n");
  const matches = body.split(before).length - 1;
  if (matches !== 1) {
    fail(
      `expected exactly one source fragment in ${path.relative(checkout, file)}, found ${matches}`,
    );
  }
  fs.writeFileSync(file, body.replace(before, after));
}

const checkoutArg = process.argv[2];
if (!checkoutArg) {
  fail(
    "usage: node scripts/prepare-safeory-continuity-sdk-proof.mjs <prepared-sdk-checkout>",
  );
}

const checkout = path.resolve(checkoutArg);
const vaultCargo = path.join(
  checkout,
  "crates",
  "bitwarden-vault",
  "Cargo.toml",
);
const cipherFile = path.join(
  checkout,
  "crates",
  "bitwarden-vault",
  "src",
  "cipher",
  "cipher.rs",
);
const cipherMod = path.join(
  checkout,
  "crates",
  "bitwarden-vault",
  "src",
  "cipher",
  "mod.rs",
);

for (const file of [vaultCargo, cipherFile, cipherMod]) {
  if (!fs.existsSync(file))
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
  fail("SDK must be cleaned before continuity proof preparation");
}

replaceExact(
  vaultCargo,
  "zxcvbn = { workspace = true }\n",
  "zxcvbn = { workspace = true }\nzeroize = { workspace = true }\n",
);

replaceExact(
  cipherFile,
  `use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, EncString, IdentifyKey, KeyStoreContext,
    PrimitiveEncryptable,
};
`,
  `use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, Decryptable, EncString, IdentifyKey, KeyStore,
    KeyStoreContext, PrimitiveEncryptable,
};
`,
);

replaceExact(
  cipherFile,
  '#[cfg(feature = "wasm")]\nuse wasm_bindgen::prelude::wasm_bindgen;\n',
  '#[cfg(feature = "wasm")]\nuse wasm_bindgen::prelude::wasm_bindgen;\nuse zeroize::Zeroizing;\n',
);

replaceExact(
  cipherFile,
  `    #[error(transparent)]
    Api(#[from] ApiError),
}
`,
  `    #[error(transparent)]
    Api(#[from] ApiError),
    #[error("continuity record-key selection requires a per-record cipher key")]
    ContinuityRecordKeyMissing,
}
`,
);

const continuityFunctions = `/// Proof-only native bridge for selected continuity release of one record key.
///
/// The selected key exists as encoded bytes only for the duration of \`use_key\`
/// and is zeroized on scope exit. This function has no WASM/UniFFI binding.
#[doc(hidden)]
pub fn with_record_key_for_continuity_proof<R>(
    cipher: &Cipher,
    key_store: &KeyStore<KeySlotIds>,
    use_key: impl FnOnce(&[u8]) -> R,
) -> Result<R, CipherError> {
    if cipher.key.is_none() {
        return Err(CipherError::ContinuityRecordKeyMissing);
    }
    let mut ctx = key_store.context();
    let key_id = Cipher::decrypt_cipher_key(&mut ctx, cipher.key_identifier(), &cipher.key)?;
    #[allow(deprecated)]
    let key = ctx.dangerous_get_symmetric_key(key_id)?;
    let encoded = Zeroizing::new(key.to_encoded().to_vec());
    Ok(use_key(encoded.as_slice()))
}

/// Proof-only native bridge for selected continuity release of one Space key.
///
/// The selected key exists as encoded bytes only for the duration of \`use_key\`
/// and is zeroized on scope exit. This function has no WASM/UniFFI binding.
#[doc(hidden)]
pub fn with_space_key_for_continuity_proof<R>(
    organization_id: OrganizationId,
    key_store: &KeyStore<KeySlotIds>,
    use_key: impl FnOnce(&[u8]) -> R,
) -> Result<R, CipherError> {
    let ctx = key_store.context();
    #[allow(deprecated)]
    let key = ctx.dangerous_get_symmetric_key(SymmetricKeySlotId::Organization(organization_id))?;
    let encoded = Zeroizing::new(key.to_encoded().to_vec());
    Ok(use_key(encoded.as_slice()))
}
`;

replaceExact(
  cipherFile,
  "/// Helper trait for operations on cipher types.\n",
  `${continuityFunctions}\n/// Helper trait for operations on cipher types.\n`,
);

replaceExact(
  cipherMod,
  `    CipherType, CipherView, DecryptCipherListResult, DecryptCipherResult, EncryptionContext,
    ListOrganizationCiphersResult,
`,
  `    CipherType, CipherView, DecryptCipherListResult, DecryptCipherResult, EncryptionContext,
    ListOrganizationCiphersResult, with_record_key_for_continuity_proof,
    with_space_key_for_continuity_proof,
`,
);

console.log(
  "prepare-safeory-continuity-sdk-proof: installed two native, zeroizing selected-key callback bridges",
);
