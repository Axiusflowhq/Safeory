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
      "decrypt_blob_cipher, encrypt_blob_cipher, is_blob_encrypted",
      "self.should_use_blob_encryption(cipher_view.organization_id)",
      "encrypt_blob_cipher(&mut cipher_view, &mut ctx)",
      "if is_blob_encrypted(&cipher)",
      "decrypt_blob_cipher(&cipher, &mut ctx)",
      "contexts.push(self.encrypt(cipher_view).await?)",
      "match self.decrypt(cipher.clone()).await",
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
  "check-safeory-sdk-adapter-proof: OK (public blob cipher paths + server-compatible JSON container present)",
);
