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
  console.error(`check-safeory-continuity-sdk-proof: ${message}`);
}

const checkoutArg = process.argv[2];
if (!checkoutArg) {
  console.error(
    "usage: node scripts/check-safeory-continuity-sdk-proof.mjs <adapted-sdk-checkout>",
  );
  process.exit(2);
}

const checkout = path.resolve(checkoutArg);
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

if (!fs.existsSync(cipherFile) || !fs.existsSync(cipherMod)) {
  fail("continuity proof SDK source is missing");
} else {
  const cipher = fs.readFileSync(cipherFile, "utf8");
  const module = fs.readFileSync(cipherMod, "utf8");
  for (const fragment of [
    "with_record_key_for_continuity_proof",
    "with_space_key_for_continuity_proof",
    "Zeroizing::new(key.to_encoded().to_vec())",
    "ContinuityRecordKeyMissing",
  ]) {
    if (!cipher.includes(fragment) && !module.includes(fragment)) {
      fail(`missing selected-key bridge fragment: ${fragment}`);
    }
  }
  if (
    cipher.includes(
      "wasm_bindgen]\npub fn with_record_key_for_continuity_proof",
    )
  ) {
    fail("record-key continuity bridge must not be wasm_bindgen exported");
  }
  if (
    cipher.includes("wasm_bindgen]\npub fn with_space_key_for_continuity_proof")
  ) {
    fail("Space-key continuity bridge must not be wasm_bindgen exported");
  }
}

const diff = execFileSync(
  "git",
  [
    "-C",
    checkout,
    "diff",
    "--numstat",
    "--",
    "crates/bitwarden-vault/Cargo.toml",
    "crates/bitwarden-vault/src/cipher/cipher.rs",
    "crates/bitwarden-vault/src/cipher/mod.rs",
  ],
  { encoding: "utf8" },
).trim();
const entries = diff
  .split(/\r?\n/)
  .filter(Boolean)
  .map((line) => line.split("\t"));
const added = entries.reduce((sum, [value]) => sum + Number(value || 0), 0);
const removed = entries.reduce((sum, [, value]) => sum + Number(value || 0), 0);
if (entries.length !== 3) {
  fail(
    `expected continuity patch to touch exactly 3 vault files, found ${entries.length}`,
  );
}
if (added > 80 || removed > 5) {
  fail(`continuity patch surface exceeded proof budget: +${added}/-${removed}`);
}

if (failed) process.exit(1);
console.log(
  `check-safeory-continuity-sdk-proof: OK (${entries.length} files, +${added}/-${removed}; native selected-key bridges only)`,
);
