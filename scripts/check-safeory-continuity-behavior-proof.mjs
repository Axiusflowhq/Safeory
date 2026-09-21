import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, "..");
const continuityLock = path.join(
  root,
  "tests",
  "foundation",
  "continuity-behavior",
  "Cargo.lock",
);
const safeoryLock = path.join(root, "Cargo.lock");
const sdkLock = path.join(
  root,
  ".proof",
  "bitwarden-sdk-continuity",
  "Cargo.lock",
);

function fail(message) {
  console.error(`check-safeory-continuity-behavior-proof: ${message}`);
  process.exit(1);
}

function packageIdentities(lockBody) {
  const identities = new Set();
  for (const block of lockBody.split("[[package]]").slice(1)) {
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    const source = block.match(/^\s*source\s*=\s*"([^"]+)"/m)?.[1] ?? "";
    const checksum = block.match(/^\s*checksum\s*=\s*"([^"]+)"/m)?.[1] ?? "";
    if (name && version)
      identities.add(`${name}\u0000${version}\u0000${source}\u0000${checksum}`);
  }
  return identities;
}

for (const file of [continuityLock, safeoryLock, sdkLock]) {
  if (!fs.existsSync(file))
    fail(`required lockfile is missing: ${path.relative(root, file)}`);
}

const continuity = packageIdentities(fs.readFileSync(continuityLock, "utf8"));
const allowed = new Set([
  ...packageIdentities(fs.readFileSync(safeoryLock, "utf8")),
  ...packageIdentities(fs.readFileSync(sdkLock, "utf8")),
]);
const harnessPrefix = "safeory-foundation-continuity-behavior\u00000.0.0\u0000";
const unexpected = [...continuity].filter(
  (identity) => !identity.startsWith(harnessPrefix) && !allowed.has(identity),
);
if (unexpected.length > 0) {
  fail(
    `mixed continuity graph contains packages outside the pinned Safeory/SDK lock union:\n${unexpected
      .map((identity) => `  ${identity.replaceAll("\u0000", " ")}`)
      .join("\n")}`,
  );
}

const forbiddenNames = [
  "with_record_key_for_continuity_proof",
  "with_space_key_for_continuity_proof",
];
const forbiddenRoots = [
  path.join(root, "apps"),
  path.join(root, "packages"),
  path.join(root, "crates", "vault-wasm"),
];
const sourceExtensions = new Set([".js", ".mjs", ".ts", ".tsx", ".rs"]);
const violations = [];

function scan(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (["node_modules", "target", "dist", ".next"].includes(entry.name))
        continue;
      scan(target);
      continue;
    }
    if (!sourceExtensions.has(path.extname(entry.name))) continue;
    const body = fs.readFileSync(target, "utf8");
    for (const name of forbiddenNames) {
      if (body.includes(name))
        violations.push(`${path.relative(root, target)}: ${name}`);
    }
  }
}

for (const directory of forbiddenRoots) scan(directory);
if (violations.length > 0) {
  fail(
    `selected-key proof bridge leaked into ordinary app/WASM surfaces:\n${violations.join("\n")}`,
  );
}

console.log(
  `check-safeory-continuity-behavior-proof: OK (${continuity.size - 1} resolved packages are within the pinned Safeory/SDK lock union; no JS/WASM bridge exposure)`,
);
