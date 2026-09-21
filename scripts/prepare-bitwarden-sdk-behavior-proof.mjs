import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const safeoryRoot = path.resolve(scriptDir, "..");
const checkoutArg = process.argv[2];

if (!checkoutArg) {
  console.error(
    "usage: node scripts/prepare-bitwarden-sdk-behavior-proof.mjs <prepared-sdk-checkout>",
  );
  process.exit(2);
}

const checkout = path.resolve(checkoutArg);
const source = path.join(safeoryRoot, "tests", "foundation", "sdk-behavior");
const destination = path.join(checkout, ".safeory", "sdk-behavior");
const sourceLock = path.join(checkout, "Cargo.lock");
const harnessLock = path.join(destination, "Cargo.lock");

function packageIdentities(lockBody) {
  const identities = new Set();
  for (const block of lockBody.split("[[package]]").slice(1)) {
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    const sourceValue = block.match(/^\s*source\s*=\s*"([^"]+)"/m)?.[1] ?? "";
    const checksum = block.match(/^\s*checksum\s*=\s*"([^"]+)"/m)?.[1] ?? "";
    if (!name || !version) continue;
    identities.add(
      `${name}\u0000${version}\u0000${sourceValue}\u0000${checksum}`,
    );
  }
  return identities;
}

if (
  !fs.existsSync(path.join(checkout, "crates", "bitwarden-pm", "Cargo.toml"))
) {
  console.error(
    "prepare-bitwarden-sdk-behavior-proof: prepared Bitwarden SDK checkout is missing",
  );
  process.exit(1);
}

fs.rmSync(destination, { recursive: true, force: true });
fs.mkdirSync(path.dirname(destination), { recursive: true });
fs.cpSync(source, destination, { recursive: true });
fs.copyFileSync(sourceLock, harnessLock);

execFileSync(
  "cargo",
  [
    "metadata",
    "--manifest-path",
    path.join(destination, "Cargo.toml"),
    "--offline",
    "--format-version",
    "1",
  ],
  { stdio: ["ignore", "ignore", "inherit"] },
);

const sourcePackages = packageIdentities(fs.readFileSync(sourceLock, "utf8"));
const harnessPackages = packageIdentities(fs.readFileSync(harnessLock, "utf8"));
const harnessRootPrefix = "safeory-foundation-sdk-behavior\u00000.0.0\u0000";
for (const identity of harnessPackages) {
  if (identity.startsWith(harnessRootPrefix)) continue;
  if (!sourcePackages.has(identity)) {
    console.error(
      `prepare-bitwarden-sdk-behavior-proof: harness lock resolved package outside pinned SDK graph: ${identity.replaceAll("\u0000", " ")}`,
    );
    process.exit(1);
  }
}

console.log(
  `prepare-bitwarden-sdk-behavior-proof: prepared Safeory harness at ${destination} (${harnessPackages.size - 1} pinned SDK packages)`,
);
