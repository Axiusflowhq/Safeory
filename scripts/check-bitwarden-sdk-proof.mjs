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
const forbiddenTerms = ["bitwarden-commercial-vault", "bitwarden-license"];
let failed = false;

function fail(message) {
  failed = true;
  console.error(`check-bitwarden-sdk-proof: ${message}`);
}

const checkoutArg = process.argv[2];
if (!checkoutArg) {
  console.error(
    "usage: node scripts/check-bitwarden-sdk-proof.mjs <prepared-sdk-checkout>",
  );
  process.exit(2);
}

const checkout = path.resolve(checkoutArg);
if (
  !fs.existsSync(path.join(checkout, ".git")) ||
  !fs.existsSync(path.join(checkout, "Cargo.toml"))
) {
  fail(`not a Bitwarden SDK git checkout: ${checkout}`);
}

if (!expectedCommit) {
  fail("missing SDK commit in provenance manifest");
} else {
  try {
    const actualCommit = execFileSync(
      "git",
      ["-C", checkout, "rev-parse", "HEAD"],
      {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      },
    ).trim();
    if (actualCommit !== expectedCommit) {
      fail(
        `checkout is ${actualCommit}; expected pinned commit ${expectedCommit}`,
      );
    }
  } catch (error) {
    fail(`could not resolve checkout commit: ${error.message}`);
  }
}

for (const restrictedTree of [
  path.join(checkout, "bitwarden_license"),
  path.join(checkout, "crates", "bitwarden-wasm-internal", "bitwarden_license"),
]) {
  if (fs.existsSync(restrictedTree)) {
    fail(
      `restricted source tree still exists: ${path.relative(checkout, restrictedTree)}`,
    );
  }
}

const filesToScan = [
  "Cargo.toml",
  "Cargo.lock",
  "crates/bitwarden-pm/Cargo.toml",
  "crates/bitwarden-pm/src/lib.rs",
  "crates/bitwarden-wasm-internal/Cargo.toml",
  "crates/bitwarden-wasm-internal/src/client.rs",
  "crates/bitwarden-wasm-internal/build.sh",
];
for (const relative of filesToScan) {
  const body = fs.readFileSync(path.join(checkout, relative), "utf8");
  for (const term of forbiddenTerms) {
    if (body.includes(term)) {
      fail(`${relative} still contains restricted build/API term ${term}`);
    }
  }
}

try {
  const metadata = JSON.parse(
    execFileSync(
      "cargo",
      ["metadata", "--locked", "--format-version", "1", "--no-deps"],
      {
        cwd: checkout,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      },
    ),
  );
  for (const pkg of metadata.packages ?? []) {
    if (pkg.name === "bitwarden-commercial-vault") {
      fail("Cargo metadata still contains bitwarden-commercial-vault");
    }
    if (
      pkg.manifest_path?.replaceAll("\\", "/").includes("/bitwarden_license/")
    ) {
      fail(
        `Cargo metadata still includes restricted manifest ${pkg.manifest_path}`,
      );
    }
    for (const featureName of Object.keys(pkg.features ?? {})) {
      if (featureName === "bitwarden-license") {
        fail(`${pkg.name} still exposes the bitwarden-license feature`);
      }
    }
  }
} catch (error) {
  fail(
    `cargo metadata --locked failed: ${error.stderr?.toString().trim() || error.message}`,
  );
}

if (failed) {
  process.exit(1);
}

console.log(
  "check-bitwarden-sdk-proof: OK (pinned commit and OSS-only Cargo graph verified)",
);
