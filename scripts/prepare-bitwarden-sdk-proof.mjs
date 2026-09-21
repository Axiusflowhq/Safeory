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
  console.error(`prepare-bitwarden-sdk-proof: ${message}`);
  process.exit(1);
}

function replaceExact(file, before, after) {
  const body = fs.readFileSync(file, "utf8").replaceAll("\r\n", "\n");
  if (!body.includes(before)) {
    fail(
      `expected source fragment not found in ${path.relative(checkout, file)}`,
    );
  }
  fs.writeFileSync(file, body.replace(before, after));
}

const checkoutArg = process.argv[2];
if (!checkoutArg) {
  fail(
    "usage: node scripts/prepare-bitwarden-sdk-proof.mjs <fresh-sdk-checkout>",
  );
}
if (!expectedCommit) {
  fail("missing SDK commit in provenance manifest");
}

const checkout = path.resolve(checkoutArg);
if (
  !fs.existsSync(path.join(checkout, ".git")) ||
  !fs.existsSync(path.join(checkout, "Cargo.toml"))
) {
  fail(`not a Bitwarden SDK git checkout: ${checkout}`);
}

const actualCommit = execFileSync(
  "git",
  ["-C", checkout, "rev-parse", "HEAD"],
  {
    encoding: "utf8",
  },
).trim();
if (actualCommit !== expectedCommit) {
  fail(`checkout is ${actualCommit}; expected pinned commit ${expectedCommit}`);
}

const status = execFileSync("git", ["-C", checkout, "status", "--porcelain"], {
  encoding: "utf8",
}).trim();
if (status) {
  fail("checkout must be fresh and clean before preparation");
}

const licensedRoot = path.join(checkout, "bitwarden_license");
const licensedWasmNpm = path.join(
  checkout,
  "crates",
  "bitwarden-wasm-internal",
  "bitwarden_license",
);
for (const restrictedTree of [licensedRoot, licensedWasmNpm]) {
  if (!fs.existsSync(restrictedTree)) {
    fail(
      `expected restricted tree is missing before cleanup: ${path.relative(checkout, restrictedTree)}`,
    );
  }
  fs.rmSync(restrictedTree, { recursive: true, force: false });
}

replaceExact(
  path.join(checkout, "Cargo.toml"),
  'members = ["bitwarden_license/*", "crates/*"]',
  'members = ["crates/*"]',
);
replaceExact(
  path.join(checkout, "Cargo.toml"),
  'bitwarden-commercial-vault = { path = "bitwarden_license/bitwarden-commercial-vault", version = "=3.0.0" }\n',
  "",
);

const pmCargo = path.join(checkout, "crates", "bitwarden-pm", "Cargo.toml");
replaceExact(pmCargo, '    "bitwarden-commercial-vault/wasm",\n', "");
replaceExact(
  pmCargo,
  'bitwarden-license = ["dep:bitwarden-commercial-vault"]\n',
  "",
);
replaceExact(
  pmCargo,
  "bitwarden-commercial-vault = { workspace = true, optional = true }\n",
  "",
);

const pmLib = path.join(checkout, "crates", "bitwarden-pm", "src", "lib.rs");
replaceExact(
  pmLib,
  '#[cfg(feature = "bitwarden-license")]\nmod commercial;\n\n',
  "",
);
replaceExact(
  pmLib,
  '#[cfg(feature = "bitwarden-license")]\npub use commercial::CommercialPasswordManagerClient;\n\n',
  "",
);
replaceExact(
  pmLib,
  `    /// Bitwarden licensed operations
    #[cfg(feature = "bitwarden-license")]
    pub fn commercial(&self) -> CommercialPasswordManagerClient {
        CommercialPasswordManagerClient::new(self.0.clone())
    }

`,
  "",
);
fs.rmSync(
  path.join(checkout, "crates", "bitwarden-pm", "src", "commercial.rs"),
);

const wasmCargo = path.join(
  checkout,
  "crates",
  "bitwarden-wasm-internal",
  "Cargo.toml",
);
replaceExact(
  wasmCargo,
  'bitwarden-license = ["bitwarden-pm/bitwarden-license", "dep:bitwarden-commercial-vault"]\n',
  "",
);
replaceExact(
  wasmCargo,
  `bitwarden-commercial-vault = { workspace = true, optional = true, features = [
  "wasm",
] }
`,
  "",
);

const wasmClient = path.join(
  checkout,
  "crates",
  "bitwarden-wasm-internal",
  "src",
  "client.rs",
);
replaceExact(
  wasmClient,
  `    pub fn version(&self) -> String {
        #[cfg(feature = "bitwarden-license")]
        return format!("COMMERCIAL-{}", env!("SDK_VERSION"));
        #[cfg(not(feature = "bitwarden-license"))]
        return env!("SDK_VERSION").to_owned();
    }
`,
  `    pub fn version(&self) -> String {
        env!("SDK_VERSION").to_owned()
    }
`,
);
replaceExact(
  wasmClient,
  `    /// Bitwarden licensed operations.
    #[cfg(feature = "bitwarden-license")]
    pub fn commercial(&self) -> bitwarden_pm::CommercialPasswordManagerClient {
        self.0.commercial()
    }

`,
  "",
);

const wasmBuild = path.join(
  checkout,
  "crates",
  "bitwarden-wasm-internal",
  "build.sh",
);
replaceExact(wasmBuild, 'ENABLE_LICENSE_FEATURE=""\n', "");
replaceExact(
  wasmBuild,
  `    -b)
      ENABLE_LICENSE_FEATURE="--features bitwarden-license"
      NPM_FOLDER="bitwarden_license/npm"
      ;;
`,
  "",
);
replaceExact(
  wasmBuild,
  `if [ -n "$ENABLE_LICENSE_FEATURE" ]; then
  echo "Build will include BITWARDEN LICENSED FEATURES"
fi

`,
  "",
);
replaceExact(
  wasmBuild,
  "RUSTFLAGS='-Ctarget-cpu=mvp --cfg getrandom_backend=\"wasm_js\"' RUSTC_BOOTSTRAP=1 cargo build -p bitwarden-wasm-internal -Zbuild-std=panic_abort,std --target wasm32-unknown-unknown ${RELEASE_FLAG} ${ENABLE_LICENSE_FEATURE}",
  "RUSTFLAGS='-Ctarget-cpu=mvp --cfg getrandom_backend=\"wasm_js\"' RUSTC_BOOTSTRAP=1 cargo build -p bitwarden-wasm-internal -Zbuild-std=panic_abort,std --target wasm32-unknown-unknown ${RELEASE_FLAG}",
);

// Resolve the now-smaller workspace so Cargo prunes unreachable licensed crates
// and their now-unused transitive dependencies from Cargo.lock. The existing lock
// continues to pin all retained packages; reject any normalization that adds or
// changes lockfile content rather than only removing unreachable entries.
execFileSync("cargo", ["metadata", "--format-version", "1"], {
  cwd: checkout,
  stdio: "ignore",
});
const lockDiff = execFileSync(
  "git",
  ["-C", checkout, "diff", "--unified=0", "--", "Cargo.lock"],
  {
    encoding: "utf8",
  },
);
const addedLockLines = lockDiff
  .split(/\r?\n/)
  .filter((line) => line.startsWith("+") && !line.startsWith("+++"));
if (addedLockLines.length > 0) {
  fail(
    `Cargo lock normalization added or changed content:\n${addedLockLines.slice(0, 20).join("\n")}`,
  );
}
execFileSync(
  "cargo",
  ["metadata", "--locked", "--format-version", "1", "--no-deps"],
  {
    cwd: checkout,
    stdio: "ignore",
  },
);

console.log(`prepare-bitwarden-sdk-proof: prepared ${checkout}`);
console.log(`prepare-bitwarden-sdk-proof: pinned commit ${actualCommit}`);
