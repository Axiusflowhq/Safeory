import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const WASM_PACK_VERSION = "0.15.0";
const WASM_TARGET = "wasm32-unknown-unknown";
const CRATE_PATH = "crates/vault-wasm";
const PKG_PATH = resolve(CRATE_PATH, "pkg");
const LOCAL_CONSUMERS = [
  resolve("apps/web/node_modules/vault-wasm"),
  resolve("apps/extension/node_modules/vault-wasm"),
];

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
  });

  if (result.error) {
    throw new Error(`${command} could not be started: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const detail = options.capture ? (result.stderr || result.stdout || "").trim() : "";
    throw new Error(
      `${command} exited with status ${result.status}${detail ? `: ${detail}` : ""}`,
    );
  }
  return options.capture ? result.stdout.trim() : "";
}

function requireTooling() {
  const wasmPackVersion = run("wasm-pack", ["--version"], { capture: true });
  if (wasmPackVersion !== `wasm-pack ${WASM_PACK_VERSION}`) {
    throw new Error(
      `Expected wasm-pack ${WASM_PACK_VERSION}, found ${wasmPackVersion || "an unknown version"}. ` +
        `Install it with: cargo install wasm-pack --version ${WASM_PACK_VERSION} --locked`,
    );
  }

  const installedTargets = run("rustup", ["target", "list", "--installed"], { capture: true })
    .split(/\r?\n/)
    .filter(Boolean);
  if (!installedTargets.includes(WASM_TARGET)) {
    throw new Error(`Missing Rust target ${WASM_TARGET}. Install it with: rustup target add ${WASM_TARGET}`);
  }
}

function verifyPackage() {
  const requiredFiles = [
    "package.json",
    "vault_wasm.js",
    "vault_wasm_bg.wasm",
    "vault_wasm.d.ts",
  ];
  for (const file of requiredFiles) {
    if (!existsSync(resolve(PKG_PATH, file))) {
      throw new Error(`wasm-pack did not generate ${resolve(PKG_PATH, file)}`);
    }
  }

  const packageJson = JSON.parse(readFileSync(resolve(PKG_PATH, "package.json"), "utf8"));
  if (packageJson.name !== "vault-wasm") {
    throw new Error(`Generated package name must be vault-wasm, found ${String(packageJson.name)}`);
  }
}

function refreshInstalledWasmBinary() {
  const source = resolve(PKG_PATH, "vault_wasm_bg.wasm");
  const sourceBytes = readFileSync(source);

  for (const consumer of LOCAL_CONSUMERS) {
    const installed = resolve(consumer, "vault_wasm_bg.wasm");
    if (!existsSync(installed)) continue;

    const installedBytes = readFileSync(installed);
    if (!sourceBytes.equals(installedBytes)) {
      copyFileSync(source, installed);
      console.log(`Refreshed ${installed} from the generated WASM package.`);
    }

    if (!sourceBytes.equals(readFileSync(installed))) {
      throw new Error(`Installed vault-wasm binary did not refresh: ${installed}`);
    }
  }
}

try {
  requireTooling();
  run("wasm-pack", [
    "build",
    CRATE_PATH,
    "--target",
    "web",
    "--release",
    "--out-dir",
    "pkg",
    "--locked",
  ]);
  verifyPackage();
  refreshInstalledWasmBinary();
  console.log(`Generated ${CRATE_PATH}/pkg with wasm-pack ${WASM_PACK_VERSION}.`);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
