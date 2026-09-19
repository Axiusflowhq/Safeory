// Node smoke test for the generated vault-wasm bindings (ESM, --target web).
// Proves the WASM crypto core actually runs outside Rust: create, put, list,
// lock, snapshot, reload, unlock, decrypt, and fail-closed behaviors.
import { readFile } from "node:fs/promises";
import init, { WasmVault } from "./pkg/vault_wasm.js";

// --target web exports an async init that must run before any binding call.
// Node cannot fetch file:// URLs, so feed the wasm bytes directly.
const wasmBytes = await readFile(new URL("./pkg/vault_wasm_bg.wasm", import.meta.url));
await init({ module_or_path: wasmBytes });

const pass = "correct horse battery";
const wrong = "definitely wrong pass";

// 1. Create + unlock.
const vault = new WasmVault();
if (vault.isInitialized()) throw new Error("new vault should be uninitialized");
vault.create(pass);
if (!vault.isInitialized()) throw new Error("create should initialize");
if (!vault.isUnlocked()) throw new Error("create should leave vault unlocked");

// 2. Put an item (VaultItem shape: tagged by kind with a fields map).
const item = {
  id: "11111111-1111-4111-8111-111111111111",
  kind: "secure_note",
  title: "Bank password",
  links: [],
  attachments: [],
  legacy_disposition: "unspecified",
  account_closure_plan: { disposition: "unspecified", instructions: "" },
  fields: { body: "hunter2" },
  notes: null,
};
vault.putItemJson(JSON.stringify(item));

// 3. List + get back.
const listed = JSON.parse(vault.listItemsJson());
if (listed.length !== 1) throw new Error("expected 1 item, got " + listed.length);
if (JSON.stringify(listed).includes("hunter2")) throw new Error("list projection leaked secret fields");
if ("fields" in listed[0].item || "notes" in listed[0].item) {
  throw new Error("list projection must not contain full item fields");
}
const fetched = JSON.parse(vault.getItemJson(item.id));
if (fetched.title !== "Bank password") throw new Error("round-trip title mismatch");

// 4. Snapshot must be ciphertext-only (no plaintext title anywhere).
const snapshotJson = vault.snapshotJson();
if (snapshotJson.includes("Bank password") || snapshotJson.includes("hunter2")) {
  throw new Error("SNAPSHOT LEAKED PLAINTEXT");
}

// 5. Lock zeroizes the key -> get must fail.
vault.lock();
let lockedFailed = false;
try { vault.getItemJson(item.id); } catch { lockedFailed = true; }
if (!lockedFailed) throw new Error("locked vault should not decrypt");

// 6. Reload from snapshot, unlock, decrypt again.
const restored = WasmVault.fromSnapshotJson(snapshotJson);
let lockedRestoreFailed = false;
try { restored.getItemJson(item.id); } catch { lockedRestoreFailed = true; }
if (!lockedRestoreFailed) throw new Error("restored vault should start locked");
restored.unlock(pass);
const refetched = JSON.parse(restored.getItemJson(item.id));
if (refetched.title !== "Bank password") throw new Error("post-restore decrypt mismatch");

// 7. Wrong passphrase fails closed.
const restored2 = WasmVault.fromSnapshotJson(snapshotJson);
let wrongFailed = false;
try { restored2.unlock(wrong); } catch { wrongFailed = true; }
if (!wrongFailed) throw new Error("wrong passphrase should be rejected");
if (restored2.isUnlocked()) throw new Error("wrong passphrase must not unlock");

// 8. Emergency Card: null initially, set + read + hidden from list.
if (restored.getEmergencyCardJson() !== null) throw new Error("card should be absent initially");
const card = { selected_item_ids: [item.id], contacts: [], instructions: "Call my sister" };
const cardRev = restored.setEmergencyCardJson(JSON.stringify(card));
if (cardRev !== 1n) throw new Error("card create should be revision 1, got " + cardRev);
const cardBack = JSON.parse(restored.getEmergencyCardJson());
if (cardBack.card.instructions !== "Call my sister") throw new Error("card round-trip mismatch");
if (JSON.parse(restored.listItemsJson()).length !== 1) {
  throw new Error("emergency card must be hidden from the item list");
}

// 9. Recovery kit: generate, install, verify, unlock fresh instance with it.
const secretHex = WasmVault.generateRecoverySecret();
if (!/^[0-9a-f]{64}$/.test(secretHex)) throw new Error("recovery secret should be 64 hex chars");
restored.installRecoveryKit(secretHex);
if (!restored.hasRecoveryKit()) throw new Error("recovery kit should be installed");
if (!restored.verifyRecoveryKit(secretHex)) throw new Error("recovery kit should verify");
const snap2 = restored.snapshotJson();
const viaKit = WasmVault.fromSnapshotJson(snap2);
viaKit.unlockWithRecoveryKit(secretHex);
if (!viaKit.isUnlocked()) throw new Error("recovery kit unlock failed");
if (JSON.parse(viaKit.getItemJson(item.id)).title !== "Bank password") {
  throw new Error("recovery-kit-unlocked decrypt mismatch");
}

// 10. Password generation: length + all character classes.
const pw = WasmVault.generatePassword(24);
if (pw.length !== 24) throw new Error("password length mismatch");
for (const re of [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/]) {
  if (!re.test(pw)) throw new Error("password missing a required character class: " + re);
}

console.log("WASM smoke test: ALL PASS");
