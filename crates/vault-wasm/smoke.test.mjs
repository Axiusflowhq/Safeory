// Node smoke test for the generated vault-wasm bindings (ESM, --target web).
// Proves the WASM crypto core actually runs outside Rust: create, put, list,
// lock, snapshot, reload, unlock, decrypt, and fail-closed behaviors.
import { readFile } from "node:fs/promises";
import init, { WasmDeviceIdentity, WasmVault } from "./pkg/vault_wasm.js";

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
  access_policy: {
    owner_only_default: true,
    grants: [],
    private_forever: false,
    destruction: null,
  },
  fields: { body: "hunter2" },
  notes: null,
};
vault.putItemJson(JSON.stringify(item));
const encryptedItemIds = JSON.parse(vault.listEncryptedItemIdsJson());
if (encryptedItemIds.length !== 1 || encryptedItemIds[0] !== item.id) {
  throw new Error("encrypted sync inventory did not include the stored item");
}
if (vault.encryptedItemIsTombstone(item.id)) {
  throw new Error("an active encrypted sync item must not be marked as a tombstone");
}

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
const readableExport = JSON.parse(restored.exportReadableJson());
if (readableExport.format !== "safeory-readable-export") {
  throw new Error("readable export format mismatch");
}
if (readableExport.items.length !== 1 || readableExport.items[0].item.id !== item.id) {
  throw new Error("readable export item mismatch");
}

// Encrypted sync records cross the boundary without plaintext or key export.
// Exact ciphertext CAS must preserve an unlocked target and reject stale input.
const syncTarget = WasmVault.fromSnapshotJson(snapshotJson);
syncTarget.unlock(pass);
const syncBase = syncTarget.getEncryptedItemJson(item.id);
if (typeof syncBase !== "string") throw new Error("encrypted sync base should exist");
if (syncTarget.getEncryptedItemJson("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") !== null) {
  throw new Error("missing encrypted sync item should return null");
}
const syncRemote = WasmVault.fromSnapshotJson(snapshotJson);
syncRemote.unlock(pass);
const remoteItem = JSON.parse(syncRemote.getItemJson(item.id));
remoteItem.title = "Remote bank record";
syncRemote.updateItemJson(JSON.stringify(remoteItem), 0n);
const syncNext = syncRemote.getEncryptedItemJson(item.id);
syncTarget.applyEncryptedItemJson(syncNext, syncBase);
if (!syncTarget.isUnlocked()) throw new Error("encrypted sync apply should preserve unlock");
if (JSON.parse(syncTarget.getItemJson(item.id)).title !== "Remote bank record") {
  throw new Error("encrypted sync apply did not replace the record");
}
let staleSyncFailed = false;
try { syncTarget.applyEncryptedItemJson(syncNext, syncBase); } catch { staleSyncFailed = true; }
if (!staleSyncFailed) throw new Error("stale encrypted sync precondition should fail");

// 7. Wrong passphrase fails closed.
const restored2 = WasmVault.fromSnapshotJson(snapshotJson);
let wrongFailed = false;
try { restored2.unlock(wrong); } catch { wrongFailed = true; }
if (!wrongFailed) throw new Error("wrong passphrase should be rejected");
if (restored2.isUnlocked()) throw new Error("wrong passphrase must not unlock");

// 8. Emergency Card: null initially, set + read + hidden from list.
if (restored.getEmergencyCardJson() !== null) throw new Error("card should be absent initially");
const principalId = "22222222-2222-4222-8222-222222222222";
const deviceId = "33333333-3333-4333-8333-333333333333";
const deviceKey = "09" + "00".repeat(31);
const card = {
  selected_item_ids: [item.id],
  contacts: [],
  principals: [{
    id: principalId,
    name: "Ada",
    relation: "Sibling",
    devices: [{ id: deviceId, label: "Phone", encryption_public_key_hex: deviceKey }],
  }],
  retired_principal_ids: [],
  retired_device_ids: [],
  retired_signing_public_key_hexes: [],
  instructions: "Call my sister",
};
const cardRev = restored.setEmergencyCardJson(JSON.stringify(card));
if (cardRev !== 1n) throw new Error("card create should be revision 1, got " + cardRev);
const cardBack = JSON.parse(restored.getEmergencyCardJson());
if (cardBack.card.instructions !== "Call my sister") throw new Error("card round-trip mismatch");
if (JSON.parse(restored.listItemsJson()).length !== 1) {
  throw new Error("emergency card must be hidden from the item list");
}

// 9. v10-compatible trusted-principal + access-policy round trip through real WASM.
const itemWithGrant = JSON.parse(restored.getItemJson(item.id));
itemWithGrant.access_policy.grants.push({
  trustee_id: principalId,
  what: "record",
  permission: "view",
  condition: "emergency",
  wait_period: "one_day",
  duration: "until_revoked",
  approvals_required: 0,
  approver_ids: [],
});
const itemRev = restored.updateItemJson(JSON.stringify(itemWithGrant), 0n);
if (itemRev !== 1n) throw new Error("grant update should advance item revision to 1");
const granted = JSON.parse(restored.getItemJson(item.id));
if (granted.access_policy.grants[0]?.trustee_id !== principalId) {
  throw new Error("principal-bound access grant did not round trip");
}

const withoutPrincipal = { ...cardBack.card, principals: [] };
const cardRev2 = restored.setEmergencyCardJson(JSON.stringify(withoutPrincipal));
if (cardRev2 !== 2n) throw new Error("principal removal should advance card revision to 2");
const retiredCard = JSON.parse(restored.getEmergencyCardJson()).card;
if (!retiredCard.retired_principal_ids.includes(principalId)) {
  throw new Error("removed principal UUID was not retired");
}
if (!retiredCard.retired_device_ids.includes(deviceId)) {
  throw new Error("removed device UUID was not retired");
}
let revivalFailed = false;
try {
  restored.setEmergencyCardJson(JSON.stringify({ ...retiredCard, principals: card.principals }));
} catch {
  revivalFailed = true;
}
if (!revivalFailed) throw new Error("retired principal UUID must not be reusable");

// 10. Attachment lifecycle through the generated Uint8Array bindings.
const attachmentPlaintext = new TextEncoder().encode("browser attachment payload");
const attachmentSummary = JSON.parse(
  restored.beginAttachmentImportJson(
    item.id,
    1n,
    "proof.txt",
    BigInt(attachmentPlaintext.byteLength),
  ),
);
const attachmentCiphertext = restored.encryptAttachmentImportChunk(
  attachmentSummary.id,
  0,
  attachmentPlaintext,
);
let duplicateChunkFailed = false;
try {
  restored.encryptAttachmentImportChunk(attachmentSummary.id, 0, attachmentPlaintext);
} catch {
  duplicateChunkFailed = true;
}
if (!duplicateChunkFailed) throw new Error("duplicate attachment chunk encryption must fail");
const attachmentCommit = JSON.parse(
  restored.commitAttachmentImportJson(attachmentSummary.id),
);
if (attachmentCommit.item_revision !== 2) {
  throw new Error("attachment import should advance item revision to 2");
}
const ownerWithAttachment = JSON.parse(restored.getItemJson(item.id));
if (!ownerWithAttachment.attachments.includes(attachmentSummary.id)) {
  throw new Error("attachment reference was not committed to parent item");
}
const describedAttachment = JSON.parse(
  restored.describeAttachmentJson(
    item.id,
    attachmentSummary.id,
    attachmentCommit.encrypted_record_json,
  ),
);
if (describedAttachment.filename !== "proof.txt") {
  throw new Error("attachment manifest description mismatch");
}
const decryptedAttachment = restored.decryptAttachmentChunk(
  item.id,
  attachmentSummary.id,
  attachmentCommit.encrypted_record_json,
  0,
  attachmentCiphertext,
);
if (new TextDecoder().decode(decryptedAttachment) !== "browser attachment payload") {
  throw new Error("attachment chunk decrypt mismatch");
}
const attachmentDelete = JSON.parse(
  restored.deleteAttachmentJson(
    item.id,
    attachmentSummary.id,
    2n,
    1n,
    attachmentCommit.encrypted_record_json,
    42n,
  ),
);
if (attachmentDelete.item_revision !== 3 || attachmentDelete.attachment_revision !== 2) {
  throw new Error("attachment delete revisions mismatch");
}
if (JSON.parse(restored.getItemJson(item.id)).attachments.length !== 0) {
  throw new Error("attachment delete did not remove parent reference");
}

// 11. Account Secret remote root bootstrap: both factors and account binding
// are required, and accepted item ciphertext opens under the transferred root.
const accountId = "44444444-4444-4444-8444-444444444444";
const accountSecret = WasmVault.generateAccountSecret();
if (!/^SFO-A1-[0-9A-F]{64}-[0-9A-F]{8}$/.test(accountSecret)) {
  throw new Error("account secret code format mismatch");
}
const remoteRootWrap = restored.exportRemoteAccountRootWrapJson(
  pass,
  accountSecret,
  accountId,
);
const freshDevice = new WasmVault();
freshDevice.initializeFromRemoteAccountRootWrapJson(
  pass,
  accountSecret,
  accountId,
  remoteRootWrap,
);
const currentEncryptedItem = restored.getEncryptedItemJson(item.id);
freshDevice.applyEncryptedItemJson(currentEncryptedItem);
if (JSON.parse(freshDevice.getItemJson(item.id)).id !== item.id) {
  throw new Error("fresh device could not open synchronized ciphertext");
}
const wrongAccountDevice = new WasmVault();
let wrongAccountFailed = false;
try {
  wrongAccountDevice.initializeFromRemoteAccountRootWrapJson(
    pass,
    accountSecret,
    "55555555-5555-4555-8555-555555555555",
    remoteRootWrap,
  );
} catch {
  wrongAccountFailed = true;
}
if (!wrongAccountFailed || wrongAccountDevice.isInitialized()) {
  throw new Error("remote root wrap must reject account substitution");
}

// 12. Recovery kit: generate, install, verify, unlock fresh instance with it.
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

// 12. Password generation: length + all character classes.
const pw = WasmVault.generatePassword(24);
if (pw.length !== 24) throw new Error("password length mismatch");
for (const re of [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/]) {
  if (!re.test(pw)) throw new Error("password missing a required character class: " + re);
}

// 13. Recipient-side trusted-device pairing responder: durable private bytes
// round-trip through the generated bindings, then answer the owner's challenge.
const pairingPrincipalId = "44444444-4444-4444-8444-444444444444";
const pairingDeviceId = "55555555-5555-4555-8555-555555555555";
const recipientIdentity = WasmDeviceIdentity.generate(pairingDeviceId);
const registration = JSON.parse(recipientIdentity.registrationJson());
if (registration.device_id !== pairingDeviceId) throw new Error("device registration id mismatch");
if (!/^[0-9a-f]{64}$/.test(registration.encryption_public_key_hex)) {
  throw new Error("recipient encryption public key format mismatch");
}
if (!/^[0-9a-f]{64}$/.test(registration.signing_public_key_hex)) {
  throw new Error("recipient signing public key format mismatch");
}
const privateKeyBytes = recipientIdentity.exportPrivateKeyBytes();
if (privateKeyBytes.byteLength !== 64) throw new Error("device private-key bundle length mismatch");
const restoredIdentity = WasmDeviceIdentity.fromPrivateKeyBytes(pairingDeviceId, privateKeyBytes);
privateKeyBytes.fill(0);
if (restoredIdentity.registrationJson() !== recipientIdentity.registrationJson()) {
  throw new Error("restored device identity public keys changed");
}

const pairingOwner = new WasmVault();
pairingOwner.create(pass);
pairingOwner.setEmergencyCardJson(JSON.stringify({
  selected_item_ids: [],
  contacts: [],
  principals: [{
    id: pairingPrincipalId,
    name: "Grace",
    relation: "Trustee",
    devices: [{
      id: pairingDeviceId,
      label: "Recipient browser",
      encryption_public_key_hex: registration.encryption_public_key_hex,
      signing_public_key_hex: null,
    }],
  }],
  retired_principal_ids: [],
  retired_device_ids: [],
  retired_signing_public_key_hexes: [],
  instructions: "",
}));
const pairingChallenge = pairingOwner.createTrustedDevicePairingChallengeJson(
  pairingPrincipalId,
  pairingDeviceId,
);
const pairingProof = restoredIdentity.answerPairingChallengeJson(pairingChallenge);
const pairingRevision = pairingOwner.completeTrustedDevicePairingJson(pairingProof);
if (pairingRevision !== 2n) throw new Error("pairing completion should advance card revision to 2");
const pairedDevice = JSON.parse(pairingOwner.getEmergencyCardJson()).card.principals[0].devices[0];
if (pairedDevice.signing_public_key_hex !== registration.signing_public_key_hex) {
  throw new Error("pairing did not persist recipient signing key");
}
recipientIdentity.free();
restoredIdentity.free();

console.log("WASM smoke test: ALL PASS");
