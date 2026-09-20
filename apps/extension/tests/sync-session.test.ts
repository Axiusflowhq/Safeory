import assert from "node:assert/strict";
import test from "node:test";

import type { EncryptedVaultItemV1 } from "@safeory/contracts";
import { createSerializedMutationRunner } from "../src/mutation.ts";
import { createExtensionVaultSyncSession } from "../src/sync-session.ts";

const item: EncryptedVaultItemV1 = {
  format_version: 1,
  payload_schema_version: 1,
  algorithm: "xchacha20poly1305",
  object_id: "11111111-1111-4111-8111-111111111111",
  key_id: "22222222-2222-4222-8222-222222222222",
  revision: 1,
  key_nonce: Array(24).fill(1) as number[],
  wrapped_item_key: [2],
  payload_nonce: Array(24).fill(3) as number[],
  ciphertext: [4],
};

test("remote acceptance uses exact ciphertext CAS and persists before resolving", async () => {
  const calls: Array<{ next: string; expected?: string }> = [];
  let persisted = false;
  const state = {
    verifyMasterPassphrase: (_passphrase: string) => undefined,
    exportRemoteAccountRootWrapJson: () => "{}",
    getEncryptedItemJson: () => JSON.stringify(item),
    listEncryptedItemIdsJson: () => JSON.stringify([item.object_id]),
    encryptedItemIsTombstone: () => false,
    applyEncryptedItemJson: (next: string, expected?: string) => {
      calls.push({ next, ...(expected === undefined ? {} : { expected }) });
    },
  };
  const mutations = createSerializedMutationRunner({
    acquire: async () => state,
    persist: async () => {
      persisted = true;
    },
    discard: () => assert.fail("persistence succeeds"),
  });
  const session = createExtensionVaultSyncSession(mutations);

  await session.applyRemoteEncryptedItemForSync(item, item);
  assert.equal(persisted, true);
  assert.deepEqual(calls, [{ next: JSON.stringify(item), expected: JSON.stringify(item) }]);
  assert.deepEqual(await session.listEncryptedItemIdsForSync(), [item.object_id]);
  assert.deepEqual(await session.loadEncryptedItemForSync(item.object_id), item);
  assert.equal(await session.encryptedItemIsTombstoneForSync(item.object_id), false);
});

test("remote creation passes no expected ciphertext", async () => {
  let expectedArgument: string | undefined = "unexpected";
  const state = {
    verifyMasterPassphrase: (_passphrase: string) => undefined,
    exportRemoteAccountRootWrapJson: () => "{}",
    getEncryptedItemJson: () => null,
    listEncryptedItemIdsJson: () => "[]",
    encryptedItemIsTombstone: () => false,
    applyEncryptedItemJson: (_next: string, expected?: string) => {
      expectedArgument = expected;
    },
  };
  const session = createExtensionVaultSyncSession(createSerializedMutationRunner({
    acquire: async () => state,
    persist: async () => undefined,
    discard: () => assert.fail("persistence succeeds"),
  }));
  await session.applyRemoteEncryptedItemForSync(item, null);
  assert.equal(expectedArgument, undefined);
});

test("enrollment re-authentication and root export are read-only serialized access", async () => {
  const calls: string[] = [];
  let persistCount = 0;
  const state = {
    verifyMasterPassphrase: (passphrase: string) => {
      calls.push(`verify:${passphrase}`);
    },
    exportRemoteAccountRootWrapJson: (
      passphrase: string,
      accountSecretCode: string,
      accountId: string,
    ) => {
      calls.push(`export:${passphrase}:${accountSecretCode}:${accountId}`);
      return "{\"format_version\":1}";
    },
    getEncryptedItemJson: () => null,
    listEncryptedItemIdsJson: () => "[]",
    encryptedItemIsTombstone: () => false,
    applyEncryptedItemJson: () => undefined,
  };
  const session = createExtensionVaultSyncSession(createSerializedMutationRunner({
    acquire: async () => state,
    persist: async () => {
      persistCount += 1;
    },
    discard: () => assert.fail("read-only access does not persist"),
  }));

  await session.verifyMasterPassphrase("correct horse battery");
  const wrapped = await session.exportRemoteAccountRootWrap(
    "correct horse battery",
    "SFO-A1-secret",
    "11111111-1111-4111-8111-111111111111",
  );

  assert.equal(wrapped, "{\"format_version\":1}");
  assert.deepEqual(calls, [
    "verify:correct horse battery",
    "export:correct horse battery:SFO-A1-secret:11111111-1111-4111-8111-111111111111",
  ]);
  assert.equal(persistCount, 0);
});
