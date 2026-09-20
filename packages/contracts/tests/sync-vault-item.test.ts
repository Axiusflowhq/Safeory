import assert from "node:assert/strict"
import test from "node:test"

import { SyncClientError, type ObjectScopeV1 } from "../src/sync-client"
import {
  decodePulledVaultItem,
  parseEncryptedVaultItem,
  prepareVaultItemMutation,
  prepareVaultItemMutationFromBaseline,
  reconcilePulledVaultItem,
  type EncryptedVaultItemV1,
} from "../src/sync-vault-item"

const ITEM_ID = "11111111-1111-4111-8111-111111111111"
const KEY_ID = "22222222-2222-4222-8222-222222222222"
const OPERATION_ID = "33333333-3333-4333-8333-333333333333"
const ACCOUNT_ID = "44444444-4444-4444-8444-444444444444"
const HOUSEHOLD_ID = "55555555-5555-4555-8555-555555555555"
const SPACE_ID = "66666666-6666-4666-8666-666666666666"

const scope: ObjectScopeV1 = {
  scope: "space",
  account_id: ACCOUNT_ID,
  household_id: HOUSEHOLD_ID,
  space_id: SPACE_ID,
}

function item(revision = 1): EncryptedVaultItemV1 {
  return {
    format_version: 1,
    payload_schema_version: 8,
    algorithm: "xchacha20poly1305",
    object_id: ITEM_ID,
    key_id: KEY_ID,
    revision,
    key_nonce: Array.from({ length: 24 }, (_, index) => index),
    wrapped_item_key: [1, 2, 3, 4],
    payload_nonce: Array.from({ length: 24 }, (_, index) => 23 - index),
    ciphertext: [9, 8, 7, revision],
  }
}

test("prepares create and revision-fenced update mutations from encrypted items", async () => {
  const created = await prepareVaultItemMutation(item(), null, scope, OPERATION_ID)
  assert.equal(created.mutation.object.object_id, ITEM_ID)
  assert.equal(created.mutation.object.class, "item")
  assert.equal(created.mutation.object.payload_version, 8)
  assert.equal(created.mutation.object.revision, 1)
  assert.deepEqual(created.mutation.precondition, { condition: "create_only" })

  const updated = await prepareVaultItemMutation(
    item(2),
    item(1),
    scope,
    "77777777-7777-4777-8777-777777777777",
  )
  assert.equal(updated.mutation.object.revision, 2)
  assert.equal(updated.mutation.precondition.condition, "match")
  if (updated.mutation.precondition.condition === "match") {
    assert.equal(updated.mutation.precondition.revision, 1)
    assert.equal(updated.mutation.precondition.ciphertext_sha256.length, 32)
  }
})

test("prepares restart-time updates directly from an accepted baseline", async () => {
  const baseline = (await prepareVaultItemMutation(item(), null, scope, OPERATION_ID))
    .mutation.object
  const updated = await prepareVaultItemMutationFromBaseline(
    item(2),
    baseline,
    scope,
    "77777777-7777-4777-8777-777777777777",
  )
  assert.deepEqual(updated.mutation.precondition, {
    condition: "match",
    revision: baseline.revision,
    ciphertext_sha256: baseline.ciphertext_sha256,
  })
  await assert.rejects(
    prepareVaultItemMutationFromBaseline(item(), baseline, scope, OPERATION_ID),
    /must advance/,
  )
})

test("pulled items are bound to the verified opaque header", async () => {
  const prepared = await prepareVaultItemMutation(item(), null, scope, OPERATION_ID)
  const decoded = await decodePulledVaultItem(
    { object: prepared.mutation.object, change_seq: 1, etag: "item-1" },
    prepared.ciphertext,
  )
  assert.deepEqual(decoded.encryptedItem, item())

  await assert.rejects(
    decodePulledVaultItem(
      {
        object: { ...prepared.mutation.object, revision: 2 },
        change_seq: 1,
        etag: "item-2",
      },
      prepared.ciphertext,
    ),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "ciphertext_mismatch",
  )
})

test("item codec rejects unknown fields, bad crypto metadata, and identity changes", async () => {
  assert.throws(
    () => parseEncryptedVaultItem({ ...item(), plaintext: "secret" }),
    SyncClientError,
  )
  assert.throws(
    () => parseEncryptedVaultItem({ ...item(), key_nonce: [1, 2, 3] }),
    SyncClientError,
  )
  assert.throws(
    () => parseEncryptedVaultItem({ ...item(), algorithm: "aes-gcm" }),
    SyncClientError,
  )
  await assert.rejects(
    prepareVaultItemMutation(
      item(2),
      { ...item(1), object_id: "88888888-8888-4888-8888-888888888888" },
      scope,
      OPERATION_ID,
    ),
    /cannot change its object ID/,
  )
})

test("download validation rejects non-item objects and modified bodies", async () => {
  const prepared = await prepareVaultItemMutation(item(), null, scope, OPERATION_ID)
  await assert.rejects(
    decodePulledVaultItem(
      {
        object: { ...prepared.mutation.object, class: "activity" },
        change_seq: 1,
        etag: "wrong-class",
      },
      prepared.ciphertext,
    ),
    /not a vault item/,
  )
  const changed = Uint8Array.from(prepared.ciphertext)
  changed[changed.length - 2] ^= 1
  await assert.rejects(
    decodePulledVaultItem(
      { object: prepared.mutation.object, change_seq: 1, etag: "changed" },
      changed,
    ),
    (error: unknown) =>
      error instanceof SyncClientError && error.code === "ciphertext_mismatch",
  )
})

async function pulled(next: EncryptedVaultItemV1) {
  const prepared = await prepareVaultItemMutation(next, null, scope, OPERATION_ID)
  return decodePulledVaultItem(
    { object: prepared.mutation.object, change_seq: next.revision, etag: `item-${next.revision}` },
    prepared.ciphertext,
  )
}

test("three-way reconciliation fast-forwards only an unchanged local baseline", async () => {
  const first = await pulled(item(1))
  const second = await pulled(item(2))

  const bootstrap = await reconcilePulledVaultItem(null, null, first)
  assert.equal(bootstrap.action, "apply_remote")

  const fastForward = await reconcilePulledVaultItem(item(1), first.metadata.object, second)
  assert.equal(fastForward.action, "apply_remote")
  if (fastForward.action === "apply_remote") {
    assert.equal(fastForward.item.revision, 2)
    assert.equal(fastForward.baseline.revision, 2)
  }

  const replay = await reconcilePulledVaultItem(item(2), second.metadata.object, second)
  assert.equal(replay.action, "unchanged")
})

test("three-way reconciliation preserves local-ahead and concurrent ciphertext", async () => {
  const baseline = await pulled(item(1))
  const remote = await pulled({ ...item(2), ciphertext: [9, 8, 7, 20] })
  const local = { ...item(2), ciphertext: [9, 8, 7, 21] }

  const localAhead = await reconcilePulledVaultItem(local, baseline.metadata.object, baseline)
  assert.equal(localAhead.action, "keep_local")

  const conflict = await reconcilePulledVaultItem(local, baseline.metadata.object, remote)
  assert.equal(conflict.action, "conflict")
  if (conflict.action === "conflict") {
    assert.deepEqual(conflict.local, local)
    assert.deepEqual(conflict.remote, remote.encryptedItem)
    assert.equal(conflict.baseline?.revision, 1)
  }

  const unknownAncestry = await reconcilePulledVaultItem(local, null, remote)
  assert.equal(unknownAncestry.action, "conflict")
})

test("three-way reconciliation rejects baseline rollback, substitution, and scope moves", async () => {
  const first = await pulled(item(1))
  const second = await pulled(item(2))

  await assert.rejects(
    reconcilePulledVaultItem(item(2), second.metadata.object, first),
    /predates its accepted server baseline/,
  )
  await assert.rejects(
    reconcilePulledVaultItem(
      item(1),
      { ...first.metadata.object, ciphertext_sha256: Array(32).fill(0) },
      first,
    ),
    /substituted a vault item/,
  )
  await assert.rejects(
    reconcilePulledVaultItem(
      item(1),
      {
        ...first.metadata.object,
        scope: { ...scope, space_id: "99999999-9999-4999-8999-999999999999" },
      },
      second,
    ),
    /changed an existing vault item's sync scope/,
  )
})
