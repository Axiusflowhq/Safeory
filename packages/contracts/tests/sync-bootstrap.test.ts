import assert from "node:assert/strict"
import test from "node:test"

import {
  BrowserSingleOwnerSyncBootstrap,
  createSingleOwnerMigration,
  type SingleOwnerSyncBootstrapState,
  type SingleOwnerSyncBootstrapStore,
} from "../src/sync-bootstrap"
import type { HouseholdTopologyV1 } from "../src/sync-domain"

const API_URL = "https://sync.example.test"
const ACCOUNT_ID = "11111111-1111-4111-8111-111111111111"
const DEVICE_ID = "22222222-2222-4222-8222-222222222222"
const ITEM_ID = "33333333-3333-4333-8333-333333333333"
const IDS = [
  "44444444-4444-4444-8444-444444444444",
  "55555555-5555-4555-8555-555555555555",
  "66666666-6666-4666-8666-666666666666",
  "77777777-7777-4777-8777-777777777777",
  "88888888-8888-4888-8888-888888888888",
  "99999999-9999-4999-8999-999999999999",
]

class MemoryStore implements SingleOwnerSyncBootstrapStore {
  state: SingleOwnerSyncBootstrapState | null = null
  failNextMark = false

  async load(): Promise<SingleOwnerSyncBootstrapState | null> {
    return this.state === null ? null : structuredClone(this.state)
  }

  async create(
    _key: string,
    state: SingleOwnerSyncBootstrapState,
  ): Promise<SingleOwnerSyncBootstrapState> {
    this.state ??= structuredClone(state)
    return structuredClone(this.state)
  }

  async markPublished(
    _key: string,
    expectedVersion: number,
  ): Promise<SingleOwnerSyncBootstrapState> {
    if (this.failNextMark) {
      this.failNextMark = false
      throw new Error("bootstrap disk unavailable")
    }
    if (this.state === null || this.state.version !== expectedVersion) {
      throw new Error("bootstrap changed")
    }
    this.state = {
      ...this.state,
      version: expectedVersion + 1,
      publication: "published",
    }
    return structuredClone(this.state)
  }
}

function uuidSequence(): () => string {
  let index = 0
  return () => {
    const value = IDS[index]
    if (value === undefined) throw new Error("UUID sequence exhausted")
    index += 1
    return value
  }
}

test("single-owner migration binds existing ciphertext IDs to one private space", () => {
  const migration = createSingleOwnerMigration(
    ACCOUNT_ID,
    DEVICE_ID,
    [ITEM_ID],
    uuidSequence(),
  )
  assert.equal(migration.topology.accounts[0]?.account_id, ACCOUNT_ID)
  assert.deepEqual(migration.topology.accounts[0]?.device_ids, [DEVICE_ID])
  assert.equal(migration.topology.memberships[0]?.role, "owner")
  assert.equal(migration.topology.spaces[0]?.kind, "private")
  assert.equal(migration.topology.space_members[0]?.access, "manage")
  assert.deepEqual(migration.object_assignments, [
    { object_id: ITEM_ID, space_id: migration.private_space_id },
  ])
})

test("bootstrap persists identifiers before publication and reuses the draft", async () => {
  const store = new MemoryStore()
  const bootstrap = new BrowserSingleOwnerSyncBootstrap(
    API_URL,
    ACCOUNT_ID,
    DEVICE_ID,
    store,
  )
  const draft = await bootstrap.prepare([ITEM_ID], uuidSequence())
  const reloaded = await bootstrap.prepare(
    [ITEM_ID],
    () => assert.fail("persisted bootstrap must not regenerate IDs"),
  )
  assert.deepEqual(reloaded, draft)
  assert.equal(draft.publication, "draft")
  assert.deepEqual(bootstrap.scope(draft), {
    scope: "space",
    account_id: ACCOUNT_ID,
    household_id: draft.migration.topology.household.household_id,
    space_id: draft.migration.private_space_id,
  })
})

test("publication retries the identical topology after network and disk interruption", async () => {
  const store = new MemoryStore()
  const bootstrap = new BrowserSingleOwnerSyncBootstrap(
    API_URL,
    ACCOUNT_ID,
    DEVICE_ID,
    store,
  )
  const published: HouseholdTopologyV1[] = []
  let failNetwork = true
  const publisher = {
    accountId: ACCOUNT_ID,
    deviceId: DEVICE_ID,
    async putHouseholdTopology(topology: HouseholdTopologyV1): Promise<void> {
      published.push(structuredClone(topology))
      if (failNetwork) {
        failNetwork = false
        throw new Error("network unavailable")
      }
    },
  }

  await assert.rejects(
    bootstrap.publish(publisher, [ITEM_ID], uuidSequence()),
    /network unavailable/,
  )
  assert.equal(store.state?.publication, "draft")

  store.failNextMark = true
  await assert.rejects(
    bootstrap.publish(publisher, [ITEM_ID], uuidSequence()),
    /bootstrap disk unavailable/,
  )
  assert.equal(store.state?.publication, "draft")

  const completed = await bootstrap.publish(publisher, [ITEM_ID], uuidSequence())
  assert.equal(completed.publication, "published")
  assert.equal(published.length, 3)
  assert.deepEqual(published[0], published[1])
  assert.deepEqual(published[1], published[2])
})

test("bootstrap rejects duplicate objects, identifier exhaustion, and publisher substitution", async () => {
  assert.throws(
    () => createSingleOwnerMigration(ACCOUNT_ID, DEVICE_ID, [ITEM_ID, ITEM_ID]),
    /duplicate/,
  )
  assert.throws(
    () => createSingleOwnerMigration(ACCOUNT_ID, DEVICE_ID, [ACCOUNT_ID]),
    /reserved account bootstrap/,
  )
  assert.throws(
    () => createSingleOwnerMigration(ACCOUNT_ID, DEVICE_ID, [], () => ACCOUNT_ID),
    /Unable to generate/,
  )

  const bootstrap = new BrowserSingleOwnerSyncBootstrap(
    API_URL,
    ACCOUNT_ID,
    DEVICE_ID,
    new MemoryStore(),
  )
  await assert.rejects(
    bootstrap.publish(
      {
        accountId: ACCOUNT_ID,
        deviceId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        async putHouseholdTopology() {},
      },
      [],
      uuidSequence(),
    ),
    /does not match/,
  )
})
