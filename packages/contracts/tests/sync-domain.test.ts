import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import test from "node:test"

import { SyncClientError } from "../src/sync-client"
import {
  canDeviceAccessScope,
  parseHouseholdTopology,
  parseSingleOwnerMigration,
  type HouseholdTopologyV1,
  type SingleOwnerMigrationV1,
} from "../src/sync-domain"

const ACCOUNT = "11111111-1111-4111-8111-111111111111"
const HOUSEHOLD = "22222222-2222-4222-8222-222222222222"
const MEMBERSHIP = "33333333-3333-4333-8333-333333333333"
const DEVICE = "44444444-4444-4444-8444-444444444444"
const SPACE = "55555555-5555-4555-8555-555555555555"
const PROFILE = "66666666-6666-4666-8666-666666666666"
const MANIFEST = "77777777-7777-4777-8777-777777777777"
const ENVELOPE = "88888888-8888-4888-8888-888888888888"
const ITEM = "99999999-9999-4999-8999-999999999999"
const SECOND_MEMBERSHIP = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

function topology(): HouseholdTopologyV1 {
  return {
    format_version: 1,
    accounts: [
      {
        format_version: 1,
        account_id: ACCOUNT,
        household_ids: [HOUSEHOLD],
        device_ids: [DEVICE],
      },
    ],
    household: {
      format_version: 1,
      household_id: HOUSEHOLD,
      encrypted_profile_object_id: PROFILE,
      membership_ids: [MEMBERSHIP],
      space_ids: [SPACE],
      revision: 0,
    },
    memberships: [
      {
        format_version: 1,
        membership_id: MEMBERSHIP,
        account_id: ACCOUNT,
        household_id: HOUSEHOLD,
        role: "owner",
        state: "active",
        revision: 0,
      },
    ],
    spaces: [
      {
        format_version: 1,
        space_id: SPACE,
        household_id: HOUSEHOLD,
        kind: "private",
        encrypted_manifest_object_id: MANIFEST,
        key_generation: 1,
        revision: 0,
      },
    ],
    space_members: [
      {
        format_version: 1,
        space_id: SPACE,
        membership_id: MEMBERSHIP,
        access: "manage",
        envelope_object_id: ENVELOPE,
        device_id: DEVICE,
        key_generation: 1,
        revision: 0,
      },
    ],
  }
}

function migration(): SingleOwnerMigrationV1 {
  return {
    format_version: 1,
    topology: topology(),
    private_space_id: SPACE,
    object_assignments: [{ object_id: ITEM, space_id: SPACE }],
  }
}

function retainSeparateOwner(value: HouseholdTopologyV1): void {
  value.household.membership_ids.push(SECOND_MEMBERSHIP)
  value.memberships.push({
    format_version: 1,
    membership_id: SECOND_MEMBERSHIP,
    account_id: ACCOUNT,
    household_id: HOUSEHOLD,
    role: "owner",
    state: "active",
    revision: 0,
  })
}

test("browser parser accepts the shared canonical Rust topology fixture", () => {
  const fixturePath = resolve(
    process.cwd(),
    "../../crates/vault-sync/fixtures/household_topology_v1.json",
  )
  const fixture: unknown = JSON.parse(readFileSync(fixturePath, "utf8"))

  assert.deepEqual(parseHouseholdTopology(fixture), fixture)
})

test("browser domain parser accepts the canonical single-owner topology", () => {
  assert.deepEqual(parseHouseholdTopology(topology()), topology())
  assert.deepEqual(parseSingleOwnerMigration(migration()), migration())
})

test("domain contracts reject unknown fields, versions, duplicates, and unsafe integers", () => {
  const valid = migration()
  assert.throws(
    () => parseSingleOwnerMigration({ ...valid, future_required_field: true }),
    SyncClientError,
  )
  assert.throws(
    () => parseSingleOwnerMigration({ ...valid, format_version: 2 }),
    SyncClientError,
  )
  assert.throws(
    () =>
      parseSingleOwnerMigration({
        ...valid,
        object_assignments: [
          { object_id: ITEM, space_id: SPACE },
          { object_id: ITEM, space_id: SPACE },
        ],
      }),
    SyncClientError,
  )
  assert.throws(
    () =>
      parseHouseholdTopology({
        ...topology(),
        household: { ...topology().household, revision: Number.MAX_SAFE_INTEGER + 1 },
      }),
    SyncClientError,
  )
})

test("topology validation rejects broken references and generation bindings", () => {
  const wrongAccount = topology()
  wrongAccount.memberships[0]!.account_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  assert.throws(() => parseHouseholdTopology(wrongAccount), /inconsistent account/)

  const wrongGeneration = topology()
  wrongGeneration.spaces[0]!.key_generation = 2
  assert.throws(() => parseHouseholdTopology(wrongGeneration), /generation/)

  const missingOwner = topology()
  missingOwner.memberships[0]!.state = "revoked"
  assert.throws(() => parseHouseholdTopology(missingOwner), /active owner/)
})

test("private spaces and role access fail closed", () => {
  const noPrivateReader = topology()
  noPrivateReader.space_members = []
  assert.throws(() => parseHouseholdTopology(noPrivateReader), /exactly one membership/)

  const memberManager = topology()
  retainSeparateOwner(memberManager)
  memberManager.memberships[0]!.role = "member"
  assert.throws(() => parseHouseholdTopology(memberManager), /does not permit/)

  const legacyReader = topology()
  retainSeparateOwner(legacyReader)
  legacyReader.memberships[0]!.role = "legacy_collaborator"
  legacyReader.space_members[0]!.access = "read"
  assert.throws(() => parseHouseholdTopology(legacyReader), /does not permit/)
})

test("migration assignments cannot escape the private space or reuse metadata IDs", () => {
  const wrongSpace = migration()
  wrongSpace.object_assignments[0]!.space_id = HOUSEHOLD
  assert.throws(() => parseSingleOwnerMigration(wrongSpace), /assignment/)

  const metadataCollision = migration()
  metadataCollision.object_assignments[0]!.object_id = PROFILE
  assert.throws(() => parseSingleOwnerMigration(metadataCollision), /conflicts/)
})

test("scope authorization binds the authenticated account and device", () => {
  const valid = topology()
  assert.equal(
    canDeviceAccessScope(
      valid,
      ACCOUNT,
      DEVICE,
      { scope: "account", account_id: ACCOUNT },
      "write",
    ),
    true,
  )
  assert.equal(
    canDeviceAccessScope(
      valid,
      ACCOUNT,
      DEVICE,
      { scope: "household", account_id: ACCOUNT, household_id: HOUSEHOLD },
      "manage",
    ),
    true,
  )
  assert.equal(
    canDeviceAccessScope(
      valid,
      ACCOUNT,
      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      { scope: "space", account_id: ACCOUNT, household_id: HOUSEHOLD, space_id: SPACE },
      "read",
    ),
    false,
  )
  assert.equal(
    canDeviceAccessScope(
      valid,
      ACCOUNT,
      DEVICE,
      {
        scope: "space",
        account_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        household_id: HOUSEHOLD,
        space_id: SPACE,
      },
      "read",
    ),
    false,
  )
})

test("scope authorization separates read, write, and manage access", () => {
  const valid = topology()
  const scope = {
    scope: "space",
    account_id: ACCOUNT,
    household_id: HOUSEHOLD,
    space_id: SPACE,
  }
  valid.space_members[0]!.access = "read"
  assert.equal(canDeviceAccessScope(valid, ACCOUNT, DEVICE, scope, "read"), true)
  assert.equal(canDeviceAccessScope(valid, ACCOUNT, DEVICE, scope, "write"), false)

  valid.space_members[0]!.access = "edit"
  assert.equal(canDeviceAccessScope(valid, ACCOUNT, DEVICE, scope, "write"), true)
  assert.equal(canDeviceAccessScope(valid, ACCOUNT, DEVICE, scope, "manage"), false)

  valid.space_members[0]!.access = "manage"
  assert.equal(canDeviceAccessScope(valid, ACCOUNT, DEVICE, scope, "manage"), true)
})
