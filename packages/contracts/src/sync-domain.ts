import type { ObjectScopeV1 } from "./sync-client"
import { SyncClientError } from "./sync-error"

const DOMAIN_FORMAT_VERSION = 1
const MAX_HOUSEHOLDS_PER_ACCOUNT = 32
const MAX_DEVICES_PER_ACCOUNT = 64
const MAX_ACCOUNTS_PER_HOUSEHOLD = 256
const MAX_MEMBERSHIPS_PER_HOUSEHOLD = 256
const MAX_SPACES_PER_HOUSEHOLD = 256
const MAX_SPACE_MEMBERS = 256
const MAX_MIGRATED_OBJECTS = 100_000
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const NIL_UUID = "00000000-0000-0000-0000-000000000000"

export const MEMBERSHIP_ROLES = [
  "owner",
  "organizer",
  "member",
  "full_collaborator",
  "partial_collaborator",
  "legacy_collaborator",
] as const
export const MEMBERSHIP_STATES = ["invited", "active", "revoked"] as const
export const SPACE_KINDS = ["private", "shared", "purpose"] as const
export const SPACE_ACCESS_LEVELS = ["read", "edit", "manage"] as const
export const TOPOLOGY_ACTIONS = ["read", "write", "manage"] as const

export type MembershipRoleV1 = (typeof MEMBERSHIP_ROLES)[number]
export type MembershipStateV1 = (typeof MEMBERSHIP_STATES)[number]
export type SpaceKindV1 = (typeof SPACE_KINDS)[number]
export type SpaceAccessV1 = (typeof SPACE_ACCESS_LEVELS)[number]
export type TopologyActionV1 = (typeof TOPOLOGY_ACTIONS)[number]

export interface AccountV1 {
  format_version: number
  account_id: string
  household_ids: string[]
  device_ids: string[]
}

export interface HouseholdV1 {
  format_version: number
  household_id: string
  encrypted_profile_object_id: string
  membership_ids: string[]
  space_ids: string[]
  revision: number
}

export interface MembershipV1 {
  format_version: number
  membership_id: string
  account_id: string
  household_id: string
  role: MembershipRoleV1
  state: MembershipStateV1
  revision: number
}

export interface SpaceV1 {
  format_version: number
  space_id: string
  household_id: string
  kind: SpaceKindV1
  encrypted_manifest_object_id: string
  key_generation: number
  revision: number
}

export interface SpaceMemberV1 {
  format_version: number
  space_id: string
  membership_id: string
  access: SpaceAccessV1
  envelope_object_id: string
  device_id: string
  key_generation: number
  revision: number
}

export interface HouseholdTopologyV1 {
  format_version: number
  accounts: AccountV1[]
  household: HouseholdV1
  memberships: MembershipV1[]
  spaces: SpaceV1[]
  space_members: SpaceMemberV1[]
}

export interface ObjectSpaceAssignmentV1 {
  object_id: string
  space_id: string
}

export interface SingleOwnerMigrationV1 {
  format_version: number
  topology: HouseholdTopologyV1
  private_space_id: string
  object_assignments: ObjectSpaceAssignmentV1[]
}

export function parseHouseholdTopology(value: unknown): HouseholdTopologyV1 {
  const record = exactRecord(value, [
    "format_version",
    "accounts",
    "household",
    "memberships",
    "spaces",
    "space_members",
  ])
  version(record.format_version)
  const accounts = boundedArray(record.accounts, MAX_ACCOUNTS_PER_HOUSEHOLD, "accounts").map(
    parseAccount,
  )
  const household = parseHousehold(record.household)
  const memberships = boundedArray(
    record.memberships,
    MAX_MEMBERSHIPS_PER_HOUSEHOLD,
    "memberships",
  ).map(parseMembership)
  const spaces = boundedArray(record.spaces, MAX_SPACES_PER_HOUSEHOLD, "spaces").map(
    parseSpace,
  )
  const spaceMembers = boundedArray(
    record.space_members,
    MAX_SPACE_MEMBERS,
    "space members",
  ).map(parseSpaceMember)

  if (accounts.length === 0) invalid("A household must contain an account.")
  unique(accounts.map((account) => account.account_id), "account IDs")
  unique(memberships.map((membership) => membership.membership_id), "membership IDs")
  unique(spaces.map((space) => space.space_id), "space IDs")
  unique(
    spaceMembers.map((member) => `${member.space_id}:${member.device_id}`),
    "space/device memberships",
  )
  unique(
    [
      household.encrypted_profile_object_id,
      ...spaces.map((space) => space.encrypted_manifest_object_id),
      ...spaceMembers.map((member) => member.envelope_object_id),
    ],
    "topology object IDs",
  )

  const deviceAccounts = new Map<string, string>()
  for (const account of accounts) {
    if (!account.household_ids.includes(household.household_id)) {
      invalid("An account does not reference the topology household.")
    }
    for (const deviceId of account.device_ids) {
      if (deviceAccounts.has(deviceId)) invalid("A device belongs to multiple accounts.")
      deviceAccounts.set(deviceId, account.account_id)
    }
  }

  sameSet(household.membership_ids, memberships.map((value) => value.membership_id), "memberships")
  sameSet(household.space_ids, spaces.map((value) => value.space_id), "spaces")
  if (
    !memberships.some(
      (membership) => membership.role === "owner" && membership.state === "active",
    )
  ) {
    invalid("A household must retain at least one active owner.")
  }

  const accountsById = new Map(accounts.map((account) => [account.account_id, account]))
  const membershipsById = new Map(
    memberships.map((membership) => [membership.membership_id, membership]),
  )
  const spacesById = new Map(spaces.map((space) => [space.space_id, space]))
  for (const membership of memberships) {
    if (
      !accountsById.has(membership.account_id) ||
      membership.household_id !== household.household_id
    ) {
      invalid("A membership has an inconsistent account or household reference.")
    }
  }
  for (const space of spaces) {
    if (space.household_id !== household.household_id) {
      invalid("A space has an inconsistent household reference.")
    }
  }
  for (const member of spaceMembers) {
    const membership = membershipsById.get(member.membership_id)
    const space = spacesById.get(member.space_id)
    if (
      membership === undefined ||
      space === undefined ||
      membership.state !== "active" ||
      deviceAccounts.get(member.device_id) !== membership.account_id ||
      member.key_generation !== space.key_generation
    ) {
      invalid("A space member has an inconsistent membership, device, or generation.")
    }
    if (
      membership.role === "legacy_collaborator" ||
      (member.access === "manage" &&
        membership.role !== "owner" &&
        membership.role !== "organizer")
    ) {
      invalid("The membership role does not permit the requested space access.")
    }
  }
  for (const space of spaces.filter((candidate) => candidate.kind === "private")) {
    const readableMemberships = new Set(
      spaceMembers
        .filter((member) => member.space_id === space.space_id)
        .map((member) => member.membership_id),
    )
    if (readableMemberships.size !== 1) {
      invalid("A private space must be readable by exactly one membership.")
    }
  }

  return {
    format_version: DOMAIN_FORMAT_VERSION,
    accounts,
    household,
    memberships,
    spaces,
    space_members: spaceMembers,
  }
}

export function parseSingleOwnerMigration(value: unknown): SingleOwnerMigrationV1 {
  const record = exactRecord(value, [
    "format_version",
    "topology",
    "private_space_id",
    "object_assignments",
  ])
  version(record.format_version)
  const topology = parseHouseholdTopology(record.topology)
  const privateSpaceId = uuid(record.private_space_id, "private space ID")
  const assignments = boundedArray(
    record.object_assignments,
    MAX_MIGRATED_OBJECTS,
    "migrated objects",
  ).map(parseAssignment)
  unique(assignments.map((assignment) => assignment.object_id), "migrated object IDs")

  const topologyObjectIds = new Set([
    topology.household.encrypted_profile_object_id,
    ...topology.spaces.map((space) => space.encrypted_manifest_object_id),
    ...topology.space_members.map((member) => member.envelope_object_id),
  ])
  if (assignments.some((assignment) => topologyObjectIds.has(assignment.object_id))) {
    invalid("A migrated object ID conflicts with topology metadata.")
  }
  const privateSpace = topology.spaces.find((space) => space.space_id === privateSpaceId)
  if (
    privateSpace?.kind !== "private" ||
    assignments.some((assignment) => assignment.space_id !== privateSpaceId)
  ) {
    invalid("The migration private-space assignment is inconsistent.")
  }
  return {
    format_version: DOMAIN_FORMAT_VERSION,
    topology,
    private_space_id: privateSpaceId,
    object_assignments: assignments,
  }
}

/**
 * Evaluates server-visible routing authorization. Returning true never implies
 * that the device possesses the client-side key needed to decrypt the object.
 */
export function canDeviceAccessScope(
  topologyValue: unknown,
  accountIdValue: unknown,
  deviceIdValue: unknown,
  scopeValue: unknown,
  actionValue: unknown,
): boolean {
  const topology = parseHouseholdTopology(topologyValue)
  const accountId = uuid(accountIdValue, "authorized account ID")
  const deviceId = uuid(deviceIdValue, "authorized device ID")
  const scope = parseObjectScope(scopeValue)
  const action = enumValue(actionValue, TOPOLOGY_ACTIONS, "topology action")
  const account = topology.accounts.find((candidate) => candidate.account_id === accountId)
  if (
    account === undefined ||
    !account.device_ids.includes(deviceId) ||
    scope.account_id !== accountId
  ) {
    return false
  }
  if (scope.scope === "account") return true
  if (scope.household_id !== topology.household.household_id) return false

  if (scope.scope === "household") {
    return topology.memberships.some(
      (membership) =>
        membership.account_id === accountId &&
        membership.household_id === scope.household_id &&
        membership.state === "active" &&
        (action === "read"
          ? membership.role !== "legacy_collaborator"
          : membership.role === "owner" || membership.role === "organizer"),
    )
  }

  return topology.space_members.some((spaceMember) => {
    if (spaceMember.space_id !== scope.space_id || spaceMember.device_id !== deviceId) {
      return false
    }
    const membership = topology.memberships.find(
      (candidate) => candidate.membership_id === spaceMember.membership_id,
    )
    if (
      membership?.account_id !== accountId ||
      membership.state !== "active"
    ) {
      return false
    }
    if (action === "read") return true
    if (action === "write") return spaceMember.access !== "read"
    return spaceMember.access === "manage"
  })
}

function parseAccount(value: unknown): AccountV1 {
  const record = exactRecord(value, [
    "format_version",
    "account_id",
    "household_ids",
    "device_ids",
  ])
  version(record.format_version)
  const householdIds = uuidArray(record.household_ids, MAX_HOUSEHOLDS_PER_ACCOUNT, "households")
  const deviceIds = uuidArray(record.device_ids, MAX_DEVICES_PER_ACCOUNT, "devices")
  if (householdIds.length === 0 || deviceIds.length === 0) {
    invalid("An account must contain a household and a device.")
  }
  return {
    format_version: DOMAIN_FORMAT_VERSION,
    account_id: uuid(record.account_id, "account ID"),
    household_ids: householdIds,
    device_ids: deviceIds,
  }
}

function parseHousehold(value: unknown): HouseholdV1 {
  const record = exactRecord(value, [
    "format_version",
    "household_id",
    "encrypted_profile_object_id",
    "membership_ids",
    "space_ids",
    "revision",
  ])
  version(record.format_version)
  const membershipIds = uuidArray(
    record.membership_ids,
    MAX_MEMBERSHIPS_PER_HOUSEHOLD,
    "memberships",
  )
  const spaceIds = uuidArray(record.space_ids, MAX_SPACES_PER_HOUSEHOLD, "spaces")
  if (membershipIds.length === 0 || spaceIds.length === 0) {
    invalid("A household must contain a membership and a space.")
  }
  return {
    format_version: DOMAIN_FORMAT_VERSION,
    household_id: uuid(record.household_id, "household ID"),
    encrypted_profile_object_id: uuid(
      record.encrypted_profile_object_id,
      "encrypted profile object ID",
    ),
    membership_ids: membershipIds,
    space_ids: spaceIds,
    revision: wireInteger(record.revision, "household revision"),
  }
}

function parseMembership(value: unknown): MembershipV1 {
  const record = exactRecord(value, [
    "format_version",
    "membership_id",
    "account_id",
    "household_id",
    "role",
    "state",
    "revision",
  ])
  version(record.format_version)
  return {
    format_version: DOMAIN_FORMAT_VERSION,
    membership_id: uuid(record.membership_id, "membership ID"),
    account_id: uuid(record.account_id, "membership account ID"),
    household_id: uuid(record.household_id, "membership household ID"),
    role: enumValue(record.role, MEMBERSHIP_ROLES, "membership role"),
    state: enumValue(record.state, MEMBERSHIP_STATES, "membership state"),
    revision: wireInteger(record.revision, "membership revision"),
  }
}

function parseSpace(value: unknown): SpaceV1 {
  const record = exactRecord(value, [
    "format_version",
    "space_id",
    "household_id",
    "kind",
    "encrypted_manifest_object_id",
    "key_generation",
    "revision",
  ])
  version(record.format_version)
  const keyGeneration = wireInteger(record.key_generation, "space key generation")
  if (keyGeneration === 0) invalid("Space key generation zero is reserved.")
  return {
    format_version: DOMAIN_FORMAT_VERSION,
    space_id: uuid(record.space_id, "space ID"),
    household_id: uuid(record.household_id, "space household ID"),
    kind: enumValue(record.kind, SPACE_KINDS, "space kind"),
    encrypted_manifest_object_id: uuid(
      record.encrypted_manifest_object_id,
      "encrypted manifest object ID",
    ),
    key_generation: keyGeneration,
    revision: wireInteger(record.revision, "space revision"),
  }
}

function parseSpaceMember(value: unknown): SpaceMemberV1 {
  const record = exactRecord(value, [
    "format_version",
    "space_id",
    "membership_id",
    "access",
    "envelope_object_id",
    "device_id",
    "key_generation",
    "revision",
  ])
  version(record.format_version)
  const keyGeneration = wireInteger(record.key_generation, "space-member key generation")
  if (keyGeneration === 0) invalid("Space-member key generation zero is reserved.")
  return {
    format_version: DOMAIN_FORMAT_VERSION,
    space_id: uuid(record.space_id, "space-member space ID"),
    membership_id: uuid(record.membership_id, "space-member membership ID"),
    access: enumValue(record.access, SPACE_ACCESS_LEVELS, "space access"),
    envelope_object_id: uuid(record.envelope_object_id, "space-key envelope object ID"),
    device_id: uuid(record.device_id, "space-member device ID"),
    key_generation: keyGeneration,
    revision: wireInteger(record.revision, "space-member revision"),
  }
}

function parseAssignment(value: unknown): ObjectSpaceAssignmentV1 {
  const record = exactRecord(value, ["object_id", "space_id"])
  return {
    object_id: uuid(record.object_id, "migrated object ID"),
    space_id: uuid(record.space_id, "migration space ID"),
  }
}

function parseObjectScope(value: unknown): ObjectScopeV1 {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return invalid("The authorization scope is invalid.")
  }
  const scope = (value as Record<string, unknown>).scope
  if (scope === "account") {
    const record = exactRecord(value, ["scope", "account_id"])
    return { scope, account_id: uuid(record.account_id, "scope account ID") }
  }
  if (scope === "household") {
    const record = exactRecord(value, ["scope", "account_id", "household_id"])
    return {
      scope,
      account_id: uuid(record.account_id, "scope account ID"),
      household_id: uuid(record.household_id, "scope household ID"),
    }
  }
  if (scope === "space") {
    const record = exactRecord(value, ["scope", "account_id", "household_id", "space_id"])
    return {
      scope,
      account_id: uuid(record.account_id, "scope account ID"),
      household_id: uuid(record.household_id, "scope household ID"),
      space_id: uuid(record.space_id, "scope space ID"),
    }
  }
  return invalid("The authorization scope is unsupported.")
}

function uuidArray(value: unknown, maximum: number, label: string): string[] {
  const values = boundedArray(value, maximum, label).map((entry) => uuid(entry, `${label} ID`))
  unique(values, `${label} IDs`)
  return values
}

function boundedArray(value: unknown, maximum: number, label: string): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) {
    return invalid(`The ${label} collection is invalid or too large.`)
  }
  return value
}

function sameSet(left: string[], right: string[], label: string): void {
  if (left.length !== right.length || left.some((value) => !right.includes(value))) {
    invalid(`The household ${label} references are inconsistent.`)
  }
}

function unique(values: string[], label: string): void {
  if (new Set(values).size !== values.length) invalid(`The ${label} contain a duplicate.`)
}

function enumValue<const T extends readonly string[]>(
  value: unknown,
  values: T,
  label: string,
): T[number] {
  if (typeof value !== "string" || !values.includes(value)) {
    return invalid(`The ${label} is unsupported.`)
  }
  return value as T[number]
}

function version(value: unknown): void {
  if (value !== DOMAIN_FORMAT_VERSION) invalid("The sync domain format is unsupported.")
}

function uuid(value: unknown, label: string): string {
  if (typeof value !== "string" || !UUID.test(value) || value.toLowerCase() === NIL_UUID) {
    return invalid(`The ${label} must be a non-nil UUID.`)
  }
  return value.toLowerCase()
}

function wireInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    return invalid(`The ${label} is outside the exact browser integer range.`)
  }
  return value as number
}

function exactRecord(value: unknown, expectedKeys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return invalid("The sync domain contract has an invalid shape.")
  }
  const record = value as Record<string, unknown>
  const actual = Object.keys(record).sort()
  const expected = [...expectedKeys].sort()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    return invalid("The sync domain contract has unknown or missing fields.")
  }
  return record
}

function invalid(message: string): never {
  throw new SyncClientError("invalid_contract", message)
}
