import {
  fetchSyncCompatibility,
  type NegotiatedCompatibility,
} from "./sync-compatibility"
import {
  parseHouseholdTopology,
  type HouseholdTopologyV1,
} from "./sync-domain"
import { SyncClientError } from "./sync-error"
import type { DeviceRegistrationV1 } from "./device-keys"

export { SyncClientError } from "./sync-error"

const SYNC_PROTOCOL_VERSION = 1
const OBJECT_HEADER_FORMAT_VERSION = 1
const OPAQUE_MUTATION_FORMAT_VERSION = 1
const MAX_VERSION = 65_535
const MAX_WIRE_INTEGER = Number.MAX_SAFE_INTEGER
const MAX_CIPHERTEXT_BYTES = 128 * 1024 * 1024
const MAX_MUTATION_HEADER_CHARS = 8 * 1024
const MAX_METADATA_RESPONSE_CHARS = 2 * 1024 * 1024
const MAX_TOPOLOGY_BYTES = 1024 * 1024
const MAX_DEVICE_CREDENTIAL_BYTES = 4 * 1024
const MAX_DEVICE_INVENTORY_BYTES = 64 * 1024
const MAX_DEVICES_PER_ACCOUNT = 64
const DEVICE_TOKEN = /^sfo_dev_v1_[0-9a-f]{64}$/
const PUBLIC_KEY_HEX = /^[0-9a-f]{64}$/i
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const NIL_UUID = "00000000-0000-0000-0000-000000000000"

export const OPAQUE_OBJECT_CLASSES = [
  "account_bootstrap",
  "device_bootstrap",
  "household_profile",
  "space_manifest",
  "space_key_envelope",
  "item",
  "attachment_manifest",
  "attachment_chunk",
  "item_history",
  "reminder",
  "activity",
  "inbox",
  "secure_link_copy",
  "recovery_capsule",
  "emergency_capsule",
  "security_event",
] as const

export type OpaqueObjectClassV1 = (typeof OPAQUE_OBJECT_CLASSES)[number]

export type ObjectScopeV1 =
  | { scope: "account"; account_id: string }
  | { scope: "household"; account_id: string; household_id: string }
  | {
      scope: "space"
      account_id: string
      household_id: string
      space_id: string
    }

export interface OpaqueObjectHeaderV1 {
  format_version: number
  protocol_version: number
  object_id: string
  class: OpaqueObjectClassV1
  scope: ObjectScopeV1
  revision: number
  payload_version: number
  envelope_version: number
  ciphertext_size_bytes: number
  ciphertext_sha256: number[]
  tombstone: boolean
}

export type WritePreconditionV1 =
  | { condition: "create_only" }
  | { condition: "match"; revision: number; ciphertext_sha256: number[] }

export interface OpaqueMutationV1 {
  format_version: number
  operation_id: string
  object: OpaqueObjectHeaderV1
  precondition: WritePreconditionV1
}

export interface SyncObjectMetadataV1 {
  object: OpaqueObjectHeaderV1
  change_seq: number
  etag: string
}

export interface SyncObjectPageV1 {
  objects: SyncObjectMetadataV1[]
  next_change_seq: number
}

export interface DeviceCredentialsV1 {
  account_id: string
  device_id: string
  device_token: string
}

export interface DeviceInventoryEntryV1 {
  device_id: string
  encryption_public_key: string | null
  signing_public_key: string | null
}

export interface DeviceInventoryV1 {
  current_device_id: string
  devices: DeviceInventoryEntryV1[]
}

export class SyncClient {
  private constructor(
    private readonly baseUrl: URL,
    readonly accountId: string,
    readonly deviceId: string | null,
    private readonly deviceToken: string,
    private readonly fetcher: typeof fetch,
    readonly compatibility: NegotiatedCompatibility,
  ) {}

  static async connect(
    apiBaseUrl: string,
    accountIdValue: string,
    deviceToken: string,
    options: {
      fetcher?: typeof fetch
      signal?: AbortSignal
      deviceId?: string
    } = {},
  ): Promise<SyncClient> {
    const baseUrl = syncBaseUrl(apiBaseUrl)
    const accountId = uuid(accountIdValue, "account ID")
    const deviceId = options.deviceId === undefined
      ? null
      : uuid(options.deviceId, "device ID")
    if (!DEVICE_TOKEN.test(deviceToken)) {
      throw new SyncClientError(
        "invalid_configuration",
        "The device credential has an invalid format.",
      )
    }
    const fetcher = options.fetcher ?? globalThis.fetch
    const compatibility = await fetchSyncCompatibility(baseUrl.href, {
      fetcher,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    })
    return new SyncClient(
      baseUrl,
      accountId,
      deviceId,
      deviceToken,
      fetcher,
      compatibility,
    )
  }

  static async createAccount(
    apiBaseUrl: string,
    registrationToken: string,
    registration: DeviceRegistrationV1,
    options: { fetcher?: typeof fetch; signal?: AbortSignal } = {},
  ): Promise<DeviceCredentialsV1> {
    const baseUrl = syncBaseUrl(apiBaseUrl)
    if (
      new TextEncoder().encode(registrationToken).byteLength < 32 ||
      /\s/.test(registrationToken)
    ) {
      throw new SyncClientError(
        "invalid_configuration",
        "The account registration credential is invalid.",
      )
    }
    const fetcher = options.fetcher ?? globalThis.fetch
    await fetchSyncCompatibility(baseUrl.href, {
      fetcher,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    })
    const payload = deviceRegistrationPayload(registration)
    const response = await performSyncRequest(fetcher, new URL("v1/accounts", baseUrl), {
      method: "POST",
      headers: authenticatedJsonHeaders(registrationToken),
      body: JSON.stringify(payload),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    })
    return parseDeviceCredentials(
      await boundedJson(response, MAX_DEVICE_CREDENTIAL_BYTES),
      payload.device_id,
    )
  }

  async createDevice(
    registration: DeviceRegistrationV1,
    options: { signal?: AbortSignal } = {},
  ): Promise<DeviceCredentialsV1> {
    const payload = deviceRegistrationPayload(registration)
    const response = await this.request(this.endpoint("v1/devices"), {
      method: "POST",
      headers: this.headers({ "Content-Type": "application/json" }),
      body: JSON.stringify(payload),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    })
    const credentials = parseDeviceCredentials(
      await boundedJson(response, MAX_DEVICE_CREDENTIAL_BYTES),
      payload.device_id,
    )
    if (credentials.account_id !== this.accountId) {
      throw new SyncClientError(
        "invalid_response",
        "The registered device response changed the authenticated account.",
      )
    }
    return credentials
  }

  async revokeDevice(
    deviceIdValue: string,
    options: { signal?: AbortSignal } = {},
  ): Promise<void> {
    const deviceId = uuid(deviceIdValue, "device ID")
    await this.request(
      this.endpoint(`v1/devices/${encodeURIComponent(deviceId)}`),
      {
        method: "DELETE",
        headers: this.headers({ Accept: "application/json" }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      },
    )
  }

  async listDevices(
    options: { signal?: AbortSignal } = {},
  ): Promise<DeviceInventoryV1> {
    const response = await this.request(this.endpoint("v1/devices"), {
      method: "GET",
      headers: this.headers({ Accept: "application/json" }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    })
    const inventory = parseDeviceInventory(
      await boundedJson(response, MAX_DEVICE_INVENTORY_BYTES),
    )
    if (this.deviceId !== null && inventory.current_device_id !== this.deviceId) {
      throw new SyncClientError(
        "invalid_response",
        "The device inventory changed the authenticated device identity.",
      )
    }
    return inventory
  }

  async listObjects(
    options: { after?: number; limit?: number; signal?: AbortSignal } = {},
  ): Promise<SyncObjectPageV1> {
    const after = wireInteger(options.after ?? 0, "after")
    const limit = options.limit ?? 100
    if (!Number.isInteger(limit) || limit < 1 || limit > 256) {
      throw new SyncClientError(
        "invalid_contract",
        "The sync page limit must be between 1 and 256.",
      )
    }
    const endpoint = this.endpoint("v1/objects")
    endpoint.searchParams.set("after", String(after))
    endpoint.searchParams.set("limit", String(limit))
    const response = await this.request(endpoint, {
      method: "GET",
      headers: this.headers({ Accept: "application/json" }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    })
    const page = parseSyncObjectPage(
      await boundedJson(response, MAX_METADATA_RESPONSE_CHARS),
    )
    if (page.next_change_seq < after) {
      throw new SyncClientError(
        "invalid_response",
        "The sync response cursor moved backwards.",
      )
    }
    if (page.objects.some((object) => object.change_seq <= after)) {
      throw new SyncClientError(
        "invalid_response",
        "The sync response repeated an acknowledged change.",
      )
    }
    for (const object of page.objects) this.requireAccount(object.object)
    return page
  }

  async getObject(
    expected: OpaqueObjectHeaderV1,
    options: { signal?: AbortSignal } = {},
  ): Promise<Uint8Array> {
    const header = parseOpaqueObjectHeader(expected)
    this.requireAccount(header)
    const response = await this.request(
      this.endpoint(`v1/objects/${encodeURIComponent(header.object_id)}`),
      {
        method: "GET",
        headers: this.headers({ Accept: "application/octet-stream" }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      },
    )
    const declaredLength = response.headers.get("content-length")
    if (
      declaredLength !== null &&
      (!/^\d+$/.test(declaredLength) || Number(declaredLength) !== header.ciphertext_size_bytes)
    ) {
      throw new SyncClientError(
        "ciphertext_mismatch",
        "The downloaded ciphertext length does not match its opaque header.",
      )
    }
    const bytes = await readExactBody(response, header.ciphertext_size_bytes)
    await verifyOpaqueCiphertext(header, bytes)
    return bytes
  }

  async putObject(
    mutationValue: OpaqueMutationV1,
    ciphertext: Uint8Array,
    options: { signal?: AbortSignal } = {},
  ): Promise<SyncObjectMetadataV1> {
    const mutation = parseOpaqueMutation(mutationValue)
    this.requireAccount(mutation.object)
    await verifyOpaqueCiphertext(mutation.object, ciphertext)
    const encodedMutation = JSON.stringify(mutation)
    if (encodedMutation.length > MAX_MUTATION_HEADER_CHARS) {
      throw new SyncClientError(
        "invalid_contract",
        "The opaque mutation header exceeds the transport bound.",
      )
    }
    const body = ciphertext.buffer.slice(
      ciphertext.byteOffset,
      ciphertext.byteOffset + ciphertext.byteLength,
    ) as ArrayBuffer
    const response = await this.request(
      this.endpoint(`v1/objects/${encodeURIComponent(mutation.object.object_id)}`),
      {
        method: "PUT",
        headers: this.headers({
          Accept: "application/json",
          "Content-Type": "application/octet-stream",
          "x-safeory-mutation": encodedMutation,
        }),
        body,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      },
    )
    const metadata = parseSyncObjectMetadata(
      await boundedJson(response, MAX_MUTATION_HEADER_CHARS),
    )
    this.requireAccount(metadata.object)
    if (!sameOpaqueObjectHeader(metadata.object, mutation.object)) {
      throw new SyncClientError(
        "invalid_response",
        "The sync upload response does not match the submitted opaque object.",
      )
    }
    return metadata
  }

  async getHouseholdTopology(
    householdIdValue: string,
    options: { signal?: AbortSignal } = {},
  ): Promise<HouseholdTopologyV1> {
    const householdId = uuid(householdIdValue, "household ID")
    const response = await this.request(
      this.endpoint(`v1/households/${encodeURIComponent(householdId)}/topology`),
      {
        method: "GET",
        headers: this.headers({ Accept: "application/json" }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      },
    )
    const topology = parseHouseholdTopology(
      await boundedJson(response, MAX_TOPOLOGY_BYTES),
    )
    requireTopologyAccount(topology, this.accountId)
    if (topology.household.household_id !== householdId) {
      throw new SyncClientError(
        "invalid_response",
        "The household topology does not match the requested household.",
      )
    }
    return topology
  }

  async putHouseholdTopology(
    topologyValue: HouseholdTopologyV1,
    options: { signal?: AbortSignal } = {},
  ): Promise<void> {
    const topology = parseHouseholdTopology(topologyValue)
    requireTopologyAccount(topology, this.accountId)
    const encoded = JSON.stringify(topology)
    if (new TextEncoder().encode(encoded).byteLength > MAX_TOPOLOGY_BYTES) {
      throw new SyncClientError(
        "invalid_contract",
        "The household topology exceeds the transport bound.",
      )
    }
    await this.request(
      this.endpoint(
        `v1/households/${encodeURIComponent(topology.household.household_id)}/topology`,
      ),
      {
        method: "PUT",
        headers: this.headers({
          Accept: "application/json",
          "Content-Type": "application/json",
        }),
        body: encoded,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      },
    )
  }

  private endpoint(path: string): URL {
    return new URL(path, this.baseUrl)
  }

  private requireAccount(header: OpaqueObjectHeaderV1): void {
    if (header.scope.account_id.toLowerCase() !== this.accountId.toLowerCase()) {
      throw new SyncClientError(
        "invalid_contract",
        "The opaque object scope does not match the authenticated account.",
      )
    }
  }

  private headers(values: Record<string, string>): Headers {
    return new Headers({
      ...values,
      Authorization: `Bearer ${this.deviceToken}`,
    })
  }

  private async request(endpoint: URL, init: RequestInit): Promise<Response> {
    return performSyncRequest(this.fetcher, endpoint, init)
  }
}

function authenticatedJsonHeaders(token: string): Headers {
  return new Headers({
    Accept: "application/json",
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  })
}

function deviceRegistrationPayload(registration: DeviceRegistrationV1): {
  device_id: string
  encryption_public_key: string
  signing_public_key: string
} {
  if (
    registration.format_version !== 1 ||
    !PUBLIC_KEY_HEX.test(registration.encryption_public_key_hex) ||
    !PUBLIC_KEY_HEX.test(registration.signing_public_key_hex)
  ) {
    throw new SyncClientError(
      "invalid_contract",
      "The device registration is invalid.",
    )
  }
  return {
    device_id: uuid(registration.device_id, "device ID"),
    encryption_public_key: registration.encryption_public_key_hex.toLowerCase(),
    signing_public_key: registration.signing_public_key_hex.toLowerCase(),
  }
}

function parseDeviceCredentials(
  value: unknown,
  expectedDeviceId: string,
): DeviceCredentialsV1 {
  let record: Record<string, unknown>
  try {
    record = exactRecord(value, ["account_id", "device_id", "device_token"])
  } catch {
    throw new SyncClientError(
      "invalid_response",
      "The device credentials response is invalid.",
    )
  }
  let accountId: string
  let deviceId: string
  try {
    accountId = uuid(record.account_id, "account ID")
    deviceId = uuid(record.device_id, "device ID")
  } catch {
    throw new SyncClientError(
      "invalid_response",
      "The device credentials response is invalid.",
    )
  }
  if (
    deviceId !== expectedDeviceId ||
    typeof record.device_token !== "string" ||
    !DEVICE_TOKEN.test(record.device_token)
  ) {
    throw new SyncClientError(
      "invalid_response",
      "The device credentials response is invalid.",
    )
  }
  return { account_id: accountId, device_id: deviceId, device_token: record.device_token }
}

function parseDeviceInventory(value: unknown): DeviceInventoryV1 {
  const record = responseRecord(value, ["current_device_id", "devices"], "device inventory")
  let currentDeviceId: string
  try {
    currentDeviceId = uuid(record.current_device_id, "current device ID")
  } catch {
    return invalidResponse("The device inventory response is invalid.")
  }
  if (!Array.isArray(record.devices) || record.devices.length > MAX_DEVICES_PER_ACCOUNT) {
    return invalidResponse("The device inventory response is invalid.")
  }
  const seen = new Set<string>()
  const devices = record.devices.map((value): DeviceInventoryEntryV1 => {
    const device = responseRecord(
      value,
      ["device_id", "encryption_public_key", "signing_public_key"],
      "device inventory entry",
    )
    let deviceId: string
    try {
      deviceId = uuid(device.device_id, "device ID")
    } catch {
      return invalidResponse("The device inventory response is invalid.")
    }
    if (seen.has(deviceId)) return invalidResponse("The device inventory contains a duplicate.")
    seen.add(deviceId)
    return {
      device_id: deviceId,
      encryption_public_key: nullablePublicKey(device.encryption_public_key),
      signing_public_key: nullablePublicKey(device.signing_public_key),
    }
  })
  if (!seen.has(currentDeviceId)) {
    return invalidResponse("The device inventory omits the authenticated device.")
  }
  return { current_device_id: currentDeviceId, devices }
}

function responseRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  try {
    return exactRecord(value, keys)
  } catch {
    return invalidResponse(`The ${label} response is invalid.`)
  }
}

function nullablePublicKey(value: unknown): string | null {
  if (value === null) return null
  if (typeof value !== "string" || !PUBLIC_KEY_HEX.test(value)) {
    return invalidResponse("The device inventory contains an invalid public key.")
  }
  return value.toLowerCase()
}

function invalidResponse(message: string): never {
  throw new SyncClientError("invalid_response", message)
}

async function performSyncRequest(
  fetcher: typeof fetch,
  endpoint: URL,
  init: RequestInit,
): Promise<Response> {
  let response: Response
  try {
    response = await fetcher(endpoint, {
      ...init,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
    })
  } catch {
    throw new SyncClientError("request_failed", "The sync request failed.")
  }
  if (response.ok) return response
  if (response.status === 401) {
    throw new SyncClientError("unauthorized", "The device credential was rejected.")
  }
  if (response.status === 403) {
    throw new SyncClientError("forbidden", "The device is not authorized for this scope.")
  }
  if (response.status === 404) {
    throw new SyncClientError("not_found", "The requested sync resource was not found.")
  }
  if (response.status === 409) {
    const errorCode = await responseErrorCode(response)
    if (errorCode === "last_active_device") {
      throw new SyncClientError(
        "last_active_device",
        "The account must retain at least one active device.",
      )
    }
    if (errorCode === "device_identifier_conflict") {
      throw new SyncClientError(
        "identifier_conflict",
        "The device identifier is already registered.",
      )
    }
    throw new SyncClientError(
      "operation_conflict",
      "The operation ID was already used for different input.",
    )
  }
  if (response.status === 412) {
    throw new SyncClientError(
      "precondition_failed",
      "The sync write precondition failed.",
    )
  }
  if (response.status === 422) {
    throw new SyncClientError("limit_reached", "The device limit was reached.")
  }
  throw new SyncClientError("request_failed", "The sync endpoint returned an error.")
}

async function responseErrorCode(response: Response): Promise<string | null> {
  try {
    const value = await boundedJson(response, 1024)
    if (
      typeof value === "object" &&
      value !== null &&
      Object.keys(value).length === 1 &&
      typeof (value as { error?: unknown }).error === "string"
    ) {
      return (value as { error: string }).error
    }
  } catch {
    // Status remains authoritative when a legacy error body is absent.
  }
  return null
}

function requireTopologyAccount(topology: HouseholdTopologyV1, accountId: string): void {
  if (!topology.accounts.some((account) => account.account_id === accountId)) {
    throw new SyncClientError(
      "invalid_contract",
      "The household topology does not include the authenticated account.",
    )
  }
}

export function parseOpaqueObjectHeader(value: unknown): OpaqueObjectHeaderV1 {
  const record = exactRecord(value, [
    "format_version",
    "protocol_version",
    "object_id",
    "class",
    "scope",
    "revision",
    "payload_version",
    "envelope_version",
    "ciphertext_size_bytes",
    "ciphertext_sha256",
    "tombstone",
  ])
  if (record.format_version !== OBJECT_HEADER_FORMAT_VERSION) {
    invalid("The opaque object header format is unsupported.")
  }
  if (record.protocol_version !== SYNC_PROTOCOL_VERSION) {
    invalid("The sync protocol version is unsupported.")
  }
  if (
    typeof record.class !== "string" ||
    !(OPAQUE_OBJECT_CLASSES as readonly string[]).includes(record.class)
  ) {
    invalid("The opaque object class is unsupported.")
  }
  const ciphertextSize = wireInteger(record.ciphertext_size_bytes, "ciphertext size")
  if (ciphertextSize === 0 || ciphertextSize > MAX_CIPHERTEXT_BYTES) {
    invalid("The ciphertext size is outside the supported bound.")
  }
  if (typeof record.tombstone !== "boolean") {
    invalid("The opaque tombstone flag is invalid.")
  }
  return {
    format_version: OBJECT_HEADER_FORMAT_VERSION,
    protocol_version: SYNC_PROTOCOL_VERSION,
    object_id: uuid(record.object_id, "object ID"),
    class: record.class as OpaqueObjectClassV1,
    scope: parseScope(record.scope),
    revision: wireInteger(record.revision, "revision"),
    payload_version: positiveVersion(record.payload_version, "payload version"),
    envelope_version: positiveVersion(record.envelope_version, "envelope version"),
    ciphertext_size_bytes: ciphertextSize,
    ciphertext_sha256: sha256(record.ciphertext_sha256),
    tombstone: record.tombstone,
  }
}

export function parseOpaqueMutation(value: unknown): OpaqueMutationV1 {
  const record = exactRecord(value, [
    "format_version",
    "operation_id",
    "object",
    "precondition",
  ])
  if (record.format_version !== OPAQUE_MUTATION_FORMAT_VERSION) {
    invalid("The opaque mutation format is unsupported.")
  }
  const object = parseOpaqueObjectHeader(record.object)
  const precondition = parsePrecondition(record.precondition)
  if (precondition.condition === "match" && object.revision <= precondition.revision) {
    invalid("The candidate revision must advance the matched revision.")
  }
  return {
    format_version: OPAQUE_MUTATION_FORMAT_VERSION,
    operation_id: uuid(record.operation_id, "operation ID"),
    object,
    precondition,
  }
}

export function parseSyncObjectMetadata(value: unknown): SyncObjectMetadataV1 {
  const record = exactRecord(value, ["object", "change_seq", "etag"])
  if (typeof record.etag !== "string" || record.etag.length === 0 || record.etag.length > 256) {
    invalid("The opaque object ETag is invalid.")
  }
  return {
    object: parseOpaqueObjectHeader(record.object),
    change_seq: positiveWireInteger(record.change_seq, "change sequence"),
    etag: record.etag,
  }
}

export function parseSyncObjectPage(value: unknown): SyncObjectPageV1 {
  const record = exactRecord(value, ["objects", "next_change_seq"])
  if (!Array.isArray(record.objects) || record.objects.length > 256) {
    invalid("The opaque object page is invalid or too large.")
  }
  const objects = record.objects.map(parseSyncObjectMetadata)
  const nextChangeSeq = wireInteger(record.next_change_seq, "next change sequence")
  let previous = 0
  for (const object of objects) {
    if (object.change_seq <= previous || object.change_seq > nextChangeSeq) {
      invalid("The opaque object page cursor ordering is invalid.")
    }
    previous = object.change_seq
  }
  return { objects, next_change_seq: nextChangeSeq }
}

function parseScope(value: unknown): ObjectScopeV1 {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    invalid("The opaque object scope is invalid.")
  }
  const scope = (value as Record<string, unknown>).scope
  if (scope === "account") {
    const record = exactRecord(value, ["scope", "account_id"])
    return { scope, account_id: uuid(record.account_id, "account ID") }
  }
  if (scope === "household") {
    const record = exactRecord(value, ["scope", "account_id", "household_id"])
    return {
      scope,
      account_id: uuid(record.account_id, "account ID"),
      household_id: uuid(record.household_id, "household ID"),
    }
  }
  if (scope === "space") {
    const record = exactRecord(value, ["scope", "account_id", "household_id", "space_id"])
    return {
      scope,
      account_id: uuid(record.account_id, "account ID"),
      household_id: uuid(record.household_id, "household ID"),
      space_id: uuid(record.space_id, "space ID"),
    }
  }
  return invalid("The opaque object scope is unsupported.")
}

function parsePrecondition(value: unknown): WritePreconditionV1 {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    invalid("The write precondition is invalid.")
  }
  const condition = (value as Record<string, unknown>).condition
  if (condition === "create_only") {
    exactRecord(value, ["condition"])
    return { condition }
  }
  if (condition === "match") {
    const record = exactRecord(value, ["condition", "revision", "ciphertext_sha256"])
    return {
      condition,
      revision: wireInteger(record.revision, "precondition revision"),
      ciphertext_sha256: sha256(record.ciphertext_sha256),
    }
  }
  return invalid("The write precondition is unsupported.")
}

export async function verifyOpaqueCiphertext(
  header: OpaqueObjectHeaderV1,
  ciphertext: Uint8Array,
): Promise<void> {
  if (ciphertext.byteLength !== header.ciphertext_size_bytes) {
    throw new SyncClientError(
      "ciphertext_mismatch",
      "The ciphertext length does not match its opaque header.",
    )
  }
  const digestInput = Uint8Array.from(ciphertext).buffer
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", digestInput),
  )
  if (
    digest.length !== header.ciphertext_sha256.length ||
    digest.some((byte, index) => byte !== header.ciphertext_sha256[index])
  ) {
    throw new SyncClientError(
      "ciphertext_mismatch",
      "The ciphertext digest does not match its opaque header.",
    )
  }
}

function sameOpaqueObjectHeader(
  left: OpaqueObjectHeaderV1,
  right: OpaqueObjectHeaderV1,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right)
}

async function boundedJson(response: Response, maximum: number): Promise<unknown> {
  const declaredLength = response.headers.get("content-length")
  if (
    declaredLength !== null &&
    (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximum)
  ) {
    throw new SyncClientError("invalid_response", "The sync response is too large.")
  }
  const text = await readBoundedText(response, maximum)
  try {
    return JSON.parse(text) as unknown
  } catch {
    throw new SyncClientError("invalid_response", "The sync response is not valid JSON.")
  }
}

async function readExactBody(response: Response, expectedLength: number): Promise<Uint8Array> {
  if (response.body === null) {
    const bytes = new Uint8Array(await response.arrayBuffer())
    if (bytes.byteLength !== expectedLength) {
      throw new SyncClientError(
        "ciphertext_mismatch",
        "The downloaded ciphertext length does not match its opaque header.",
      )
    }
    return bytes
  }
  const output = new Uint8Array(expectedLength)
  const reader = response.body.getReader()
  let offset = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      if (offset + value.byteLength > expectedLength) {
        await reader.cancel()
        throw new SyncClientError(
          "ciphertext_mismatch",
          "The downloaded ciphertext exceeds its opaque header size.",
        )
      }
      output.set(value, offset)
      offset += value.byteLength
    }
  } finally {
    reader.releaseLock()
  }
  if (offset !== expectedLength) {
    throw new SyncClientError(
      "ciphertext_mismatch",
      "The downloaded ciphertext length does not match its opaque header.",
    )
  }
  return output
}

async function readBoundedText(response: Response, maximumBytes: number): Promise<string> {
  if (response.body === null) {
    const text = await response.text()
    if (new TextEncoder().encode(text).byteLength > maximumBytes) {
      throw new SyncClientError("invalid_response", "The sync response is too large.")
    }
    return text
  }
  const reader = response.body.getReader()
  const decoder = new TextDecoder("utf-8", { fatal: true })
  let total = 0
  let text = ""
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > maximumBytes) {
        await reader.cancel()
        throw new SyncClientError("invalid_response", "The sync response is too large.")
      }
      text += decoder.decode(value, { stream: true })
    }
    text += decoder.decode()
  } catch (error) {
    if (error instanceof SyncClientError) throw error
    throw new SyncClientError("invalid_response", "The sync response is not valid UTF-8.")
  } finally {
    reader.releaseLock()
  }
  return text
}

export function normalizeSyncApiBaseUrl(value: string): string {
  return syncBaseUrl(value).href
}

function syncBaseUrl(value: string): URL {
  let url: URL
  try {
    url = new URL(value.endsWith("/") ? value : `${value}/`)
  } catch {
    throw new SyncClientError("invalid_configuration", "The sync API URL is invalid.")
  }
  const local = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]"
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
    throw new SyncClientError(
      "invalid_configuration",
      "Device credentials require HTTPS except on the local development host.",
    )
  }
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") {
    throw new SyncClientError(
      "invalid_configuration",
      "The sync API URL must not contain credentials, a query, or a fragment.",
    )
  }
  return url
}

function uuid(value: unknown, label: string): string {
  if (typeof value !== "string" || !UUID.test(value) || value.toLowerCase() === NIL_UUID) {
    return invalid(`${label} must be a non-nil UUID.`)
  }
  return value.toLowerCase()
}

function sha256(value: unknown): number[] {
  if (
    !Array.isArray(value) ||
    value.length !== 32 ||
    value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)
  ) {
    return invalid("The ciphertext SHA-256 digest is invalid.")
  }
  return [...value] as number[]
}

function positiveVersion(value: unknown, label: string): number {
  if (!Number.isInteger(value) || (value as number) < 1 || (value as number) > MAX_VERSION) {
    return invalid(`${label} is invalid.`)
  }
  return value as number
}

function wireInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > MAX_WIRE_INTEGER) {
    return invalid(`${label} is outside the exact browser integer range.`)
  }
  return value as number
}

function positiveWireInteger(value: unknown, label: string): number {
  const result = wireInteger(value, label)
  if (result === 0) return invalid(`${label} must be positive.`)
  return result
}

function exactRecord(value: unknown, expectedKeys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return invalid("The sync contract has an invalid shape.")
  }
  const record = value as Record<string, unknown>
  const keys = Object.keys(record)
  if (
    keys.length !== expectedKeys.length ||
    expectedKeys.some((key) => !Object.hasOwn(record, key))
  ) {
    return invalid("The sync contract has unknown or missing fields.")
  }
  return record
}

function invalid(message: string): never {
  throw new SyncClientError("invalid_contract", message)
}
