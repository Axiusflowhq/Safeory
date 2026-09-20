import {
  fetchSyncCompatibility,
  type NegotiatedCompatibility,
} from "./sync-compatibility"

const SYNC_PROTOCOL_VERSION = 1
const OBJECT_HEADER_FORMAT_VERSION = 1
const OPAQUE_MUTATION_FORMAT_VERSION = 1
const MAX_VERSION = 65_535
const MAX_WIRE_INTEGER = Number.MAX_SAFE_INTEGER
const MAX_CIPHERTEXT_BYTES = 128 * 1024 * 1024
const MAX_MUTATION_HEADER_CHARS = 8 * 1024
const MAX_METADATA_RESPONSE_CHARS = 2 * 1024 * 1024
const DEVICE_TOKEN = /^sfo_dev_v1_[0-9a-f]{64}$/
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

export class SyncClientError extends Error {
  constructor(
    readonly code:
      | "invalid_configuration"
      | "invalid_contract"
      | "request_failed"
      | "unauthorized"
      | "not_found"
      | "precondition_failed"
      | "operation_conflict"
      | "invalid_response"
      | "ciphertext_mismatch",
    message: string,
  ) {
    super(message)
    this.name = "SyncClientError"
  }
}

export class SyncClient {
  private constructor(
    private readonly baseUrl: URL,
    private readonly accountId: string,
    private readonly deviceToken: string,
    private readonly fetcher: typeof fetch,
    readonly compatibility: NegotiatedCompatibility,
  ) {}

  static async connect(
    apiBaseUrl: string,
    accountIdValue: string,
    deviceToken: string,
    options: { fetcher?: typeof fetch; signal?: AbortSignal } = {},
  ): Promise<SyncClient> {
    const baseUrl = syncBaseUrl(apiBaseUrl)
    const accountId = uuid(accountIdValue, "account ID")
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
    return new SyncClient(baseUrl, accountId, deviceToken, fetcher, compatibility)
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
    const expectedNext = page.objects.at(-1)?.change_seq ?? after
    if (page.next_change_seq !== expectedNext) {
      throw new SyncClientError(
        "invalid_response",
        "The sync response cursor does not match the returned changes.",
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
    let response: Response
    try {
      response = await this.fetcher(endpoint, {
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
    if (response.status === 404) {
      throw new SyncClientError("not_found", "The opaque object was not found.")
    }
    if (response.status === 409) {
      throw new SyncClientError(
        "operation_conflict",
        "The operation ID was already used for different input.",
      )
    }
    if (response.status === 412) {
      throw new SyncClientError(
        "precondition_failed",
        "The opaque object revision precondition failed.",
      )
    }
    throw new SyncClientError("request_failed", "The sync endpoint returned an error.")
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
