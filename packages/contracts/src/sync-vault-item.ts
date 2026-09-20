import {
  parseOpaqueObjectHeader,
  parseSyncObjectMetadata,
  verifyOpaqueCiphertext,
  type OpaqueMutationV1,
  type OpaqueObjectHeaderV1,
  type ObjectScopeV1,
  type SyncObjectMetadataV1,
  type WritePreconditionV1,
} from "./sync-client"
import { SyncClientError } from "./sync-error"

const ITEM_FORMAT_VERSION = 1
const ITEM_ENVELOPE_VERSION = 1
const MAX_ITEM_CIPHERTEXT_BYTES = 128 * 1024 * 1024
const MAX_WIRE_INTEGER = Number.MAX_SAFE_INTEGER
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const NIL_UUID = "00000000-0000-0000-0000-000000000000"

export interface EncryptedVaultItemV1 {
  format_version: number
  payload_schema_version: number
  algorithm: "xchacha20poly1305"
  object_id: string
  key_id: string
  revision: number
  key_nonce: number[]
  wrapped_item_key: number[]
  payload_nonce: number[]
  ciphertext: number[]
}

export interface PreparedVaultItemMutation {
  mutation: OpaqueMutationV1
  ciphertext: Uint8Array
}

export interface DecodedPulledVaultItem {
  metadata: SyncObjectMetadataV1
  encryptedItem: EncryptedVaultItemV1
  ciphertext: Uint8Array
}

export type VaultItemReconciliation =
  | {
      action: "apply_remote"
      item: EncryptedVaultItemV1
      baseline: OpaqueObjectHeaderV1
    }
  | {
      action: "unchanged"
      item: EncryptedVaultItemV1
      baseline: OpaqueObjectHeaderV1
    }
  | {
      action: "keep_local"
      item: EncryptedVaultItemV1
      baseline: OpaqueObjectHeaderV1
    }
  | {
      action: "conflict"
      local: EncryptedVaultItemV1 | null
      remote: EncryptedVaultItemV1
      baseline: OpaqueObjectHeaderV1 | null
      remoteHeader: OpaqueObjectHeaderV1
    }

/**
 * Turns one already-encrypted vault item into the canonical opaque transport
 * mutation. The server body is the encrypted record itself; plaintext and item
 * keys never cross this boundary.
 */
export async function prepareVaultItemMutation(
  nextValue: unknown,
  previousValue: unknown | null,
  scope: ObjectScopeV1,
  operationIdValue: string,
  options: { tombstone?: boolean } = {},
): Promise<PreparedVaultItemMutation> {
  const next = parseEncryptedVaultItem(nextValue)
  const previous = previousValue === null ? null : parseEncryptedVaultItem(previousValue)
  const operationId = uuid(operationIdValue, "operation ID")

  if (previous !== null) {
    if (previous.object_id !== next.object_id) {
      invalid("A vault item mutation cannot change its object ID.")
    }
    if (next.revision <= previous.revision) {
      invalid("A vault item mutation must advance its revision.")
    }
  }

  const ciphertext = encodeEncryptedVaultItem(next)
  const digest = await sha256(ciphertext)
  const precondition: WritePreconditionV1 = previous === null
    ? { condition: "create_only" }
    : {
        condition: "match",
        revision: previous.revision,
        ciphertext_sha256: await sha256(encodeEncryptedVaultItem(previous)),
      }
  const object: OpaqueObjectHeaderV1 = parseOpaqueObjectHeader({
    format_version: 1,
    protocol_version: 1,
    object_id: next.object_id,
    class: "item",
    scope,
    revision: next.revision,
    payload_version: next.payload_schema_version,
    envelope_version: ITEM_ENVELOPE_VERSION,
    ciphertext_size_bytes: ciphertext.byteLength,
    ciphertext_sha256: digest,
    tombstone: options.tombstone ?? false,
  })

  return {
    mutation: {
      format_version: 1,
      operation_id: operationId,
      object,
      precondition,
    },
    ciphertext,
  }
}

/**
 * Verifies and decodes an item downloaded by SyncClient. This intentionally
 * does not merge it into a live vault: callers must first apply their durable
 * conflict/acceptance policy, then allow the pull cursor to advance.
 */
export async function decodePulledVaultItem(
  metadataValue: SyncObjectMetadataV1,
  ciphertextValue: Uint8Array,
): Promise<DecodedPulledVaultItem> {
  const metadata = parseSyncObjectMetadata(metadataValue)
  const header = metadata.object
  if (header.class !== "item") {
    invalid("The pulled opaque object is not a vault item.")
  }
  const ciphertext = Uint8Array.from(ciphertextValue)
  await verifyOpaqueCiphertext(header, ciphertext)
  const encryptedItem = parseEncryptedVaultItem(decodeJson(ciphertext))
  requireItemMatchesHeader(encryptedItem, header)
  return { metadata, encryptedItem, ciphertext }
}

/**
 * Three-way reconciliation for an already-verified pull. `baselineValue` is
 * the last server header durably accepted for this object. It is the evidence
 * needed to distinguish a safe fast-forward from concurrent local/remote
 * edits; without it, differing existing ciphertext is preserved as a conflict.
 */
export async function reconcilePulledVaultItem(
  localValue: unknown | null,
  baselineValue: OpaqueObjectHeaderV1 | null,
  pulled: DecodedPulledVaultItem,
): Promise<VaultItemReconciliation> {
  const verified = await decodePulledVaultItem(pulled.metadata, pulled.ciphertext)
  const remoteHeader = verified.metadata.object
  const remote = verified.encryptedItem

  const baseline = baselineValue === null ? null : parseOpaqueObjectHeader(baselineValue)
  if (baseline !== null) {
    if (baseline.class !== "item" || baseline.object_id !== remoteHeader.object_id) {
      invalid("The vault item sync baseline belongs to a different object.")
    }
    if (!sameScope(baseline.scope, remoteHeader.scope)) {
      throw new SyncClientError(
        "invalid_response",
        "The server changed an existing vault item's sync scope.",
      )
    }
    if (remoteHeader.revision < baseline.revision) {
      throw new SyncClientError(
        "invalid_response",
        "The pulled vault item predates its accepted server baseline.",
      )
    }
    if (
      remoteHeader.revision === baseline.revision &&
      !sameHeaderVersion(baseline, remoteHeader)
    ) {
      throw new SyncClientError(
        "invalid_response",
        "The server substituted a vault item at an accepted revision.",
      )
    }
  }

  if (localValue === null) {
    if (baseline !== null) {
      return {
        action: "conflict",
        local: null,
        remote,
        baseline,
        remoteHeader,
      }
    }
    return { action: "apply_remote", item: remote, baseline: remoteHeader }
  }

  const local = parseEncryptedVaultItem(localValue)
  if (local.object_id !== remoteHeader.object_id) {
    invalid("The local vault item belongs to a different object.")
  }
  const localDigest = await sha256(encodeEncryptedVaultItem(local))
  if (itemMatchesHeader(local, localDigest, remoteHeader)) {
    return { action: "unchanged", item: local, baseline: remoteHeader }
  }
  if (baseline === null) {
    return { action: "conflict", local, remote, baseline: null, remoteHeader }
  }
  if (itemMatchesHeader(local, localDigest, baseline)) {
    return { action: "apply_remote", item: remote, baseline: remoteHeader }
  }
  if (sameHeaderVersion(baseline, remoteHeader)) {
    return { action: "keep_local", item: local, baseline }
  }
  return { action: "conflict", local, remote, baseline, remoteHeader }
}

export function parseEncryptedVaultItem(value: unknown): EncryptedVaultItemV1 {
  const record = exactRecord(value, [
    "format_version",
    "payload_schema_version",
    "algorithm",
    "object_id",
    "key_id",
    "revision",
    "key_nonce",
    "wrapped_item_key",
    "payload_nonce",
    "ciphertext",
  ])
  if (record.format_version !== ITEM_FORMAT_VERSION) {
    invalid("The encrypted vault item format is unsupported.")
  }
  const payloadSchemaVersion = positiveVersion(
    record.payload_schema_version,
    "item payload schema version",
  )
  if (record.algorithm !== "xchacha20poly1305") {
    invalid("The encrypted vault item algorithm is unsupported.")
  }
  const revision = wireInteger(record.revision, "item revision")
  if (revision === 0) invalid("Encrypted vault item revision zero is reserved.")

  const result: EncryptedVaultItemV1 = {
    format_version: ITEM_FORMAT_VERSION,
    payload_schema_version: payloadSchemaVersion,
    algorithm: "xchacha20poly1305",
    object_id: uuid(record.object_id, "item object ID"),
    key_id: uuid(record.key_id, "item key ID"),
    revision,
    key_nonce: byteArray(record.key_nonce, 24, 24, "item key nonce"),
    wrapped_item_key: byteArray(record.wrapped_item_key, 1, 1024, "wrapped item key"),
    payload_nonce: byteArray(record.payload_nonce, 24, 24, "item payload nonce"),
    ciphertext: byteArray(
      record.ciphertext,
      1,
      MAX_ITEM_CIPHERTEXT_BYTES,
      "item ciphertext",
    ),
  }
  if (encodeEncryptedVaultItem(result).byteLength > MAX_ITEM_CIPHERTEXT_BYTES) {
    invalid("The encrypted vault item exceeds the transport bound.")
  }
  return result
}

function encodeEncryptedVaultItem(item: EncryptedVaultItemV1): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(item))
}

function requireItemMatchesHeader(
  item: EncryptedVaultItemV1,
  header: OpaqueObjectHeaderV1,
): void {
  if (
    item.object_id !== header.object_id ||
    item.revision !== header.revision ||
    item.payload_schema_version !== header.payload_version ||
    header.envelope_version !== ITEM_ENVELOPE_VERSION
  ) {
    throw new SyncClientError(
      "ciphertext_mismatch",
      "The encrypted vault item does not match its opaque header.",
    )
  }
}

function itemMatchesHeader(
  item: EncryptedVaultItemV1,
  digest: readonly number[],
  header: OpaqueObjectHeaderV1,
): boolean {
  return (
    item.object_id === header.object_id &&
    item.revision === header.revision &&
    item.payload_schema_version === header.payload_version &&
    header.envelope_version === ITEM_ENVELOPE_VERSION &&
    sameBytes(digest, header.ciphertext_sha256)
  )
}

function sameHeaderVersion(
  left: OpaqueObjectHeaderV1,
  right: OpaqueObjectHeaderV1,
): boolean {
  return (
    left.object_id === right.object_id &&
    left.revision === right.revision &&
    left.payload_version === right.payload_version &&
    left.envelope_version === right.envelope_version &&
    left.ciphertext_size_bytes === right.ciphertext_size_bytes &&
    left.tombstone === right.tombstone &&
    sameBytes(left.ciphertext_sha256, right.ciphertext_sha256)
  )
}

function sameScope(left: ObjectScopeV1, right: ObjectScopeV1): boolean {
  return JSON.stringify(left) === JSON.stringify(right)
}

function sameBytes(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

function decodeJson(bytes: Uint8Array): unknown {
  let encoded: string
  try {
    encoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes)
    return JSON.parse(encoded) as unknown
  } catch {
    throw new SyncClientError("ciphertext_mismatch", "The encrypted vault item is invalid JSON.")
  }
}

async function sha256(bytes: Uint8Array): Promise<number[]> {
  const input = Uint8Array.from(bytes).buffer
  return Array.from(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", input)))
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return invalid("The encrypted vault item is invalid.")
  }
  const record = value as Record<string, unknown>
  const actual = Object.keys(record)
  if (actual.length !== keys.length || keys.some((key) => !Object.hasOwn(record, key))) {
    return invalid("The encrypted vault item fields are invalid.")
  }
  return record
}

function byteArray(value: unknown, minimum: number, maximum: number, label: string): number[] {
  if (
    !Array.isArray(value) ||
    value.length < minimum ||
    value.length > maximum ||
    value.some((entry) => !Number.isInteger(entry) || entry < 0 || entry > 255)
  ) {
    return invalid(`The ${label} is invalid.`)
  }
  return value.slice() as number[]
}

function positiveVersion(value: unknown, label: string): number {
  const parsed = wireInteger(value, label)
  if (parsed === 0 || parsed > 65_535) invalid(`The ${label} is unsupported.`)
  return parsed
}

function wireInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > MAX_WIRE_INTEGER) {
    return invalid(`The ${label} is invalid.`)
  }
  return value as number
}

function uuid(value: unknown, label: string): string {
  if (typeof value !== "string" || !UUID.test(value) || value.toLowerCase() === NIL_UUID) {
    return invalid(`The ${label} is invalid.`)
  }
  return value.toLowerCase()
}

function invalid(message: string): never {
  throw new SyncClientError("invalid_contract", message)
}
