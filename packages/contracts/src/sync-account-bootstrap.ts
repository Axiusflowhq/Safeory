import {
  parseOpaqueObjectHeader,
  parseSyncObjectMetadata,
  verifyOpaqueCiphertext,
  type OpaqueMutationV1,
  type OpaqueObjectHeaderV1,
  type SyncClient,
  type SyncObjectMetadataV1,
  type WritePreconditionV1,
} from "./sync-client"
import { SyncClientError } from "./sync-error"

const REMOTE_ROOT_FORMAT_VERSION = 1
const REMOTE_ROOT_ALGORITHM = "argon2id-v19+hkdf-sha256+xchacha20poly1305"
const ACCOUNT_BOOTSTRAP_PAYLOAD_VERSION = 1
const ACCOUNT_BOOTSTRAP_ENVELOPE_VERSION = 1
const MAX_REMOTE_ROOT_JSON_BYTES = 4 * 1024
const MIN_ARGON2_MEMORY_KIB = 19 * 1024
const MAX_ARGON2_MEMORY_KIB = 512 * 1024
const MIN_ARGON2_ITERATIONS = 2
const MAX_ARGON2_ITERATIONS = 10
const MIN_ARGON2_PARALLELISM = 1
const MAX_ARGON2_PARALLELISM = 4
const MAX_WIRE_INTEGER = Number.MAX_SAFE_INTEGER
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const NIL_UUID = "00000000-0000-0000-0000-000000000000"

export interface RemoteAccountRootWrapV1 {
  format_version: 1
  algorithm: typeof REMOTE_ROOT_ALGORITHM
  account_id: string
  argon2_memory_kib: number
  argon2_iterations: number
  argon2_parallelism: number
  passphrase_salt: number[]
  nonce: number[]
  ciphertext: number[]
}

export interface PreparedAccountBootstrapMutation {
  mutation: OpaqueMutationV1
  ciphertext: Uint8Array
  wrappedRoot: RemoteAccountRootWrapV1
}

export interface DecodedAccountBootstrap {
  metadata: SyncObjectMetadataV1
  wrappedJson: string
  wrappedRoot: RemoteAccountRootWrapV1
  ciphertext: Uint8Array
}

/**
 * Prepare the singleton account-scoped root bootstrap object for the generic
 * opaque transport. The account UUID is also its stable object UUID, allowing a
 * newly authenticated device to discover it directly without a plaintext
 * server-side pointer or a scan across vault items.
 */
export async function prepareAccountBootstrapMutation(
  wrappedJsonValue: string,
  accountIdValue: string,
  operationIdValue: string,
  previousValue: OpaqueObjectHeaderV1 | null,
): Promise<PreparedAccountBootstrapMutation> {
  const accountId = uuid(accountIdValue, "account ID")
  const operationId = uuid(operationIdValue, "operation ID")
  const { wrappedRoot, ciphertext } = parseWrappedJson(wrappedJsonValue)
  if (wrappedRoot.account_id !== accountId) {
    invalid("The remote root envelope belongs to a different account.")
  }

  let revision = 1
  let precondition: WritePreconditionV1 = { condition: "create_only" }
  if (previousValue !== null) {
    const previous = requireAccountBootstrapHeader(previousValue, accountId)
    if (previous.revision === MAX_WIRE_INTEGER) {
      invalid("The account bootstrap revision is exhausted.")
    }
    revision = previous.revision + 1
    precondition = {
      condition: "match",
      revision: previous.revision,
      ciphertext_sha256: previous.ciphertext_sha256,
    }
  }

  const object = parseOpaqueObjectHeader({
    format_version: 1,
    protocol_version: 1,
    object_id: accountId,
    class: "account_bootstrap",
    scope: { scope: "account", account_id: accountId },
    revision,
    payload_version: ACCOUNT_BOOTSTRAP_PAYLOAD_VERSION,
    envelope_version: ACCOUNT_BOOTSTRAP_ENVELOPE_VERSION,
    ciphertext_size_bytes: ciphertext.byteLength,
    ciphertext_sha256: await sha256(ciphertext),
    tombstone: false,
  })
  return {
    mutation: {
      format_version: 1,
      operation_id: operationId,
      object,
      precondition,
    },
    ciphertext,
    wrappedRoot,
  }
}

/** Verify a downloaded bootstrap body before passing its JSON into WASM. */
export async function decodePulledAccountBootstrap(
  metadataValue: SyncObjectMetadataV1,
  ciphertextValue: Uint8Array,
): Promise<DecodedAccountBootstrap> {
  const metadata = parseSyncObjectMetadata(metadataValue)
  const accountId = requireBootstrapIdentity(metadata.object)
  const ciphertext = Uint8Array.from(ciphertextValue)
  await verifyOpaqueCiphertext(metadata.object, ciphertext)
  if (ciphertext.byteLength > MAX_REMOTE_ROOT_JSON_BYTES) {
    invalidResponse("The remote root envelope exceeds the supported size.")
  }
  let wrappedJson: string
  try {
    wrappedJson = new TextDecoder("utf-8", { fatal: true }).decode(ciphertext)
  } catch {
    return invalidResponse("The remote root envelope is not valid UTF-8.")
  }
  const parsed = parseWrappedJson(wrappedJson)
  if (parsed.wrappedRoot.account_id !== accountId) {
    invalidResponse("The remote root envelope changed its authenticated account context.")
  }
  return {
    metadata,
    wrappedJson: parsed.wrappedJson,
    wrappedRoot: parsed.wrappedRoot,
    ciphertext,
  }
}

/** Fetch the stable account bootstrap object and verify its body end to end. */
export async function fetchAccountBootstrap(
  client: SyncClient,
  options: { signal?: AbortSignal } = {},
): Promise<DecodedAccountBootstrap> {
  const requestOptions = options.signal === undefined ? {} : { signal: options.signal }
  const metadata = await client.getObjectMetadata(client.accountId, requestOptions)
  const metadataAccountId = requireBootstrapIdentity(metadata.object)
  if (metadataAccountId !== client.accountId) {
    invalidResponse("The account bootstrap header belongs to a different account.")
  }
  const ciphertext = await client.getObject(metadata.object, requestOptions)
  return decodePulledAccountBootstrap(metadata, ciphertext)
}

export function parseRemoteAccountRootWrap(value: unknown): RemoteAccountRootWrapV1 {
  const record = exactRecord(value, [
    "format_version",
    "algorithm",
    "account_id",
    "argon2_memory_kib",
    "argon2_iterations",
    "argon2_parallelism",
    "passphrase_salt",
    "nonce",
    "ciphertext",
  ])
  if (record.format_version !== REMOTE_ROOT_FORMAT_VERSION) {
    invalid("The remote root envelope format is unsupported.")
  }
  if (record.algorithm !== REMOTE_ROOT_ALGORITHM) {
    invalid("The remote root envelope algorithm is unsupported.")
  }
  const memory = boundedInteger(
    record.argon2_memory_kib,
    MIN_ARGON2_MEMORY_KIB,
    MAX_ARGON2_MEMORY_KIB,
    "Argon2 memory",
  )
  const iterations = boundedInteger(
    record.argon2_iterations,
    MIN_ARGON2_ITERATIONS,
    MAX_ARGON2_ITERATIONS,
    "Argon2 iterations",
  )
  const parallelism = boundedInteger(
    record.argon2_parallelism,
    MIN_ARGON2_PARALLELISM,
    MAX_ARGON2_PARALLELISM,
    "Argon2 parallelism",
  )
  return {
    format_version: REMOTE_ROOT_FORMAT_VERSION,
    algorithm: REMOTE_ROOT_ALGORITHM,
    account_id: uuid(record.account_id, "remote root account ID"),
    argon2_memory_kib: memory,
    argon2_iterations: iterations,
    argon2_parallelism: parallelism,
    passphrase_salt: byteArray(record.passphrase_salt, 16, "passphrase salt"),
    nonce: byteArray(record.nonce, 24, "nonce"),
    ciphertext: byteArray(record.ciphertext, 48, "ciphertext"),
  }
}

function requireAccountBootstrapHeader(
  value: OpaqueObjectHeaderV1,
  expectedAccountId: string,
): OpaqueObjectHeaderV1 {
  const header = parseOpaqueObjectHeader(value)
  const accountId = requireBootstrapIdentity(header)
  if (accountId !== uuid(expectedAccountId, "expected account ID")) {
    invalid("The account bootstrap header belongs to a different account.")
  }
  return header
}

function requireBootstrapIdentity(header: OpaqueObjectHeaderV1): string {
  if (
    header.class !== "account_bootstrap" ||
    header.scope.scope !== "account" ||
    header.object_id !== header.scope.account_id ||
    header.revision < 1 ||
    header.payload_version !== ACCOUNT_BOOTSTRAP_PAYLOAD_VERSION ||
    header.envelope_version !== ACCOUNT_BOOTSTRAP_ENVELOPE_VERSION ||
    header.tombstone
  ) {
    invalidResponse("The account bootstrap header is invalid or non-canonical.")
  }
  return header.scope.account_id
}

function parseWrappedJson(value: string): {
  wrappedJson: string
  wrappedRoot: RemoteAccountRootWrapV1
  ciphertext: Uint8Array
} {
  if (typeof value !== "string") invalid("The remote root envelope must be JSON text.")
  const ciphertext = new TextEncoder().encode(value)
  if (ciphertext.byteLength === 0 || ciphertext.byteLength > MAX_REMOTE_ROOT_JSON_BYTES) {
    invalid("The remote root envelope exceeds the supported size.")
  }
  let decoded: unknown
  try {
    decoded = JSON.parse(value)
  } catch {
    return invalid("The remote root envelope is not valid JSON.")
  }
  return { wrappedJson: value, wrappedRoot: parseRemoteAccountRootWrap(decoded), ciphertext }
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    invalid("The remote root envelope is invalid.")
  }
  const record = value as Record<string, unknown>
  const actual = Object.keys(record)
  if (actual.length !== keys.length || !keys.every((key) => Object.hasOwn(record, key))) {
    invalid("The remote root envelope contains missing or unknown fields.")
  }
  return record
}

function byteArray(value: unknown, length: number, label: string): number[] {
  if (
    !Array.isArray(value) ||
    value.length !== length ||
    value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)
  ) {
    invalid(`The remote root envelope ${label} is invalid.`)
  }
  return Array.from(value) as number[]
}

function boundedInteger(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    invalid(`The remote root envelope ${label} is outside the supported bound.`)
  }
  return value as number
}

function uuid(value: unknown, label: string): string {
  if (typeof value !== "string" || !UUID.test(value) || value.toLowerCase() === NIL_UUID) {
    invalid(`The ${label} is invalid.`)
  }
  return value.toLowerCase()
}

async function sha256(value: Uint8Array): Promise<number[]> {
  const bytes = Uint8Array.from(value)
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.buffer)))
}

function invalid(message: string): never {
  throw new SyncClientError("invalid_contract", message)
}

function invalidResponse(message: string): never {
  throw new SyncClientError("invalid_response", message)
}
