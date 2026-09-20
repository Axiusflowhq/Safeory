import type {
  ObjectScopeV1,
  OpaqueObjectHeaderV1,
  WritePreconditionV1,
} from "./sync-client"
import { SyncClientError } from "./sync-error"
import type { DurableSyncOutbox, QueuedOpaqueMutation } from "./sync-queue"
import type { VaultItemSyncState } from "./sync-vault-acceptance"
import {
  encryptedVaultItemMatchesHeader,
  parseEncryptedVaultItem,
  prepareVaultItemMutationFromBaseline,
  type EncryptedVaultItemV1,
} from "./sync-vault-item"

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const NIL_UUID = "00000000-0000-0000-0000-000000000000"
const OPERATION_DOMAIN = "safeory:v1:vault-item-mutation"
const MAX_OUTBOX_ENTRIES = 256

export interface VaultItemSyncStateReader {
  readonly accountId: string
  state(objectId: string): Promise<VaultItemSyncState>
}

export interface EncryptedVaultInventory {
  listEncryptedItemIdsForSync(): Promise<string[]>
  loadEncryptedItemForSync(objectId: string): Promise<unknown | null>
  encryptedItemIsTombstoneForSync(objectId: string): Promise<boolean>
}

export interface VaultItemHarvestResult {
  scanned: number
  enqueued: number
  alreadyQueued: number
  current: number
  blockedObjectIds: string[]
}

/**
 * Rebuilds missing outbox entries from the durable encrypted vault snapshot.
 * Operation IDs are content-derived, so interruption before/after enqueue is
 * safe to retry and converges on the same queue entry.
 */
export class DurableVaultItemHarvester {
  readonly accountId: string

  constructor(
    private readonly scope: ObjectScopeV1,
    private readonly outbox: DurableSyncOutbox,
    private readonly stateReader: VaultItemSyncStateReader,
  ) {
    this.accountId = uuid(scope.account_id, "scope account ID")
    if (outbox.accountId !== this.accountId || stateReader.accountId !== this.accountId) {
      throw new SyncClientError(
        "invalid_configuration",
        "The sync scope, outbox, and item state must use the same account.",
      )
    }
  }

  async harvest(inventory: EncryptedVaultInventory): Promise<VaultItemHarvestResult> {
    const listed = await inventory.listEncryptedItemIdsForSync()
    const ids = listed.map((value) => uuid(value, "encrypted inventory object ID"))
    if (new Set(ids).size !== ids.length) {
      throw new SyncClientError(
        "invalid_response",
        "The encrypted vault inventory contains a duplicate object ID.",
      )
    }
    ids.sort()
    const pendingByObject = new Map<string, QueuedOpaqueMutation[]>()
    for (const entry of await this.outbox.pending(MAX_OUTBOX_ENTRIES)) {
      if (entry.mutation.object.class !== "item") continue
      const objectId = entry.mutation.object.object_id
      const entries = pendingByObject.get(objectId) ?? []
      entries.push(entry)
      pendingByObject.set(objectId, entries)
    }

    const result: VaultItemHarvestResult = {
      scanned: ids.length,
      enqueued: 0,
      alreadyQueued: 0,
      current: 0,
      blockedObjectIds: [],
    }
    for (const objectId of ids) {
      const localValue = await inventory.loadEncryptedItemForSync(objectId)
      if (localValue === null) {
        throw new SyncClientError(
          "invalid_response",
          "The encrypted vault inventory referenced a missing object.",
        )
      }
      const local = parseEncryptedVaultItem(localValue)
      if (local.object_id !== objectId) {
        throw new SyncClientError(
          "invalid_response",
          "The encrypted vault inventory returned a substituted object.",
        )
      }
      const tombstone = await inventory.encryptedItemIsTombstoneForSync(objectId)
      const state = await this.stateReader.state(objectId)
      if (state.conflict !== null) {
        result.blockedObjectIds.push(objectId)
        continue
      }
      const queued = pendingByObject.get(objectId) ?? []
      const effectiveBaseline = advanceQueuedBaseline(state.baseline, queued, this.scope)
      if (
        effectiveBaseline !== null &&
        effectiveBaseline.tombstone === tombstone &&
        await encryptedVaultItemMatchesHeader(local, effectiveBaseline)
      ) {
        if (queued.length === 0) result.current += 1
        else result.alreadyQueued += 1
        continue
      }
      if (effectiveBaseline !== null && local.revision <= effectiveBaseline.revision) {
        result.blockedObjectIds.push(objectId)
        continue
      }
      const operationId = await mutationOperationId(
        local,
        effectiveBaseline,
        this.scope,
        tombstone,
      )
      const prepared = await prepareVaultItemMutationFromBaseline(
        local,
        effectiveBaseline,
        this.scope,
        operationId,
        { tombstone },
      )
      if (await this.outbox.enqueue(prepared.mutation, prepared.ciphertext)) {
        result.enqueued += 1
      } else {
        result.alreadyQueued += 1
      }
    }
    return result
  }
}

function advanceQueuedBaseline(
  baseline: OpaqueObjectHeaderV1 | null,
  queued: readonly QueuedOpaqueMutation[],
  scope: ObjectScopeV1,
): OpaqueObjectHeaderV1 | null {
  if (baseline !== null && JSON.stringify(baseline.scope) !== JSON.stringify(scope)) {
    throw new SyncClientError(
      "invalid_response",
      "The accepted vault item baseline belongs to a different sync scope.",
    )
  }
  let current = baseline
  const remaining = queued.slice()
  while (remaining.length > 0) {
    for (let index = remaining.length - 1; index >= 0; index -= 1) {
      const entry = remaining[index]
      if (entry === undefined) continue
      if (JSON.stringify(entry.mutation.object.scope) !== JSON.stringify(scope)) {
        throw new SyncClientError(
          "invalid_response",
          "A queued vault item belongs to a different sync scope.",
        )
      }
      if (current !== null && sameHeaderVersion(current, entry.mutation.object)) {
        remaining.splice(index, 1)
      }
    }
    if (remaining.length === 0) break
    const candidates = remaining.filter((entry) =>
      preconditionMatches(entry.mutation.precondition, current)
    )
    if (candidates.length !== 1) {
      throw new SyncClientError(
        "invalid_response",
        "The queued vault item mutations do not form one revision chain.",
      )
    }
    const candidate = candidates[0]
    if (candidate === undefined) {
      throw new SyncClientError("invalid_response", "The queued vault item chain is invalid.")
    }
    remaining.splice(remaining.indexOf(candidate), 1)
    current = candidate.mutation.object
  }
  return current
}

function preconditionMatches(
  precondition: WritePreconditionV1,
  baseline: OpaqueObjectHeaderV1 | null,
): boolean {
  return baseline === null
    ? precondition.condition === "create_only"
    : precondition.condition === "match" &&
      precondition.revision === baseline.revision &&
      sameBytes(precondition.ciphertext_sha256, baseline.ciphertext_sha256)
}

function sameHeaderVersion(left: OpaqueObjectHeaderV1, right: OpaqueObjectHeaderV1): boolean {
  return left.object_id === right.object_id &&
    left.revision === right.revision &&
    left.payload_version === right.payload_version &&
    left.envelope_version === right.envelope_version &&
    left.ciphertext_size_bytes === right.ciphertext_size_bytes &&
    left.tombstone === right.tombstone &&
    sameBytes(left.ciphertext_sha256, right.ciphertext_sha256)
}

function sameBytes(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

async function mutationOperationId(
  item: EncryptedVaultItemV1,
  baseline: OpaqueObjectHeaderV1 | null,
  scope: ObjectScopeV1,
  tombstone: boolean,
): Promise<string> {
  const itemDigest = await digest(new TextEncoder().encode(JSON.stringify(item)))
  const identity = JSON.stringify({
    domain: OPERATION_DOMAIN,
    object_id: item.object_id,
    revision: item.revision,
    item_sha256: Array.from(itemDigest),
    baseline: baseline === null
      ? null
      : {
          revision: baseline.revision,
          ciphertext_sha256: baseline.ciphertext_sha256,
        },
    scope,
    tombstone,
  })
  const bytes = await digest(new TextEncoder().encode(identity))
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x50
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80
  const hex = Array.from(bytes.slice(0, 16), (value) => value.toString(16).padStart(2, "0"))
    .join("")
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

async function digest(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", value.slice().buffer))
}

function uuid(value: unknown, label: string): string {
  if (typeof value !== "string" || !UUID.test(value) || value.toLowerCase() === NIL_UUID) {
    throw new SyncClientError("invalid_contract", `The ${label} is invalid.`)
  }
  return value.toLowerCase()
}
