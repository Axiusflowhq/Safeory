import type {
  SingleOwnerSyncBootstrapState,
  SingleOwnerSyncBootstrapStore,
} from "./sync-bootstrap"
import { BrowserSingleOwnerSyncBootstrap } from "./sync-bootstrap"
import type { SyncClient, ObjectScopeV1 } from "./sync-client"
import { BrowserSyncCredentialStore } from "./sync-credentials"
import { SyncClientError } from "./sync-error"
import {
  DurableSyncCoordinator,
  type SyncCycleOptions,
  type SyncCycleResult,
} from "./sync-coordinator"
import {
  DurableVaultItemHarvester,
  type EncryptedVaultInventory,
  type VaultItemHarvestResult,
} from "./sync-harvest"
import { DurableSyncPuller } from "./sync-pull"
import { DurableSyncOutbox } from "./sync-queue"
import { DurableVaultItemAcceptor } from "./sync-vault-acceptance"
import type { EncryptedVaultItemV1 } from "./sync-vault-item"

export interface VaultSyncSession extends EncryptedVaultInventory {
  applyRemoteEncryptedItemForSync(
    item: EncryptedVaultItemV1,
    expectedLocal: EncryptedVaultItemV1 | null,
  ): Promise<void>
}

export interface VaultSyncRuntimeDependencies {
  outbox?: DurableSyncOutbox
  puller?: DurableSyncPuller
  acceptor?: DurableVaultItemAcceptor
}

export type VaultSyncRuntimeCycleOptions = Omit<SyncCycleOptions, "beforePush">

export interface VaultSyncRuntimeCycleResult extends SyncCycleResult {
  harvest: VaultItemHarvestResult
}

/**
 * Live encrypted-item sync lifecycle for an authenticated single-owner space.
 * Each serialized cycle pulls and durably accepts remote state, reconstructs
 * any outbox entries missing after a local crash, then flushes uploads.
 */
export class DurableVaultSyncRuntime {
  readonly accountId: string
  private readonly coordinator: DurableSyncCoordinator
  private readonly harvester: DurableVaultItemHarvester
  private readonly acceptor: DurableVaultItemAcceptor

  constructor(
    client: SyncClient,
    scope: ObjectScopeV1,
    private readonly session: VaultSyncSession,
    dependencies: VaultSyncRuntimeDependencies = {},
  ) {
    this.accountId = client.accountId
    if (scope.account_id !== this.accountId) {
      throw new SyncClientError(
        "invalid_configuration",
        "The vault sync scope does not match the authenticated account.",
      )
    }
    const outbox = dependencies.outbox ?? new DurableSyncOutbox(this.accountId)
    const puller = dependencies.puller ?? new DurableSyncPuller(this.accountId)
    this.acceptor = dependencies.acceptor ?? new DurableVaultItemAcceptor(this.accountId)
    this.harvester = new DurableVaultItemHarvester(scope, outbox, this.acceptor)
    this.coordinator = new DurableSyncCoordinator(client, outbox, puller)
  }

  async syncOnce(
    options: VaultSyncRuntimeCycleOptions = {},
  ): Promise<VaultSyncRuntimeCycleResult> {
    let harvest: VaultItemHarvestResult | null = null
    const cycle = await this.coordinator.syncOnce(
      this.acceptor.callback(
        (objectId) => this.session.loadEncryptedItemForSync(objectId),
        (item, expected) => this.session.applyRemoteEncryptedItemForSync(item, expected),
      ),
      {
        ...options,
        beforePush: async () => {
          harvest = await this.harvester.harvest(this.session)
        },
      },
    )
    if (harvest === null) {
      throw new SyncClientError(
        "invalid_response",
        "The sync cycle completed without harvesting local ciphertext.",
      )
    }
    return { ...cycle, harvest }
  }
}

export interface ConnectedSingleOwnerVaultSync {
  client: SyncClient
  bootstrap: SingleOwnerSyncBootstrapState
  runtime: DurableVaultSyncRuntime
}

export interface SingleOwnerVaultSyncConnectOptions {
  bootstrapStore?: SingleOwnerSyncBootstrapStore
  runtimeDependencies?: VaultSyncRuntimeDependencies
  signal?: AbortSignal
}

export interface PersistedSyncCredentialConnector {
  connect(
    apiBaseUrl: string,
    accountId: string,
    options?: { fetcher?: typeof fetch; signal?: AbortSignal },
  ): Promise<SyncClient | null>
}

export interface ResumeSingleOwnerVaultSyncOptions extends SingleOwnerVaultSyncConnectOptions {
  credentials?: PersistedSyncCredentialConnector
  fetcher?: typeof fetch
}

/** Publishes/reloads the durable topology draft and starts its bound runtime. */
export async function connectSingleOwnerVaultSync(
  client: SyncClient,
  apiBaseUrl: string,
  session: VaultSyncSession,
  options: SingleOwnerVaultSyncConnectOptions = {},
): Promise<ConnectedSingleOwnerVaultSync> {
  if (client.deviceId === null) {
    throw new SyncClientError(
      "invalid_configuration",
      "The authenticated sync client is not bound to a device.",
    )
  }
  const bootstrapper = new BrowserSingleOwnerSyncBootstrap(
    apiBaseUrl,
    client.accountId,
    client.deviceId,
    options.bootstrapStore,
  )
  const signal = options.signal
  const bootstrap = await bootstrapper.publish(
    signal === undefined
      ? client
      : {
          accountId: client.accountId,
          deviceId: client.deviceId,
          putHouseholdTopology: (topology) => client.putHouseholdTopology(topology, {
            signal,
          }),
        },
    await session.listEncryptedItemIdsForSync(),
  )
  return {
    client,
    bootstrap,
    runtime: new DurableVaultSyncRuntime(
      client,
      bootstrapper.scope(bootstrap),
      session,
      options.runtimeDependencies,
    ),
  }
}

/** Reconnects locally wrapped device credentials and resumes the full lifecycle. */
export async function resumeSingleOwnerVaultSync(
  apiBaseUrl: string,
  accountId: string,
  session: VaultSyncSession,
  options: ResumeSingleOwnerVaultSyncOptions = {},
): Promise<ConnectedSingleOwnerVaultSync | null> {
  const credentials = options.credentials ?? new BrowserSyncCredentialStore()
  const client = await credentials.connect(apiBaseUrl, accountId, {
    ...(options.fetcher === undefined ? {} : { fetcher: options.fetcher }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  })
  if (client === null) return null
  return connectSingleOwnerVaultSync(client, apiBaseUrl, session, options)
}
