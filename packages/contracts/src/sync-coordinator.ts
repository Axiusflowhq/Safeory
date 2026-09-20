import { SyncClient } from "./sync-client"
import { SyncClientError } from "./sync-error"
import {
  DurableSyncPuller,
  type AcceptPulledObject,
  type SyncPullResult,
} from "./sync-pull"
import {
  DurableSyncOutbox,
  type SyncFlushResult,
} from "./sync-queue"

export interface SyncCycleOptions {
  pullLimit?: number
  pushLimit?: number
  signal?: AbortSignal
  /** Runs after remote acceptance and before any queued upload is attempted. */
  beforePush?: () => Promise<void>
}

export interface SyncCycleResult {
  pull: SyncPullResult
  push: SyncFlushResult
}

/**
 * Serializes bounded pull-then-push cycles for one authenticated account.
 *
 * Pull runs first so remotely committed revisions reach the application's
 * durable acceptance path before queued local mutations are attempted. A
 * successful push is intentionally observed again by a later pull; acceptance
 * callbacks must remain idempotent, as required by DurableSyncPuller.
 */
export class DurableSyncCoordinator {
  private pending: Promise<void> = Promise.resolve()

  constructor(
    private readonly client: SyncClient,
    private readonly outbox: DurableSyncOutbox,
    private readonly puller: DurableSyncPuller,
  ) {
    if (
      client.accountId !== outbox.accountId ||
      client.accountId !== puller.accountId
    ) {
      throw new SyncClientError(
        "invalid_configuration",
        "The sync client, outbox, and pull cursor must use the same account.",
      )
    }
  }

  syncOnce(
    accept: AcceptPulledObject,
    options: SyncCycleOptions = {},
  ): Promise<SyncCycleResult> {
    const cycle = this.pending.then(() => this.runCycle(accept, options))
    this.pending = cycle.then(
      () => undefined,
      () => undefined,
    )
    return cycle
  }

  private async runCycle(
    accept: AcceptPulledObject,
    options: SyncCycleOptions,
  ): Promise<SyncCycleResult> {
    const pull = await this.puller.pullPage(this.client, accept, {
      ...(options.pullLimit === undefined ? {} : { limit: options.pullLimit }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    })
    await options.beforePush?.()
    const push = await this.outbox.flush(this.client, {
      ...(options.pushLimit === undefined ? {} : { limit: options.pushLimit }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    })
    return { pull, push }
  }
}
