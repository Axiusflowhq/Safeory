/** Coalesces overlapping triggers and guarantees one follow-up after an active run. */
export function createSyncRequestRunner(
  run: () => Promise<boolean>,
): { request: () => Promise<boolean>; invalidate: () => void } {
  let generation = 0;
  let pending: Promise<boolean> | null = null;
  let queued = false;

  const request = (): Promise<boolean> => {
    if (pending !== null) {
      queued = true;
      return pending;
    }
    const currentGeneration = generation;
    const task = run().finally(() => {
      if (pending !== task) return;
      pending = null;
      if (queued && generation === currentGeneration) {
        queued = false;
        queueMicrotask(() => void request());
      }
    });
    pending = task;
    return task;
  };

  return {
    request,
    invalidate: () => {
      generation += 1;
      pending = null;
      queued = false;
    },
  };
}
