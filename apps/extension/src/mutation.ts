export interface SerializedMutationOptions<State> {
  acquire: () => Promise<State>;
  persist: (state: State) => Promise<void>;
  discard: (state: State) => void;
}

export interface SerializedMutationRunner<State> {
  <T>(mutate: (state: State) => T): Promise<T>;
  access<T>(operation: (state: State) => T | Promise<T>): Promise<T>;
}

/**
 * Runs state mutations one at a time, persisting each mutation before the next
 * one can acquire state. A persistence failure discards the mutated state and
 * does not poison the queue, so the next operation can reacquire durable state.
 */
export function createSerializedMutationRunner<State>({
  acquire,
  persist,
  discard,
}: SerializedMutationOptions<State>): SerializedMutationRunner<State> {
  let tail: Promise<void> = Promise.resolve();

  function enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = tail.then(operation, operation);
    tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  const runMutation = function runMutation<T>(mutate: (state: State) => T): Promise<T> {
    return enqueue(async () => {
      const current = await acquire();
      const result = mutate(current);

      try {
        await persist(current);
      } catch (error) {
        discard(current);
        throw error;
      }

      return result;
    });
  };

  runMutation.access = <T>(operation: (state: State) => T | Promise<T>) =>
    enqueue(async () => operation(await acquire()));

  return runMutation;
}
