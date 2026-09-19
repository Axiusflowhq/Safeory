import assert from "node:assert/strict";
import test from "node:test";

import { createSerializedMutationRunner } from "../src/mutation.ts";

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

test("serializes mutation snapshots before the next mutation runs", async () => {
  const state = { value: 0 };
  const firstPersistGate = deferred();
  const firstPersistStarted = deferred();
  const events: string[] = [];
  let acquireCount = 0;
  let persistCount = 0;

  const runMutation = createSerializedMutationRunner({
    acquire: async () => {
      acquireCount += 1;
      events.push(`acquire:${acquireCount}`);
      return state;
    },
    persist: async (current) => {
      persistCount += 1;
      events.push(`persist:${current.value}:start`);
      if (persistCount === 1) {
        firstPersistStarted.resolve();
        await firstPersistGate.promise;
      }
      events.push(`persist:${current.value}:end`);
    },
    discard: () => assert.fail("successful persistence must not discard state"),
  });

  const first = runMutation((current) => {
    events.push("mutate:1");
    current.value = 1;
    return current.value;
  });
  const second = runMutation((current) => {
    events.push("mutate:2");
    current.value = 2;
    return current.value;
  });

  await firstPersistStarted.promise;
  assert.deepEqual(events, ["acquire:1", "mutate:1", "persist:1:start"]);

  firstPersistGate.resolve();
  assert.deepEqual(await Promise.all([first, second]), [1, 2]);
  assert.deepEqual(events, [
    "acquire:1",
    "mutate:1",
    "persist:1:start",
    "persist:1:end",
    "acquire:2",
    "mutate:2",
    "persist:2:start",
    "persist:2:end",
  ]);
});

test("failed persistence discards mutated state before a later mutation succeeds", async () => {
  interface State {
    value: number;
    locked: boolean;
  }

  let durableValue = 0;
  let live: State | null = null;
  let failNextPersist = true;
  const discarded: State[] = [];

  const runMutation = createSerializedMutationRunner<State>({
    acquire: async () => {
      live ??= { value: durableValue, locked: false };
      return live;
    },
    persist: async (current) => {
      if (failNextPersist) {
        failNextPersist = false;
        throw new Error("disk full");
      }
      durableValue = current.value;
    },
    discard: (current) => {
      current.locked = true;
      discarded.push(current);
      if (live === current) live = null;
    },
  });

  const failed = runMutation((current) => {
    current.value += 1;
    return current.value;
  });
  const later = runMutation((current) => {
    current.value += 10;
    return current.value;
  });

  await assert.rejects(failed, /disk full/);
  assert.equal(await later, 10);
  assert.equal(durableValue, 10);
  assert.equal(discarded.length, 1);
  assert.equal(discarded[0]?.value, 1);
  assert.equal(discarded[0]?.locked, true);
  assert.equal(live?.value, 10);
});

test("reads wait until persistence finishes before observing mutated state", async () => {
  const state = { value: 0 };
  const persistStarted = deferred();
  const allowPersist = deferred();

  const runMutation = createSerializedMutationRunner({
    acquire: async () => state,
    persist: async () => {
      persistStarted.resolve();
      await allowPersist.promise;
    },
    discard: () => assert.fail("successful persistence must not discard state"),
  });

  const mutation = runMutation((current) => {
    current.value = 1;
  });
  await persistStarted.promise;

  let readResolved = false;
  const read = runMutation.access((current) => current.value).then((value) => {
    readResolved = true;
    return value;
  });
  await Promise.resolve();
  assert.equal(readResolved, false);

  allowPersist.resolve();
  await mutation;
  assert.equal(await read, 1);
});
