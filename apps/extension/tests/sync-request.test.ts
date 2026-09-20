import assert from "node:assert/strict";
import test from "node:test";

import { createSyncRequestRunner } from "../src/sync-request.ts";

function deferred(): { promise: Promise<boolean>; resolve: (value: boolean) => void } {
  let resolve!: (value: boolean) => void;
  const promise = new Promise<boolean>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

test("coalesces active triggers and runs exactly one follow-up", async () => {
  const first = deferred();
  let runs = 0;
  const runner = createSyncRequestRunner(async () => {
    runs += 1;
    return runs === 1 ? first.promise : true;
  });
  const active = runner.request();
  assert.equal(runner.request(), active);
  assert.equal(runner.request(), active);
  first.resolve(true);
  assert.equal(await active, true);
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(runs, 2);
});

test("invalidation suppresses a queued follow-up", async () => {
  const first = deferred();
  let runs = 0;
  const runner = createSyncRequestRunner(async () => {
    runs += 1;
    return first.promise;
  });
  const active = runner.request();
  void runner.request();
  runner.invalidate();
  first.resolve(false);
  assert.equal(await active, false);
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(runs, 1);
});
