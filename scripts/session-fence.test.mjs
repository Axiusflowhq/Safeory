import assert from "node:assert/strict";
import test from "node:test";
import { SessionFence } from "../apps/desktop/src/sessionFence.ts";

test("invalidating a session rejects delayed work from the previous generation", () => {
  const fence = new SessionFence();
  const delayedWorkToken = fence.token();

  fence.invalidate();

  assert.equal(fence.accepts(delayedWorkToken), false);
  assert.equal(fence.accepts(fence.token()), true);
});
