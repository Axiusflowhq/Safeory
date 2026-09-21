import assert from "node:assert/strict";
import test from "node:test";

import { saveCapturedCredential } from "../src/credential-capture.ts";
import type { CaptureCredentialRequest } from "../src/messages.ts";

interface StoredItem {
  item: Record<string, unknown>;
  revision: number;
}

class FakeVault {
  unlocked = true;
  readonly items = new Map<string, StoredItem>();
  lastExpectedRevision: bigint | null = null;

  isUnlocked(): boolean {
    return this.unlocked;
  }

  getItemJson(id: string): string {
    const stored = this.items.get(id);
    if (!stored) throw new Error("not found");
    return JSON.stringify(stored.item);
  }

  putItemJson(itemJson: string): void {
    const item = JSON.parse(itemJson) as { id: string };
    if (this.items.has(item.id)) throw new Error("duplicate");
    this.items.set(item.id, { item, revision: 0 });
  }

  updateItemJson(itemJson: string, expectedRevision: bigint): bigint {
    const item = JSON.parse(itemJson) as { id: string };
    const stored = this.items.get(item.id);
    if (!stored || BigInt(stored.revision) !== expectedRevision)
      throw new Error("stale");
    this.lastExpectedRevision = expectedRevision;
    const revision = stored.revision + 1;
    this.items.set(item.id, { item, revision });
    return BigInt(revision);
  }
}

function request(
  overrides: Partial<CaptureCredentialRequest> = {},
): CaptureCredentialRequest {
  return {
    type: "captureCredential",
    authorization: "one-shot",
    title: "Example sign in",
    username: "alice@example.com",
    password: "new-password",
    ...overrides,
  };
}

test("captured credentials bind website to the trusted sender origin", () => {
  const vault = new FakeVault();
  const result = saveCapturedCredential(
    vault,
    "https://example.com",
    request(),
    () => "11111111-1111-4111-8111-111111111111",
  );

  assert.deepEqual(result, { type: "capture", ok: true, action: "created" });
  const stored = vault.items.get("11111111-1111-4111-8111-111111111111");
  assert.ok(stored);
  assert.equal(stored.revision, 0);
  assert.deepEqual(stored.item.fields, {
    username: "alice@example.com",
    password: "new-password",
    website: "https://example.com",
  });
});

test("capture update uses the redacted revision CAS and preserves record metadata", () => {
  const vault = new FakeVault();
  const id = "22222222-2222-4222-8222-222222222222";
  vault.items.set(id, {
    revision: 7,
    item: {
      id,
      kind: "password",
      title: "Preserve this title",
      links: ["linked-record"],
      attachments: [],
      legacy_disposition: "unspecified",
      account_closure_plan: {
        disposition: "unspecified",
        instructions: "keep",
      },
      fields: {
        username: "old-user",
        password: "old-password",
        website: "https://example.com",
        custom: "keep-me",
      },
      notes: "keep notes",
    },
  });

  const result = saveCapturedCredential(
    vault,
    "https://example.com",
    request({ existing: { id, revision: 7 } }),
  );

  assert.deepEqual(result, { type: "capture", ok: true, action: "updated" });
  assert.equal(vault.lastExpectedRevision, 7n);
  const stored = vault.items.get(id);
  assert.equal(stored?.revision, 8);
  assert.equal(stored?.item.title, "Preserve this title");
  assert.equal(stored?.item.notes, "keep notes");
  assert.deepEqual(stored?.item.links, ["linked-record"]);
  assert.deepEqual(stored?.item.fields, {
    username: "alice@example.com",
    password: "new-password",
    website: "https://example.com",
    custom: "keep-me",
  });
});

test("capture update rejects cross-origin target substitution", () => {
  const vault = new FakeVault();
  const id = "33333333-3333-4333-8333-333333333333";
  vault.items.set(id, {
    revision: 2,
    item: {
      id,
      kind: "password",
      title: "Other origin",
      fields: {
        username: "other",
        password: "secret",
        website: "https://other.example",
      },
    },
  });

  const result = saveCapturedCredential(
    vault,
    "https://example.com",
    request({ existing: { id, revision: 2 } }),
  );

  assert.deepEqual(result, {
    type: "capture",
    ok: false,
    error: "origin mismatch",
  });
  assert.equal(vault.items.get(id)?.revision, 2);
});

test("capture update fails closed on a stale summary revision", () => {
  const vault = new FakeVault();
  const id = "44444444-4444-4444-8444-444444444444";
  vault.items.set(id, {
    revision: 5,
    item: {
      id,
      kind: "password",
      title: "Current",
      fields: {
        username: "current-user",
        password: "current-password",
        website: "https://example.com",
      },
    },
  });

  const result = saveCapturedCredential(
    vault,
    "https://example.com",
    request({ existing: { id, revision: 4 } }),
  );

  assert.deepEqual(result, {
    type: "capture",
    ok: false,
    error: "credential changed; retry from the page",
  });
  assert.equal(vault.items.get(id)?.revision, 5);
});

test("capture refuses secrets while locked", () => {
  const vault = new FakeVault();
  vault.unlocked = false;
  assert.deepEqual(
    saveCapturedCredential(vault, "https://example.com", request()),
    {
      type: "capture",
      ok: false,
      error: "locked",
    },
  );
  assert.equal(vault.items.size, 0);
});
