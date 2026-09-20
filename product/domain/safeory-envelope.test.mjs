import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_SAFEORY_ENVELOPE_BYTES,
  SAFEORY_ENVELOPE_MARKER,
  SAFEORY_ENVELOPE_VERSION,
  validateSafeoryEnvelopeV1,
} from "./safeory-envelope.mjs";

const RECORD_ID = "11111111-1111-4111-8111-111111111111";

function fixture() {
  return {
    marker: SAFEORY_ENVELOPE_MARKER,
    schema_version: SAFEORY_ENVELOPE_VERSION,
    record_id: RECORD_ID,
    record_kind: "insurance",
    data: {
      title: "Family health policy",
      provider: "Example Mutual",
      policy_number: "POL-123",
      renewal: "2027-01-15",
      notes: "Call before renewal.",
    },
    links: ["22222222-2222-4222-8222-222222222222"],
    relationships: [
      {
        target_record_id: "33333333-3333-4333-8333-333333333333",
        relation: "covers_person",
      },
    ],
    reminders: [
      {
        reminder_id: "44444444-4444-4444-8444-444444444444",
        mode: "recurring",
        next_date: "2027-01-01",
        label: "Review insurance renewal",
        recurrence: {
          frequency: "yearly",
          interval: 1,
          end_date: null,
        },
      },
    ],
    continuity: {
      legacy_disposition: "selected_for_legacy",
      policy_ref: "55555555-5555-4555-8555-555555555555",
    },
    extensions: {
      "safeory.example.future": {
        preserved: true,
        version: 2,
      },
    },
  };
}

test("accepts representative life record and exact outer binding", () => {
  const value = fixture();
  assert.equal(validateSafeoryEnvelopeV1(value, RECORD_ID), value);
});

test("rejects outer/inner identity mismatch", () => {
  assert.throws(
    () =>
      validateSafeoryEnvelopeV1(
        fixture(),
        "99999999-9999-4999-8999-999999999999",
      ),
    /record_id does not match/,
  );
});

test("rejects unknown top-level fields instead of silently dropping them", () => {
  const value = fixture();
  value.unreviewed = true;
  assert.throws(() => validateSafeoryEnvelopeV1(value), /unknown field/);
});

test("preserves unknown extension payloads", () => {
  const value = fixture();
  value.extensions["vendor.future"] = {
    nested: ["a", "b", { supportedLater: true }],
  };
  validateSafeoryEnvelopeV1(value);
  assert.deepEqual(value.extensions["vendor.future"].nested[2], {
    supportedLater: true,
  });
});

test("rejects duplicate links and reminder identities", () => {
  const value = fixture();
  value.links.push(value.links[0]);
  assert.throws(() => validateSafeoryEnvelopeV1(value), /links contains duplicates/);

  const reminders = fixture();
  reminders.reminders.push(structuredClone(reminders.reminders[0]));
  assert.throws(
    () => validateSafeoryEnvelopeV1(reminders),
    /duplicate reminder_id/,
  );
});

test("rejects invalid calendar dates", () => {
  const value = fixture();
  value.reminders[0].next_date = "2027-02-30";
  assert.throws(() => validateSafeoryEnvelopeV1(value), /valid date/);
});

test("rejects dangerous extension keys", () => {
  const value = fixture();
  Object.defineProperty(value.extensions, "__proto__", {
    value: { polluted: true },
    enumerable: true,
    configurable: true,
  });
  assert.throws(() => validateSafeoryEnvelopeV1(value), /invalid extension key|unsafe extension key/);
});

test("rejects oversized serialized envelopes", () => {
  const value = fixture();
  value.data.notes = "x".repeat(MAX_SAFEORY_ENVELOPE_BYTES);
  assert.throws(() => validateSafeoryEnvelopeV1(value), /byte limit/);
});

test("rejects excessive nesting", () => {
  const value = fixture();
  let cursor = value.extensions;
  for (let index = 0; index < 20; index += 1) {
    cursor.next = {};
    cursor = cursor.next;
  }
  assert.throws(() => validateSafeoryEnvelopeV1(value), /nesting depth/);
});
