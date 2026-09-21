import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_SAFEORY_ENVELOPE_BYTES,
  parseSafeoryEnvelopeV1,
  serializeSafeoryEnvelopeV1,
  validateSafeoryEnvelopeV1,
} from "./safeory-envelope.mjs";
import {
  SAFEORY_ENVELOPE_FIXTURE_RECORD_ID as RECORD_ID,
  representativeSafeoryEnvelopeV1,
} from "./safeory-envelope-fixture.mjs";

function fixture() {
  return representativeSafeoryEnvelopeV1();
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

test("rejects corrupted marker and schema version", () => {
  const marker = fixture();
  marker.marker = "safeory.other";
  assert.throws(() => validateSafeoryEnvelopeV1(marker), /marker is invalid/);

  const version = fixture();
  version.schema_version = 99;
  assert.throws(
    () => validateSafeoryEnvelopeV1(version),
    /schema_version is unsupported/,
  );
});

test("parses serialized envelopes and rejects malformed JSON", () => {
  const serialized = JSON.stringify(fixture());
  assert.equal(
    parseSafeoryEnvelopeV1(serialized, RECORD_ID).record_id,
    RECORD_ID,
  );
  assert.throws(
    () => parseSafeoryEnvelopeV1('{"marker":"safeory.life_record",'),
    /invalid JSON/,
  );
});

test("validated serialization round-trips extension data losslessly", () => {
  const value = fixture();
  value.extensions["vendor.future"] = {
    nested: ["a", { later: true }],
  };
  const serialized = serializeSafeoryEnvelopeV1(value, RECORD_ID);
  const restored = parseSafeoryEnvelopeV1(serialized, RECORD_ID);
  assert.deepEqual(restored, value);
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
  assert.throws(
    () => validateSafeoryEnvelopeV1(value),
    /links contains duplicates/,
  );

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
  assert.throws(
    () => validateSafeoryEnvelopeV1(value),
    /invalid extension key|unsafe extension key/,
  );
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
