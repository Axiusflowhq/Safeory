export const SAFEORY_ENVELOPE_MARKER = "safeory.life_record";
export const SAFEORY_ENVELOPE_VERSION = 1;
export const MAX_SAFEORY_ENVELOPE_BYTES = 256 * 1024;
export const MAX_SAFEORY_LINKS = 256;
export const MAX_SAFEORY_RELATIONSHIPS = 256;
export const MAX_SAFEORY_REMINDERS = 64;
export const MAX_SAFEORY_EXTENSIONS = 64;

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const KIND_RE = /^[a-z][a-z0-9_]{0,63}$/;
const EXTENSION_KEY_RE = /^[a-z][a-z0-9_.-]{0,63}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const LEGACY_DISPOSITIONS = new Set([
  "unspecified",
  "selected_for_legacy",
  "private_forever",
  "destroy_on_death",
]);
const REMINDER_MODES = new Set(["one_time", "recurring"]);
const RECURRENCE_FREQUENCIES = new Set(["daily", "weekly", "monthly", "yearly"]);
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const TOP_LEVEL_KEYS = new Set([
  "marker",
  "schema_version",
  "record_id",
  "record_kind",
  "data",
  "links",
  "relationships",
  "reminders",
  "continuity",
  "extensions",
]);

function assert(condition, message) {
  if (!condition) {
    throw new TypeError("SafeoryEnvelopeV1: " + message);
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value, allowed, context) {
  for (const key of Object.keys(value)) {
    assert(allowed.has(key), context + " contains unknown field " + key);
  }
}

function assertUuid(value, context) {
  assert(typeof value === "string" && UUID_RE.test(value), context + " must be a UUID");
}

function assertDate(value, context) {
  assert(typeof value === "string" && DATE_RE.test(value), context + " must be YYYY-MM-DD");
  const parsed = new Date(value + "T00:00:00Z");
  assert(!Number.isNaN(parsed.valueOf()), context + " must be a valid date");
  assert(parsed.toISOString().slice(0, 10) === value, context + " must be a valid date");
}

function validateJsonTree(value, context, state, depth = 0) {
  assert(depth <= 16, context + " exceeds maximum nesting depth");
  state.nodes += 1;
  assert(state.nodes <= 4096, context + " exceeds maximum JSON node count");

  if (value === null || typeof value === "boolean") return;

  if (typeof value === "number") {
    assert(Number.isFinite(value), context + " contains a non-finite number");
    return;
  }

  if (typeof value === "string") {
    assert(value.length <= 65_536, context + " contains an oversized string");
    return;
  }

  if (Array.isArray(value)) {
    assert(value.length <= 1024, context + " contains an oversized array");
    for (let index = 0; index < value.length; index += 1) {
      validateJsonTree(value[index], context + "[" + index + "]", state, depth + 1);
    }
    return;
  }

  assert(isRecord(value), context + " contains a non-JSON value");
  const keys = Object.keys(value);
  assert(keys.length <= 1024, context + " contains an oversized object");
  for (const key of keys) {
    assert(!DANGEROUS_KEYS.has(key), context + " contains unsafe key " + key);
    assert(key.length <= 128, context + " contains an oversized key");
    validateJsonTree(value[key], context + "." + key, state, depth + 1);
  }
}

function validateReminder(reminder, index) {
  const context = "reminders[" + index + "]";
  assert(isRecord(reminder), context + " must be an object");
  assertExactKeys(
    reminder,
    new Set(["reminder_id", "mode", "next_date", "label", "recurrence"]),
    context,
  );
  assertUuid(reminder.reminder_id, context + ".reminder_id");
  assert(REMINDER_MODES.has(reminder.mode), context + ".mode is unsupported");
  assertDate(reminder.next_date, context + ".next_date");
  assert(
    typeof reminder.label === "string" && reminder.label.length <= 128,
    context + ".label is invalid",
  );

  if (reminder.mode === "one_time") {
    assert(reminder.recurrence === null, context + ".recurrence must be null");
    return;
  }

  assert(isRecord(reminder.recurrence), context + ".recurrence must be an object");
  assertExactKeys(
    reminder.recurrence,
    new Set(["frequency", "interval", "end_date"]),
    context + ".recurrence",
  );
  assert(
    RECURRENCE_FREQUENCIES.has(reminder.recurrence.frequency),
    context + ".recurrence.frequency is unsupported",
  );
  assert(
    Number.isSafeInteger(reminder.recurrence.interval) &&
      reminder.recurrence.interval >= 1 &&
      reminder.recurrence.interval <= 365,
    context + ".recurrence.interval is invalid",
  );
  if (reminder.recurrence.end_date !== null) {
    assertDate(reminder.recurrence.end_date, context + ".recurrence.end_date");
  }
}

export function validateSafeoryEnvelopeV1(value, expectedRecordId = null) {
  assert(isRecord(value), "envelope must be an object");

  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new TypeError("SafeoryEnvelopeV1: envelope must be JSON serializable");
  }
  assert(typeof serialized === "string", "envelope must be JSON serializable");
  assert(
    new TextEncoder().encode(serialized).byteLength <= MAX_SAFEORY_ENVELOPE_BYTES,
    "serialized envelope exceeds byte limit",
  );

  assertExactKeys(value, TOP_LEVEL_KEYS, "envelope");
  assert(value.marker === SAFEORY_ENVELOPE_MARKER, "marker is invalid");
  assert(value.schema_version === SAFEORY_ENVELOPE_VERSION, "schema_version is unsupported");
  assertUuid(value.record_id, "record_id");
  if (expectedRecordId !== null) {
    assertUuid(expectedRecordId, "expectedRecordId");
    assert(value.record_id === expectedRecordId, "record_id does not match outer foundation record");
  }
  assert(
    typeof value.record_kind === "string" && KIND_RE.test(value.record_kind),
    "record_kind is invalid",
  );

  assert(isRecord(value.data), "data must be an object");
  validateJsonTree(value.data, "data", { nodes: 0 });

  assert(Array.isArray(value.links), "links must be an array");
  assert(value.links.length <= MAX_SAFEORY_LINKS, "too many links");
  const links = new Set();
  for (let index = 0; index < value.links.length; index += 1) {
    const link = value.links[index];
    assertUuid(link, "links[" + index + "]");
    assert(!links.has(link), "links contains duplicates");
    links.add(link);
  }

  assert(Array.isArray(value.relationships), "relationships must be an array");
  assert(value.relationships.length <= MAX_SAFEORY_RELATIONSHIPS, "too many relationships");
  for (let index = 0; index < value.relationships.length; index += 1) {
    const relationship = value.relationships[index];
    const context = "relationships[" + index + "]";
    assert(isRecord(relationship), context + " must be an object");
    assertExactKeys(relationship, new Set(["target_record_id", "relation"]), context);
    assertUuid(relationship.target_record_id, context + ".target_record_id");
    assert(
      typeof relationship.relation === "string" &&
        relationship.relation.length >= 1 &&
        relationship.relation.length <= 64 &&
        KIND_RE.test(relationship.relation),
      context + ".relation is invalid",
    );
  }

  assert(Array.isArray(value.reminders), "reminders must be an array");
  assert(value.reminders.length <= MAX_SAFEORY_REMINDERS, "too many reminders");
  const reminderIds = new Set();
  for (let index = 0; index < value.reminders.length; index += 1) {
    validateReminder(value.reminders[index], index);
    const reminderId = value.reminders[index].reminder_id;
    assert(!reminderIds.has(reminderId), "reminders contains duplicate reminder_id");
    reminderIds.add(reminderId);
  }

  assert(isRecord(value.continuity), "continuity must be an object");
  assertExactKeys(value.continuity, new Set(["legacy_disposition", "policy_ref"]), "continuity");
  assert(
    LEGACY_DISPOSITIONS.has(value.continuity.legacy_disposition),
    "continuity.legacy_disposition is unsupported",
  );
  if (value.continuity.policy_ref !== null) {
    assertUuid(value.continuity.policy_ref, "continuity.policy_ref");
  }

  assert(isRecord(value.extensions), "extensions must be an object");
  const extensionKeys = Object.keys(value.extensions);
  assert(extensionKeys.length <= MAX_SAFEORY_EXTENSIONS, "too many extensions");
  for (const key of extensionKeys) {
    assert(EXTENSION_KEY_RE.test(key), "invalid extension key " + key);
    assert(!DANGEROUS_KEYS.has(key), "unsafe extension key " + key);
  }
  validateJsonTree(value.extensions, "extensions", { nodes: 0 });

  return value;
}
