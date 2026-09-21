import {
  SAFEORY_ENVELOPE_MARKER,
  SAFEORY_ENVELOPE_VERSION,
} from "./safeory-envelope.mjs";

export const SAFEORY_ENVELOPE_FIXTURE_RECORD_ID =
  "11111111-1111-4111-8111-111111111111";

export function representativeSafeoryEnvelopeV1() {
  return {
    marker: SAFEORY_ENVELOPE_MARKER,
    schema_version: SAFEORY_ENVELOPE_VERSION,
    record_id: SAFEORY_ENVELOPE_FIXTURE_RECORD_ID,
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
