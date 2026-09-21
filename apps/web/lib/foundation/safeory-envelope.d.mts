export interface SafeoryEnvelopeRelationship {
  target_record_id: string
  relation: string
}

export interface SafeoryEnvelopeReminder {
  reminder_id: string
  mode: "one_time" | "recurring"
  next_date: string
  label: string
  recurrence: null | {
    frequency: "daily" | "weekly" | "monthly" | "yearly"
    interval: number
    end_date: string | null
  }
}

export interface SafeoryEnvelopeV1 {
  marker: "safeory.life_record"
  schema_version: 1
  record_id: string
  record_kind: string
  data: Record<string, unknown>
  links: string[]
  relationships: SafeoryEnvelopeRelationship[]
  reminders: SafeoryEnvelopeReminder[]
  continuity: {
    legacy_disposition:
      | "unspecified"
      | "selected_for_legacy"
      | "private_forever"
      | "destroy_on_death"
    policy_ref: string | null
  }
  extensions: Record<string, unknown>
}

export const SAFEORY_ENVELOPE_MARKER: "safeory.life_record"
export const SAFEORY_ENVELOPE_VERSION: 1
export const SAFEORY_ENVELOPE_FIXTURE_RECORD_ID: string

export function parseSafeoryEnvelopeV1(
  serialized: string,
  expectedRecordId?: string | null
): SafeoryEnvelopeV1

export function serializeSafeoryEnvelopeV1(
  value: unknown,
  expectedRecordId?: string | null
): string

export function validateSafeoryEnvelopeV1(
  value: unknown,
  expectedRecordId?: string | null
): SafeoryEnvelopeV1

export function representativeSafeoryEnvelopeV1(): SafeoryEnvelopeV1
