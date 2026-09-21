import type { Metadata } from "next"
import Link from "next/link"
import {
  ArrowLeft01Icon,
  Calendar03Icon,
  Link01Icon,
  ShieldCheckIcon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import {
  SAFEORY_ENVELOPE_FIXTURE_RECORD_ID,
  representativeSafeoryEnvelopeV1,
  validateSafeoryEnvelopeV1,
} from "@/lib/foundation/safeory-envelope.mjs"

export const metadata: Metadata = {
  title: "Foundation envelope proof · Safeory",
  description:
    "Temporary Safeory-owned route proving a validated life-record envelope can be rendered without adopting foundation frontend code.",
}

function textField(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`foundation proof fixture ${field} must be a string`)
  }
  return value
}

export default function FoundationEnvelopeProofPage() {
  const envelope = validateSafeoryEnvelopeV1(
    representativeSafeoryEnvelopeV1(),
    SAFEORY_ENVELOPE_FIXTURE_RECORD_ID
  )
  const title = textField(envelope.data.title, "data.title")
  const provider = textField(envelope.data.provider, "data.provider")
  const policyNumber = textField(
    envelope.data.policy_number,
    "data.policy_number"
  )
  const renewal = textField(envelope.data.renewal, "data.renewal")
  const notes = textField(envelope.data.notes, "data.notes")
  const reminder = envelope.reminders[0]
  const futureExtension = envelope.extensions["safeory.example.future"] as {
    preserved?: unknown
    version?: unknown
  }

  return (
    <main className="min-h-screen bg-[var(--surface)] px-5 py-8 text-[var(--text-primary)] md:px-8 md:py-12">
      <section className="mx-auto w-full max-w-4xl">
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-sm font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
        >
          <HugeiconsIcon
            icon={ArrowLeft01Icon}
            strokeWidth={2}
            className="size-4"
          />
          Back to Safeory
        </Link>

        <div className="mt-7 flex flex-col gap-5 border-b pb-7 md:flex-row md:items-start md:justify-between">
          <div className="max-w-2xl">
            <div className="mb-4 flex size-11 items-center justify-center rounded-[var(--radius-default)] border bg-[var(--surface-secondary)]">
              <HugeiconsIcon
                icon={ShieldCheckIcon}
                strokeWidth={2}
                className="size-5 text-[var(--primary)]"
              />
            </div>
            <p className="text-sm font-medium text-[var(--primary)]">
              Foundation carrier proof
            </p>
            <h1 className="mt-1 text-3xl font-semibold tracking-tight">
              {title}
            </h1>
            <p className="mt-3 max-w-[68ch] text-sm leading-6 text-pretty text-[var(--text-secondary)]">
              This temporary Safeory-owned route renders a strictly validated
              SafeoryEnvelopeV1. In the foundation proof, the same envelope is
              carried inside a blob-encrypted secure note; the server sees only
              opaque encrypted data.
            </p>
          </div>
          <span className="w-fit rounded-[var(--radius-large)] border bg-[var(--surface-secondary)] px-3 py-1 text-xs font-medium text-[var(--text-secondary)]">
            schema v{envelope.schema_version}
          </span>
        </div>

        <div className="grid gap-5 py-7 md:grid-cols-[minmax(0,1.45fr)_minmax(16rem,0.8fr)]">
          <div className="space-y-5">
            <section className="rounded-[var(--radius-default)] border bg-[var(--surface)] p-5">
              <h2 className="text-base font-semibold">Insurance details</h2>
              <dl className="mt-4 grid gap-4 sm:grid-cols-2">
                <div>
                  <dt className="text-xs font-medium tracking-wide text-[var(--text-secondary)] uppercase">
                    Provider
                  </dt>
                  <dd className="mt-1 text-sm font-medium">{provider}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium tracking-wide text-[var(--text-secondary)] uppercase">
                    Policy number
                  </dt>
                  <dd className="mt-1 text-sm font-medium">{policyNumber}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium tracking-wide text-[var(--text-secondary)] uppercase">
                    Renewal
                  </dt>
                  <dd className="mt-1 text-sm font-medium">{renewal}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium tracking-wide text-[var(--text-secondary)] uppercase">
                    Record kind
                  </dt>
                  <dd className="mt-1 text-sm font-medium">
                    {envelope.record_kind}
                  </dd>
                </div>
              </dl>
              <div className="mt-5 border-t pt-4">
                <p className="text-xs font-medium tracking-wide text-[var(--text-secondary)] uppercase">
                  Private note
                </p>
                <p className="mt-1 text-sm leading-6">{notes}</p>
              </div>
            </section>

            <section className="rounded-[var(--radius-default)] border bg-[var(--surface-secondary)] p-5">
              <div className="flex items-center gap-2">
                <HugeiconsIcon
                  icon={Calendar03Icon}
                  strokeWidth={2}
                  className="size-4 text-[var(--icon)]"
                />
                <h2 className="text-sm font-semibold">
                  Reminder carried in the envelope
                </h2>
              </div>
              <p className="mt-3 text-sm font-medium">{reminder.label}</p>
              <p className="mt-1 text-sm text-[var(--text-secondary)]">
                Next: {reminder.next_date} · {reminder.mode}
              </p>
            </section>
          </div>

          <aside className="space-y-5">
            <section className="rounded-[var(--radius-default)] border p-5">
              <h2 className="text-sm font-semibold">Foundation binding</h2>
              <dl className="mt-4 space-y-4">
                <div>
                  <dt className="text-xs text-[var(--text-secondary)]">
                    Record ID
                  </dt>
                  <dd className="mt-1 font-mono text-xs leading-5 break-all">
                    {envelope.record_id}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-[var(--text-secondary)]">
                    Marker
                  </dt>
                  <dd className="mt-1 font-mono text-xs">{envelope.marker}</dd>
                </div>
                <div>
                  <dt className="text-xs text-[var(--text-secondary)]">
                    Continuity
                  </dt>
                  <dd className="mt-1 text-sm">
                    {envelope.continuity.legacy_disposition}
                  </dd>
                </div>
              </dl>
            </section>

            <section className="rounded-[var(--radius-default)] border p-5">
              <div className="flex items-center gap-2">
                <HugeiconsIcon
                  icon={Link01Icon}
                  strokeWidth={2}
                  className="size-4 text-[var(--icon)]"
                />
                <h2 className="text-sm font-semibold">
                  Lossless extension proof
                </h2>
              </div>
              <p className="mt-3 text-sm leading-6 text-[var(--text-secondary)]">
                Unknown extension data is still present after validation and can
                round-trip without Safeory interpreting it.
              </p>
              <div className="mt-4 rounded-[var(--radius-small)] bg-[var(--surface-secondary)] p-3 font-mono text-xs leading-5">
                <div>safeory.example.future</div>
                <div className="text-[var(--text-secondary)]">
                  preserved: {String(futureExtension.preserved)} · version:{" "}
                  {String(futureExtension.version)}
                </div>
              </div>
            </section>
          </aside>
        </div>
      </section>
    </main>
  )
}
