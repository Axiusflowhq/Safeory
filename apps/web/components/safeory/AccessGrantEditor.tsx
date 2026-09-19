"use client"

import type { TrustedPrincipal } from "@safeory/contracts"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import type {
  AccessCondition,
  AccessGrant,
  AccessPolicy,
  GrantDuration,
  Permission,
  WaitPeriod,
} from "@/lib/vault/items"
import { MAX_ACCESS_GRANTS, RECORD_ACCESS_SCOPE } from "@/lib/vault/items"

interface Props {
  policy: AccessPolicy
  principals: TrustedPrincipal[]
  onChange: (policy: AccessPolicy) => void
}

const permissionOptions: { value: Permission; label: string }[] = [
  { value: "view", label: "View" },
  { value: "download", label: "Download" },
  { value: "edit", label: "Edit" },
  { value: "share", label: "Share" },
  { value: "manage", label: "Manage" },
]

const conditionOptions: { value: AccessCondition; label: string }[] = [
  { value: "emergency", label: "Emergency" },
  { value: "incapacity", label: "Incapacity" },
  { value: "death", label: "Death" },
  { value: "normal", label: "Normal" },
]

const waitOptions: { value: Exclude<WaitPeriod, { custom: number }>; label: string }[] = [
  { value: "immediate", label: "Immediate" },
  { value: "one_hour", label: "1 hour" },
  { value: "one_day", label: "24 hours" },
  { value: "seven_days", label: "7 days" },
]

const durationOptions: {
  value: Exclude<GrantDuration, { custom: number }>
  label: string
}[] = [
  { value: "until_revoked", label: "Until revoked" },
  { value: "one_hour", label: "1 hour" },
  { value: "one_day", label: "24 hours" },
  { value: "seven_days", label: "7 days" },
]

function isSimpleRecordGrant(grant: AccessGrant): boolean {
  return (
    grant.what === RECORD_ACCESS_SCOPE &&
    grant.approvals_required === 0 &&
    grant.approver_ids.length === 0 &&
    typeof grant.wait_period === "string" &&
    typeof grant.duration === "string"
  )
}

export function AccessGrantEditor({ policy, principals, onChange }: Props) {
  const principalsById = new Map(principals.map((principal) => [principal.id, principal]))
  const editable = policy.grants
    .map((grant, index) => ({ grant, index }))
    .filter(({ grant }) => isSimpleRecordGrant(grant))
  const preservedAdvancedCount = policy.grants.length - editable.length
  const hasRecordCondition = (
    principalId: string,
    condition: AccessCondition,
    exceptIndex?: number
  ) =>
    policy.grants.some(
      (grant, index) =>
        index !== exceptIndex &&
        grant.trustee_id === principalId &&
        grant.what === RECORD_ACCESS_SCOPE &&
        grant.condition === condition
    )
  const addablePrincipals = principals.filter(
    (principal) =>
      principal.devices.length > 0 &&
      conditionOptions.some(
        (option) => !hasRecordCondition(principal.id, option.value)
      )
  )
  const grantLimitReached = policy.grants.length >= MAX_ACCESS_GRANTS

  function replaceGrant(index: number, patch: Partial<AccessGrant>) {
    const grants = policy.grants.map((grant, grantIndex) =>
      grantIndex === index ? { ...grant, ...patch } : grant
    )
    onChange({ ...policy, grants })
  }

  function removeGrant(index: number) {
    onChange({
      ...policy,
      grants: policy.grants.filter((_, grantIndex) => grantIndex !== index),
    })
  }

  function addGrant() {
    const principal = addablePrincipals[0]
    if (!principal || grantLimitReached) return
    const condition = conditionOptions.find(
      (option) => !hasRecordCondition(principal.id, option.value)
    )?.value
    if (!condition) return
    onChange({
      ...policy,
      grants: [
        ...policy.grants,
        {
          trustee_id: principal.id,
          what: RECORD_ACCESS_SCOPE,
          permission: "view",
          condition,
          wait_period: "one_day",
          duration: "until_revoked",
          approvals_required: 0,
          approver_ids: [],
        },
      ],
    })
  }

  return (
    <div className="space-y-4 rounded-[var(--radius-default)] border bg-[var(--surface-secondary)] p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h4 className="text-sm font-medium">Trusted-person access plan</h4>
            <Badge variant="outline">Encrypted</Badge>
          </div>
          <p className="mt-1 max-w-[65ch] text-sm leading-6 text-pretty text-[var(--text-secondary)]">
            These rules record access intent for this item. Saving them does not
            send keys, notify anyone, start a waiting-period timer, or release
            access.
          </p>
        </div>
        <Button
          type="button"
          variant="secondary"
          size="sm"
          onClick={addGrant}
          disabled={addablePrincipals.length === 0 || grantLimitReached}
        >
          Add access rule
        </Button>
      </div>

      {principals.length === 0 ? (
        <p className="text-sm text-[var(--text-secondary)]">
          Create an access identity under Trusted people before adding a rule.
        </p>
      ) : principals.every((principal) => principal.devices.length === 0) ? (
        <p className="text-sm text-[var(--text-secondary)]">
          Add at least one recipient-encryption device to a trusted principal
          before adding a rule.
        </p>
      ) : grantLimitReached ? (
        <p className="text-sm text-[var(--text-secondary)]">
          This item already has the maximum supported 64 access rules.
        </p>
      ) : null}

      {editable.length > 0 ? (
        <div className="space-y-3">
          {editable.map(({ grant, index }) => {
            const principal = principalsById.get(grant.trustee_id)
            const selectablePrincipals = principals.filter(
              (candidate) =>
                candidate.id === grant.trustee_id ||
                (candidate.devices.length > 0 &&
                  !hasRecordCondition(candidate.id, grant.condition, index))
            )
            return (
              <div
                key={`${grant.trustee_id}-${grant.condition}-${index}`}
                className="rounded-[var(--radius-default)] border bg-[var(--surface)] p-4"
              >
                <FieldGroup className="grid gap-4 md:grid-cols-2">
                  <Field>
                    <FieldLabel htmlFor={`safeory-grant-principal-${index}`}>
                      Principal
                    </FieldLabel>
                    <select
                      id={`safeory-grant-principal-${index}`}
                      value={grant.trustee_id}
                      onChange={(event) =>
                        replaceGrant(index, { trustee_id: event.target.value })
                      }
                      className="h-10 w-full rounded-[var(--radius-default)] border border-[var(--input-border)] bg-[var(--input-fill)] px-3 text-sm text-[var(--text-primary)] outline-none focus-visible:border-[var(--ring)] focus-visible:ring-3 focus-visible:ring-[var(--ring)]"
                    >
                      {!principal ? (
                        <option value={grant.trustee_id}>Unresolved principal</option>
                      ) : null}
                      {selectablePrincipals.map((candidate) => (
                        <option key={candidate.id} value={candidate.id}>
                          {candidate.name}
                        </option>
                      ))}
                    </select>
                    <FieldDescription>
                      {principal
                        ? `${principal.devices.length} recipient-encryption device${principal.devices.length === 1 ? "" : "s"} registered.`
                        : "This legacy trustee UUID has no matching principal and cannot be released by the current identity model."}
                    </FieldDescription>
                  </Field>

                  <Field>
                    <FieldLabel htmlFor={`safeory-grant-permission-${index}`}>
                      Permission
                    </FieldLabel>
                    <select
                      id={`safeory-grant-permission-${index}`}
                      value={grant.permission}
                      onChange={(event) =>
                        replaceGrant(index, {
                          permission: event.target.value as Permission,
                        })
                      }
                      className="h-10 w-full rounded-[var(--radius-default)] border border-[var(--input-border)] bg-[var(--input-fill)] px-3 text-sm text-[var(--text-primary)] outline-none focus-visible:border-[var(--ring)] focus-visible:ring-3 focus-visible:ring-[var(--ring)]"
                    >
                      {permissionOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </Field>

                  <Field>
                    <FieldLabel htmlFor={`safeory-grant-condition-${index}`}>
                      Condition
                    </FieldLabel>
                    <select
                      id={`safeory-grant-condition-${index}`}
                      value={grant.condition}
                      onChange={(event) =>
                        replaceGrant(index, {
                          condition: event.target.value as AccessCondition,
                        })
                      }
                      className="h-10 w-full rounded-[var(--radius-default)] border border-[var(--input-border)] bg-[var(--input-fill)] px-3 text-sm text-[var(--text-primary)] outline-none focus-visible:border-[var(--ring)] focus-visible:ring-3 focus-visible:ring-[var(--ring)]"
                    >
                      {conditionOptions.map((option) => (
                        <option
                          key={option.value}
                          value={option.value}
                          disabled={hasRecordCondition(
                            grant.trustee_id,
                            option.value,
                            index
                          )}
                        >
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </Field>

                  <Field>
                    <FieldLabel htmlFor={`safeory-grant-wait-${index}`}>
                      Waiting period
                    </FieldLabel>
                    <select
                      id={`safeory-grant-wait-${index}`}
                      value={grant.wait_period as string}
                      onChange={(event) =>
                        replaceGrant(index, {
                          wait_period: event.target.value as Exclude<
                            WaitPeriod,
                            { custom: number }
                          >,
                        })
                      }
                      className="h-10 w-full rounded-[var(--radius-default)] border border-[var(--input-border)] bg-[var(--input-fill)] px-3 text-sm text-[var(--text-primary)] outline-none focus-visible:border-[var(--ring)] focus-visible:ring-3 focus-visible:ring-[var(--ring)]"
                    >
                      {waitOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </Field>

                  <Field>
                    <FieldLabel htmlFor={`safeory-grant-duration-${index}`}>
                      Planned duration
                    </FieldLabel>
                    <select
                      id={`safeory-grant-duration-${index}`}
                      value={grant.duration as string}
                      onChange={(event) =>
                        replaceGrant(index, {
                          duration: event.target.value as Exclude<
                            GrantDuration,
                            { custom: number }
                          >,
                        })
                      }
                      className="h-10 w-full rounded-[var(--radius-default)] border border-[var(--input-border)] bg-[var(--input-fill)] px-3 text-sm text-[var(--text-primary)] outline-none focus-visible:border-[var(--ring)] focus-visible:ring-3 focus-visible:ring-[var(--ring)]"
                    >
                      {durationOptions.map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                  </Field>
                </FieldGroup>

                <div className="mt-4 flex justify-end">
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => removeGrant(index)}
                  >
                    Remove rule
                  </Button>
                </div>
              </div>
            )
          })}
        </div>
      ) : null}

      {preservedAdvancedCount > 0 ? (
        <p className="text-xs leading-5 text-[var(--text-secondary)]">
          {preservedAdvancedCount} advanced or legacy access rule
          {preservedAdvancedCount === 1 ? " is" : "s are"} preserved but not
          editable here because it uses a custom scope, custom timer, or approval
          policy.
        </p>
      ) : null}
    </div>
  )
}
