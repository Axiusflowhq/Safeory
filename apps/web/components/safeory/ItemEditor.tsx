"use client"

import { useRef, useState } from "react"
import type { TrustedPrincipal } from "@safeory/contracts"
import { SparklesIcon, ViewIcon, ViewOffIcon } from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "@/components/ui/input-group"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { Textarea } from "@/components/ui/textarea"
import { AccessGrantEditor } from "@/components/safeory/AccessGrantEditor"
import type {
  AccessPolicy,
  AccountClosureDisposition,
  ItemKind,
  LegacyDisposition,
  VaultItemJson,
} from "@/lib/vault/items"
import {
  buildEditedItem,
  buildItem,
  KIND_FIELDS,
  kindLabel,
  newId,
  ownerOnlyAccessPolicy,
} from "@/lib/vault/items"

interface Props {
  existing: { item: VaultItemJson; revision: number } | null
  defaultKind: ItemKind
  onSave: (
    item: VaultItemJson,
    expectedRevision: number | null
  ) => void | Promise<void>
  onCancel: () => void
  generatePassword: (length: number) => string
  trustedPrincipals: TrustedPrincipal[]
  onTrash?: () => void | Promise<void>
}

export function ItemEditor({
  existing,
  defaultKind,
  onSave,
  onCancel,
  generatePassword,
  trustedPrincipals,
  onTrash,
}: Props) {
  const isEdit = existing !== null
  const kind: ItemKind =
    isEdit && existing.item.kind !== undefined
      ? (existing.item.kind as ItemKind)
      : defaultKind
  const specs = KIND_FIELDS[kind] ?? []

  const [title, setTitle] = useState(existing?.item.title ?? "")
  const [fields, setFields] = useState<Record<string, string>>(() => {
    const initialFields: Record<string, string> = {}
    for (const spec of specs) {
      initialFields[spec.key] = existing?.item.fields[spec.key] ?? ""
    }
    return initialFields
  })
  const [notes, setNotes] = useState(existing?.item.notes ?? "")
  const [legacyDisposition, setLegacyDisposition] = useState<LegacyDisposition>(
    existing?.item.legacy_disposition ?? "unspecified"
  )
  const [accountClosureDisposition, setAccountClosureDisposition] =
    useState<AccountClosureDisposition>(
      existing?.item.account_closure_plan.disposition ?? "unspecified"
    )
  const [accountClosureInstructions, setAccountClosureInstructions] = useState(
    existing?.item.account_closure_plan.instructions ?? ""
  )
  const [accessPolicy, setAccessPolicy] = useState<AccessPolicy>(
    existing?.item.access_policy ?? ownerOnlyAccessPolicy()
  )
  const [revealed, setRevealed] = useState<Record<string, boolean>>({})
  const [titleError, setTitleError] = useState<string | null>(null)
  const titleInputRef = useRef<HTMLInputElement>(null)

  function setField(key: string, value: string) {
    setFields((previous) => ({ ...previous, [key]: value }))
  }

  function save() {
    const planning = {
      legacyDisposition,
      accountClosurePlan: {
        disposition: accountClosureDisposition,
        instructions: accountClosureInstructions,
      },
      accessPolicy,
    }
    if (existing) {
      onSave(
        buildEditedItem(
          existing.item,
          kind,
          title.trim(),
          fields,
          notes,
          planning
        ),
        existing.revision
      )
      return
    }

    const id = newId()
    onSave(buildItem(id, kind, title.trim(), fields, notes, planning), null)
  }

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault()
        if (title.trim().length === 0) {
          setTitleError("Enter a title so you can find this item later.")
          titleInputRef.current?.focus()
          return
        }
        setTitleError(null)
        save()
      }}
      className="space-y-6"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">
            {isEdit ? "Edit item" : "Add to vault"}
          </h2>
          <p className="mt-1 max-w-[65ch] text-sm text-pretty text-[var(--text-secondary)]">
            {isEdit
              ? "Update the encrypted details for this item."
              : "Details are encrypted before they are stored in your vault."}
          </p>
        </div>
        <Badge variant="secondary">{kindLabel(kind)}</Badge>
      </div>

      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="safeory-item-title">Title</FieldLabel>
          <Input
            ref={titleInputRef}
            id="safeory-item-title"
            autoFocus
            value={title}
            onChange={(event) => {
              setTitle(event.target.value)
              if (titleError) setTitleError(null)
            }}
            placeholder="A name you will recognize"
            className="h-10"
            aria-invalid={titleError ? true : undefined}
            aria-describedby={
              titleError
                ? "safeory-item-title-help safeory-item-title-error"
                : "safeory-item-title-help"
            }
          />
          <FieldDescription id="safeory-item-title-help">
            Use a clear name so this item is easy to find later.
          </FieldDescription>
          {titleError ? (
            <FieldError id="safeory-item-title-error">{titleError}</FieldError>
          ) : null}
        </Field>

        <Separator />

        {specs.map((spec) => {
          const fieldId = `safeory-item-${spec.key}`
          const value = fields[spec.key] ?? ""

          if (spec.kind === "textarea") {
            return (
              <Field key={spec.key}>
                <FieldLabel htmlFor={fieldId}>{spec.label}</FieldLabel>
                <Textarea
                  id={fieldId}
                  value={value}
                  onChange={(event) => setField(spec.key, event.target.value)}
                  placeholder={spec.placeholder ?? spec.label}
                  rows={7}
                  className="min-h-36 resize-y"
                />
              </Field>
            )
          }

          if (spec.kind === "secret") {
            const shown = revealed[spec.key] ?? false
            const isPasswordField =
              kind === "password" && spec.key === "password"

            return (
              <Field key={spec.key}>
                <FieldLabel htmlFor={fieldId}>{spec.label}</FieldLabel>
                <InputGroup className="h-10">
                  <InputGroupInput
                    id={fieldId}
                    type={shown ? "text" : "password"}
                    value={value}
                    onChange={(event) => setField(spec.key, event.target.value)}
                    placeholder={spec.placeholder ?? spec.label}
                    autoComplete="off"
                    className="font-mono"
                  />
                  <InputGroupAddon align="inline-end">
                    {isPasswordField ? (
                      <InputGroupButton
                        aria-label="Generate strong password"
                        title="Generate strong password"
                        onClick={() => setField(spec.key, generatePassword(20))}
                      >
                        <HugeiconsIcon icon={SparklesIcon} strokeWidth={2} />
                        <span className="hidden sm:inline">Generate</span>
                      </InputGroupButton>
                    ) : null}
                    <InputGroupButton
                      size="icon-xs"
                      aria-label={
                        shown ? `Hide ${spec.label}` : `Show ${spec.label}`
                      }
                      title={
                        shown ? `Hide ${spec.label}` : `Show ${spec.label}`
                      }
                      onClick={() =>
                        setRevealed((previous) => ({
                          ...previous,
                          [spec.key]: !shown,
                        }))
                      }
                    >
                      <span
                        aria-hidden="true"
                        className="relative size-3.5 shrink-0"
                      >
                        <HugeiconsIcon
                          icon={ViewIcon}
                          strokeWidth={2}
                          className={
                            shown
                              ? "absolute inset-0 size-3.5 scale-75 opacity-0 blur-[4px] motion-safe:transition-[transform,opacity,filter] motion-safe:duration-150 motion-safe:ease-out"
                              : "blur-0 absolute inset-0 size-3.5 scale-100 opacity-100 motion-safe:transition-[transform,opacity,filter] motion-safe:duration-150 motion-safe:ease-out"
                          }
                        />
                        <HugeiconsIcon
                          icon={ViewOffIcon}
                          strokeWidth={2}
                          className={
                            shown
                              ? "blur-0 absolute inset-0 size-3.5 scale-100 opacity-100 motion-safe:transition-[transform,opacity,filter] motion-safe:duration-150 motion-safe:ease-out"
                              : "absolute inset-0 size-3.5 scale-25 opacity-0 blur-[4px] motion-safe:transition-[transform,opacity,filter] motion-safe:duration-150 motion-safe:ease-out"
                          }
                        />
                      </span>
                    </InputGroupButton>
                  </InputGroupAddon>
                </InputGroup>
              </Field>
            )
          }

          return (
            <Field key={spec.key}>
              <FieldLabel htmlFor={fieldId}>{spec.label}</FieldLabel>
              <Input
                id={fieldId}
                type={spec.kind === "date" ? "date" : "text"}
                value={value}
                onChange={(event) => setField(spec.key, event.target.value)}
                placeholder={spec.placeholder ?? spec.label}
                className="h-10"
              />
            </Field>
          )
        })}

        {kind !== "secure_note" ? (
          <>
            <Separator />
            <Field>
              <FieldLabel htmlFor="safeory-item-notes">Notes</FieldLabel>
              <Textarea
                id="safeory-item-notes"
                value={notes}
                onChange={(event) => setNotes(event.target.value)}
                placeholder="Optional private notes"
                rows={4}
                className="min-h-24 resize-y"
              />
            </Field>
          </>
        ) : null}

        <Separator />

        <div className="space-y-4">
          <div>
            <h3 className="text-sm font-medium">Continuity planning</h3>
            <p className="mt-1 max-w-[65ch] text-sm leading-6 text-pretty text-[var(--text-secondary)]">
              These encrypted preferences record your intent only. Safeory does
              not automatically share this item, delete it, or carry out account
              actions from these settings.
            </p>
          </div>

          <Field>
            <FieldLabel htmlFor="safeory-item-legacy-disposition">
              Legacy preference
            </FieldLabel>
            <select
              id="safeory-item-legacy-disposition"
              value={legacyDisposition}
              onChange={(event) =>
                setLegacyDisposition(event.target.value as LegacyDisposition)
              }
              className="h-10 w-full rounded-[var(--radius-default)] border border-[var(--input-border)] bg-[var(--input-fill)] px-3 text-sm text-[var(--text-primary)] outline-none focus-visible:border-[var(--ring)] focus-visible:ring-3 focus-visible:ring-[var(--ring)]"
            >
              <option value="unspecified">Unspecified</option>
              <option value="selected_for_legacy">Selected for legacy</option>
              <option value="private_forever">Keep private forever</option>
              <option value="destroy_on_death">Destroy on death</option>
            </select>
            <FieldDescription>
              “Destroy on death” is a planning preference only. It does not
              automatically delete this item.
            </FieldDescription>
          </Field>

          {kind === "password" ? (
            <>
              <Field>
                <FieldLabel htmlFor="safeory-item-account-closure">
                  Account closure preference
                </FieldLabel>
                <select
                  id="safeory-item-account-closure"
                  value={accountClosureDisposition}
                  onChange={(event) =>
                    setAccountClosureDisposition(
                      event.target.value as AccountClosureDisposition
                    )
                  }
                  className="h-10 w-full rounded-[var(--radius-default)] border border-[var(--input-border)] bg-[var(--input-fill)] px-3 text-sm text-[var(--text-primary)] outline-none focus-visible:border-[var(--ring)] focus-visible:ring-3 focus-visible:ring-[var(--ring)]"
                >
                  <option value="unspecified">Unspecified</option>
                  <option value="keep_open">Keep account open</option>
                  <option value="close_account">Close account</option>
                  <option value="review_manually">Review manually</option>
                </select>
                <FieldDescription>
                  Safeory does not contact the provider or close this account
                  automatically.
                </FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="safeory-item-account-closure-instructions">
                  Closure instructions
                </FieldLabel>
                <Textarea
                  id="safeory-item-account-closure-instructions"
                  value={accountClosureInstructions}
                  onChange={(event) =>
                    setAccountClosureInstructions(event.target.value)
                  }
                  placeholder="Optional notes for a future manual review"
                  rows={3}
                  className="min-h-20 resize-y"
                />
                <FieldDescription>
                  Encrypted planning notes only; they do not trigger account
                  closure or sharing.
                </FieldDescription>
              </Field>
            </>
          ) : null}

          <AccessGrantEditor
            policy={accessPolicy}
            principals={trustedPrincipals}
            onChange={setAccessPolicy}
          />
        </div>
      </FieldGroup>

      <div className="flex flex-col gap-3 border-t pt-5 sm:flex-row sm:items-center sm:justify-between">
        <div>
          {isEdit && onTrash ? (
            <Button type="button" variant="destructive" onClick={onTrash}>
              Move to trash
            </Button>
          ) : null}
        </div>
        <div className="flex flex-col-reverse gap-2 sm:flex-row">
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="submit">{isEdit ? "Save changes" : "Add item"}</Button>
        </div>
      </div>
    </form>
  )
}
