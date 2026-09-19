"use client"

import { useRef, useState } from "react"
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
import type { ItemKind, VaultItemJson } from "@/lib/vault/items"
import {
  buildEditedItem,
  buildItem,
  KIND_FIELDS,
  kindLabel,
  newId,
} from "@/lib/vault/items"

interface Props {
  existing: { item: VaultItemJson; revision: number } | null
  defaultKind: ItemKind
  onSave: (item: VaultItemJson, expectedRevision: number | null) => void
  onCancel: () => void
  generatePassword: (length: number) => string
  onTrash?: () => void
}

export function ItemEditor({
  existing,
  defaultKind,
  onSave,
  onCancel,
  generatePassword,
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
  const [revealed, setRevealed] = useState<Record<string, boolean>>({})
  const [titleError, setTitleError] = useState<string | null>(null)
  const titleInputRef = useRef<HTMLInputElement>(null)

  function setField(key: string, value: string) {
    setFields((previous) => ({ ...previous, [key]: value }))
  }

  function save() {
    if (existing) {
      onSave(
        buildEditedItem(existing.item, kind, title.trim(), fields, notes),
        existing.revision
      )
      return
    }

    const id = newId()
    onSave(buildItem(id, kind, title.trim(), fields, notes), null)
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
