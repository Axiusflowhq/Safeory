"use client"

import { useState } from "react"
import type { EmergencyCard } from "@safeory/contracts"
import { IdCardIcon } from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Textarea } from "@/components/ui/textarea"

interface Props {
  initial: EmergencyCard | null
  onSaveInstructions: (instructions: string) => void
}

export function EmergencyCardEditor({ initial, onSaveInstructions }: Props) {
  const [instructions, setInstructions] = useState(initial?.instructions ?? "")

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault()
        onSaveInstructions(instructions)
      }}
      className="space-y-6"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <div className="flex size-9 items-center justify-center rounded-[var(--radius-default)] border bg-[var(--surface-secondary)]">
              <HugeiconsIcon
                icon={IdCardIcon}
                strokeWidth={1.8}
                className="size-4 text-[var(--icon-active)]"
              />
            </div>
            <div>
              <h2 className="text-lg font-semibold tracking-tight">
                Emergency card
              </h2>
              <p className="max-w-[65ch] text-sm text-pretty text-[var(--text-secondary)]">
                Private instructions for what should happen in an emergency.
              </p>
            </div>
          </div>
        </div>
        <Badge variant="outline">Encrypted</Badge>
      </div>

      <Field>
        <FieldLabel htmlFor="safeory-emergency-instructions">
          Instructions for trusted people
        </FieldLabel>
        <Textarea
          id="safeory-emergency-instructions"
          value={instructions}
          onChange={(event) => setInstructions(event.target.value)}
          rows={5}
          placeholder="What should happen, who to contact, where important things are…"
          className="min-h-28 resize-y"
        />
        <FieldDescription>
          Keep this concise and actionable. These instructions stay encrypted in
          your vault.
        </FieldDescription>
      </Field>

      <div className="flex justify-end border-t pt-5">
        <Button type="submit">Save emergency card</Button>
      </div>
    </form>
  )
}
