"use client"

import { useState } from "react"
import { LockPasswordIcon } from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"

interface Props {
  onChangePassphrase: (
    currentPassphrase: string,
    newPassphrase: string
  ) => Promise<boolean>
}

export function PassphraseChangePanel({ onChangePassphrase }: Props) {
  const [currentPassphrase, setCurrentPassphrase] = useState("")
  const [newPassphrase, setNewPassphrase] = useState("")
  const [confirmPassphrase, setConfirmPassphrase] = useState("")
  const [localError, setLocalError] = useState<string | null>(null)
  const [changed, setChanged] = useState(false)
  const [busy, setBusy] = useState(false)

  async function submit() {
    setLocalError(null)
    setChanged(false)
    if (newPassphrase.length < 12) {
      setLocalError("Use at least 12 characters for the new master passphrase.")
      return
    }
    if (newPassphrase !== confirmPassphrase) {
      setLocalError("The new passphrase confirmation does not match.")
      return
    }
    if (newPassphrase === currentPassphrase) {
      setLocalError(
        "Choose a new passphrase that differs from the current one."
      )
      return
    }
    setBusy(true)
    try {
      const saved = await onChangePassphrase(currentPassphrase, newPassphrase)
      if (!saved) return
      setCurrentPassphrase("")
      setNewPassphrase("")
      setConfirmPassphrase("")
      setChanged(true)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="space-y-5 border-t pt-7">
      <div className="flex items-start gap-3">
        <div className="flex size-10 shrink-0 items-center justify-center rounded-[var(--radius-default)] border bg-[var(--surface-secondary)]">
          <HugeiconsIcon
            icon={LockPasswordIcon}
            strokeWidth={1.8}
            className="size-5"
          />
        </div>
        <div>
          <h2 className="text-base font-semibold">Master passphrase</h2>
          <p className="mt-1 max-w-[65ch] text-sm leading-6 text-[var(--text-secondary)]">
            Reauthenticate with the current passphrase, then replace the local
            root-key wrap. Existing vault data is not re-encrypted.
          </p>
        </div>
      </div>

      {changed ? (
        <Alert>
          <AlertTitle>Master passphrase changed</AlertTitle>
          <AlertDescription>
            The browser reload credential was rotated as part of the change.
          </AlertDescription>
        </Alert>
      ) : null}
      {localError ? (
        <Alert variant="destructive">
          <AlertTitle>Passphrase change blocked</AlertTitle>
          <AlertDescription>{localError}</AlertDescription>
        </Alert>
      ) : null}

      <div className="space-y-4">
        <Field>
          <FieldLabel htmlFor="safeory-current-passphrase">
            Current passphrase
          </FieldLabel>
          <Input
            id="safeory-current-passphrase"
            type="password"
            autoComplete="current-password"
            value={currentPassphrase}
            disabled={busy}
            onChange={(event) => setCurrentPassphrase(event.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="safeory-new-passphrase">
            New passphrase
          </FieldLabel>
          <Input
            id="safeory-new-passphrase"
            type="password"
            autoComplete="new-password"
            value={newPassphrase}
            disabled={busy}
            onChange={(event) => setNewPassphrase(event.target.value)}
          />
          <FieldDescription>
            Use at least 12 characters. Longer is better.
          </FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor="safeory-confirm-passphrase">
            Confirm new passphrase
          </FieldLabel>
          <Input
            id="safeory-confirm-passphrase"
            type="password"
            autoComplete="new-password"
            value={confirmPassphrase}
            disabled={busy}
            onChange={(event) => setConfirmPassphrase(event.target.value)}
          />
          {newPassphrase.length > 0 &&
          confirmPassphrase.length > 0 &&
          newPassphrase !== confirmPassphrase ? (
            <FieldError>The passphrases do not match.</FieldError>
          ) : null}
        </Field>
        <Button
          type="button"
          disabled={
            busy || currentPassphrase.length === 0 || newPassphrase.length === 0
          }
          onClick={() => void submit()}
        >
          <HugeiconsIcon
            icon={LockPasswordIcon}
            strokeWidth={2}
            data-icon="inline-start"
          />
          Change master passphrase
        </Button>
      </div>
    </section>
  )
}
