"use client"

import { useState } from "react"
import {
  AlertCircleIcon,
  ArrowLeft01Icon,
  Key01Icon,
  LockKeyIcon,
  ShieldKeyIcon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"

interface Props {
  mode: "setup" | "unlock"
  error: string | null
  onSubmit: (passphrase: string) => void
  onRecoveryUnlock: (secretHex: string) => void
  hasRecoveryKit?: boolean
}

type Strength = {
  label: string
  variant: "default" | "outline" | "destructive"
}

function strength(passphrase: string): Strength {
  const length = passphrase.length
  const variety =
    Number(/[a-z]/.test(passphrase)) +
    Number(/[A-Z]/.test(passphrase)) +
    Number(/[0-9]/.test(passphrase)) +
    Number(/[^A-Za-z0-9]/.test(passphrase))

  if (length < 12) {
    return {
      label: "Too short · 12 characters minimum",
      variant: "destructive",
    }
  }
  if (length >= 16 && variety >= 3) {
    return { label: "Strong passphrase", variant: "default" }
  }
  if (length >= 12 && variety >= 2) {
    return { label: "Good passphrase", variant: "outline" }
  }
  return { label: "Consider adding more variety", variant: "outline" }
}

export function PassphraseGate({
  mode,
  error,
  onSubmit,
  onRecoveryUnlock,
  hasRecoveryKit,
}: Props) {
  const [passphrase, setPassphrase] = useState("")
  const [showRecovery, setShowRecovery] = useState(false)
  const [secret, setSecret] = useState("")
  const passphraseStrength = strength(passphrase)
  const isSetup = mode === "setup"

  return (
    <main className="flex min-h-svh items-center justify-center bg-background px-4 py-10">
      <section className="w-full max-w-md overflow-hidden rounded-2xl border bg-card text-card-foreground shadow-sm">
        <div className="border-b bg-muted/30 px-6 py-6 sm:px-8">
          <div className="mb-5 flex size-11 items-center justify-center rounded-xl border bg-background shadow-xs">
            <HugeiconsIcon
              icon={showRecovery ? ShieldKeyIcon : LockKeyIcon}
              strokeWidth={1.8}
              className="size-5 text-primary"
            />
          </div>
          <h1 className="text-xl font-semibold tracking-tight">
            {showRecovery
              ? "Unlock with recovery key"
              : isSetup
                ? "Create your Safeory vault"
                : "Welcome back"}
          </h1>
          <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">
            {showRecovery
              ? "Use the recovery key you saved when you created or replaced your recovery kit."
              : isSetup
                ? "Choose a master passphrase that only you know. Your vault is encrypted on this device."
                : "Enter your master passphrase to decrypt your vault on this device."}
          </p>
        </div>

        <div className="space-y-5 px-6 py-6 sm:px-8">
          {error ? (
            <Alert variant="destructive">
              <HugeiconsIcon icon={AlertCircleIcon} strokeWidth={2} />
              <AlertTitle>
                {isSetup ? "Couldn’t create the vault" : "Couldn’t unlock the vault"}
              </AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}

          {!showRecovery ? (
            <form
              onSubmit={(event) => {
                event.preventDefault()
                onSubmit(passphrase)
              }}
            >
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="safeory-master-passphrase">
                    Master passphrase
                  </FieldLabel>
                  <Input
                    id="safeory-master-passphrase"
                    type="password"
                    autoComplete={isSetup ? "new-password" : "current-password"}
                    autoFocus
                    value={passphrase}
                    onChange={(event) => setPassphrase(event.target.value)}
                    placeholder={
                      isSetup
                        ? "Create a memorable passphrase"
                        : "Enter your passphrase"
                    }
                    className="h-10"
                  />
                  {isSetup && passphrase.length > 0 ? (
                    <div className="flex items-center justify-between gap-3">
                      <FieldDescription>
                        Use at least 12 characters. Longer is better.
                      </FieldDescription>
                      <Badge variant={passphraseStrength.variant}>
                        {passphraseStrength.label}
                      </Badge>
                    </div>
                  ) : null}
                </Field>

                <Button
                  type="submit"
                  size="lg"
                  className="w-full"
                  disabled={isSetup && passphrase.length < 12}
                >
                  <HugeiconsIcon
                    icon={isSetup ? Key01Icon : LockKeyIcon}
                    strokeWidth={2}
                    data-icon="inline-start"
                  />
                  {isSetup ? "Create encrypted vault" : "Unlock vault"}
                </Button>
              </FieldGroup>

              {mode === "unlock" ? (
                <div className="mt-4 border-t pt-4">
                  <Button
                    type="button"
                    variant="ghost"
                    className="w-full text-muted-foreground"
                    onClick={() => setShowRecovery(true)}
                  >
                    <HugeiconsIcon
                      icon={ShieldKeyIcon}
                      strokeWidth={2}
                      data-icon="inline-start"
                    />
                    Use a recovery kit instead
                  </Button>
                </div>
              ) : null}
            </form>
          ) : (
            <form
              onSubmit={(event) => {
                event.preventDefault()
                onRecoveryUnlock(secret.trim())
              }}
            >
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="safeory-recovery-key">
                    Recovery key
                  </FieldLabel>
                  <Input
                    id="safeory-recovery-key"
                    type="text"
                    inputMode="text"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                    autoFocus
                    value={secret}
                    onChange={(event) => setSecret(event.target.value)}
                    placeholder="64-character recovery key"
                    className="h-10 font-mono"
                  />
                  <FieldDescription>
                    Enter the 64-character hexadecimal key from your saved
                    recovery kit.
                  </FieldDescription>
                </Field>

                <Button
                  type="submit"
                  size="lg"
                  className="w-full"
                  disabled={secret.trim().length !== 64}
                >
                  <HugeiconsIcon
                    icon={ShieldKeyIcon}
                    strokeWidth={2}
                    data-icon="inline-start"
                  />
                  Unlock with recovery kit
                </Button>

                <Button
                  type="button"
                  variant="ghost"
                  className="w-full text-muted-foreground"
                  onClick={() => setShowRecovery(false)}
                >
                  <HugeiconsIcon
                    icon={ArrowLeft01Icon}
                    strokeWidth={2}
                    data-icon="inline-start"
                  />
                  Back to passphrase
                </Button>
              </FieldGroup>
            </form>
          )}

          {mode === "unlock" && hasRecoveryKit === false && !showRecovery ? (
            <Alert>
              <HugeiconsIcon icon={ShieldKeyIcon} strokeWidth={2} />
              <AlertTitle>Recovery kit not installed</AlertTitle>
              <AlertDescription>
                Unlock with your passphrase first, then create a recovery kit
                from your vault settings.
              </AlertDescription>
            </Alert>
          ) : null}
        </div>
      </section>
    </main>
  )
}
