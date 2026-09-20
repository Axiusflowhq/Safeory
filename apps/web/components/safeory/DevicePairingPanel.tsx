"use client"

import { useEffect, useState } from "react"
import type {
  DeviceRegistrationV1,
  PairingChallengeV1,
  PairingProofV1,
} from "@safeory/contracts"
import {
  Copy01Icon,
  Delete02Icon,
  DeviceAccessIcon,
  Key01Icon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Textarea } from "@/components/ui/textarea"

interface DevicePairingPanelProps {
  listIdentities: () => Promise<DeviceRegistrationV1[]>
  createIdentity: () => Promise<DeviceRegistrationV1 | null>
  deleteIdentity: (deviceId: string) => Promise<boolean>
  answerChallenge: (challenge: PairingChallengeV1) => Promise<PairingProofV1 | null>
}

function parseChallenge(value: string): PairingChallengeV1 {
  let parsed: unknown
  try {
    parsed = JSON.parse(value)
  } catch {
    throw new Error("Pairing challenge must be valid JSON.")
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    (parsed as { format_version?: unknown }).format_version !== 1 ||
    typeof (parsed as { device_id?: unknown }).device_id !== "string" ||
    !Array.isArray((parsed as { encryption_public?: unknown }).encryption_public)
  ) {
    throw new Error("Pairing challenge format is invalid.")
  }
  return parsed as PairingChallengeV1
}

async function copyText(value: string): Promise<void> {
  await navigator.clipboard.writeText(value)
}

export function DevicePairingPanel({
  listIdentities,
  createIdentity,
  deleteIdentity,
  answerChallenge,
}: DevicePairingPanelProps) {
  const [identities, setIdentities] = useState<DeviceRegistrationV1[]>([])
  const [challengeText, setChallengeText] = useState("")
  const [proofText, setProofText] = useState("")
  const [localError, setLocalError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let active = true
    void listIdentities().then((loaded) => {
      if (active) setIdentities(loaded)
    })
    return () => {
      active = false
    }
  }, [listIdentities])

  return (
    <section className="space-y-5 rounded-[var(--radius-default)] border bg-[var(--surface)] p-5 shadow-[var(--fancy-shadow-basic)]">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <div className="flex size-9 shrink-0 items-center justify-center rounded-[var(--radius-default)] border bg-[var(--surface-secondary)]">
            <HugeiconsIcon
              icon={DeviceAccessIcon}
              strokeWidth={1.8}
              className="size-4 text-[var(--icon-active)]"
            />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-lg font-semibold tracking-tight">This browser device</h2>
              <Badge variant="outline">Local keys</Badge>
            </div>
            <p className="mt-1 max-w-[65ch] text-sm leading-6 text-pretty text-[var(--text-secondary)]">
              Device private keys are wrapped locally with a non-extractable browser key.
              Share only the public registration bundle below. Pairing proves key possession;
              it does not verify a person&apos;s identity or release vault data.
            </p>
          </div>
        </div>
        <Button
          type="button"
          variant="secondary"
          size="sm"
          disabled={busy}
          onClick={async () => {
            setBusy(true)
            setLocalError(null)
            try {
              const created = await createIdentity()
              if (created) setIdentities((current) => [...current, created])
            } finally {
              setBusy(false)
            }
          }}
        >
          <HugeiconsIcon icon={Key01Icon} strokeWidth={2} data-icon="inline-start" />
          Create device identity
        </Button>
      </div>

      {identities.length === 0 ? (
        <div className="rounded-[var(--radius-default)] border border-dashed bg-[var(--surface-secondary)] px-5 py-6 text-sm text-[var(--text-secondary)]">
          No durable device identity exists in this browser yet.
        </div>
      ) : (
        <div className="space-y-3">
          {identities.map((identity) => {
            const registration = JSON.stringify(identity)
            return (
              <div
                key={identity.device_id}
                className="space-y-3 rounded-[var(--radius-default)] border bg-[var(--surface-secondary)] p-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-sm font-medium">Recipient device</p>
                    <p className="mt-1 break-all font-mono text-[11px] text-[var(--text-secondary)]">
                      {identity.device_id}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => void copyText(registration)}
                    >
                      <HugeiconsIcon icon={Copy01Icon} strokeWidth={2} data-icon="inline-start" />
                      Copy registration
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      disabled={busy}
                      onClick={async () => {
                        setBusy(true)
                        try {
                          if (await deleteIdentity(identity.device_id)) {
                            setIdentities((current) =>
                              current.filter((entry) => entry.device_id !== identity.device_id)
                            )
                          }
                        } finally {
                          setBusy(false)
                        }
                      }}
                    >
                      <HugeiconsIcon icon={Delete02Icon} strokeWidth={2} data-icon="inline-start" />
                      Delete local key
                    </Button>
                  </div>
                </div>
                <div className="grid gap-2 text-xs text-[var(--text-secondary)]">
                  <p className="break-all font-mono">X25519 {identity.encryption_public_key_hex}</p>
                  <p className="break-all font-mono">Ed25519 {identity.signing_public_key_hex}</p>
                </div>
              </div>
            )
          })}
        </div>
      )}

      <div className="grid gap-4 border-t pt-5">
        <Field>
          <FieldLabel htmlFor="safeory-recipient-pairing-challenge">
            Owner pairing challenge
          </FieldLabel>
          <Textarea
            id="safeory-recipient-pairing-challenge"
            value={challengeText}
            onChange={(event) => {
              setChallengeText(event.target.value)
              setProofText("")
              setLocalError(null)
            }}
            rows={5}
            spellCheck={false}
            autoComplete="off"
            className="font-mono text-xs"
            placeholder="Paste the one-shot challenge JSON from the vault owner"
          />
          <FieldDescription>
            The challenge must target a device identity stored in this browser.
          </FieldDescription>
        </Field>

        <div>
          <Button
            type="button"
            variant="secondary"
            disabled={busy || challengeText.trim().length === 0}
            onClick={async () => {
              setBusy(true)
              setLocalError(null)
              setProofText("")
              try {
                const challenge = parseChallenge(challengeText)
                const proof = await answerChallenge(challenge)
                if (proof) setProofText(JSON.stringify(proof))
              } catch (error) {
                setLocalError(error instanceof Error ? error.message : String(error))
              } finally {
                setBusy(false)
              }
            }}
          >
            Answer pairing challenge
          </Button>
        </div>

        {proofText ? (
          <Field>
            <div className="flex items-center justify-between gap-3">
              <FieldLabel htmlFor="safeory-recipient-pairing-proof">Pairing proof</FieldLabel>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => void copyText(proofText)}
              >
                <HugeiconsIcon icon={Copy01Icon} strokeWidth={2} data-icon="inline-start" />
                Copy proof
              </Button>
            </div>
            <Textarea
              id="safeory-recipient-pairing-proof"
              value={proofText}
              readOnly
              rows={5}
              className="font-mono text-xs"
            />
          </Field>
        ) : null}

        {localError ? (
          <p className="text-sm text-[var(--danger)]" role="alert">
            {localError}
          </p>
        ) : null}
      </div>
    </section>
  )
}
