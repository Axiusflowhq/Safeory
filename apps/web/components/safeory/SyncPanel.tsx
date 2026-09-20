"use client"

import { useState } from "react"
import {
  CloudOffIcon,
  CloudSyncIcon,
  Refresh01Icon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import type { VaultSyncStatus } from "@/lib/vault/use-vault"

interface SyncPanelProps {
  status: VaultSyncStatus
  onEnroll: (registrationToken: string) => Promise<boolean>
  onRetry: () => Promise<boolean>
  onResetInvalidConfiguration: () => boolean
  onSyncNow: () => Promise<boolean>
}

function statusLabel(status: VaultSyncStatus): string {
  switch (status.phase) {
    case "connecting":
      return "Connecting"
    case "syncing":
      return "Syncing"
    case "ready":
      return "Connected"
    case "error":
      return "Needs attention"
    default:
      return "Local only"
  }
}

export function SyncPanel({
  status,
  onEnroll,
  onRetry,
  onResetInvalidConfiguration,
  onSyncNow,
}: SyncPanelProps) {
  const [registrationToken, setRegistrationToken] = useState("")
  const [busy, setBusy] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)
  const connected = status.accountId !== null
  const working = status.phase === "connecting" || status.phase === "syncing" || busy

  async function run(operation: () => Promise<boolean>): Promise<void> {
    setBusy(true)
    setLocalError(null)
    try {
      if (!(await operation())) setLocalError("Sync did not complete. Review the status below and retry.")
    } catch (error) {
      setLocalError(error instanceof Error ? error.message : String(error))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="space-y-5 rounded-[var(--radius-default)] border bg-[var(--surface)] p-5 shadow-[var(--fancy-shadow-basic)]">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <div className="flex size-9 shrink-0 items-center justify-center rounded-[var(--radius-default)] border bg-[var(--surface-secondary)]">
            <HugeiconsIcon
              icon={connected ? CloudSyncIcon : CloudOffIcon}
              strokeWidth={1.8}
              className="size-4 text-[var(--icon-active)]"
            />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-lg font-semibold tracking-tight">Encrypted sync</h2>
              <Badge variant={status.phase === "error" ? "destructive" : "outline"}>
                {statusLabel(status)}
              </Badge>
            </div>
            <p className="mt-1 max-w-[65ch] text-sm leading-6 text-pretty text-[var(--text-secondary)]">
              Sync sends opaque ciphertext through this deployment&apos;s same-origin API.
              Your device bearer is wrapped locally in IndexedDB; vault plaintext,
              passphrases, and recovery secrets never enter browser storage or the API.
            </p>
          </div>
        </div>
        {connected ? (
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={working}
            onClick={() => void run(onSyncNow)}
          >
            <HugeiconsIcon icon={Refresh01Icon} strokeWidth={2} data-icon="inline-start" />
            Sync now
          </Button>
        ) : null}
      </div>

      {status.phase === "not_configured" ? (
        <div className="space-y-4 border-t pt-5">
          <Field>
            <FieldLabel htmlFor="safeory-registration-token">
              Deployment registration token
            </FieldLabel>
            <Input
              id="safeory-registration-token"
              type="password"
              value={registrationToken}
              onChange={(event) => {
                setRegistrationToken(event.target.value)
                setLocalError(null)
              }}
              autoComplete="off"
              spellCheck={false}
              placeholder="Paste the one-time deployment bootstrap token"
            />
            <FieldDescription>
              Used once to create this account and browser device. It is never persisted.
            </FieldDescription>
          </Field>
          <Button
            type="button"
            variant="secondary"
            disabled={working || registrationToken.length < 32 || /\s/.test(registrationToken)}
            onClick={() => {
              const token = registrationToken
              setRegistrationToken("")
              void run(() => onEnroll(token))
            }}
          >
            Enable encrypted sync
          </Button>
        </div>
      ) : null}

      {status.accountId ? (
        <div className="grid gap-2 rounded-[var(--radius-default)] border bg-[var(--surface-secondary)] p-4 text-sm">
          <div className="flex flex-wrap justify-between gap-2">
            <span className="text-[var(--text-secondary)]">Account</span>
            <span className="break-all font-mono text-xs">{status.accountId}</span>
          </div>
          <div className="flex flex-wrap justify-between gap-2">
            <span className="text-[var(--text-secondary)]">Last completed</span>
            <span>{status.lastSyncedAt === null ? "Not yet" : new Date(status.lastSyncedAt).toLocaleString()}</span>
          </div>
          <div className="flex flex-wrap justify-between gap-2">
            <span className="text-[var(--text-secondary)]">Pending uploads</span>
            <span className="tabular-nums">{status.pendingUploads}</span>
          </div>
          {status.blockedItems > 0 ? (
            <div className="flex flex-wrap justify-between gap-2 text-[var(--danger)]">
              <span>Encrypted conflicts</span>
              <span className="tabular-nums">{status.blockedItems}</span>
            </div>
          ) : null}
        </div>
      ) : null}

      {status.error || localError ? (
        <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
          <p className="max-w-[65ch] text-sm text-[var(--danger)]" role="alert">
            {status.error ?? localError}
          </p>
          {status.accountId ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={working}
              onClick={() => void run(onRetry)}
            >
              Retry connection
            </Button>
          ) : status.phase === "error" ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={working}
              onClick={() => {
                if (!onResetInvalidConfiguration()) {
                  setLocalError("The saved connection could not be reset safely.")
                }
              }}
            >
              Reset routing metadata
            </Button>
          ) : null}
        </div>
      ) : null}
    </section>
  )
}
