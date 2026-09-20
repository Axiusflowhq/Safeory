"use client"

import { useState } from "react"
import {
  CloudOffIcon,
  CloudSyncIcon,
  Copy01Icon,
  Refresh01Icon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import type { VaultSyncStatus } from "@/lib/vault/use-vault"
import type { BrowserSyncEnrollment } from "@/lib/vault/sync"

interface SyncPanelProps {
  status: VaultSyncStatus
  onGenerateAccountSecret: () => string
  onEnroll: (enrollment: BrowserSyncEnrollment) => Promise<boolean>
  onApproveDevice: (requestJson: string) => Promise<string>
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
  onGenerateAccountSecret,
  onEnroll,
  onApproveDevice,
  onRetry,
  onResetInvalidConfiguration,
  onSyncNow,
}: SyncPanelProps) {
  const [registrationToken, setRegistrationToken] = useState("")
  const [masterPassphrase, setMasterPassphrase] = useState("")
  const [accountSecret, setAccountSecret] = useState("")
  const [accountSecretConfirmation, setAccountSecretConfirmation] = useState("")
  const [recoveryCopyConfirmed, setRecoveryCopyConfirmed] = useState(false)
  const [secretCopied, setSecretCopied] = useState(false)
  const [busy, setBusy] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)
  const [deviceRequest, setDeviceRequest] = useState("")
  const [deviceGrant, setDeviceGrant] = useState("")
  const [grantCopied, setGrantCopied] = useState(false)
  const connected = status.accountId !== null
  const working = status.phase === "connecting" || status.phase === "syncing" || busy
  const accountSecretConfirmed =
    accountSecret.length > 0 && accountSecretConfirmation === accountSecret
  const enrollmentReady =
    registrationToken.length >= 32 &&
    !/\s/.test(registrationToken) &&
    masterPassphrase.length >= 12 &&
    accountSecretConfirmed &&
    recoveryCopyConfirmed

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

  function generateAccountSecret(): void {
    try {
      setAccountSecret(onGenerateAccountSecret())
      setAccountSecretConfirmation("")
      setRecoveryCopyConfirmed(false)
      setSecretCopied(false)
      setLocalError(null)
    } catch (error) {
      setLocalError(error instanceof Error ? error.message : String(error))
    }
  }

  async function copyAccountSecret(): Promise<void> {
    try {
      await navigator.clipboard.writeText(accountSecret)
      setSecretCopied(true)
      setLocalError(null)
    } catch {
      setSecretCopied(false)
      setLocalError("Clipboard access was unavailable. Select and copy the Account Secret manually.")
    }
  }

  async function copyDeviceGrant(): Promise<void> {
    try {
      await navigator.clipboard.writeText(deviceGrant)
      setGrantCopied(true)
      setLocalError(null)
    } catch {
      setGrantCopied(false)
      setLocalError("Clipboard access was unavailable. Select and copy the encrypted grant manually.")
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
              passphrases, Account Secrets, and recovery secrets never enter browser
              storage or the API.
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
          <Field>
            <FieldLabel htmlFor="safeory-sync-master-passphrase">
              Master passphrase
            </FieldLabel>
            <Input
              id="safeory-sync-master-passphrase"
              type="password"
              value={masterPassphrase}
              onChange={(event) => {
                setMasterPassphrase(event.target.value)
                setLocalError(null)
              }}
              autoComplete="current-password"
              placeholder="Re-enter your master passphrase"
            />
            <FieldDescription>
              Re-authenticates the local root before any hosted account is created. It is
              never sent to the API or persisted.
            </FieldDescription>
          </Field>
          {accountSecret === "" ? (
            <div className="rounded-[var(--radius-default)] border bg-[var(--surface-secondary)] p-4">
              <p className="text-sm font-medium">Create your Account Secret</p>
              <p className="mt-1 text-sm leading-6 text-[var(--text-secondary)]">
                This high-entropy code protects the remotely stored root envelope. Safeory
                cannot recover it. Save it separately from your master passphrase.
              </p>
              <Button
                type="button"
                variant="outline"
                className="mt-3"
                disabled={working}
                onClick={generateAccountSecret}
              >
                Generate Account Secret
              </Button>
            </div>
          ) : (
            <div className="space-y-4 rounded-[var(--radius-default)] border bg-[var(--surface-secondary)] p-4">
              <Field>
                <FieldLabel htmlFor="safeory-account-secret">Account Secret</FieldLabel>
                <div className="flex flex-col gap-2 sm:flex-row">
                  <Input
                    id="safeory-account-secret"
                    readOnly
                    value={accountSecret}
                    className="font-mono text-xs"
                    aria-describedby="safeory-account-secret-description"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    disabled={working}
                    onClick={() => void copyAccountSecret()}
                  >
                    <HugeiconsIcon icon={Copy01Icon} strokeWidth={2} data-icon="inline-start" />
                    {secretCopied ? "Copied" : "Copy"}
                  </Button>
                </div>
                <FieldDescription id="safeory-account-secret-description">
                  Store this code now. It is shown only for this enrollment attempt and is
                  never written to browser storage.
                </FieldDescription>
              </Field>
              <Field>
                <FieldLabel htmlFor="safeory-account-secret-confirmation">
                  Confirm Account Secret
                </FieldLabel>
                <Input
                  id="safeory-account-secret-confirmation"
                  type="password"
                  value={accountSecretConfirmation}
                  onChange={(event) => {
                    setAccountSecretConfirmation(event.target.value.trim())
                    setLocalError(null)
                  }}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="Paste the saved Account Secret"
                />
                <FieldDescription>
                  Paste the saved code to catch an incomplete or incorrect recovery copy.
                </FieldDescription>
              </Field>
              <label className="flex items-start gap-3 text-sm leading-5">
                <input
                  type="checkbox"
                  className="mt-0.5 size-4 accent-[var(--primary)]"
                  checked={recoveryCopyConfirmed}
                  onChange={(event) => setRecoveryCopyConfirmed(event.target.checked)}
                />
                <span>
                  I saved the Account Secret separately. I understand that losing every
                  authorized device, recovery kit, and this code can make the vault
                  unrecoverable.
                </span>
              </label>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={working}
                onClick={generateAccountSecret}
              >
                Replace with a new Account Secret
              </Button>
            </div>
          )}
          <Button
            type="button"
            variant="secondary"
            disabled={working || !enrollmentReady}
            onClick={() => {
              const enrollment = {
                registrationToken,
                masterPassphrase,
                accountSecretCode: accountSecret,
              }
              void run(async () => {
                try {
                  const succeeded = await onEnroll(enrollment)
                  if (succeeded) setRegistrationToken("")
                  return succeeded
                } finally {
                  setMasterPassphrase("")
                  setAccountSecret("")
                  setAccountSecretConfirmation("")
                  setRecoveryCopyConfirmed(false)
                  setSecretCopied(false)
                }
              })
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

      {status.phase === "ready" ? (
        <div className="space-y-4 border-t pt-5">
          <div>
            <h3 className="text-sm font-semibold">Approve another device</h3>
            <p className="mt-1 max-w-[65ch] text-sm leading-6 text-[var(--text-secondary)]">
              Paste the self-signed request shown on the joining device. Approval creates
              an encrypted, device-bound grant and reserves a pending device for 30 minutes.
              Only approve a request you initiated and recognize.
            </p>
          </div>
          <Field>
            <FieldLabel htmlFor="safeory-device-enrollment-request">
              Joining-device request
            </FieldLabel>
            <Textarea
              id="safeory-device-enrollment-request"
              value={deviceRequest}
              onChange={(event) => {
                setDeviceRequest(event.target.value.trim())
                setDeviceGrant("")
                setGrantCopied(false)
                setLocalError(null)
              }}
              className="min-h-28 font-mono text-xs"
              autoComplete="off"
              spellCheck={false}
              placeholder="Paste the complete enrollment request JSON"
              disabled={working}
            />
          </Field>
          <Button
            type="button"
            variant="secondary"
            disabled={working || deviceRequest.length === 0}
            onClick={() => void run(async () => {
              const grant = await onApproveDevice(deviceRequest)
              setDeviceGrant(grant)
              setGrantCopied(false)
              return true
            })}
          >
            Approve and create encrypted grant
          </Button>
          {deviceGrant !== "" ? (
            <Field>
              <FieldLabel htmlFor="safeory-device-enrollment-grant">
                Encrypted device grant
              </FieldLabel>
              <Textarea
                id="safeory-device-enrollment-grant"
                readOnly
                value={deviceGrant}
                className="min-h-28 font-mono text-xs"
                aria-describedby="safeory-device-enrollment-grant-description"
              />
              <FieldDescription id="safeory-device-enrollment-grant-description">
                Return this complete package to the joining device. It contains no Account
                Secret or vault plaintext and can be opened only by that device.
              </FieldDescription>
              <Button
                type="button"
                variant="outline"
                disabled={working}
                onClick={() => void copyDeviceGrant()}
              >
                <HugeiconsIcon icon={Copy01Icon} strokeWidth={2} data-icon="inline-start" />
                {grantCopied ? "Copied" : "Copy encrypted grant"}
              </Button>
            </Field>
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
