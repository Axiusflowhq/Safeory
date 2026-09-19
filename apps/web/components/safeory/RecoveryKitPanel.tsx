"use client"

import { useState } from "react"
import {
  CheckmarkCircle02Icon,
  Copy01Icon,
  RefreshIcon,
  ShieldKeyIcon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"

interface Props {
  hasRecoveryKit: boolean
  generatedSecret: string | null
  onInstall: () => void
  onClearSecret: () => void
}

export function RecoveryKitPanel({
  hasRecoveryKit,
  generatedSecret,
  onInstall,
  onClearSecret,
}: Props) {
  const [copied, setCopied] = useState(false)
  const [copyFailed, setCopyFailed] = useState(false)

  async function copySecret(secret: string) {
    setCopyFailed(false)
    try {
      await navigator.clipboard.writeText(secret)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopyFailed(true)
    }
  }

  return (
    <section className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <div className="flex size-10 shrink-0 items-center justify-center rounded-[var(--radius-default)] border bg-[var(--surface-secondary)]">
            <HugeiconsIcon
              icon={ShieldKeyIcon}
              strokeWidth={1.8}
              className="size-5 text-[var(--primary)]"
            />
          </div>
          <div>
            <h2 className="text-lg font-semibold tracking-tight">
              Recovery kit
            </h2>
            <p className="mt-1 max-w-2xl text-sm leading-relaxed text-[var(--text-secondary)]">
              A recovery kit lets you regain access if you forget your master
              passphrase. Anyone with the key can unlock your vault, so keep it
              offline and somewhere only you can access.
            </p>
          </div>
        </div>
        {!generatedSecret ? (
          <Badge variant={hasRecoveryKit ? "default" : "secondary"}>
            {hasRecoveryKit ? "Installed" : "Not installed"}
          </Badge>
        ) : null}
      </div>

      {generatedSecret ? (
        <div className="rounded-[var(--radius-default)] border bg-[var(--surface)] p-5 shadow-[var(--fancy-shadow-basic)]">
          <Alert className="mb-4">
            <HugeiconsIcon icon={ShieldKeyIcon} strokeWidth={2} />
            <AlertTitle>Save this recovery key now</AlertTitle>
            <AlertDescription>
              This is the only time Safeory shows the key in plaintext. Print it
              or write it down before continuing.
            </AlertDescription>
          </Alert>

          <div className="rounded-[var(--radius-default)] border bg-[var(--surface-secondary)] p-4">
            <code className="block font-mono text-sm leading-6 break-all text-[var(--text-primary)]">
              {generatedSecret}
            </code>
          </div>

          {copyFailed ? (
            <p className="mt-2 text-sm text-[var(--danger)]">
              Clipboard access was unavailable. Select the key and copy it
              manually.
            </p>
          ) : null}

          <div className="mt-4 flex flex-col gap-2 sm:flex-row sm:justify-end">
            <Button
              type="button"
              variant="outline"
              onClick={() => void copySecret(generatedSecret)}
            >
              <HugeiconsIcon
                icon={copied ? CheckmarkCircle02Icon : Copy01Icon}
                strokeWidth={2}
                data-icon="inline-start"
              />
              {copied ? "Copied" : "Copy key"}
            </Button>
            <Button type="button" onClick={onClearSecret}>
              <HugeiconsIcon
                icon={CheckmarkCircle02Icon}
                strokeWidth={2}
                data-icon="inline-start"
              />
              I&apos;ve saved it
            </Button>
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-4 rounded-[var(--radius-default)] border bg-[var(--surface-secondary)] p-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-sm font-medium">
              {hasRecoveryKit
                ? "Your vault has a recovery kit"
                : "Protect yourself from a forgotten passphrase"}
            </p>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
              {hasRecoveryKit
                ? "Replacing it invalidates the previous recovery key."
                : "Create one recovery key and store it separately from this device."}
            </p>
          </div>
          <Button
            type="button"
            variant={hasRecoveryKit ? "outline" : "default"}
            onClick={onInstall}
            className="shrink-0"
          >
            <HugeiconsIcon
              icon={hasRecoveryKit ? RefreshIcon : ShieldKeyIcon}
              strokeWidth={2}
              data-icon="inline-start"
            />
            {hasRecoveryKit ? "Replace recovery kit" : "Create recovery kit"}
          </Button>
        </div>
      )}
    </section>
  )
}
