"use client"

import {
  DatabaseBackupIcon,
  DatabaseExportIcon,
  FileExportIcon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"

interface Props {
  onExportReadable: () => string | null
  onExportEncrypted: () => Promise<string | null>
}

function dateStamp(now = new Date()): string {
  const year = now.getFullYear()
  const month = String(now.getMonth() + 1).padStart(2, "0")
  const day = String(now.getDate()).padStart(2, "0")
  return `${year}-${month}-${day}`
}

function downloadJson(filename: string, json: string) {
  const blob = new Blob([json], { type: "application/json;charset=utf-8" })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  link.rel = "noopener"
  document.body.appendChild(link)
  try {
    link.click()
  } finally {
    link.remove()
    URL.revokeObjectURL(url)
  }
}

export function ExportPanel({ onExportReadable, onExportEncrypted }: Props) {
  function exportReadable() {
    const json = onExportReadable()
    if (json === null) return
    downloadJson(`safeory-readable-export-${dateStamp()}.json`, json)
  }

  async function exportEncrypted() {
    const json = await onExportEncrypted()
    if (json === null) return
    downloadJson(`safeory-encrypted-backup-${dateStamp()}.json`, json)
  }

  return (
    <section className="space-y-5 border-t pt-7">
      <div className="flex items-start gap-3">
        <div className="flex size-10 shrink-0 items-center justify-center rounded-[var(--radius-default)] border bg-[var(--surface-secondary)]">
          <HugeiconsIcon
            icon={DatabaseExportIcon}
            strokeWidth={1.8}
            className="size-5"
          />
        </div>
        <div>
          <h2 className="text-base font-semibold">Portable export</h2>
          <p className="mt-1 max-w-[65ch] text-sm leading-6 text-pretty text-[var(--text-secondary)]">
            Download either a readable copy of your active vault or the
            encrypted browser snapshot used for local persistence.
          </p>
        </div>
      </div>

      <Alert variant="destructive">
        <AlertTitle>Readable export contains decrypted secrets</AlertTitle>
        <AlertDescription>
          Store the readable JSON only where you would store the original
          documents and passwords. It is not encrypted by Safeory after
          download.
        </AlertDescription>
      </Alert>

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-[var(--radius-default)] border p-4">
          <h3 className="text-sm font-medium">Readable JSON</h3>
          <p className="mt-1 min-h-12 text-xs leading-5 text-[var(--text-secondary)]">
            Includes full active records and the Emergency Card. Recovery
            secrets and vault keys are not included.
          </p>
          <Button
            variant="outline"
            className="mt-4 w-full"
            onClick={exportReadable}
          >
            <HugeiconsIcon
              icon={FileExportIcon}
              strokeWidth={2}
              data-icon="inline-start"
            />
            Download readable JSON
          </Button>
        </div>

        <div className="rounded-[var(--radius-default)] border p-4">
          <h3 className="text-sm font-medium">Encrypted backup</h3>
          <p className="mt-1 min-h-12 text-xs leading-5 text-[var(--text-secondary)]">
            Saves the ciphertext vault, encrypted attachment manifests/chunks,
            and wrapped key material. The master passphrase and recovery secret
            are never embedded in the file.
          </p>
          <Button
            variant="outline"
            className="mt-4 w-full"
            onClick={() => void exportEncrypted()}
          >
            <HugeiconsIcon
              icon={DatabaseBackupIcon}
              strokeWidth={2}
              data-icon="inline-start"
            />
            Download encrypted backup
          </Button>
        </div>
      </div>
    </section>
  )
}
