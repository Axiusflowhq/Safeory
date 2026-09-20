"use client"

import { useEffect, useRef, useState } from "react"
import type { AttachmentSummary } from "@safeory/contracts"
import {
  Attachment01Icon,
  Delete02Icon,
  Download01Icon,
  FileAttachmentIcon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import type { EditableEntry } from "@/lib/vault/use-vault"

interface Props {
  owner: EditableEntry
  onOwnerChange: (owner: EditableEntry) => void
  getAttachments: (owner: EditableEntry) => Promise<AttachmentSummary[]>
  addAttachment: (
    owner: EditableEntry,
    file: File
  ) => Promise<EditableEntry | null>
  deleteAttachment: (
    owner: EditableEntry,
    summary: AttachmentSummary
  ) => Promise<EditableEntry | null>
  downloadAttachment: (
    owner: EditableEntry,
    summary: AttachmentSummary
  ) => Promise<{ summary: AttachmentSummary; blob: Blob } | null>
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`
}

export function AttachmentEditor({
  owner,
  onOwnerChange,
  getAttachments,
  addAttachment,
  deleteAttachment,
  downloadAttachment,
}: Props) {
  const [attachments, setAttachments] = useState<AttachmentSummary[]>([])
  const [loadedRevision, setLoadedRevision] = useState<number | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [localError, setLocalError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    let active = true
    void getAttachments(owner).then((next) => {
      if (!active) return
      setAttachments(next)
      setLoadedRevision(owner.revision)
    })
    return () => {
      active = false
    }
  }, [getAttachments, owner])

  const loading = loadedRevision !== owner.revision

  async function add(file: File | undefined) {
    if (!file) return
    setLocalError(null)
    setBusyId("add")
    try {
      const updated = await addAttachment(owner, file)
      if (updated !== null) onOwnerChange(updated)
    } catch (error) {
      setLocalError(error instanceof Error ? error.message : String(error))
    } finally {
      setBusyId(null)
      if (fileInputRef.current) fileInputRef.current.value = ""
    }
  }

  async function download(summary: AttachmentSummary) {
    setLocalError(null)
    setBusyId(summary.id)
    try {
      const downloaded = await downloadAttachment(owner, summary)
      if (downloaded === null) return
      const url = URL.createObjectURL(downloaded.blob)
      const link = document.createElement("a")
      link.href = url
      link.download = downloaded.summary.filename
      link.rel = "noopener"
      document.body.appendChild(link)
      try {
        link.click()
      } finally {
        link.remove()
        URL.revokeObjectURL(url)
      }
    } finally {
      setBusyId(null)
    }
  }

  async function remove(summary: AttachmentSummary) {
    if (!window.confirm(`Remove “${summary.filename}” from this record?`))
      return
    setLocalError(null)
    setBusyId(summary.id)
    try {
      const updated = await deleteAttachment(owner, summary)
      if (updated !== null) onOwnerChange(updated)
    } catch (error) {
      setLocalError(error instanceof Error ? error.message : String(error))
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3">
        <div className="flex size-9 shrink-0 items-center justify-center rounded-[var(--radius-default)] bg-[var(--surface-secondary)]">
          <HugeiconsIcon icon={Attachment01Icon} strokeWidth={1.8} className="size-4" />
        </div>
        <div>
          <h3 className="text-sm font-medium">Attachments</h3>
          <p className="mt-1 text-sm leading-6 text-[var(--text-secondary)]">
            Files are encrypted in 1 MiB chunks before IndexedDB persistence. Up
            to 16 files and 64 MiB per file are supported.
          </p>
        </div>
      </div>

      {localError ? (
        <Alert variant="destructive">
          <AlertTitle>Attachment action failed</AlertTitle>
          <AlertDescription>{localError}</AlertDescription>
        </Alert>
      ) : null}

      <Input
        ref={fileInputRef}
        type="file"
        disabled={busyId !== null}
        onChange={(event) => void add(event.target.files?.[0])}
        className="file:mr-3 file:border-0 file:bg-transparent file:text-sm file:font-medium"
      />

      {loading ? (
        <p className="text-sm text-[var(--text-secondary)]">
          Loading attachments…
        </p>
      ) : attachments.length === 0 ? (
        <p className="text-sm text-[var(--text-secondary)]">
          No attachments yet.
        </p>
      ) : (
        <div className="space-y-2">
          {attachments.map((attachment) => (
            <div
              key={attachment.id}
              className="flex flex-col gap-3 rounded-[var(--radius-default)] border p-3 sm:flex-row sm:items-center"
            >
              <div className="flex min-w-0 flex-1 items-center gap-3">
                <div className="flex size-9 shrink-0 items-center justify-center rounded-[var(--radius-default)] bg-[var(--surface-secondary)]">
                  <HugeiconsIcon
                    icon={FileAttachmentIcon}
                    strokeWidth={2}
                    className="size-4"
                  />
                </div>
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">
                    {attachment.filename}
                  </p>
                  <p className="text-xs text-[var(--text-secondary)]">
                    {formatBytes(attachment.plaintext_size)}
                  </p>
                </div>
              </div>
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={busyId !== null}
                  onClick={() => void download(attachment)}
                >
                  <HugeiconsIcon
                    icon={Download01Icon}
                    strokeWidth={2}
                    data-icon="inline-start"
                  />
                  Download
                </Button>
                <Button
                  type="button"
                  variant="destructive"
                  size="sm"
                  disabled={busyId !== null}
                  onClick={() => void remove(attachment)}
                >
                  <HugeiconsIcon
                    icon={Delete02Icon}
                    strokeWidth={2}
                    data-icon="inline-start"
                  />
                  Remove
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
