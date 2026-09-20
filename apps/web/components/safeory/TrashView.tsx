"use client"

import {
  Delete02Icon,
  RestoreBinIcon,
  TrashIcon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import type { TrashedItemSummary } from "@safeory/contracts"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { itemKindIcon } from "@/lib/vault/record-visuals"
import { kindLabel } from "@/lib/vault/items"

interface Props {
  items: TrashedItemSummary[]
  onRestore: (id: string, expectedRevision: number) => Promise<boolean>
  onPurge: (id: string, expectedRevision: number) => Promise<boolean>
}

export function TrashView({ items, onRestore, onPurge }: Props) {
  return (
    <section className="mx-auto w-full max-w-3xl p-5 md:p-8 lg:p-10">
      <div className="mb-7 flex items-start gap-3">
        <div className="flex size-10 shrink-0 items-center justify-center rounded-[var(--radius-default)] border bg-[var(--surface-secondary)]">
          <HugeiconsIcon icon={TrashIcon} strokeWidth={1.8} className="size-5" />
        </div>
        <div>
          <p className="text-sm font-medium text-[var(--primary)]">Lifecycle</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">Trash</h1>
          <p className="mt-2 max-w-[65ch] text-sm leading-6 text-pretty text-[var(--text-secondary)]">
            Trashed records stay encrypted locally until you restore or
            permanently delete them. Secret fields remain hidden in this list.
          </p>
        </div>
      </div>

      <Alert>
        <AlertTitle>Permanent deletion cannot be undone</AlertTitle>
        <AlertDescription>
          Permanently deleting a record also tombstones its encrypted attachment
          manifests and removes attachment ciphertext chunks from this browser.
        </AlertDescription>
      </Alert>

      {items.length === 0 ? (
        <div className="mt-6 rounded-[var(--radius-default)] border bg-[var(--surface-secondary)] p-6 text-center">
          <p className="text-sm font-medium">Trash is empty</p>
          <p className="mt-1 text-sm text-[var(--text-secondary)]">
            Records you move to trash will appear here.
          </p>
        </div>
      ) : (
        <div className="mt-6 space-y-2">
          {items.map((item) => (
            <div
              key={item.id}
              className="flex flex-col gap-4 rounded-[var(--radius-default)] border p-4 sm:flex-row sm:items-center"
            >
              <div className="flex min-w-0 flex-1 items-center gap-3">
                <div className="flex size-9 shrink-0 items-center justify-center rounded-[var(--radius-default)] bg-[var(--surface-secondary)]">
                  <HugeiconsIcon
                    icon={itemKindIcon(item.kind)}
                    strokeWidth={2}
                    className="size-4"
                  />
                </div>
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium">{item.title}</p>
                  <p className="mt-0.5 text-xs text-[var(--text-secondary)]">
                    {kindLabel(item.kind)} · deleted{" "}
                    {new Date(item.deleted_at_ms).toLocaleString()}
                  </p>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => void onRestore(item.id, item.revision)}
                >
                  <HugeiconsIcon
                    icon={RestoreBinIcon}
                    strokeWidth={2}
                    data-icon="inline-start"
                  />
                  Restore
                </Button>
                <Button
                  type="button"
                  variant="destructive"
                  size="sm"
                  onClick={() => {
                    if (
                      window.confirm(
                        `Permanently delete “${item.title}”? This cannot be undone.`
                      )
                    ) {
                      void onPurge(item.id, item.revision)
                    }
                  }}
                >
                  <HugeiconsIcon
                    icon={Delete02Icon}
                    strokeWidth={2}
                    data-icon="inline-start"
                  />
                  Delete permanently
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}

