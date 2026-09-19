"use client"

import {
  Alert02Icon,
  ArrowRight01Icon,
  Calendar03Icon,
  Clock01Icon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import type { DeadlineSummary } from "@safeory/contracts"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { kindLabel } from "@/lib/vault/items"

interface Props {
  deadlines: DeadlineSummary[]
  onOpen: (deadline: DeadlineSummary) => void
}

interface DeadlineGroup {
  key: "overdue" | "today" | "upcoming"
  title: string
  description: string
  items: DeadlineSummary[]
}

function relativeLabel(daysUntil: number): string {
  if (daysUntil < 0) {
    const days = Math.abs(daysUntil)
    return `${days} ${days === 1 ? "day" : "days"} overdue`
  }
  if (daysUntil === 0) return "Due today"
  if (daysUntil === 1) return "Due tomorrow"
  return `Due in ${daysUntil} days`
}

function groupDeadlines(deadlines: DeadlineSummary[]): DeadlineGroup[] {
  return [
    {
      key: "overdue",
      title: "Overdue",
      description: "Past dates that still need your attention.",
      items: deadlines.filter((deadline) => deadline.daysUntil < 0),
    },
    {
      key: "today",
      title: "Today",
      description: "Deadlines that land on your local calendar date.",
      items: deadlines.filter((deadline) => deadline.daysUntil === 0),
    },
    {
      key: "upcoming",
      title: "Upcoming",
      description: "Future renewals, expiries, returns, and refunds.",
      items: deadlines.filter((deadline) => deadline.daysUntil > 0),
    },
  ]
}

export function TodayView({ deadlines, onOpen }: Props) {
  const groups = groupDeadlines(deadlines)

  return (
    <section className="mx-auto w-full max-w-4xl p-5 md:p-8 lg:p-10">
      <div className="mb-7 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="text-sm font-medium text-[var(--primary)]">Local reminders</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">Today</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-[var(--text-secondary)]">
            Review important dates derived locally from your encrypted vault. Protected fields stay
            inside Safeory until you open a specific record.
          </p>
        </div>
        <Badge variant="outline" className="self-start">
          <HugeiconsIcon icon={Calendar03Icon} strokeWidth={2} />
          {deadlines.length} {deadlines.length === 1 ? "deadline" : "deadlines"}
        </Badge>
      </div>

      {deadlines.length === 0 ? (
        <div className="rounded-[var(--radius-default)] border border-dashed bg-[var(--surface-secondary)] px-6 py-14 text-center">
          <div className="mx-auto mb-4 flex size-11 items-center justify-center rounded-[var(--radius-default)] border bg-[var(--surface)] shadow-[var(--fancy-shadow-basic)]">
            <HugeiconsIcon
              icon={Calendar03Icon}
              strokeWidth={2}
              className="size-5 text-[var(--text-secondary)]"
            />
          </div>
          <h2 className="text-base font-medium">Nothing due yet</h2>
          <p className="mx-auto mt-1 max-w-md text-sm leading-6 text-[var(--text-secondary)]">
            Add expiry, renewal, warranty, return, refund, or subscription dates to supported vault
            items and they will appear here.
          </p>
        </div>
      ) : (
        <div className="space-y-8">
          {groups.map((group) =>
            group.items.length > 0 ? (
              <section key={group.key} className="space-y-3">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <HugeiconsIcon
                        icon={group.key === "overdue" ? Alert02Icon : Clock01Icon}
                        strokeWidth={2}
                        className={
                          group.key === "overdue"
                            ? "size-4 text-[var(--danger)]"
                            : "size-4 text-[var(--text-secondary)]"
                        }
                      />
                      <h2 className="text-sm font-semibold">{group.title}</h2>
                    </div>
                    <p className="mt-1 text-xs text-[var(--text-secondary)]">{group.description}</p>
                  </div>
                  <Badge variant={group.key === "overdue" ? "destructive" : "secondary"}>
                    {group.items.length}
                  </Badge>
                </div>

                <div className="overflow-hidden rounded-[var(--radius-default)] border bg-[var(--surface)]">
                  {group.items.map((deadline, index) => (
                    <div key={`${deadline.itemId}:${deadline.label}`}>
                      {index > 0 ? <Separator /> : null}
                      <Button
                        type="button"
                        variant="ghost"
                        onClick={() => onOpen(deadline)}
                        className="h-auto w-full justify-start rounded-none px-4 py-4 text-left hover:bg-[var(--hover-bg)]"
                      >
                        <div className="flex min-w-0 flex-1 items-center gap-3">
                          <div className="flex size-9 shrink-0 items-center justify-center rounded-[var(--radius-default)] border bg-[var(--surface)] text-[var(--text-secondary)]">
                            <HugeiconsIcon icon={Calendar03Icon} strokeWidth={2} className="size-4" />
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                              <span className="truncate text-sm font-medium">{deadline.title}</span>
                              <span className="text-xs text-[var(--text-secondary)]">
                                {kindLabel(deadline.kind)}
                              </span>
                            </div>
                            <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-[var(--text-secondary)]">
                              <span>{deadline.label}</span>
                              <span aria-hidden="true">•</span>
                              <span>{deadline.date}</span>
                              <span aria-hidden="true">•</span>
                              <span
                                className={
                                  deadline.daysUntil < 0 ? "font-medium text-[var(--danger)]" : undefined
                                }
                              >
                                {relativeLabel(deadline.daysUntil)}
                              </span>
                            </div>
                          </div>
                          <HugeiconsIcon
                            icon={ArrowRight01Icon}
                            strokeWidth={2}
                            className="size-4 shrink-0 text-[var(--text-secondary)]"
                          />
                        </div>
                      </Button>
                    </div>
                  ))}
                </div>
              </section>
            ) : null,
          )}
        </div>
      )}
    </section>
  )
}
