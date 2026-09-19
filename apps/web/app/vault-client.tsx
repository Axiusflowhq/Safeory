"use client"

import { useMemo, useState } from "react"
import {
  Add01Icon,
  BankIcon,
  Building03Icon,
  Car01Icon,
  Contact01Icon,
  DocumentValidationIcon,
  FileTextIcon,
  Key01Icon,
  LockIcon,
  PackageIcon,
  ReceiptDollarIcon,
  Search01Icon,
  Settings01Icon,
  ShieldCheckIcon,
  Wallet02Icon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"

import { EmergencyCardEditor } from "@/components/safeory/EmergencyCardEditor"
import { ItemEditor } from "@/components/safeory/ItemEditor"
import { PassphraseGate } from "@/components/safeory/PassphraseGate"
import { RecoveryKitPanel } from "@/components/safeory/RecoveryKitPanel"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { Skeleton } from "@/components/ui/skeleton"
import { ITEM_KINDS, kindLabel, type ItemKind, type VaultItemJson } from "@/lib/vault/items"
import { useVault, type EditableEntry } from "@/lib/vault/use-vault"

type View = "items" | "emergency" | "settings"

const categoryIcons = {
  password: Key01Icon,
  secure_note: FileTextIcon,
  document: DocumentValidationIcon,
  insurance: ShieldCheckIcon,
  financial: BankIcon,
  property: Building03Icon,
  vehicle: Car01Icon,
  possession: PackageIcon,
  receipt: ReceiptDollarIcon,
  subscription: Wallet02Icon,
} satisfies Record<ItemKind, Parameters<typeof HugeiconsIcon>[0]["icon"]>

export function VaultClient() {
  const vault = useVault()

  if (vault.phase === "loading") {
    return <LoadingVault />
  }

  if (vault.phase === "load_error") {
    return (
      <main className="grid min-h-svh place-items-center bg-muted/30 p-6">
        <div className="w-full max-w-lg space-y-5 rounded-2xl border bg-card p-7 shadow-sm">
          <div className="flex size-11 items-center justify-center rounded-xl bg-destructive/10 text-destructive">
            <HugeiconsIcon icon={ShieldCheckIcon} strokeWidth={2} className="size-5" />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Unable to load your vault</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Safeory left the stored encrypted data unchanged.
            </p>
          </div>
          {vault.error ? (
            <Alert variant="destructive">
              <AlertTitle>Vault load failed</AlertTitle>
              <AlertDescription>{vault.error}</AlertDescription>
            </Alert>
          ) : null}
          <Button variant="outline" onClick={() => window.location.reload()}>
            Reload Safeory
          </Button>
        </div>
      </main>
    )
  }

  if (vault.phase === "setup" || vault.phase === "unlock") {
    return (
      <PassphraseGate
        mode={vault.phase === "setup" ? "setup" : "unlock"}
        error={vault.error}
        onSubmit={vault.phase === "setup" ? vault.create : vault.unlock}
        onRecoveryUnlock={vault.unlockWithRecoveryKit}
      />
    )
  }

  return <VaultWorkspace vault={vault} />
}

type Vault = ReturnType<typeof useVault>

function VaultWorkspace({ vault }: { vault: Vault }) {
  const [view, setView] = useState<View>("items")
  const [activeKind, setActiveKind] = useState<ItemKind | "all">("all")
  const [query, setQuery] = useState("")
  const [editing, setEditing] = useState<EditableEntry | null>(null)
  const [creating, setCreating] = useState(false)

  const counts = useMemo(() => {
    const values = new Map<string, number>()
    for (const entry of vault.items) {
      values.set(entry.item.kind, (values.get(entry.item.kind) ?? 0) + 1)
    }
    return values
  }, [vault.items])

  const filteredItems = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    return vault.items.filter((entry) => {
      if (activeKind !== "all" && entry.item.kind !== activeKind) return false
      return normalizedQuery.length === 0 || entry.item.title.toLowerCase().includes(normalizedQuery)
    })
  }, [activeKind, query, vault.items])

  function selectItems(kind: ItemKind | "all") {
    setView("items")
    setActiveKind(kind)
    setCreating(false)
    setEditing(null)
  }

  function saveItem(item: VaultItemJson, expectedRevision: number | null) {
    if (expectedRevision === null) {
      vault.putItem(item)
    } else {
      vault.updateItem(item, expectedRevision)
    }
    setCreating(false)
    setEditing(null)
  }

  return (
    <SidebarProvider>
      <Sidebar collapsible="icon" className="border-sidebar-border">
        <SidebarHeader className="px-3 py-3">
          <div className="flex h-10 items-center gap-2 overflow-hidden rounded-lg px-1.5">
            <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-sm">
              <HugeiconsIcon icon={ShieldCheckIcon} strokeWidth={2} className="size-4" />
            </div>
            <div className="min-w-0 group-data-[collapsible=icon]:hidden">
              <p className="truncate text-sm font-semibold tracking-tight">Safeory</p>
              <p className="truncate text-[11px] text-muted-foreground">Private life vault</p>
            </div>
          </div>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>Vault</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton
                    tooltip="All items"
                    isActive={view === "items" && activeKind === "all"}
                    onClick={() => selectItems("all")}
                  >
                    <HugeiconsIcon icon={PackageIcon} strokeWidth={2} />
                    <span>All items</span>
                  </SidebarMenuButton>
                  <SidebarMenuBadge>{vault.items.length}</SidebarMenuBadge>
                </SidebarMenuItem>
                {ITEM_KINDS.map(({ kind, label }) => (
                  <SidebarMenuItem key={kind}>
                    <SidebarMenuButton
                      tooltip={label}
                      isActive={view === "items" && activeKind === kind}
                      onClick={() => selectItems(kind)}
                    >
                      <HugeiconsIcon icon={categoryIcons[kind]} strokeWidth={2} />
                      <span>{label}</span>
                    </SidebarMenuButton>
                    <SidebarMenuBadge>{counts.get(kind) ?? 0}</SidebarMenuBadge>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
          <SidebarGroup>
            <SidebarGroupLabel>Continuity</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton
                    tooltip="Emergency card"
                    isActive={view === "emergency"}
                    onClick={() => {
                      setView("emergency")
                      setCreating(false)
                      setEditing(null)
                    }}
                  >
                    <HugeiconsIcon icon={Contact01Icon} strokeWidth={2} />
                    <span>Emergency card</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton
                    tooltip="Settings"
                    isActive={view === "settings"}
                    onClick={() => {
                      setView("settings")
                      setCreating(false)
                      setEditing(null)
                    }}
                  >
                    <HugeiconsIcon icon={Settings01Icon} strokeWidth={2} />
                    <span>Settings</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
        <SidebarFooter className="p-3">
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton tooltip="Lock vault" onClick={vault.lock}>
                <HugeiconsIcon icon={LockIcon} strokeWidth={2} />
                <span>Lock vault</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
      </Sidebar>

      <SidebarInset className="min-w-0 bg-background">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b px-4 md:px-6">
          <SidebarTrigger />
          <Separator orientation="vertical" className="h-4" />
          <div className="min-w-0">
            <p className="truncate text-sm font-medium">
              {view === "items"
                ? activeKind === "all"
                  ? "All items"
                  : kindLabel(activeKind)
                : view === "emergency"
                  ? "Emergency card"
                  : "Settings"}
            </p>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <Badge variant="outline" className="hidden sm:inline-flex">
              Local encrypted vault
            </Badge>
            {view === "items" ? (
              <Button
                onClick={() => {
                  setCreating(true)
                  setEditing(null)
                }}
              >
                <HugeiconsIcon icon={Add01Icon} strokeWidth={2} data-icon="inline-start" />
                New item
              </Button>
            ) : null}
          </div>
        </header>

        {vault.error ? (
          <div className="px-4 pt-4 md:px-6">
            <Alert variant="destructive">
              <AlertTitle>Action failed</AlertTitle>
              <AlertDescription>{vault.error}</AlertDescription>
            </Alert>
          </div>
        ) : null}

        {view === "items" ? (
          <div className="grid min-h-0 flex-1 grid-cols-1 xl:grid-cols-[minmax(20rem,0.8fr)_minmax(28rem,1.2fr)]">
            <section className="min-w-0 border-r bg-muted/15">
              <div className="border-b p-4 md:p-5">
                <div className="relative">
                  <HugeiconsIcon
                    icon={Search01Icon}
                    strokeWidth={2}
                    className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground"
                  />
                  <Input
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="Search this view"
                    className="pl-9"
                  />
                </div>
              </div>
              <div className="max-h-[calc(100svh-7.5rem)] overflow-y-auto p-2 md:p-3">
                {filteredItems.length === 0 ? (
                  <EmptyList activeKind={activeKind} onNew={() => setCreating(true)} />
                ) : (
                  <div className="space-y-1">
                    {filteredItems.map((entry) => {
                      const selected = editing?.item.id === entry.item.id
                      return (
                        <button
                          key={entry.item.id}
                          type="button"
                          onClick={() => {
                            const detail = vault.getItem(entry)
                            if (detail) {
                              setEditing(detail)
                              setCreating(false)
                            }
                          }}
                          className="flex w-full items-start gap-3 rounded-xl px-3 py-3 text-left transition-colors hover:bg-accent data-[selected=true]:bg-accent"
                          data-selected={selected}
                        >
                          <div className="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-lg border bg-background text-muted-foreground">
                            <HugeiconsIcon
                              icon={categoryIcons[entry.item.kind as ItemKind] ?? FileTextIcon}
                              strokeWidth={2}
                              className="size-4"
                            />
                          </div>
                          <div className="min-w-0 flex-1">
                            <p className="truncate text-sm font-medium">{entry.item.title}</p>
                            <p className="mt-0.5 truncate text-xs text-muted-foreground">
                              {kindLabel(entry.item.kind)}
                            </p>
                          </div>
                        </button>
                      )
                    })}
                  </div>
                )}
              </div>
            </section>

            <section className="min-w-0 bg-background p-5 md:p-7 lg:p-9">
              {creating || editing ? (
                <div className="mx-auto w-full max-w-2xl">
                  <div className="mb-6">
                    <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
                      {editing ? "Edit record" : "Create record"}
                    </p>
                    <h1 className="mt-1 text-2xl font-semibold tracking-tight">
                      {editing ? editing.item.title : "New item"}
                    </h1>
                  </div>
                  <ItemEditor
                    existing={editing}
                    defaultKind={activeKind === "all" ? "secure_note" : activeKind}
                    onSave={saveItem}
                    onCancel={() => {
                      setCreating(false)
                      setEditing(null)
                    }}
                    onTrash={
                      editing
                        ? () => {
                            vault.trashItem(editing.item.id, editing.revision)
                            setEditing(null)
                          }
                        : undefined
                    }
                    generatePassword={vault.generatePassword}
                  />
                </div>
              ) : (
                <DetailPlaceholder />
              )}
            </section>
          </div>
        ) : null}

        {view === "emergency" ? (
          <section className="mx-auto w-full max-w-3xl p-5 md:p-8 lg:p-10">
            <div className="mb-7">
              <p className="text-sm font-medium text-primary">Life continuity</p>
              <h1 className="mt-1 text-2xl font-semibold tracking-tight">Emergency card</h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
                Keep the instructions and trusted contacts somebody would need during an emergency,
                encrypted with the rest of your vault.
              </p>
            </div>
            <EmergencyCardEditor
              initial={vault.getEmergencyCard()?.card ?? null}
              onSave={vault.setEmergencyCard}
            />
          </section>
        ) : null}

        {view === "settings" ? (
          <section className="mx-auto w-full max-w-3xl p-5 md:p-8 lg:p-10">
            <div className="mb-7">
              <p className="text-sm font-medium text-primary">Vault security</p>
              <h1 className="mt-1 text-2xl font-semibold tracking-tight">Recovery & access</h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
                Recovery material stays client-side. Safeory cannot retrieve your master passphrase
                or recovery key for you.
              </p>
            </div>
            <RecoveryKitPanel
              hasRecoveryKit={vault.hasRecoveryKit}
              generatedSecret={vault.generatedSecret}
              onInstall={vault.installRecoveryKit}
              onClearSecret={vault.clearGeneratedSecret}
            />
          </section>
        ) : null}
      </SidebarInset>
    </SidebarProvider>
  )
}

function EmptyList({ activeKind, onNew }: { activeKind: ItemKind | "all"; onNew: () => void }) {
  return (
    <div className="flex min-h-72 flex-col items-center justify-center px-6 text-center">
      <div className="mb-4 flex size-11 items-center justify-center rounded-xl border bg-background shadow-sm">
        <HugeiconsIcon icon={PackageIcon} strokeWidth={2} className="size-5 text-muted-foreground" />
      </div>
      <p className="text-sm font-medium">No {activeKind === "all" ? "items" : kindLabel(activeKind).toLowerCase()} yet</p>
      <p className="mt-1 max-w-56 text-xs leading-5 text-muted-foreground">
        Add your first record. It will be encrypted locally before it is persisted.
      </p>
      <Button variant="outline" size="sm" className="mt-4" onClick={onNew}>
        <HugeiconsIcon icon={Add01Icon} strokeWidth={2} data-icon="inline-start" />
        Add item
      </Button>
    </div>
  )
}

function DetailPlaceholder() {
  return (
    <div className="flex min-h-[60svh] flex-col items-center justify-center text-center">
      <div className="mb-5 flex size-12 items-center justify-center rounded-2xl bg-muted text-muted-foreground">
        <HugeiconsIcon icon={ShieldCheckIcon} strokeWidth={2} className="size-5" />
      </div>
      <h2 className="text-base font-medium">Select an item</h2>
      <p className="mt-1 max-w-sm text-sm leading-6 text-muted-foreground">
        Safeory keeps the item list redacted. Protected fields are decrypted only when you open a
        specific record.
      </p>
    </div>
  )
}

function LoadingVault() {
  return (
    <main className="min-h-svh bg-background p-5">
      <div className="mx-auto flex min-h-[calc(100svh-2.5rem)] max-w-6xl overflow-hidden rounded-2xl border bg-card shadow-sm">
        <aside className="hidden w-64 border-r bg-muted/25 p-4 md:block">
          <div className="mb-6 flex items-center gap-3">
            <Skeleton className="size-9 rounded-xl" />
            <div className="space-y-2">
              <Skeleton className="h-3 w-24" />
              <Skeleton className="h-2.5 w-16" />
            </div>
          </div>
          <div className="space-y-2">
            {Array.from({ length: 8 }).map((_, index) => (
              <Skeleton key={index} className="h-8 w-full rounded-lg" />
            ))}
          </div>
        </aside>
        <section className="flex flex-1 items-center justify-center p-8">
          <div className="text-center">
            <div className="mx-auto mb-4 flex size-10 items-center justify-center rounded-xl bg-primary text-primary-foreground">
              <HugeiconsIcon icon={ShieldCheckIcon} strokeWidth={2} className="size-4" />
            </div>
            <p className="text-sm font-medium">Opening Safeory</p>
            <p className="mt-1 text-xs text-muted-foreground">Loading your encrypted local vault…</p>
          </div>
        </section>
      </div>
    </main>
  )
}
