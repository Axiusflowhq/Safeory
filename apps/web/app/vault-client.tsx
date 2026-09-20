"use client"

import { useMemo, useState } from "react"
import Image from "next/image"
import {
  Add01Icon,
  FileViewIcon,
  FolderOpenIcon,
  Search01Icon,
  SecurityWarningIcon,
} from "@hugeicons/core-free-icons"
import { HugeiconsIcon } from "@hugeicons/react"
import {
  BillListIcon,
  BoxIcon,
  CalendarDateIcon,
  CarIcon,
  DocumentsIcon,
  FolderWithFilesIcon,
  Home2Icon,
  LockKeyholeIcon as SolarLockKeyholeIcon,
  LockPasswordIcon,
  NotesIcon,
  RepeatIcon,
  SettingsIcon,
  ShieldCheckIcon,
  TrashBin2Icon,
  UserIdIcon,
  UsersGroupRoundedIcon,
  WalletMoneyIcon,
} from "@solar-icons/react/bold"

import { EmergencyCardEditor } from "@/components/safeory/EmergencyCardEditor"
import { DevicePairingPanel } from "@/components/safeory/DevicePairingPanel"
import { ExportPanel } from "@/components/safeory/ExportPanel"
import { ItemEditor } from "@/components/safeory/ItemEditor"
import { PassphraseGate } from "@/components/safeory/PassphraseGate"
import { PassphraseChangePanel } from "@/components/safeory/PassphraseChangePanel"
import { RecoveryKitPanel } from "@/components/safeory/RecoveryKitPanel"
import { SyncPanel } from "@/components/safeory/SyncPanel"
import { TodayView } from "@/components/safeory/TodayView"
import { TrashView } from "@/components/safeory/TrashView"
import { TrustedPeopleEditor } from "@/components/safeory/TrustedPeopleEditor"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { FancyButton } from "@/components/ui/fancy-button"
import { Input } from "@/components/ui/input"
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
import type { DeadlineSummary } from "@safeory/contracts"
import { itemKindIcon } from "@/lib/vault/record-visuals"
import {
  ITEM_KINDS,
  kindLabel,
  type ItemKind,
  type VaultItemJson,
} from "@/lib/vault/items"
import { useVault, type EditableEntry } from "@/lib/vault/use-vault"

type View =
  "today" | "items" | "trash" | "trusted-people" | "emergency" | "settings"

const SIDEBAR_ITEM_ICONS = {
  password: LockPasswordIcon,
  secure_note: NotesIcon,
  document: DocumentsIcon,
  insurance: ShieldCheckIcon,
  financial: WalletMoneyIcon,
  property: Home2Icon,
  vehicle: CarIcon,
  possession: BoxIcon,
  receipt: BillListIcon,
  subscription: RepeatIcon,
} satisfies Record<ItemKind, typeof LockPasswordIcon>

export function VaultClient() {
  const vault = useVault()

  if (vault.phase === "loading") {
    return <LoadingVault />
  }

  if (vault.phase === "load_error") {
    return (
      <main className="grid min-h-svh place-items-center bg-[var(--surface-secondary)] p-6">
        <div className="w-full max-w-lg space-y-5 rounded-[var(--radius-default)] border bg-[var(--surface)] p-7 shadow-[var(--fancy-shadow-basic)]">
          <div className="flex size-11 items-center justify-center rounded-[var(--radius-default)] bg-[var(--danger)]/10 text-[var(--danger)]">
            <HugeiconsIcon
              icon={SecurityWarningIcon}
              strokeWidth={2}
              className="size-5"
            />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight">
              Unable to load your vault
            </h1>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
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
        onImportBackup={
          vault.phase === "setup" ? vault.importEncryptedBackup : undefined
        }
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
  const [deadlines, setDeadlines] = useState<DeadlineSummary[]>([])

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
      return (
        normalizedQuery.length === 0 ||
        entry.item.title.toLowerCase().includes(normalizedQuery)
      )
    })
  }, [activeKind, query, vault.items])

  function selectItems(kind: ItemKind | "all") {
    setDeadlines([])
    setView("items")
    setActiveKind(kind)
    setCreating(false)
    setEditing(null)
  }

  function selectToday() {
    setDeadlines(vault.getDeadlines())
    setView("today")
    setCreating(false)
    setEditing(null)
  }

  async function saveItem(
    item: VaultItemJson,
    expectedRevision: number | null
  ) {
    const saved =
      expectedRevision === null
        ? await vault.putItem(item)
        : await vault.updateItem(item, expectedRevision)
    if (saved) {
      setCreating(false)
      setEditing(null)
    }
  }

  return (
    <SidebarProvider>
      <a
        href="#main-content"
        className="fixed top-3 left-3 z-[100] -translate-y-20 rounded-[var(--radius-default)] bg-[var(--surface)] px-3 py-2 text-sm font-medium text-[var(--text-primary)] shadow-[var(--fancy-shadow-neutral)] outline-none focus-visible:translate-y-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ring)]"
      >
        Skip to content
      </a>
      <Sidebar collapsible="icon" className="border-[var(--border)]">
        <SidebarHeader className="px-3 py-3 group-data-[collapsible=icon]:px-2">
          <div className="flex h-10 items-center gap-2 overflow-hidden rounded-[var(--radius-default)] px-1.5 group-data-[collapsible=icon]:px-0">
            <div className="flex size-8 shrink-0 items-center justify-center">
              <Image
                src="/branding-assets/safeory-logo.svg"
                alt=""
                width={48}
                height={48}
                aria-hidden="true"
                className="size-8"
                priority
              />
            </div>
            <div className="min-w-0 group-data-[collapsible=icon]:hidden">
              <p className="truncate text-sm font-semibold tracking-tight">
                Safeory
              </p>
              <p className="truncate text-[11px] text-[var(--text-secondary)]">
                Private life vault
              </p>
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
                    tooltip="Today"
                    isActive={view === "today"}
                    onClick={selectToday}
                  >
                    <CalendarDateIcon className="size-[18px]" aria-hidden="true" />
                    <span>Today</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton
                    tooltip="All items"
                    isActive={view === "items" && activeKind === "all"}
                    onClick={() => selectItems("all")}
                  >
                    <FolderWithFilesIcon className="size-[18px]" aria-hidden="true" />
                    <span>All items</span>
                  </SidebarMenuButton>
                  <SidebarMenuBadge className="tabular-nums">
                    {vault.items.length}
                  </SidebarMenuBadge>
                </SidebarMenuItem>
                {ITEM_KINDS.map(({ kind, label }) => {
                  const ItemIcon = SIDEBAR_ITEM_ICONS[kind]
                  return (
                    <SidebarMenuItem key={kind}>
                      <SidebarMenuButton
                        tooltip={label}
                        isActive={view === "items" && activeKind === kind}
                        onClick={() => selectItems(kind)}
                      >
                        <ItemIcon className="size-[18px]" aria-hidden="true" />
                        <span>{label}</span>
                      </SidebarMenuButton>
                      <SidebarMenuBadge className="tabular-nums">
                        {counts.get(kind) ?? 0}
                      </SidebarMenuBadge>
                    </SidebarMenuItem>
                  )
                })}
                <SidebarMenuItem>
                  <SidebarMenuButton
                    tooltip="Trash"
                    isActive={view === "trash"}
                    onClick={() => {
                      setDeadlines([])
                      setView("trash")
                      setCreating(false)
                      setEditing(null)
                    }}
                  >
                    <TrashBin2Icon className="size-[18px]" aria-hidden="true" />
                    <span>Trash</span>
                  </SidebarMenuButton>
                  <SidebarMenuBadge className="tabular-nums">
                    {vault.trashedItems.length}
                  </SidebarMenuBadge>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
          <SidebarGroup>
            <SidebarGroupLabel>Continuity</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton
                    tooltip="Trusted people"
                    isActive={view === "trusted-people"}
                    onClick={() => {
                      setDeadlines([])
                      setView("trusted-people")
                      setCreating(false)
                      setEditing(null)
                    }}
                  >
                    <UsersGroupRoundedIcon className="size-[18px]" aria-hidden="true" />
                    <span>Trusted people</span>
                  </SidebarMenuButton>
                  <SidebarMenuBadge className="tabular-nums">
                    {vault.getEmergencyCard()?.card.contacts.length ?? 0}
                  </SidebarMenuBadge>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton
                    tooltip="Emergency card"
                    isActive={view === "emergency"}
                    onClick={() => {
                      setDeadlines([])
                      setView("emergency")
                      setCreating(false)
                      setEditing(null)
                    }}
                  >
                    <UserIdIcon className="size-[18px]" aria-hidden="true" />
                    <span>Emergency card</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton
                    tooltip="Settings"
                    isActive={view === "settings"}
                    onClick={() => {
                      setDeadlines([])
                      setView("settings")
                      setCreating(false)
                      setEditing(null)
                    }}
                  >
                    <SettingsIcon className="size-[18px]" aria-hidden="true" />
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
                <SolarLockKeyholeIcon className="size-[18px]" aria-hidden="true" />
                <span>Lock vault</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
      </Sidebar>

      <SidebarInset
        id="main-content"
        tabIndex={-1}
        className="min-w-0 bg-[var(--surface)] outline-none"
      >
        <header className="flex h-[3.25rem] shrink-0 items-center gap-2 px-4 [border-bottom:var(--border-width)_solid_var(--border)] md:px-6">
          <SidebarTrigger />
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-[var(--text-primary)]">
              {view === "today"
                ? "Today"
                : view === "items"
                  ? activeKind === "all"
                    ? "All items"
                    : kindLabel(activeKind)
                  : view === "trash"
                    ? "Trash"
                    : view === "trusted-people"
                      ? "Trusted people"
                      : view === "emergency"
                        ? "Emergency card"
                        : "Settings"}
            </p>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <Badge variant="outline" className="hidden sm:inline-flex">
              {vault.syncStatus.phase === "ready"
                ? "Encrypted sync on"
                : vault.syncStatus.phase === "syncing"
                  ? "Syncing encrypted vault"
                  : "Local encrypted vault"}
            </Badge>
            {view === "items" ? (
              <FancyButton
                variant="primary"
                size="xsmall"
                className="h-7"
                onClick={() => {
                  setCreating(true)
                  setEditing(null)
                }}
                leadingIcon={
                  <HugeiconsIcon icon={Add01Icon} strokeWidth={2} />
                }
              >
                New item
              </FancyButton>
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

        {view === "today" ? (
          <TodayView
            deadlines={deadlines}
            onAddItem={() => {
              setDeadlines([])
              setView("items")
              setActiveKind("all")
              setEditing(null)
              setCreating(true)
            }}
            onOpen={(deadline) => {
              const detail = vault.getItem({
                item: {
                  id: deadline.itemId,
                  title: deadline.title,
                  kind: deadline.kind,
                },
                revision: deadline.revision,
              })
              if (!detail) return
              setDeadlines([])
              setView("items")
              setActiveKind(deadline.kind as ItemKind)
              setCreating(false)
              setEditing(detail)
            }}
          />
        ) : null}

        {view === "items" ? (
          <div className="grid min-h-0 flex-1 grid-cols-1 xl:grid-cols-[minmax(20rem,0.8fr)_minmax(28rem,1.2fr)]">
            <section className="min-w-0 border-r bg-[var(--surface-secondary)]">
              <div className="border-b p-4 md:p-5">
                <label
                  htmlFor="safeory-item-search"
                  className="mb-2 block text-xs font-medium text-[var(--text-secondary)]"
                >
                  Search items
                </label>
                <div className="relative">
                  <HugeiconsIcon
                    icon={Search01Icon}
                    strokeWidth={2}
                    className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-[var(--icon)]"
                  />
                  <Input
                    id="safeory-item-search"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="Search this view"
                    className="pl-9"
                  />
                </div>
              </div>
              <div className="max-h-[calc(100svh-7.5rem)] overflow-y-auto p-2 md:p-3">
                {filteredItems.length === 0 ? (
                  <EmptyList
                    activeKind={activeKind}
                    onNew={() => setCreating(true)}
                  />
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
                          title={`${entry.item.title} â€” ${kindLabel(entry.item.kind)}`}
                          className="flex w-full items-start gap-3 rounded-[var(--radius-default)] px-3 py-3 text-left outline-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--ring)] active:scale-[0.97] data-[selected=true]:bg-[var(--active-bg)] motion-safe:transition-[scale] motion-safe:duration-200 motion-safe:ease-out motion-safe:will-change-transform [@media(hover:hover)]:hover:bg-[var(--hover-bg)]"
                          data-selected={selected}
                        >
                          <div className="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-[var(--radius-default)] border bg-[var(--surface)] text-[var(--icon)]">
                            <HugeiconsIcon
                              icon={itemKindIcon(entry.item.kind)}
                              strokeWidth={2}
                              className="size-4"
                            />
                          </div>
                          <div className="min-w-0 flex-1">
                            <p className="truncate text-sm font-medium">
                              {entry.item.title}
                            </p>
                            <p className="mt-0.5 truncate text-xs text-[var(--text-secondary)]">
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

            <section className="min-w-0 bg-[var(--surface)] p-5 md:p-7 lg:p-9">
              {creating || editing ? (
                <div className="mx-auto w-full max-w-2xl">
                  <div className="mb-6">
                    <p className="text-xs font-medium tracking-wide text-[var(--text-secondary)] uppercase">
                      {editing ? "Edit record" : "Create record"}
                    </p>
                    <h1 className="mt-1 text-2xl font-semibold tracking-tight">
                      {editing ? editing.item.title : "New item"}
                    </h1>
                  </div>
                  <ItemEditor
                    existing={editing}
                    defaultKind={
                      activeKind === "all" ? "secure_note" : activeKind
                    }
                    onSave={saveItem}
                    onCancel={() => {
                      setCreating(false)
                      setEditing(null)
                    }}
                    onTrash={
                      editing
                        ? async () => {
                            const trashed = await vault.trashItem(
                              editing.item.id,
                              editing.revision
                            )
                            if (trashed) setEditing(null)
                          }
                        : undefined
                    }
                    generatePassword={vault.generatePassword}
                    trustedPrincipals={
                      vault.getEmergencyCard()?.card.principals ?? []
                    }
                    onOwnerChange={setEditing}
                    getAttachments={vault.getAttachments}
                    addAttachment={vault.addAttachment}
                    deleteAttachment={vault.deleteAttachment}
                    downloadAttachment={vault.downloadAttachment}
                  />
                </div>
              ) : (
                <DetailPlaceholder />
              )}
            </section>
          </div>
        ) : null}

        {view === "trash" ? (
          <TrashView
            items={vault.trashedItems}
            onRestore={vault.restoreItem}
            onPurge={vault.purgeItem}
          />
        ) : null}

        {view === "emergency" ? (
          <section className="mx-auto w-full max-w-3xl p-5 md:p-8 lg:p-10">
            <div className="mb-7">
              <p className="text-sm font-medium text-[var(--primary)]">
                Life continuity
              </p>
              <h1 className="mt-1 text-2xl font-semibold tracking-tight">
                Emergency card
              </h1>
              <p className="mt-2 max-w-[65ch] text-sm leading-6 text-pretty text-[var(--text-secondary)]">
                Keep the instructions and trusted contacts somebody would need
                during an emergency, encrypted with the rest of your vault.
              </p>
            </div>
            <EmergencyCardEditor
              initial={vault.getEmergencyCard()?.card ?? null}
              onSaveInstructions={vault.setEmergencyInstructions}
            />
          </section>
        ) : null}

        {view === "trusted-people" ? (
          <section className="mx-auto w-full max-w-3xl p-5 md:p-8 lg:p-10">
            <div className="mb-7">
              <p className="text-sm font-medium text-[var(--primary)]">
                Life continuity
              </p>
              <h1 className="mt-1 text-2xl font-semibold tracking-tight">
                Trusted people
              </h1>
              <p className="mt-2 max-w-[65ch] text-sm leading-6 text-pretty text-[var(--text-secondary)]">
                Keep the people who should be contacted during an emergency in
                one encrypted place.
              </p>
            </div>
            <DevicePairingPanel
              listIdentities={vault.listBrowserDeviceIdentities}
              createIdentity={vault.createBrowserDeviceIdentity}
              deleteIdentity={vault.deleteBrowserDeviceIdentity}
              answerChallenge={vault.answerBrowserPairingChallenge}
            />
            <TrustedPeopleEditor
              initialContacts={vault.getEmergencyCard()?.card.contacts ?? []}
              initialPrincipals={
                vault.getEmergencyCard()?.card.principals ?? []
              }
              onSaveContacts={vault.setEmergencyContacts}
              onSavePrincipals={vault.setTrustedPrincipals}
              onCreatePairingChallenge={vault.createTrustedDevicePairingChallenge}
              onCompletePairing={vault.completeTrustedDevicePairing}
            />
          </section>
        ) : null}

        {view === "settings" ? (
          <section className="mx-auto w-full max-w-3xl p-5 md:p-8 lg:p-10">
            <div className="mb-7">
              <p className="text-sm font-medium text-[var(--primary)]">
                Vault security
              </p>
              <h1 className="mt-1 text-2xl font-semibold tracking-tight">
                Recovery & access
              </h1>
              <p className="mt-2 max-w-[65ch] text-sm leading-6 text-pretty text-[var(--text-secondary)]">
                Recovery material stays client-side. Safeory cannot retrieve
                your master passphrase or recovery key for you.
              </p>
            </div>
            <RecoveryKitPanel
              hasRecoveryKit={vault.hasRecoveryKit}
              generatedSecret={vault.generatedSecret}
              onInstall={vault.installRecoveryKit}
              onClearSecret={vault.clearGeneratedSecret}
            />
            <div className="mt-5">
              <SyncPanel
                status={vault.syncStatus}
                onGenerateAccountSecret={vault.generateAccountSecret}
                onEnroll={vault.enrollSync}
                onApproveDevice={vault.approveSyncDevice}
                onRetry={vault.retrySync}
                onResetInvalidConfiguration={vault.resetInvalidSyncConfiguration}
                onSyncNow={vault.syncNow}
              />
            </div>
            <PassphraseChangePanel
              onChangePassphrase={vault.changePassphrase}
            />
            <ExportPanel
              onExportReadable={vault.exportReadableVault}
              onExportEncrypted={vault.exportEncryptedSnapshot}
            />
          </section>
        ) : null}
      </SidebarInset>
    </SidebarProvider>
  )
}

function EmptyList({
  activeKind,
  onNew,
}: {
  activeKind: ItemKind | "all"
  onNew: () => void
}) {
  return (
    <div className="flex min-h-72 flex-col items-center justify-center px-6 text-center">
      <div className="mb-4 flex size-11 items-center justify-center rounded-[var(--radius-default)] border bg-[var(--surface)] shadow-[var(--fancy-shadow-basic)]">
        <HugeiconsIcon
          icon={FolderOpenIcon}
          strokeWidth={2}
          className="size-5 text-[var(--icon)]"
        />
      </div>
      <p className="text-sm font-medium">
        No{" "}
        {activeKind === "all" ? "items" : kindLabel(activeKind).toLowerCase()}{" "}
        yet
      </p>
      <p className="mt-1 max-w-[65ch] text-xs leading-5 text-pretty text-[var(--text-secondary)]">
        Add your first record. It will be encrypted locally before it is
        persisted.
      </p>
      <Button variant="outline" size="sm" className="mt-4" onClick={onNew}>
        <HugeiconsIcon
          icon={Add01Icon}
          strokeWidth={2}
          data-icon="inline-start"
        />
        Add item
      </Button>
    </div>
  )
}

function DetailPlaceholder() {
  return (
    <div className="flex min-h-[60svh] flex-col items-center justify-center text-center">
      <div className="mb-5 flex size-12 items-center justify-center rounded-[var(--radius-default)] bg-[var(--surface-secondary)] text-[var(--icon)]">
        <HugeiconsIcon
          icon={FileViewIcon}
          strokeWidth={2}
          className="size-5"
        />
      </div>
      <h2 className="text-base font-medium">Select an item</h2>
      <p className="mt-1 max-w-[65ch] text-sm leading-6 text-pretty text-[var(--text-secondary)]">
        Safeory keeps the item list redacted. Protected fields are decrypted
        only when you open a specific record.
      </p>
    </div>
  )
}

function LoadingVault() {
  return (
    <SidebarProvider>
      <Sidebar collapsible="icon" className="border-[var(--border)]">
        <SidebarHeader className="px-3 py-3 group-data-[collapsible=icon]:px-2">
          <div className="flex h-10 items-center gap-2 overflow-hidden rounded-[var(--radius-default)] px-1.5 group-data-[collapsible=icon]:px-0">
            <div className="flex size-8 shrink-0 items-center justify-center">
              <Image
                src="/branding-assets/safeory-logo.svg"
                alt=""
                width={48}
                height={48}
                aria-hidden="true"
                className="size-8"
                priority
              />
            </div>
            <div className="min-w-0 group-data-[collapsible=icon]:hidden">
              <p className="truncate text-sm font-semibold tracking-tight">
                Safeory
              </p>
              <p className="truncate text-[11px] text-[var(--text-secondary)]">
                Private life vault
              </p>
            </div>
          </div>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>Vault</SidebarGroupLabel>
            <SidebarGroupContent>
              <div className="space-y-1 px-2">
                {Array.from({ length: 6 }).map((_, index) => (
                  <Skeleton
                    key={index}
                    className="h-8 w-full rounded-[var(--radius-default)]"
                  />
                ))}
              </div>
            </SidebarGroupContent>
          </SidebarGroup>
          <SidebarGroup>
            <SidebarGroupLabel>Continuity</SidebarGroupLabel>
            <SidebarGroupContent>
              <div className="space-y-1 px-2">
                {Array.from({ length: 3 }).map((_, index) => (
                  <Skeleton
                    key={index}
                    className="h-8 w-full rounded-[var(--radius-default)]"
                  />
                ))}
              </div>
            </SidebarGroupContent>
          </SidebarGroup>
        </SidebarContent>
        <SidebarFooter className="p-3">
          <Skeleton className="h-8 w-full rounded-[var(--radius-default)]" />
        </SidebarFooter>
      </Sidebar>

      <SidebarInset className="min-w-0 bg-[var(--surface)] outline-none">
        <header className="flex h-[3.25rem] shrink-0 items-center gap-2 px-4 [border-bottom:var(--border-width)_solid_var(--border)] md:px-6">
          <SidebarTrigger disabled />
          <Skeleton className="h-4 w-20" />
          <div className="ml-auto">
            <Skeleton className="h-7 w-32 rounded-[var(--radius-default)]" />
          </div>
        </header>
        <div
          className="flex min-h-0 flex-1 items-center justify-center"
          role="status"
          aria-live="polite"
        >
          <div className="text-center">
            <p className="text-sm font-medium text-[var(--text-primary)]">
              Opening Safeory
            </p>
            <p className="mt-1 text-xs text-[var(--text-secondary)]">
              Loading your encrypted local vaultâ€¦
            </p>
          </div>
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
