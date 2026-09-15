import {
  Add01Icon,
  Attachment01Icon,
  ArrowLeft01Icon,
  BankIcon,
  Building03Icon,
  Car01Icon,
  Contact01Icon,
  Copy01Icon,
  DatabaseRestoreIcon,
  Delete02Icon,
  DocumentValidationIcon,
  Download01Icon,
  EyeIcon,
  EyeOffIcon,
  FileEditIcon,
  FileTextIcon,
  Key01Icon,
  Link01Icon,
  LockIcon,
  MagicWand01Icon,
  PackageIcon,
  Search01Icon,
  ShieldCheckIcon,
  ShieldKeyIcon,
  RestoreBinIcon,
  Settings01Icon,
} from "@hugeicons/core-free-icons";
import { HugeiconsIcon } from "@hugeicons/react";
import { ShieldKeyholeBoldIcon } from "@solar-icons/react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { SessionFence } from "./sessionFence";

type VaultStatus = {
  initialized: boolean;
  unlocked: boolean;
  cloud_sync_enabled: boolean;
};

type DeviceSettings = {
  auto_lock_minutes: number;
  lock_on_background: boolean;
};

type GeneratedRecoverySecret = {
  secret: string;
  generation: number;
};

type NoteView = {
  id: string;
  revision: number;
  title: string;
  body: string;
  links: string[];
};

type CredentialView = {
  id: string;
  revision: number;
  title: string;
  username: string;
  website: string;
  notes: string;
  has_password: boolean;
  links: string[];
};

type CredentialDetailView = {
  id: string;
  revision: number;
  title: string;
  username: string;
  password: string;
  website: string;
  notes: string;
};

type DocumentView = {
  id: string;
  revision: number;
  title: string;
  issuer: string;
  expiry: string;
  notes: string;
  has_document_number: boolean;
  links: string[];
};

type DocumentDetailView = {
  id: string;
  revision: number;
  title: string;
  document_number: string;
  issuer: string;
  expiry: string;
  notes: string;
};

type ReceiptView = {
  id: string;
  revision: number;
  title: string;
  merchant: string;
  purchase_date: string;
  amount: string;
  currency: string;
  tracking_status: string;
  return_by: string;
  refund_due: string;
  has_receipt_reference: boolean;
  links: string[];
};

type ReceiptDetailView = {
  id: string;
  revision: number;
  title: string;
  merchant: string;
  purchase_date: string;
  amount: string;
  currency: string;
  receipt_reference: string;
  tracking_status: string;
  return_by: string;
  refund_due: string;
  notes: string;
};

type InsuranceView = {
  id: string;
  revision: number;
  title: string;
  provider: string;
  policy_type: string;
  renewal: string;
  notes: string;
  has_policy_number: boolean;
  links: string[];
};

type InsuranceDetailView = {
  id: string;
  revision: number;
  title: string;
  provider: string;
  policy_type: string;
  policy_number: string;
  renewal: string;
  notes: string;
};

type FinancialView = {
  id: string;
  revision: number;
  title: string;
  institution: string;
  account_type: string;
  currency: string;
  has_account_number: boolean;
  links: string[];
};

type FinancialDetailView = {
  id: string;
  revision: number;
  title: string;
  institution: string;
  account_type: string;
  currency: string;
  account_number: string;
  notes: string;
};

type PropertyView = {
  id: string;
  revision: number;
  title: string;
  property_type: string;
  ownership: string;
  has_address: boolean;
  has_property_reference: boolean;
  links: string[];
};

type PropertyDetailView = {
  id: string;
  revision: number;
  title: string;
  property_type: string;
  address: string;
  ownership: string;
  property_reference: string;
  notes: string;
};

type VehicleView = {
  id: string;
  revision: number;
  title: string;
  make: string;
  model: string;
  year: string;
  renewal: string;
  notes: string;
  has_registration_number: boolean;
  has_vin: boolean;
  links: string[];
};

type VehicleDetailView = {
  id: string;
  revision: number;
  title: string;
  make: string;
  model: string;
  year: string;
  registration_number: string;
  vin: string;
  renewal: string;
  notes: string;
};

type PossessionView = {
  id: string;
  revision: number;
  title: string;
  brand: string;
  model: string;
  purchase_date: string;
  purchase_price: string;
  store: string;
  warranty_expiry: string;
  notes: string;
  has_serial_number: boolean;
  links: string[];
};

type PossessionDetailView = {
  id: string;
  revision: number;
  title: string;
  brand: string;
  model: string;
  serial_number: string;
  purchase_date: string;
  purchase_price: string;
  store: string;
  warranty_expiry: string;
  notes: string;
};

type VaultItem =
  | ({ kind: "secure_note" } & NoteView)
  | ({ kind: "password" } & CredentialView)
  | ({ kind: "document" } & DocumentView)
  | ({ kind: "receipt" } & ReceiptView)
  | ({ kind: "insurance" } & InsuranceView)
  | ({ kind: "financial" } & FinancialView)
  | ({ kind: "property" } & PropertyView)
  | ({ kind: "vehicle" } & VehicleView)
  | ({ kind: "possession" } & PossessionView);

type Section =
  | "secure_note"
  | "password"
  | "document"
  | "receipt"
  | "insurance"
  | "financial"
  | "property"
  | "vehicle"
  | "possession";
type Screen = "loading" | "setup" | "locked" | "vault";
type EditorState =
  | { kind: "secure_note"; item: NoteView | null }
  | { kind: "password"; item: CredentialView | null }
  | { kind: "document"; item: DocumentView | null }
  | { kind: "receipt"; item: ReceiptView | null }
  | { kind: "insurance"; item: InsuranceView | null }
  | { kind: "financial"; item: FinancialView | null }
  | { kind: "property"; item: PropertyView | null }
  | { kind: "vehicle"; item: VehicleView | null }
  | { kind: "possession"; item: PossessionView | null };

type TrashedItemView = {
  id: string;
  revision: number;
  title: string;
  kind: Section;
  deleted_at_ms: number;
};

type EmergencyContact = {
  name: string;
  relation: string;
  phone: string;
  notes: string;
};

type EmergencyCardData = {
  selected_item_ids: string[];
  contacts: EmergencyContact[];
  instructions: string;
};

type EmergencyCardResult = {
  card: EmergencyCardData;
  revision: number;
};

type ItemTitle = {
  id: string;
  kind: string;
  title: string;
};

type DeadlineRow = {
  item_id: string;
  kind: string;
  title: string;
  label: string;
  date: string;
  days_until: number;
};

type PlanReadiness = {
  recovery_configured: boolean;
  has_selected_records: boolean;
  has_contacts: boolean;
  has_instructions: boolean;
  has_stale_selected_records: boolean;
};

type AttachmentSummary = {
  id: string;
  revision: number;
  filename: string;
  plaintext_size: number;
};

type AttachmentAddResult = {
  attachment: AttachmentSummary;
  item_revision: number;
};

type LinkedSectionProps = {
  linkedTitles: ItemTitle[];
  allItems: VaultItem[];
  onJump: (kind: string, id: string) => void;
  onLinksChanged: () => void;
};

type VaultView = "active" | "trash";

const desktopRuntime = isTauri();
const DEFAULT_DEVICE_SETTINGS: DeviceSettings = {
  auto_lock_minutes: 10,
  lock_on_background: true,
};

export default function App() {
  const [screen, setScreen] = useState<Screen>(
    desktopRuntime ? "loading" : "vault",
  );
  const [items, setItems] = useState<VaultItem[]>([]);
  const [section, setSection] = useState<Section>("secure_note");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [query, setQuery] = useState("");
  const [vaultView, setVaultView] = useState<VaultView>("active");
  const [trashItems, setTrashItems] = useState<TrashedItemView[]>([]);
  const [loadingTrash, setLoadingTrash] = useState(false);
  const trashLoadGeneration = useRef(0);
  const deadlineLoadGeneration = useRef(0);
  const [deviceSettings, setDeviceSettings] = useState<DeviceSettings>(
    DEFAULT_DEVICE_SETTINGS,
  );
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [cardOpen, setCardOpen] = useState(false);
  const [planOpen, setPlanOpen] = useState(false);
  const closePlanTest = useCallback(() => setPlanOpen(false), []);
  const [deadlines, setDeadlines] = useState<TodayEntry[] | null>(null);
  const [linkedTitles, setLinkedTitles] = useState<ItemTitle[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [sessionFence] = useState(() => new SessionFence());
  const isSessionGenerationCurrent = useCallback(
    (token: number) => sessionFence.accepts(token),
    [sessionFence],
  );

  const refreshDeadlines = useCallback(
    (token: number) => {
      if (!desktopRuntime) return;
      const requestGeneration = ++deadlineLoadGeneration.current;
      const today = deviceLocalCalendarDate();
      void invoke<DeadlineRow[]>("list_deadlines", {
        todayYear: today.year,
        todayMonth: today.month,
        todayDay: today.day,
      })
        .then((rows) => {
          if (
            !sessionFence.accepts(token) ||
            requestGeneration !== deadlineLoadGeneration.current
          )
            return;
          // Sorted as returned by Rust; TodayPanel renders the top entries as-is.
          setDeadlines(
            rows.slice(0, 8).map((row) => ({
              id: row.item_id,
              title: row.title,
              label: row.label,
              date: row.date,
              daysUntil: row.days_until,
            })),
          );
        })
        .catch(() => {
          // Deadlines are advisory: fall back to local parsing silently.
          if (
            sessionFence.accepts(token) &&
            requestGeneration === deadlineLoadGeneration.current
          ) {
            setDeadlines(null);
          }
        });
    },
    [sessionFence],
  );

  const clearPlaintextUi = useCallback(() => {
    deadlineLoadGeneration.current += 1;
    setItems([]);
    setSelectedId(null);
    setEditor(null);
    setQuery("");
    setVaultView("active");
    setTrashItems([]);
    setSettingsOpen(false);
    setCardOpen(false);
    setPlanOpen(false);
    setDeadlines(null);
    setLinkedTitles([]);
  }, []);

  const lockVault = useCallback(async () => {
    if (!desktopRuntime) return;
    sessionFence.invalidate();
    clearPlaintextUi();
    setError(null);
    setScreen("locked");
    try {
      await invoke("lock_vault");
    } catch {
      setError(
        "The vault UI is locked, but the local session could not be closed cleanly. Close and reopen Safeory before continuing.",
      );
    }
  }, [clearPlaintextUi, sessionFence]);

  useEffect(() => {
    if (!desktopRuntime) return;
    void invoke<VaultStatus>("vault_status")
      .then((status) => {
        if (!status.initialized) setScreen("setup");
        else if (!status.unlocked) setScreen("locked");
        else {
          sessionFence.invalidate();
          setScreen("vault");
        }
      })
      .catch((reason: unknown) => setError(readError(reason)));
  }, [sessionFence]);

  useEffect(() => {
    if (!desktopRuntime || screen !== "vault") return;
    const token = sessionFence.token();
    void fetchVaultItems()
      .then(({ initialSection, items: loaded, selectedId: initialId }) => {
        if (!sessionFence.accepts(token)) return;
        setItems(loaded);
        setSection(initialSection);
        setSelectedId(initialId);
        setError(null);
      })
      .catch((reason: unknown) => {
        if (sessionFence.accepts(token)) setError(readError(reason));
      });
  }, [screen, sessionFence]);

  useEffect(() => {
    if (!desktopRuntime || screen !== "vault") return;
    const token = sessionFence.token();
    void invoke<DeviceSettings>("get_device_settings")
      .then((settings) => {
        if (!sessionFence.accepts(token)) return;
        setDeviceSettings(settings);
      })
      .catch((reason: unknown) => {
        if (sessionFence.accepts(token)) setError(readError(reason));
      });
  }, [screen, sessionFence]);

  const selectedForLinks = items.find((item) => item.id === selectedId) ?? null;
  // Stable effect key carrying both the selected id and its link ids, so the
  // titles request is keyed by selected.id and never reads a stale closure.
  const selectedLinksKey = selectedForLinks
    ? JSON.stringify({
        id: selectedForLinks.id,
        links: selectedForLinks.links ?? [],
      })
    : "";

  useEffect(() => {
    if (!desktopRuntime || screen !== "vault") return;
    const token = sessionFence.token();
    refreshDeadlines(token);
  }, [refreshDeadlines, screen, sessionFence]);

  useEffect(() => {
    if (!desktopRuntime || screen !== "vault") return;
    let currentDay = deviceLocalCalendarDateKey();
    let timeoutId: number | undefined;

    const refreshAfterDayChange = () => {
      const nextDay = deviceLocalCalendarDateKey();
      if (nextDay === currentDay) return;
      currentDay = nextDay;
      refreshDeadlines(sessionFence.token());
    };

    const scheduleNextDayCheck = () => {
      const now = new Date();
      const nextLocalDay = new Date(
        now.getFullYear(),
        now.getMonth(),
        now.getDate() + 1,
        0,
        0,
        1,
        0,
      );
      timeoutId = window.setTimeout(
        () => {
          refreshAfterDayChange();
          scheduleNextDayCheck();
        },
        Math.max(1_000, nextLocalDay.getTime() - now.getTime()),
      );
    };

    const onVisible = () => {
      if (document.visibilityState === "visible") refreshAfterDayChange();
    };

    scheduleNextDayCheck();
    window.addEventListener("focus", refreshAfterDayChange);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      if (timeoutId !== undefined) window.clearTimeout(timeoutId);
      window.removeEventListener("focus", refreshAfterDayChange);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [refreshDeadlines, screen, sessionFence]);

  useEffect(() => {
    if (!desktopRuntime || screen !== "vault") return;
    if (!selectedLinksKey) {
      setLinkedTitles([]);
      return;
    }
    const parsed = JSON.parse(selectedLinksKey) as {
      id: string;
      links: string[];
    };
    if (parsed.links.length === 0) {
      setLinkedTitles([]);
      return;
    }
    const token = sessionFence.token();
    let active = true;
    void invoke<ItemTitle[]>("get_item_titles", { ids: parsed.links })
      .then((titles) => {
        if (!active || !sessionFence.accepts(token)) return;
        setLinkedTitles(titles);
      })
      .catch((reason: unknown) => {
        if (active && sessionFence.accepts(token)) {
          setLinkedTitles([]);
          setError(readError(reason));
        }
      });
    return () => {
      active = false;
    };
  }, [screen, sessionFence, selectedLinksKey]);

  useEffect(() => {
    if (!desktopRuntime || screen !== "vault") return;

    let timer: ReturnType<typeof setTimeout>;
    let lastActivityReport = 0;
    const resetTimer = () => {
      clearTimeout(timer);
      timer = setTimeout(
        () => void lockVault(),
        deviceSettings.auto_lock_minutes * 60 * 1000,
      );
      const now = Date.now();
      if (now - lastActivityReport >= 15_000) {
        lastActivityReport = now;
        void invoke("record_activity").catch(() => undefined);
      }
    };
    const handleVisibilityChange = () => {
      if (document.hidden && deviceSettings.lock_on_background) {
        void lockVault();
      }
    };
    const activityEvents = ["pointerdown", "keydown", "wheel"] as const;
    for (const eventName of activityEvents) {
      window.addEventListener(eventName, resetTimer, { passive: true });
    }
    document.addEventListener("visibilitychange", handleVisibilityChange);
    resetTimer();

    return () => {
      clearTimeout(timer);
      for (const eventName of activityEvents) {
        window.removeEventListener(eventName, resetTimer);
      }
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [deviceSettings, lockVault, screen]);

  if (screen === "loading") {
    return (
      <main className="grid min-h-screen place-items-center bg-[var(--surface)] text-[var(--text-primary)]">
        <div className="max-w-md px-6 text-center">
          {error ? (
            <>
              <div className="text-base font-medium">
                Unable to open the local vault
              </div>
              <div className="mt-2 text-sm leading-6 text-[var(--danger)]">
                {error}
              </div>
            </>
          ) : (
            <div className="text-sm text-[var(--text-muted)]">
              Opening local vault…
            </div>
          )}
        </div>
      </main>
    );
  }

  if (screen === "setup" || screen === "locked") {
    return (
      <AccessScreen
        mode={screen}
        error={error}
        onauccess={() => {
          sessionFence.invalidate();
          setError(null);
          setScreen("vault");
        }}
        onError={setError}
      />
    );
  }

  const noteCount = items.filter((item) => item.kind === "secure_note").length;
  const credentialCount = items.filter(
    (item) => item.kind === "password",
  ).length;
  const documentCount = items.filter((item) => item.kind === "document").length;
  const receiptCount = items.filter((item) => item.kind === "receipt").length;
  const insuranceCount = items.filter(
    (item) => item.kind === "insurance",
  ).length;
  const financialCount = items.filter(
    (item) => item.kind === "financial",
  ).length;
  const propertyCount = items.filter((item) => item.kind === "property").length;
  const vehicleCount = items.filter((item) => item.kind === "vehicle").length;
  const possessionCount = items.filter(
    (item) => item.kind === "possession",
  ).length;
  const selected = items.find((item) => item.id === selectedId) ?? null;
  const needle = query.trim().toLocaleLowerCase();
  const visibleItems = items.filter(
    (item) => item.kind === section && itemMatchesSearch(item, needle),
  );
  const visibleTrashItems = trashItems.filter(
    (item) =>
      item.kind === section &&
      (!needle || item.title.toLocaleLowerCase().includes(needle)),
  );

  const switchSection = (next: Section) => {
    setSection(next);
    setEditor(null);
    setError(null);
    setSelectedId(null);
  };

  const jumpToRecord = (kind: string, id: string) => {
    setCardOpen(false);
    setEditor(null);
    setError(null);
    const target = kindToSection(kind);
    if (target) setSection(target);
    setSelectedId(id);
  };

  const refreshVaultItems = async () => {
    const token = sessionFence.token();
    try {
      const refreshed = await fetchVaultItems();
      if (!sessionFence.accepts(token)) return;
      setItems(refreshed.items);
    } catch (reason) {
      if (sessionFence.accepts(token)) setError(readError(reason));
    }
  };

  const enterTrash = async () => {
    if (!desktopRuntime || loadingTrash) return;
    const token = sessionFence.token();
    const requestGeneration = ++trashLoadGeneration.current;
    setVaultView("trash");
    setSelectedId(null);
    setEditor(null);
    setQuery("");
    setError(null);
    setLoadingTrash(true);
    try {
      const loaded = await invoke<TrashedItemView[]>("list_trashed_items");
      if (
        !sessionFence.accepts(token) ||
        requestGeneration !== trashLoadGeneration.current
      )
        return;
      setTrashItems(loaded);
    } catch (reason) {
      if (
        sessionFence.accepts(token) &&
        requestGeneration === trashLoadGeneration.current
      )
        setError(readError(reason));
    } finally {
      if (
        sessionFence.accepts(token) &&
        requestGeneration === trashLoadGeneration.current
      )
        setLoadingTrash(false);
    }
  };

  const leaveTrash = () => {
    trashLoadGeneration.current += 1;
    setVaultView("active");
    setTrashItems([]);
    setLoadingTrash(false);
    setQuery("");
    setError(null);
  };

  const trashSelected = async () => {
    if (!desktopRuntime || !selected) return;
    if (!window.confirm(`Move “${selected.title}” to Trash?`)) return;
    const token = sessionFence.token();
    setError(null);
    try {
      await invoke<number>("trash_item", {
        id: selected.id,
        revision: selected.revision,
      });
      if (!sessionFence.accepts(token)) return;
      setItems((current) => current.filter((item) => item.id !== selected.id));
      setSelectedId(null);
      refreshDeadlines(token);
    } catch (reason) {
      if (sessionFence.accepts(token)) setError(readError(reason));
    }
  };

  const restoreTrashItem = async (item: TrashedItemView) => {
    const token = sessionFence.token();
    setError(null);
    try {
      await invoke<number>("restore_trashed_item", {
        id: item.id,
        revision: item.revision,
      });
      refreshDeadlines(token);
      const refreshed = await fetchVaultItems();
      if (!sessionFence.accepts(token)) return;
      setItems(refreshed.items);
      setTrashItems((current) =>
        current.filter((candidate) => candidate.id !== item.id),
      );
    } catch (reason) {
      if (sessionFence.accepts(token)) setError(readError(reason));
    }
  };

  const purgeTrashItem = async (item: TrashedItemView) => {
    if (
      !window.confirm(
        `Delete “${item.title}” permanently? The record cannot be restored from Safeory after this.`,
      )
    )
      return;
    const token = sessionFence.token();
    setError(null);
    try {
      await invoke<number>("purge_trashed_item", {
        id: item.id,
        revision: item.revision,
      });
      if (!sessionFence.accepts(token)) return;
      setTrashItems((current) =>
        current.filter((candidate) => candidate.id !== item.id),
      );
    } catch (reason) {
      if (sessionFence.accepts(token)) setError(readError(reason));
    }
  };

  const startNewItem = () => {
    setSelectedId(null);
    setError(null);
    if (section === "secure_note") {
      setEditor({ kind: "secure_note", item: null });
    } else if (section === "password") {
      setEditor({ kind: "password", item: null });
    } else if (section === "document") {
      setEditor({ kind: "document", item: null });
    } else if (section === "receipt") {
      setEditor({ kind: "receipt", item: null });
    } else if (section === "insurance") {
      setEditor({ kind: "insurance", item: null });
    } else if (section === "financial") {
      setEditor({ kind: "financial", item: null });
    } else if (section === "property") {
      setEditor({ kind: "property", item: null });
    } else if (section === "vehicle") {
      setEditor({ kind: "vehicle", item: null });
    } else {
      setEditor({ kind: "possession", item: null });
    }
  };

  const saveItem = (token: number, item: VaultItem, created: boolean) => {
    if (!sessionFence.accepts(token)) return;
    setItems((current) =>
      created
        ? [item, ...current]
        : current.map((candidate) =>
            candidate.id === item.id ? item : candidate,
          ),
    );
    setSelectedId(item.id);
    setEditor(null);
    setError(null);
    refreshDeadlines(token);
  };

  return (
    <main className="min-h-screen bg-[var(--surface)] text-[var(--text-primary)]">
      <header className="border-b border-[var(--border)] bg-[var(--surface)]">
        <div className="mx-auto flex h-16 w-full max-w-[1440px] items-center justify-between gap-4 px-6">
          <div className="flex items-center gap-2.5">
            <div className="grid size-8 place-items-center rounded-xl bg-[var(--primary-soft)] text-[var(--primary)]">
              <ShieldKeyholeBoldIcon
                className="size-[18px]"
                aria-hidden="true"
              />
            </div>
            <div>
              <div className="text-sm font-semibold tracking-[-0.01em]">
                Safeory
              </div>
              <div className="text-[11px] text-[var(--text-muted)]">
                {desktopRuntime ? "Local vault" : "Browser preview"}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden items-center gap-2 text-xs text-[var(--text-muted)] sm:flex">
              <HugeiconsIcon
                icon={ShieldKeyIcon}
                className="size-4 text-[var(--primary)]"
                aria-hidden="true"
              />
              Encrypted locally
            </div>
            {desktopRuntime ? (
              <>
                <div className="hidden rounded-full border border-[var(--border)] bg-[var(--surface-secondary)] px-3 py-1.5 text-xs text-[var(--text-muted)] md:block">
                  Auto-lock: {deviceSettings.auto_lock_minutes} min
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setCardOpen((current) => !current);
                    setSettingsOpen(false);
                    setPlanOpen(false);
                    setError(null);
                  }}
                  className="flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
                >
                  <HugeiconsIcon
                    icon={Contact01Icon}
                    className="size-4"
                    aria-hidden="true"
                  />
                  <span className="hidden sm:inline">Emergency Card</span>
                </button>
                <button
                  type="button"
                  aria-label="Plan Test"
                  onClick={() => {
                    setPlanOpen(true);
                    setCardOpen(false);
                    setSettingsOpen(false);
                    setError(null);
                  }}
                  className="flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
                >
                  <HugeiconsIcon
                    icon={ShieldCheckIcon}
                    className="size-4"
                    aria-hidden="true"
                  />
                  <span className="hidden sm:inline">Plan Test</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setSettingsOpen(true);
                    setCardOpen(false);
                    setPlanOpen(false);
                    setError(null);
                  }}
                  className="flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
                >
                  <HugeiconsIcon
                    icon={Settings01Icon}
                    className="size-4"
                    aria-hidden="true"
                  />
                  <span className="hidden sm:inline">Settings</span>
                </button>
                <button
                  type="button"
                  onClick={() => void lockVault()}
                  className="flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
                >
                  <HugeiconsIcon
                    icon={LockIcon}
                    className="size-4"
                    aria-hidden="true"
                  />
                  <span className="hidden sm:inline">Lock</span>
                </button>
              </>
            ) : null}
          </div>
        </div>
      </header>

      {settingsOpen ? (
        <SettingsPanel
          settings={deviceSettings}
          generation={sessionFence.token()}
          isGenerationCurrent={isSessionGenerationCurrent}
          onClose={() => setSettingsOpen(false)}
          onSettingsSaved={setDeviceSettings}
          onVaultRestored={() => {
            sessionFence.invalidate();
            clearPlaintextUi();
            setError(null);
            setScreen("locked");
          }}
          onError={setError}
        />
      ) : null}

      {planOpen ? (
        <PlanTestPanel
          generation={sessionFence.token()}
          isGenerationCurrent={isSessionGenerationCurrent}
          onClose={closePlanTest}
        />
      ) : null}

      {cardOpen ? (
        <EmergencyCardScreen
          generation={sessionFence.token()}
          isGenerationCurrent={isSessionGenerationCurrent}
          items={items}
          onJump={jumpToRecord}
          onClose={() => setCardOpen(false)}
          onError={setError}
        />
      ) : null}

      <section className="mx-auto w-full max-w-[1440px] px-6 py-6">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div className="flex min-w-0 flex-1 flex-wrap items-end gap-3">
            <label className="block min-w-[190px]">
              <span className="mb-1.5 block text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--text-muted)]">
                Record type
              </span>
              <select
                value={section}
                disabled={editor !== null}
                onChange={(event) =>
                  switchSection(event.target.value as Section)
                }
                className="h-10 w-full rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-3 text-sm font-medium text-[var(--text-primary)] outline-none transition focus:border-[var(--primary)] disabled:cursor-not-allowed disabled:opacity-55"
              >
                <option value="secure_note">Secure notes ({noteCount})</option>
                <option value="password">
                  Credentials ({credentialCount})
                </option>
                <option value="document">Documents ({documentCount})</option>
                <option value="receipt">Receipts ({receiptCount})</option>
                <option value="insurance">Insurance ({insuranceCount})</option>
                <option value="financial">Financial ({financialCount})</option>
                <option value="property">Property ({propertyCount})</option>
                <option value="vehicle">Vehicles ({vehicleCount})</option>
                <option value="possession">
                  Possessions ({possessionCount})
                </option>
              </select>
            </label>

            <label className="block min-w-[240px] flex-1 sm:max-w-md">
              <span className="mb-1.5 block text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--text-muted)]">
                Search
              </span>
              <span className="relative block">
                <HugeiconsIcon
                  icon={Search01Icon}
                  className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-[var(--text-muted)]"
                  aria-hidden="true"
                />
                <input
                  aria-label={`Search ${sectionLabel(section).toLocaleLowerCase()}`}
                  placeholder={`Search ${sectionLabel(section).toLocaleLowerCase()}`}
                  value={query}
                  disabled={editor !== null}
                  onChange={(event) => {
                    setQuery(event.target.value);
                    setSelectedId(null);
                    setError(null);
                  }}
                  className="h-10 w-full rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] pl-9 pr-3 text-sm text-[var(--text-primary)] outline-none transition placeholder:text-[var(--text-muted)] focus:border-[var(--primary)] disabled:cursor-not-allowed disabled:opacity-55"
                />
              </span>
            </label>

            {selected && !editor ? (
              <button
                type="button"
                onClick={() => setSelectedId(null)}
                className="flex h-10 items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-3 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
              >
                <HugeiconsIcon
                  icon={ArrowLeft01Icon}
                  className="size-4"
                  aria-hidden="true"
                />
                Browse
              </button>
            ) : null}
          </div>

          <div className="flex items-center gap-2">
            {vaultView === "trash" ? (
              <button
                type="button"
                onClick={leaveTrash}
                className="flex h-10 items-center justify-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-4 text-sm font-medium text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
              >
                <HugeiconsIcon
                  icon={ArrowLeft01Icon}
                  className="size-4"
                  aria-hidden="true"
                />
                Back to vault
              </button>
            ) : (
              <>
                <button
                  type="button"
                  onClick={() => void enterTrash()}
                  disabled={!desktopRuntime || editor !== null}
                  className="flex h-10 items-center justify-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-4 text-sm font-medium text-[var(--text-secondary)] transition hover:bg-[var(--selected)] disabled:cursor-not-allowed disabled:opacity-55"
                >
                  <HugeiconsIcon
                    icon={Delete02Icon}
                    className="size-4"
                    aria-hidden="true"
                  />
                  Trash
                </button>
                {selected && !editor ? (
                  <button
                    type="button"
                    onClick={() => void trashSelected()}
                    className="flex h-10 items-center justify-center gap-2 rounded-xl border border-[var(--danger-border)] bg-[var(--danger-soft)] px-4 text-sm font-medium text-[var(--danger)] transition hover:opacity-80"
                  >
                    <HugeiconsIcon
                      icon={Delete02Icon}
                      className="size-4"
                      aria-hidden="true"
                    />
                    Move to Trash
                  </button>
                ) : null}
                <button
                  type="button"
                  onClick={startNewItem}
                  disabled={!desktopRuntime || editor !== null}
                  className="flex h-10 items-center justify-center gap-2 rounded-xl bg-[var(--primary)] px-4 text-sm font-medium text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
                >
                  <HugeiconsIcon
                    icon={Add01Icon}
                    className="size-4"
                    aria-hidden="true"
                  />
                  {newItemLabel(section)}
                </button>
              </>
            )}
          </div>
        </div>

        {!desktopRuntime ? (
          <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-4 py-3 text-xs leading-5 text-[var(--text-muted)]">
            Browser preview only. Open the Tauri desktop app to create or
            decrypt local records.
          </div>
        ) : null}

        {error ? (
          <div
            role="alert"
            className="mt-5 rounded-xl border border-[var(--danger-border)] bg-[var(--danger-soft)] px-4 py-3 text-sm text-[var(--danger)]"
          >
            {error}
          </div>
        ) : null}

        <div className="mt-6">
          {vaultView === "active" && editor === null ? (
            <TodayPanel items={items} deadlines={deadlines} />
          ) : null}
          {vaultView === "trash" ? (
            <TrashCollection
              items={visibleTrashItems}
              section={section}
              query={query}
              loading={loadingTrash}
              onRestore={(item) => void restoreTrashItem(item)}
              onPurge={(item) => void purgeTrashItem(item)}
            />
          ) : editor?.kind === "secure_note" ? (
            <NoteComposer
              key={`secure-note:${editor.item?.id ?? "new"}`}
              note={editor.item}
              generation={sessionFence.token()}
              onCancel={() => setEditor(null)}
              onSaved={(note, created, token) =>
                saveItem(token, { kind: "secure_note", ...note }, created)
              }
              onError={setError}
            />
          ) : editor?.kind === "password" ? (
            <CredentialComposer
              key={`credential:${editor.item?.id ?? "new"}`}
              credential={editor.item}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onCancel={() => setEditor(null)}
              onSaved={(credential, created, token) =>
                saveItem(token, { kind: "password", ...credential }, created)
              }
              onError={setError}
            />
          ) : editor?.kind === "document" ? (
            <DocumentComposer
              key={`document:${editor.item?.id ?? "new"}`}
              document={editor.item}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onCancel={() => setEditor(null)}
              onSaved={(document, created, token) =>
                saveItem(token, { kind: "document", ...document }, created)
              }
              onError={setError}
            />
          ) : editor?.kind === "receipt" ? (
            <ReceiptComposer
              key={`receipt:${editor.item?.id ?? "new"}`}
              receipt={editor.item}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onCancel={() => setEditor(null)}
              onSaved={(receipt, created, token) =>
                saveItem(token, { kind: "receipt", ...receipt }, created)
              }
              onError={setError}
            />
          ) : editor?.kind === "insurance" ? (
            <InsuranceComposer
              key={`insurance:${editor.item?.id ?? "new"}`}
              insurance={editor.item}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onCancel={() => setEditor(null)}
              onSaved={(insurance, created, token) =>
                saveItem(token, { kind: "insurance", ...insurance }, created)
              }
              onError={setError}
            />
          ) : editor?.kind === "financial" ? (
            <FinancialComposer
              key={`financial:${editor.item?.id ?? "new"}`}
              financial={editor.item}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onCancel={() => setEditor(null)}
              onSaved={(financial, created, token) =>
                saveItem(token, { kind: "financial", ...financial }, created)
              }
              onError={setError}
            />
          ) : editor?.kind === "property" ? (
            <PropertyComposer
              key={`property:${editor.item?.id ?? "new"}`}
              property={editor.item}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onCancel={() => setEditor(null)}
              onSaved={(property, created, token) =>
                saveItem(token, { kind: "property", ...property }, created)
              }
              onError={setError}
            />
          ) : editor?.kind === "vehicle" ? (
            <VehicleComposer
              key={`vehicle:${editor.item?.id ?? "new"}`}
              vehicle={editor.item}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onCancel={() => setEditor(null)}
              onSaved={(vehicle, created, token) =>
                saveItem(token, { kind: "vehicle", ...vehicle }, created)
              }
              onError={setError}
            />
          ) : editor?.kind === "possession" ? (
            <PossessionComposer
              key={`possession:${editor.item?.id ?? "new"}`}
              possession={editor.item}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onCancel={() => setEditor(null)}
              onSaved={(possession, created, token) =>
                saveItem(token, { kind: "possession", ...possession }, created)
              }
              onError={setError}
            />
          ) : selected?.kind === "secure_note" ? (
            <NoteReader
              note={selected}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              linkedTitles={linkedTitles}
              allItems={items}
              onJump={jumpToRecord}
              onLinksChanged={() => void refreshVaultItems()}
              onEdit={() =>
                setEditor({
                  kind: "secure_note",
                  item: withoutKind(selected),
                })
              }
              onError={setError}
            />
          ) : selected?.kind === "password" ? (
            <CredentialReader
              key={selected.id}
              credential={selected}
              linkedTitles={linkedTitles}
              allItems={items}
              onJump={jumpToRecord}
              onLinksChanged={() => void refreshVaultItems()}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onEdit={() => {
                setError(null);
                setEditor({ kind: "password", item: withoutKind(selected) });
              }}
              onError={setError}
            />
          ) : selected?.kind === "document" ? (
            <DocumentReader
              key={selected.id}
              document={selected}
              linkedTitles={linkedTitles}
              allItems={items}
              onJump={jumpToRecord}
              onLinksChanged={() => void refreshVaultItems()}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onEdit={() => {
                setError(null);
                setEditor({ kind: "document", item: withoutKind(selected) });
              }}
              onError={setError}
            />
          ) : selected?.kind === "receipt" ? (
            <ReceiptReader
              key={selected.id}
              receipt={selected}
              linkedTitles={linkedTitles}
              allItems={items}
              onJump={jumpToRecord}
              onLinksChanged={() => void refreshVaultItems()}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onEdit={() => {
                setError(null);
                setEditor({ kind: "receipt", item: withoutKind(selected) });
              }}
              onError={setError}
            />
          ) : selected?.kind === "insurance" ? (
            <InsuranceReader
              key={selected.id}
              insurance={selected}
              linkedTitles={linkedTitles}
              allItems={items}
              onJump={jumpToRecord}
              onLinksChanged={() => void refreshVaultItems()}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onEdit={() => {
                setError(null);
                setEditor({ kind: "insurance", item: withoutKind(selected) });
              }}
              onError={setError}
            />
          ) : selected?.kind === "financial" ? (
            <FinancialReader
              key={selected.id}
              financial={selected}
              linkedTitles={linkedTitles}
              allItems={items}
              onJump={jumpToRecord}
              onLinksChanged={() => void refreshVaultItems()}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onEdit={() => {
                setError(null);
                setEditor({ kind: "financial", item: withoutKind(selected) });
              }}
              onError={setError}
            />
          ) : selected?.kind === "property" ? (
            <PropertyReader
              key={selected.id}
              property={selected}
              linkedTitles={linkedTitles}
              allItems={items}
              onJump={jumpToRecord}
              onLinksChanged={() => void refreshVaultItems()}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onEdit={() => {
                setError(null);
                setEditor({ kind: "property", item: withoutKind(selected) });
              }}
              onError={setError}
            />
          ) : selected?.kind === "vehicle" ? (
            <VehicleReader
              key={selected.id}
              vehicle={selected}
              linkedTitles={linkedTitles}
              allItems={items}
              onJump={jumpToRecord}
              onLinksChanged={() => void refreshVaultItems()}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onEdit={() => {
                setError(null);
                setEditor({ kind: "vehicle", item: withoutKind(selected) });
              }}
              onError={setError}
            />
          ) : selected?.kind === "possession" ? (
            <PossessionReader
              key={selected.id}
              possession={selected}
              linkedTitles={linkedTitles}
              allItems={items}
              onJump={jumpToRecord}
              onLinksChanged={() => void refreshVaultItems()}
              generation={sessionFence.token()}
              isGenerationCurrent={isSessionGenerationCurrent}
              onEdit={() => {
                setError(null);
                setEditor({ kind: "possession", item: withoutKind(selected) });
              }}
              onError={setError}
            />
          ) : visibleItems.length > 0 ? (
            <VaultCollection
              items={visibleItems}
              section={section}
              query={query}
              onSelect={(item) => {
                setSelectedId(item.id);
                setEditor(null);
                setError(null);
              }}
            />
          ) : query ? (
            <NoSearchResults section={section} query={query} />
          ) : (
            <EmptyVault section={section} browserPreview={!desktopRuntime} />
          )}
        </div>
      </section>
    </main>
  );
}

function PlanTestPanel({
  generation,
  isGenerationCurrent,
  onClose,
}: {
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onClose: () => void;
}) {
  const [readiness, setReadiness] = useState<PlanReadiness | null>(null);
  const [recoveryKey, setRecoveryKey] = useState("");
  const [verification, setVerification] = useState<
    "idle" | "verified" | "mismatch"
  >("idle");
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [panelError, setPanelError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLElement | null>(null);
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (dialog === null) return;
    const previousFocus =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    closeButtonRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = Array.from(
        dialog.querySelectorAll<HTMLElement>(
          'button:not([disabled]), input:not([disabled]), a[href], [tabindex]:not([tabindex="-1"])',
        ),
      );
      if (focusable.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }
      const first = focusable[0]!;
      const last = focusable[focusable.length - 1]!;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      } else if (!dialog.contains(document.activeElement)) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previousFocus?.focus();
    };
  }, [onClose]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setPanelError(null);
    setVerification("idle");
    setRecoveryKey("");
    void invoke<PlanReadiness>("get_plan_readiness")
      .then((report) => {
        if (!active || !isGenerationCurrent(generation)) return;
        setReadiness(report);
      })
      .catch((reason: unknown) => {
        if (!active || !isGenerationCurrent(generation)) return;
        setPanelError(readError(reason));
      })
      .finally(() => {
        if (active && isGenerationCurrent(generation)) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [generation, isGenerationCurrent]);

  async function verifyRecoveryKey(event: FormEvent) {
    event.preventDefault();
    if (verifying || !recoveryKey || !readiness?.recovery_configured) return;
    const candidate = recoveryKey;
    setRecoveryKey("");
    setVerifying(true);
    setPanelError(null);
    setVerification("idle");
    try {
      const matches = await invoke<boolean>("verify_recovery_secret", {
        secret: candidate,
      });
      if (!isGenerationCurrent(generation)) return;
      setVerification(matches ? "verified" : "mismatch");
    } catch (reason) {
      if (isGenerationCurrent(generation)) setPanelError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) {
        setVerifying(false);
      }
    }
  }

  const recordsReady =
    readiness?.has_selected_records === true &&
    readiness.has_stale_selected_records === false;
  const checks = readiness
    ? [
        {
          ready: readiness.recovery_configured,
          label: "Recovery kit installed",
          detail: readiness.recovery_configured
            ? "The current vault has a recovery wrap."
            : "Set up a recovery kit in Settings.",
        },
        {
          ready: recordsReady,
          label: "Emergency records available",
          detail: readiness.has_stale_selected_records
            ? "The Emergency Card references a record that is no longer active."
            : readiness.has_selected_records
              ? "At least one active record is selected."
              : "Select at least one active record in the Emergency Card.",
        },
        {
          ready: readiness.has_contacts,
          label: "Emergency contact added",
          detail: readiness.has_contacts
            ? "At least one named contact with a phone number is present."
            : "Add a named contact with a phone number to the Emergency Card.",
        },
        {
          ready: readiness.has_instructions,
          label: "Emergency instructions written",
          detail: readiness.has_instructions
            ? "The Emergency Card includes instructions."
            : "Add instructions to the Emergency Card.",
        },
        {
          ready: verification === "verified",
          label: "Recovery key tested now",
          detail:
            verification === "verified"
              ? "The entered key matches this currently open vault."
              : verification === "mismatch"
                ? "Safeory could not verify this key against the current recovery wrap."
                : "Enter your saved or printed recovery key below to test it.",
        },
      ]
    : [];
  const readyCount = checks.filter((check) => check.ready).length;

  return (
    <div
      className="fixed inset-0 z-50 overflow-y-auto bg-black/20"
      role="presentation"
    >
      <div className="mx-auto my-10 w-full max-w-2xl px-4">
        <section
          ref={dialogRef}
          tabIndex={-1}
          role="dialog"
          aria-modal="true"
          aria-labelledby="plan-test-title"
          className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-6 shadow-2xl"
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="text-[11px] font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
                Local preparedness
              </div>
              <h1
                id="plan-test-title"
                className="mt-1 text-2xl font-semibold tracking-[-0.03em]"
              >
                Plan Test
              </h1>
              <p className="mt-1 text-sm leading-6 text-[var(--text-muted)]">
                Check the emergency information and recovery path that Safeory
                can verify on this device today.
              </p>
            </div>
            <button
              ref={closeButtonRef}
              type="button"
              onClick={onClose}
              className="flex shrink-0 items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
            >
              <HugeiconsIcon
                icon={ArrowLeft01Icon}
                className="size-4"
                aria-hidden="true"
              />
              Close
            </button>
          </div>

          {panelError ? (
            <div
              role="alert"
              className="mt-5 rounded-xl border border-[var(--danger-border)] bg-[var(--danger-soft)] px-4 py-3 text-sm text-[var(--danger)]"
            >
              {panelError}
            </div>
          ) : null}

          {loading || readiness === null ? (
            <p className="mt-6 text-sm text-[var(--text-muted)]">
              Checking local plan readiness…
            </p>
          ) : (
            <>
              <div className="mt-6 rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)] p-5">
                <div className="text-sm font-semibold">
                  {readyCount} of {checks.length} checks ready
                </div>
                <div className="mt-4 overflow-hidden rounded-xl border border-[var(--border)] bg-[var(--surface)]">
                  {checks.map((check) => (
                    <div
                      key={check.label}
                      className="grid grid-cols-[auto_minmax(0,1fr)] gap-3 px-4 py-3 [&+&]:border-t [&+&]:border-[var(--border)]"
                    >
                      <div
                        className={`mt-0.5 text-xs font-semibold ${
                          check.ready
                            ? "text-[var(--primary)]"
                            : "text-[var(--text-muted)]"
                        }`}
                      >
                        {check.ready ? "Ready" : "Check"}
                      </div>
                      <div>
                        <div className="text-sm font-medium">{check.label}</div>
                        <div className="mt-0.5 text-xs leading-5 text-[var(--text-muted)]">
                          {check.detail}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <form
                onSubmit={verifyRecoveryKey}
                className="mt-5 rounded-2xl border border-[var(--border)] p-5"
              >
                <div className="text-sm font-semibold">Test recovery key</div>
                <p className="mt-1 text-xs leading-5 text-[var(--text-muted)]">
                  This read-only test checks that the key unwraps the exact root
                  of the currently open vault. The key is not saved by this
                  test, and the result is not persisted.
                </p>
                <div className="mt-4 flex gap-2">
                  <input
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    value={recoveryKey}
                    onChange={(event) => setRecoveryKey(event.target.value)}
                    disabled={!readiness.recovery_configured || verifying}
                    className="field-input font-mono"
                    placeholder={
                      readiness.recovery_configured
                        ? "Enter your 64-character recovery key"
                        : "Set up a recovery kit first"
                    }
                  />
                  <button
                    type="submit"
                    disabled={
                      !readiness.recovery_configured ||
                      verifying ||
                      !recoveryKey
                    }
                    className="shrink-0 rounded-xl bg-[var(--primary)] px-4 py-2.5 text-sm font-medium text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
                  >
                    {verifying ? "Testing…" : "Test key"}
                  </button>
                </div>
              </form>

              <p className="mt-5 text-xs leading-5 text-[var(--text-muted)]">
                This local test does not exercise trusted-person sharing or
                desktop/server enforcement for waiting periods, timed release,
                or destruction. Policy evaluation exists in the portable core,
                but no release path is wired yet.
              </p>
            </>
          )}
        </section>
      </div>
    </div>
  );
}

function EmergencyCardScreen({
  generation,
  isGenerationCurrent,
  items,
  onJump,
  onClose,
  onError,
}: {
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  items: VaultItem[];
  onJump: (kind: string, id: string) => void;
  onClose: () => void;
  onError: (message: string | null) => void;
}) {
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState<number | null>(null);
  const [card, setCard] = useState<EmergencyCardData | null>(null);
  const [editing, setEditing] = useState(false);
  const [instructions, setInstructions] = useState("");
  const [contacts, setContacts] = useState<EmergencyContact[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [pickerQuery, setPickerQuery] = useState("");
  const [titles, setTitles] = useState<ItemTitle[]>([]);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let active = true;
    void invoke<EmergencyCardResult | null>("get_emergency_card")
      .then((result) => {
        if (!active || !isGenerationCurrent(generation)) return;
        if (result === null) {
          setCard(null);
          setRevision(null);
        } else {
          setCard(result.card);
          setRevision(result.revision);
        }
        setLoading(false);
      })
      .catch((reason: unknown) => {
        if (!active || !isGenerationCurrent(generation)) return;
        onError(readError(reason));
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [generation, isGenerationCurrent, onError]);

  const cardIdsKey = (card?.selected_item_ids ?? []).join(",");
  useEffect(() => {
    if (editing || cardIdsKey === "") {
      setTitles([]);
      return;
    }
    const ids = card?.selected_item_ids ?? [];
    if (ids.length === 0) {
      setTitles([]);
      return;
    }
    let active = true;
    void invoke<ItemTitle[]>("get_item_titles", { ids })
      .then((loaded) => {
        if (!active || !isGenerationCurrent(generation)) return;
        setTitles(loaded);
      })
      .catch((reason: unknown) => {
        if (active && isGenerationCurrent(generation))
          onError(readError(reason));
      });
    return () => {
      active = false;
    };
  }, [editing, cardIdsKey, card, generation, isGenerationCurrent, onError]);

  const startEdit = () => {
    setInstructions(card?.instructions ?? "");
    setContacts(card?.contacts ?? []);
    setSelectedIds(card?.selected_item_ids ?? []);
    setPickerQuery("");
    setEditing(true);
    onError(null);
  };

  const updateContact = (index: number, patch: Partial<EmergencyContact>) => {
    setContacts((current) =>
      current.map((contact, position) =>
        position === index ? { ...contact, ...patch } : contact,
      ),
    );
  };

  const toggleSelected = (id: string) => {
    setSelectedIds((current) =>
      current.includes(id)
        ? current.filter((candidate) => candidate !== id)
        : [...current, id],
    );
  };

  async function saveCard(event: FormEvent) {
    event.preventDefault();
    if (saving) return;
    setSaving(true);
    onError(null);
    try {
      const nextRevision = await invoke<number>("update_emergency_card", {
        revision,
        selectedItemIds: selectedIds,
        contacts,
        instructions,
      });
      if (!isGenerationCurrent(generation)) return;
      setRevision(nextRevision);
      setEditing(false);
      const refreshed = await invoke<EmergencyCardResult | null>(
        "get_emergency_card",
      );
      if (!isGenerationCurrent(generation)) return;
      if (refreshed === null) {
        setCard(null);
        setRevision(null);
      } else {
        setCard(refreshed.card);
        setRevision(refreshed.revision);
      }
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setSaving(false);
    }
  }

  const titleById = new Map(titles.map((entry) => [entry.id, entry]));
  const pickerNeedle = pickerQuery.trim().toLocaleLowerCase();
  const pickerGroups = groupItemsByKind(items, pickerNeedle);
  const viewIds = card?.selected_item_ids ?? [];

  return (
    <div
      className="fixed inset-0 z-50 overflow-y-auto bg-black/20"
      role="presentation"
    >
      <div className="mx-auto my-10 w-full max-w-2xl px-4">
        <section
          role="dialog"
          aria-modal="true"
          aria-labelledby="emergency-card-title"
          className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-6 shadow-2xl"
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="text-[11px] font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
                Trusted people
              </div>
              <h1
                id="emergency-card-title"
                className="mt-1 text-2xl font-semibold tracking-[-0.03em]"
              >
                Emergency Card
              </h1>
              <p className="mt-1 text-sm leading-6 text-[var(--text-muted)]">
                Contacts, instructions, and key records for someone helping in
                an emergency.
              </p>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="flex shrink-0 items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
            >
              <HugeiconsIcon
                icon={ArrowLeft01Icon}
                className="size-4"
                aria-hidden="true"
              />
              Close
            </button>
          </div>

          {loading ? (
            <p className="mt-8 text-sm text-[var(--text-muted)]">
              Opening emergency card…
            </p>
          ) : editing ? (
            <form onSubmit={saveCard} className="mt-8 space-y-6">
              <Field label="Instructions">
                <textarea
                  value={instructions}
                  onChange={(event) => setInstructions(event.target.value)}
                  className="field-input min-h-28 resize-y"
                  placeholder="What should a helper do first?"
                />
              </Field>

              <div>
                <div className="mb-2 text-sm font-medium">Contacts</div>
                {contacts.length === 0 ? (
                  <p className="text-sm text-[var(--text-muted)]">
                    No emergency contacts yet.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {contacts.map((contact, index) => (
                      <div
                        key={index}
                        className="rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)] p-4"
                      >
                        <div className="grid gap-3 sm:grid-cols-2">
                          <Field label="Name">
                            <input
                              value={contact.name}
                              autoComplete="off"
                              onChange={(event) =>
                                updateContact(index, {
                                  name: event.target.value,
                                })
                              }
                              className="field-input"
                              placeholder="Full name"
                            />
                          </Field>
                          <Field label="Relation">
                            <input
                              value={contact.relation}
                              autoComplete="off"
                              onChange={(event) =>
                                updateContact(index, {
                                  relation: event.target.value,
                                })
                              }
                              className="field-input"
                              placeholder="Spouse, friend, doctor…"
                            />
                          </Field>
                          <Field label="Phone">
                            <input
                              value={contact.phone}
                              autoComplete="off"
                              inputMode="tel"
                              onChange={(event) =>
                                updateContact(index, {
                                  phone: event.target.value,
                                })
                              }
                              className="field-input"
                              placeholder="+91 …"
                            />
                          </Field>
                          <Field label="Notes">
                            <input
                              value={contact.notes}
                              autoComplete="off"
                              onChange={(event) =>
                                updateContact(index, {
                                  notes: event.target.value,
                                })
                              }
                              className="field-input"
                              placeholder="Optional context"
                            />
                          </Field>
                        </div>
                        <div className="mt-3 flex justify-end">
                          <button
                            type="button"
                            onClick={() =>
                              setContacts((current) =>
                                current.filter(
                                  (_, position) => position !== index,
                                ),
                              )
                            }
                            className="rounded-lg px-2.5 py-1.5 text-xs text-[var(--danger)] transition hover:bg-[var(--danger-soft)]"
                          >
                            Remove
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
                <button
                  type="button"
                  onClick={() =>
                    setContacts((current) => [
                      ...current,
                      { name: "", relation: "", phone: "", notes: "" },
                    ])
                  }
                  className="mt-3 flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
                >
                  <HugeiconsIcon
                    icon={Add01Icon}
                    className="size-4"
                    aria-hidden="true"
                  />
                  Add contact
                </button>
              </div>

              <div>
                <div className="mb-2 text-sm font-medium">Key records</div>
                <input
                  aria-label="Search records"
                  placeholder="Search records"
                  value={pickerQuery}
                  onChange={(event) => setPickerQuery(event.target.value)}
                  className="h-10 w-full rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-3 text-sm text-[var(--text-primary)] outline-none transition placeholder:text-[var(--text-muted)] focus:border-[var(--primary)]"
                />
                {pickerGroups.length === 0 ? (
                  <p className="mt-3 text-sm text-[var(--text-muted)]">
                    {items.length === 0
                      ? "No records in the vault yet."
                      : "No records match this search."}
                  </p>
                ) : (
                  <div className="mt-3 space-y-4 rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)] p-4">
                    {pickerGroups.map((group) => (
                      <div key={group.section}>
                        <div className="text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--text-muted)]">
                          {sectionLabel(group.section)}
                        </div>
                        <div className="mt-2 space-y-1.5">
                          {group.items.map((item) => (
                            <label
                              key={item.id}
                              className="flex cursor-pointer items-center gap-3 rounded-xl px-2 py-1.5 text-sm transition hover:bg-[var(--selected)]"
                            >
                              <input
                                type="checkbox"
                                checked={selectedIds.includes(item.id)}
                                onChange={() => toggleSelected(item.id)}
                                className="size-4"
                              />
                              <span className="min-w-0">
                                <span className="block truncate font-medium text-[var(--text-primary)]">
                                  {item.title}
                                </span>
                                <span className="block text-xs text-[var(--text-muted)]">
                                  {sectionLabel(item.kind)}
                                </span>
                              </span>
                            </label>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="flex items-center justify-end gap-2 border-t border-[var(--border)] pt-5">
                <button
                  type="button"
                  onClick={() => setEditing(false)}
                  className="rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-4 py-2.5 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={saving}
                  className="rounded-xl bg-[var(--primary)] px-4 py-2.5 text-sm font-medium text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
                >
                  {saving ? "Saving…" : "Save emergency card"}
                </button>
              </div>
            </form>
          ) : (
            <div className="mt-8 space-y-8">
              <div>
                <div className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
                  Instructions
                </div>
                {card?.instructions ? (
                  <p className="mt-3 whitespace-pre-wrap text-[15px] leading-7 text-[var(--text-secondary)]">
                    {card.instructions}
                  </p>
                ) : (
                  <p className="mt-3 text-sm text-[var(--text-muted)]">
                    No instructions yet.
                  </p>
                )}
              </div>

              <div>
                <div className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
                  Contacts
                </div>
                {(card?.contacts ?? []).length === 0 ? (
                  <p className="mt-3 text-sm text-[var(--text-muted)]">
                    No emergency contacts yet.
                  </p>
                ) : (
                  <div className="mt-3 grid gap-3 sm:grid-cols-2">
                    {(card?.contacts ?? []).map((contact, index) => (
                      <div
                        key={index}
                        className="rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)] p-4"
                      >
                        <div className="text-sm font-medium text-[var(--text-primary)]">
                          {contact.name || "Unnamed contact"}
                        </div>
                        <div className="mt-2 space-y-1 text-sm">
                          {contact.relation ? (
                            <div className="text-[var(--text-secondary)]">
                              {contact.relation}
                            </div>
                          ) : null}
                          {contact.phone ? (
                            <div className="text-[var(--text-secondary)]">
                              {contact.phone}
                            </div>
                          ) : null}
                          {contact.notes ? (
                            <div className="text-xs leading-5 text-[var(--text-muted)]">
                              {contact.notes}
                            </div>
                          ) : null}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <div className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
                  Key records
                </div>
                {viewIds.length === 0 ? (
                  <p className="mt-3 text-sm text-[var(--text-muted)]">
                    No records selected yet.
                  </p>
                ) : (
                  <div className="mt-3 overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)]">
                    {viewIds.map((id) => {
                      const entry = titleById.get(id);
                      if (!entry) {
                        return (
                          <div
                            key={id}
                            className="grid grid-cols-[140px_minmax(0,1fr)] gap-4 px-5 py-4 [&+&]:border-t [&+&]:border-[var(--border)]"
                          >
                            <div className="text-sm text-[var(--text-muted)]">
                              Record
                            </div>
                            <div className="min-w-0 truncate text-sm text-[var(--text-muted)]">
                              Unavailable (moved to Trash or deleted)
                            </div>
                          </div>
                        );
                      }
                      return (
                        <button
                          key={id}
                          type="button"
                          onClick={() => onJump(entry.kind, entry.id)}
                          className="grid w-full grid-cols-[140px_minmax(0,1fr)] gap-4 px-5 py-4 text-left transition hover:bg-[var(--selected)] [&+&]:border-t [&+&]:border-[var(--border)]"
                        >
                          <div className="text-sm text-[var(--text-muted)]">
                            {kindLabel(entry.kind)}
                          </div>
                          <div className="min-w-0 truncate text-sm text-[var(--text-primary)]">
                            {entry.title}
                          </div>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="flex justify-end border-t border-[var(--border)] pt-5">
                <button
                  type="button"
                  onClick={startEdit}
                  className="flex items-center gap-2 rounded-xl bg-[var(--primary)] px-4 py-2.5 text-sm font-medium text-white transition hover:opacity-90"
                >
                  <HugeiconsIcon
                    icon={FileEditIcon}
                    className="size-4"
                    aria-hidden="true"
                  />
                  {card ? "Edit emergency card" : "Set up emergency card"}
                </button>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function SettingsPanel({
  settings,
  generation,
  isGenerationCurrent,
  onClose,
  onSettingsSaved,
  onVaultRestored,
  onError,
}: {
  settings: DeviceSettings;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onClose: () => void;
  onSettingsSaved: (settings: DeviceSettings) => void;
  onVaultRestored: () => void;
  onError: (message: string | null) => void;
}) {
  const [autoLockMinutes, setAutoLockMinutes] = useState(
    settings.auto_lock_minutes,
  );
  const [lockOnBackground, setLockOnBackground] = useState(
    settings.lock_on_background,
  );
  const [savingSettings, setSavingSettings] = useState(false);
  const [currentPassphrase, setCurrentPassphrase] = useState("");
  const [newPassphrase, setNewPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [changingPassphrase, setChangingPassphrase] = useState(false);
  const [panelError, setPanelError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [recoveryStatus, setRecoveryStatus] = useState<{
    configured: boolean;
  } | null>(null);
  const [generatedRecovery, setGeneratedRecovery] = useState<
    (GeneratedRecoverySecret & { replacing: boolean }) | null
  >(null);
  const [recoveryConfirm, setRecoveryConfirm] = useState("");
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [backupBusy, setBackupBusy] = useState(false);
  const [restorePath, setRestorePath] = useState<string | null>(null);
  const [restorePassphrase, setRestorePassphrase] = useState("");
  const [restoreBusy, setRestoreBusy] = useState(false);

  useEffect(() => {
    let active = true;
    void invoke<{ configured: boolean }>("get_recovery_status")
      .then((recovery) => {
        if (!active || !isGenerationCurrent(generation)) return;
        setRecoveryStatus(recovery);
      })
      .catch((reason: unknown) => {
        if (active && isGenerationCurrent(generation))
          setPanelError(readError(reason));
      });
    return () => {
      active = false;
      // The recovery secret lives only in this panel's local state.
      setGeneratedRecovery(null);
      setRecoveryConfirm("");
    };
  }, [generation, isGenerationCurrent]);

  async function generateRecoverySecret(replacing: boolean) {
    if (recoveryBusy) return;
    setRecoveryBusy(true);
    setPanelError(null);
    setStatus(null);
    try {
      const generated = await invoke<GeneratedRecoverySecret>(
        "generate_recovery_secret",
      );
      if (!isGenerationCurrent(generation)) return;
      setGeneratedRecovery({ ...generated, replacing });
      setRecoveryConfirm("");
    } catch (reason) {
      if (isGenerationCurrent(generation)) setPanelError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setRecoveryBusy(false);
    }
  }

  async function confirmRecoverySecret(event: FormEvent) {
    event.preventDefault();
    if (recoveryBusy || !generatedRecovery) return;
    if (recoveryConfirm !== generatedRecovery.secret) {
      setPanelError(
        "The re-entered secret does not match the generated secret. Copy it carefully and try again.",
      );
      return;
    }
    setRecoveryBusy(true);
    setPanelError(null);
    setStatus(null);
    try {
      await invoke("confirm_recovery_secret", {
        secret: generatedRecovery.secret,
        expectedGeneration: generatedRecovery.generation,
      });
      if (!isGenerationCurrent(generation)) return;
      const wasReplacement = generatedRecovery.replacing;
      setGeneratedRecovery(null);
      setRecoveryConfirm("");
      const refreshed = await invoke<{ configured: boolean }>(
        "get_recovery_status",
      );
      if (!isGenerationCurrent(generation)) return;
      setRecoveryStatus(refreshed);
      setStatus(
        wasReplacement
          ? "Recovery key replaced for the current vault. Older backup files may still accept the key they were created with."
          : "Recovery kit confirmed and installed on this device.",
      );
    } catch (reason) {
      if (isGenerationCurrent(generation)) setPanelError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setRecoveryBusy(false);
    }
  }

  async function saveRecoverySecret() {
    if (recoveryBusy || !generatedRecovery) return;
    setRecoveryBusy(true);
    setPanelError(null);
    setStatus(null);
    try {
      const saved = await invoke<boolean>("save_recovery_secret", {
        secret: generatedRecovery.secret,
        expectedGeneration: generatedRecovery.generation,
      });
      if (!isGenerationCurrent(generation)) return;
      if (saved) {
        setStatus(
          "Recovery key saved. It becomes active for this vault only after you confirm it below.",
        );
      }
    } catch (reason) {
      if (isGenerationCurrent(generation)) setPanelError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setRecoveryBusy(false);
    }
  }

  function cancelRecoverySecret() {
    setGeneratedRecovery(null);
    setRecoveryConfirm("");
    setPanelError(null);
    setStatus(null);
  }

  async function exportReadable() {
    if (backupBusy) return;
    setBackupBusy(true);
    setPanelError(null);
    try {
      const path = await save({
        defaultPath: "safeory-export.json",
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (path === null) return;
      const result = await invoke<{ items: number; path: string }>(
        "export_human_readable",
        { path },
      );
      if (!isGenerationCurrent(generation)) return;
      setStatus(`Exported ${result.items} records to ${result.path}`);
    } catch (reason) {
      if (isGenerationCurrent(generation)) setPanelError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setBackupBusy(false);
    }
  }

  async function backupDatabase() {
    if (backupBusy) return;
    setBackupBusy(true);
    setPanelError(null);
    try {
      const path = await save({ defaultPath: "safeory-backup.sqlite3" });
      if (path === null) return;
      const result = await invoke<{ path: string }>("backup_database_copy", {
        path,
      });
      if (!isGenerationCurrent(generation)) return;
      setStatus(`Encrypted database backup written to ${result.path}`);
    } catch (reason) {
      if (isGenerationCurrent(generation)) setPanelError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setBackupBusy(false);
    }
  }

  async function chooseRestoreBackup() {
    if (restoreBusy) return;
    setPanelError(null);
    const selected = await open({
      multiple: false,
      filters: [
        {
          name: "Safeory encrypted backup",
          extensions: ["sqlite3", "db"],
        },
      ],
    });
    if (typeof selected === "string") {
      setRestorePath(selected);
      setRestorePassphrase("");
      setStatus(null);
    }
  }

  async function restoreDatabase(event: FormEvent) {
    event.preventDefault();
    if (restoreBusy || restorePath === null || !restorePassphrase) return;
    if (
      !window.confirm(
        "Replace the current local vault with this encrypted backup? Current records not present in the backup will be removed.",
      )
    ) {
      return;
    }
    setRestoreBusy(true);
    setPanelError(null);
    setStatus(null);
    try {
      const status = await invoke<VaultStatus>("restore_database_backup", {
        path: restorePath,
        passphrase: restorePassphrase,
      });
      if (!isGenerationCurrent(generation)) return;
      if (!status.initialized || status.unlocked) {
        throw new Error(
          "The restored vault did not enter the expected locked state.",
        );
      }
      setRestorePassphrase("");
      setRestorePath(null);
      onVaultRestored();
    } catch (reason) {
      if (isGenerationCurrent(generation)) setPanelError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setRestoreBusy(false);
    }
  }

  async function saveSettings(event: FormEvent) {
    event.preventDefault();
    if (savingSettings) return;
    setSavingSettings(true);
    setPanelError(null);
    setStatus(null);
    onError(null);
    try {
      const saved = await invoke<DeviceSettings>("update_device_settings", {
        autoLockMinutes,
        lockOnBackground,
      });
      if (!isGenerationCurrent(generation)) return;
      onSettingsSaved(saved);
      setStatus("Device lock settings saved.");
    } catch (reason) {
      if (isGenerationCurrent(generation)) setPanelError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setSavingSettings(false);
    }
  }

  async function changePassphrase(event: FormEvent) {
    event.preventDefault();
    if (changingPassphrase) return;
    if (Array.from(newPassphrase).length < 12) {
      setPanelError(
        "Use at least 12 characters for the new master passphrase.",
      );
      return;
    }
    if (newPassphrase !== confirmation) {
      setPanelError("The new passphrase confirmation does not match.");
      return;
    }
    setChangingPassphrase(true);
    setPanelError(null);
    setStatus(null);
    onError(null);
    try {
      await invoke("change_master_passphrase", {
        currentPassphrase,
        newPassphrase,
      });
      if (!isGenerationCurrent(generation)) return;
      setCurrentPassphrase("");
      setNewPassphrase("");
      setConfirmation("");
      setStatus(
        "Master passphrase changed. The vault root key was rewrapped locally.",
      );
    } catch (reason) {
      if (isGenerationCurrent(generation)) setPanelError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setChangingPassphrase(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/20"
      role="presentation"
    >
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="settings-title"
        className="h-full w-full max-w-lg overflow-y-auto border-l border-[var(--border)] bg-[var(--surface)] p-6 shadow-2xl"
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="text-[11px] font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
              This device
            </div>
            <h1
              id="settings-title"
              className="mt-1 text-2xl font-semibold tracking-[-0.03em]"
            >
              Settings
            </h1>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
          >
            <HugeiconsIcon
              icon={ArrowLeft01Icon}
              className="size-4"
              aria-hidden="true"
            />
            Close
          </button>
        </div>

        {panelError ? (
          <div
            role="alert"
            className="mt-5 rounded-xl border border-[var(--danger-border)] bg-[var(--danger-soft)] px-4 py-3 text-sm text-[var(--danger)]"
          >
            {panelError}
          </div>
        ) : null}
        {status ? (
          <div
            role="status"
            aria-live="polite"
            className="mt-5 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-4 py-3 text-sm text-[var(--text-secondary)]"
          >
            {status}
          </div>
        ) : null}

        <form onSubmit={saveSettings} className="mt-8">
          <h2 className="text-base font-semibold">Auto-lock</h2>
          <p className="mt-1 text-sm leading-6 text-[var(--text-muted)]">
            Safeory also enforces this timeout in Rust, so an idle unlocked
            session is dropped even if the WebView stops responding.
          </p>
          <div className="mt-4">
            <Field label="Lock after inactivity">
              <select
                value={autoLockMinutes}
                onChange={(event) =>
                  setAutoLockMinutes(Number(event.target.value))
                }
                className="field-input"
              >
                {[1, 5, 10, 15, 30, 60].map((minutes) => (
                  <option key={minutes} value={minutes}>
                    {minutes} {minutes === 1 ? "minute" : "minutes"}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          <label className="mt-4 flex items-start gap-3 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] p-4">
            <input
              type="checkbox"
              checked={lockOnBackground}
              onChange={(event) => setLockOnBackground(event.target.checked)}
              className="mt-1"
            />
            <span>
              <span className="block text-sm font-medium">
                Lock when Safeory goes to the background
              </span>
              <span className="mt-1 block text-xs leading-5 text-[var(--text-muted)]">
                The renderer clears decrypted state immediately when the app
                becomes hidden.
              </span>
            </span>
          </label>
          <div className="mt-4 flex justify-end">
            <button
              type="submit"
              disabled={savingSettings}
              className="rounded-xl bg-[var(--primary)] px-4 py-2.5 text-sm font-medium text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
            >
              {savingSettings ? "Saving…" : "Save lock settings"}
            </button>
          </div>
        </form>

        <form
          onSubmit={changePassphrase}
          className="mt-9 border-t border-[var(--border)] pt-8"
        >
          <h2 className="text-base font-semibold">Master passphrase</h2>
          <p className="mt-1 text-sm leading-6 text-[var(--text-muted)]">
            Changing it rewraps the same random vault root key. Existing item
            ciphertext is not rewritten.
          </p>
          <div className="mt-4 space-y-4">
            <Field label="Current master passphrase">
              <input
                type="password"
                autoComplete="current-password"
                value={currentPassphrase}
                onChange={(event) => setCurrentPassphrase(event.target.value)}
                className="field-input"
              />
            </Field>
            <Field label="New master passphrase">
              <input
                type="password"
                autoComplete="new-password"
                value={newPassphrase}
                onChange={(event) => setNewPassphrase(event.target.value)}
                className="field-input"
                placeholder="12 characters or more"
              />
            </Field>
            <Field label="Confirm new passphrase">
              <input
                type="password"
                autoComplete="new-password"
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
                className="field-input"
              />
            </Field>
          </div>
          <div className="mt-4 flex justify-end">
            <button
              type="submit"
              disabled={
                changingPassphrase ||
                !currentPassphrase ||
                !newPassphrase ||
                !confirmation
              }
              className="rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-4 py-2.5 text-sm font-medium text-[var(--text-primary)] transition hover:bg-[var(--selected)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              {changingPassphrase ? "Changing…" : "Change master passphrase"}
            </button>
          </div>
        </form>

        <div className="mt-9 border-t border-[var(--border)] pt-8">
          <h2 className="text-base font-semibold">Recovery kit</h2>
          <p className="mt-1 text-sm leading-6 text-[var(--text-muted)]">
            A saved or printed recovery key unlocks this vault when the master
            passphrase is lost.
          </p>
          {recoveryStatus === null ? (
            <p className="mt-4 text-sm text-[var(--text-muted)]">
              Checking recovery status…
            </p>
          ) : generatedRecovery !== null ? (
            <form onSubmit={confirmRecoverySecret} className="mt-4 space-y-4">
              <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] p-4">
                <div className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
                  {generatedRecovery.replacing
                    ? "Replacement recovery key"
                    : "Your recovery key"}
                </div>
                <div className="mt-2 break-all font-mono text-sm leading-6 text-[var(--text-primary)]">
                  {generatedRecovery.secret}
                </div>
                <p className="mt-2 text-xs leading-5 text-[var(--danger)]">
                  Save or print this key before confirming it. It becomes active
                  only after confirmation and will not be shown again afterward.
                </p>
                {generatedRecovery.replacing ? (
                  <p className="mt-2 text-xs leading-5 text-[var(--text-muted)]">
                    Your existing recovery key remains active until
                    confirmation. Replacing it changes the current vault and
                    future backups; historical backup files may still be
                    unlockable with their old recovery key, and restoring one
                    can restore that old recovery configuration.
                  </p>
                ) : null}
                <p className="mt-2 text-xs leading-5 text-[var(--text-muted)]">
                  Saved key files are plaintext bearer secrets. Cloud-synced
                  folders may replicate them, and print previews, spoolers,
                  network printers, or PDF printers may retain copies. Use a
                  trusted offline location or printer when possible.
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => void saveRecoverySecret()}
                    disabled={recoveryBusy}
                    className="flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm font-medium text-[var(--text-primary)] transition hover:bg-[var(--selected)] disabled:cursor-not-allowed disabled:opacity-55"
                  >
                    <HugeiconsIcon
                      icon={Download01Icon}
                      className="size-4"
                      aria-hidden="true"
                    />
                    Save recovery key
                  </button>
                  <button
                    type="button"
                    onClick={() => window.print()}
                    disabled={recoveryBusy}
                    className="rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm font-medium text-[var(--text-primary)] transition hover:bg-[var(--selected)] disabled:cursor-not-allowed disabled:opacity-55"
                  >
                    Print recovery key
                  </button>
                  <button
                    type="button"
                    onClick={cancelRecoverySecret}
                    disabled={recoveryBusy}
                    className="rounded-xl border border-[var(--border)] px-3 py-2 text-sm font-medium text-[var(--text-muted)] transition hover:bg-[var(--selected)] disabled:cursor-not-allowed disabled:opacity-55"
                  >
                    Cancel
                  </button>
                </div>
              </div>
              <div className="recovery-print-sheet" aria-hidden="true">
                <h1>Safeory recovery key</h1>
                <p className="recovery-print-secret">
                  {generatedRecovery.secret}
                </p>
                <p>
                  Keep this key offline and separate from the device that stores
                  your vault. This key becomes active only after you return to
                  Safeory and confirm it.
                </p>
                {generatedRecovery.replacing ? (
                  <p>
                    This is a replacement key. Historical Safeory backup files
                    may still accept the recovery key captured when they were
                    created, and restoring one restores that historical recovery
                    configuration.
                  </p>
                ) : null}
              </div>
              <Field label="Re-enter the key to confirm">
                <input
                  value={recoveryConfirm}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(event) => setRecoveryConfirm(event.target.value)}
                  className="field-input font-mono"
                  placeholder="Type the recovery key again"
                />
              </Field>
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={recoveryBusy || !recoveryConfirm}
                  className="rounded-xl bg-[var(--primary)] px-4 py-2.5 text-sm font-medium text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
                >
                  {recoveryBusy
                    ? "Confirming…"
                    : generatedRecovery.replacing
                      ? "Replace recovery key"
                      : "Confirm recovery key"}
                </button>
              </div>
            </form>
          ) : recoveryStatus.configured ? (
            <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] p-4">
              <p className="text-sm font-medium">
                Recovery kit is installed on this device.
              </p>
              <p className="mt-1 text-xs leading-5 text-[var(--text-muted)]">
                The saved or printed key is the only way back if the master
                passphrase is forgotten. Keep it somewhere safe and separate
                from this device.
              </p>
              <div className="mt-4">
                <button
                  type="button"
                  onClick={() => void generateRecoverySecret(true)}
                  disabled={recoveryBusy}
                  className="rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm font-medium text-[var(--text-primary)] transition hover:bg-[var(--selected)] disabled:cursor-not-allowed disabled:opacity-55"
                >
                  {recoveryBusy ? "Generating…" : "Replace recovery key"}
                </button>
              </div>
            </div>
          ) : (
            <div className="mt-4">
              <button
                type="button"
                onClick={() => void generateRecoverySecret(false)}
                disabled={recoveryBusy}
                className="rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-4 py-2.5 text-sm font-medium text-[var(--text-primary)] transition hover:bg-[var(--selected)] disabled:cursor-not-allowed disabled:opacity-55"
              >
                {recoveryBusy ? "Generating…" : "Generate recovery key"}
              </button>
            </div>
          )}
        </div>

        <div className="mt-9 border-t border-[var(--border)] pt-8">
          <h2 className="text-base font-semibold">Backup &amp; export</h2>
          <p className="mt-1 text-sm leading-6 text-[var(--text-muted)]">
            Readable JSON contains decrypted active records, excludes Trash, and
            does not include attachment files. The encrypted backup preserves
            the complete local vault, including attachments, Trash, tombstones,
            and recovery configuration.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => void exportReadable()}
              disabled={backupBusy}
              className="flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-4 py-2.5 text-sm font-medium text-[var(--text-primary)] transition hover:bg-[var(--selected)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={Download01Icon}
                className="size-4"
                aria-hidden="true"
              />
              {backupBusy ? "Working…" : "Export readable JSON"}
            </button>
            <button
              type="button"
              onClick={() => void backupDatabase()}
              disabled={backupBusy}
              className="flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-4 py-2.5 text-sm font-medium text-[var(--text-primary)] transition hover:bg-[var(--selected)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={Download01Icon}
                className="size-4"
                aria-hidden="true"
              />
              {backupBusy ? "Working…" : "Backup encrypted database"}
            </button>
          </div>

          <form
            onSubmit={restoreDatabase}
            className="mt-6 rounded-2xl border border-[var(--danger-border)] bg-[var(--danger-soft)] p-4"
          >
            <div className="flex items-start gap-3">
              <HugeiconsIcon
                icon={DatabaseRestoreIcon}
                className="mt-0.5 size-5 shrink-0 text-[var(--danger)]"
                aria-hidden="true"
              />
              <div>
                <div className="text-sm font-semibold">
                  Restore encrypted backup
                </div>
                <p className="mt-1 text-xs leading-5 text-[var(--text-muted)]">
                  Safeory validates the selected backup before atomically
                  replacing encrypted vault data. Device-only lock settings are
                  kept. A successful restore ends locked.
                </p>
              </div>
            </div>
            <div className="mt-4 space-y-4">
              <button
                type="button"
                onClick={() => void chooseRestoreBackup()}
                disabled={restoreBusy}
                className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface)] px-4 py-2.5 text-left text-sm text-[var(--text-primary)] transition hover:bg-[var(--selected)] disabled:cursor-not-allowed disabled:opacity-55"
              >
                {restorePath ?? "Choose encrypted backup…"}
              </button>
              {restorePath !== null ? (
                <Field label="Backup master passphrase">
                  <input
                    type="password"
                    autoComplete="off"
                    value={restorePassphrase}
                    onChange={(event) =>
                      setRestorePassphrase(event.target.value)
                    }
                    className="field-input"
                    placeholder="Passphrase used by this backup"
                  />
                </Field>
              ) : null}
            </div>
            <div className="mt-4 flex justify-end">
              <button
                type="submit"
                disabled={
                  restoreBusy || restorePath === null || !restorePassphrase
                }
                className="rounded-xl bg-[var(--danger)] px-4 py-2.5 text-sm font-medium text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
              >
                {restoreBusy ? "Validating…" : "Validate and restore"}
              </button>
            </div>
          </form>
        </div>
      </section>
    </div>
  );
}

function AccessScreen({
  mode,
  error,
  onauccess,
  onError,
}: {
  mode: "setup" | "locked";
  error: string | null;
  onauccess: () => void;
  onError: (message: string | null) => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [recoveryMode, setRecoveryMode] = useState(false);
  const [recoverySecret, setRecoverySecret] = useState("");
  const [restoreMode, setRestoreMode] = useState(false);
  const [restorePath, setRestorePath] = useState<string | null>(null);
  const [restorePassphrase, setRestorePassphrase] = useState("");
  const creating = mode === "setup";

  useEffect(() => {
    return () => {
      // The recovery secret lives only in this screen's local state.
      setRecoverySecret("");
      setRestorePassphrase("");
    };
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    onError(null);
    if (creating && Array.from(passphrase).length < 12) {
      onError("Use at least 12 characters for the master passphrase.");
      return;
    }
    if (creating && passphrase !== confirmation) {
      onError("The passphrase confirmation does not match.");
      return;
    }
    setBusy(true);
    try {
      await invoke(creating ? "initialize_vault" : "unlock_vault", {
        passphrase,
      });
      setPassphrase("");
      setConfirmation("");
      onauccess();
    } catch (reason) {
      onError(readError(reason));
    } finally {
      setBusy(false);
    }
  }

  async function submitRecovery(event: FormEvent) {
    event.preventDefault();
    onError(null);
    if (!recoverySecret) return;
    setBusy(true);
    try {
      await invoke<VaultStatus>("unlock_vault_with_recovery_kit", {
        secret: recoverySecret,
      });
      setRecoverySecret("");
      setPassphrase("");
      onauccess();
    } catch (reason) {
      onError(readError(reason));
    } finally {
      setBusy(false);
    }
  }

  async function chooseInitialRestoreBackup() {
    onError(null);
    const selected = await open({
      multiple: false,
      filters: [
        {
          name: "Safeory encrypted backup",
          extensions: ["sqlite3", "db"],
        },
      ],
    });
    if (typeof selected === "string") {
      setRestorePath(selected);
      setRestorePassphrase("");
    }
  }

  async function submitInitialRestore(event: FormEvent) {
    event.preventDefault();
    onError(null);
    if (restorePath === null || !restorePassphrase) return;
    setBusy(true);
    try {
      const status = await invoke<VaultStatus>("restore_database_backup", {
        path: restorePath,
        passphrase: restorePassphrase,
      });
      if (!status.initialized) {
        throw new Error("The selected backup was not installed.");
      }
      await invoke<VaultStatus>("unlock_vault", {
        passphrase: restorePassphrase,
      });
      setRestorePassphrase("");
      setRestorePath(null);
      onauccess();
    } catch (reason) {
      onError(readError(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="grid min-h-screen place-items-center bg-[var(--surface)] px-6 text-[var(--text-primary)]">
      <div className="w-full max-w-[420px]">
        <div className="mb-7 grid size-11 place-items-center rounded-2xl bg-[var(--primary-soft)] text-[var(--primary)]">
          <ShieldKeyholeBoldIcon className="size-6" aria-hidden="true" />
        </div>
        <h1 className="text-3xl font-semibold tracking-[-0.035em]">
          {creating ? "Create your local vault" : "Unlock Safeory"}
        </h1>
        <p className="mt-3 text-sm leading-6 text-[var(--text-secondary)]">
          {creating
            ? "Your master passphrase protects a random root key. It is not stored in plaintext."
            : "Enter your master passphrase to decrypt the local vault on this device."}
        </p>

        {creating && restoreMode ? (
          <form className="mt-8 space-y-4" onSubmit={submitInitialRestore}>
            <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] p-4">
              <div className="flex items-start gap-3">
                <HugeiconsIcon
                  icon={DatabaseRestoreIcon}
                  className="mt-0.5 size-5 shrink-0 text-[var(--primary)]"
                  aria-hidden="true"
                />
                <div>
                  <div className="text-sm font-semibold">
                    Restore an encrypted Safeory backup
                  </div>
                  <p className="mt-1 text-xs leading-5 text-[var(--text-muted)]">
                    The backup is validated on a staged copy before it becomes
                    this device&apos;s local vault.
                  </p>
                </div>
              </div>
            </div>
            <button
              type="button"
              onClick={() => void chooseInitialRestoreBackup()}
              disabled={busy}
              className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-4 py-3 text-left text-sm text-[var(--text-primary)] transition hover:bg-[var(--selected)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              {restorePath ?? "Choose encrypted backup…"}
            </button>
            {restorePath !== null ? (
              <Field label="Backup master passphrase">
                <input
                  autoFocus
                  type="password"
                  autoComplete="off"
                  value={restorePassphrase}
                  onChange={(event) => setRestorePassphrase(event.target.value)}
                  className="field-input"
                  placeholder="Passphrase used by this backup"
                />
              </Field>
            ) : null}

            {error ? (
              <div
                role="alert"
                className="rounded-xl border border-[var(--danger-border)] bg-[var(--danger-soft)] px-4 py-3 text-sm text-[var(--danger)]"
              >
                {error}
              </div>
            ) : null}

            <button
              type="submit"
              disabled={busy || restorePath === null || !restorePassphrase}
              className="mt-2 flex w-full items-center justify-center gap-2 rounded-xl bg-[var(--primary)] px-4 py-3 text-sm font-medium text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={DatabaseRestoreIcon}
                className="size-4"
                aria-hidden="true"
              />
              {busy ? "Validating…" : "Restore backup"}
            </button>
          </form>
        ) : recoveryMode && !creating ? (
          <form className="mt-8 space-y-4" onSubmit={submitRecovery}>
            <Field label="Recovery secret">
              <input
                autoFocus
                type="password"
                autoComplete="off"
                spellCheck={false}
                value={recoverySecret}
                onChange={(event) => setRecoverySecret(event.target.value)}
                className="field-input font-mono"
                placeholder="Paste your recovery secret"
              />
            </Field>

            {error ? (
              <div
                role="alert"
                className="rounded-xl border border-[var(--danger-border)] bg-[var(--danger-soft)] px-4 py-3 text-sm text-[var(--danger)]"
              >
                {error}
              </div>
            ) : null}

            <button
              type="submit"
              disabled={busy || !recoverySecret}
              className="mt-2 flex w-full items-center justify-center gap-2 rounded-xl bg-[var(--primary)] px-4 py-3 text-sm font-medium text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={LockIcon}
                className="size-4"
                aria-hidden="true"
              />
              {busy ? "Working…" : "Unlock with recovery kit"}
            </button>
          </form>
        ) : (
          <form className="mt-8 space-y-4" onSubmit={submit}>
            <Field label="Master passphrase">
              <input
                autoFocus
                type="password"
                autoComplete={creating ? "new-password" : "current-password"}
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
                className="field-input"
                placeholder={
                  creating ? "12 characters or more" : "Enter your passphrase"
                }
              />
            </Field>
            {creating ? (
              <Field label="Confirm passphrase">
                <input
                  type="password"
                  autoComplete="new-password"
                  value={confirmation}
                  onChange={(event) => setConfirmation(event.target.value)}
                  className="field-input"
                  placeholder="Repeat your passphrase"
                />
              </Field>
            ) : null}

            {error ? (
              <div
                role="alert"
                className="rounded-xl border border-[var(--danger-border)] bg-[var(--danger-soft)] px-4 py-3 text-sm text-[var(--danger)]"
              >
                {error}
              </div>
            ) : null}

            <button
              type="submit"
              disabled={busy || !passphrase}
              className="mt-2 flex w-full items-center justify-center gap-2 rounded-xl bg-[var(--primary)] px-4 py-3 text-sm font-medium text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={LockIcon}
                className="size-4"
                aria-hidden="true"
              />
              {busy ? "Working…" : creating ? "Create vault" : "Unlock vault"}
            </button>
          </form>
        )}

        {creating ? (
          <button
            type="button"
            onClick={() => {
              setRestoreMode((current) => !current);
              setRestorePath(null);
              setRestorePassphrase("");
              setPassphrase("");
              setConfirmation("");
              onError(null);
            }}
            className="mt-4 text-sm text-[var(--text-muted)] underline-offset-4 transition hover:text-[var(--text-primary)] hover:underline"
          >
            {restoreMode
              ? "Create a new vault instead"
              : "Restore an encrypted backup instead"}
          </button>
        ) : (
          <button
            type="button"
            onClick={() => {
              setRecoveryMode((current) => !current);
              onError(null);
            }}
            className="mt-4 text-sm text-[var(--text-muted)] underline-offset-4 transition hover:text-[var(--text-primary)] hover:underline"
          >
            {recoveryMode
              ? "Use your passphrase instead"
              : "Use a recovery kit instead"}
          </button>
        )}

        <p className="mt-6 text-xs leading-5 text-[var(--text-muted)]">
          Local encrypted backup and recovery-kit unlock are available. Cloud
          sync, trusted people, and emergency access are not enabled yet.
        </p>
      </div>
    </main>
  );
}

function NoteComposer({
  note,
  generation,
  onCancel,
  onSaved,
  onError,
}: {
  note: NoteView | null;
  generation: number;
  onCancel: () => void;
  onSaved: (note: NoteView, created: boolean, generation: number) => void;
  onError: (message: string | null) => void;
}) {
  const [title, setTitle] = useState(note?.title ?? "");
  const [body, setBody] = useState(note?.body ?? "");
  const [saving, setSaving] = useState(false);
  const editing = note !== null;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!title.trim()) return;
    setSaving(true);
    onError(null);
    try {
      const saved = editing
        ? await invoke<NoteView>("update_note", {
            id: note.id,
            revision: note.revision,
            title,
            body,
          })
        : await invoke<NoteView>("create_note", { title, body });
      setTitle("");
      setBody("");
      onSaved(saved, !editing, generation);
    } catch (reason) {
      onError(readError(reason));
    } finally {
      setSaving(false);
    }
  }

  return (
    <EditorFrame
      title={editing ? "Edit secure note" : "New secure note"}
      onCancel={onCancel}
    >
      <form onSubmit={submit} autoComplete="off">
        <input
          autoFocus
          value={title}
          onChange={(event) => setTitle(event.target.value)}
          placeholder="Untitled note"
          aria-label="Note title"
          className="editor-title"
        />
        <textarea
          value={body}
          onChange={(event) => setBody(event.target.value)}
          placeholder="Write something you want to keep private…"
          aria-label="Note body"
          className="mt-7 min-h-[320px] w-full resize-none border-0 bg-transparent p-0 text-[15px] leading-7 text-[var(--text-secondary)] outline-none placeholder:text-[var(--text-muted)]"
        />
        <EditorFooter
          saving={saving}
          disabled={!title.trim()}
          action={editing ? "Save changes" : "Save note"}
        />
      </form>
    </EditorFrame>
  );
}

function CredentialComposer({
  credential,
  generation,
  isGenerationCurrent,
  onCancel,
  onSaved,
  onError,
}: {
  credential: CredentialView | null;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onCancel: () => void;
  onSaved: (
    credential: CredentialView,
    created: boolean,
    generation: number,
  ) => void;
  onError: (message: string | null) => void;
}) {
  const [title, setTitle] = useState(credential?.title ?? "");
  const [username, setUsername] = useState(credential?.username ?? "");
  const [password, setPassword] = useState("");
  const [website, setWebsite] = useState(credential?.website ?? "");
  const [notes, setNotes] = useState(credential?.notes ?? "");
  const [revealed, setRevealed] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [saving, setSaving] = useState(false);
  const editing = credential !== null;
  const [detailReady, setDetailReady] = useState(!editing);

  useEffect(() => {
    if (!credential) return;
    let active = true;
    void invoke<CredentialDetailView>("get_credential", {
      id: credential.id,
      revision: credential.revision,
    })
      .then((detail) => {
        if (!active || !isGenerationCurrent(generation)) return;
        setPassword(detail.password);
        setDetailReady(true);
      })
      .catch((reason: unknown) => {
        if (active && isGenerationCurrent(generation))
          onError(readError(reason));
      });
    return () => {
      active = false;
    };
  }, [credential, generation, isGenerationCurrent, onError]);

  async function generatePassword() {
    if (generating || !detailReady) return;
    setGenerating(true);
    onError(null);
    try {
      const generated = await invoke<string>("generate_password");
      if (!isGenerationCurrent(generation)) return;
      setPassword(generated);
      setRevealed(true);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setGenerating(false);
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!title.trim() || !detailReady) return;
    setSaving(true);
    onError(null);
    try {
      const input = { title, username, password, website, notes };
      const saved = editing
        ? await invoke<CredentialView>("update_credential", {
            id: credential.id,
            revision: credential.revision,
            ...input,
          })
        : await invoke<CredentialView>("create_credential", input);
      setPassword("");
      onSaved(saved, !editing, generation);
    } catch (reason) {
      onError(readError(reason));
    } finally {
      setSaving(false);
    }
  }

  return (
    <EditorFrame
      title={editing ? "Edit credential" : "New credential"}
      onCancel={onCancel}
    >
      <form onSubmit={submit} autoComplete="off">
        <input
          autoFocus
          value={title}
          onChange={(event) => setTitle(event.target.value)}
          placeholder="Account or service name"
          aria-label="Credential title"
          className="editor-title"
        />
        <div className="mt-8 grid gap-5 sm:grid-cols-2">
          <Field label="Username or email">
            <input
              value={username}
              autoComplete="off"
              onChange={(event) => setUsername(event.target.value)}
              className="field-input"
              placeholder="name@example.com"
            />
          </Field>
          <Field label="Website">
            <input
              value={website}
              inputMode="url"
              autoComplete="off"
              onChange={(event) => setWebsite(event.target.value)}
              className="field-input"
              placeholder="https://example.com"
            />
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Password">
            <div className="relative">
              <input
                value={password}
                type={revealed ? "text" : "password"}
                autoComplete="off"
                onChange={(event) => setPassword(event.target.value)}
                disabled={!detailReady}
                className="field-input pr-11"
                placeholder="Stored encrypted locally"
              />
              <button
                type="button"
                aria-label={revealed ? "Hide password" : "Show password"}
                onClick={() => setRevealed((current) => !current)}
                className="absolute right-2 top-1/2 grid size-8 -translate-y-1/2 place-items-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)]"
              >
                <HugeiconsIcon
                  icon={revealed ? EyeOffIcon : EyeIcon}
                  className="size-4"
                  aria-hidden="true"
                />
              </button>
            </div>
            <button
              type="button"
              onClick={() => void generatePassword()}
              disabled={generating || !detailReady}
              className="mt-2 flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={MagicWand01Icon}
                className="size-4"
                aria-hidden="true"
              />
              {generating ? "Generating…" : "Generate strong password"}
            </button>
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Notes">
            <textarea
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              className="field-input min-h-28 resize-y"
              placeholder="Optional private context"
            />
          </Field>
        </div>
        <EditorFooter
          saving={saving}
          disabled={!title.trim() || !detailReady}
          action={editing ? "Save changes" : "Save credential"}
        />
      </form>
    </EditorFrame>
  );
}

function DocumentComposer({
  document,
  generation,
  isGenerationCurrent,
  onCancel,
  onSaved,
  onError,
}: {
  document: DocumentView | null;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onCancel: () => void;
  onSaved: (
    document: DocumentView,
    created: boolean,
    generation: number,
  ) => void;
  onError: (message: string | null) => void;
}) {
  const [title, setTitle] = useState(document?.title ?? "");
  const [documentNumber, setDocumentNumber] = useState("");
  const [issuer, setIssuer] = useState(document?.issuer ?? "");
  const [expiry, setExpiry] = useState(document?.expiry ?? "");
  const [notes, setNotes] = useState(document?.notes ?? "");
  const [revealed, setRevealed] = useState(false);
  const [saving, setSaving] = useState(false);
  const editing = document !== null;
  const [detailReady, setDetailReady] = useState(!editing);

  useEffect(() => {
    if (!document) return;
    let active = true;
    void invoke<DocumentDetailView>("get_document", {
      id: document.id,
      revision: document.revision,
    })
      .then((detail) => {
        if (!active || !isGenerationCurrent(generation)) return;
        setDocumentNumber(detail.document_number);
        setDetailReady(true);
      })
      .catch((reason: unknown) => {
        if (active && isGenerationCurrent(generation))
          onError(readError(reason));
      });
    return () => {
      active = false;
    };
  }, [document, generation, isGenerationCurrent, onError]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!title.trim() || !detailReady) return;
    setSaving(true);
    onError(null);
    try {
      const input = {
        title,
        documentNumber,
        issuer,
        expiry,
        notes,
      };
      const saved = editing
        ? await invoke<DocumentView>("update_document", {
            id: document.id,
            revision: document.revision,
            ...input,
          })
        : await invoke<DocumentView>("create_document", input);
      setDocumentNumber("");
      onSaved(saved, !editing, generation);
    } catch (reason) {
      onError(readError(reason));
    } finally {
      setSaving(false);
    }
  }

  return (
    <EditorFrame
      title={editing ? "Edit document" : "New document"}
      onCancel={onCancel}
    >
      <form onSubmit={submit} autoComplete="off">
        <input
          autoFocus
          value={title}
          onChange={(event) => setTitle(event.target.value)}
          placeholder="Passport, ID card, certificate…"
          aria-label="Document title"
          className="editor-title"
        />
        <div className="mt-8 grid gap-5 sm:grid-cols-2">
          <Field label="Issuer">
            <input
              value={issuer}
              autoComplete="off"
              onChange={(event) => setIssuer(event.target.value)}
              className="field-input"
              placeholder="Issuing organization"
            />
          </Field>
          <Field label="Expiry date">
            <input
              value={expiry}
              type="date"
              autoComplete="off"
              onChange={(event) => setExpiry(event.target.value)}
              className="field-input"
            />
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Document number">
            <div className="relative">
              <input
                value={documentNumber}
                type={revealed ? "text" : "password"}
                autoComplete="off"
                onChange={(event) => setDocumentNumber(event.target.value)}
                disabled={!detailReady}
                className="field-input pr-11"
                placeholder="Stored encrypted locally"
              />
              <button
                type="button"
                aria-label={
                  revealed ? "Hide document number" : "Show document number"
                }
                onClick={() => setRevealed((current) => !current)}
                className="absolute right-2 top-1/2 grid size-8 -translate-y-1/2 place-items-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)]"
              >
                <HugeiconsIcon
                  icon={revealed ? EyeOffIcon : EyeIcon}
                  className="size-4"
                  aria-hidden="true"
                />
              </button>
            </div>
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Notes">
            <textarea
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              className="field-input min-h-28 resize-y"
              placeholder="Optional private context"
            />
          </Field>
        </div>
        <EditorFooter
          saving={saving}
          disabled={!title.trim() || !detailReady}
          action={editing ? "Save changes" : "Save document"}
        />
      </form>
    </EditorFrame>
  );
}

function ReceiptComposer({
  receipt,
  generation,
  isGenerationCurrent,
  onCancel,
  onSaved,
  onError,
}: {
  receipt: ReceiptView | null;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onCancel: () => void;
  onSaved: (receipt: ReceiptView, created: boolean, generation: number) => void;
  onError: (message: string | null) => void;
}) {
  const [title, setTitle] = useState(receipt?.title ?? "");
  const [merchant, setMerchant] = useState(receipt?.merchant ?? "");
  const [purchaseDate, setPurchaseDate] = useState(
    receipt?.purchase_date ?? "",
  );
  const [amount, setAmount] = useState(receipt?.amount ?? "");
  const [currency, setCurrency] = useState(receipt?.currency ?? "");
  const [receiptReference, setReceiptReference] = useState("");
  const [trackingStatus, setTrackingStatus] = useState(
    receipt?.tracking_status ?? "",
  );
  const [returnBy, setReturnBy] = useState(receipt?.return_by ?? "");
  const [refundDue, setRefundDue] = useState(receipt?.refund_due ?? "");
  const [notes, setNotes] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [saving, setSaving] = useState(false);
  const editing = receipt !== null;
  const [detailReady, setDetailReady] = useState(!editing);

  useEffect(() => {
    if (!receipt) return;
    let active = true;
    void invoke<ReceiptDetailView>("get_receipt", {
      id: receipt.id,
      revision: receipt.revision,
    })
      .then((detail) => {
        if (!active || !isGenerationCurrent(generation)) return;
        setMerchant(detail.merchant);
        setPurchaseDate(detail.purchase_date);
        setAmount(detail.amount);
        setCurrency(detail.currency);
        setReceiptReference(detail.receipt_reference);
        setTrackingStatus(detail.tracking_status);
        setReturnBy(detail.return_by);
        setRefundDue(detail.refund_due);
        setNotes(detail.notes);
        setDetailReady(true);
      })
      .catch((reason: unknown) => {
        if (active && isGenerationCurrent(generation))
          onError(readError(reason));
      });
    return () => {
      active = false;
    };
  }, [receipt, generation, isGenerationCurrent, onError]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!title.trim() || !detailReady) return;
    setSaving(true);
    onError(null);
    try {
      const input = {
        title,
        merchant,
        purchaseDate,
        amount,
        currency,
        receiptReference,
        trackingStatus,
        returnBy,
        refundDue,
        notes,
      };
      const saved = editing
        ? await invoke<ReceiptView>("update_receipt", {
            id: receipt.id,
            revision: receipt.revision,
            ...input,
          })
        : await invoke<ReceiptView>("create_receipt", input);
      setReceiptReference("");
      setNotes("");
      if (isGenerationCurrent(generation)) onSaved(saved, !editing, generation);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setSaving(false);
    }
  }

  return (
    <EditorFrame
      title={editing ? "Edit receipt" : "New receipt"}
      onCancel={onCancel}
    >
      <form onSubmit={submit} autoComplete="off">
        <input
          autoFocus
          value={title}
          onChange={(event) => setTitle(event.target.value)}
          placeholder="MacBook receipt, appliance invoice…"
          aria-label="Receipt title"
          className="editor-title"
        />
        <div className="mt-8 grid gap-5 sm:grid-cols-2">
          <Field label="Merchant">
            <input
              value={merchant}
              autoComplete="off"
              onChange={(event) => setMerchant(event.target.value)}
              className="field-input"
              placeholder="Store or seller"
            />
          </Field>
          <Field label="Purchase date">
            <input
              value={purchaseDate}
              type="date"
              autoComplete="off"
              onChange={(event) => setPurchaseDate(event.target.value)}
              className="field-input"
            />
          </Field>
        </div>
        <div className="mt-5 grid gap-5 sm:grid-cols-2">
          <Field label="Amount">
            <input
              value={amount}
              autoComplete="off"
              onChange={(event) => setAmount(event.target.value)}
              className="field-input"
              placeholder="199900"
            />
          </Field>
          <Field label="Currency">
            <input
              value={currency}
              autoComplete="off"
              onChange={(event) => setCurrency(event.target.value)}
              className="field-input"
              placeholder="INR, USD, EUR…"
            />
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Receipt reference">
            <div className="relative">
              <input
                value={receiptReference}
                type={revealed ? "text" : "password"}
                autoComplete="off"
                onChange={(event) => setReceiptReference(event.target.value)}
                disabled={!detailReady}
                className="field-input pr-11"
                placeholder="Invoice, order or receipt number"
              />
              <button
                type="button"
                aria-label={
                  revealed ? "Hide receipt reference" : "Show receipt reference"
                }
                onClick={() => setRevealed((current) => !current)}
                className="absolute right-2 top-1/2 grid size-8 -translate-y-1/2 place-items-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)]"
              >
                <HugeiconsIcon
                  icon={revealed ? EyeOffIcon : EyeIcon}
                  className="size-4"
                  aria-hidden="true"
                />
              </button>
            </div>
          </Field>
        </div>
        <div className="mt-5 grid gap-5 sm:grid-cols-2">
          <Field label="Return / refund status">
            <select
              value={trackingStatus}
              onChange={(event) => setTrackingStatus(event.target.value)}
              className="field-input"
            >
              <option value="">Not tracking</option>
              <option value="kept">Keeping item</option>
              <option value="return_planned">Return planned</option>
              <option value="returned">Returned</option>
              <option value="refund_pending">Refund pending</option>
              <option value="refunded">Refunded</option>
            </select>
          </Field>
          <Field label="Return by">
            <input
              value={returnBy}
              type="date"
              autoComplete="off"
              onChange={(event) => setReturnBy(event.target.value)}
              className="field-input"
            />
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Refund due">
            <input
              value={refundDue}
              type="date"
              autoComplete="off"
              onChange={(event) => setRefundDue(event.target.value)}
              className="field-input"
            />
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Notes">
            <textarea
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              className="field-input min-h-28 resize-y"
              placeholder="Optional private context"
            />
          </Field>
        </div>
        <EditorFooter
          saving={saving}
          disabled={!title.trim() || !detailReady}
          action={editing ? "Save changes" : "Save receipt"}
        />
      </form>
    </EditorFrame>
  );
}

function InsuranceComposer({
  insurance,
  generation,
  isGenerationCurrent,
  onCancel,
  onSaved,
  onError,
}: {
  insurance: InsuranceView | null;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onCancel: () => void;
  onSaved: (
    insurance: InsuranceView,
    created: boolean,
    generation: number,
  ) => void;
  onError: (message: string | null) => void;
}) {
  const [title, setTitle] = useState(insurance?.title ?? "");
  const [provider, setProvider] = useState(insurance?.provider ?? "");
  const [policyType, setPolicyType] = useState(insurance?.policy_type ?? "");
  const [policyNumber, setPolicyNumber] = useState("");
  const [renewal, setRenewal] = useState(insurance?.renewal ?? "");
  const [notes, setNotes] = useState(insurance?.notes ?? "");
  const [revealed, setRevealed] = useState(false);
  const [saving, setSaving] = useState(false);
  const editing = insurance !== null;
  const [detailReady, setDetailReady] = useState(!editing);

  useEffect(() => {
    if (!insurance) return;
    let active = true;
    void invoke<InsuranceDetailView>("get_insurance", {
      id: insurance.id,
      revision: insurance.revision,
    })
      .then((detail) => {
        if (!active || !isGenerationCurrent(generation)) return;
        setPolicyNumber(detail.policy_number);
        setDetailReady(true);
      })
      .catch((reason: unknown) => {
        if (active && isGenerationCurrent(generation))
          onError(readError(reason));
      });
    return () => {
      active = false;
    };
  }, [insurance, generation, isGenerationCurrent, onError]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!title.trim() || !detailReady) return;
    setSaving(true);
    onError(null);
    try {
      const input = {
        title,
        provider,
        policyType,
        policyNumber,
        renewal,
        notes,
      };
      const saved = editing
        ? await invoke<InsuranceView>("update_insurance", {
            id: insurance.id,
            revision: insurance.revision,
            ...input,
          })
        : await invoke<InsuranceView>("create_insurance", input);
      setPolicyNumber("");
      onSaved(saved, !editing, generation);
    } catch (reason) {
      onError(readError(reason));
    } finally {
      setSaving(false);
    }
  }

  return (
    <EditorFrame
      title={editing ? "Edit insurance" : "New insurance"}
      onCancel={onCancel}
    >
      <form onSubmit={submit} autoComplete="off">
        <input
          autoFocus
          value={title}
          onChange={(event) => setTitle(event.target.value)}
          placeholder="Health cover, vehicle policy…"
          aria-label="Insurance title"
          className="editor-title"
        />
        <div className="mt-8 grid gap-5 sm:grid-cols-2">
          <Field label="Provider">
            <input
              value={provider}
              autoComplete="off"
              onChange={(event) => setProvider(event.target.value)}
              className="field-input"
              placeholder="Insurance provider"
            />
          </Field>
          <Field label="Policy type">
            <input
              value={policyType}
              autoComplete="off"
              onChange={(event) => setPolicyType(event.target.value)}
              className="field-input"
              placeholder="Health, vehicle, home…"
            />
          </Field>
        </div>
        <div className="mt-5 grid gap-5 sm:grid-cols-2">
          <Field label="Renewal date">
            <input
              value={renewal}
              type="date"
              autoComplete="off"
              onChange={(event) => setRenewal(event.target.value)}
              className="field-input"
            />
          </Field>
          <Field label="Policy number">
            <div className="relative">
              <input
                value={policyNumber}
                type={revealed ? "text" : "password"}
                autoComplete="off"
                onChange={(event) => setPolicyNumber(event.target.value)}
                disabled={!detailReady}
                className="field-input pr-11"
                placeholder="Stored encrypted locally"
              />
              <button
                type="button"
                aria-label={
                  revealed ? "Hide policy number" : "Show policy number"
                }
                onClick={() => setRevealed((current) => !current)}
                className="absolute right-2 top-1/2 grid size-8 -translate-y-1/2 place-items-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)]"
              >
                <HugeiconsIcon
                  icon={revealed ? EyeOffIcon : EyeIcon}
                  className="size-4"
                  aria-hidden="true"
                />
              </button>
            </div>
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Notes">
            <textarea
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              className="field-input min-h-28 resize-y"
              placeholder="Optional private context"
            />
          </Field>
        </div>
        <EditorFooter
          saving={saving}
          disabled={!title.trim() || !detailReady}
          action={editing ? "Save changes" : "Save insurance"}
        />
      </form>
    </EditorFrame>
  );
}

function FinancialComposer({
  financial,
  generation,
  isGenerationCurrent,
  onCancel,
  onSaved,
  onError,
}: {
  financial: FinancialView | null;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onCancel: () => void;
  onSaved: (
    financial: FinancialView,
    created: boolean,
    generation: number,
  ) => void;
  onError: (message: string | null) => void;
}) {
  const [title, setTitle] = useState(financial?.title ?? "");
  const [institution, setInstitution] = useState(financial?.institution ?? "");
  const [accountType, setAccountType] = useState(financial?.account_type ?? "");
  const [currency, setCurrency] = useState(financial?.currency ?? "");
  const [accountNumber, setAccountNumber] = useState("");
  const [notes, setNotes] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [saving, setSaving] = useState(false);
  const editing = financial !== null;
  const [detailReady, setDetailReady] = useState(!editing);

  useEffect(() => {
    if (!financial) return;
    let active = true;
    void invoke<FinancialDetailView>("get_financial", {
      id: financial.id,
      revision: financial.revision,
    })
      .then((detail) => {
        if (!active || !isGenerationCurrent(generation)) return;
        setCurrency(detail.currency);
        setAccountNumber(detail.account_number);
        setNotes(detail.notes);
        setDetailReady(true);
      })
      .catch((reason: unknown) => {
        if (active && isGenerationCurrent(generation))
          onError(readError(reason));
      });
    return () => {
      active = false;
    };
  }, [financial, generation, isGenerationCurrent, onError]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!title.trim() || !detailReady) return;
    setSaving(true);
    onError(null);
    try {
      const input = {
        title,
        institution,
        accountType,
        currency,
        accountNumber,
        notes,
      };
      const saved = editing
        ? await invoke<FinancialView>("update_financial", {
            id: financial.id,
            revision: financial.revision,
            ...input,
          })
        : await invoke<FinancialView>("create_financial", input);
      setAccountNumber("");
      setNotes("");
      onSaved(saved, !editing, generation);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setSaving(false);
    }
  }

  return (
    <EditorFrame
      title={editing ? "Edit financial record" : "New financial record"}
      onCancel={onCancel}
    >
      <form onSubmit={submit} autoComplete="off">
        <input
          autoFocus
          value={title}
          onChange={(event) => setTitle(event.target.value)}
          placeholder="Bank account, investment, loan…"
          aria-label="Financial record title"
          className="editor-title"
        />
        <div className="mt-8 grid gap-5 sm:grid-cols-2">
          <Field label="Institution">
            <input
              value={institution}
              autoComplete="off"
              onChange={(event) => setInstitution(event.target.value)}
              className="field-input"
              placeholder="Bank or provider"
            />
          </Field>
          <Field label="Account type">
            <input
              value={accountType}
              autoComplete="off"
              onChange={(event) => setAccountType(event.target.value)}
              className="field-input"
              placeholder="Savings, brokerage, loan…"
            />
          </Field>
        </div>
        <div className="mt-5 grid gap-5 sm:grid-cols-2">
          <Field label="Currency">
            <input
              value={currency}
              autoComplete="off"
              onChange={(event) => setCurrency(event.target.value)}
              className="field-input"
              placeholder="USD, INR, EUR…"
            />
          </Field>
          <Field label="Account number">
            <div className="relative">
              <input
                value={accountNumber}
                type={revealed ? "text" : "password"}
                autoComplete="off"
                onChange={(event) => setAccountNumber(event.target.value)}
                disabled={!detailReady}
                className="field-input pr-11"
                placeholder="Stored encrypted locally"
              />
              <button
                type="button"
                aria-label={
                  revealed ? "Hide account number" : "Show account number"
                }
                onClick={() => setRevealed((current) => !current)}
                className="absolute right-2 top-1/2 grid size-8 -translate-y-1/2 place-items-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)]"
              >
                <HugeiconsIcon
                  icon={revealed ? EyeOffIcon : EyeIcon}
                  className="size-4"
                  aria-hidden="true"
                />
              </button>
            </div>
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Notes">
            <textarea
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              className="field-input min-h-28 resize-y"
              placeholder="Optional private context"
            />
          </Field>
        </div>
        <EditorFooter
          saving={saving}
          disabled={!title.trim() || !detailReady}
          action={editing ? "Save changes" : "Save financial record"}
        />
      </form>
    </EditorFrame>
  );
}

function PropertyComposer({
  property,
  generation,
  isGenerationCurrent,
  onCancel,
  onSaved,
  onError,
}: {
  property: PropertyView | null;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onCancel: () => void;
  onSaved: (
    property: PropertyView,
    created: boolean,
    generation: number,
  ) => void;
  onError: (message: string | null) => void;
}) {
  const [title, setTitle] = useState(property?.title ?? "");
  const [propertyType, setPropertyType] = useState(
    property?.property_type ?? "",
  );
  const [ownership, setOwnership] = useState(property?.ownership ?? "");
  const [address, setAddress] = useState("");
  const [propertyReference, setPropertyReference] = useState("");
  const [notes, setNotes] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [saving, setSaving] = useState(false);
  const editing = property !== null;
  const [detailReady, setDetailReady] = useState(!editing);

  useEffect(() => {
    if (!property) return;
    let active = true;
    void invoke<PropertyDetailView>("get_property", {
      id: property.id,
      revision: property.revision,
    })
      .then((detail) => {
        if (!active || !isGenerationCurrent(generation)) return;
        setAddress(detail.address);
        setOwnership(detail.ownership);
        setPropertyReference(detail.property_reference);
        setNotes(detail.notes);
        setDetailReady(true);
      })
      .catch((reason: unknown) => {
        if (active && isGenerationCurrent(generation))
          onError(readError(reason));
      });
    return () => {
      active = false;
    };
  }, [property, generation, isGenerationCurrent, onError]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!title.trim() || !detailReady) return;
    setSaving(true);
    onError(null);
    try {
      const input = {
        title,
        propertyType,
        address,
        ownership,
        propertyReference,
        notes,
      };
      const saved = editing
        ? await invoke<PropertyView>("update_property", {
            id: property.id,
            revision: property.revision,
            ...input,
          })
        : await invoke<PropertyView>("create_property", input);
      setAddress("");
      setPropertyReference("");
      setNotes("");
      onSaved(saved, !editing, generation);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setSaving(false);
    }
  }

  return (
    <EditorFrame
      title={editing ? "Edit property" : "New property"}
      onCancel={onCancel}
    >
      <form onSubmit={submit} autoComplete="off">
        <input
          autoFocus
          value={title}
          onChange={(event) => setTitle(event.target.value)}
          placeholder="Home, apartment, land…"
          aria-label="Property title"
          className="editor-title"
        />
        <div className="mt-8 grid gap-5 sm:grid-cols-2">
          <Field label="Property type">
            <input
              value={propertyType}
              autoComplete="off"
              onChange={(event) => setPropertyType(event.target.value)}
              className="field-input"
              placeholder="House, apartment, land…"
            />
          </Field>
          <Field label="Ownership">
            <select
              value={ownership}
              onChange={(event) => setOwnership(event.target.value)}
              className="field-input"
            >
              <option value="">Not set</option>
              <option value="Owned">Owned</option>
              <option value="Rented">Rented</option>
              <option value="Leased">Leased</option>
              <option value="Shared">Shared</option>
              <option value="Other">Other</option>
            </select>
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Address">
            <textarea
              value={address}
              onChange={(event) => setAddress(event.target.value)}
              className="field-input min-h-20 resize-y"
              placeholder="Stored encrypted locally"
            />
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Property reference">
            <div className="relative">
              <input
                value={propertyReference}
                type={revealed ? "text" : "password"}
                autoComplete="off"
                onChange={(event) => setPropertyReference(event.target.value)}
                disabled={!detailReady}
                className="field-input pr-11"
                placeholder="Deed, parcel, registry or internal reference"
              />
              <button
                type="button"
                aria-label={
                  revealed
                    ? "Hide property reference"
                    : "Show property reference"
                }
                onClick={() => setRevealed((current) => !current)}
                className="absolute right-2 top-1/2 grid size-8 -translate-y-1/2 place-items-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)]"
              >
                <HugeiconsIcon
                  icon={revealed ? EyeOffIcon : EyeIcon}
                  className="size-4"
                  aria-hidden="true"
                />
              </button>
            </div>
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Notes">
            <textarea
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              className="field-input min-h-28 resize-y"
              placeholder="Optional private context"
            />
          </Field>
        </div>
        <EditorFooter
          saving={saving}
          disabled={!title.trim() || !detailReady}
          action={editing ? "Save changes" : "Save property"}
        />
      </form>
    </EditorFrame>
  );
}

function VehicleComposer({
  vehicle,
  generation,
  isGenerationCurrent,
  onCancel,
  onSaved,
  onError,
}: {
  vehicle: VehicleView | null;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onCancel: () => void;
  onSaved: (vehicle: VehicleView, created: boolean, generation: number) => void;
  onError: (message: string | null) => void;
}) {
  const [title, setTitle] = useState(vehicle?.title ?? "");
  const [make, setMake] = useState(vehicle?.make ?? "");
  const [model, setModel] = useState(vehicle?.model ?? "");
  const [year, setYear] = useState(vehicle?.year ?? "");
  const [registrationNumber, setRegistrationNumber] = useState("");
  const [vin, setVin] = useState("");
  const [renewal, setRenewal] = useState(vehicle?.renewal ?? "");
  const [notes, setNotes] = useState(vehicle?.notes ?? "");
  const [revealedRegistration, setRevealedRegistration] = useState(false);
  const [revealedVin, setRevealedVin] = useState(false);
  const [saving, setSaving] = useState(false);
  const editing = vehicle !== null;
  const [detailReady, setDetailReady] = useState(!editing);

  useEffect(() => {
    if (!vehicle) return;
    let active = true;
    void invoke<VehicleDetailView>("get_vehicle", {
      id: vehicle.id,
      revision: vehicle.revision,
    })
      .then((detail) => {
        if (!active || !isGenerationCurrent(generation)) return;
        setRegistrationNumber(detail.registration_number);
        setVin(detail.vin);
        setDetailReady(true);
      })
      .catch((reason: unknown) => {
        if (active && isGenerationCurrent(generation))
          onError(readError(reason));
      });
    return () => {
      active = false;
    };
  }, [vehicle, generation, isGenerationCurrent, onError]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!title.trim() || !detailReady) return;
    setSaving(true);
    onError(null);
    try {
      const input = {
        title,
        make,
        model,
        year,
        registrationNumber,
        vin,
        renewal,
        notes,
      };
      const saved = editing
        ? await invoke<VehicleView>("update_vehicle", {
            id: vehicle.id,
            revision: vehicle.revision,
            ...input,
          })
        : await invoke<VehicleView>("create_vehicle", input);
      setRegistrationNumber("");
      setVin("");
      onSaved(saved, !editing, generation);
    } catch (reason) {
      onError(readError(reason));
    } finally {
      setSaving(false);
    }
  }

  return (
    <EditorFrame
      title={editing ? "Edit vehicle" : "New vehicle"}
      onCancel={onCancel}
    >
      <form onSubmit={submit} autoComplete="off">
        <input
          autoFocus
          value={title}
          onChange={(event) => setTitle(event.target.value)}
          placeholder="Family car, motorcycle…"
          aria-label="Vehicle title"
          className="editor-title"
        />
        <div className="mt-8 grid gap-5 sm:grid-cols-2">
          <Field label="Make">
            <input
              value={make}
              autoComplete="off"
              onChange={(event) => setMake(event.target.value)}
              className="field-input"
              placeholder="Toyota, Honda…"
            />
          </Field>
          <Field label="Model">
            <input
              value={model}
              autoComplete="off"
              onChange={(event) => setModel(event.target.value)}
              className="field-input"
              placeholder="Innova, City…"
            />
          </Field>
        </div>
        <div className="mt-5 grid gap-5 sm:grid-cols-2">
          <Field label="Year">
            <input
              value={year}
              autoComplete="off"
              onChange={(event) => setYear(event.target.value)}
              className="field-input"
              placeholder="2021"
            />
          </Field>
          <Field label="Renewal date">
            <input
              value={renewal}
              type="date"
              autoComplete="off"
              onChange={(event) => setRenewal(event.target.value)}
              className="field-input"
            />
          </Field>
        </div>
        <div className="mt-5 grid gap-5 sm:grid-cols-2">
          <Field label="Registration number">
            <div className="relative">
              <input
                value={registrationNumber}
                type={revealedRegistration ? "text" : "password"}
                autoComplete="off"
                onChange={(event) => setRegistrationNumber(event.target.value)}
                disabled={!detailReady}
                className="field-input pr-11"
                placeholder="Stored encrypted locally"
              />
              <button
                type="button"
                aria-label={
                  revealedRegistration
                    ? "Hide registration number"
                    : "Show registration number"
                }
                onClick={() => setRevealedRegistration((current) => !current)}
                className="absolute right-2 top-1/2 grid size-8 -translate-y-1/2 place-items-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)]"
              >
                <HugeiconsIcon
                  icon={revealedRegistration ? EyeOffIcon : EyeIcon}
                  className="size-4"
                  aria-hidden="true"
                />
              </button>
            </div>
          </Field>
          <Field label="VIN">
            <div className="relative">
              <input
                value={vin}
                type={revealedVin ? "text" : "password"}
                autoComplete="off"
                onChange={(event) => setVin(event.target.value)}
                disabled={!detailReady}
                className="field-input pr-11"
                placeholder="Stored encrypted locally"
              />
              <button
                type="button"
                aria-label={revealedVin ? "Hide VIN" : "Show VIN"}
                onClick={() => setRevealedVin((current) => !current)}
                className="absolute right-2 top-1/2 grid size-8 -translate-y-1/2 place-items-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)]"
              >
                <HugeiconsIcon
                  icon={revealedVin ? EyeOffIcon : EyeIcon}
                  className="size-4"
                  aria-hidden="true"
                />
              </button>
            </div>
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Notes">
            <textarea
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              className="field-input min-h-28 resize-y"
              placeholder="Optional private context"
            />
          </Field>
        </div>
        <EditorFooter
          saving={saving}
          disabled={!title.trim() || !detailReady}
          action={editing ? "Save changes" : "Save vehicle"}
        />
      </form>
    </EditorFrame>
  );
}

function PossessionComposer({
  possession,
  generation,
  isGenerationCurrent,
  onCancel,
  onSaved,
  onError,
}: {
  possession: PossessionView | null;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onCancel: () => void;
  onSaved: (
    possession: PossessionView,
    created: boolean,
    generation: number,
  ) => void;
  onError: (message: string | null) => void;
}) {
  const [title, setTitle] = useState(possession?.title ?? "");
  const [brand, setBrand] = useState(possession?.brand ?? "");
  const [model, setModel] = useState(possession?.model ?? "");
  const [serialNumber, setSerialNumber] = useState("");
  const [purchaseDate, setPurchaseDate] = useState(
    possession?.purchase_date ?? "",
  );
  const [purchasePrice, setPurchasePrice] = useState(
    possession?.purchase_price ?? "",
  );
  const [store, setStore] = useState(possession?.store ?? "");
  const [warrantyExpiry, setWarrantyExpiry] = useState(
    possession?.warranty_expiry ?? "",
  );
  const [notes, setNotes] = useState(possession?.notes ?? "");
  const [revealed, setRevealed] = useState(false);
  const [saving, setSaving] = useState(false);
  const editing = possession !== null;
  const [detailReady, setDetailReady] = useState(!editing);

  useEffect(() => {
    if (!possession) return;
    let active = true;
    void invoke<PossessionDetailView>("get_possession", {
      id: possession.id,
      revision: possession.revision,
    })
      .then((detail) => {
        if (!active || !isGenerationCurrent(generation)) return;
        setSerialNumber(detail.serial_number);
        setDetailReady(true);
      })
      .catch((reason: unknown) => {
        if (active && isGenerationCurrent(generation))
          onError(readError(reason));
      });
    return () => {
      active = false;
    };
  }, [possession, generation, isGenerationCurrent, onError]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!title.trim() || !detailReady) return;
    setSaving(true);
    onError(null);
    try {
      const input = {
        title,
        brand,
        model,
        serialNumber,
        purchaseDate,
        purchasePrice,
        store,
        warrantyExpiry,
        notes,
      };
      const saved = editing
        ? await invoke<PossessionView>("update_possession", {
            id: possession.id,
            revision: possession.revision,
            ...input,
          })
        : await invoke<PossessionView>("create_possession", input);
      setSerialNumber("");
      onSaved(saved, !editing, generation);
    } catch (reason) {
      onError(readError(reason));
    } finally {
      setSaving(false);
    }
  }

  return (
    <EditorFrame
      title={editing ? "Edit possession" : "New possession"}
      onCancel={onCancel}
    >
      <form onSubmit={submit} autoComplete="off">
        <input
          autoFocus
          value={title}
          onChange={(event) => setTitle(event.target.value)}
          placeholder="Laptop, watch, appliance…"
          aria-label="Possession title"
          className="editor-title"
        />
        <div className="mt-8 grid gap-5 sm:grid-cols-2">
          <Field label="Brand">
            <input
              value={brand}
              autoComplete="off"
              onChange={(event) => setBrand(event.target.value)}
              className="field-input"
              placeholder="Apple, Samsung…"
            />
          </Field>
          <Field label="Model">
            <input
              value={model}
              autoComplete="off"
              onChange={(event) => setModel(event.target.value)}
              className="field-input"
              placeholder="Model name or number"
            />
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Serial number">
            <div className="relative">
              <input
                value={serialNumber}
                type={revealed ? "text" : "password"}
                autoComplete="off"
                onChange={(event) => setSerialNumber(event.target.value)}
                disabled={!detailReady}
                className="field-input pr-11"
                placeholder="Stored encrypted locally"
              />
              <button
                type="button"
                aria-label={
                  revealed ? "Hide serial number" : "Show serial number"
                }
                onClick={() => setRevealed((current) => !current)}
                className="absolute right-2 top-1/2 grid size-8 -translate-y-1/2 place-items-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)]"
              >
                <HugeiconsIcon
                  icon={revealed ? EyeOffIcon : EyeIcon}
                  className="size-4"
                  aria-hidden="true"
                />
              </button>
            </div>
          </Field>
        </div>
        <div className="mt-5 grid gap-5 sm:grid-cols-2">
          <Field label="Purchase date">
            <input
              value={purchaseDate}
              type="date"
              autoComplete="off"
              onChange={(event) => setPurchaseDate(event.target.value)}
              className="field-input"
            />
          </Field>
          <Field label="Purchase price">
            <input
              value={purchasePrice}
              autoComplete="off"
              onChange={(event) => setPurchasePrice(event.target.value)}
              className="field-input"
              placeholder="199900"
            />
          </Field>
        </div>
        <div className="mt-5 grid gap-5 sm:grid-cols-2">
          <Field label="Store">
            <input
              value={store}
              autoComplete="off"
              onChange={(event) => setStore(event.target.value)}
              className="field-input"
              placeholder="Where it was purchased"
            />
          </Field>
          <Field label="Warranty expiry">
            <input
              value={warrantyExpiry}
              type="date"
              autoComplete="off"
              onChange={(event) => setWarrantyExpiry(event.target.value)}
              className="field-input"
            />
          </Field>
        </div>
        <div className="mt-5">
          <Field label="Notes">
            <textarea
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              className="field-input min-h-28 resize-y"
              placeholder="Optional private context"
            />
          </Field>
        </div>
        <EditorFooter
          saving={saving}
          disabled={!title.trim() || !detailReady}
          action={editing ? "Save changes" : "Save possession"}
        />
      </form>
    </EditorFrame>
  );
}

function LinkedRecordsSection({
  itemId,
  revision,
  links,
  generation,
  isGenerationCurrent,
  linkedTitles,
  allItems,
  onJump,
  onLinksChanged,
  onError,
}: {
  itemId: string;
  revision: number;
  links: string[];
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onError: (message: string | null) => void;
} & LinkedSectionProps) {
  const [managing, setManaging] = useState(false);
  const [draft, setDraft] = useState<string[]>(links);
  const [saving, setSaving] = useState(false);
  const titleById = new Map(linkedTitles.map((entry) => [entry.id, entry]));
  const candidates = allItems.filter((item) => item.id !== itemId);

  const openManager = () => {
    setDraft(links);
    setManaging(true);
    onError(null);
  };

  const toggleDraft = (id: string) => {
    setDraft((current) =>
      current.includes(id)
        ? current.filter((candidate) => candidate !== id)
        : [...current, id],
    );
  };

  async function saveLinks() {
    if (saving) return;
    setSaving(true);
    onError(null);
    try {
      await invoke<number>("set_item_links", {
        id: itemId,
        revision,
        links: draft,
      });
      if (!isGenerationCurrent(generation)) return;
      setManaging(false);
      onLinksChanged();
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setSaving(false);
    }
  }

  return (
    <div className="mt-8">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
          <HugeiconsIcon
            icon={Link01Icon}
            className="size-4"
            aria-hidden="true"
          />
          Linked records
        </div>
        <button
          type="button"
          onClick={() => {
            if (managing) setManaging(false);
            else openManager();
          }}
          className="rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)]"
        >
          {managing ? "Done" : "Manage links"}
        </button>
      </div>
      {managing ? (
        <div className="mt-3 rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)] p-4">
          {candidates.length === 0 ? (
            <p className="text-sm text-[var(--text-muted)]">
              No other records to link yet.
            </p>
          ) : (
            <div className="space-y-4">
              {groupItemsByKind(candidates, "").map((group) => (
                <div key={group.section}>
                  <div className="text-[11px] font-medium uppercase tracking-[0.1em] text-[var(--text-muted)]">
                    {sectionLabel(group.section)}
                  </div>
                  <div className="mt-2 space-y-1.5">
                    {group.items.map((candidate) => (
                      <label
                        key={candidate.id}
                        className="flex cursor-pointer items-center gap-3 rounded-xl px-2 py-1.5 text-sm transition hover:bg-[var(--selected)]"
                      >
                        <input
                          type="checkbox"
                          checked={draft.includes(candidate.id)}
                          onChange={() => toggleDraft(candidate.id)}
                          className="size-4"
                        />
                        <span className="min-w-0">
                          <span className="block truncate font-medium text-[var(--text-primary)]">
                            {candidate.title}
                          </span>
                          <span className="block text-xs text-[var(--text-muted)]">
                            {sectionLabel(candidate.kind)}
                          </span>
                        </span>
                      </label>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
          <div className="mt-4 flex items-center justify-end gap-2 border-t border-[var(--border)] pt-3">
            <button
              type="button"
              onClick={() => setManaging(false)}
              className="rounded-xl border border-[var(--border)] bg-[var(--surface)] px-4 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => void saveLinks()}
              disabled={saving}
              className="rounded-xl bg-[var(--primary)] px-4 py-2 text-sm font-medium text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
            >
              {saving ? "Saving…" : "Save links"}
            </button>
          </div>
        </div>
      ) : links.length === 0 ? (
        <p className="mt-3 text-sm text-[var(--text-muted)]">
          No linked records yet.
        </p>
      ) : (
        <div className="mt-3 overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)]">
          {links.map((id) => {
            const entry = titleById.get(id);
            if (!entry) {
              return (
                <div
                  key={id}
                  className="grid grid-cols-[140px_minmax(0,1fr)] gap-4 px-5 py-4 [&+&]:border-t [&+&]:border-[var(--border)]"
                >
                  <div className="text-sm text-[var(--text-muted)]">Record</div>
                  <div className="min-w-0 truncate text-sm text-[var(--text-muted)]">
                    Unavailable (moved to Trash or deleted)
                  </div>
                </div>
              );
            }
            return (
              <button
                key={id}
                type="button"
                onClick={() => onJump(entry.kind, entry.id)}
                className="grid w-full grid-cols-[140px_minmax(0,1fr)] gap-4 px-5 py-4 text-left transition hover:bg-[var(--selected)] [&+&]:border-t [&+&]:border-[var(--border)]"
              >
                <div className="text-sm text-[var(--text-muted)]">
                  {kindLabel(entry.kind)}
                </div>
                <div className="min-w-0 truncate text-sm text-[var(--text-primary)]">
                  {entry.title}
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function formatAttachmentSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

function AttachmentsSection({
  ownerItemId,
  revision,
  generation,
  isGenerationCurrent,
  onAttachmentsChanged,
  onError,
}: {
  ownerItemId: string;
  revision: number;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onAttachmentsChanged: () => void;
  onError: (message: string | null) => void;
}) {
  const [attachments, setAttachments] = useState<AttachmentSummary[]>([]);
  const [itemRevision, setItemRevision] = useState(revision);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);
  const [activeAction, setActiveAction] = useState<string | null>(null);

  useEffect(() => {
    setItemRevision(revision);
  }, [revision]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    void invoke<AttachmentSummary[]>("list_attachments", {
      ownerItemId,
    })
      .then((loaded) => {
        if (!active || !isGenerationCurrent(generation)) return;
        setAttachments(loaded);
      })
      .catch((reason: unknown) => {
        if (active && isGenerationCurrent(generation)) {
          onError(readError(reason));
        }
      })
      .finally(() => {
        if (active && isGenerationCurrent(generation)) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [generation, isGenerationCurrent, onError, ownerItemId]);

  async function addAttachment() {
    if (adding || activeAction !== null || attachments.length >= 16) return;
    setAdding(true);
    onError(null);
    try {
      const result = await invoke<AttachmentAddResult | null>(
        "add_attachment",
        {
          ownerItemId,
          expectedItemRevision: itemRevision,
        },
      );
      if (!isGenerationCurrent(generation)) return;
      if (result === null) return;
      setAttachments((current) => [...current, result.attachment]);
      setItemRevision(result.item_revision);
      onAttachmentsChanged();
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setAdding(false);
    }
  }

  async function exportAttachment(attachment: AttachmentSummary) {
    if (adding || activeAction !== null) return;
    setActiveAction(`export:${attachment.id}`);
    onError(null);
    try {
      await invoke<boolean>("export_attachment", {
        ownerItemId,
        attachmentId: attachment.id,
      });
      if (!isGenerationCurrent(generation)) return;
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setActiveAction(null);
    }
  }

  async function deleteAttachment(attachment: AttachmentSummary) {
    if (adding || activeAction !== null) return;
    if (!window.confirm(`Delete ${attachment.filename} permanently?`)) return;
    setActiveAction(`delete:${attachment.id}`);
    onError(null);
    try {
      const nextRevision = await invoke<number>("delete_attachment", {
        ownerItemId,
        attachmentId: attachment.id,
        expectedItemRevision: itemRevision,
        expectedAttachmentRevision: attachment.revision,
      });
      if (!isGenerationCurrent(generation)) return;
      setAttachments((current) =>
        current.filter((candidate) => candidate.id !== attachment.id),
      );
      setItemRevision(nextRevision);
      onAttachmentsChanged();
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setActiveAction(null);
    }
  }

  const busy = adding || activeAction !== null;

  return (
    <div className="mt-8">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
          <HugeiconsIcon
            icon={Attachment01Icon}
            className="size-4"
            aria-hidden="true"
          />
          Attachments
        </div>
        <button
          type="button"
          onClick={() => void addAttachment()}
          disabled={busy || loading || attachments.length >= 16}
          className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
        >
          <HugeiconsIcon
            icon={Add01Icon}
            className="size-4"
            aria-hidden="true"
          />
          {adding
            ? "Adding…"
            : attachments.length >= 16
              ? "Attachment limit reached"
              : "Add attachment"}
        </button>
      </div>
      {loading ? (
        <p className="mt-3 text-sm text-[var(--text-muted)]">
          Loading attachments…
        </p>
      ) : attachments.length === 0 ? (
        <p className="mt-3 text-sm text-[var(--text-muted)]">
          No attachments yet.
        </p>
      ) : (
        <div className="mt-3 overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)]">
          {attachments.map((attachment) => {
            const exporting = activeAction === `export:${attachment.id}`;
            const deleting = activeAction === `delete:${attachment.id}`;
            return (
              <div
                key={attachment.id}
                className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 px-5 py-4 [&+&]:border-t [&+&]:border-[var(--border)]"
              >
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium text-[var(--text-primary)]">
                    {attachment.filename}
                  </div>
                  <div className="mt-0.5 text-xs text-[var(--text-muted)]">
                    {formatAttachmentSize(attachment.plaintext_size)}
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => void exportAttachment(attachment)}
                    disabled={busy}
                    className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
                  >
                    <HugeiconsIcon
                      icon={Download01Icon}
                      className="size-4"
                      aria-hidden="true"
                    />
                    {exporting ? "Saving…" : "Save"}
                  </button>
                  <button
                    type="button"
                    onClick={() => void deleteAttachment(attachment)}
                    disabled={busy}
                    className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs text-[var(--danger)] transition hover:bg-[var(--danger-soft)] disabled:cursor-not-allowed disabled:opacity-55"
                  >
                    <HugeiconsIcon
                      icon={Delete02Icon}
                      className="size-4"
                      aria-hidden="true"
                    />
                    {deleting ? "Deleting…" : "Delete"}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
function NoteReader({
  note,
  generation,
  isGenerationCurrent,
  linkedTitles,
  allItems,
  onJump,
  onLinksChanged,
  onEdit,
  onError,
}: {
  note: NoteView;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onEdit: () => void;
  onError: (message: string | null) => void;
} & LinkedSectionProps) {
  return (
    <article className="mx-auto max-w-3xl px-8 py-12">
      <ReaderHeader icon={FileTextIcon} label="Secure note" onEdit={onEdit} />
      <h1 className="text-3xl font-semibold tracking-[-0.035em]">
        {note.title}
      </h1>
      <div className="mt-8 whitespace-pre-wrap text-[15px] leading-7 text-[var(--text-secondary)]">
        {note.body || (
          <span className="text-[var(--text-muted)]">This note is empty.</span>
        )}
      </div>
      <AttachmentsSection
        key={note.id}
        ownerItemId={note.id}
        revision={note.revision}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        onAttachmentsChanged={onLinksChanged}
        onError={onError}
      />
      <LinkedRecordsSection
        itemId={note.id}
        revision={note.revision}
        links={note.links ?? []}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        linkedTitles={linkedTitles}
        allItems={allItems}
        onJump={onJump}
        onLinksChanged={onLinksChanged}
        onError={onError}
      />
    </article>
  );
}

function CredentialReader({
  credential,
  generation,
  isGenerationCurrent,
  linkedTitles,
  allItems,
  onJump,
  onLinksChanged,
  onEdit,
  onError,
}: {
  credential: CredentialView;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onEdit: () => void;
  onError: (message: string | null) => void;
} & LinkedSectionProps) {
  const [password, setPassword] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [loadingSecret, setLoadingSecret] = useState(false);
  const [copyingPassword, setCopyingPassword] = useState(false);
  const [copyNotice, setCopyNotice] = useState<string | null>(null);
  const copyNoticeTimeout = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyNoticeTimeout.current !== null) {
        window.clearTimeout(copyNoticeTimeout.current);
      }
    };
  }, []);

  async function togglePassword() {
    if (revealed) {
      setRevealed(false);
      setPassword(null);
      return;
    }
    if (!credential.has_password || loadingSecret) return;

    setLoadingSecret(true);
    onError(null);
    try {
      const detail = await invoke<CredentialDetailView>("get_credential", {
        id: credential.id,
        revision: credential.revision,
      });
      if (!isGenerationCurrent(generation)) return;
      setPassword(detail.password);
      setRevealed(true);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setLoadingSecret(false);
    }
  }

  async function copyPassword() {
    if (!credential.has_password || copyingPassword) return;

    setCopyingPassword(true);
    setCopyNotice(null);
    onError(null);
    try {
      const result = await invoke<{ clears_in_seconds: number }>(
        "copy_credential_password",
        {
          id: credential.id,
          revision: credential.revision,
        },
      );
      if (!isGenerationCurrent(generation)) return;
      setCopyNotice(`Copied · clears in ${result.clears_in_seconds}s`);
      if (copyNoticeTimeout.current !== null) {
        window.clearTimeout(copyNoticeTimeout.current);
      }
      copyNoticeTimeout.current = window.setTimeout(() => {
        if (isGenerationCurrent(generation)) setCopyNotice(null);
      }, 5_000);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setCopyingPassword(false);
    }
  }

  return (
    <article className="mx-auto max-w-3xl px-8 py-12">
      <ReaderHeader icon={Key01Icon} label="Credential" onEdit={onEdit} />
      <h1 className="text-3xl font-semibold tracking-[-0.035em]">
        {credential.title}
      </h1>
      <div className="mt-8 overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)]">
        <CredentialRow
          label="Username"
          value={credential.username || "Not set"}
        />
        <CredentialRow
          label="Website"
          value={credential.website || "Not set"}
        />
        <div className="grid grid-cols-[140px_minmax(0,1fr)_auto] items-center gap-4 border-t border-[var(--border)] px-5 py-4">
          <div className="text-sm text-[var(--text-muted)]">Password</div>
          <div
            className={`min-w-0 truncate font-mono text-sm ${
              credential.has_password
                ? "text-[var(--text-primary)]"
                : "text-[var(--text-muted)]"
            }`}
          >
            {credential.has_password
              ? revealed && password !== null
                ? password
                : "••••••••••••"
              : "Not set"}
          </div>
          {credential.has_password ? (
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => void copyPassword()}
                disabled={copyingPassword}
                className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
              >
                <HugeiconsIcon
                  icon={Copy01Icon}
                  className="size-4"
                  aria-hidden="true"
                />
                {copyingPassword ? "Copying…" : "Copy"}
              </button>
              <button
                type="button"
                onClick={() => void togglePassword()}
                disabled={loadingSecret}
                className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
              >
                <HugeiconsIcon
                  icon={revealed ? EyeOffIcon : EyeIcon}
                  className="size-4"
                  aria-hidden="true"
                />
                {loadingSecret ? "Opening…" : revealed ? "Hide" : "Reveal"}
              </button>
            </div>
          ) : null}
        </div>
      </div>
      {credential.notes ? (
        <div className="mt-8">
          <div className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
            Notes
          </div>
          <div className="mt-3 whitespace-pre-wrap text-[15px] leading-7 text-[var(--text-secondary)]">
            {credential.notes}
          </div>
        </div>
      ) : null}
      <p className="mt-8 text-xs leading-5 text-[var(--text-muted)]">
        {copyNotice ??
          "Best effort: Safeory ownership-checks copied passwords before clearing after 30 seconds. Clipboard history and OS clipboard behavior may still retain copied values."}
      </p>
      <AttachmentsSection
        key={credential.id}
        ownerItemId={credential.id}
        revision={credential.revision}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        onAttachmentsChanged={onLinksChanged}
        onError={onError}
      />
      <LinkedRecordsSection
        itemId={credential.id}
        revision={credential.revision}
        links={credential.links ?? []}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        linkedTitles={linkedTitles}
        allItems={allItems}
        onJump={onJump}
        onLinksChanged={onLinksChanged}
        onError={onError}
      />
    </article>
  );
}

function DocumentReader({
  document,
  generation,
  isGenerationCurrent,
  linkedTitles,
  allItems,
  onJump,
  onLinksChanged,
  onEdit,
  onError,
}: {
  document: DocumentView;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onEdit: () => void;
  onError: (message: string | null) => void;
} & LinkedSectionProps) {
  const [documentNumber, setDocumentNumber] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [loadingSecret, setLoadingSecret] = useState(false);

  async function toggleDocumentNumber() {
    if (revealed) {
      setRevealed(false);
      setDocumentNumber(null);
      return;
    }
    if (!document.has_document_number || loadingSecret) return;

    setLoadingSecret(true);
    onError(null);
    try {
      const detail = await invoke<DocumentDetailView>("get_document", {
        id: document.id,
        revision: document.revision,
      });
      if (!isGenerationCurrent(generation)) return;
      setDocumentNumber(detail.document_number);
      setRevealed(true);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setLoadingSecret(false);
    }
  }

  return (
    <article className="mx-auto max-w-3xl px-8 py-12">
      <ReaderHeader
        icon={DocumentValidationIcon}
        label="Document"
        onEdit={onEdit}
      />
      <h1 className="text-3xl font-semibold tracking-[-0.035em]">
        {document.title}
      </h1>
      <div className="mt-8 overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)]">
        <CredentialRow label="Issuer" value={document.issuer || "Not set"} />
        <CredentialRow label="Expiry" value={document.expiry || "Not set"} />
        <div className="grid grid-cols-[140px_minmax(0,1fr)_auto] items-center gap-4 border-t border-[var(--border)] px-5 py-4">
          <div className="text-sm text-[var(--text-muted)]">
            Document number
          </div>
          <div
            className={`min-w-0 truncate font-mono text-sm ${
              document.has_document_number
                ? "text-[var(--text-primary)]"
                : "text-[var(--text-muted)]"
            }`}
          >
            {document.has_document_number
              ? revealed && documentNumber !== null
                ? documentNumber
                : "••••••••••••"
              : "Not set"}
          </div>
          {document.has_document_number ? (
            <button
              type="button"
              onClick={() => void toggleDocumentNumber()}
              disabled={loadingSecret}
              className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={revealed ? EyeOffIcon : EyeIcon}
                className="size-4"
                aria-hidden="true"
              />
              {loadingSecret ? "Opening…" : revealed ? "Hide" : "Reveal"}
            </button>
          ) : null}
        </div>
      </div>
      {document.notes ? (
        <div className="mt-8">
          <div className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
            Notes
          </div>
          <div className="mt-3 whitespace-pre-wrap text-[15px] leading-7 text-[var(--text-secondary)]">
            {document.notes}
          </div>
        </div>
      ) : null}
      <AttachmentsSection
        key={document.id}
        ownerItemId={document.id}
        revision={document.revision}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        onAttachmentsChanged={onLinksChanged}
        onError={onError}
      />
      <LinkedRecordsSection
        itemId={document.id}
        revision={document.revision}
        links={document.links ?? []}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        linkedTitles={linkedTitles}
        allItems={allItems}
        onJump={onJump}
        onLinksChanged={onLinksChanged}
        onError={onError}
      />
    </article>
  );
}

function ReceiptReader({
  receipt,
  generation,
  isGenerationCurrent,
  linkedTitles,
  allItems,
  onJump,
  onLinksChanged,
  onEdit,
  onError,
}: {
  receipt: ReceiptView;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onEdit: () => void;
  onError: (message: string | null) => void;
} & LinkedSectionProps) {
  const [receiptReference, setReceiptReference] = useState<string | null>(null);
  const [notes, setNotes] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [loadingSecret, setLoadingSecret] = useState(false);

  useEffect(() => {
    let active = true;
    void invoke<string>("get_receipt_notes", {
      id: receipt.id,
      revision: receipt.revision,
    })
      .then((value) => {
        if (active && isGenerationCurrent(generation)) setNotes(value);
      })
      .catch((reason: unknown) => {
        if (active && isGenerationCurrent(generation))
          onError(readError(reason));
      });
    return () => {
      active = false;
    };
  }, [receipt.id, receipt.revision, generation, isGenerationCurrent, onError]);

  async function toggleReceiptReference() {
    if (revealed) {
      setRevealed(false);
      setReceiptReference(null);
      return;
    }
    if (!receipt.has_receipt_reference || loadingSecret) return;
    setLoadingSecret(true);
    onError(null);
    try {
      const value = await invoke<string>("reveal_receipt_reference", {
        id: receipt.id,
        revision: receipt.revision,
      });
      if (!isGenerationCurrent(generation)) return;
      setReceiptReference(value);
      setRevealed(true);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setLoadingSecret(false);
    }
  }

  return (
    <article className="mx-auto max-w-3xl px-8 py-12">
      <ReaderHeader icon={FileTextIcon} label="Receipt" onEdit={onEdit} />
      <h1 className="text-3xl font-semibold tracking-[-0.035em]">
        {receipt.title}
      </h1>
      <div className="mt-8 overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)]">
        <CredentialRow label="Merchant" value={receipt.merchant || "Not set"} />
        <CredentialRow
          label="Purchase date"
          value={receipt.purchase_date || "Not set"}
        />
        <CredentialRow
          label="Amount"
          value={
            receipt.amount
              ? `${receipt.amount}${receipt.currency ? ` ${receipt.currency}` : ""}`
              : "Not set"
          }
        />
        <CredentialRow
          label="Status"
          value={receiptTrackingLabel(receipt.tracking_status)}
        />
        <CredentialRow
          label="Return by"
          value={receipt.return_by || "Not set"}
        />
        <CredentialRow
          label="Refund due"
          value={receipt.refund_due || "Not set"}
        />
        <div className="grid grid-cols-[140px_minmax(0,1fr)_auto] items-center gap-4 border-t border-[var(--border)] px-5 py-4">
          <div className="text-sm text-[var(--text-muted)]">
            Receipt reference
          </div>
          <div
            className={`min-w-0 truncate font-mono text-sm ${
              receipt.has_receipt_reference
                ? "text-[var(--text-primary)]"
                : "text-[var(--text-muted)]"
            }`}
          >
            {receipt.has_receipt_reference
              ? revealed && receiptReference !== null
                ? receiptReference
                : "••••••••••••"
              : "Not set"}
          </div>
          {receipt.has_receipt_reference ? (
            <button
              type="button"
              onClick={() => void toggleReceiptReference()}
              disabled={loadingSecret}
              className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={revealed ? EyeOffIcon : EyeIcon}
                className="size-4"
                aria-hidden="true"
              />
              {loadingSecret ? "Opening…" : revealed ? "Hide" : "Reveal"}
            </button>
          ) : null}
        </div>
      </div>
      {notes ? (
        <div className="mt-8">
          <div className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
            Notes
          </div>
          <div className="mt-3 whitespace-pre-wrap text-[15px] leading-7 text-[var(--text-secondary)]">
            {notes}
          </div>
        </div>
      ) : null}
      <p className="mt-8 text-xs leading-5 text-[var(--text-muted)]">
        Receipt references and notes stay out of list and search state and are
        fetched only inside this receipt view.
      </p>
      <AttachmentsSection
        key={receipt.id}
        ownerItemId={receipt.id}
        revision={receipt.revision}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        onAttachmentsChanged={onLinksChanged}
        onError={onError}
      />
      <LinkedRecordsSection
        itemId={receipt.id}
        revision={receipt.revision}
        links={receipt.links ?? []}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        linkedTitles={linkedTitles}
        allItems={allItems}
        onJump={onJump}
        onLinksChanged={onLinksChanged}
        onError={onError}
      />
    </article>
  );
}

function InsuranceReader({
  insurance,
  generation,
  isGenerationCurrent,
  linkedTitles,
  allItems,
  onJump,
  onLinksChanged,
  onEdit,
  onError,
}: {
  insurance: InsuranceView;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onEdit: () => void;
  onError: (message: string | null) => void;
} & LinkedSectionProps) {
  const [policyNumber, setPolicyNumber] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [loadingSecret, setLoadingSecret] = useState(false);

  async function togglePolicyNumber() {
    if (revealed) {
      setRevealed(false);
      setPolicyNumber(null);
      return;
    }
    if (!insurance.has_policy_number || loadingSecret) return;

    setLoadingSecret(true);
    onError(null);
    try {
      const detail = await invoke<InsuranceDetailView>("get_insurance", {
        id: insurance.id,
        revision: insurance.revision,
      });
      if (!isGenerationCurrent(generation)) return;
      setPolicyNumber(detail.policy_number);
      setRevealed(true);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setLoadingSecret(false);
    }
  }

  return (
    <article className="mx-auto max-w-3xl px-8 py-12">
      <ReaderHeader icon={ShieldCheckIcon} label="Insurance" onEdit={onEdit} />
      <h1 className="text-3xl font-semibold tracking-[-0.035em]">
        {insurance.title}
      </h1>
      <div className="mt-8 overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)]">
        <CredentialRow
          label="Provider"
          value={insurance.provider || "Not set"}
        />
        <CredentialRow
          label="Policy type"
          value={insurance.policy_type || "Not set"}
        />
        <CredentialRow label="Renewal" value={insurance.renewal || "Not set"} />
        <div className="grid grid-cols-[140px_minmax(0,1fr)_auto] items-center gap-4 border-t border-[var(--border)] px-5 py-4">
          <div className="text-sm text-[var(--text-muted)]">Policy number</div>
          <div
            className={`min-w-0 truncate font-mono text-sm ${
              insurance.has_policy_number
                ? "text-[var(--text-primary)]"
                : "text-[var(--text-muted)]"
            }`}
          >
            {insurance.has_policy_number
              ? revealed && policyNumber !== null
                ? policyNumber
                : "••••••••••••"
              : "Not set"}
          </div>
          {insurance.has_policy_number ? (
            <button
              type="button"
              onClick={() => void togglePolicyNumber()}
              disabled={loadingSecret}
              className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={revealed ? EyeOffIcon : EyeIcon}
                className="size-4"
                aria-hidden="true"
              />
              {loadingSecret ? "Opening…" : revealed ? "Hide" : "Reveal"}
            </button>
          ) : null}
        </div>
      </div>
      {insurance.notes ? (
        <div className="mt-8">
          <div className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
            Notes
          </div>
          <div className="mt-3 whitespace-pre-wrap text-[15px] leading-7 text-[var(--text-secondary)]">
            {insurance.notes}
          </div>
        </div>
      ) : null}
      <AttachmentsSection
        key={insurance.id}
        ownerItemId={insurance.id}
        revision={insurance.revision}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        onAttachmentsChanged={onLinksChanged}
        onError={onError}
      />
      <LinkedRecordsSection
        itemId={insurance.id}
        revision={insurance.revision}
        links={insurance.links ?? []}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        linkedTitles={linkedTitles}
        allItems={allItems}
        onJump={onJump}
        onLinksChanged={onLinksChanged}
        onError={onError}
      />
    </article>
  );
}

function FinancialReader({
  financial,
  generation,
  isGenerationCurrent,
  linkedTitles,
  allItems,
  onJump,
  onLinksChanged,
  onEdit,
  onError,
}: {
  financial: FinancialView;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onEdit: () => void;
  onError: (message: string | null) => void;
} & LinkedSectionProps) {
  const [accountNumber, setAccountNumber] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [loadingSecret, setLoadingSecret] = useState(false);

  async function toggleAccountNumber() {
    if (revealed) {
      setRevealed(false);
      setAccountNumber(null);
      return;
    }
    if (!financial.has_account_number || loadingSecret) return;

    setLoadingSecret(true);
    onError(null);
    try {
      const value = await invoke<string>("reveal_financial_account_number", {
        id: financial.id,
        revision: financial.revision,
      });
      if (!isGenerationCurrent(generation)) return;
      setAccountNumber(value);
      setRevealed(true);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setLoadingSecret(false);
    }
  }

  return (
    <article className="mx-auto max-w-3xl px-8 py-12">
      <ReaderHeader icon={BankIcon} label="Financial" onEdit={onEdit} />
      <h1 className="text-3xl font-semibold tracking-[-0.035em]">
        {financial.title}
      </h1>
      <div className="mt-8 overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)]">
        <CredentialRow
          label="Institution"
          value={financial.institution || "Not set"}
        />
        <CredentialRow
          label="Account type"
          value={financial.account_type || "Not set"}
        />
        <CredentialRow
          label="Currency"
          value={financial.currency || "Not set"}
        />
        <div className="grid grid-cols-[140px_minmax(0,1fr)_auto] items-center gap-4 border-t border-[var(--border)] px-5 py-4">
          <div className="text-sm text-[var(--text-muted)]">Account number</div>
          <div
            className={`min-w-0 truncate font-mono text-sm ${
              financial.has_account_number
                ? "text-[var(--text-primary)]"
                : "text-[var(--text-muted)]"
            }`}
          >
            {financial.has_account_number
              ? revealed && accountNumber !== null
                ? accountNumber
                : "••••••••••••"
              : "Not set"}
          </div>
          {financial.has_account_number ? (
            <button
              type="button"
              onClick={() => void toggleAccountNumber()}
              disabled={loadingSecret}
              className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={revealed ? EyeOffIcon : EyeIcon}
                className="size-4"
                aria-hidden="true"
              />
              {loadingSecret ? "Opening…" : revealed ? "Hide" : "Reveal"}
            </button>
          ) : null}
        </div>
      </div>
      <p className="mt-8 text-xs leading-5 text-[var(--text-muted)]">
        Account numbers are excluded from list and search state and are fetched
        only when you reveal them.
      </p>
      <AttachmentsSection
        key={financial.id}
        ownerItemId={financial.id}
        revision={financial.revision}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        onAttachmentsChanged={onLinksChanged}
        onError={onError}
      />
      <LinkedRecordsSection
        itemId={financial.id}
        revision={financial.revision}
        links={financial.links ?? []}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        linkedTitles={linkedTitles}
        allItems={allItems}
        onJump={onJump}
        onLinksChanged={onLinksChanged}
        onError={onError}
      />
    </article>
  );
}

function PropertyReader({
  property,
  generation,
  isGenerationCurrent,
  linkedTitles,
  allItems,
  onJump,
  onLinksChanged,
  onEdit,
  onError,
}: {
  property: PropertyView;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onEdit: () => void;
  onError: (message: string | null) => void;
} & LinkedSectionProps) {
  const [address, setAddress] = useState<string | null>(null);
  const [propertyReference, setPropertyReference] = useState<string | null>(
    null,
  );
  const [addressRevealed, setAddressRevealed] = useState(false);
  const [referenceRevealed, setReferenceRevealed] = useState(false);
  const [loadingAddress, setLoadingAddress] = useState(false);
  const [loadingReference, setLoadingReference] = useState(false);

  async function toggleAddress() {
    if (addressRevealed) {
      setAddressRevealed(false);
      setAddress(null);
      return;
    }
    if (!property.has_address || loadingAddress) return;
    setLoadingAddress(true);
    onError(null);
    try {
      const value = await invoke<string>("reveal_property_address", {
        id: property.id,
        revision: property.revision,
      });
      if (!isGenerationCurrent(generation)) return;
      setAddress(value);
      setAddressRevealed(true);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setLoadingAddress(false);
    }
  }

  async function toggleReference() {
    if (referenceRevealed) {
      setReferenceRevealed(false);
      setPropertyReference(null);
      return;
    }
    if (!property.has_property_reference || loadingReference) return;
    setLoadingReference(true);
    onError(null);
    try {
      const value = await invoke<string>("reveal_property_reference", {
        id: property.id,
        revision: property.revision,
      });
      if (!isGenerationCurrent(generation)) return;
      setPropertyReference(value);
      setReferenceRevealed(true);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setLoadingReference(false);
    }
  }

  return (
    <article className="mx-auto max-w-3xl px-8 py-12">
      <ReaderHeader icon={Building03Icon} label="Property" onEdit={onEdit} />
      <h1 className="text-3xl font-semibold tracking-[-0.035em]">
        {property.title}
      </h1>
      <div className="mt-8 overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)]">
        <CredentialRow
          label="Property type"
          value={property.property_type || "Not set"}
        />
        <CredentialRow
          label="Ownership"
          value={property.ownership || "Not set"}
        />
        <div className="grid grid-cols-[140px_minmax(0,1fr)_auto] items-center gap-4 border-t border-[var(--border)] px-5 py-4">
          <div className="text-sm text-[var(--text-muted)]">Address</div>
          <div className="min-w-0 whitespace-pre-wrap text-sm text-[var(--text-primary)]">
            {property.has_address
              ? addressRevealed && address !== null
                ? address
                : "Hidden"
              : "Not set"}
          </div>
          {property.has_address ? (
            <button
              type="button"
              onClick={() => void toggleAddress()}
              disabled={loadingAddress}
              className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={addressRevealed ? EyeOffIcon : EyeIcon}
                className="size-4"
                aria-hidden="true"
              />
              {loadingAddress
                ? "Opening…"
                : addressRevealed
                  ? "Hide"
                  : "Reveal"}
            </button>
          ) : null}
        </div>
        <div className="grid grid-cols-[140px_minmax(0,1fr)_auto] items-center gap-4 border-t border-[var(--border)] px-5 py-4">
          <div className="text-sm text-[var(--text-muted)]">
            Property reference
          </div>
          <div
            className={`min-w-0 truncate font-mono text-sm ${
              property.has_property_reference
                ? "text-[var(--text-primary)]"
                : "text-[var(--text-muted)]"
            }`}
          >
            {property.has_property_reference
              ? referenceRevealed && propertyReference !== null
                ? propertyReference
                : "••••••••••••"
              : "Not set"}
          </div>
          {property.has_property_reference ? (
            <button
              type="button"
              onClick={() => void toggleReference()}
              disabled={loadingReference}
              className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={referenceRevealed ? EyeOffIcon : EyeIcon}
                className="size-4"
                aria-hidden="true"
              />
              {loadingReference
                ? "Opening…"
                : referenceRevealed
                  ? "Hide"
                  : "Reveal"}
            </button>
          ) : null}
        </div>
      </div>
      <p className="mt-8 text-xs leading-5 text-[var(--text-muted)]">
        Addresses and property references stay out of list and search state and
        are fetched only on explicit reveal.
      </p>
      <AttachmentsSection
        key={property.id}
        ownerItemId={property.id}
        revision={property.revision}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        onAttachmentsChanged={onLinksChanged}
        onError={onError}
      />
      <LinkedRecordsSection
        itemId={property.id}
        revision={property.revision}
        links={property.links ?? []}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        linkedTitles={linkedTitles}
        allItems={allItems}
        onJump={onJump}
        onLinksChanged={onLinksChanged}
        onError={onError}
      />
    </article>
  );
}

function VehicleReader({
  vehicle,
  generation,
  isGenerationCurrent,
  linkedTitles,
  allItems,
  onJump,
  onLinksChanged,
  onEdit,
  onError,
}: {
  vehicle: VehicleView;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onEdit: () => void;
  onError: (message: string | null) => void;
} & LinkedSectionProps) {
  const [registrationNumber, setRegistrationNumber] = useState<string | null>(
    null,
  );
  const [vin, setVin] = useState<string | null>(null);
  const [registrationRevealed, setRegistrationRevealed] = useState(false);
  const [vinRevealed, setVinRevealed] = useState(false);
  const [loadingRegistration, setLoadingRegistration] = useState(false);
  const [loadingVin, setLoadingVin] = useState(false);

  async function fetchDetail() {
    const detail = await invoke<VehicleDetailView>("get_vehicle", {
      id: vehicle.id,
      revision: vehicle.revision,
    });
    return detail;
  }

  async function toggleRegistration() {
    if (registrationRevealed) {
      setRegistrationRevealed(false);
      setRegistrationNumber(null);
      return;
    }
    if (!vehicle.has_registration_number || loadingRegistration) return;
    setLoadingRegistration(true);
    onError(null);
    try {
      const detail = await fetchDetail();
      if (!isGenerationCurrent(generation)) return;
      setRegistrationNumber(detail.registration_number);
      setRegistrationRevealed(true);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setLoadingRegistration(false);
    }
  }

  async function toggleVin() {
    if (vinRevealed) {
      setVinRevealed(false);
      setVin(null);
      return;
    }
    if (!vehicle.has_vin || loadingVin) return;
    setLoadingVin(true);
    onError(null);
    try {
      const detail = await fetchDetail();
      if (!isGenerationCurrent(generation)) return;
      setVin(detail.vin);
      setVinRevealed(true);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setLoadingVin(false);
    }
  }

  return (
    <article className="mx-auto max-w-3xl px-8 py-12">
      <ReaderHeader icon={Car01Icon} label="Vehicle" onEdit={onEdit} />
      <h1 className="text-3xl font-semibold tracking-[-0.035em]">
        {vehicle.title}
      </h1>
      <div className="mt-8 overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)]">
        <CredentialRow label="Make" value={vehicle.make || "Not set"} />
        <CredentialRow label="Model" value={vehicle.model || "Not set"} />
        <CredentialRow label="Year" value={vehicle.year || "Not set"} />
        <CredentialRow label="Renewal" value={vehicle.renewal || "Not set"} />
        <div className="grid grid-cols-[140px_minmax(0,1fr)_auto] items-center gap-4 border-t border-[var(--border)] px-5 py-4">
          <div className="text-sm text-[var(--text-muted)]">
            Registration number
          </div>
          <div
            className={`min-w-0 truncate font-mono text-sm ${
              vehicle.has_registration_number
                ? "text-[var(--text-primary)]"
                : "text-[var(--text-muted)]"
            }`}
          >
            {vehicle.has_registration_number
              ? registrationRevealed && registrationNumber !== null
                ? registrationNumber
                : "••••••••••••"
              : "Not set"}
          </div>
          {vehicle.has_registration_number ? (
            <button
              type="button"
              onClick={() => void toggleRegistration()}
              disabled={loadingRegistration}
              className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={registrationRevealed ? EyeOffIcon : EyeIcon}
                className="size-4"
                aria-hidden="true"
              />
              {loadingRegistration
                ? "Opening…"
                : registrationRevealed
                  ? "Hide"
                  : "Reveal"}
            </button>
          ) : null}
        </div>
        <div className="grid grid-cols-[140px_minmax(0,1fr)_auto] items-center gap-4 border-t border-[var(--border)] px-5 py-4">
          <div className="text-sm text-[var(--text-muted)]">VIN</div>
          <div
            className={`min-w-0 truncate font-mono text-sm ${
              vehicle.has_vin
                ? "text-[var(--text-primary)]"
                : "text-[var(--text-muted)]"
            }`}
          >
            {vehicle.has_vin
              ? vinRevealed && vin !== null
                ? vin
                : "••••••••••••"
              : "Not set"}
          </div>
          {vehicle.has_vin ? (
            <button
              type="button"
              onClick={() => void toggleVin()}
              disabled={loadingVin}
              className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={vinRevealed ? EyeOffIcon : EyeIcon}
                className="size-4"
                aria-hidden="true"
              />
              {loadingVin ? "Opening…" : vinRevealed ? "Hide" : "Reveal"}
            </button>
          ) : null}
        </div>
      </div>
      {vehicle.notes ? (
        <div className="mt-8">
          <div className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
            Notes
          </div>
          <div className="mt-3 whitespace-pre-wrap text-[15px] leading-7 text-[var(--text-secondary)]">
            {vehicle.notes}
          </div>
        </div>
      ) : null}
      <AttachmentsSection
        key={vehicle.id}
        ownerItemId={vehicle.id}
        revision={vehicle.revision}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        onAttachmentsChanged={onLinksChanged}
        onError={onError}
      />
      <LinkedRecordsSection
        itemId={vehicle.id}
        revision={vehicle.revision}
        links={vehicle.links ?? []}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        linkedTitles={linkedTitles}
        allItems={allItems}
        onJump={onJump}
        onLinksChanged={onLinksChanged}
        onError={onError}
      />
    </article>
  );
}

function PossessionReader({
  possession,
  generation,
  isGenerationCurrent,
  linkedTitles,
  allItems,
  onJump,
  onLinksChanged,
  onEdit,
  onError,
}: {
  possession: PossessionView;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
  onEdit: () => void;
  onError: (message: string | null) => void;
} & LinkedSectionProps) {
  const [serialNumber, setSerialNumber] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [loadingSecret, setLoadingSecret] = useState(false);

  async function toggleSerialNumber() {
    if (revealed) {
      setRevealed(false);
      setSerialNumber(null);
      return;
    }
    if (!possession.has_serial_number || loadingSecret) return;

    setLoadingSecret(true);
    onError(null);
    try {
      const detail = await invoke<PossessionDetailView>("get_possession", {
        id: possession.id,
        revision: possession.revision,
      });
      if (!isGenerationCurrent(generation)) return;
      setSerialNumber(detail.serial_number);
      setRevealed(true);
    } catch (reason) {
      if (isGenerationCurrent(generation)) onError(readError(reason));
    } finally {
      if (isGenerationCurrent(generation)) setLoadingSecret(false);
    }
  }

  return (
    <article className="mx-auto max-w-3xl px-8 py-12">
      <ReaderHeader icon={PackageIcon} label="Possession" onEdit={onEdit} />
      <h1 className="text-3xl font-semibold tracking-[-0.035em]">
        {possession.title}
      </h1>
      <div className="mt-8 overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)]">
        <CredentialRow label="Brand" value={possession.brand || "Not set"} />
        <CredentialRow label="Model" value={possession.model || "Not set"} />
        <CredentialRow
          label="Purchase date"
          value={possession.purchase_date || "Not set"}
        />
        <CredentialRow
          label="Purchase price"
          value={possession.purchase_price || "Not set"}
        />
        <CredentialRow label="Store" value={possession.store || "Not set"} />
        <CredentialRow
          label="Warranty expiry"
          value={possession.warranty_expiry || "Not set"}
        />
        <div className="grid grid-cols-[140px_minmax(0,1fr)_auto] items-center gap-4 border-t border-[var(--border)] px-5 py-4">
          <div className="text-sm text-[var(--text-muted)]">Serial number</div>
          <div
            className={`min-w-0 truncate font-mono text-sm ${
              possession.has_serial_number
                ? "text-[var(--text-primary)]"
                : "text-[var(--text-muted)]"
            }`}
          >
            {possession.has_serial_number
              ? revealed && serialNumber !== null
                ? serialNumber
                : "••••••••••••"
              : "Not set"}
          </div>
          {possession.has_serial_number ? (
            <button
              type="button"
              onClick={() => void toggleSerialNumber()}
              disabled={loadingSecret}
              className="flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-muted)] transition hover:bg-[var(--selected)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-55"
            >
              <HugeiconsIcon
                icon={revealed ? EyeOffIcon : EyeIcon}
                className="size-4"
                aria-hidden="true"
              />
              {loadingSecret ? "Opening…" : revealed ? "Hide" : "Reveal"}
            </button>
          ) : null}
        </div>
      </div>
      {possession.notes ? (
        <div className="mt-8">
          <div className="text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
            Notes
          </div>
          <div className="mt-3 whitespace-pre-wrap text-[15px] leading-7 text-[var(--text-secondary)]">
            {possession.notes}
          </div>
        </div>
      ) : null}
      <AttachmentsSection
        key={possession.id}
        ownerItemId={possession.id}
        revision={possession.revision}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        onAttachmentsChanged={onLinksChanged}
        onError={onError}
      />
      <LinkedRecordsSection
        itemId={possession.id}
        revision={possession.revision}
        links={possession.links ?? []}
        generation={generation}
        isGenerationCurrent={isGenerationCurrent}
        linkedTitles={linkedTitles}
        allItems={allItems}
        onJump={onJump}
        onLinksChanged={onLinksChanged}
        onError={onError}
      />
    </article>
  );
}

function ReaderHeader({
  icon,
  label,
  onEdit,
}: {
  icon: Parameters<typeof HugeiconsIcon>[0]["icon"];
  label: string;
  onEdit: () => void;
}) {
  return (
    <div className="mb-5 flex items-center justify-between">
      <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
        <HugeiconsIcon icon={icon} className="size-4" aria-hidden="true" />
        {label}
      </div>
      <button
        type="button"
        onClick={onEdit}
        className="flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
      >
        <HugeiconsIcon
          icon={FileEditIcon}
          className="size-4"
          aria-hidden="true"
        />
        Edit
      </button>
    </div>
  );
}

function CredentialRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[140px_minmax(0,1fr)] gap-4 px-5 py-4 first:border-0 [&+&]:border-t [&+&]:border-[var(--border)]">
      <div className="text-sm text-[var(--text-muted)]">{label}</div>
      <div className="min-w-0 truncate text-sm text-[var(--text-primary)]">
        {value}
      </div>
    </div>
  );
}

function EditorFrame({
  title,
  onCancel,
  children,
}: {
  title: string;
  onCancel: () => void;
  children: React.ReactNode;
}) {
  return (
    <div className="mx-auto max-w-3xl px-8 py-10">
      <button
        type="button"
        onClick={onCancel}
        className="mb-8 flex items-center gap-2 text-sm text-[var(--text-muted)] transition hover:text-[var(--text-primary)]"
      >
        <HugeiconsIcon
          icon={ArrowLeft01Icon}
          className="size-4"
          aria-hidden="true"
        />
        Back to vault
      </button>
      <div className="mb-2 text-xs font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
        {title}
      </div>
      {children}
    </div>
  );
}

function EditorFooter({
  saving,
  disabled,
  action,
}: {
  saving: boolean;
  disabled: boolean;
  action: string;
}) {
  return (
    <div className="mt-7 flex items-center justify-between border-t border-[var(--border)] pt-5">
      <span className="text-xs text-[var(--text-muted)]">
        Encrypted before it reaches SQLite.
      </span>
      <button
        type="submit"
        disabled={disabled || saving}
        className="rounded-xl bg-[var(--primary)] px-4 py-2.5 text-sm font-medium text-white transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-55"
      >
        {saving ? "Saving…" : action}
      </button>
    </div>
  );
}

function TodayPanel({
  items,
  deadlines,
}: {
  items: VaultItem[];
  deadlines: TodayEntry[] | null;
}) {
  // IPC-backed deadlines when available; the local parse below is the advisory
  // fallback used while loading or when list_deadlines fails.
  const entries = deadlines ?? collectTodayEntries(items);
  if (entries.length === 0) return null;
  return (
    <section
      aria-label="Today"
      className="mb-8 rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)] p-4"
    >
      <div className="flex flex-wrap items-end justify-between gap-3 px-1">
        <div>
          <div className="text-[11px] font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
            Today
          </div>
          <h2 className="mt-1 text-lg font-semibold tracking-[-0.02em]">
            Upcoming renewals &amp; expiries
          </h2>
        </div>
        <p className="text-xs text-[var(--text-muted)]">
          {entries.length} {entries.length === 1 ? "date" : "dates"} to watch
        </p>
      </div>
      <div className="mt-4 grid gap-2">
        {entries.map((entry) => {
          const overdue = entry.daysUntil < 0;
          const dueSoon = entry.daysUntil >= 0 && entry.daysUntil <= 30;
          return (
            <div
              key={`${entry.id}:${entry.date}`}
              className={`flex items-center justify-between gap-3 rounded-xl border px-3 py-2.5 ${
                overdue
                  ? "border-[var(--danger-border)] bg-[var(--danger-soft)]"
                  : dueSoon
                    ? "border-[#d9770645] bg-[#d9770612]"
                    : "border-[var(--border)] bg-[var(--surface)]"
              }`}
            >
              <div className="min-w-0">
                <div className="truncate text-sm font-medium text-[var(--text-primary)]">
                  {entry.title}
                </div>
                <div className="mt-0.5 text-xs text-[var(--text-muted)]">
                  {entry.label}
                </div>
              </div>
              <div className="shrink-0 text-right">
                <div className="font-mono text-xs text-[var(--text-secondary)]">
                  {entry.date}
                </div>
                <div
                  className={`mt-0.5 text-xs font-medium ${
                    overdue
                      ? "text-[var(--danger)]"
                      : dueSoon
                        ? "text-[#b45309] dark:text-[#fbbf24]"
                        : "text-[var(--text-muted)]"
                  }`}
                >
                  {formatDaysUntil(entry.daysUntil)}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function VaultCollection({
  items,
  section,
  query,
  onSelect,
}: {
  items: VaultItem[];
  section: Section;
  query: string;
  onSelect: (item: VaultItem) => void;
}) {
  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <div className="text-[11px] font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
            {sectionLabel(section)}
          </div>
          <h1 className="mt-1 text-2xl font-semibold tracking-[-0.03em]">
            {query.trim() ? "Filtered records" : "Your records"}
          </h1>
          <p className="mt-1 text-sm text-[var(--text-muted)]">
            {items.length} {items.length === 1 ? "record" : "records"}
            {query.trim() ? ` matching “${query.trim()}”` : ""}
          </p>
        </div>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {items.map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => onSelect(item)}
            className="group rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)] p-4 text-left transition hover:-translate-y-px hover:bg-[var(--selected)]"
          >
            <div className="flex items-start gap-3">
              <div className="grid size-9 shrink-0 place-items-center rounded-xl border border-[var(--border)] bg-[var(--surface)] text-[var(--icon)]">
                <HugeiconsIcon
                  icon={sectionIcon(item.kind)}
                  className="size-4"
                  aria-hidden="true"
                />
              </div>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium text-[var(--text-primary)]">
                  {item.title}
                </div>
                <div className="mt-1 line-clamp-2 text-xs leading-5 text-[var(--text-muted)]">
                  {itemPreview(item)}
                </div>
              </div>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function TrashCollection({
  items,
  section,
  query,
  loading,
  onRestore,
  onPurge,
}: {
  items: TrashedItemView[];
  section: Section;
  query: string;
  loading: boolean;
  onRestore: (item: TrashedItemView) => void;
  onPurge: (item: TrashedItemView) => void;
}) {
  if (loading) {
    return (
      <div className="grid min-h-[calc(100vh-13rem)] place-items-center text-sm text-[var(--text-muted)]">
        Opening Trash…
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="grid min-h-[calc(100vh-13rem)] place-items-center px-8">
        <div className="max-w-sm text-center">
          <div className="mx-auto mb-5 grid size-12 place-items-center rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)] text-[var(--icon)]">
            <HugeiconsIcon
              icon={Delete02Icon}
              className="size-5"
              aria-hidden="true"
            />
          </div>
          <h1 className="text-xl font-semibold tracking-[-0.02em]">
            {query.trim()
              ? `No matching ${sectionLabel(section).toLocaleLowerCase()} in Trash`
              : `No ${sectionLabel(section).toLocaleLowerCase()} in Trash`}
          </h1>
          <p className="mt-2 text-sm leading-6 text-[var(--text-muted)]">
            {query.trim()
              ? "Trash search only checks record titles."
              : "Records moved to Trash stay encrypted and can be restored until you delete them permanently."}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div>
        <div className="text-[11px] font-medium uppercase tracking-[0.12em] text-[var(--text-muted)]">
          Trash · {sectionLabel(section)}
        </div>
        <h1 className="mt-1 text-2xl font-semibold tracking-[-0.03em]">
          Deleted records
        </h1>
        <p className="mt-1 text-sm text-[var(--text-muted)]">
          {items.length} {items.length === 1 ? "record" : "records"}
          {query.trim() ? ` matching “${query.trim()}”` : ""}
        </p>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {items.map((item) => (
          <article
            key={item.id}
            className="rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)] p-4"
          >
            <div className="flex items-start gap-3">
              <div className="grid size-9 shrink-0 place-items-center rounded-xl border border-[var(--border)] bg-[var(--surface)] text-[var(--icon)]">
                <HugeiconsIcon
                  icon={sectionIcon(item.kind)}
                  className="size-4"
                  aria-hidden="true"
                />
              </div>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium text-[var(--text-primary)]">
                  {item.title}
                </div>
                <div className="mt-1 text-xs text-[var(--text-muted)]">
                  Deleted {new Date(item.deleted_at_ms).toLocaleString()}
                </div>
              </div>
            </div>
            <div className="mt-4 flex items-center gap-2 border-t border-[var(--border)] pt-3">
              <button
                type="button"
                onClick={() => onRestore(item)}
                className="flex flex-1 items-center justify-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-xs font-medium text-[var(--text-secondary)] transition hover:bg-[var(--selected)]"
              >
                <HugeiconsIcon
                  icon={RestoreBinIcon}
                  className="size-4"
                  aria-hidden="true"
                />
                Restore
              </button>
              <button
                type="button"
                onClick={() => onPurge(item)}
                className="flex flex-1 items-center justify-center gap-2 rounded-xl border border-[var(--danger-border)] bg-[var(--danger-soft)] px-3 py-2 text-xs font-medium text-[var(--danger)] transition hover:opacity-80"
              >
                <HugeiconsIcon
                  icon={Delete02Icon}
                  className="size-4"
                  aria-hidden="true"
                />
                Delete forever
              </button>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}

function NoSearchResults({
  section,
  query,
}: {
  section: Section;
  query: string;
}) {
  return (
    <div className="grid min-h-[calc(100vh-13rem)] place-items-center px-8">
      <div className="max-w-sm text-center">
        <div className="mx-auto mb-5 grid size-12 place-items-center rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)] text-[var(--icon)]">
          <HugeiconsIcon
            icon={Search01Icon}
            className="size-5"
            aria-hidden="true"
          />
        </div>
        <h1 className="text-xl font-semibold tracking-[-0.02em]">
          No matching {sectionLabel(section).toLocaleLowerCase()}
        </h1>
        <p className="mt-2 text-sm leading-6 text-[var(--text-muted)]">
          Nothing in this record type matches “{query.trim()}”. Try another
          search or change the record-type filter.
        </p>
      </div>
    </div>
  );
}

function sectionLabel(section: Section) {
  if (section === "secure_note") return "Secure notes";
  if (section === "password") return "Credentials";
  if (section === "document") return "Documents";
  if (section === "receipt") return "Receipts";
  if (section === "insurance") return "Insurance";
  if (section === "financial") return "Financial";
  if (section === "property") return "Property";
  if (section === "vehicle") return "Vehicles";
  return "Possessions";
}

function newItemLabel(section: Section) {
  if (section === "secure_note") return "New note";
  if (section === "password") return "New credential";
  if (section === "document") return "New document";
  if (section === "receipt") return "New receipt";
  if (section === "insurance") return "New insurance";
  if (section === "financial") return "New financial record";
  if (section === "property") return "New property";
  if (section === "vehicle") return "New vehicle";
  return "New possession";
}

function sectionIcon(section: Section) {
  if (section === "secure_note") return FileTextIcon;
  if (section === "password") return Key01Icon;
  if (section === "document") return DocumentValidationIcon;
  if (section === "receipt") return FileTextIcon;
  if (section === "insurance") return ShieldCheckIcon;
  if (section === "financial") return BankIcon;
  if (section === "property") return Building03Icon;
  if (section === "vehicle") return Car01Icon;
  return PackageIcon;
}

const SECTION_ORDER: Section[] = [
  "secure_note",
  "password",
  "document",
  "receipt",
  "insurance",
  "financial",
  "property",
  "vehicle",
  "possession",
];

function kindToSection(kind: string): Section | null {
  if (
    kind === "secure_note" ||
    kind === "password" ||
    kind === "document" ||
    kind === "receipt" ||
    kind === "insurance" ||
    kind === "financial" ||
    kind === "property" ||
    kind === "vehicle" ||
    kind === "possession"
  ) {
    return kind;
  }
  return null;
}

function kindLabel(kind: string): string {
  const section = kindToSection(kind);
  return section ? sectionLabel(section) : kind;
}

function groupItemsByKind(
  items: VaultItem[],
  needle: string,
): { section: Section; items: VaultItem[] }[] {
  return SECTION_ORDER.map((section) => ({
    section,
    items: items.filter(
      (item) =>
        item.kind === section &&
        (!needle || item.title.toLocaleLowerCase().includes(needle)),
    ),
  })).filter((group) => group.items.length > 0);
}

function EmptyVault({
  section,
  browserPreview,
}: {
  section: Section;
  browserPreview: boolean;
}) {
  const notes = section === "secure_note";
  const credentials = section === "password";
  const documents = section === "document";
  const receipts = section === "receipt";
  const insurance = section === "insurance";
  const financial = section === "financial";
  const property = section === "property";
  const vehicle = section === "vehicle";
  return (
    <div className="grid min-h-[calc(100vh-13rem)] place-items-center px-8">
      <div className="max-w-sm text-center">
        <div className="mx-auto mb-5 grid size-12 place-items-center rounded-2xl border border-[var(--border)] bg-[var(--surface-secondary)] text-[var(--icon)]">
          <HugeiconsIcon
            icon={
              notes
                ? FileTextIcon
                : credentials
                  ? Key01Icon
                  : documents
                    ? DocumentValidationIcon
                    : receipts
                      ? FileTextIcon
                      : insurance
                        ? ShieldCheckIcon
                        : financial
                          ? BankIcon
                          : property
                            ? Building03Icon
                            : vehicle
                              ? Car01Icon
                              : PackageIcon
            }
            className="size-5"
            aria-hidden="true"
          />
        </div>
        <h1 className="text-xl font-semibold tracking-[-0.02em]">
          {browserPreview
            ? "Safeory desktop preview"
            : notes
              ? "No secure notes yet"
              : credentials
                ? "No credentials yet"
                : documents
                  ? "No documents yet"
                  : receipts
                    ? "No receipts yet"
                    : insurance
                      ? "No insurance records yet"
                      : financial
                        ? "No financial records yet"
                        : property
                          ? "No property records yet"
                          : vehicle
                            ? "No vehicle records yet"
                            : "No possession records yet"}
        </h1>
        <p className="mt-2 text-sm leading-6 text-[var(--text-muted)]">
          {browserPreview
            ? "This browser shows the production interface. Local encryption and persistence are only active inside the Tauri desktop runtime."
            : notes
              ? "Create a note for private text that should stay encrypted at rest."
              : credentials
                ? "Store an account username, password, website, and private notes in the encrypted local vault."
                : documents
                  ? "Store document metadata locally with sensitive document numbers hidden until you reveal them."
                  : receipts
                    ? "Store receipts locally, link them to possessions, and track return or refund deadlines without exposing receipt references in list state."
                    : insurance
                      ? "Store insurance details locally with policy numbers hidden until you reveal them."
                      : financial
                        ? "Store financial account metadata locally while keeping account numbers out of list and search state."
                        : property
                          ? "Store property metadata locally while keeping addresses and property references hidden until you reveal them."
                          : vehicle
                            ? "Store vehicle details locally with registration numbers and VINs hidden until you reveal them."
                            : "Store possession details locally with serial numbers hidden until you reveal them."}
        </p>
      </div>
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-2 block text-sm font-medium">{label}</span>
      {children}
    </label>
  );
}

async function fetchVaultItems() {
  const loaded = await invoke<VaultItem[]>("list_vault_items");
  const sorted = [...loaded].sort((left, right) =>
    left.title.localeCompare(right.title),
  );
  const firstNote = sorted.find((item) => item.kind === "secure_note");
  const firstCredential = sorted.find((item) => item.kind === "password");
  const firstDocument = sorted.find((item) => item.kind === "document");
  const firstReceipt = sorted.find((item) => item.kind === "receipt");
  const firstInsurance = sorted.find((item) => item.kind === "insurance");
  const firstFinancial = sorted.find((item) => item.kind === "financial");
  const firstProperty = sorted.find((item) => item.kind === "property");
  const firstVehicle = sorted.find((item) => item.kind === "vehicle");
  const firstPossession = sorted.find((item) => item.kind === "possession");
  const initialSection: Section = firstNote
    ? "secure_note"
    : firstCredential
      ? "password"
      : firstDocument
        ? "document"
        : firstReceipt
          ? "receipt"
          : firstInsurance
            ? "insurance"
            : firstFinancial
              ? "financial"
              : firstProperty
                ? "property"
                : firstVehicle
                  ? "vehicle"
                  : firstPossession
                    ? "possession"
                    : "secure_note";
  return {
    items: sorted,
    initialSection,
    selectedId: null,
  };
}

function itemMatchesSearch(item: VaultItem, needle: string) {
  if (!needle) return true;
  if (item.title.toLocaleLowerCase().includes(needle)) return true;
  if (item.kind === "secure_note") {
    return item.body.toLocaleLowerCase().includes(needle);
  }
  if (item.kind === "password") {
    return [item.username, item.website, item.notes].some((value) =>
      value.toLocaleLowerCase().includes(needle),
    );
  }
  if (item.kind === "document") {
    return [item.issuer, item.expiry, item.notes].some((value) =>
      value.toLocaleLowerCase().includes(needle),
    );
  }
  if (item.kind === "receipt") {
    return [
      item.merchant,
      item.purchase_date,
      item.amount,
      item.currency,
      item.tracking_status,
      item.return_by,
      item.refund_due,
    ].some((value) => value.toLocaleLowerCase().includes(needle));
  }
  if (item.kind === "insurance") {
    return [item.provider, item.policy_type, item.renewal, item.notes].some(
      (value) => value.toLocaleLowerCase().includes(needle),
    );
  }
  if (item.kind === "financial") {
    return [item.institution, item.account_type, item.currency].some((value) =>
      value.toLocaleLowerCase().includes(needle),
    );
  }
  if (item.kind === "property") {
    return [item.property_type, item.ownership].some((value) =>
      value.toLocaleLowerCase().includes(needle),
    );
  }
  if (item.kind === "vehicle") {
    return [item.make, item.model, item.year, item.renewal, item.notes].some(
      (value) => value.toLocaleLowerCase().includes(needle),
    );
  }
  return [
    item.brand,
    item.model,
    item.purchase_date,
    item.purchase_price,
    item.store,
    item.warranty_expiry,
    item.notes,
  ].some((value) => value.toLocaleLowerCase().includes(needle));
}

function itemPreview(item: VaultItem) {
  if (item.kind === "secure_note") return item.body || "Empty note";
  if (item.kind === "password")
    return item.username || item.website || "Credential";
  if (item.kind === "document") return item.issuer || item.expiry || "Document";
  if (item.kind === "receipt")
    return item.merchant || item.purchase_date || item.amount || "Receipt";
  if (item.kind === "insurance")
    return item.provider || item.policy_type || "Insurance";
  if (item.kind === "financial")
    return (
      item.institution || item.account_type || item.currency || "Financial"
    );
  if (item.kind === "property")
    return item.property_type || item.ownership || "Property";
  if (item.kind === "vehicle")
    return item.make || item.model || item.year || "Vehicle";
  return item.brand || item.model || item.store || "Possession";
}

function receiptTrackingLabel(status: string) {
  if (status === "kept") return "Keeping item";
  if (status === "return_planned") return "Return planned";
  if (status === "returned") return "Returned";
  if (status === "refund_pending") return "Refund pending";
  if (status === "refunded") return "Refunded";
  return "Not tracking";
}

function withoutKind<T extends VaultItem>(item: T): Omit<T, "kind"> {
  const { kind: _kind, ...rest } = item;
  return rest;
}

type TodayEntry = {
  id: string;
  title: string;
  label: string;
  date: string;
  daysUntil: number;
};

function deviceLocalCalendarDate(now = new Date()) {
  return {
    year: now.getFullYear(),
    month: now.getMonth() + 1,
    day: now.getDate(),
  };
}

function deviceLocalCalendarDateKey(now = new Date()) {
  const date = deviceLocalCalendarDate(now);
  return `${date.year}-${date.month}-${date.day}`;
}

function parseStrictYYYYMMDD(value: string): number | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  const ms = Date.UTC(year, month - 1, day);
  const check = new Date(ms);
  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month - 1 ||
    check.getUTCDate() !== day
  ) {
    return null;
  }
  return ms;
}

function collectTodayEntries(items: VaultItem[]): TodayEntry[] {
  const today = deviceLocalCalendarDate();
  const todayMs = Date.UTC(today.year, today.month - 1, today.day);
  const entries: TodayEntry[] = [];
  for (const item of items) {
    let date = "";
    let label = "";
    if (item.kind === "document") {
      date = item.expiry;
      label = "Document expiry";
    } else if (item.kind === "receipt") {
      if (!item.tracking_status) {
        continue;
      } else if (item.tracking_status === "refund_pending") {
        date = item.refund_due;
        label = "Refund due";
      } else if (
        item.tracking_status === "refunded" ||
        item.tracking_status === "kept" ||
        item.tracking_status === "returned"
      ) {
        continue;
      } else {
        date = item.return_by;
        label = "Return deadline";
      }
    } else if (item.kind === "insurance") {
      date = item.renewal;
      label = "Insurance renewal";
    } else if (item.kind === "vehicle") {
      date = item.renewal;
      label = "Vehicle renewal";
    } else if (item.kind === "possession") {
      date = item.warranty_expiry;
      label = "Warranty expiry";
    } else {
      continue;
    }
    if (!date) continue;
    const targetMs = parseStrictYYYYMMDD(date);
    if (targetMs === null) continue;
    const daysUntil = Math.round((targetMs - todayMs) / 86_400_000);
    entries.push({ id: item.id, title: item.title, label, date, daysUntil });
  }
  entries.sort(
    (left, right) =>
      left.daysUntil - right.daysUntil ||
      left.date.localeCompare(right.date) ||
      left.title.localeCompare(right.title),
  );
  return entries.slice(0, 8);
}

function formatDaysUntil(daysUntil: number): string {
  if (daysUntil < 0) {
    const overdue = -daysUntil;
    return `Overdue by ${overdue} ${overdue === 1 ? "day" : "days"}`;
  }
  if (daysUntil === 0) return "Due today";
  return `In ${daysUntil} ${daysUntil === 1 ? "day" : "days"}`;
}

function readError(reason: unknown) {
  if (typeof reason === "string") return reason;
  if (reason instanceof Error) return reason.message;
  return "The local vault operation could not be completed.";
}
