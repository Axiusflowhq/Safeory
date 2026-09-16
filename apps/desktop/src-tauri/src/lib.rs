#![forbid(unsafe_code)]

#[cfg(windows)]
use clipboard_win::{
    Clipboard as WindowsClipboard, Format as _, Getter as _, Unicode as WindowsUnicode,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;
use vault_core::{
    AttachmentImportSource, AttachmentSummary as CoreAttachmentSummary, PreparedVaultRestore,
    VaultBackupPlan, VaultError, VaultSession, generate_strong_password,
    reminders::{collect_deadlines, parse_ymd},
};
use vault_crypto::RecoverySecret;
use vault_models::{
    AccountClosurePlan, EMERGENCY_CARD_ID, EmergencyCard, EmergencyContact, ItemKind,
    LegacyDisposition, VaultItem,
};
use vault_platform::{Clipboard as PlatformClipboard, PlatformError};
use vault_storage::StorageError;
use zeroize::Zeroizing;

const LEGACY_PRE_SAFEORY_APP_IDENTIFIER: &str = "com.lifevault.desktop";
const CREDENTIAL_CLIPBOARD_TTL_SECONDS: u64 = 30;
const CLIPBOARD_GENERATION_POLL: Duration = Duration::from_millis(100);
const CLIPBOARD_CLEAR_RETRY_DELAY: Duration = Duration::from_millis(150);
const CLIPBOARD_CLEAR_MAX_ATTEMPTS: u8 = 8;

struct VaultRuntime {
    database_path: PathBuf,
    settings_path: PathBuf,
    session: Arc<Mutex<Option<VaultSession>>>,
    session_generation: Arc<AtomicU64>,
    restore_in_progress: Arc<AtomicBool>,
    settings: Arc<Mutex<DeviceSettings>>,
    last_activity: Arc<Mutex<Instant>>,
    clipboard_cleaner: ClipboardCleaner,
}

#[derive(Clone)]
struct PendingClipboardClear {
    token: u64,
    digest: [u8; 32],
    generation: u64,
    clear_at: Instant,
    attempts: u8,
}

struct ClipboardCleanerState {
    pending: Option<PendingClipboardClear>,
    next_token: u64,
    shutdown: bool,
}

struct ClipboardCleanerShared {
    clipboard: Arc<dyn PlatformClipboard>,
    session_generation: Arc<AtomicU64>,
    state: Mutex<ClipboardCleanerState>,
    wake: Condvar,
    io_gate: Mutex<()>,
    ttl: Duration,
}

struct ClipboardCleaner {
    shared: Arc<ClipboardCleanerShared>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl ClipboardCleaner {
    fn spawn(
        clipboard: Arc<dyn PlatformClipboard>,
        session_generation: Arc<AtomicU64>,
        ttl: Duration,
    ) -> Self {
        let shared = Arc::new(ClipboardCleanerShared {
            clipboard,
            session_generation,
            state: Mutex::new(ClipboardCleanerState {
                pending: None,
                next_token: 0,
                shutdown: false,
            }),
            wake: Condvar::new(),
            io_gate: Mutex::new(()),
            ttl,
        });
        let worker_shared = Arc::clone(&shared);
        let worker = std::thread::spawn(move || clipboard_cleaner_loop(worker_shared));
        Self {
            shared,
            worker: Mutex::new(Some(worker)),
        }
    }

    fn copy_secret(&self, secret: &str, generation: u64) -> Result<(), String> {
        if self.shared.session_generation.load(Ordering::Acquire) != generation {
            return Err(clipboard_session_changed_error());
        }
        let digest = clipboard_digest(secret);
        let _io = self
            .shared
            .io_gate
            .lock()
            .map_err(|_| "The secure clipboard is unavailable.".to_owned())?;
        if self.shared.session_generation.load(Ordering::Acquire) != generation {
            return Err(clipboard_session_changed_error());
        }
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| "The secure clipboard cleaner is unavailable.".to_owned())?;
        if state.shutdown {
            return Err("The secure clipboard is shutting down.".to_owned());
        }
        self.shared.clipboard.set_secret(secret).map_err(|_| {
            "Unable to copy the credential password to the system clipboard.".to_owned()
        })?;

        let generation_still_current =
            self.shared.session_generation.load(Ordering::Acquire) == generation;
        state.next_token = state.next_token.wrapping_add(1);
        let token = state.next_token;
        state.pending = Some(PendingClipboardClear {
            token,
            digest,
            generation,
            clear_at: if generation_still_current {
                Instant::now() + self.shared.ttl
            } else {
                Instant::now()
            },
            attempts: 0,
        });
        drop(state);
        self.shared.wake.notify_one();
        if generation_still_current {
            Ok(())
        } else {
            Err(clipboard_session_changed_error())
        }
    }

    fn shutdown_and_clear(&self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.shutdown = true;
            if let Some(pending) = state.pending.as_mut() {
                pending.clear_at = Instant::now();
            }
            self.shared.wake.notify_one();
        }
        if let Ok(mut worker) = self.worker.lock()
            && let Some(worker) = worker.take()
        {
            let _ = worker.join();
        }
    }
}

impl Drop for ClipboardCleaner {
    fn drop(&mut self) {
        self.shutdown_and_clear();
    }
}

fn clipboard_cleaner_loop(shared: Arc<ClipboardCleanerShared>) {
    loop {
        let candidate = {
            let mut state = match shared.state.lock() {
                Ok(state) => state,
                Err(_) => return,
            };
            loop {
                if state.shutdown {
                    break state.pending.clone();
                }
                let Some(pending) = state.pending.as_ref() else {
                    state = match shared.wake.wait(state) {
                        Ok(state) => state,
                        Err(_) => return,
                    };
                    continue;
                };
                let generation_changed =
                    shared.session_generation.load(Ordering::Acquire) != pending.generation;
                let now = Instant::now();
                if generation_changed || now >= pending.clear_at {
                    break Some(pending.clone());
                }
                let until_expiry = pending.clear_at.saturating_duration_since(now);
                let wait_for = until_expiry.min(CLIPBOARD_GENERATION_POLL);
                let (next, _) = match shared.wake.wait_timeout(state, wait_for) {
                    Ok(result) => result,
                    Err(_) => return,
                };
                state = next;
            }
        };

        let shutdown = shared
            .state
            .lock()
            .map(|state| state.shutdown)
            .unwrap_or(true);
        if let Some(candidate) = candidate {
            process_pending_clipboard_clear(&shared, candidate, shutdown);
        }
        if shutdown {
            return;
        }
    }
}

fn process_pending_clipboard_clear(
    shared: &ClipboardCleanerShared,
    candidate: PendingClipboardClear,
    shutdown: bool,
) {
    let _io = match shared.io_gate.lock() {
        Ok(gate) => gate,
        Err(_) => return,
    };
    let still_current = shared
        .state
        .lock()
        .ok()
        .and_then(|state| {
            state
                .pending
                .as_ref()
                .map(|pending| pending.token == candidate.token)
        })
        .unwrap_or(false);
    if !still_current {
        return;
    }

    match shared.clipboard.compare_and_clear(&candidate.digest) {
        Ok(true) => {
            discard_pending_clipboard_token(shared, candidate.token);
        }
        Ok(false) => {
            discard_pending_clipboard_token(shared, candidate.token);
        }
        Err(_) => {
            if !shutdown {
                retry_pending_clipboard_clear(shared, &candidate);
            }
        }
    }
}

fn retry_pending_clipboard_clear(
    shared: &ClipboardCleanerShared,
    candidate: &PendingClipboardClear,
) {
    let Ok(mut state) = shared.state.lock() else {
        return;
    };
    let Some(pending) = state.pending.as_mut() else {
        return;
    };
    if pending.token != candidate.token {
        return;
    }
    if pending.attempts >= CLIPBOARD_CLEAR_MAX_ATTEMPTS {
        state.pending = None;
        return;
    }
    pending.attempts = pending.attempts.saturating_add(1);
    pending.clear_at = Instant::now() + CLIPBOARD_CLEAR_RETRY_DELAY;
    shared.wake.notify_one();
}

fn discard_pending_clipboard_token(shared: &ClipboardCleanerShared, token: u64) {
    if let Ok(mut state) = shared.state.lock()
        && state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.token == token)
    {
        state.pending = None;
    }
}

fn clipboard_digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

fn clipboard_session_changed_error() -> String {
    "The vault session changed while copying the credential password. Try again.".to_owned()
}

struct TauriClipboard {
    app: tauri::AppHandle,
}

impl PlatformClipboard for TauriClipboard {
    fn set_secret(&self, value: &str) -> Result<(), PlatformError> {
        self.app
            .clipboard()
            .write_text(value)
            .map_err(|_| PlatformError::OperationFailed)
    }

    fn compare_and_clear(&self, expected_sha256: &[u8; 32]) -> Result<bool, PlatformError> {
        #[cfg(windows)]
        {
            let _clipboard =
                WindowsClipboard::new_attempts(10).map_err(|_| PlatformError::OperationFailed)?;
            if !WindowsUnicode.is_format_avail() {
                return Ok(false);
            }
            let mut current = Zeroizing::new(String::new());
            WindowsUnicode
                .read_clipboard(&mut *current)
                .map_err(|_| PlatformError::OperationFailed)?;
            if clipboard_digest(&current) != *expected_sha256 {
                return Ok(false);
            }
            clipboard_win::empty().map_err(|_| PlatformError::OperationFailed)?;
            Ok(true)
        }
        #[cfg(not(windows))]
        {
            let first = Zeroizing::new(
                self.app
                    .clipboard()
                    .read_text()
                    .map_err(|_| PlatformError::OperationFailed)?,
            );
            if clipboard_digest(&first) != *expected_sha256 {
                return Ok(false);
            }
            let second = Zeroizing::new(
                self.app
                    .clipboard()
                    .read_text()
                    .map_err(|_| PlatformError::OperationFailed)?,
            );
            if clipboard_digest(&second) != *expected_sha256 {
                return Ok(false);
            }
            self.app
                .clipboard()
                .clear()
                .map_err(|_| PlatformError::OperationFailed)?;
            Ok(true)
        }
    }
}

#[derive(Clone, Copy, serde::Deserialize, serde::Serialize)]
struct DeviceSettings {
    auto_lock_minutes: u64,
    lock_on_background: bool,
    #[serde(default)]
    last_successful_encrypted_backup_at_ms: Option<u64>,
}

impl Default for DeviceSettings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 10,
            lock_on_background: true,
            last_successful_encrypted_backup_at_ms: None,
        }
    }
}

#[derive(serde::Serialize)]
struct VaultStatus {
    initialized: bool,
    unlocked: bool,
    cloud_sync_enabled: bool,
}

#[derive(serde::Serialize)]
struct NoteView {
    id: String,
    revision: u64,
    title: String,
    body: String,
    links: Vec<String>,
}

#[derive(serde::Serialize)]
struct CredentialView {
    id: String,
    revision: u64,
    title: String,
    username: String,
    website: String,
    notes: String,
    has_password: bool,
    links: Vec<String>,
}

#[derive(serde::Serialize)]
struct CredentialDetailView {
    id: String,
    revision: u64,
    title: String,
    username: String,
    password: String,
    website: String,
    notes: String,
}

#[derive(serde::Serialize)]
struct CopyCredentialPasswordStatus {
    clears_in_seconds: u64,
}

#[derive(serde::Serialize)]
struct DocumentView {
    id: String,
    revision: u64,
    title: String,
    issuer: String,
    expiry: String,
    notes: String,
    has_document_number: bool,
    links: Vec<String>,
}

#[derive(serde::Serialize)]
struct DocumentDetailView {
    id: String,
    revision: u64,
    title: String,
    document_number: String,
    issuer: String,
    expiry: String,
    notes: String,
}

#[derive(serde::Serialize)]
struct ReceiptView {
    id: String,
    revision: u64,
    title: String,
    merchant: String,
    purchase_date: String,
    amount: String,
    currency: String,
    tracking_status: String,
    return_by: String,
    refund_due: String,
    has_receipt_reference: bool,
    links: Vec<String>,
}

#[derive(serde::Serialize)]
struct ReceiptDetailView {
    id: String,
    revision: u64,
    title: String,
    merchant: String,
    purchase_date: String,
    amount: String,
    currency: String,
    receipt_reference: String,
    tracking_status: String,
    return_by: String,
    refund_due: String,
    notes: String,
}

#[derive(serde::Serialize)]
struct InsuranceView {
    id: String,
    revision: u64,
    title: String,
    provider: String,
    policy_type: String,
    renewal: String,
    notes: String,
    has_policy_number: bool,
    links: Vec<String>,
}

#[derive(serde::Serialize)]
struct InsuranceDetailView {
    id: String,
    revision: u64,
    title: String,
    provider: String,
    policy_type: String,
    policy_number: String,
    renewal: String,
    notes: String,
}

#[derive(serde::Serialize)]
struct FinancialView {
    id: String,
    revision: u64,
    title: String,
    institution: String,
    account_type: String,
    currency: String,
    has_account_number: bool,
    links: Vec<String>,
}

#[derive(serde::Serialize)]
struct FinancialDetailView {
    id: String,
    revision: u64,
    title: String,
    institution: String,
    account_type: String,
    currency: String,
    account_number: String,
    notes: String,
}

#[derive(serde::Serialize)]
struct PropertyView {
    id: String,
    revision: u64,
    title: String,
    property_type: String,
    ownership: String,
    has_address: bool,
    has_property_reference: bool,
    links: Vec<String>,
}

#[derive(serde::Serialize)]
struct PropertyDetailView {
    id: String,
    revision: u64,
    title: String,
    property_type: String,
    address: String,
    ownership: String,
    property_reference: String,
    notes: String,
}

#[derive(serde::Serialize)]
struct VehicleView {
    id: String,
    revision: u64,
    title: String,
    make: String,
    model: String,
    year: String,
    renewal: String,
    notes: String,
    has_registration_number: bool,
    has_vin: bool,
    links: Vec<String>,
}

#[derive(serde::Serialize)]
struct VehicleDetailView {
    id: String,
    revision: u64,
    title: String,
    make: String,
    model: String,
    year: String,
    registration_number: String,
    vin: String,
    renewal: String,
    notes: String,
}

#[derive(serde::Serialize)]
struct PossessionView {
    id: String,
    revision: u64,
    title: String,
    category: String,
    location: String,
    brand: String,
    model: String,
    purchase_date: String,
    purchase_price: String,
    store: String,
    warranty_expiry: String,
    notes: String,
    has_serial_number: bool,
    links: Vec<String>,
}

#[derive(serde::Serialize)]
struct PossessionDetailView {
    id: String,
    revision: u64,
    title: String,
    category: String,
    location: String,
    brand: String,
    model: String,
    serial_number: String,
    purchase_date: String,
    purchase_price: String,
    store: String,
    warranty_expiry: String,
    notes: String,
}

#[derive(serde::Serialize)]
struct SubscriptionView {
    id: String,
    revision: u64,
    title: String,
    provider: String,
    plan: String,
    amount: String,
    currency: String,
    billing_cycle: String,
    next_renewal: String,
    notes: String,
    links: Vec<String>,
}

#[derive(serde::Serialize)]
struct SubscriptionDetailView {
    id: String,
    revision: u64,
    title: String,
    provider: String,
    plan: String,
    amount: String,
    currency: String,
    billing_cycle: String,
    next_renewal: String,
    notes: String,
}

#[derive(serde::Serialize)]
struct TrashedItemView {
    id: String,
    revision: u64,
    title: String,
    kind: ItemKind,
    deleted_at_ms: u64,
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum VaultItemView {
    SecureNote {
        id: String,
        revision: u64,
        title: String,
        body: String,
        links: Vec<String>,
    },
    Password {
        id: String,
        revision: u64,
        title: String,
        username: String,
        website: String,
        notes: String,
        has_password: bool,
        links: Vec<String>,
    },
    Document {
        id: String,
        revision: u64,
        title: String,
        issuer: String,
        expiry: String,
        notes: String,
        has_document_number: bool,
        links: Vec<String>,
    },
    Receipt {
        id: String,
        revision: u64,
        title: String,
        merchant: String,
        purchase_date: String,
        amount: String,
        currency: String,
        tracking_status: String,
        return_by: String,
        refund_due: String,
        has_receipt_reference: bool,
        links: Vec<String>,
    },
    Insurance {
        id: String,
        revision: u64,
        title: String,
        provider: String,
        policy_type: String,
        renewal: String,
        notes: String,
        has_policy_number: bool,
        links: Vec<String>,
    },
    Financial {
        id: String,
        revision: u64,
        title: String,
        institution: String,
        account_type: String,
        currency: String,
        has_account_number: bool,
        links: Vec<String>,
    },
    Property {
        id: String,
        revision: u64,
        title: String,
        property_type: String,
        ownership: String,
        has_address: bool,
        has_property_reference: bool,
        links: Vec<String>,
    },
    Vehicle {
        id: String,
        revision: u64,
        title: String,
        make: String,
        model: String,
        year: String,
        renewal: String,
        notes: String,
        has_registration_number: bool,
        has_vin: bool,
        links: Vec<String>,
    },
    Possession {
        id: String,
        revision: u64,
        title: String,
        category: String,
        location: String,
        brand: String,
        model: String,
        purchase_date: String,
        purchase_price: String,
        store: String,
        warranty_expiry: String,
        notes: String,
        has_serial_number: bool,
        links: Vec<String>,
    },
    Subscription {
        id: String,
        revision: u64,
        title: String,
        provider: String,
        plan: String,
        amount: String,
        currency: String,
        billing_cycle: String,
        next_renewal: String,
        notes: String,
        links: Vec<String>,
    },
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ContactPayload {
    name: String,
    relation: String,
    phone: String,
    email: String,
    notes: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct EmergencyCardPayload {
    selected_item_ids: Vec<String>,
    contacts: Vec<ContactPayload>,
    instructions: String,
}

#[derive(serde::Serialize)]
struct EmergencyCardView {
    card: EmergencyCardPayload,
    revision: u64,
}

#[derive(serde::Serialize)]
struct ItemTitleView {
    id: String,
    kind: ItemKind,
    title: String,
}

#[derive(serde::Serialize)]
struct DeadlineView {
    item_id: String,
    kind: ItemKind,
    title: String,
    label: String,
    date: String,
    days_until: i64,
}

#[derive(serde::Serialize)]
struct RecoveryStatusView {
    configured: bool,
}

#[derive(serde::Serialize)]
struct PlanReadinessView {
    recovery_configured: bool,
    has_selected_records: bool,
    has_contacts: bool,
    has_instructions: bool,
    has_stale_selected_records: bool,
    has_legacy_preferences: bool,
    has_unspecified_legacy_items: bool,
}

struct GeneratedRecoverySecretView {
    secret: Zeroizing<String>,
    generation: u64,
}

impl serde::Serialize for GeneratedRecoverySecretView {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut view = serializer.serialize_struct("GeneratedRecoverySecretView", 2)?;
        view.serialize_field("secret", self.secret.as_str())?;
        view.serialize_field("generation", &self.generation)?;
        view.end()
    }
}

#[derive(serde::Serialize)]
struct ExportView {
    items: u64,
    path: String,
}

#[derive(serde::Serialize)]
struct BackupCreationView {
    settings: Option<DeviceSettings>,
    status_recorded: bool,
}

struct BackupCopyResult {
    settings: Option<DeviceSettings>,
}

#[derive(serde::Serialize)]
struct AttachmentSummaryView {
    id: String,
    revision: u64,
    filename: String,
    plaintext_size: u64,
}

#[derive(serde::Serialize)]
struct AttachmentAddView {
    attachment: AttachmentSummaryView,
    item_revision: u64,
}

#[derive(serde::Serialize)]
struct ItemHistorySupportView {
    linked_record_count: usize,
    attachment_count: usize,
    legacy_disposition: LegacyDisposition,
    account_closure_plan: Option<AccountClosurePlan>,
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ItemHistoryDetailView {
    SecureNote {
        id: String,
        revision: u64,
        title: String,
        body: String,
        support: ItemHistorySupportView,
    },
    Password {
        id: String,
        revision: u64,
        title: String,
        username: String,
        website: String,
        notes: String,
        has_password: bool,
        support: ItemHistorySupportView,
    },
    Document {
        id: String,
        revision: u64,
        title: String,
        issuer: String,
        expiry: String,
        notes: String,
        has_document_number: bool,
        support: ItemHistorySupportView,
    },
    Receipt {
        id: String,
        revision: u64,
        title: String,
        merchant: String,
        purchase_date: String,
        amount: String,
        currency: String,
        tracking_status: String,
        return_by: String,
        refund_due: String,
        notes: String,
        has_receipt_reference: bool,
        support: ItemHistorySupportView,
    },
    Insurance {
        id: String,
        revision: u64,
        title: String,
        provider: String,
        policy_type: String,
        renewal: String,
        notes: String,
        has_policy_number: bool,
        support: ItemHistorySupportView,
    },
    Financial {
        id: String,
        revision: u64,
        title: String,
        institution: String,
        account_type: String,
        currency: String,
        notes: String,
        has_account_number: bool,
        support: ItemHistorySupportView,
    },
    Property {
        id: String,
        revision: u64,
        title: String,
        property_type: String,
        ownership: String,
        notes: String,
        has_address: bool,
        has_property_reference: bool,
        support: ItemHistorySupportView,
    },
    Vehicle {
        id: String,
        revision: u64,
        title: String,
        make: String,
        model: String,
        year: String,
        renewal: String,
        notes: String,
        has_registration_number: bool,
        has_vin: bool,
        support: ItemHistorySupportView,
    },
    Possession {
        id: String,
        revision: u64,
        title: String,
        category: String,
        location: String,
        brand: String,
        model: String,
        purchase_date: String,
        purchase_price: String,
        store: String,
        warranty_expiry: String,
        notes: String,
        has_serial_number: bool,
        support: ItemHistorySupportView,
    },
    Subscription {
        id: String,
        revision: u64,
        title: String,
        provider: String,
        plan: String,
        amount: String,
        currency: String,
        billing_cycle: String,
        next_renewal: String,
        notes: String,
        support: ItemHistorySupportView,
    },
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ItemHistorySensitiveField {
    Password,
    DocumentNumber,
    ReceiptReference,
    PolicyNumber,
    AccountNumber,
    Address,
    PropertyReference,
    RegistrationNumber,
    Vin,
    SerialNumber,
}

#[tauri::command]
fn vault_status(state: State<'_, VaultRuntime>) -> Result<VaultStatus, String> {
    vault_status_impl(&state)
}

#[tauri::command]
fn initialize_vault(
    state: State<'_, VaultRuntime>,
    passphrase: String,
) -> Result<VaultStatus, String> {
    initialize_vault_impl(&state, passphrase)
}

#[tauri::command]
fn unlock_vault(state: State<'_, VaultRuntime>, passphrase: String) -> Result<VaultStatus, String> {
    unlock_vault_impl(&state, passphrase)
}

#[tauri::command]
fn lock_vault(state: State<'_, VaultRuntime>) -> Result<(), String> {
    lock_vault_impl(&state)
}

#[tauri::command]
fn record_activity(state: State<'_, VaultRuntime>) -> Result<(), String> {
    record_activity_impl(&state)
}

#[tauri::command]
fn get_device_settings(state: State<'_, VaultRuntime>) -> Result<DeviceSettings, String> {
    get_device_settings_impl(&state)
}

#[tauri::command]
fn update_device_settings(
    state: State<'_, VaultRuntime>,
    auto_lock_minutes: u64,
    lock_on_background: bool,
) -> Result<DeviceSettings, String> {
    update_device_settings_impl(&state, auto_lock_minutes, lock_on_background)
}

#[tauri::command]
fn change_master_passphrase(
    state: State<'_, VaultRuntime>,
    current_passphrase: String,
    new_passphrase: String,
) -> Result<(), String> {
    change_master_passphrase_impl(&state, current_passphrase, new_passphrase)
}

#[tauri::command]
fn list_vault_items(state: State<'_, VaultRuntime>) -> Result<Vec<VaultItemView>, String> {
    list_vault_items_impl(&state)
}

#[tauri::command]
fn list_trashed_items(state: State<'_, VaultRuntime>) -> Result<Vec<TrashedItemView>, String> {
    list_trashed_items_impl(&state)
}

#[tauri::command]
fn trash_item(state: State<'_, VaultRuntime>, id: String, revision: u64) -> Result<u64, String> {
    trash_item_impl(&state, id, revision)
}

#[tauri::command]
fn restore_trashed_item(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<u64, String> {
    restore_trashed_item_impl(&state, id, revision)
}

#[tauri::command]
fn purge_trashed_item(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<u64, String> {
    purge_trashed_item_impl(&state, id, revision)
}

#[tauri::command]
fn create_note(
    state: State<'_, VaultRuntime>,
    title: String,
    body: String,
) -> Result<NoteView, String> {
    create_note_impl(&state, title, body)
}

#[tauri::command]
fn update_note(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
    title: String,
    body: String,
) -> Result<NoteView, String> {
    update_note_impl(&state, id, revision, title, body)
}

#[tauri::command]
fn create_credential(
    state: State<'_, VaultRuntime>,
    title: String,
    username: String,
    password: String,
    website: String,
    notes: String,
) -> Result<CredentialView, String> {
    create_credential_impl(&state, title, username, password, website, notes)
}

#[tauri::command]
fn get_credential(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<CredentialDetailView, String> {
    get_credential_impl(&state, id, revision)
}

#[tauri::command]
fn copy_credential_password(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<CopyCredentialPasswordStatus, String> {
    copy_credential_password_impl(&state, id, revision)
}

#[tauri::command]
fn generate_password(state: State<'_, VaultRuntime>) -> Result<String, String> {
    generate_password_impl(&state)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_credential(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
    title: String,
    username: String,
    password: String,
    website: String,
    notes: String,
) -> Result<CredentialView, String> {
    update_credential_impl(
        &state, id, revision, title, username, password, website, notes,
    )
}

#[tauri::command]
fn create_document(
    state: State<'_, VaultRuntime>,
    title: String,
    document_number: String,
    issuer: String,
    expiry: String,
    notes: String,
) -> Result<DocumentView, String> {
    create_document_impl(&state, title, document_number, issuer, expiry, notes)
}

#[tauri::command]
fn get_document(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<DocumentDetailView, String> {
    get_document_impl(&state, id, revision)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_document(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
    title: String,
    document_number: String,
    issuer: String,
    expiry: String,
    notes: String,
) -> Result<DocumentView, String> {
    update_document_impl(
        &state,
        id,
        revision,
        title,
        document_number,
        issuer,
        expiry,
        notes,
    )
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_receipt(
    state: State<'_, VaultRuntime>,
    title: String,
    merchant: String,
    purchase_date: String,
    amount: String,
    currency: String,
    receipt_reference: String,
    tracking_status: String,
    return_by: String,
    refund_due: String,
    notes: String,
) -> Result<ReceiptView, String> {
    create_receipt_impl(
        &state,
        title,
        merchant,
        purchase_date,
        amount,
        currency,
        receipt_reference,
        tracking_status,
        return_by,
        refund_due,
        notes,
    )
}

#[tauri::command]
fn get_receipt(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<ReceiptDetailView, String> {
    get_receipt_impl(&state, id, revision)
}

#[tauri::command]
fn reveal_receipt_reference(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<String, String> {
    Ok(get_receipt_impl(&state, id, revision)?.receipt_reference)
}

#[tauri::command]
fn get_receipt_notes(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<String, String> {
    Ok(get_receipt_impl(&state, id, revision)?.notes)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_receipt(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
    title: String,
    merchant: String,
    purchase_date: String,
    amount: String,
    currency: String,
    receipt_reference: String,
    tracking_status: String,
    return_by: String,
    refund_due: String,
    notes: String,
) -> Result<ReceiptView, String> {
    update_receipt_impl(
        &state,
        id,
        revision,
        title,
        merchant,
        purchase_date,
        amount,
        currency,
        receipt_reference,
        tracking_status,
        return_by,
        refund_due,
        notes,
    )
}

#[tauri::command]
fn create_insurance(
    state: State<'_, VaultRuntime>,
    title: String,
    provider: String,
    policy_type: String,
    policy_number: String,
    renewal: String,
    notes: String,
) -> Result<InsuranceView, String> {
    create_insurance_impl(
        &state,
        title,
        provider,
        policy_type,
        policy_number,
        renewal,
        notes,
    )
}

#[tauri::command]
fn get_insurance(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<InsuranceDetailView, String> {
    get_insurance_impl(&state, id, revision)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_insurance(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
    title: String,
    provider: String,
    policy_type: String,
    policy_number: String,
    renewal: String,
    notes: String,
) -> Result<InsuranceView, String> {
    update_insurance_impl(
        &state,
        id,
        revision,
        title,
        provider,
        policy_type,
        policy_number,
        renewal,
        notes,
    )
}

#[tauri::command]
fn create_financial(
    state: State<'_, VaultRuntime>,
    title: String,
    institution: String,
    account_type: String,
    currency: String,
    account_number: String,
    notes: String,
) -> Result<FinancialView, String> {
    create_financial_impl(
        &state,
        title,
        institution,
        account_type,
        currency,
        account_number,
        notes,
    )
}

#[tauri::command]
fn get_financial(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<FinancialDetailView, String> {
    get_financial_impl(&state, id, revision)
}

#[tauri::command]
fn reveal_financial_account_number(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<String, String> {
    Ok(get_financial_impl(&state, id, revision)?.account_number)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_financial(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
    title: String,
    institution: String,
    account_type: String,
    currency: String,
    account_number: String,
    notes: String,
) -> Result<FinancialView, String> {
    update_financial_impl(
        &state,
        id,
        revision,
        title,
        institution,
        account_type,
        currency,
        account_number,
        notes,
    )
}

#[tauri::command]
fn create_property(
    state: State<'_, VaultRuntime>,
    title: String,
    property_type: String,
    address: String,
    ownership: String,
    property_reference: String,
    notes: String,
) -> Result<PropertyView, String> {
    create_property_impl(
        &state,
        title,
        property_type,
        address,
        ownership,
        property_reference,
        notes,
    )
}

#[tauri::command]
fn get_property(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<PropertyDetailView, String> {
    get_property_impl(&state, id, revision)
}

#[tauri::command]
fn reveal_property_address(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<String, String> {
    Ok(get_property_impl(&state, id, revision)?.address)
}

#[tauri::command]
fn reveal_property_reference(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<String, String> {
    Ok(get_property_impl(&state, id, revision)?.property_reference)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_property(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
    title: String,
    property_type: String,
    address: String,
    ownership: String,
    property_reference: String,
    notes: String,
) -> Result<PropertyView, String> {
    update_property_impl(
        &state,
        id,
        revision,
        title,
        property_type,
        address,
        ownership,
        property_reference,
        notes,
    )
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_vehicle(
    state: State<'_, VaultRuntime>,
    title: String,
    make: String,
    model: String,
    year: String,
    registration_number: String,
    vin: String,
    renewal: String,
    notes: String,
) -> Result<VehicleView, String> {
    create_vehicle_impl(
        &state,
        title,
        make,
        model,
        year,
        registration_number,
        vin,
        renewal,
        notes,
    )
}

#[tauri::command]
fn get_vehicle(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<VehicleDetailView, String> {
    get_vehicle_impl(&state, id, revision)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_vehicle(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
    title: String,
    make: String,
    model: String,
    year: String,
    registration_number: String,
    vin: String,
    renewal: String,
    notes: String,
) -> Result<VehicleView, String> {
    update_vehicle_impl(
        &state,
        id,
        revision,
        title,
        make,
        model,
        year,
        registration_number,
        vin,
        renewal,
        notes,
    )
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_possession(
    state: State<'_, VaultRuntime>,
    title: String,
    category: String,
    location: String,
    brand: String,
    model: String,
    serial_number: String,
    purchase_date: String,
    purchase_price: String,
    store: String,
    warranty_expiry: String,
    notes: String,
) -> Result<PossessionView, String> {
    create_possession_impl(
        &state,
        title,
        category,
        location,
        brand,
        model,
        serial_number,
        purchase_date,
        purchase_price,
        store,
        warranty_expiry,
        notes,
    )
}

#[tauri::command]
fn get_possession(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<PossessionDetailView, String> {
    get_possession_impl(&state, id, revision)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_possession(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
    title: String,
    category: String,
    location: String,
    brand: String,
    model: String,
    serial_number: String,
    purchase_date: String,
    purchase_price: String,
    store: String,
    warranty_expiry: String,
    notes: String,
) -> Result<PossessionView, String> {
    update_possession_impl(
        &state,
        id,
        revision,
        title,
        category,
        location,
        brand,
        model,
        serial_number,
        purchase_date,
        purchase_price,
        store,
        warranty_expiry,
        notes,
    )
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_subscription(
    state: State<'_, VaultRuntime>,
    title: String,
    provider: String,
    plan: String,
    amount: String,
    currency: String,
    billing_cycle: String,
    next_renewal: String,
    notes: String,
) -> Result<SubscriptionView, String> {
    create_subscription_impl(
        &state,
        title,
        provider,
        plan,
        amount,
        currency,
        billing_cycle,
        next_renewal,
        notes,
    )
}

#[tauri::command]
fn get_subscription(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<SubscriptionDetailView, String> {
    get_subscription_impl(&state, id, revision)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn update_subscription(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
    title: String,
    provider: String,
    plan: String,
    amount: String,
    currency: String,
    billing_cycle: String,
    next_renewal: String,
    notes: String,
) -> Result<SubscriptionView, String> {
    update_subscription_impl(
        &state,
        id,
        revision,
        title,
        provider,
        plan,
        amount,
        currency,
        billing_cycle,
        next_renewal,
        notes,
    )
}

#[tauri::command]
fn get_emergency_card(state: State<'_, VaultRuntime>) -> Result<Option<EmergencyCardView>, String> {
    get_emergency_card_impl(&state)
}

#[tauri::command]
fn update_emergency_card(
    state: State<'_, VaultRuntime>,
    revision: Option<u64>,
    selected_item_ids: Vec<String>,
    contacts: Vec<ContactPayload>,
    instructions: String,
) -> Result<u64, String> {
    update_emergency_card_impl(&state, revision, selected_item_ids, contacts, instructions)
}

#[tauri::command]
fn get_item_titles(
    state: State<'_, VaultRuntime>,
    ids: Vec<String>,
) -> Result<Vec<ItemTitleView>, String> {
    get_item_titles_impl(&state, ids)
}

#[tauri::command]
fn set_item_links(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
    links: Vec<String>,
) -> Result<u64, String> {
    set_item_links_impl(&state, id, revision, links)
}

#[tauri::command]
fn get_item_legacy_disposition(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<LegacyDisposition, String> {
    get_item_legacy_disposition_impl(&state, id, revision)
}

#[tauri::command]
fn set_item_legacy_disposition(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
    disposition: LegacyDisposition,
) -> Result<u64, String> {
    set_item_legacy_disposition_impl(&state, id, revision, disposition)
}

#[tauri::command]
fn get_credential_closure_plan(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
) -> Result<AccountClosurePlan, String> {
    get_credential_closure_plan_impl(&state, id, revision)
}

#[tauri::command]
fn set_credential_closure_plan(
    state: State<'_, VaultRuntime>,
    id: String,
    revision: u64,
    plan: AccountClosurePlan,
) -> Result<u64, String> {
    set_credential_closure_plan_impl(&state, id, revision, plan)
}

#[tauri::command]
fn list_item_history(
    state: State<'_, VaultRuntime>,
    id: String,
    current_revision: u64,
) -> Result<Vec<u64>, String> {
    list_item_history_impl(&state, id, current_revision)
}

#[tauri::command]
fn get_item_history_detail(
    state: State<'_, VaultRuntime>,
    id: String,
    current_revision: u64,
    history_revision: u64,
) -> Result<ItemHistoryDetailView, String> {
    get_item_history_detail_impl(&state, id, current_revision, history_revision)
}

#[tauri::command]
fn reveal_item_history_sensitive(
    state: State<'_, VaultRuntime>,
    id: String,
    current_revision: u64,
    history_revision: u64,
    field: ItemHistorySensitiveField,
) -> Result<String, String> {
    reveal_item_history_sensitive_impl(&state, id, current_revision, history_revision, field)
}

#[tauri::command]
async fn add_attachment(
    app: tauri::AppHandle,
    state: State<'_, VaultRuntime>,
    owner_item_id: String,
    expected_item_revision: u64,
) -> Result<Option<AttachmentAddView>, String> {
    let generation = capture_unlocked_session_generation(&state)?;
    let selected =
        tauri::async_runtime::spawn_blocking(move || app.dialog().file().blocking_pick_file())
            .await
            .map_err(|_| "Unable to open the attachment file picker.".to_owned())?;
    let Some(selected) = selected else {
        return Ok(None);
    };
    let source_path = selected
        .into_path()
        .map_err(|_| "The selected attachment path is unavailable.".to_owned())?;
    add_attachment_impl_for_generation(
        &state,
        owner_item_id,
        expected_item_revision,
        source_path,
        generation,
    )
    .map(Some)
}

#[tauri::command]
fn list_attachments(
    state: State<'_, VaultRuntime>,
    owner_item_id: String,
) -> Result<Vec<AttachmentSummaryView>, String> {
    list_attachments_impl(&state, owner_item_id)
}

#[tauri::command]
async fn export_attachment(
    app: tauri::AppHandle,
    state: State<'_, VaultRuntime>,
    owner_item_id: String,
    attachment_id: String,
) -> Result<bool, String> {
    let (filename, generation) = attachment_filename_impl(&state, &owner_item_id, &attachment_id)?;
    let selected = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_file_name(filename)
            .blocking_save_file()
    })
    .await
    .map_err(|_| "Unable to open the attachment save dialog.".to_owned())?;
    let Some(selected) = selected else {
        return Ok(false);
    };
    let destination_path = selected
        .into_path()
        .map_err(|_| "The selected attachment destination is unavailable.".to_owned())?;
    export_attachment_impl_for_generation(
        &state,
        owner_item_id,
        attachment_id,
        destination_path,
        generation,
    )?;
    Ok(true)
}

#[tauri::command]
fn delete_attachment(
    state: State<'_, VaultRuntime>,
    owner_item_id: String,
    attachment_id: String,
    expected_item_revision: u64,
    expected_attachment_revision: u64,
) -> Result<u64, String> {
    delete_attachment_impl(
        &state,
        owner_item_id,
        attachment_id,
        expected_item_revision,
        expected_attachment_revision,
    )
}

#[tauri::command]
fn list_deadlines(
    state: State<'_, VaultRuntime>,
    today_year: i32,
    today_month: u32,
    today_day: u32,
) -> Result<Vec<DeadlineView>, String> {
    list_deadlines_impl(&state, today_year, today_month, today_day)
}

#[tauri::command]
fn generate_recovery_secret(
    state: State<'_, VaultRuntime>,
) -> Result<GeneratedRecoverySecretView, String> {
    generate_recovery_secret_impl(&state)
}

#[tauri::command]
fn confirm_recovery_secret(
    state: State<'_, VaultRuntime>,
    secret: String,
    expected_generation: u64,
) -> Result<(), String> {
    confirm_recovery_secret_impl(&state, secret, expected_generation)
}

#[tauri::command]
async fn save_recovery_secret(
    app: tauri::AppHandle,
    state: State<'_, VaultRuntime>,
    secret: String,
    expected_generation: u64,
) -> Result<bool, String> {
    let secret = Zeroizing::new(secret);
    require_recovery_generation(&state, expected_generation, "saving the recovery key")?;
    let selected = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_file_name("safeory-recovery-key.txt")
            .blocking_save_file()
    })
    .await
    .map_err(|_| "Unable to open the recovery-key save dialog.".to_owned())?;
    let Some(selected) = selected else {
        return Ok(false);
    };
    let destination = selected
        .into_path()
        .map_err(|_| "The selected recovery-key destination is unavailable.".to_owned())?;
    save_recovery_secret_impl_for_generation(&state, &secret, expected_generation, &destination)?;
    Ok(true)
}

#[tauri::command]
fn get_recovery_status(state: State<'_, VaultRuntime>) -> Result<RecoveryStatusView, String> {
    get_recovery_status_impl(&state)
}

#[tauri::command]
fn verify_recovery_secret(state: State<'_, VaultRuntime>, secret: String) -> Result<bool, String> {
    verify_recovery_secret_impl(&state, secret)
}

#[tauri::command]
fn get_plan_readiness(state: State<'_, VaultRuntime>) -> Result<PlanReadinessView, String> {
    get_plan_readiness_impl(&state)
}

#[tauri::command]
fn unlock_vault_with_recovery_kit(
    state: State<'_, VaultRuntime>,
    secret: String,
) -> Result<VaultStatus, String> {
    unlock_vault_with_recovery_kit_impl(&state, secret)
}

#[tauri::command]
async fn export_human_readable(
    app: tauri::AppHandle,
    state: State<'_, VaultRuntime>,
) -> Result<Option<u64>, String> {
    let generation = capture_export_generation(&state, "exporting records")?;
    let selected = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_file_name("safeory-export.json")
            .blocking_save_file()
    })
    .await
    .map_err(|_| "Unable to open the readable-export save dialog.".to_owned())?;
    let Some(selected) = selected else {
        return Ok(None);
    };
    let destination = selected
        .into_path()
        .map_err(|_| "The selected export destination is unavailable.".to_owned())?;
    export_human_readable_impl_for_generation(
        &state,
        destination.to_string_lossy().to_string(),
        generation,
    )
    .map(|exported| Some(exported.items))
}

#[tauri::command]
async fn backup_database_copy(
    app: tauri::AppHandle,
    state: State<'_, VaultRuntime>,
) -> Result<Option<BackupCreationView>, String> {
    let generation = capture_export_generation(&state, "backing up the vault")?;
    let selected = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_file_name("safeory-backup.sqlite3")
            .blocking_save_file()
    })
    .await
    .map_err(|_| "Unable to open the encrypted-backup save dialog.".to_owned())?;
    let Some(selected) = selected else {
        return Ok(None);
    };
    let destination = selected
        .into_path()
        .map_err(|_| "The selected backup destination is unavailable.".to_owned())?;
    backup_database_copy_impl_for_generation(
        &state,
        destination.to_string_lossy().to_string(),
        generation,
    )
    .map(|result| {
        let status_recorded = result.settings.is_some();
        Some(BackupCreationView {
            settings: result.settings,
            status_recorded,
        })
    })
}

#[tauri::command]
fn restore_database_backup(
    state: State<'_, VaultRuntime>,
    path: String,
    passphrase: String,
) -> Result<VaultStatus, String> {
    restore_database_backup_impl(&state, path, passphrase)
}

#[tauri::command]
fn restore_database_backup_with_recovery_kit(
    state: State<'_, VaultRuntime>,
    path: String,
    secret: String,
    new_passphrase: String,
) -> Result<VaultStatus, String> {
    restore_database_backup_with_recovery_kit_impl(&state, path, secret, new_passphrase)
}

fn vault_status_impl(state: &VaultRuntime) -> Result<VaultStatus, String> {
    let initialized = if state.database_path.exists() {
        VaultSession::is_initialized(&state.database_path).map_err(safe_vault_error)?
    } else {
        false
    };
    let unlocked = lock_session(state)?.is_some();
    Ok(VaultStatus {
        initialized,
        unlocked,
        cloud_sync_enabled: false,
    })
}

fn initialize_vault_impl(state: &VaultRuntime, passphrase: String) -> Result<VaultStatus, String> {
    let passphrase = Zeroizing::new(passphrase);
    let mut session = lock_session(state)?;
    if session.is_some() {
        return Err("The vault is already unlocked.".to_owned());
    }
    let opened =
        VaultSession::create(&state.database_path, &passphrase).map_err(safe_vault_error)?;
    *session = Some(opened);
    advance_session_generation(&state.session_generation);
    Ok(VaultStatus {
        initialized: true,
        unlocked: true,
        cloud_sync_enabled: false,
    })
}

fn unlock_vault_impl(state: &VaultRuntime, passphrase: String) -> Result<VaultStatus, String> {
    let passphrase = Zeroizing::new(passphrase);
    let opened = VaultSession::unlock(&state.database_path, &passphrase).map_err(|_| {
        "Unable to unlock the vault. Check the master passphrase and try again.".to_owned()
    })?;
    let mut session = lock_session(state)?;
    *session = Some(opened);
    advance_session_generation(&state.session_generation);
    Ok(VaultStatus {
        initialized: true,
        unlocked: true,
        cloud_sync_enabled: false,
    })
}

fn lock_vault_impl(state: &VaultRuntime) -> Result<(), String> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "The local vault session is unavailable.".to_owned())?;
    *session = None;
    advance_session_generation(&state.session_generation);
    Ok(())
}

fn record_activity_impl(state: &VaultRuntime) -> Result<(), String> {
    expire_session_if_needed(state)?;
    let unlocked = state
        .session
        .lock()
        .map_err(|_| "The local vault session is unavailable.".to_owned())?
        .is_some();
    if unlocked {
        *state
            .last_activity
            .lock()
            .map_err(|_| "The local activity tracker is unavailable.".to_owned())? = Instant::now();
    }
    Ok(())
}

fn get_device_settings_impl(state: &VaultRuntime) -> Result<DeviceSettings, String> {
    state
        .settings
        .lock()
        .map(|settings| *settings)
        .map_err(|_| "The local device settings are unavailable.".to_owned())
}

fn update_device_settings_impl(
    state: &VaultRuntime,
    auto_lock_minutes: u64,
    lock_on_background: bool,
) -> Result<DeviceSettings, String> {
    if lock_session(state)?.is_none() {
        return Err("Unlock the vault before changing device settings.".to_owned());
    }
    mutate_device_settings(state, |current| DeviceSettings {
        auto_lock_minutes,
        lock_on_background,
        last_successful_encrypted_backup_at_ms: current.last_successful_encrypted_backup_at_ms,
    })
}

fn change_master_passphrase_impl(
    state: &VaultRuntime,
    current_passphrase: String,
    new_passphrase: String,
) -> Result<(), String> {
    if lock_session(state)?.is_none() {
        return Err("Unlock the vault before changing the master passphrase.".to_owned());
    }
    let current_passphrase = Zeroizing::new(current_passphrase);
    let new_passphrase = Zeroizing::new(new_passphrase);
    VaultSession::unlock(&state.database_path, &current_passphrase).map_err(|_| {
        "The current master passphrase is incorrect. No changes were made.".to_owned()
    })?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before changing the master passphrase.".to_owned())?;
    session
        .change_passphrase(&new_passphrase)
        .map_err(safe_vault_error)
}

fn validate_device_settings(settings: DeviceSettings) -> Result<(), String> {
    if !matches!(settings.auto_lock_minutes, 1 | 5 | 10 | 15 | 30 | 60) {
        return Err("Choose a supported auto-lock interval.".to_owned());
    }
    Ok(())
}

fn mutate_device_settings(
    state: &VaultRuntime,
    mutate: impl FnOnce(DeviceSettings) -> DeviceSettings,
) -> Result<DeviceSettings, String> {
    let mut current = state
        .settings
        .lock()
        .map_err(|_| "The local device settings are unavailable.".to_owned())?;
    let updated = mutate(*current);
    validate_device_settings(updated)?;
    persist_device_settings(&state.settings_path, *current, updated)?;
    *current = updated;
    Ok(updated)
}

fn persist_device_settings(
    path: &Path,
    previous: DeviceSettings,
    settings: DeviceSettings,
) -> Result<(), String> {
    ensure_device_settings_canonical_durable(path)?;
    let previous_encoded = serde_json::to_vec_pretty(&previous)
        .map_err(|_| "Unable to encode local device settings.".to_owned())?;
    let encoded = serde_json::to_vec_pretty(&settings)
        .map_err(|_| "Unable to encode local device settings.".to_owned())?;
    let recovery = device_settings_recovery_path(path);
    let mut recovery_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&recovery)
        .map_err(|_| "Unable to save local device settings.".to_owned())?;
    if recovery_file.write_all(&previous_encoded).is_err() || recovery_file.sync_all().is_err() {
        return Err("Unable to save local device settings.".to_owned());
    }
    drop(recovery_file);
    sync_device_settings_parent(&recovery)?;

    let staged = temporary_sibling_path(path, "settings")?;
    let mut staged_file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
    {
        Ok(file) => file,
        Err(_) => return Err("Unable to save local device settings.".to_owned()),
    };
    if staged_file.write_all(&encoded).is_err() || staged_file.sync_all().is_err() {
        drop(staged_file);
        let _ = fs::remove_file(&staged);
        return Err("Unable to save local device settings.".to_owned());
    }
    drop(staged_file);

    if path.exists() && fs::remove_file(path).is_err() {
        let _ = fs::remove_file(&staged);
        return Err("Unable to save local device settings.".to_owned());
    }
    if fs::rename(&staged, path).is_err() {
        let _ = fs::copy(&recovery, path);
        let _ = fs::remove_file(&staged);
        return Err("Unable to save local device settings.".to_owned());
    }
    if sync_device_settings_parent(path).is_err() {
        let _ = fs::remove_file(path);
        let _ = fs::copy(&recovery, path);
        let _ = sync_device_settings_parent(path);
        return Err("Unable to save local device settings.".to_owned());
    }
    Ok(())
}

fn device_settings_recovery_path(path: &Path) -> PathBuf {
    let mut file_name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("device-settings.json"))
        .to_os_string();
    file_name.push(".previous");
    path.with_file_name(file_name)
}

fn sync_device_settings_parent(path: &Path) -> Result<(), String> {
    sync_parent_directory(path).map_err(|_| "Unable to save local device settings.".to_owned())
}

fn load_device_settings(path: &Path) -> DeviceSettings {
    let recovery = device_settings_recovery_path(path);
    if let Some(settings) = read_valid_device_settings(path) {
        if sync_existing_file(path).is_ok() && sync_parent_directory(path).is_ok() {
            let _ = fs::remove_file(&recovery);
            let _ = sync_parent_directory(path);
        }
        return settings;
    }
    if let Some(settings) = read_valid_device_settings(&recovery) {
        if fs::copy(&recovery, path).is_ok() {
            let _ = sync_existing_file(path);
            let _ = sync_parent_directory(path);
        }
        return settings;
    }
    DeviceSettings::default()
}

fn read_valid_device_settings(path: &Path) -> Option<DeviceSettings> {
    let bytes = fs::read(path).ok()?;
    let settings = serde_json::from_slice::<DeviceSettings>(&bytes).ok()?;
    validate_device_settings(settings).ok()?;
    Some(settings)
}

fn ensure_device_settings_canonical_durable(path: &Path) -> Result<(), String> {
    if read_valid_device_settings(path).is_some() {
        sync_existing_file(path)
            .and_then(|()| sync_parent_directory(path))
            .map_err(|_| "Unable to save local device settings.".to_owned())?;
        return Ok(());
    }

    let recovery = device_settings_recovery_path(path);
    if read_valid_device_settings(&recovery).is_some() {
        fs::copy(&recovery, path)
            .and_then(|_| sync_existing_file(path))
            .and_then(|()| sync_parent_directory(path))
            .map_err(|_| "Unable to save local device settings.".to_owned())?;
    }
    Ok(())
}

fn sync_existing_file(path: &Path) -> Result<(), std::io::Error> {
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
}

fn record_successful_backup_creation(state: &VaultRuntime) -> Result<DeviceSettings, String> {
    let mut current = state
        .settings
        .lock()
        .map_err(|_| "The local device settings are unavailable.".to_owned())?;
    let clock_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "The system clock is unavailable.".to_owned())?
            .as_millis(),
    )
    .map_err(|_| "The system clock is unavailable.".to_owned())?;
    let recorded_at_ms = monotonic_backup_creation_timestamp(
        current.last_successful_encrypted_backup_at_ms,
        clock_ms,
    );
    let updated = DeviceSettings {
        last_successful_encrypted_backup_at_ms: Some(recorded_at_ms),
        ..*current
    };
    persist_device_settings(&state.settings_path, *current, updated)?;
    *current = updated;
    Ok(updated)
}

fn monotonic_backup_creation_timestamp(existing: Option<u64>, candidate: u64) -> u64 {
    existing.map_or(candidate, |existing| existing.max(candidate))
}

fn spawn_auto_lock_watchdog(
    session: Arc<Mutex<Option<VaultSession>>>,
    session_generation: Arc<AtomicU64>,
    settings: Arc<Mutex<DeviceSettings>>,
    last_activity: Arc<Mutex<Instant>>,
) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let auto_lock_minutes = match settings.lock() {
                Ok(settings) => settings.auto_lock_minutes,
                Err(_) => continue,
            };
            let idle_for = match last_activity.lock() {
                Ok(last_activity) => last_activity.elapsed(),
                Err(_) => continue,
            };
            if idle_for < Duration::from_secs(auto_lock_minutes.saturating_mul(60)) {
                continue;
            }
            if let Ok(mut session) = session.lock()
                && session.take().is_some()
            {
                advance_session_generation(&session_generation);
            }
        }
    });
}

fn list_vault_items_impl(state: &VaultRuntime) -> Result<Vec<VaultItemView>, String> {
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading items.".to_owned())?;
    let items = session
        .list_items_with_revisions()
        .map_err(safe_vault_error)?;
    let mut views = Vec::with_capacity(items.len());
    for (item, revision) in items {
        match item.kind {
            ItemKind::SecureNote => {
                let note = note_view(item, revision)?;
                views.push(VaultItemView::SecureNote {
                    id: note.id,
                    revision: note.revision,
                    title: note.title,
                    body: note.body,
                    links: note.links,
                });
            }
            ItemKind::Password => {
                let credential = credential_view(item, revision)?;
                views.push(VaultItemView::Password {
                    id: credential.id,
                    revision: credential.revision,
                    title: credential.title,
                    username: credential.username,
                    website: credential.website,
                    notes: credential.notes,
                    has_password: credential.has_password,
                    links: credential.links,
                });
            }
            ItemKind::Document => {
                let document = document_view(item, revision)?;
                views.push(VaultItemView::Document {
                    id: document.id,
                    revision: document.revision,
                    title: document.title,
                    issuer: document.issuer,
                    expiry: document.expiry,
                    notes: document.notes,
                    has_document_number: document.has_document_number,
                    links: document.links,
                });
            }
            ItemKind::Receipt => {
                let receipt = receipt_view(item, revision)?;
                views.push(VaultItemView::Receipt {
                    id: receipt.id,
                    revision: receipt.revision,
                    title: receipt.title,
                    merchant: receipt.merchant,
                    purchase_date: receipt.purchase_date,
                    amount: receipt.amount,
                    currency: receipt.currency,
                    tracking_status: receipt.tracking_status,
                    return_by: receipt.return_by,
                    refund_due: receipt.refund_due,
                    has_receipt_reference: receipt.has_receipt_reference,
                    links: receipt.links,
                });
            }
            ItemKind::Insurance => {
                let insurance = insurance_view(item, revision)?;
                views.push(VaultItemView::Insurance {
                    id: insurance.id,
                    revision: insurance.revision,
                    title: insurance.title,
                    provider: insurance.provider,
                    policy_type: insurance.policy_type,
                    renewal: insurance.renewal,
                    notes: insurance.notes,
                    has_policy_number: insurance.has_policy_number,
                    links: insurance.links,
                });
            }
            ItemKind::Financial => {
                let financial = financial_view(item, revision)?;
                views.push(VaultItemView::Financial {
                    id: financial.id,
                    revision: financial.revision,
                    title: financial.title,
                    institution: financial.institution,
                    account_type: financial.account_type,
                    currency: financial.currency,
                    has_account_number: financial.has_account_number,
                    links: financial.links,
                });
            }
            ItemKind::Property => {
                let property = property_view(item, revision)?;
                views.push(VaultItemView::Property {
                    id: property.id,
                    revision: property.revision,
                    title: property.title,
                    property_type: property.property_type,
                    ownership: property.ownership,
                    has_address: property.has_address,
                    has_property_reference: property.has_property_reference,
                    links: property.links,
                });
            }
            ItemKind::Vehicle => {
                let vehicle = vehicle_view(item, revision)?;
                views.push(VaultItemView::Vehicle {
                    id: vehicle.id,
                    revision: vehicle.revision,
                    title: vehicle.title,
                    make: vehicle.make,
                    model: vehicle.model,
                    year: vehicle.year,
                    renewal: vehicle.renewal,
                    notes: vehicle.notes,
                    has_registration_number: vehicle.has_registration_number,
                    has_vin: vehicle.has_vin,
                    links: vehicle.links,
                });
            }
            ItemKind::Possession => {
                let possession = possession_view(item, revision)?;
                views.push(VaultItemView::Possession {
                    id: possession.id,
                    revision: possession.revision,
                    title: possession.title,
                    category: possession.category,
                    location: possession.location,
                    brand: possession.brand,
                    model: possession.model,
                    purchase_date: possession.purchase_date,
                    purchase_price: possession.purchase_price,
                    store: possession.store,
                    warranty_expiry: possession.warranty_expiry,
                    notes: possession.notes,
                    has_serial_number: possession.has_serial_number,
                    links: possession.links,
                });
            }
            ItemKind::Subscription => {
                let subscription = subscription_view(item, revision)?;
                views.push(VaultItemView::Subscription {
                    id: subscription.id,
                    revision: subscription.revision,
                    title: subscription.title,
                    provider: subscription.provider,
                    plan: subscription.plan,
                    amount: subscription.amount,
                    currency: subscription.currency,
                    billing_cycle: subscription.billing_cycle,
                    next_renewal: subscription.next_renewal,
                    notes: subscription.notes,
                    links: subscription.links,
                });
            }
            ItemKind::EmergencyInstruction => {
                // Emergency instructions stay hidden from the standard list view.
            }
        }
    }
    Ok(views)
}

fn list_trashed_items_impl(state: &VaultRuntime) -> Result<Vec<TrashedItemView>, String> {
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading Trash.".to_owned())?;
    let items = session
        .list_trashed_items_with_revisions()
        .map_err(safe_vault_error)?;
    let mut views = Vec::with_capacity(items.len());
    for (item, revision, deleted_at_ms) in items {
        if item.kind == ItemKind::EmergencyInstruction {
            continue;
        }
        views.push(TrashedItemView {
            id: item.id.to_string(),
            revision,
            title: item.title,
            kind: item.kind,
            deleted_at_ms,
        });
    }
    Ok(views)
}

fn trash_item_impl(state: &VaultRuntime, id: String, revision: u64) -> Result<u64, String> {
    let id = id
        .parse()
        .map_err(|_| "The record identifier is invalid.".to_owned())?;
    let deleted_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "The system clock is unavailable.".to_owned())?
        .as_millis();
    let deleted_at_ms =
        u64::try_from(deleted_at_ms).map_err(|_| "The system clock is unavailable.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before moving a record to Trash.".to_owned())?;
    session
        .trash_item(id, revision, deleted_at_ms)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This record changed since you opened it. Reload it before moving it to Trash."
                    .to_owned()
            }
            other => safe_vault_error(other),
        })
}

fn restore_trashed_item_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
) -> Result<u64, String> {
    let id = id
        .parse()
        .map_err(|_| "The record identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before restoring a record.".to_owned())?;
    session
        .restore_item(id, revision)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This Trash record changed. Reload Trash before restoring it.".to_owned()
            }
            other => safe_vault_error(other),
        })
}

fn purge_trashed_item_impl(state: &VaultRuntime, id: String, revision: u64) -> Result<u64, String> {
    let id = id
        .parse()
        .map_err(|_| "The record identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before permanently deleting a record.".to_owned())?;
    session
        .purge_item(id, revision)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This Trash record changed. Reload Trash before deleting it.".to_owned()
            }
            other => safe_vault_error(other),
        })
}

fn create_note_impl(state: &VaultRuntime, title: String, body: String) -> Result<NoteView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A note title is required.".to_owned());
    }
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before creating a note.".to_owned())?;
    let item = VaultItem::secure_note(title, body);
    session.put_item(&item, 1).map_err(safe_vault_error)?;
    note_view(item, 1)
}

fn update_note_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
    title: String,
    body: String,
) -> Result<NoteView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A note title is required.".to_owned());
    }
    let id = id
        .parse()
        .map_err(|_| "The note identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before editing a note.".to_owned())?;
    let (existing, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err("This note changed since you opened it. Reload it before saving.".to_owned());
    }
    if existing.kind != ItemKind::SecureNote {
        return Err("Only secure notes can be edited from this view.".to_owned());
    }
    let mut fields = BTreeMap::new();
    fields.insert("body".to_owned(), body);
    let item = VaultItem {
        id,
        kind: ItemKind::SecureNote,
        title: title.to_owned(),
        links: existing.links.clone(),
        attachments: existing.attachments.clone(),
        legacy_disposition: existing.legacy_disposition,
        account_closure_plan: existing.account_closure_plan.clone(),
        fields,
        notes: existing.notes,
    };
    let revision = session
        .update_item(&item, revision)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This note changed since you opened it. Reload it before saving.".to_owned()
            }
            other => safe_vault_error(other),
        })?;
    note_view(item, revision)
}

fn create_credential_impl(
    state: &VaultRuntime,
    title: String,
    username: String,
    password: String,
    website: String,
    notes: String,
) -> Result<CredentialView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A credential title is required.".to_owned());
    }
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before creating a credential.".to_owned())?;
    let item = VaultItem::password(title, username, password, website, notes);
    session.put_item(&item, 1).map_err(safe_vault_error)?;
    credential_view(item, 1)
}

fn get_credential_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
) -> Result<CredentialDetailView, String> {
    let id = id
        .parse()
        .map_err(|_| "The credential identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading a credential.".to_owned())?;
    let (item, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This credential changed since you opened it. Reload it before continuing.".to_owned(),
        );
    }
    if item.kind != ItemKind::Password {
        return Err("Only credentials can be opened from this view.".to_owned());
    }
    credential_detail_view(item, current_revision)
}

fn copy_credential_password_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
) -> Result<CopyCredentialPasswordStatus, String> {
    let id = id
        .parse()
        .map_err(|_| "The credential identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session_ref = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before copying a credential password.".to_owned())?;
    let (mut item, current_revision) = session_ref
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This credential changed since you opened it. Reload it before copying its password."
                .to_owned(),
        );
    }
    if item.kind != ItemKind::Password {
        return Err("Only credential passwords can be copied from this command.".to_owned());
    }
    let password = Zeroizing::new(
        item.fields
            .remove("password")
            .ok_or_else(|| "The encrypted credential is missing its password field.".to_owned())?,
    );
    if password.is_empty() {
        return Err("This credential does not have a password to copy.".to_owned());
    }
    let generation = capture_session_generation(state);
    drop(item);
    drop(session);

    state.clipboard_cleaner.copy_secret(&password, generation)?;
    Ok(CopyCredentialPasswordStatus {
        clears_in_seconds: CREDENTIAL_CLIPBOARD_TTL_SECONDS,
    })
}

fn generate_password_impl(state: &VaultRuntime) -> Result<String, String> {
    let session = lock_session(state)?;
    if session.is_none() {
        return Err("Unlock the vault before generating a password.".to_owned());
    }
    drop(session);
    generate_strong_password(20).map_err(safe_vault_error)
}

fn create_document_impl(
    state: &VaultRuntime,
    title: String,
    document_number: String,
    issuer: String,
    expiry: String,
    notes: String,
) -> Result<DocumentView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A document title is required.".to_owned());
    }
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before creating a document.".to_owned())?;
    let item = VaultItem::document(title, document_number, issuer, expiry, notes);
    session.put_item(&item, 1).map_err(safe_vault_error)?;
    document_view(item, 1)
}

fn get_document_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
) -> Result<DocumentDetailView, String> {
    let id = id
        .parse()
        .map_err(|_| "The document identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading a document.".to_owned())?;
    let (item, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This document changed since you opened it. Reload it before continuing.".to_owned(),
        );
    }
    if item.kind != ItemKind::Document {
        return Err("Only documents can be opened from this view.".to_owned());
    }
    document_detail_view(item, current_revision)
}

#[allow(clippy::too_many_arguments)]
fn update_document_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
    title: String,
    document_number: String,
    issuer: String,
    expiry: String,
    notes: String,
) -> Result<DocumentView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A document title is required.".to_owned());
    }
    let id = id
        .parse()
        .map_err(|_| "The document identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before editing a document.".to_owned())?;
    let (existing, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This document changed since you opened it. Reload it before saving.".to_owned(),
        );
    }
    if existing.kind != ItemKind::Document {
        return Err("Only documents can be edited from this view.".to_owned());
    }
    let mut fields = BTreeMap::new();
    fields.insert("document_number".to_owned(), document_number);
    fields.insert("issuer".to_owned(), issuer);
    fields.insert("expiry".to_owned(), expiry);
    let item = VaultItem {
        id,
        kind: ItemKind::Document,
        title: title.to_owned(),
        links: existing.links.clone(),
        attachments: existing.attachments.clone(),
        legacy_disposition: existing.legacy_disposition,
        account_closure_plan: existing.account_closure_plan.clone(),
        fields,
        notes: (!notes.is_empty()).then_some(notes),
    };
    let revision = session
        .update_item(&item, revision)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This document changed since you opened it. Reload it before saving.".to_owned()
            }
            other => safe_vault_error(other),
        })?;
    document_view(item, revision)
}

#[allow(clippy::too_many_arguments)]
fn create_receipt_impl(
    state: &VaultRuntime,
    title: String,
    merchant: String,
    purchase_date: String,
    amount: String,
    currency: String,
    receipt_reference: String,
    tracking_status: String,
    return_by: String,
    refund_due: String,
    notes: String,
) -> Result<ReceiptView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A receipt title is required.".to_owned());
    }
    validate_receipt_tracking_status(&tracking_status)?;
    validate_optional_receipt_date("Purchase date", &purchase_date)?;
    validate_optional_receipt_date("Return deadline", &return_by)?;
    validate_optional_receipt_date("Refund due date", &refund_due)?;
    validate_receipt_tracking_dates(&tracking_status, &return_by, &refund_due)?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before creating a receipt.".to_owned())?;
    let item = VaultItem::receipt(
        title,
        merchant,
        purchase_date,
        amount,
        currency,
        receipt_reference,
        tracking_status,
        return_by,
        refund_due,
        notes,
    );
    session.put_item(&item, 1).map_err(safe_vault_error)?;
    receipt_view(item, 1)
}

fn get_receipt_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
) -> Result<ReceiptDetailView, String> {
    let id = id
        .parse()
        .map_err(|_| "The receipt identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading a receipt.".to_owned())?;
    let (item, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This receipt changed since you opened it. Reload it before continuing.".to_owned(),
        );
    }
    if item.kind != ItemKind::Receipt {
        return Err("Only receipt records can be opened from this view.".to_owned());
    }
    receipt_detail_view(item, current_revision)
}

#[allow(clippy::too_many_arguments)]
fn update_receipt_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
    title: String,
    merchant: String,
    purchase_date: String,
    amount: String,
    currency: String,
    receipt_reference: String,
    tracking_status: String,
    return_by: String,
    refund_due: String,
    notes: String,
) -> Result<ReceiptView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A receipt title is required.".to_owned());
    }
    validate_receipt_tracking_status(&tracking_status)?;
    validate_optional_receipt_date("Purchase date", &purchase_date)?;
    validate_optional_receipt_date("Return deadline", &return_by)?;
    validate_optional_receipt_date("Refund due date", &refund_due)?;
    validate_receipt_tracking_dates(&tracking_status, &return_by, &refund_due)?;
    let id = id
        .parse()
        .map_err(|_| "The receipt identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before editing a receipt.".to_owned())?;
    let (existing, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This receipt changed since you opened it. Reload it before saving.".to_owned(),
        );
    }
    if existing.kind != ItemKind::Receipt {
        return Err("Only receipt records can be edited from this view.".to_owned());
    }
    let mut fields = BTreeMap::new();
    fields.insert("merchant".to_owned(), merchant);
    fields.insert("purchase_date".to_owned(), purchase_date);
    fields.insert("amount".to_owned(), amount);
    fields.insert("currency".to_owned(), currency);
    fields.insert("receipt_reference".to_owned(), receipt_reference);
    fields.insert("tracking_status".to_owned(), tracking_status);
    fields.insert("return_by".to_owned(), return_by);
    fields.insert("refund_due".to_owned(), refund_due);
    let item = VaultItem {
        id,
        kind: ItemKind::Receipt,
        title: title.to_owned(),
        links: existing.links.clone(),
        attachments: existing.attachments.clone(),
        legacy_disposition: existing.legacy_disposition,
        account_closure_plan: existing.account_closure_plan.clone(),
        fields,
        notes: (!notes.is_empty()).then_some(notes),
    };
    let revision = session
        .update_item(&item, revision)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This receipt changed since you opened it. Reload it before saving.".to_owned()
            }
            other => safe_vault_error(other),
        })?;
    receipt_view(item, revision)
}

fn create_insurance_impl(
    state: &VaultRuntime,
    title: String,
    provider: String,
    policy_type: String,
    policy_number: String,
    renewal: String,
    notes: String,
) -> Result<InsuranceView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("An insurance title is required.".to_owned());
    }
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before creating an insurance record.".to_owned())?;
    let item = VaultItem::insurance(title, provider, policy_type, policy_number, renewal, notes);
    session.put_item(&item, 1).map_err(safe_vault_error)?;
    insurance_view(item, 1)
}

fn get_insurance_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
) -> Result<InsuranceDetailView, String> {
    let id = id
        .parse()
        .map_err(|_| "The insurance identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading an insurance record.".to_owned())?;
    let (item, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This insurance record changed since you opened it. Reload it before continuing."
                .to_owned(),
        );
    }
    if item.kind != ItemKind::Insurance {
        return Err("Only insurance records can be opened from this view.".to_owned());
    }
    insurance_detail_view(item, current_revision)
}

#[allow(clippy::too_many_arguments)]
fn update_insurance_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
    title: String,
    provider: String,
    policy_type: String,
    policy_number: String,
    renewal: String,
    notes: String,
) -> Result<InsuranceView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("An insurance title is required.".to_owned());
    }
    let id = id
        .parse()
        .map_err(|_| "The insurance identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before editing an insurance record.".to_owned())?;
    let (existing, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This insurance record changed since you opened it. Reload it before saving."
                .to_owned(),
        );
    }
    if existing.kind != ItemKind::Insurance {
        return Err("Only insurance records can be edited from this view.".to_owned());
    }
    let mut fields = BTreeMap::new();
    fields.insert("provider".to_owned(), provider);
    fields.insert("policy_type".to_owned(), policy_type);
    fields.insert("policy_number".to_owned(), policy_number);
    fields.insert("renewal".to_owned(), renewal);
    let item = VaultItem {
        id,
        kind: ItemKind::Insurance,
        title: title.to_owned(),
        links: existing.links.clone(),
        attachments: existing.attachments.clone(),
        legacy_disposition: existing.legacy_disposition,
        account_closure_plan: existing.account_closure_plan.clone(),
        fields,
        notes: (!notes.is_empty()).then_some(notes),
    };
    let revision = session
        .update_item(&item, revision)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This insurance record changed since you opened it. Reload it before saving."
                    .to_owned()
            }
            other => safe_vault_error(other),
        })?;
    insurance_view(item, revision)
}

#[allow(clippy::too_many_arguments)]
fn create_financial_impl(
    state: &VaultRuntime,
    title: String,
    institution: String,
    account_type: String,
    currency: String,
    account_number: String,
    notes: String,
) -> Result<FinancialView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A financial record title is required.".to_owned());
    }
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before creating a financial record.".to_owned())?;
    let item = VaultItem::financial(
        title,
        institution,
        account_type,
        currency,
        account_number,
        notes,
    );
    session.put_item(&item, 1).map_err(safe_vault_error)?;
    financial_view(item, 1)
}

fn get_financial_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
) -> Result<FinancialDetailView, String> {
    let id = id
        .parse()
        .map_err(|_| "The financial record identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading a financial record.".to_owned())?;
    let (item, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This financial record changed since you opened it. Reload it before continuing."
                .to_owned(),
        );
    }
    if item.kind != ItemKind::Financial {
        return Err("Only financial records can be opened from this view.".to_owned());
    }
    financial_detail_view(item, current_revision)
}

#[allow(clippy::too_many_arguments)]
fn update_financial_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
    title: String,
    institution: String,
    account_type: String,
    currency: String,
    account_number: String,
    notes: String,
) -> Result<FinancialView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A financial record title is required.".to_owned());
    }
    let id = id
        .parse()
        .map_err(|_| "The financial record identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before editing a financial record.".to_owned())?;
    let (existing, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This financial record changed since you opened it. Reload it before saving."
                .to_owned(),
        );
    }
    if existing.kind != ItemKind::Financial {
        return Err("Only financial records can be edited from this view.".to_owned());
    }
    let mut fields = BTreeMap::new();
    fields.insert("institution".to_owned(), institution);
    fields.insert("account_type".to_owned(), account_type);
    fields.insert("currency".to_owned(), currency);
    fields.insert("account_number".to_owned(), account_number);
    let item = VaultItem {
        id,
        kind: ItemKind::Financial,
        title: title.to_owned(),
        links: existing.links.clone(),
        attachments: existing.attachments.clone(),
        legacy_disposition: existing.legacy_disposition,
        account_closure_plan: existing.account_closure_plan.clone(),
        fields,
        notes: (!notes.is_empty()).then_some(notes),
    };
    let revision = session
        .update_item(&item, revision)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This financial record changed since you opened it. Reload it before saving."
                    .to_owned()
            }
            other => safe_vault_error(other),
        })?;
    financial_view(item, revision)
}

#[allow(clippy::too_many_arguments)]
fn create_property_impl(
    state: &VaultRuntime,
    title: String,
    property_type: String,
    address: String,
    ownership: String,
    property_reference: String,
    notes: String,
) -> Result<PropertyView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A property title is required.".to_owned());
    }
    validate_property_ownership(&ownership)?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before creating a property record.".to_owned())?;
    let item = VaultItem::property(
        title,
        property_type,
        address,
        ownership,
        property_reference,
        notes,
    );
    session.put_item(&item, 1).map_err(safe_vault_error)?;
    property_view(item, 1)
}

fn get_property_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
) -> Result<PropertyDetailView, String> {
    let id = id
        .parse()
        .map_err(|_| "The property record identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading a property record.".to_owned())?;
    let (item, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This property record changed since you opened it. Reload it before continuing."
                .to_owned(),
        );
    }
    if item.kind != ItemKind::Property {
        return Err("Only property records can be opened from this view.".to_owned());
    }
    property_detail_view(item, current_revision)
}

#[allow(clippy::too_many_arguments)]
fn update_property_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
    title: String,
    property_type: String,
    address: String,
    ownership: String,
    property_reference: String,
    notes: String,
) -> Result<PropertyView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A property title is required.".to_owned());
    }
    validate_property_ownership(&ownership)?;
    let id = id
        .parse()
        .map_err(|_| "The property record identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before editing a property record.".to_owned())?;
    let (existing, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This property record changed since you opened it. Reload it before saving.".to_owned(),
        );
    }
    if existing.kind != ItemKind::Property {
        return Err("Only property records can be edited from this view.".to_owned());
    }
    let mut fields = BTreeMap::new();
    fields.insert("property_type".to_owned(), property_type);
    fields.insert("address".to_owned(), address);
    fields.insert("ownership".to_owned(), ownership);
    fields.insert("property_reference".to_owned(), property_reference);
    let item = VaultItem {
        id,
        kind: ItemKind::Property,
        title: title.to_owned(),
        links: existing.links.clone(),
        attachments: existing.attachments.clone(),
        legacy_disposition: existing.legacy_disposition,
        account_closure_plan: existing.account_closure_plan.clone(),
        fields,
        notes: (!notes.is_empty()).then_some(notes),
    };
    let revision = session
        .update_item(&item, revision)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This property record changed since you opened it. Reload it before saving."
                    .to_owned()
            }
            other => safe_vault_error(other),
        })?;
    property_view(item, revision)
}

#[allow(clippy::too_many_arguments)]
fn create_vehicle_impl(
    state: &VaultRuntime,
    title: String,
    make: String,
    model: String,
    year: String,
    registration_number: String,
    vin: String,
    renewal: String,
    notes: String,
) -> Result<VehicleView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A vehicle title is required.".to_owned());
    }
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before creating a vehicle record.".to_owned())?;
    let item = VaultItem::vehicle(
        title,
        make,
        model,
        year,
        registration_number,
        vin,
        renewal,
        notes,
    );
    session.put_item(&item, 1).map_err(safe_vault_error)?;
    vehicle_view(item, 1)
}

fn get_vehicle_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
) -> Result<VehicleDetailView, String> {
    let id = id
        .parse()
        .map_err(|_| "The vehicle identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading a vehicle record.".to_owned())?;
    let (item, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This vehicle record changed since you opened it. Reload it before continuing."
                .to_owned(),
        );
    }
    if item.kind != ItemKind::Vehicle {
        return Err("Only vehicle records can be opened from this view.".to_owned());
    }
    vehicle_detail_view(item, current_revision)
}

#[allow(clippy::too_many_arguments)]
fn update_vehicle_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
    title: String,
    make: String,
    model: String,
    year: String,
    registration_number: String,
    vin: String,
    renewal: String,
    notes: String,
) -> Result<VehicleView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A vehicle title is required.".to_owned());
    }
    let id = id
        .parse()
        .map_err(|_| "The vehicle identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before editing a vehicle record.".to_owned())?;
    let (existing, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This vehicle record changed since you opened it. Reload it before saving.".to_owned(),
        );
    }
    if existing.kind != ItemKind::Vehicle {
        return Err("Only vehicle records can be edited from this view.".to_owned());
    }
    let mut fields = BTreeMap::new();
    fields.insert("make".to_owned(), make);
    fields.insert("model".to_owned(), model);
    fields.insert("year".to_owned(), year);
    fields.insert("registration_number".to_owned(), registration_number);
    fields.insert("vin".to_owned(), vin);
    fields.insert("renewal".to_owned(), renewal);
    let item = VaultItem {
        id,
        kind: ItemKind::Vehicle,
        title: title.to_owned(),
        links: existing.links.clone(),
        attachments: existing.attachments.clone(),
        legacy_disposition: existing.legacy_disposition,
        account_closure_plan: existing.account_closure_plan.clone(),
        fields,
        notes: (!notes.is_empty()).then_some(notes),
    };
    let revision = session
        .update_item(&item, revision)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This vehicle record changed since you opened it. Reload it before saving."
                    .to_owned()
            }
            other => safe_vault_error(other),
        })?;
    vehicle_view(item, revision)
}

#[allow(clippy::too_many_arguments)]
fn create_possession_impl(
    state: &VaultRuntime,
    title: String,
    category: String,
    location: String,
    brand: String,
    model: String,
    serial_number: String,
    purchase_date: String,
    purchase_price: String,
    store: String,
    warranty_expiry: String,
    notes: String,
) -> Result<PossessionView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A possession title is required.".to_owned());
    }
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before creating a possession record.".to_owned())?;
    let item = VaultItem::possession(
        title,
        category,
        location,
        brand,
        model,
        serial_number,
        purchase_date,
        purchase_price,
        store,
        warranty_expiry,
        notes,
    );
    session.put_item(&item, 1).map_err(safe_vault_error)?;
    possession_view(item, 1)
}

fn get_possession_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
) -> Result<PossessionDetailView, String> {
    let id = id
        .parse()
        .map_err(|_| "The possession identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading a possession record.".to_owned())?;
    let (item, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This possession record changed since you opened it. Reload it before continuing."
                .to_owned(),
        );
    }
    if item.kind != ItemKind::Possession {
        return Err("Only possession records can be opened from this view.".to_owned());
    }
    possession_detail_view(item, current_revision)
}

#[allow(clippy::too_many_arguments)]
fn update_possession_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
    title: String,
    category: String,
    location: String,
    brand: String,
    model: String,
    serial_number: String,
    purchase_date: String,
    purchase_price: String,
    store: String,
    warranty_expiry: String,
    notes: String,
) -> Result<PossessionView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A possession title is required.".to_owned());
    }
    let id = id
        .parse()
        .map_err(|_| "The possession identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before editing a possession record.".to_owned())?;
    let (existing, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This possession record changed since you opened it. Reload it before saving."
                .to_owned(),
        );
    }
    if existing.kind != ItemKind::Possession {
        return Err("Only possession records can be edited from this view.".to_owned());
    }
    let mut fields = existing.fields.clone();
    fields.insert("category".to_owned(), category.trim().to_owned());
    fields.insert("location".to_owned(), location.trim().to_owned());
    fields.insert("brand".to_owned(), brand);
    fields.insert("model".to_owned(), model);
    fields.insert("serial_number".to_owned(), serial_number);
    fields.insert("purchase_date".to_owned(), purchase_date);
    fields.insert("purchase_price".to_owned(), purchase_price);
    fields.insert("store".to_owned(), store);
    fields.insert("warranty_expiry".to_owned(), warranty_expiry);
    let item = VaultItem {
        id,
        kind: ItemKind::Possession,
        title: title.to_owned(),
        links: existing.links.clone(),
        attachments: existing.attachments.clone(),
        legacy_disposition: existing.legacy_disposition,
        account_closure_plan: existing.account_closure_plan.clone(),
        fields,
        notes: (!notes.is_empty()).then_some(notes),
    };
    let revision = session
        .update_item(&item, revision)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This possession record changed since you opened it. Reload it before saving."
                    .to_owned()
            }
            other => safe_vault_error(other),
        })?;
    possession_view(item, revision)
}

#[allow(clippy::too_many_arguments)]
fn create_subscription_impl(
    state: &VaultRuntime,
    title: String,
    provider: String,
    plan: String,
    amount: String,
    currency: String,
    billing_cycle: String,
    next_renewal: String,
    notes: String,
) -> Result<SubscriptionView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A subscription title is required.".to_owned());
    }
    validate_subscription_billing_cycle(&billing_cycle)?;
    validate_optional_date("Next renewal", &next_renewal)?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before creating a subscription.".to_owned())?;
    let item = VaultItem::subscription(
        title,
        provider,
        plan,
        amount,
        currency,
        billing_cycle,
        next_renewal,
        notes,
    );
    session.put_item(&item, 1).map_err(safe_vault_error)?;
    subscription_view(item, 1)
}

fn get_subscription_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
) -> Result<SubscriptionDetailView, String> {
    let id = id
        .parse()
        .map_err(|_| "The subscription identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading a subscription.".to_owned())?;
    let (item, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This subscription changed since you opened it. Reload it before continuing."
                .to_owned(),
        );
    }
    if item.kind != ItemKind::Subscription {
        return Err("Only subscription records can be opened from this view.".to_owned());
    }
    subscription_detail_view(item, current_revision)
}

#[allow(clippy::too_many_arguments)]
fn update_subscription_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
    title: String,
    provider: String,
    plan: String,
    amount: String,
    currency: String,
    billing_cycle: String,
    next_renewal: String,
    notes: String,
) -> Result<SubscriptionView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A subscription title is required.".to_owned());
    }
    validate_subscription_billing_cycle(&billing_cycle)?;
    validate_optional_date("Next renewal", &next_renewal)?;
    let id = id
        .parse()
        .map_err(|_| "The subscription identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before editing a subscription.".to_owned())?;
    let (existing, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This subscription changed since you opened it. Reload it before saving.".to_owned(),
        );
    }
    if existing.kind != ItemKind::Subscription {
        return Err("Only subscription records can be edited from this view.".to_owned());
    }
    let mut fields = BTreeMap::new();
    fields.insert("provider".to_owned(), provider);
    fields.insert("plan".to_owned(), plan);
    fields.insert("amount".to_owned(), amount);
    fields.insert("currency".to_owned(), currency);
    fields.insert("billing_cycle".to_owned(), billing_cycle);
    fields.insert("next_renewal".to_owned(), next_renewal);
    let item = VaultItem {
        id,
        kind: ItemKind::Subscription,
        title: title.to_owned(),
        links: existing.links.clone(),
        attachments: existing.attachments.clone(),
        legacy_disposition: existing.legacy_disposition,
        account_closure_plan: existing.account_closure_plan.clone(),
        fields,
        notes: (!notes.is_empty()).then_some(notes),
    };
    let revision = session
        .update_item(&item, revision)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This subscription changed since you opened it. Reload it before saving.".to_owned()
            }
            other => safe_vault_error(other),
        })?;
    subscription_view(item, revision)
}

fn emergency_card_payload(card: EmergencyCard) -> EmergencyCardPayload {
    EmergencyCardPayload {
        selected_item_ids: card
            .selected_item_ids
            .iter()
            .map(ToString::to_string)
            .collect(),
        contacts: card
            .contacts
            .into_iter()
            .map(|contact| ContactPayload {
                name: contact.name,
                relation: contact.relation,
                phone: contact.phone,
                email: contact.email,
                notes: contact.notes,
            })
            .collect(),
        instructions: card.instructions,
    }
}

fn get_emergency_card_impl(state: &VaultRuntime) -> Result<Option<EmergencyCardView>, String> {
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading the emergency card.".to_owned())?;
    let current = session.get_emergency_card().map_err(safe_vault_error)?;
    Ok(current.map(|(card, revision)| EmergencyCardView {
        card: emergency_card_payload(card),
        revision,
    }))
}

fn update_emergency_card_impl(
    state: &VaultRuntime,
    revision: Option<u64>,
    selected_item_ids: Vec<String>,
    contacts: Vec<ContactPayload>,
    instructions: String,
) -> Result<u64, String> {
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before editing the emergency card.".to_owned())?;
    let mut parsed_ids = Vec::with_capacity(selected_item_ids.len());
    for id in selected_item_ids {
        let parsed = id
            .parse()
            .map_err(|_| "One of the selected records is invalid.".to_owned())?;
        parsed_ids.push(parsed);
    }
    let card = EmergencyCard {
        selected_item_ids: parsed_ids,
        contacts: contacts
            .into_iter()
            .map(|contact| EmergencyContact {
                name: contact.name,
                relation: contact.relation,
                phone: contact.phone,
                email: contact.email,
                notes: contact.notes,
            })
            .collect(),
        instructions,
    };
    let current = session.get_emergency_card().map_err(safe_vault_error)?;
    let stale =
        "The emergency card changed since you opened it. Reload it before saving.".to_owned();
    match (&current, revision) {
        (None, None) => {}
        (Some((_, current_revision)), Some(expected)) if *current_revision == expected => {}
        _ => return Err(stale),
    }
    session.set_emergency_card(&card).map_err(safe_vault_error)
}

fn get_item_titles_impl(
    state: &VaultRuntime,
    ids: Vec<String>,
) -> Result<Vec<ItemTitleView>, String> {
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading items.".to_owned())?;
    let mut views = Vec::new();
    for id in ids {
        let Ok(parsed) = id.parse() else {
            continue;
        };
        if parsed == EMERGENCY_CARD_ID {
            continue;
        }
        let Ok((item, _)) = session.get_item_with_revision(parsed) else {
            continue;
        };
        views.push(ItemTitleView {
            id: item.id.to_string(),
            kind: item.kind,
            title: item.title,
        });
    }
    Ok(views)
}

fn set_item_links_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
    links: Vec<String>,
) -> Result<u64, String> {
    let parsed_id = id
        .parse()
        .map_err(|_| "The record identifier is invalid.".to_owned())?;
    if parsed_id == EMERGENCY_CARD_ID {
        return Err("The emergency card cannot be linked.".to_owned());
    }
    let mut parsed_links = Vec::with_capacity(links.len());
    for link in links {
        let parsed = link
            .parse()
            .map_err(|_| "One of the linked records is invalid.".to_owned())?;
        if parsed == EMERGENCY_CARD_ID {
            return Err("The emergency card cannot be linked.".to_owned());
        }
        parsed_links.push(parsed);
    }
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before editing a record.".to_owned())?;
    let (mut item, current_revision) = session
        .get_item_with_revision(parsed_id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err("This record changed since you opened it. Reload it before saving.".to_owned());
    }
    item.links = parsed_links;
    session
        .update_item(&item, revision)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This record changed since you opened it. Reload it before saving.".to_owned()
            }
            other => safe_vault_error(other),
        })
}

fn get_item_legacy_disposition_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
) -> Result<LegacyDisposition, String> {
    let id = id
        .parse()
        .map_err(|_| "The record identifier is invalid.".to_owned())?;
    if id == EMERGENCY_CARD_ID {
        return Err("The emergency card does not support a legacy preference.".to_owned());
    }
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading the legacy plan.".to_owned())?;
    let (item, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This record changed since you opened it. Reload it before continuing.".to_owned(),
        );
    }
    Ok(item.legacy_disposition)
}

fn set_item_legacy_disposition_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
    disposition: LegacyDisposition,
) -> Result<u64, String> {
    let id = id
        .parse()
        .map_err(|_| "The record identifier is invalid.".to_owned())?;
    if id == EMERGENCY_CARD_ID {
        return Err("The emergency card does not support a legacy preference.".to_owned());
    }
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before changing the legacy plan.".to_owned())?;
    session
        .set_legacy_disposition(id, revision, disposition)
        .map_err(|error| match error {
            VaultError::Storage(StorageError::StaleRevision) => {
                "This record changed since you opened it. Reload it before saving.".to_owned()
            }
            other => safe_vault_error(other),
        })
}

fn get_credential_closure_plan_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
) -> Result<AccountClosurePlan, String> {
    let id = id
        .parse()
        .map_err(|_| "The credential identifier is invalid.".to_owned())?;
    if id == EMERGENCY_CARD_ID {
        return Err("The emergency card does not support an account closure plan.".to_owned());
    }
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading the account closure plan.".to_owned())?;
    let (item, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This credential changed since you opened it. Reload it before continuing.".to_owned(),
        );
    }
    if item.kind != ItemKind::Password {
        return Err("Only credentials support an account closure plan.".to_owned());
    }
    Ok(item.account_closure_plan)
}

fn set_credential_closure_plan_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
    plan: AccountClosurePlan,
) -> Result<u64, String> {
    let id = id
        .parse()
        .map_err(|_| "The credential identifier is invalid.".to_owned())?;
    if id == EMERGENCY_CARD_ID {
        return Err("The emergency card does not support an account closure plan.".to_owned());
    }
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before changing the account closure plan.".to_owned())?;
    session
        .set_account_closure_plan(id, revision, plan)
        .map_err(|error| match error {
            VaultError::Storage(StorageError::StaleRevision) => {
                "This credential changed since you opened it. Reload it before saving.".to_owned()
            }
            VaultError::InvalidAccountClosurePlan => {
                "Only credentials support an account closure plan.".to_owned()
            }
            other => safe_vault_error(other),
        })
}

fn list_item_history_impl(
    state: &VaultRuntime,
    id: String,
    current_revision: u64,
) -> Result<Vec<u64>, String> {
    let id = id
        .parse()
        .map_err(|_| "The record identifier is invalid.".to_owned())?;
    let generation = capture_session_generation(state);
    let session = lock_session(state)?;
    if !is_session_generation_current(state, generation) {
        return Err(history_session_changed_error());
    }
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading version history.".to_owned())?;
    let revisions = session
        .list_item_history_revisions(id, current_revision)
        .map_err(map_history_error)?;
    if !is_session_generation_current(state, generation) {
        return Err(history_session_changed_error());
    }
    Ok(revisions)
}

fn get_item_history_detail_impl(
    state: &VaultRuntime,
    id: String,
    current_revision: u64,
    history_revision: u64,
) -> Result<ItemHistoryDetailView, String> {
    let id = id
        .parse()
        .map_err(|_| "The record identifier is invalid.".to_owned())?;
    let generation = capture_session_generation(state);
    let session = lock_session(state)?;
    if !is_session_generation_current(state, generation) {
        return Err(history_session_changed_error());
    }
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading version history.".to_owned())?;
    let item = session
        .get_item_history(id, current_revision, history_revision)
        .map_err(map_history_error)?;
    if !is_session_generation_current(state, generation) {
        return Err(history_session_changed_error());
    }
    item_history_detail_view(item, history_revision)
}

fn reveal_item_history_sensitive_impl(
    state: &VaultRuntime,
    id: String,
    current_revision: u64,
    history_revision: u64,
    field: ItemHistorySensitiveField,
) -> Result<String, String> {
    let id = id
        .parse()
        .map_err(|_| "The record identifier is invalid.".to_owned())?;
    let generation = capture_session_generation(state);
    let session = lock_session(state)?;
    if !is_session_generation_current(state, generation) {
        return Err(history_session_changed_error());
    }
    let item = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before revealing version history.".to_owned())?
        .get_item_history(id, current_revision, history_revision)
        .map_err(map_history_error)?;
    let field_name = match (item.kind, field) {
        (ItemKind::Password, ItemHistorySensitiveField::Password) => "password",
        (ItemKind::Document, ItemHistorySensitiveField::DocumentNumber) => "document_number",
        (ItemKind::Receipt, ItemHistorySensitiveField::ReceiptReference) => "receipt_reference",
        (ItemKind::Insurance, ItemHistorySensitiveField::PolicyNumber) => "policy_number",
        (ItemKind::Financial, ItemHistorySensitiveField::AccountNumber) => "account_number",
        (ItemKind::Property, ItemHistorySensitiveField::Address) => "address",
        (ItemKind::Property, ItemHistorySensitiveField::PropertyReference) => "property_reference",
        (ItemKind::Vehicle, ItemHistorySensitiveField::RegistrationNumber) => "registration_number",
        (ItemKind::Vehicle, ItemHistorySensitiveField::Vin) => "vin",
        (ItemKind::Possession, ItemHistorySensitiveField::SerialNumber) => "serial_number",
        _ => return Err("That protected field is not available for this record type.".to_owned()),
    };
    let value = item.fields.get(field_name).cloned().ok_or_else(|| {
        "The encrypted historical record is missing a protected field.".to_owned()
    })?;
    if !is_session_generation_current(state, generation) {
        return Err(history_session_changed_error());
    }
    Ok(value)
}

fn history_session_changed_error() -> String {
    "The vault session changed while version history was loading. Reopen the record and try again."
        .to_owned()
}

fn map_history_error(error: VaultError) -> String {
    match error {
        VaultError::Storage(StorageError::StaleRevision) => {
            "This record changed since version history was opened. Reload it before continuing."
                .to_owned()
        }
        VaultError::HistoryNotAvailable => {
            "That historical version is no longer available.".to_owned()
        }
        other => safe_vault_error(other),
    }
}

fn attachment_summary_view(summary: CoreAttachmentSummary) -> AttachmentSummaryView {
    AttachmentSummaryView {
        id: summary.id.to_string(),
        revision: summary.revision,
        filename: summary.filename,
        plaintext_size: summary.plaintext_size,
    }
}

#[cfg(test)]
fn add_attachment_impl(
    state: &VaultRuntime,
    owner_item_id: String,
    expected_item_revision: u64,
    source_path: PathBuf,
) -> Result<AttachmentAddView, String> {
    add_attachment_impl_inner(
        state,
        owner_item_id,
        expected_item_revision,
        source_path,
        None,
    )
}

fn add_attachment_impl_for_generation(
    state: &VaultRuntime,
    owner_item_id: String,
    expected_item_revision: u64,
    source_path: PathBuf,
    expected_session_generation: u64,
) -> Result<AttachmentAddView, String> {
    add_attachment_impl_inner(
        state,
        owner_item_id,
        expected_item_revision,
        source_path,
        Some(expected_session_generation),
    )
}

fn add_attachment_impl_inner(
    state: &VaultRuntime,
    owner_item_id: String,
    expected_item_revision: u64,
    source_path: PathBuf,
    expected_session_generation: Option<u64>,
) -> Result<AttachmentAddView, String> {
    let owner_item_id = owner_item_id
        .parse()
        .map_err(|_| "The attachment owner identifier is invalid.".to_owned())?;
    if source_path.as_os_str().is_empty() {
        return Err("Choose a file to attach.".to_owned());
    }
    let generation = match expected_session_generation {
        Some(generation) => generation,
        None => capture_unlocked_session_generation(state)?,
    };
    if !is_session_generation_current(state, generation) {
        return Err(attachment_session_changed_error());
    }

    // Opening/stat'ing and reading the selected file must never hold the vault-session
    // mutex. The prepared plan contains only per-file crypto context plus ciphertext.
    let source = AttachmentImportSource::open(source_path).map_err(safe_vault_error)?;
    if !is_session_generation_current(state, generation) {
        return Err(attachment_session_changed_error());
    }
    let plan = {
        let session = lock_session(state)?;
        if !is_session_generation_current(state, generation) {
            return Err(attachment_session_changed_error());
        }
        let session = session
            .as_ref()
            .ok_or_else(|| "Unlock the vault before adding an attachment.".to_owned())?;
        session
            .prepare_attachment_import(owner_item_id, expected_item_revision, &source)
            .map_err(map_attachment_import_error)?
    };
    let prepared = plan
        .encrypt_source(source, || !is_session_generation_current(state, generation))
        .map_err(map_attachment_operation_error)?;
    let (attachment, item_revision) = {
        let session = lock_session(state)?;
        if !is_session_generation_current(state, generation) {
            return Err(attachment_session_changed_error());
        }
        let session = session
            .as_ref()
            .ok_or_else(|| "Unlock the vault before adding an attachment.".to_owned())?;
        session
            .commit_attachment_import(prepared)
            .map_err(map_attachment_import_error)?
    };
    Ok(AttachmentAddView {
        attachment: attachment_summary_view(attachment),
        item_revision,
    })
}

fn list_attachments_impl(
    state: &VaultRuntime,
    owner_item_id: String,
) -> Result<Vec<AttachmentSummaryView>, String> {
    let owner_item_id = owner_item_id
        .parse()
        .map_err(|_| "The attachment owner identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading attachments.".to_owned())?;
    session
        .list_attachments(owner_item_id)
        .map_err(safe_vault_error)
        .map(|attachments| {
            attachments
                .into_iter()
                .map(attachment_summary_view)
                .collect()
        })
}

fn attachment_filename_impl(
    state: &VaultRuntime,
    owner_item_id: &str,
    attachment_id: &str,
) -> Result<(String, u64), String> {
    let owner_item_id = owner_item_id
        .parse()
        .map_err(|_| "The attachment owner identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before exporting an attachment.".to_owned())?;
    let filename = session
        .list_attachments(owner_item_id)
        .map_err(safe_vault_error)?
        .into_iter()
        .find(|attachment| attachment.id.to_string() == attachment_id)
        .ok_or_else(|| "This attachment does not belong to the selected record.".to_owned())?
        .filename;
    Ok((filename, capture_session_generation(state)))
}

#[cfg(test)]
fn export_attachment_impl(
    state: &VaultRuntime,
    owner_item_id: String,
    attachment_id: String,
    destination_path: PathBuf,
) -> Result<(), String> {
    export_attachment_impl_inner(state, owner_item_id, attachment_id, destination_path, None)
}

fn export_attachment_impl_for_generation(
    state: &VaultRuntime,
    owner_item_id: String,
    attachment_id: String,
    destination_path: PathBuf,
    expected_session_generation: u64,
) -> Result<(), String> {
    export_attachment_impl_inner(
        state,
        owner_item_id,
        attachment_id,
        destination_path,
        Some(expected_session_generation),
    )
}

fn export_attachment_impl_inner(
    state: &VaultRuntime,
    owner_item_id: String,
    attachment_id: String,
    destination_path: PathBuf,
    expected_session_generation: Option<u64>,
) -> Result<(), String> {
    let owner_item_id = owner_item_id
        .parse()
        .map_err(|_| "The attachment owner identifier is invalid.".to_owned())?;
    let attachment_id = attachment_id
        .parse()
        .map_err(|_| "The attachment identifier is invalid.".to_owned())?;
    if destination_path.as_os_str().is_empty() {
        return Err("Choose where to save the attachment.".to_owned());
    }
    let generation = match expected_session_generation {
        Some(generation) => generation,
        None => capture_unlocked_session_generation(state)?,
    };
    let plan = {
        let session = lock_session(state)?;
        if !is_session_generation_current(state, generation) {
            return Err(attachment_session_changed_error());
        }
        let session = session
            .as_ref()
            .ok_or_else(|| "Unlock the vault before exporting an attachment.".to_owned())?;
        session
            .prepare_attachment_export(owner_item_id, attachment_id)
            .map_err(safe_vault_error)?
    };
    plan.write_to_path(destination_path, || {
        !is_session_generation_current(state, generation)
    })
    .map_err(map_attachment_operation_error)
}

fn attachment_session_changed_error() -> String {
    "The vault session changed during the attachment operation. Try again after unlocking."
        .to_owned()
}

fn map_attachment_operation_error(error: VaultError) -> String {
    match error {
        VaultError::AttachmentOperationCancelled => attachment_session_changed_error(),
        other => safe_vault_error(other),
    }
}

fn map_attachment_import_error(error: VaultError) -> String {
    match error {
        VaultError::Storage(StorageError::StaleRevision) => {
            "This record changed since you opened it. Reload it before adding an attachment."
                .to_owned()
        }
        VaultError::AttachmentOperationCancelled => attachment_session_changed_error(),
        other => safe_vault_error(other),
    }
}

fn delete_attachment_impl(
    state: &VaultRuntime,
    owner_item_id: String,
    attachment_id: String,
    expected_item_revision: u64,
    expected_attachment_revision: u64,
) -> Result<u64, String> {
    let owner_item_id = owner_item_id
        .parse()
        .map_err(|_| "The attachment owner identifier is invalid.".to_owned())?;
    let attachment_id = attachment_id
        .parse()
        .map_err(|_| "The attachment identifier is invalid.".to_owned())?;
    let deleted_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "The system clock is unavailable.".to_owned())?
        .as_millis();
    let deleted_at_ms =
        u64::try_from(deleted_at_ms).map_err(|_| "The system clock is unavailable.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before deleting an attachment.".to_owned())?;
    session
        .delete_attachment(
            owner_item_id,
            attachment_id,
            expected_item_revision,
            expected_attachment_revision,
            deleted_at_ms,
        )
        .map_err(|error| match error {
            VaultError::Storage(StorageError::StaleRevision) => {
                "This record or attachment changed since you opened it. Reload before deleting the attachment."
                    .to_owned()
            }
            other => safe_vault_error(other),
        })
}

fn list_deadlines_impl(
    state: &VaultRuntime,
    today_year: i32,
    today_month: u32,
    today_day: u32,
) -> Result<Vec<DeadlineView>, String> {
    let encoded_today = format!("{today_year:04}-{today_month:02}-{today_day:02}");
    let today = parse_ymd(&encoded_today)
        .filter(|date| *date == (today_year, today_month, today_day))
        .ok_or_else(|| "The device local calendar date is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading reminders.".to_owned())?;
    let items = session.list_items().map_err(safe_vault_error)?;
    let deadlines = collect_deadlines(&items, today);
    Ok(deadlines
        .into_iter()
        .map(|deadline| DeadlineView {
            item_id: deadline.item_id.to_string(),
            kind: deadline.kind,
            title: deadline.title,
            label: deadline.label.to_owned(),
            date: deadline.date,
            days_until: deadline.days_until,
        })
        .collect())
}

fn generate_recovery_secret_impl(
    state: &VaultRuntime,
) -> Result<GeneratedRecoverySecretView, String> {
    let session = lock_session(state)?;
    if session.is_none() {
        return Err("Unlock the vault before generating a recovery secret.".to_owned());
    }
    let generation = capture_session_generation(state);
    let secret = Zeroizing::new(
        RecoverySecret::generate()
            .map_err(safe_vault_error)?
            .to_hex(),
    );
    Ok(GeneratedRecoverySecretView { secret, generation })
}

fn confirm_recovery_secret_impl(
    state: &VaultRuntime,
    secret: String,
    expected_generation: u64,
) -> Result<(), String> {
    let secret = Zeroizing::new(secret);
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before confirming the recovery secret.".to_owned())?;
    if capture_session_generation(state) != expected_generation {
        return Err(
            "The vault session changed after this recovery key was generated. Generate a new recovery key and try again."
                .to_owned(),
        );
    }
    let parsed = RecoverySecret::from_hex(secret.trim()).map_err(|_| {
        "The recovery secret is invalid. Check all 64 characters and try again.".to_owned()
    })?;
    session
        .install_recovery_kit(&parsed)
        .map_err(safe_vault_error)
}

fn require_recovery_generation(
    state: &VaultRuntime,
    expected_generation: u64,
    action: &str,
) -> Result<(), String> {
    let session = lock_session(state)?;
    if session.is_none() {
        return Err(format!("Unlock the vault before {action}."));
    }
    if capture_session_generation(state) != expected_generation {
        return Err(
            "The vault session changed after this recovery key was generated. Generate a new recovery key and try again."
                .to_owned(),
        );
    }
    Ok(())
}

fn save_recovery_secret_impl_for_generation(
    state: &VaultRuntime,
    secret: &str,
    expected_generation: u64,
    destination: &Path,
) -> Result<(), String> {
    require_recovery_generation(state, expected_generation, "saving the recovery key")?;
    let parsed = RecoverySecret::from_hex(secret.trim()).map_err(|_| {
        "The recovery secret is invalid. Generate a new recovery key and try again.".to_owned()
    })?;
    let canonical = Zeroizing::new(parsed.to_hex());
    const SESSION_CHANGED: &str = "The vault session changed while saving the recovery key. Generate a new recovery key and try again.";
    if !is_session_generation_current(state, expected_generation) {
        return Err(SESSION_CHANGED.to_owned());
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(destination)
        .map_err(|_| {
            "Unable to create the recovery-key file. Choose a new filename in a trusted location and try again."
                .to_owned()
        })?;
    let write_result = (|| -> Result<(), std::io::Error> {
        file.write_all(canonical.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(destination);
        let _ = sync_recovery_secret_parent(destination);
        return Err(
            "Unable to create the recovery-key file. Choose a new filename in a trusted location and try again."
                .to_owned(),
        );
    }
    if let Err(error) = sync_recovery_secret_parent(destination) {
        let _ = fs::remove_file(destination);
        let _ = sync_recovery_secret_parent(destination);
        return Err(error);
    }
    if !is_session_generation_current(state, expected_generation) {
        let _ = fs::remove_file(destination);
        let _ = sync_recovery_secret_parent(destination);
        return Err(SESSION_CHANGED.to_owned());
    }
    Ok(())
}

fn sync_recovery_secret_parent(destination: &Path) -> Result<(), String> {
    sync_parent_directory(destination)
        .map_err(|_| "Unable to durably save the recovery-key file in this location.".to_owned())
}

fn sync_parent_directory(path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
        })?;
        fs::File::open(parent)?.sync_all()
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn get_recovery_status_impl(state: &VaultRuntime) -> Result<RecoveryStatusView, String> {
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading the recovery status.".to_owned())?;
    Ok(RecoveryStatusView {
        configured: session.has_recovery_kit().map_err(safe_vault_error)?,
    })
}

fn verify_recovery_secret_impl(state: &VaultRuntime, secret: String) -> Result<bool, String> {
    let secret = Zeroizing::new(secret);
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before testing the recovery key.".to_owned())?;
    let Ok(parsed) = RecoverySecret::from_hex(secret.trim()) else {
        return Ok(false);
    };
    session
        .verify_recovery_kit(&parsed)
        .map_err(safe_vault_error)
}

fn get_plan_readiness_impl(state: &VaultRuntime) -> Result<PlanReadinessView, String> {
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before testing the emergency plan.".to_owned())?;
    let recovery_configured = session.has_recovery_kit().map_err(safe_vault_error)?;
    let active_items = session.list_items().map_err(safe_vault_error)?;
    let mut has_legacy_preferences = false;
    let mut has_unspecified_legacy_items = false;
    for item in &active_items {
        if item.id == EMERGENCY_CARD_ID {
            continue;
        }
        if item.legacy_disposition == LegacyDisposition::Unspecified {
            has_unspecified_legacy_items = true;
        } else {
            has_legacy_preferences = true;
        }
    }
    let card = session.get_emergency_card().map_err(safe_vault_error)?;
    let Some((card, _revision)) = card else {
        return Ok(PlanReadinessView {
            recovery_configured,
            has_selected_records: false,
            has_contacts: false,
            has_instructions: false,
            has_stale_selected_records: false,
            has_legacy_preferences,
            has_unspecified_legacy_items,
        });
    };
    let mut has_selected_records = false;
    let mut has_stale_selected_records = false;
    for id in &card.selected_item_ids {
        if *id == EMERGENCY_CARD_ID {
            has_stale_selected_records = true;
            continue;
        }
        match session.get_item_with_revision(*id) {
            Ok(_) => has_selected_records = true,
            Err(VaultError::ItemNotActive)
            | Err(VaultError::Storage(StorageError::ItemNotFound)) => {
                has_stale_selected_records = true;
            }
            Err(error) => return Err(safe_vault_error(error)),
        }
    }
    Ok(PlanReadinessView {
        recovery_configured,
        has_selected_records,
        has_contacts: card.contacts.iter().any(|contact| {
            !contact.name.trim().is_empty()
                && (!contact.phone.trim().is_empty() || !contact.email.trim().is_empty())
        }),
        has_instructions: !card.instructions.trim().is_empty(),
        has_stale_selected_records,
        has_legacy_preferences,
        has_unspecified_legacy_items,
    })
}

fn unlock_vault_with_recovery_kit_impl(
    state: &VaultRuntime,
    secret: String,
) -> Result<VaultStatus, String> {
    let secret = Zeroizing::new(secret);
    let parsed = RecoverySecret::from_hex(secret.trim()).map_err(|_| {
        "Unable to unlock with this recovery kit. Check the secret and try again.".to_owned()
    })?;
    let opened =
        VaultSession::unlock_with_recovery_kit(&state.database_path, &parsed).map_err(|_| {
            "Unable to unlock with this recovery kit. Check the secret and try again.".to_owned()
        })?;
    let mut session = lock_session(state)?;
    *session = Some(opened);
    advance_session_generation(&state.session_generation);
    Ok(VaultStatus {
        initialized: true,
        unlocked: true,
        cloud_sync_enabled: false,
    })
}

struct HumanReadableExportSnapshot {
    items: Vec<(VaultItem, u64)>,
    emergency_card: Option<(EmergencyCard, u64)>,
    generation: u64,
}

#[cfg(test)]
fn export_human_readable_impl(state: &VaultRuntime, path: String) -> Result<ExportView, String> {
    let generation = capture_export_generation(state, "exporting records")?;
    export_human_readable_impl_for_generation(state, path, generation)
}

fn export_human_readable_impl_for_generation(
    state: &VaultRuntime,
    path: String,
    expected_generation: u64,
) -> Result<ExportView, String> {
    if path.trim().is_empty() {
        return Err("Choose a location for the export.".to_owned());
    }
    let destination = PathBuf::from(&path);
    reject_active_database_destination(
        state,
        &destination,
        "Choose an export path other than the active Safeory database.",
    )?;
    if !is_session_generation_current(state, expected_generation) {
        return Err("The vault session changed while creating the export. Try again.".to_owned());
    }
    let HumanReadableExportSnapshot {
        items,
        emergency_card,
        generation,
    } = capture_human_readable_export(state)?;
    if generation != expected_generation {
        return Err("The vault session changed while creating the export. Try again.".to_owned());
    }
    let (staged, item_count) =
        stage_human_readable_export_with_cancel(&items, emergency_card, &destination, || {
            !is_session_generation_current(state, generation)
        })?;
    commit_human_readable_export(state, generation, &staged, &destination)?;
    Ok(ExportView {
        items: item_count,
        path,
    })
}

fn capture_human_readable_export(
    state: &VaultRuntime,
) -> Result<HumanReadableExportSnapshot, String> {
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before exporting records.".to_owned())?;
    let generation = capture_session_generation(state);
    let items = session
        .list_items_with_revisions()
        .map_err(safe_vault_error)?;
    let emergency_card = session.get_emergency_card().map_err(safe_vault_error)?;
    Ok(HumanReadableExportSnapshot {
        items,
        emergency_card,
        generation,
    })
}

#[cfg(test)]
fn stage_human_readable_export(
    items: &[(VaultItem, u64)],
    card: Option<(EmergencyCard, u64)>,
    destination: &Path,
) -> Result<(PathBuf, u64), String> {
    stage_human_readable_export_with_cancel(items, card, destination, || false)
}

fn stage_human_readable_export_with_cancel<F>(
    items: &[(VaultItem, u64)],
    card: Option<(EmergencyCard, u64)>,
    destination: &Path,
    should_cancel: F,
) -> Result<(PathBuf, u64), String>
where
    F: Fn() -> bool,
{
    const SESSION_CHANGED: &str = "The vault session changed while creating the export. Try again.";
    const WRITE_FAILED: &str =
        "Unable to write the export file. Choose a different location and try again.";
    const WRITE_CHUNK_BYTES: usize = 64 * 1024;

    if should_cancel() {
        return Err(SESSION_CHANGED.to_owned());
    }
    let item_count = u64::try_from(
        items
            .iter()
            .filter(|(item, _)| item.kind != ItemKind::EmergencyInstruction)
            .count(),
    )
    .map_err(safe_vault_error)?;
    let exported_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(safe_vault_error)?
        .as_millis();
    let exported_at_ms =
        u64::try_from(exported_at_ms).map_err(|_| "The system clock is unavailable.".to_owned())?;
    let mut export_items = Vec::with_capacity(items.len());
    for (item, revision) in items {
        if item.kind == ItemKind::EmergencyInstruction {
            continue;
        }
        export_items.push(serde_json::json!({
            "id": item.id.to_string(),
            "kind": item.kind,
            "title": item.title,
            "links": item.links.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "legacy_disposition": item.legacy_disposition,
            "account_closure_plan": item.account_closure_plan,
            "fields": item.fields,
            "notes": item.notes,
            "revision": revision,
        }));
    }
    let emergency_card = card
        .map(|(card, _)| serde_json::to_value(emergency_card_payload(card)))
        .transpose()
        .map_err(safe_vault_error)?
        .unwrap_or(serde_json::Value::Null);
    if should_cancel() {
        return Err(SESSION_CHANGED.to_owned());
    }
    let document = serde_json::json!({
        "app": "safeory",
        "format": 1,
        "exported_at_ms": exported_at_ms,
        "scope": "active_records_only",
        "binary_attachments_included": false,
        "items": export_items,
        "emergency_card": emergency_card,
    });
    let encoded = serde_json::to_vec_pretty(&document).map_err(safe_vault_error)?;
    if should_cancel() {
        return Err(SESSION_CHANGED.to_owned());
    }
    let staged = temporary_sibling_path(destination, "export")?;
    let mut staged_file = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
    {
        Ok(file) => file,
        Err(_) => return Err(WRITE_FAILED.to_owned()),
    };
    let write_result = (|| -> Result<(), String> {
        for chunk in encoded.chunks(WRITE_CHUNK_BYTES) {
            if should_cancel() {
                return Err(SESSION_CHANGED.to_owned());
            }
            staged_file
                .write_all(chunk)
                .map_err(|_| WRITE_FAILED.to_owned())?;
            if should_cancel() {
                return Err(SESSION_CHANGED.to_owned());
            }
        }
        staged_file.flush().map_err(|_| WRITE_FAILED.to_owned())?;
        if should_cancel() {
            return Err(SESSION_CHANGED.to_owned());
        }
        Ok(())
    })();
    drop(staged_file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    Ok((staged, item_count))
}

fn commit_human_readable_export(
    state: &VaultRuntime,
    generation: u64,
    staged: &Path,
    destination: &Path,
) -> Result<(), String> {
    const SESSION_CHANGED: &str = "The vault session changed while creating the export. Try again.";

    if !is_session_generation_current(state, generation) {
        let _ = fs::remove_file(staged);
        return Err(SESSION_CHANGED.to_owned());
    }

    let rollback = match temporary_sibling_path(destination, "previous") {
        Ok(rollback) => rollback,
        Err(error) => {
            let _ = fs::remove_file(staged);
            return Err(error);
        }
    };
    let had_destination = destination.exists();
    if had_destination && fs::rename(destination, &rollback).is_err() {
        let _ = fs::remove_file(staged);
        return Err("Unable to replace the existing output file.".to_owned());
    }

    if !is_session_generation_current(state, generation) {
        if had_destination {
            let _ = fs::rename(&rollback, destination);
        }
        let _ = fs::remove_file(staged);
        return Err(SESSION_CHANGED.to_owned());
    }

    if fs::rename(staged, destination).is_err() {
        if had_destination {
            let _ = fs::rename(&rollback, destination);
        }
        let _ = fs::remove_file(staged);
        return Err("Unable to finish writing the selected output file.".to_owned());
    }

    if !is_session_generation_current(state, generation) {
        let _ = fs::remove_file(destination);
        if had_destination {
            let _ = fs::rename(&rollback, destination);
        }
        return Err(SESSION_CHANGED.to_owned());
    }

    if had_destination {
        let _ = fs::remove_file(&rollback);
    }
    Ok(())
}

#[cfg(test)]
fn backup_database_copy_impl(
    state: &VaultRuntime,
    path: String,
) -> Result<BackupCopyResult, String> {
    let generation = capture_export_generation(state, "backing up the vault")?;
    backup_database_copy_impl_for_generation(state, path, generation)
}

fn backup_database_copy_impl_for_generation(
    state: &VaultRuntime,
    path: String,
    expected_generation: u64,
) -> Result<BackupCopyResult, String> {
    let destination = PathBuf::from(path.trim());
    if path.trim().is_empty() {
        return Err("Choose a location for the encrypted backup.".to_owned());
    }
    reject_active_database_destination(
        state,
        &destination,
        "Choose a backup path other than the active Safeory database.",
    )?;
    if !is_session_generation_current(state, expected_generation) {
        return Err("The vault session changed while creating the backup. Try again.".to_owned());
    }
    let (plan, generation) = capture_database_backup_plan(state)?;
    if generation != expected_generation {
        return Err("The vault session changed while creating the backup. Try again.".to_owned());
    }
    let staged = temporary_sibling_path(&destination, "backup")?;
    if let Err(error) = plan.write_validated_to(&staged, || {
        !is_session_generation_current(state, generation)
    }) {
        let _ = fs::remove_file(&staged);
        if matches!(error, VaultError::OperationCancelled) {
            return Err(
                "The vault session changed while creating the backup. Try again.".to_owned(),
            );
        }
        return Err(format!(
            "Unable to create a validated encrypted backup: {error}"
        ));
    }
    commit_database_backup_copy(state, generation, &staged, &destination)?;
    let settings = record_successful_backup_creation(state).ok();
    Ok(BackupCopyResult { settings })
}

fn capture_export_generation(state: &VaultRuntime, action: &str) -> Result<u64, String> {
    let session = lock_session(state)?;
    if session.is_none() {
        return Err(format!("Unlock the vault before {action}."));
    }
    Ok(capture_session_generation(state))
}

fn reject_active_database_destination(
    state: &VaultRuntime,
    destination: &Path,
    message: &str,
) -> Result<(), String> {
    if state.database_path.exists()
        && destination.exists()
        && fs::canonicalize(destination).ok() == fs::canonicalize(&state.database_path).ok()
    {
        return Err(message.to_owned());
    }
    Ok(())
}

fn capture_database_backup_plan(state: &VaultRuntime) -> Result<(VaultBackupPlan, u64), String> {
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before backing up the vault.".to_owned())?;
    let generation = capture_session_generation(state);
    let plan = session
        .prepare_database_backup(&state.database_path)
        .map_err(safe_vault_error)?;
    Ok((plan, generation))
}

fn commit_database_backup_copy(
    state: &VaultRuntime,
    generation: u64,
    staged: &Path,
    destination: &Path,
) -> Result<(), String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "The local vault session is unavailable.".to_owned())?;
    if session.is_none() || !is_session_generation_current(state, generation) {
        drop(session);
        let _ = fs::remove_file(staged);
        return Err("The vault session changed while creating the backup. Try again.".to_owned());
    }
    install_output_file(staged, destination).inspect_err(|_error| {
        let _ = fs::remove_file(staged);
    })
}

fn restore_database_backup_impl(
    state: &VaultRuntime,
    path: String,
    passphrase: String,
) -> Result<VaultStatus, String> {
    let passphrase = Zeroizing::new(passphrase);
    let source = database_restore_source(state, &path)?;
    let initialized = if state.database_path.exists() {
        VaultSession::is_initialized(&state.database_path).map_err(safe_vault_error)?
    } else {
        false
    };
    let generation = authorize_database_restore(state, initialized)?;
    let preparation = prepare_database_restore_candidate(state, generation, &source, &passphrase);
    drop(passphrase);
    let (candidate, prepared) = preparation?;
    commit_database_restore(state, initialized, generation, &candidate, prepared)
}

fn restore_database_backup_with_recovery_kit_impl(
    state: &VaultRuntime,
    path: String,
    secret: String,
    new_passphrase: String,
) -> Result<VaultStatus, String> {
    let secret = Zeroizing::new(secret);
    let new_passphrase = Zeroizing::new(new_passphrase);
    if new_passphrase.chars().count() < 12 {
        return Err("Use at least 12 characters for the new master passphrase.".to_owned());
    }
    let source = database_restore_source(state, &path)?;
    let initialized = if state.database_path.exists() {
        VaultSession::is_initialized(&state.database_path).map_err(safe_vault_error)?
    } else {
        false
    };
    let generation = authorize_database_restore(state, initialized)?;
    let parsed = RecoverySecret::from_hex(secret.trim()).map_err(|_| {
        "Unable to validate this backup with the recovery key. Check the key and make sure the file is a complete Safeory encrypted backup.".to_owned()
    })?;
    let preparation = prepare_database_restore_candidate_with_recovery_kit(
        state,
        generation,
        &source,
        &parsed,
        &new_passphrase,
    );
    drop(parsed);
    drop(secret);
    drop(new_passphrase);
    let (candidate, prepared) = preparation?;
    commit_database_restore(state, initialized, generation, &candidate, prepared)
}

fn database_restore_source(state: &VaultRuntime, path: &str) -> Result<PathBuf, String> {
    let source = PathBuf::from(path.trim());
    if path.trim().is_empty() || !source.is_file() {
        return Err("Choose an existing Safeory encrypted backup file.".to_owned());
    }
    if state.database_path.exists()
        && fs::canonicalize(&source).ok() == fs::canonicalize(&state.database_path).ok()
    {
        return Err("Choose a backup file other than the active Safeory database.".to_owned());
    }
    Ok(source)
}

fn authorize_database_restore(state: &VaultRuntime, initialized: bool) -> Result<u64, String> {
    let live_session = lock_session(state)?;
    if initialized && live_session.is_none() {
        return Err("Unlock the current vault before replacing it from a backup.".to_owned());
    }
    Ok(capture_session_generation(state))
}

fn prepare_database_restore_candidate(
    state: &VaultRuntime,
    generation: u64,
    source: &Path,
    passphrase: &str,
) -> Result<(PathBuf, PreparedVaultRestore), String> {
    let candidate = copy_database_restore_candidate(state, source)?;
    let prepared = match VaultSession::prepare_restore_with_cancel(&candidate, passphrase, || {
        !is_session_generation_current(state, generation)
    }) {
        Ok(prepared) => prepared,
        Err(VaultError::OperationCancelled) => {
            let _ = fs::remove_file(&candidate);
            return Err(
                "The vault session changed while validating the restore. Try again.".to_owned(),
            );
        }
        Err(error) => {
            let _ = fs::remove_file(&candidate);
            return Err(backup_validation_error(error));
        }
    };
    Ok((candidate, prepared))
}

fn prepare_database_restore_candidate_with_recovery_kit(
    state: &VaultRuntime,
    generation: u64,
    source: &Path,
    secret: &RecoverySecret,
    new_passphrase: &str,
) -> Result<(PathBuf, PreparedVaultRestore), String> {
    let candidate = copy_database_restore_candidate(state, source)?;
    let prepared = match VaultSession::prepare_restore_with_recovery_kit_with_cancel(
        &candidate,
        secret,
        || !is_session_generation_current(state, generation),
    ) {
        Ok(prepared) => prepared,
        Err(VaultError::OperationCancelled) => {
            let _ = fs::remove_file(&candidate);
            return Err(
                "The vault session changed while validating the restore. Try again.".to_owned(),
            );
        }
        Err(error) => {
            let _ = fs::remove_file(&candidate);
            return Err(backup_recovery_validation_error(error));
        }
    };
    if !is_session_generation_current(state, generation) {
        let _ = fs::remove_file(&candidate);
        return Err(
            "The vault session changed while validating the restore. Try again.".to_owned(),
        );
    }
    let prepared = match prepared.rewrap_candidate_master_passphrase(new_passphrase) {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = fs::remove_file(&candidate);
            return Err(backup_recovery_validation_error(error));
        }
    };
    if !is_session_generation_current(state, generation) {
        let _ = fs::remove_file(&candidate);
        return Err(
            "The vault session changed while validating the restore. Try again.".to_owned(),
        );
    }
    Ok((candidate, prepared))
}

fn copy_database_restore_candidate(state: &VaultRuntime, source: &Path) -> Result<PathBuf, String> {
    let parent = state
        .database_path
        .parent()
        .ok_or_else(|| "The Safeory app-data directory is unavailable.".to_owned())?;
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "The system clock is unavailable.".to_owned())?
        .as_nanos();
    let candidate = parent.join(format!(
        ".safeory-restore-candidate-{}-{unique}.sqlite3",
        std::process::id()
    ));
    if fs::copy(source, &candidate).is_err() {
        let _ = fs::remove_file(&candidate);
        return Err("Unable to read the selected backup file.".to_owned());
    }
    Ok(candidate)
}

fn commit_database_restore(
    state: &VaultRuntime,
    initialized: bool,
    generation: u64,
    candidate: &Path,
    prepared: PreparedVaultRestore,
) -> Result<VaultStatus, String> {
    let live_session = state
        .session
        .lock()
        .map_err(|_| "The local vault session is unavailable.".to_owned())?;
    if !is_session_generation_current(state, generation)
        || (initialized && live_session.is_none())
        || (!initialized && live_session.is_some())
    {
        let _ = fs::remove_file(candidate);
        return Err("The vault session changed while preparing the restore. Try again.".to_owned());
    }
    if state
        .restore_in_progress
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        drop(live_session);
        let _ = fs::remove_file(candidate);
        return Err("Another vault restore is already being finished. Try again.".to_owned());
    }
    let locked_install = prepared.into_locked_install();
    drop(live_session);

    let restore_result = locked_install.install_to(&state.database_path);
    if let Err(error) = restore_result {
        state.restore_in_progress.store(false, Ordering::Release);
        let _ = fs::remove_file(candidate);
        return Err(backup_install_error(error));
    }
    let mut live_session = state
        .session
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // A restore changes the vault root key and complete encrypted record set.
    // Finish locked so renderer plaintext from the previous vault cannot remain
    // authoritative after the transaction commits.
    *live_session = None;
    advance_session_generation(&state.session_generation);
    state.restore_in_progress.store(false, Ordering::Release);
    drop(live_session);
    let _ = fs::remove_file(candidate);
    if let Ok(mut last_activity) = state.last_activity.lock() {
        *last_activity = Instant::now();
    }
    Ok(VaultStatus {
        initialized: true,
        unlocked: false,
        cloud_sync_enabled: false,
    })
}

fn temporary_sibling_path(destination: &Path, label: &str) -> Result<PathBuf, String> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("safeory");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "The system clock is unavailable.".to_owned())?
        .as_nanos();
    Ok(parent.join(format!(
        ".{file_name}.{label}-{}-{unique}.tmp",
        std::process::id()
    )))
}

fn install_output_file(staged: &Path, destination: &Path) -> Result<(), String> {
    let rollback = temporary_sibling_path(destination, "previous")?;
    let had_destination = destination.exists();
    if had_destination && fs::rename(destination, &rollback).is_err() {
        return Err("Unable to replace the existing output file.".to_owned());
    }
    if fs::rename(staged, destination).is_err() {
        if had_destination {
            let _ = fs::rename(&rollback, destination);
        }
        return Err("Unable to finish writing the selected output file.".to_owned());
    }
    if had_destination {
        let _ = fs::remove_file(&rollback);
    }
    Ok(())
}

fn backup_validation_error(error: VaultError) -> String {
    match error {
        VaultError::Storage(StorageError::UnsupportedSchemaVersion(_)) => {
            "This backup was created by a newer Safeory version and cannot be restored here."
                .to_owned()
        }
        _ => "Unable to validate this backup. Check its master passphrase and make sure the file is a complete Safeory encrypted backup.".to_owned(),
    }
}

fn backup_recovery_validation_error(error: VaultError) -> String {
    match error {
        VaultError::Storage(StorageError::UnsupportedSchemaVersion(_)) => {
            "This backup was created by a newer Safeory version and cannot be restored here."
                .to_owned()
        }
        _ => "Unable to validate this backup with the recovery key. Check the key and make sure the file is a complete Safeory encrypted backup.".to_owned(),
    }
}

fn backup_install_error(error: VaultError) -> String {
    match error {
        VaultError::Storage(StorageError::UnsupportedSchemaVersion(_)) => {
            "This backup was created by a newer Safeory version and cannot be restored here."
                .to_owned()
        }
        _ => "Unable to install the validated encrypted backup. The current vault was not replaced. Try again."
            .to_owned(),
    }
}

#[allow(clippy::too_many_arguments)]
fn update_credential_impl(
    state: &VaultRuntime,
    id: String,
    revision: u64,
    title: String,
    username: String,
    password: String,
    website: String,
    notes: String,
) -> Result<CredentialView, String> {
    let title = title.trim();
    if title.is_empty() {
        return Err("A credential title is required.".to_owned());
    }
    let id = id
        .parse()
        .map_err(|_| "The credential identifier is invalid.".to_owned())?;
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before editing a credential.".to_owned())?;
    let (existing, current_revision) = session
        .get_item_with_revision(id)
        .map_err(safe_vault_error)?;
    if current_revision != revision {
        return Err(
            "This credential changed since you opened it. Reload it before saving.".to_owned(),
        );
    }
    if existing.kind != ItemKind::Password {
        return Err("Only credentials can be edited from this view.".to_owned());
    }
    let mut fields = BTreeMap::new();
    fields.insert("username".to_owned(), username);
    fields.insert("password".to_owned(), password);
    fields.insert("website".to_owned(), website);
    let item = VaultItem {
        id,
        kind: ItemKind::Password,
        title: title.to_owned(),
        links: existing.links.clone(),
        attachments: existing.attachments.clone(),
        legacy_disposition: existing.legacy_disposition,
        account_closure_plan: existing.account_closure_plan.clone(),
        fields,
        notes: (!notes.is_empty()).then_some(notes),
    };
    let revision = session
        .update_item(&item, revision)
        .map_err(|error| match error {
            vault_core::VaultError::Storage(vault_storage::StorageError::StaleRevision) => {
                "This credential changed since you opened it. Reload it before saving.".to_owned()
            }
            other => safe_vault_error(other),
        })?;
    credential_view(item, revision)
}

fn item_history_support_view(item: &VaultItem) -> ItemHistorySupportView {
    ItemHistorySupportView {
        linked_record_count: item.links.len(),
        attachment_count: item.attachments.len(),
        legacy_disposition: item.legacy_disposition,
        account_closure_plan: (item.kind == ItemKind::Password)
            .then(|| item.account_closure_plan.clone()),
    }
}

fn item_history_detail_view(
    item: VaultItem,
    revision: u64,
) -> Result<ItemHistoryDetailView, String> {
    let support = item_history_support_view(&item);
    let notes = item.notes.clone().unwrap_or_default();
    match item.kind {
        ItemKind::SecureNote => {
            let view = note_view(item, revision)?;
            Ok(ItemHistoryDetailView::SecureNote {
                id: view.id,
                revision,
                title: view.title,
                body: view.body,
                support,
            })
        }
        ItemKind::Password => {
            let view = credential_view(item, revision)?;
            Ok(ItemHistoryDetailView::Password {
                id: view.id,
                revision,
                title: view.title,
                username: view.username,
                website: view.website,
                notes: view.notes,
                has_password: view.has_password,
                support,
            })
        }
        ItemKind::Document => {
            let view = document_view(item, revision)?;
            Ok(ItemHistoryDetailView::Document {
                id: view.id,
                revision,
                title: view.title,
                issuer: view.issuer,
                expiry: view.expiry,
                notes: view.notes,
                has_document_number: view.has_document_number,
                support,
            })
        }
        ItemKind::Receipt => {
            let view = receipt_view(item, revision)?;
            Ok(ItemHistoryDetailView::Receipt {
                id: view.id,
                revision,
                title: view.title,
                merchant: view.merchant,
                purchase_date: view.purchase_date,
                amount: view.amount,
                currency: view.currency,
                tracking_status: view.tracking_status,
                return_by: view.return_by,
                refund_due: view.refund_due,
                notes,
                has_receipt_reference: view.has_receipt_reference,
                support,
            })
        }
        ItemKind::Insurance => {
            let view = insurance_view(item, revision)?;
            Ok(ItemHistoryDetailView::Insurance {
                id: view.id,
                revision,
                title: view.title,
                provider: view.provider,
                policy_type: view.policy_type,
                renewal: view.renewal,
                notes: view.notes,
                has_policy_number: view.has_policy_number,
                support,
            })
        }
        ItemKind::Financial => {
            let view = financial_view(item, revision)?;
            Ok(ItemHistoryDetailView::Financial {
                id: view.id,
                revision,
                title: view.title,
                institution: view.institution,
                account_type: view.account_type,
                currency: view.currency,
                notes,
                has_account_number: view.has_account_number,
                support,
            })
        }
        ItemKind::Property => {
            let view = property_view(item, revision)?;
            Ok(ItemHistoryDetailView::Property {
                id: view.id,
                revision,
                title: view.title,
                property_type: view.property_type,
                ownership: view.ownership,
                notes,
                has_address: view.has_address,
                has_property_reference: view.has_property_reference,
                support,
            })
        }
        ItemKind::Vehicle => {
            let view = vehicle_view(item, revision)?;
            Ok(ItemHistoryDetailView::Vehicle {
                id: view.id,
                revision,
                title: view.title,
                make: view.make,
                model: view.model,
                year: view.year,
                renewal: view.renewal,
                notes: view.notes,
                has_registration_number: view.has_registration_number,
                has_vin: view.has_vin,
                support,
            })
        }
        ItemKind::Possession => {
            let view = possession_view(item, revision)?;
            Ok(ItemHistoryDetailView::Possession {
                id: view.id,
                revision,
                title: view.title,
                category: view.category,
                location: view.location,
                brand: view.brand,
                model: view.model,
                purchase_date: view.purchase_date,
                purchase_price: view.purchase_price,
                store: view.store,
                warranty_expiry: view.warranty_expiry,
                notes: view.notes,
                has_serial_number: view.has_serial_number,
                support,
            })
        }
        ItemKind::Subscription => {
            let view = subscription_view(item, revision)?;
            Ok(ItemHistoryDetailView::Subscription {
                id: view.id,
                revision,
                title: view.title,
                provider: view.provider,
                plan: view.plan,
                amount: view.amount,
                currency: view.currency,
                billing_cycle: view.billing_cycle,
                next_renewal: view.next_renewal,
                notes: view.notes,
                support,
            })
        }
        ItemKind::EmergencyInstruction => {
            Err("Version history is unavailable for emergency instructions.".to_owned())
        }
    }
}

fn note_view(item: VaultItem, revision: u64) -> Result<NoteView, String> {
    let body = item
        .fields
        .get("body")
        .cloned()
        .ok_or_else(|| "The encrypted note is missing its body field.".to_owned())?;
    let links = item.links.iter().map(ToString::to_string).collect();
    Ok(NoteView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        body,
        links,
    })
}

fn credential_view(item: VaultItem, revision: u64) -> Result<CredentialView, String> {
    let username = item
        .fields
        .get("username")
        .cloned()
        .ok_or_else(|| "The encrypted credential is missing its username field.".to_owned())?;
    let has_password = !item
        .fields
        .get("password")
        .ok_or_else(|| "The encrypted credential is missing its password field.".to_owned())?
        .is_empty();
    let website = item
        .fields
        .get("website")
        .cloned()
        .ok_or_else(|| "The encrypted credential is missing its website field.".to_owned())?;
    let links = item.links.iter().map(ToString::to_string).collect();
    Ok(CredentialView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        username,
        website,
        notes: item.notes.unwrap_or_default(),
        has_password,
        links,
    })
}

fn credential_detail_view(item: VaultItem, revision: u64) -> Result<CredentialDetailView, String> {
    let username = item
        .fields
        .get("username")
        .cloned()
        .ok_or_else(|| "The encrypted credential is missing its username field.".to_owned())?;
    let password = item
        .fields
        .get("password")
        .cloned()
        .ok_or_else(|| "The encrypted credential is missing its password field.".to_owned())?;
    let website = item
        .fields
        .get("website")
        .cloned()
        .ok_or_else(|| "The encrypted credential is missing its website field.".to_owned())?;
    Ok(CredentialDetailView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        username,
        password,
        website,
        notes: item.notes.unwrap_or_default(),
    })
}

fn document_view(item: VaultItem, revision: u64) -> Result<DocumentView, String> {
    let has_document_number = !item
        .fields
        .get("document_number")
        .ok_or_else(|| "The encrypted document is missing its number field.".to_owned())?
        .is_empty();
    let issuer = item
        .fields
        .get("issuer")
        .cloned()
        .ok_or_else(|| "The encrypted document is missing its issuer field.".to_owned())?;
    let expiry = item
        .fields
        .get("expiry")
        .cloned()
        .ok_or_else(|| "The encrypted document is missing its expiry field.".to_owned())?;
    let links = item.links.iter().map(ToString::to_string).collect();
    Ok(DocumentView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        issuer,
        expiry,
        notes: item.notes.unwrap_or_default(),
        has_document_number,
        links,
    })
}

fn document_detail_view(item: VaultItem, revision: u64) -> Result<DocumentDetailView, String> {
    let document_number = item
        .fields
        .get("document_number")
        .cloned()
        .ok_or_else(|| "The encrypted document is missing its number field.".to_owned())?;
    let issuer = item
        .fields
        .get("issuer")
        .cloned()
        .ok_or_else(|| "The encrypted document is missing its issuer field.".to_owned())?;
    let expiry = item
        .fields
        .get("expiry")
        .cloned()
        .ok_or_else(|| "The encrypted document is missing its expiry field.".to_owned())?;
    Ok(DocumentDetailView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        document_number,
        issuer,
        expiry,
        notes: item.notes.unwrap_or_default(),
    })
}

fn receipt_view(item: VaultItem, revision: u64) -> Result<ReceiptView, String> {
    let merchant = item
        .fields
        .get("merchant")
        .cloned()
        .ok_or_else(|| "The encrypted receipt is missing its merchant field.".to_owned())?;
    let purchase_date =
        item.fields.get("purchase_date").cloned().ok_or_else(|| {
            "The encrypted receipt is missing its purchase date field.".to_owned()
        })?;
    let amount = item
        .fields
        .get("amount")
        .cloned()
        .ok_or_else(|| "The encrypted receipt is missing its amount field.".to_owned())?;
    let currency = item
        .fields
        .get("currency")
        .cloned()
        .ok_or_else(|| "The encrypted receipt is missing its currency field.".to_owned())?;
    let tracking_status =
        item.fields.get("tracking_status").cloned().ok_or_else(|| {
            "The encrypted receipt is missing its tracking status field.".to_owned()
        })?;
    let return_by =
        item.fields.get("return_by").cloned().ok_or_else(|| {
            "The encrypted receipt is missing its return deadline field.".to_owned()
        })?;
    let refund_due = item
        .fields
        .get("refund_due")
        .cloned()
        .ok_or_else(|| "The encrypted receipt is missing its refund due field.".to_owned())?;
    let has_receipt_reference = !item
        .fields
        .get("receipt_reference")
        .ok_or_else(|| "The encrypted receipt is missing its reference field.".to_owned())?
        .is_empty();
    validate_receipt_tracking_status(&tracking_status)?;
    validate_optional_receipt_date("Purchase date", &purchase_date)?;
    validate_optional_receipt_date("Return deadline", &return_by)?;
    validate_optional_receipt_date("Refund due date", &refund_due)?;
    validate_receipt_tracking_dates(&tracking_status, &return_by, &refund_due)?;
    let links = item.links.iter().map(ToString::to_string).collect();
    Ok(ReceiptView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        merchant,
        purchase_date,
        amount,
        currency,
        tracking_status,
        return_by,
        refund_due,
        has_receipt_reference,
        links,
    })
}

fn receipt_detail_view(item: VaultItem, revision: u64) -> Result<ReceiptDetailView, String> {
    let merchant = item
        .fields
        .get("merchant")
        .cloned()
        .ok_or_else(|| "The encrypted receipt is missing its merchant field.".to_owned())?;
    let purchase_date =
        item.fields.get("purchase_date").cloned().ok_or_else(|| {
            "The encrypted receipt is missing its purchase date field.".to_owned()
        })?;
    let amount = item
        .fields
        .get("amount")
        .cloned()
        .ok_or_else(|| "The encrypted receipt is missing its amount field.".to_owned())?;
    let currency = item
        .fields
        .get("currency")
        .cloned()
        .ok_or_else(|| "The encrypted receipt is missing its currency field.".to_owned())?;
    let receipt_reference = item
        .fields
        .get("receipt_reference")
        .cloned()
        .ok_or_else(|| "The encrypted receipt is missing its reference field.".to_owned())?;
    let tracking_status =
        item.fields.get("tracking_status").cloned().ok_or_else(|| {
            "The encrypted receipt is missing its tracking status field.".to_owned()
        })?;
    let return_by =
        item.fields.get("return_by").cloned().ok_or_else(|| {
            "The encrypted receipt is missing its return deadline field.".to_owned()
        })?;
    let refund_due = item
        .fields
        .get("refund_due")
        .cloned()
        .ok_or_else(|| "The encrypted receipt is missing its refund due field.".to_owned())?;
    validate_receipt_tracking_status(&tracking_status)?;
    validate_optional_receipt_date("Purchase date", &purchase_date)?;
    validate_optional_receipt_date("Return deadline", &return_by)?;
    validate_optional_receipt_date("Refund due date", &refund_due)?;
    validate_receipt_tracking_dates(&tracking_status, &return_by, &refund_due)?;
    Ok(ReceiptDetailView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        merchant,
        purchase_date,
        amount,
        currency,
        receipt_reference,
        tracking_status,
        return_by,
        refund_due,
        notes: item.notes.unwrap_or_default(),
    })
}

fn insurance_view(item: VaultItem, revision: u64) -> Result<InsuranceView, String> {
    let provider = item.fields.get("provider").cloned().ok_or_else(|| {
        "The encrypted insurance record is missing its provider field.".to_owned()
    })?;
    let policy_type =
        item.fields.get("policy_type").cloned().ok_or_else(|| {
            "The encrypted insurance record is missing its type field.".to_owned()
        })?;
    let has_policy_number = !item
        .fields
        .get("policy_number")
        .ok_or_else(|| {
            "The encrypted insurance record is missing its policy number field.".to_owned()
        })?
        .is_empty();
    let renewal =
        item.fields.get("renewal").cloned().ok_or_else(|| {
            "The encrypted insurance record is missing its renewal field.".to_owned()
        })?;
    let links = item.links.iter().map(ToString::to_string).collect();
    Ok(InsuranceView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        provider,
        policy_type,
        renewal,
        notes: item.notes.unwrap_or_default(),
        has_policy_number,
        links,
    })
}

fn insurance_detail_view(item: VaultItem, revision: u64) -> Result<InsuranceDetailView, String> {
    let provider = item.fields.get("provider").cloned().ok_or_else(|| {
        "The encrypted insurance record is missing its provider field.".to_owned()
    })?;
    let policy_type =
        item.fields.get("policy_type").cloned().ok_or_else(|| {
            "The encrypted insurance record is missing its type field.".to_owned()
        })?;
    let policy_number = item.fields.get("policy_number").cloned().ok_or_else(|| {
        "The encrypted insurance record is missing its policy number field.".to_owned()
    })?;
    let renewal =
        item.fields.get("renewal").cloned().ok_or_else(|| {
            "The encrypted insurance record is missing its renewal field.".to_owned()
        })?;
    Ok(InsuranceDetailView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        provider,
        policy_type,
        policy_number,
        renewal,
        notes: item.notes.unwrap_or_default(),
    })
}

fn financial_view(item: VaultItem, revision: u64) -> Result<FinancialView, String> {
    let institution = item.fields.get("institution").cloned().ok_or_else(|| {
        "The encrypted financial record is missing its institution field.".to_owned()
    })?;
    let account_type = item.fields.get("account_type").cloned().ok_or_else(|| {
        "The encrypted financial record is missing its account type field.".to_owned()
    })?;
    let currency = item.fields.get("currency").cloned().ok_or_else(|| {
        "The encrypted financial record is missing its currency field.".to_owned()
    })?;
    let has_account_number = !item
        .fields
        .get("account_number")
        .ok_or_else(|| {
            "The encrypted financial record is missing its account number field.".to_owned()
        })?
        .is_empty();
    let links = item.links.iter().map(ToString::to_string).collect();
    Ok(FinancialView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        institution,
        account_type,
        currency,
        has_account_number,
        links,
    })
}

fn financial_detail_view(item: VaultItem, revision: u64) -> Result<FinancialDetailView, String> {
    let institution = item.fields.get("institution").cloned().ok_or_else(|| {
        "The encrypted financial record is missing its institution field.".to_owned()
    })?;
    let account_type = item.fields.get("account_type").cloned().ok_or_else(|| {
        "The encrypted financial record is missing its account type field.".to_owned()
    })?;
    let currency = item.fields.get("currency").cloned().ok_or_else(|| {
        "The encrypted financial record is missing its currency field.".to_owned()
    })?;
    let account_number = item.fields.get("account_number").cloned().ok_or_else(|| {
        "The encrypted financial record is missing its account number field.".to_owned()
    })?;
    Ok(FinancialDetailView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        institution,
        account_type,
        currency,
        account_number,
        notes: item.notes.unwrap_or_default(),
    })
}

fn property_view(item: VaultItem, revision: u64) -> Result<PropertyView, String> {
    let property_type = item.fields.get("property_type").cloned().ok_or_else(|| {
        "The encrypted property record is missing its property type field.".to_owned()
    })?;
    let ownership = item.fields.get("ownership").cloned().ok_or_else(|| {
        "The encrypted property record is missing its ownership field.".to_owned()
    })?;
    validate_property_ownership(&ownership)?;
    let has_address = !item
        .fields
        .get("address")
        .ok_or_else(|| "The encrypted property record is missing its address field.".to_owned())?
        .is_empty();
    let has_property_reference = !item
        .fields
        .get("property_reference")
        .ok_or_else(|| "The encrypted property record is missing its reference field.".to_owned())?
        .is_empty();
    let links = item.links.iter().map(ToString::to_string).collect();
    Ok(PropertyView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        property_type,
        ownership,
        has_address,
        has_property_reference,
        links,
    })
}

fn property_detail_view(item: VaultItem, revision: u64) -> Result<PropertyDetailView, String> {
    let property_type = item.fields.get("property_type").cloned().ok_or_else(|| {
        "The encrypted property record is missing its property type field.".to_owned()
    })?;
    let address =
        item.fields.get("address").cloned().ok_or_else(|| {
            "The encrypted property record is missing its address field.".to_owned()
        })?;
    let ownership = item.fields.get("ownership").cloned().ok_or_else(|| {
        "The encrypted property record is missing its ownership field.".to_owned()
    })?;
    validate_property_ownership(&ownership)?;
    let property_reference = item
        .fields
        .get("property_reference")
        .cloned()
        .ok_or_else(|| {
            "The encrypted property record is missing its reference field.".to_owned()
        })?;
    Ok(PropertyDetailView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        property_type,
        address,
        ownership,
        property_reference,
        notes: item.notes.unwrap_or_default(),
    })
}

fn vehicle_view(item: VaultItem, revision: u64) -> Result<VehicleView, String> {
    let make = item
        .fields
        .get("make")
        .cloned()
        .ok_or_else(|| "The encrypted vehicle record is missing its make field.".to_owned())?;
    let model = item
        .fields
        .get("model")
        .cloned()
        .ok_or_else(|| "The encrypted vehicle record is missing its model field.".to_owned())?;
    let year = item
        .fields
        .get("year")
        .cloned()
        .ok_or_else(|| "The encrypted vehicle record is missing its year field.".to_owned())?;
    let renewal =
        item.fields.get("renewal").cloned().ok_or_else(|| {
            "The encrypted vehicle record is missing its renewal field.".to_owned()
        })?;
    let has_registration_number = !item
        .fields
        .get("registration_number")
        .ok_or_else(|| {
            "The encrypted vehicle record is missing its registration number field.".to_owned()
        })?
        .is_empty();
    let has_vin = !item
        .fields
        .get("vin")
        .ok_or_else(|| "The encrypted vehicle record is missing its vin field.".to_owned())?
        .is_empty();
    let links = item.links.iter().map(ToString::to_string).collect();
    Ok(VehicleView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        make,
        model,
        year,
        renewal,
        notes: item.notes.unwrap_or_default(),
        has_registration_number,
        has_vin,
        links,
    })
}

fn vehicle_detail_view(item: VaultItem, revision: u64) -> Result<VehicleDetailView, String> {
    let make = item
        .fields
        .get("make")
        .cloned()
        .ok_or_else(|| "The encrypted vehicle record is missing its make field.".to_owned())?;
    let model = item
        .fields
        .get("model")
        .cloned()
        .ok_or_else(|| "The encrypted vehicle record is missing its model field.".to_owned())?;
    let year = item
        .fields
        .get("year")
        .cloned()
        .ok_or_else(|| "The encrypted vehicle record is missing its year field.".to_owned())?;
    let registration_number = item
        .fields
        .get("registration_number")
        .cloned()
        .ok_or_else(|| {
            "The encrypted vehicle record is missing its registration number field.".to_owned()
        })?;
    let vin = item
        .fields
        .get("vin")
        .cloned()
        .ok_or_else(|| "The encrypted vehicle record is missing its vin field.".to_owned())?;
    let renewal =
        item.fields.get("renewal").cloned().ok_or_else(|| {
            "The encrypted vehicle record is missing its renewal field.".to_owned()
        })?;
    Ok(VehicleDetailView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        make,
        model,
        year,
        registration_number,
        vin,
        renewal,
        notes: item.notes.unwrap_or_default(),
    })
}

fn possession_view(item: VaultItem, revision: u64) -> Result<PossessionView, String> {
    let category = item.fields.get("category").cloned().unwrap_or_default();
    let location = item.fields.get("location").cloned().unwrap_or_default();
    let brand =
        item.fields.get("brand").cloned().ok_or_else(|| {
            "The encrypted possession record is missing its brand field.".to_owned()
        })?;
    let model =
        item.fields.get("model").cloned().ok_or_else(|| {
            "The encrypted possession record is missing its model field.".to_owned()
        })?;
    let purchase_date = item.fields.get("purchase_date").cloned().ok_or_else(|| {
        "The encrypted possession record is missing its purchase date field.".to_owned()
    })?;
    let purchase_price = item.fields.get("purchase_price").cloned().ok_or_else(|| {
        "The encrypted possession record is missing its purchase price field.".to_owned()
    })?;
    let store =
        item.fields.get("store").cloned().ok_or_else(|| {
            "The encrypted possession record is missing its store field.".to_owned()
        })?;
    let warranty_expiry = item.fields.get("warranty_expiry").cloned().ok_or_else(|| {
        "The encrypted possession record is missing its warranty expiry field.".to_owned()
    })?;
    let has_serial_number = !item
        .fields
        .get("serial_number")
        .ok_or_else(|| {
            "The encrypted possession record is missing its serial number field.".to_owned()
        })?
        .is_empty();
    let links = item.links.iter().map(ToString::to_string).collect();
    Ok(PossessionView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        category,
        location,
        brand,
        model,
        purchase_date,
        purchase_price,
        store,
        warranty_expiry,
        notes: item.notes.unwrap_or_default(),
        has_serial_number,
        links,
    })
}

fn possession_detail_view(item: VaultItem, revision: u64) -> Result<PossessionDetailView, String> {
    let category = item.fields.get("category").cloned().unwrap_or_default();
    let location = item.fields.get("location").cloned().unwrap_or_default();
    let brand =
        item.fields.get("brand").cloned().ok_or_else(|| {
            "The encrypted possession record is missing its brand field.".to_owned()
        })?;
    let model =
        item.fields.get("model").cloned().ok_or_else(|| {
            "The encrypted possession record is missing its model field.".to_owned()
        })?;
    let serial_number = item.fields.get("serial_number").cloned().ok_or_else(|| {
        "The encrypted possession record is missing its serial number field.".to_owned()
    })?;
    let purchase_date = item.fields.get("purchase_date").cloned().ok_or_else(|| {
        "The encrypted possession record is missing its purchase date field.".to_owned()
    })?;
    let purchase_price = item.fields.get("purchase_price").cloned().ok_or_else(|| {
        "The encrypted possession record is missing its purchase price field.".to_owned()
    })?;
    let store =
        item.fields.get("store").cloned().ok_or_else(|| {
            "The encrypted possession record is missing its store field.".to_owned()
        })?;
    let warranty_expiry = item.fields.get("warranty_expiry").cloned().ok_or_else(|| {
        "The encrypted possession record is missing its warranty expiry field.".to_owned()
    })?;
    Ok(PossessionDetailView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        category,
        location,
        brand,
        model,
        serial_number,
        purchase_date,
        purchase_price,
        store,
        warranty_expiry,
        notes: item.notes.unwrap_or_default(),
    })
}

fn subscription_view(item: VaultItem, revision: u64) -> Result<SubscriptionView, String> {
    let provider = required_subscription_field(&item, "provider", "provider")?;
    let plan = required_subscription_field(&item, "plan", "plan")?;
    let amount = required_subscription_field(&item, "amount", "amount")?;
    let currency = required_subscription_field(&item, "currency", "currency")?;
    let billing_cycle = required_subscription_field(&item, "billing_cycle", "billing cycle")?;
    let next_renewal = required_subscription_field(&item, "next_renewal", "next renewal")?;
    validate_subscription_billing_cycle(&billing_cycle)?;
    validate_optional_date("Next renewal", &next_renewal)?;
    let links = item.links.iter().map(ToString::to_string).collect();
    Ok(SubscriptionView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        provider,
        plan,
        amount,
        currency,
        billing_cycle,
        next_renewal,
        notes: item.notes.unwrap_or_default(),
        links,
    })
}

fn subscription_detail_view(
    item: VaultItem,
    revision: u64,
) -> Result<SubscriptionDetailView, String> {
    let provider = required_subscription_field(&item, "provider", "provider")?;
    let plan = required_subscription_field(&item, "plan", "plan")?;
    let amount = required_subscription_field(&item, "amount", "amount")?;
    let currency = required_subscription_field(&item, "currency", "currency")?;
    let billing_cycle = required_subscription_field(&item, "billing_cycle", "billing cycle")?;
    let next_renewal = required_subscription_field(&item, "next_renewal", "next renewal")?;
    validate_subscription_billing_cycle(&billing_cycle)?;
    validate_optional_date("Next renewal", &next_renewal)?;
    Ok(SubscriptionDetailView {
        id: item.id.to_string(),
        revision,
        title: item.title,
        provider,
        plan,
        amount,
        currency,
        billing_cycle,
        next_renewal,
        notes: item.notes.unwrap_or_default(),
    })
}

fn required_subscription_field(item: &VaultItem, key: &str, label: &str) -> Result<String, String> {
    item.fields
        .get(key)
        .cloned()
        .ok_or_else(|| format!("The encrypted subscription record is missing its {label} field."))
}

fn validate_property_ownership(value: &str) -> Result<(), String> {
    match value {
        "" | "Owned" | "Rented" | "Leased" | "Shared" | "Other" => Ok(()),
        _ => Err("Choose a supported property ownership status.".to_owned()),
    }
}

fn validate_receipt_tracking_status(value: &str) -> Result<(), String> {
    match value {
        "" | "kept" | "return_planned" | "returned" | "refund_pending" | "refunded" => Ok(()),
        _ => Err("Choose a supported receipt tracking status.".to_owned()),
    }
}

fn validate_subscription_billing_cycle(value: &str) -> Result<(), String> {
    match value {
        "" | "monthly" | "quarterly" | "yearly" | "custom" => Ok(()),
        _ => Err("Choose a supported subscription billing cycle.".to_owned()),
    }
}

fn validate_optional_date(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || vault_core::reminders::parse_ymd(value).is_some() {
        Ok(())
    } else {
        Err(format!("{label} must use YYYY-MM-DD."))
    }
}

fn validate_optional_receipt_date(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || vault_core::reminders::parse_ymd(value).is_some() {
        Ok(())
    } else {
        Err(format!("{label} must use YYYY-MM-DD."))
    }
}

fn validate_receipt_tracking_dates(
    status: &str,
    return_by: &str,
    refund_due: &str,
) -> Result<(), String> {
    match status {
        "return_planned" if return_by.is_empty() => {
            Err("Set a return deadline when a return is planned.".to_owned())
        }
        "refund_pending" if refund_due.is_empty() => {
            Err("Set a refund due date while a refund is pending.".to_owned())
        }
        _ => Ok(()),
    }
}

fn advance_session_generation(session_generation: &AtomicU64) -> u64 {
    session_generation
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1)
}

fn capture_session_generation(state: &VaultRuntime) -> u64 {
    state.session_generation.load(Ordering::Acquire)
}

fn is_session_generation_current(state: &VaultRuntime, generation: u64) -> bool {
    capture_session_generation(state) == generation
}

fn capture_unlocked_session_generation(state: &VaultRuntime) -> Result<u64, String> {
    let session = lock_session(state)?;
    if session.is_none() {
        return Err("Unlock the vault before choosing an attachment.".to_owned());
    }
    Ok(capture_session_generation(state))
}

fn lock_session(state: &VaultRuntime) -> Result<MutexGuard<'_, Option<VaultSession>>, String> {
    if state.restore_in_progress.load(Ordering::Acquire) {
        return Err("The vault is finishing a restore. Try again.".to_owned());
    }
    expire_session_if_needed(state)?;
    *state
        .last_activity
        .lock()
        .map_err(|_| "The local activity tracker is unavailable.".to_owned())? = Instant::now();
    let session = state
        .session
        .lock()
        .map_err(|_| "The local vault session is unavailable.".to_owned())?;
    if state.restore_in_progress.load(Ordering::Acquire) {
        drop(session);
        return Err("The vault is finishing a restore. Try again.".to_owned());
    }
    Ok(session)
}

fn expire_session_if_needed(state: &VaultRuntime) -> Result<(), String> {
    let auto_lock_minutes = state
        .settings
        .lock()
        .map_err(|_| "The local device settings are unavailable.".to_owned())?
        .auto_lock_minutes;
    let expired = state
        .last_activity
        .lock()
        .map_err(|_| "The local activity tracker is unavailable.".to_owned())?
        .elapsed()
        >= Duration::from_secs(auto_lock_minutes.saturating_mul(60));
    if expired {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "The local vault session is unavailable.".to_owned())?;
        if session.take().is_some() {
            advance_session_generation(&state.session_generation);
        }
    }
    Ok(())
}

fn safe_vault_error(error: impl std::fmt::Display) -> String {
    format!("Local vault operation failed: {error}")
}

fn prepare_app_data_directory(directory: &Path) -> std::io::Result<()> {
    let legacy_directory = directory
        .parent()
        .map(|parent| parent.join(LEGACY_PRE_SAFEORY_APP_IDENTIFIER));

    if directory.exists() {
        if legacy_directory
            .as_ref()
            .is_some_and(|legacy| legacy.exists())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "both Safeory and legacy app-data directories exist",
            ));
        }
        return Ok(());
    }

    if let Some(legacy_directory) = legacy_directory
        && legacy_directory.exists()
    {
        fs::rename(legacy_directory, directory)?;
        return Ok(());
    }

    fs::create_dir_all(directory)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let directory = app.path().app_data_dir()?;
            prepare_app_data_directory(&directory)?;
            let settings_path = directory.join("device-settings.json");
            let settings = Arc::new(Mutex::new(load_device_settings(&settings_path)));
            let session = Arc::new(Mutex::new(None));
            let session_generation = Arc::new(AtomicU64::new(0));
            let restore_in_progress = Arc::new(AtomicBool::new(false));
            let last_activity = Arc::new(Mutex::new(Instant::now()));
            let clipboard_cleaner = ClipboardCleaner::spawn(
                Arc::new(TauriClipboard {
                    app: app.handle().clone(),
                }),
                Arc::clone(&session_generation),
                Duration::from_secs(CREDENTIAL_CLIPBOARD_TTL_SECONDS),
            );
            spawn_auto_lock_watchdog(
                Arc::clone(&session),
                Arc::clone(&session_generation),
                Arc::clone(&settings),
                Arc::clone(&last_activity),
            );
            app.manage(VaultRuntime {
                database_path: directory.join("vault.sqlite3"),
                settings_path,
                session,
                session_generation,
                restore_in_progress,
                settings,
                last_activity,
                clipboard_cleaner,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_status,
            initialize_vault,
            unlock_vault,
            lock_vault,
            record_activity,
            get_device_settings,
            update_device_settings,
            change_master_passphrase,
            list_vault_items,
            list_trashed_items,
            trash_item,
            restore_trashed_item,
            purge_trashed_item,
            create_note,
            update_note,
            create_credential,
            get_credential,
            copy_credential_password,
            generate_password,
            update_credential,
            create_document,
            get_document,
            update_document,
            create_receipt,
            get_receipt,
            reveal_receipt_reference,
            get_receipt_notes,
            update_receipt,
            create_insurance,
            get_insurance,
            update_insurance,
            create_financial,
            get_financial,
            reveal_financial_account_number,
            update_financial,
            create_property,
            get_property,
            reveal_property_address,
            reveal_property_reference,
            update_property,
            create_vehicle,
            get_vehicle,
            update_vehicle,
            create_possession,
            get_possession,
            update_possession,
            create_subscription,
            get_subscription,
            update_subscription,
            get_emergency_card,
            update_emergency_card,
            get_item_titles,
            set_item_links,
            get_item_legacy_disposition,
            set_item_legacy_disposition,
            get_credential_closure_plan,
            set_credential_closure_plan,
            list_item_history,
            get_item_history_detail,
            reveal_item_history_sensitive,
            add_attachment,
            list_attachments,
            export_attachment,
            delete_attachment,
            list_deadlines,
            generate_recovery_secret,
            confirm_recovery_secret,
            save_recovery_secret,
            get_recovery_status,
            verify_recovery_secret,
            get_plan_readiness,
            unlock_vault_with_recovery_kit,
            export_human_readable,
            backup_database_copy,
            restore_database_backup,
            restore_database_backup_with_recovery_kit
        ])
        .build(tauri::generate_context!())
        .expect("failed to build Safeory desktop shell");
    app.run(|app_handle, event| {
        if matches!(
            event,
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
        ) && let Some(state) = app_handle.try_state::<VaultRuntime>()
        {
            state.clipboard_cleaner.shutdown_and_clear();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tempfile::tempdir;

    const PASSPHRASE: &str = "a long adapter test passphrase";

    #[derive(Default)]
    struct FakeClipboard {
        text: Mutex<String>,
        clears: AtomicUsize,
    }

    impl FakeClipboard {
        fn text(&self) -> String {
            self.text.lock().expect("fake clipboard mutex").clone()
        }

        fn replace_text(&self, value: &str) {
            *self.text.lock().expect("fake clipboard mutex") = value.to_owned();
        }

        fn clears(&self) -> usize {
            self.clears.load(Ordering::Acquire)
        }
    }

    impl PlatformClipboard for FakeClipboard {
        fn set_secret(&self, value: &str) -> Result<(), PlatformError> {
            *self
                .text
                .lock()
                .map_err(|_| PlatformError::OperationFailed)? = value.to_owned();
            Ok(())
        }

        fn compare_and_clear(&self, expected_sha256: &[u8; 32]) -> Result<bool, PlatformError> {
            let mut text = self
                .text
                .lock()
                .map_err(|_| PlatformError::OperationFailed)?;
            if clipboard_digest(&text) != *expected_sha256 {
                return Ok(false);
            }
            text.clear();
            self.clears.fetch_add(1, Ordering::AcqRel);
            Ok(true)
        }
    }

    fn runtime() -> (tempfile::TempDir, VaultRuntime) {
        runtime_with_clipboard(Arc::new(FakeClipboard::default()), Duration::from_secs(30))
    }

    fn runtime_with_clipboard(
        clipboard: Arc<dyn PlatformClipboard>,
        clipboard_ttl: Duration,
    ) -> (tempfile::TempDir, VaultRuntime) {
        let directory = tempdir().expect("temp directory");
        let settings_path = directory.path().join("device-settings.json");
        let session_generation = Arc::new(AtomicU64::new(0));
        let clipboard_cleaner =
            ClipboardCleaner::spawn(clipboard, Arc::clone(&session_generation), clipboard_ttl);
        let runtime = VaultRuntime {
            database_path: directory.path().join("vault.sqlite3"),
            settings_path,
            session: Arc::new(Mutex::new(None)),
            session_generation,
            restore_in_progress: Arc::new(AtomicBool::new(false)),
            settings: Arc::new(Mutex::new(DeviceSettings::default())),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            clipboard_cleaner,
        };
        (directory, runtime)
    }

    fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if predicate() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        predicate()
    }

    #[test]
    fn legacy_app_data_directory_moves_to_safeory_identifier() {
        let root = tempdir().expect("temp directory");
        let legacy = root.path().join(LEGACY_PRE_SAFEORY_APP_IDENTIFIER);
        let safeory = root.path().join("com.safeory.desktop");
        fs::create_dir_all(&legacy).expect("create legacy directory");
        fs::write(legacy.join("vault.sqlite3"), b"legacy-vault-marker")
            .expect("write legacy marker");

        prepare_app_data_directory(&safeory).expect("migrate legacy app data");

        assert!(!legacy.exists());
        assert_eq!(
            fs::read(safeory.join("vault.sqlite3")).expect("read migrated marker"),
            b"legacy-vault-marker"
        );
    }

    #[test]
    fn session_generation_changes_when_vault_is_locked() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let generation = capture_session_generation(&runtime);
        assert!(is_session_generation_current(&runtime, generation));

        lock_vault_impl(&runtime).expect("lock vault");

        assert!(!is_session_generation_current(&runtime, generation));
        assert!(capture_session_generation(&runtime) > generation);
    }

    #[test]
    fn credential_password_copy_rejects_locked_stale_wrong_kind_and_empty() {
        let clipboard = Arc::new(FakeClipboard::default());
        let (_directory, runtime) =
            runtime_with_clipboard(clipboard.clone(), Duration::from_secs(30));
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let credential = create_credential_impl(
            &runtime,
            "Email".to_owned(),
            "user@example.com".to_owned(),
            "top-secret-password".to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create credential");
        let empty = create_credential_impl(
            &runtime,
            "No password".to_owned(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        )
        .expect("create empty credential");
        let note = create_note_impl(&runtime, "Not a credential".to_owned(), "body".to_owned())
            .expect("create note");

        assert!(
            copy_credential_password_impl(&runtime, credential.id.clone(), credential.revision + 1)
                .is_err()
        );
        assert!(copy_credential_password_impl(&runtime, note.id, note.revision).is_err());
        assert!(copy_credential_password_impl(&runtime, empty.id, empty.revision).is_err());
        assert!(clipboard.text().is_empty());

        lock_vault_impl(&runtime).expect("lock vault");
        assert!(
            copy_credential_password_impl(&runtime, credential.id, credential.revision).is_err()
        );
        assert!(clipboard.text().is_empty());
    }

    #[test]
    fn credential_password_copy_response_contains_only_ttl() {
        let clipboard = Arc::new(FakeClipboard::default());
        let (_directory, runtime) =
            runtime_with_clipboard(clipboard.clone(), Duration::from_secs(30));
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let password = "response-must-not-contain-this-secret";
        let credential = create_credential_impl(
            &runtime,
            "Email".to_owned(),
            String::new(),
            password.to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create credential");

        let response = copy_credential_password_impl(&runtime, credential.id, credential.revision)
            .expect("copy password");
        let serialized = serde_json::to_string(&response).expect("serialize copy status");

        assert_eq!(serialized, r#"{"clears_in_seconds":30}"#);
        assert!(!serialized.contains(password));
        assert_eq!(clipboard.text(), password);
    }

    #[test]
    fn credential_password_clipboard_clears_matching_owned_value_at_expiry() {
        let clipboard = Arc::new(FakeClipboard::default());
        let (_directory, runtime) =
            runtime_with_clipboard(clipboard.clone(), Duration::from_millis(60));
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let credential = create_credential_impl(
            &runtime,
            "Email".to_owned(),
            String::new(),
            "expires-from-clipboard".to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create credential");
        copy_credential_password_impl(&runtime, credential.id.clone(), credential.revision)
            .expect("copy password");

        assert!(wait_until(Duration::from_secs(2), || clipboard
            .text()
            .is_empty()));
        assert_eq!(clipboard.clears(), 1);
    }

    #[test]
    fn credential_password_clipboard_preserves_user_replacement() {
        let clipboard = Arc::new(FakeClipboard::default());
        let (_directory, runtime) =
            runtime_with_clipboard(clipboard.clone(), Duration::from_millis(60));
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let credential = create_credential_impl(
            &runtime,
            "Email".to_owned(),
            String::new(),
            "owned-secret".to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create credential");
        copy_credential_password_impl(&runtime, credential.id.clone(), credential.revision)
            .expect("copy password");
        clipboard.replace_text("user replacement");

        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(clipboard.text(), "user replacement");
        assert_eq!(clipboard.clears(), 0);
    }

    #[test]
    fn second_credential_password_copy_supersedes_first_pending_clear() {
        let clipboard = Arc::new(FakeClipboard::default());
        let (_directory, runtime) =
            runtime_with_clipboard(clipboard.clone(), Duration::from_millis(500));
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let first = create_credential_impl(
            &runtime,
            "First".to_owned(),
            String::new(),
            "first-secret".to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create first credential");
        let second = create_credential_impl(
            &runtime,
            "Second".to_owned(),
            String::new(),
            "second-secret".to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create second credential");

        copy_credential_password_impl(&runtime, first.id, first.revision)
            .expect("copy first password");
        std::thread::sleep(Duration::from_millis(300));
        copy_credential_password_impl(&runtime, second.id, second.revision)
            .expect("copy second password");
        std::thread::sleep(Duration::from_millis(250));

        assert_eq!(clipboard.text(), "second-secret");
        assert_eq!(clipboard.clears(), 0);
        assert!(wait_until(Duration::from_secs(2), || clipboard
            .text()
            .is_empty()));
        assert_eq!(clipboard.clears(), 1);
    }

    #[test]
    fn session_generation_change_clears_owned_credential_password_early() {
        let clipboard = Arc::new(FakeClipboard::default());
        let (_directory, runtime) =
            runtime_with_clipboard(clipboard.clone(), Duration::from_secs(5));
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let credential = create_credential_impl(
            &runtime,
            "Email".to_owned(),
            String::new(),
            "clear-on-lock".to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create credential");
        copy_credential_password_impl(&runtime, credential.id, credential.revision)
            .expect("copy password");
        assert_eq!(clipboard.text(), "clear-on-lock");

        lock_vault_impl(&runtime).expect("lock vault");

        assert!(wait_until(Duration::from_secs(2), || clipboard
            .text()
            .is_empty()));
        assert_eq!(clipboard.clears(), 1);
    }

    #[test]
    fn clipboard_shutdown_attempts_guarded_clear_of_owned_password() {
        let clipboard = Arc::new(FakeClipboard::default());
        let (_directory, runtime) =
            runtime_with_clipboard(clipboard.clone(), Duration::from_secs(30));
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let credential = create_credential_impl(
            &runtime,
            "Email".to_owned(),
            String::new(),
            "clear-on-exit".to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create credential");
        copy_credential_password_impl(&runtime, credential.id.clone(), credential.revision)
            .expect("copy password");

        runtime.clipboard_cleaner.shutdown_and_clear();

        assert!(clipboard.text().is_empty());
        assert_eq!(clipboard.clears(), 1);
        let error =
            match copy_credential_password_impl(&runtime, credential.id, credential.revision) {
                Ok(_) => panic!("copy after clipboard shutdown unexpectedly succeeded"),
                Err(error) => error,
            };
        assert_eq!(error, "The secure clipboard is shutting down.");
        assert!(clipboard.text().is_empty());
        assert_eq!(clipboard.clears(), 1);
    }

    #[test]
    fn desktop_restart_reopens_locked_and_preserves_local_state() {
        let (directory, first) = runtime();
        initialize_vault_impl(&first, PASSPHRASE.to_owned()).expect("initialize vault");
        let active = create_note_impl(
            &first,
            "Restart active".to_owned(),
            "active body".to_owned(),
        )
        .expect("create active record");
        let trashed = create_note_impl(&first, "Restart trash".to_owned(), "trash body".to_owned())
            .expect("create trash record");
        trash_item_impl(&first, trashed.id.clone(), trashed.revision).expect("trash record");
        let recovery = generate_recovery_secret_impl(&first).expect("generate recovery secret");
        confirm_recovery_secret_impl(&first, recovery.secret.to_string(), recovery.generation)
            .expect("confirm recovery");
        let recovery_secret = recovery.secret.to_string();
        update_device_settings_impl(&first, 30, false).expect("persist device settings");
        lock_vault_impl(&first).expect("lock before restart");
        drop(first);

        let settings_path = directory.path().join("device-settings.json");
        let session_generation = Arc::new(AtomicU64::new(0));
        let second = VaultRuntime {
            database_path: directory.path().join("vault.sqlite3"),
            settings_path: settings_path.clone(),
            session: Arc::new(Mutex::new(None)),
            session_generation: Arc::clone(&session_generation),
            restore_in_progress: Arc::new(AtomicBool::new(false)),
            settings: Arc::new(Mutex::new(load_device_settings(&settings_path))),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            clipboard_cleaner: ClipboardCleaner::spawn(
                Arc::new(FakeClipboard::default()),
                session_generation,
                Duration::from_secs(30),
            ),
        };

        let status = vault_status_impl(&second).expect("status after restart");
        assert!(status.initialized);
        assert!(!status.unlocked);
        assert_eq!(
            unlock_vault_impl(&second, "wrong restart passphrase".to_owned())
                .err()
                .expect("wrong passphrase fails"),
            "Unable to unlock the vault. Check the master passphrase and try again."
        );

        unlock_vault_impl(&second, PASSPHRASE.to_owned()).expect("unlock after restart");
        let active_items = list_vault_items_impl(&second).expect("active records after restart");
        assert!(active_items.iter().any(|item| match item {
            VaultItemView::SecureNote { id, .. } => id == &active.id,
            _ => false,
        }));
        assert!(!active_items.iter().any(|item| match item {
            VaultItemView::SecureNote { id, .. } => id == &trashed.id,
            _ => false,
        }));
        let trash = list_trashed_items_impl(&second).expect("trash after restart");
        assert!(trash.iter().any(|item| item.id == trashed.id));
        assert!(
            get_recovery_status_impl(&second)
                .expect("recovery status after restart")
                .configured
        );
        let settings = get_device_settings_impl(&second).expect("settings after restart");
        assert_eq!(settings.auto_lock_minutes, 30);
        assert!(!settings.lock_on_background);

        lock_vault_impl(&second).expect("lock before recovery restart unlock");
        unlock_vault_with_recovery_kit_impl(&second, recovery_secret)
            .expect("recovery secret still unlocks after restart");
        assert!(vault_status_impl(&second).expect("final status").unlocked);
    }

    #[test]
    fn lock_advances_generation_while_restore_gate_is_active() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let generation = capture_session_generation(&runtime);
        runtime.restore_in_progress.store(true, Ordering::Release);

        lock_vault_impl(&runtime).expect("lock while restore gate is active");

        assert!(!is_session_generation_current(&runtime, generation));
        assert!(runtime.session.lock().expect("session mutex").is_none());
        runtime.restore_in_progress.store(false, Ordering::Release);
    }

    #[test]
    fn stale_attachment_generation_cannot_commit_after_lock_and_reunlock() {
        let (directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let note = create_note_impl(&runtime, "Generation owner".to_owned(), "Body".to_owned())
            .expect("create owner");
        let source_path = directory.path().join("generation-source.txt");
        fs::write(&source_path, b"generation fenced attachment").expect("write source");

        let stale_add_generation = capture_session_generation(&runtime);
        lock_vault_impl(&runtime).expect("lock before stale add");
        unlock_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("unlock after stale add");
        assert!(
            add_attachment_impl_for_generation(
                &runtime,
                note.id.clone(),
                note.revision,
                source_path.clone(),
                stale_add_generation,
            )
            .is_err()
        );
        assert!(
            list_attachments_impl(&runtime, note.id.clone())
                .expect("list after stale add")
                .is_empty()
        );

        let added = add_attachment_impl(&runtime, note.id.clone(), note.revision, source_path)
            .expect("add under current generation");
        let stale_export_generation = capture_session_generation(&runtime);
        lock_vault_impl(&runtime).expect("lock before stale export");
        unlock_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("unlock after stale export");
        let destination = directory.path().join("stale-export.txt");
        assert!(
            export_attachment_impl_for_generation(
                &runtime,
                note.id,
                added.attachment.id,
                destination.clone(),
                stale_export_generation,
            )
            .is_err()
        );
        assert!(!destination.exists());
    }

    #[test]
    fn conflicting_legacy_and_safeory_app_data_fail_closed() {
        let root = tempdir().expect("temp directory");
        let legacy = root.path().join(LEGACY_PRE_SAFEORY_APP_IDENTIFIER);
        let safeory = root.path().join("com.safeory.desktop");
        fs::create_dir_all(&legacy).expect("create legacy directory");
        fs::create_dir_all(&safeory).expect("create Safeory directory");
        fs::write(legacy.join("vault.sqlite3"), b"legacy").expect("write legacy vault marker");
        fs::write(safeory.join("vault.sqlite3"), b"safeory").expect("write Safeory vault marker");

        let error = prepare_app_data_directory(&safeory)
            .expect_err("conflicting app-data directories must not be merged or overwritten");

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(legacy.join("vault.sqlite3")).expect("read legacy marker"),
            b"legacy"
        );
        assert_eq!(
            fs::read(safeory.join("vault.sqlite3")).expect("read Safeory marker"),
            b"safeory"
        );
    }

    #[test]
    fn device_settings_and_passphrase_change_are_local_and_lock_gated() {
        let (_directory, runtime) = runtime();
        assert!(update_device_settings_impl(&runtime, 5, true).is_err());

        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let settings =
            update_device_settings_impl(&runtime, 15, false).expect("update device settings");
        assert_eq!(settings.auto_lock_minutes, 15);
        assert!(!settings.lock_on_background);
        assert_eq!(settings.last_successful_encrypted_backup_at_ms, None);
        let persisted = load_device_settings(&runtime.settings_path);
        assert_eq!(persisted.auto_lock_minutes, 15);
        assert!(!persisted.lock_on_background);
        assert_eq!(persisted.last_successful_encrypted_backup_at_ms, None);
        assert!(update_device_settings_impl(&runtime, 2, true).is_err());

        let wrong = change_master_passphrase_impl(
            &runtime,
            "incorrect current phrase".to_owned(),
            "a new long local passphrase".to_owned(),
        )
        .expect_err("wrong current passphrase must fail");
        assert_eq!(
            wrong,
            "The current master passphrase is incorrect. No changes were made."
        );

        change_master_passphrase_impl(
            &runtime,
            PASSPHRASE.to_owned(),
            "a new long local passphrase".to_owned(),
        )
        .expect("change master passphrase");
        lock_vault_impl(&runtime).expect("lock after passphrase change");
        assert!(unlock_vault_impl(&runtime, PASSPHRASE.to_owned()).is_err());
        unlock_vault_impl(&runtime, "a new long local passphrase".to_owned())
            .expect("unlock with new passphrase");
    }

    #[test]
    fn legacy_device_settings_without_backup_timestamp_preserve_lock_preferences() {
        let directory = tempdir().expect("temp directory");
        let settings_path = directory.path().join("device-settings.json");
        fs::write(
            &settings_path,
            br#"{
  "auto_lock_minutes": 30,
  "lock_on_background": false
}"#,
        )
        .expect("write legacy settings");

        let settings = load_device_settings(&settings_path);
        assert_eq!(settings.auto_lock_minutes, 30);
        assert!(!settings.lock_on_background);
        assert_eq!(settings.last_successful_encrypted_backup_at_ms, None);
    }

    #[test]
    fn device_settings_recover_from_interrupted_install_journal() {
        let directory = tempdir().expect("temp directory");
        let settings_path = directory.path().join("device-settings.json");
        let recovery_path = device_settings_recovery_path(&settings_path);
        let expected = DeviceSettings {
            auto_lock_minutes: 1,
            lock_on_background: false,
            last_successful_encrypted_backup_at_ms: Some(42),
        };
        fs::write(
            &recovery_path,
            serde_json::to_vec_pretty(&expected).expect("encode recovery settings"),
        )
        .expect("write recovery settings");
        assert!(!settings_path.exists());

        let recovered = load_device_settings(&settings_path);
        assert_eq!(recovered.auto_lock_minutes, 1);
        assert!(!recovered.lock_on_background);
        assert_eq!(recovered.last_successful_encrypted_backup_at_ms, Some(42));
        assert!(settings_path.exists());
        let restored =
            read_valid_device_settings(&settings_path).expect("restored canonical settings");
        assert_eq!(restored.auto_lock_minutes, 1);
        assert!(!restored.lock_on_background);
        assert_eq!(restored.last_successful_encrypted_backup_at_ms, Some(42));

        let updated = DeviceSettings {
            auto_lock_minutes: 5,
            lock_on_background: true,
            last_successful_encrypted_backup_at_ms: Some(84),
        };
        persist_device_settings(&settings_path, recovered, updated)
            .expect("mutate after recovery without destroying the journal chain");
        let reloaded = load_device_settings(&settings_path);
        assert_eq!(reloaded.auto_lock_minutes, 5);
        assert!(reloaded.lock_on_background);
        assert_eq!(reloaded.last_successful_encrypted_backup_at_ms, Some(84));
    }

    #[test]
    fn device_settings_install_failure_does_not_advance_in_memory_settings() {
        let (directory, mut runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        runtime.settings_path = directory.path().join("settings-install-blocker");
        fs::create_dir(&runtime.settings_path).expect("create settings blocker directory");
        let before = get_device_settings_impl(&runtime).expect("settings before failed install");

        assert!(update_device_settings_impl(&runtime, 1, false).is_err());
        let after = get_device_settings_impl(&runtime).expect("settings after failed install");
        assert_eq!(after.auto_lock_minutes, before.auto_lock_minutes);
        assert_eq!(after.lock_on_background, before.lock_on_background);
        assert_eq!(
            after.last_successful_encrypted_backup_at_ms,
            before.last_successful_encrypted_backup_at_ms
        );
    }

    #[test]
    fn backup_creation_timestamp_merge_never_regresses() {
        assert_eq!(monotonic_backup_creation_timestamp(None, 100), 100);
        assert_eq!(monotonic_backup_creation_timestamp(Some(100), 200), 200);
        assert_eq!(monotonic_backup_creation_timestamp(Some(200), 100), 200);
    }

    #[test]
    fn lock_settings_update_preserves_recorded_backup_timestamp_across_restart() {
        let (directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        create_note_impl(&runtime, "Backup marker".to_owned(), "Body".to_owned())
            .expect("create record");
        let backup_path = directory.path().join("settings-preservation.sqlite3");
        let after_backup =
            backup_database_copy_impl(&runtime, backup_path.to_string_lossy().to_string())
                .expect("create backup");
        let recorded = after_backup
            .settings
            .expect("backup status recorded")
            .last_successful_encrypted_backup_at_ms
            .expect("backup timestamp recorded");

        let updated =
            update_device_settings_impl(&runtime, 30, false).expect("update lock settings");
        assert_eq!(
            updated.last_successful_encrypted_backup_at_ms,
            Some(recorded)
        );
        let reloaded = load_device_settings(&runtime.settings_path);
        assert_eq!(reloaded.auto_lock_minutes, 30);
        assert!(!reloaded.lock_on_background);
        assert_eq!(
            reloaded.last_successful_encrypted_backup_at_ms,
            Some(recorded)
        );
    }

    #[test]
    fn command_boundary_enforces_locking_and_redacts_wrong_passphrase() {
        let (_directory, runtime) = runtime();

        let status = vault_status_impl(&runtime).expect("initial status");
        assert!(!status.initialized);
        assert!(!status.unlocked);
        assert!(list_vault_items_impl(&runtime).is_err());

        let status =
            initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        assert!(status.initialized);
        assert!(status.unlocked);
        let generated = generate_password_impl(&runtime).expect("generate password while unlocked");
        assert_eq!(generated.len(), 20);

        let note = create_note_impl(&runtime, "Before lock".to_owned(), "Body".to_owned())
            .expect("create note before lock");
        let credential = create_credential_impl(
            &runtime,
            "Before lock".to_owned(),
            "user".to_owned(),
            "secret".to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create credential before lock");
        let document = create_document_impl(
            &runtime,
            "Passport".to_owned(),
            "P1234567".to_owned(),
            "Government".to_owned(),
            "2030-01-01".to_owned(),
            String::new(),
        )
        .expect("create document before lock");
        let insurance = create_insurance_impl(
            &runtime,
            "Health cover".to_owned(),
            "Safe Health".to_owned(),
            "Health".to_owned(),
            "POL-12345".to_owned(),
            "2030-06-01".to_owned(),
            String::new(),
        )
        .expect("create insurance before lock");
        let financial = create_financial_impl(
            &runtime,
            "Primary bank".to_owned(),
            "Safe Bank".to_owned(),
            "Savings".to_owned(),
            "USD".to_owned(),
            "123456789".to_owned(),
            String::new(),
        )
        .expect("create financial record before lock");
        let property = create_property_impl(
            &runtime,
            "Home".to_owned(),
            "House".to_owned(),
            "1 Private Street".to_owned(),
            "Owned".to_owned(),
            "PROP-123".to_owned(),
            String::new(),
        )
        .expect("create property before lock");
        let vehicle = create_vehicle_impl(
            &runtime,
            "Family car".to_owned(),
            "Toyota".to_owned(),
            "Innova".to_owned(),
            "2021".to_owned(),
            "KA01AB1234".to_owned(),
            "VIN123456".to_owned(),
            "2030-06-01".to_owned(),
            String::new(),
        )
        .expect("create vehicle before lock");
        let possession = create_possession_impl(
            &runtime,
            "MacBook".to_owned(),
            "  Electronics  ".to_owned(),
            " Home office ".to_owned(),
            "Apple".to_owned(),
            "Pro 14".to_owned(),
            "SN123".to_owned(),
            "2024-01-15".to_owned(),
            "199900".to_owned(),
            "Amazon".to_owned(),
            "2027-01-15".to_owned(),
            String::new(),
        )
        .expect("create possession before lock");

        lock_vault_impl(&runtime).expect("lock vault");
        assert!(list_vault_items_impl(&runtime).is_err());
        assert!(list_trashed_items_impl(&runtime).is_err());
        assert!(trash_item_impl(&runtime, note.id.clone(), note.revision).is_err());
        assert!(restore_trashed_item_impl(&runtime, note.id.clone(), note.revision).is_err());
        assert!(purge_trashed_item_impl(&runtime, note.id.clone(), note.revision).is_err());
        assert!(generate_password_impl(&runtime).is_err());
        assert!(create_note_impl(&runtime, "Locked".to_owned(), "Body".to_owned()).is_err());
        assert!(
            update_note_impl(
                &runtime,
                note.id,
                note.revision,
                "Locked".to_owned(),
                "Body".to_owned(),
            )
            .is_err()
        );
        assert!(
            create_credential_impl(
                &runtime,
                "Locked".to_owned(),
                "user".to_owned(),
                "secret".to_owned(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(
            update_credential_impl(
                &runtime,
                credential.id,
                credential.revision,
                "Locked".to_owned(),
                "user".to_owned(),
                "secret".to_owned(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(
            create_document_impl(
                &runtime,
                "Locked".to_owned(),
                "number".to_owned(),
                String::new(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(get_document_impl(&runtime, document.id.clone(), document.revision).is_err());
        assert!(
            update_document_impl(
                &runtime,
                document.id,
                document.revision,
                "Locked".to_owned(),
                "number".to_owned(),
                String::new(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(
            create_insurance_impl(
                &runtime,
                "Locked".to_owned(),
                String::new(),
                String::new(),
                "policy".to_owned(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(get_insurance_impl(&runtime, insurance.id.clone(), insurance.revision).is_err());
        assert!(
            update_insurance_impl(
                &runtime,
                insurance.id,
                insurance.revision,
                "Locked".to_owned(),
                String::new(),
                String::new(),
                "policy".to_owned(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(
            create_financial_impl(
                &runtime,
                "Locked".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                "account".to_owned(),
                String::new(),
            )
            .is_err()
        );
        assert!(get_financial_impl(&runtime, financial.id.clone(), financial.revision).is_err());
        assert!(
            update_financial_impl(
                &runtime,
                financial.id,
                financial.revision,
                "Locked".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                "account".to_owned(),
                String::new(),
            )
            .is_err()
        );
        assert!(
            create_property_impl(
                &runtime,
                "Locked".to_owned(),
                String::new(),
                "address".to_owned(),
                "Owned".to_owned(),
                "reference".to_owned(),
                String::new(),
            )
            .is_err()
        );
        assert!(get_property_impl(&runtime, property.id.clone(), property.revision).is_err());
        assert!(
            update_property_impl(
                &runtime,
                property.id,
                property.revision,
                "Locked".to_owned(),
                String::new(),
                "address".to_owned(),
                "Owned".to_owned(),
                "reference".to_owned(),
                String::new(),
            )
            .is_err()
        );
        assert!(
            create_vehicle_impl(
                &runtime,
                "Locked".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                "reg".to_owned(),
                "vin".to_owned(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(get_vehicle_impl(&runtime, vehicle.id.clone(), vehicle.revision).is_err());
        assert!(
            update_vehicle_impl(
                &runtime,
                vehicle.id,
                vehicle.revision,
                "Locked".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                "reg".to_owned(),
                "vin".to_owned(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(
            create_possession_impl(
                &runtime,
                "Locked".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                "serial".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(get_possession_impl(&runtime, possession.id.clone(), possession.revision).is_err());
        assert!(
            update_possession_impl(
                &runtime,
                possession.id,
                possession.revision,
                "Locked".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                "serial".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
            .is_err()
        );

        let wrong = "wrong passphrase material";
        let error = match unlock_vault_impl(&runtime, wrong.to_owned()) {
            Ok(_) => panic!("wrong passphrase unexpectedly unlocked the vault"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            "Unable to unlock the vault. Check the master passphrase and try again."
        );
        assert!(!error.contains(wrong));

        unlock_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("unlock vault");
        assert!(
            vault_status_impl(&runtime)
                .expect("unlocked status")
                .unlocked
        );
    }

    #[test]
    fn command_boundary_round_trips_revisioned_local_items() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");

        let note = create_note_impl(&runtime, "Private note".to_owned(), "Body".to_owned())
            .expect("create note");
        assert_eq!(note.revision, 1);

        let credential = create_credential_impl(
            &runtime,
            "Email".to_owned(),
            "person@example.test".to_owned(),
            "top-secret-password".to_owned(),
            "https://example.test".to_owned(),
            "primary account".to_owned(),
        )
        .expect("create credential");
        assert_eq!(credential.revision, 1);
        assert!(credential.has_password);
        let detail = get_credential_impl(&runtime, credential.id.clone(), credential.revision)
            .expect("get credential detail");
        assert_eq!(detail.password, "top-secret-password");

        let updated = update_credential_impl(
            &runtime,
            credential.id.clone(),
            credential.revision,
            "Email".to_owned(),
            "new@example.test".to_owned(),
            "rotated-password".to_owned(),
            "https://example.test".to_owned(),
            "rotated locally".to_owned(),
        )
        .expect("update credential");
        assert_eq!(updated.revision, 2);
        assert_eq!(updated.username, "new@example.test");
        assert!(updated.has_password);

        let stale_error = match update_credential_impl(
            &runtime,
            credential.id,
            1,
            "Stale".to_owned(),
            "stale@example.test".to_owned(),
            "stale-password".to_owned(),
            String::new(),
            String::new(),
        ) {
            Ok(_) => panic!("stale credential update unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(
            stale_error,
            "This credential changed since you opened it. Reload it before saving."
        );

        let listed = list_vault_items_impl(&runtime).expect("list vault items");
        assert_eq!(listed.len(), 2);
        let serialized = serde_json::to_string(&listed).expect("serialize IPC list shape");
        assert!(serialized.contains("\"kind\":\"secure_note\""));
        assert!(serialized.contains("\"kind\":\"password\""));
        assert!(!serialized.contains("rotated-password"));
        let credential = listed
            .into_iter()
            .find_map(|item| match item {
                VaultItemView::Password {
                    revision,
                    username,
                    has_password,
                    ..
                } => Some((revision, username, has_password)),
                VaultItemView::SecureNote { .. }
                | VaultItemView::Document { .. }
                | VaultItemView::Receipt { .. }
                | VaultItemView::Insurance { .. }
                | VaultItemView::Financial { .. }
                | VaultItemView::Property { .. }
                | VaultItemView::Vehicle { .. }
                | VaultItemView::Possession { .. }
                | VaultItemView::Subscription { .. } => None,
            })
            .expect("listed credential");
        assert_eq!(credential.0, 2);
        assert_eq!(credential.1, "new@example.test");
        assert!(credential.2);

        let detail = get_credential_impl(&runtime, updated.id.clone(), updated.revision)
            .expect("get updated credential detail");
        assert_eq!(detail.password, "rotated-password");

        let document = create_document_impl(
            &runtime,
            "Passport".to_owned(),
            "P1234567".to_owned(),
            "Government".to_owned(),
            "2030-01-01".to_owned(),
            "renew before travel".to_owned(),
        )
        .expect("create document");
        assert_eq!(document.revision, 1);
        assert!(document.has_document_number);
        let document_detail = get_document_impl(&runtime, document.id.clone(), document.revision)
            .expect("get document detail");
        assert_eq!(document_detail.document_number, "P1234567");

        let document = update_document_impl(
            &runtime,
            document.id,
            document.revision,
            "Passport".to_owned(),
            "P7654321".to_owned(),
            "Government".to_owned(),
            "2031-01-01".to_owned(),
            "renewed".to_owned(),
        )
        .expect("update document");
        assert_eq!(document.revision, 2);

        let listed = list_vault_items_impl(&runtime).expect("list vault items with document");
        assert_eq!(listed.len(), 3);
        let serialized = serde_json::to_string(&listed).expect("serialize IPC list with document");
        assert!(serialized.contains("\"kind\":\"document\""));
        assert!(!serialized.contains("P7654321"));

        let insurance = create_insurance_impl(
            &runtime,
            "Health cover".to_owned(),
            "Safe Health".to_owned(),
            "Health".to_owned(),
            "POL-12345".to_owned(),
            "2030-06-01".to_owned(),
            "family plan".to_owned(),
        )
        .expect("create insurance");
        assert_eq!(insurance.revision, 1);
        assert!(insurance.has_policy_number);
        let insurance_detail =
            get_insurance_impl(&runtime, insurance.id.clone(), insurance.revision)
                .expect("get insurance detail");
        assert_eq!(insurance_detail.policy_number, "POL-12345");

        let insurance = update_insurance_impl(
            &runtime,
            insurance.id,
            insurance.revision,
            "Health cover".to_owned(),
            "Safe Health".to_owned(),
            "Health".to_owned(),
            "POL-67890".to_owned(),
            "2031-06-01".to_owned(),
            "renewed".to_owned(),
        )
        .expect("update insurance");
        assert_eq!(insurance.revision, 2);

        let listed = list_vault_items_impl(&runtime).expect("list vault items with insurance");
        assert_eq!(listed.len(), 4);
        let serialized = serde_json::to_string(&listed).expect("serialize IPC list with insurance");
        assert!(serialized.contains("\"kind\":\"insurance\""));
        assert!(!serialized.contains("POL-67890"));

        let financial = create_financial_impl(
            &runtime,
            "Primary bank".to_owned(),
            "Safe Bank".to_owned(),
            "Savings".to_owned(),
            "USD".to_owned(),
            "ACC-123456".to_owned(),
            "private financial note".to_owned(),
        )
        .expect("create financial record");
        assert_eq!(financial.revision, 1);
        assert!(financial.has_account_number);
        let financial_detail =
            get_financial_impl(&runtime, financial.id.clone(), financial.revision)
                .expect("get financial detail");
        assert_eq!(financial_detail.account_number, "ACC-123456");
        assert_eq!(financial_detail.notes, "private financial note");

        let financial = update_financial_impl(
            &runtime,
            financial.id.clone(),
            financial.revision,
            "Primary bank".to_owned(),
            "Safe Bank".to_owned(),
            "Savings".to_owned(),
            "USD".to_owned(),
            "ACC-654321".to_owned(),
            "updated financial note".to_owned(),
        )
        .expect("update financial record");
        assert_eq!(financial.revision, 2);
        let stale_financial = match update_financial_impl(
            &runtime,
            financial.id.clone(),
            1,
            "Stale bank".to_owned(),
            "Stale institution".to_owned(),
            "Savings".to_owned(),
            "USD".to_owned(),
            "ACC-STALE".to_owned(),
            String::new(),
        ) {
            Ok(_) => panic!("stale financial update unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(
            stale_financial,
            "This financial record changed since you opened it. Reload it before saving."
        );

        let property = create_property_impl(
            &runtime,
            "Home".to_owned(),
            "House".to_owned(),
            "123 Secret Lane".to_owned(),
            "Owned".to_owned(),
            "DEED-123".to_owned(),
            "private property note".to_owned(),
        )
        .expect("create property");
        assert_eq!(property.revision, 1);
        assert!(property.has_address);
        assert!(property.has_property_reference);
        let property_detail = get_property_impl(&runtime, property.id.clone(), property.revision)
            .expect("get property detail");
        assert_eq!(property_detail.address, "123 Secret Lane");
        assert_eq!(property_detail.property_reference, "DEED-123");
        assert_eq!(property_detail.notes, "private property note");

        let property = update_property_impl(
            &runtime,
            property.id.clone(),
            property.revision,
            "Home".to_owned(),
            "House".to_owned(),
            "456 Private Avenue".to_owned(),
            "Owned".to_owned(),
            "DEED-456".to_owned(),
            "updated property note".to_owned(),
        )
        .expect("update property");
        assert_eq!(property.revision, 2);
        let stale_property = match update_property_impl(
            &runtime,
            property.id.clone(),
            1,
            "Stale property".to_owned(),
            "House".to_owned(),
            "Old address".to_owned(),
            "Owned".to_owned(),
            "DEED-STALE".to_owned(),
            String::new(),
        ) {
            Ok(_) => panic!("stale property update unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(
            stale_property,
            "This property record changed since you opened it. Reload it before saving."
        );

        let listed = list_vault_items_impl(&runtime)
            .expect("list vault items with financial and property records");
        assert_eq!(listed.len(), 6);
        let serialized =
            serde_json::to_string(&listed).expect("serialize IPC list with new record kinds");
        assert!(serialized.contains("\"kind\":\"financial\""));
        assert!(serialized.contains("\"kind\":\"property\""));
        assert!(serialized.contains("Safe Bank"));
        assert!(serialized.contains("House"));
        assert!(!serialized.contains("ACC-654321"));
        assert!(!serialized.contains("updated financial note"));
        assert!(!serialized.contains("456 Private Avenue"));
        assert!(!serialized.contains("DEED-456"));
        assert!(!serialized.contains("updated property note"));

        let financial_id = financial.id.clone();
        let trashed_revision = trash_item_impl(&runtime, financial_id.clone(), financial.revision)
            .expect("move financial record to trash");
        assert_eq!(trashed_revision, 3);
        assert!(get_financial_impl(&runtime, financial_id.clone(), trashed_revision).is_err());
        let active_after_trash = list_vault_items_impl(&runtime).expect("list after trash");
        assert_eq!(active_after_trash.len(), 5);
        let trash = list_trashed_items_impl(&runtime).expect("list trash");
        assert_eq!(trash.len(), 1);
        let trash_serialized = serde_json::to_string(&trash).expect("serialize trash summary");
        assert!(trash_serialized.contains("Primary bank"));
        assert!(trash_serialized.contains("\"kind\":\"financial\""));
        assert!(!trash_serialized.contains("ACC-654321"));
        assert!(!trash_serialized.contains("updated financial note"));
        assert!(trash_item_impl(&runtime, financial_id.clone(), financial.revision).is_err());

        let restored_revision =
            restore_trashed_item_impl(&runtime, financial_id.clone(), trashed_revision)
                .expect("restore financial record");
        assert_eq!(restored_revision, 4);
        assert!(
            list_trashed_items_impl(&runtime)
                .expect("trash after restore")
                .is_empty()
        );
        assert!(get_financial_impl(&runtime, financial_id.clone(), restored_revision).is_ok());
        assert!(
            restore_trashed_item_impl(&runtime, financial_id.clone(), trashed_revision).is_err()
        );

        let second_trash_revision =
            trash_item_impl(&runtime, financial_id.clone(), restored_revision)
                .expect("trash restored financial record");
        assert_eq!(second_trash_revision, 5);
        let tombstone_revision =
            purge_trashed_item_impl(&runtime, financial_id.clone(), second_trash_revision)
                .expect("permanently delete financial record");
        assert_eq!(tombstone_revision, 6);
        assert!(
            list_trashed_items_impl(&runtime)
                .expect("trash after purge")
                .is_empty()
        );
        assert!(restore_trashed_item_impl(&runtime, financial_id, tombstone_revision).is_err());

        lock_vault_impl(&runtime).expect("lock vault");
        assert_eq!(
            get_credential_impl(&runtime, updated.id, updated.revision)
                .err()
                .expect("locked credential read must fail"),
            "Unlock the vault before reading a credential."
        );
    }

    #[test]
    fn ownership_wallet_kinds_mask_secrets_and_preserve_links() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");

        assert!(
            create_vehicle_impl(
                &runtime,
                "   ".to_owned(),
                "Toyota".to_owned(),
                "Innova".to_owned(),
                "2021".to_owned(),
                "KA01AB1234".to_owned(),
                "VIN123".to_owned(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(
            create_possession_impl(
                &runtime,
                String::new(),
                String::new(),
                String::new(),
                "Apple".to_owned(),
                "Pro 14".to_owned(),
                "SN123".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
            .is_err()
        );

        let vehicle = create_vehicle_impl(
            &runtime,
            "Family car".to_owned(),
            "Toyota".to_owned(),
            "Innova".to_owned(),
            "2021".to_owned(),
            "KA01AB1234".to_owned(),
            "VIN1234567890".to_owned(),
            "2026-10-02".to_owned(),
            "family vehicle".to_owned(),
        )
        .expect("create vehicle");
        assert_eq!(vehicle.revision, 1);
        assert!(vehicle.has_registration_number);
        assert!(vehicle.has_vin);

        let empty_vehicle = create_vehicle_impl(
            &runtime,
            "Spare car".to_owned(),
            "Honda".to_owned(),
            "City".to_owned(),
            "2019".to_owned(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        )
        .expect("create vehicle without secrets");
        assert!(!empty_vehicle.has_registration_number);
        assert!(!empty_vehicle.has_vin);

        let possession = create_possession_impl(
            &runtime,
            "MacBook".to_owned(),
            "Electronics".to_owned(),
            "Home office".to_owned(),
            "Apple".to_owned(),
            "Pro 14".to_owned(),
            "SN123456".to_owned(),
            "2024-01-15".to_owned(),
            "199900".to_owned(),
            "Amazon".to_owned(),
            "2027-01-15".to_owned(),
            "work laptop".to_owned(),
        )
        .expect("create possession");
        assert_eq!(possession.revision, 1);
        assert!(possession.has_serial_number);
        assert_eq!(possession.category, "Electronics");
        assert_eq!(possession.location, "Home office");

        let empty_possession = create_possession_impl(
            &runtime,
            "Desk".to_owned(),
            "Furniture".to_owned(),
            "Study".to_owned(),
            "IKEA".to_owned(),
            "Bekant".to_owned(),
            String::new(),
            "2023-05-01".to_owned(),
            "30000".to_owned(),
            "IKEA".to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create possession without secrets");
        assert!(!empty_possession.has_serial_number);

        let listed = list_vault_items_impl(&runtime).expect("list ownership items");
        assert_eq!(listed.len(), 4);
        let serialized = serde_json::to_string(&listed).expect("serialize ownership list");
        assert!(serialized.contains("\"kind\":\"vehicle\""));
        assert!(serialized.contains("\"kind\":\"possession\""));
        assert!(serialized.contains("has_registration_number"));
        assert!(serialized.contains("has_vin"));
        assert!(serialized.contains("has_serial_number"));
        assert!(serialized.contains("Electronics"));
        assert!(serialized.contains("Home office"));
        assert!(!serialized.contains("KA01AB1234"));
        assert!(!serialized.contains("VIN1234567890"));
        assert!(!serialized.contains("SN123456"));

        let vehicle_detail = get_vehicle_impl(&runtime, vehicle.id.clone(), vehicle.revision)
            .expect("get vehicle detail");
        assert_eq!(vehicle_detail.registration_number, "KA01AB1234");
        assert_eq!(vehicle_detail.vin, "VIN1234567890");
        assert_eq!(vehicle_detail.make, "Toyota");
        assert_eq!(vehicle_detail.notes, "family vehicle");

        let possession_detail =
            get_possession_impl(&runtime, possession.id.clone(), possession.revision)
                .expect("get possession detail");
        assert_eq!(possession_detail.serial_number, "SN123456");
        assert_eq!(possession_detail.category, "Electronics");
        assert_eq!(possession_detail.location, "Home office");
        assert_eq!(possession_detail.brand, "Apple");
        assert_eq!(possession_detail.notes, "work laptop");

        let _receipt = create_note_impl(&runtime, "Invoice".to_owned(), "Body".to_owned())
            .expect("create link target");
        let receipt_id = {
            let session = lock_session(&runtime).expect("lock session");
            let session = session.as_ref().expect("unlocked session");
            let items = session.list_items().expect("list items for linking");
            items
                .iter()
                .find(|item| item.title == "Invoice")
                .expect("receipt item")
                .id
        };
        {
            let session = lock_session(&runtime).expect("lock session");
            let session = session.as_ref().expect("unlocked session");
            let items = session.list_items().expect("list items for linking");
            let vehicle_id = items
                .iter()
                .find(|item| item.title == "Family car")
                .expect("vehicle item")
                .id;
            let (mut item, current) = session
                .get_item_with_revision(vehicle_id)
                .expect("load vehicle for linking");
            assert_eq!(current, 1);
            item.links.push(receipt_id);
            session.update_item(&item, 1).expect("attach vehicle link");
            let possession_id = items
                .iter()
                .find(|item| item.title == "MacBook")
                .expect("possession item")
                .id;
            let (mut item, current) = session
                .get_item_with_revision(possession_id)
                .expect("load possession for linking");
            assert_eq!(current, 1);
            item.links.push(receipt_id);
            item.fields
                .insert("future_marker".to_owned(), "preserve me".to_owned());
            session
                .update_item(&item, 1)
                .expect("attach possession link");
        }

        let vehicle = update_vehicle_impl(
            &runtime,
            vehicle.id.clone(),
            2,
            "Family car".to_owned(),
            "Toyota".to_owned(),
            "Innova".to_owned(),
            "2021".to_owned(),
            "KA09CD9876".to_owned(),
            "VIN0987654321".to_owned(),
            "2027-10-02".to_owned(),
            "updated vehicle".to_owned(),
        )
        .expect("update vehicle");
        assert_eq!(vehicle.revision, 3);
        assert!(vehicle.has_registration_number);
        assert!(vehicle.has_vin);
        {
            let session = lock_session(&runtime).expect("lock session");
            let session = session.as_ref().expect("unlocked session");
            let items = session
                .list_items()
                .expect("list items after vehicle update");
            let vehicle_id = items
                .iter()
                .find(|item| item.title == "Family car")
                .expect("updated vehicle item")
                .id;
            let (item, _) = session
                .get_item_with_revision(vehicle_id)
                .expect("load updated vehicle");
            assert_eq!(item.links, vec![receipt_id]);
        }
        let vehicle_detail = get_vehicle_impl(&runtime, vehicle.id.clone(), vehicle.revision)
            .expect("get updated vehicle detail");
        assert_eq!(vehicle_detail.registration_number, "KA09CD9876");
        assert_eq!(vehicle_detail.vin, "VIN0987654321");

        let possession = update_possession_impl(
            &runtime,
            possession.id.clone(),
            2,
            "MacBook".to_owned(),
            " Computers ".to_owned(),
            "  Studio  ".to_owned(),
            "Apple".to_owned(),
            "Pro 14".to_owned(),
            "SN654321".to_owned(),
            "2024-01-15".to_owned(),
            "189900".to_owned(),
            "Flipkart".to_owned(),
            "2028-01-15".to_owned(),
            "updated laptop".to_owned(),
        )
        .expect("update possession");
        assert_eq!(possession.revision, 3);
        assert!(possession.has_serial_number);
        assert_eq!(possession.category, "Computers");
        assert_eq!(possession.location, "Studio");
        {
            let session = lock_session(&runtime).expect("lock session");
            let session = session.as_ref().expect("unlocked session");
            let items = session
                .list_items()
                .expect("list items after possession update");
            let possession_id = items
                .iter()
                .find(|item| item.title == "MacBook")
                .expect("updated possession item")
                .id;
            let (item, _) = session
                .get_item_with_revision(possession_id)
                .expect("load updated possession");
            assert_eq!(item.links, vec![receipt_id]);
            assert_eq!(
                item.fields.get("future_marker").map(String::as_str),
                Some("preserve me")
            );
        }
        let possession_detail =
            get_possession_impl(&runtime, possession.id.clone(), possession.revision)
                .expect("get updated possession detail");
        assert_eq!(possession_detail.serial_number, "SN654321");
        assert_eq!(possession_detail.category, "Computers");
        assert_eq!(possession_detail.location, "Studio");
        let historical =
            get_item_history_detail_impl(&runtime, possession.id.clone(), possession.revision, 2)
                .expect("load prior possession classification");
        assert!(matches!(
            historical,
            ItemHistoryDetailView::Possession {
                category,
                location,
                ..
            } if category == "Electronics" && location == "Home office"
        ));

        let stale_vehicle = match update_vehicle_impl(
            &runtime,
            vehicle.id.clone(),
            1,
            "Stale".to_owned(),
            "Toyota".to_owned(),
            "Innova".to_owned(),
            "2021".to_owned(),
            "STALE".to_owned(),
            "STALE".to_owned(),
            String::new(),
            String::new(),
        ) {
            Ok(_) => panic!("stale vehicle update unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(
            stale_vehicle,
            "This vehicle record changed since you opened it. Reload it before saving."
        );
        let stale_vehicle_get = match get_vehicle_impl(&runtime, vehicle.id.clone(), 1) {
            Ok(_) => panic!("stale vehicle read unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(
            stale_vehicle_get,
            "This vehicle record changed since you opened it. Reload it before continuing."
        );

        let stale_possession = match update_possession_impl(
            &runtime,
            possession.id.clone(),
            1,
            "Stale".to_owned(),
            String::new(),
            String::new(),
            "Apple".to_owned(),
            "Pro 14".to_owned(),
            "STALE".to_owned(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ) {
            Ok(_) => panic!("stale possession update unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(
            stale_possession,
            "This possession record changed since you opened it. Reload it before saving."
        );
        let stale_possession_get = match get_possession_impl(&runtime, possession.id.clone(), 1) {
            Ok(_) => panic!("stale possession read unexpectedly succeeded"),
            Err(error) => error,
        };
        assert_eq!(
            stale_possession_get,
            "This possession record changed since you opened it. Reload it before continuing."
        );

        lock_vault_impl(&runtime).expect("lock vault");
        assert!(
            create_vehicle_impl(
                &runtime,
                "Locked".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                "reg".to_owned(),
                "vin".to_owned(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(get_vehicle_impl(&runtime, vehicle.id.clone(), vehicle.revision).is_err());
        assert!(
            update_vehicle_impl(
                &runtime,
                vehicle.id,
                vehicle.revision,
                "Locked".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                "reg".to_owned(),
                "vin".to_owned(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(
            create_possession_impl(
                &runtime,
                "Locked".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                "serial".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(get_possession_impl(&runtime, possession.id.clone(), possession.revision).is_err());
        assert!(
            update_possession_impl(
                &runtime,
                possession.id,
                possession.revision,
                "Locked".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                "serial".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        unlock_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("unlock vault");
    }

    #[test]
    fn possession_missing_inventory_fields_default_empty_and_survive_lifecycle() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let mut legacy = VaultItem::possession(
            "Legacy camera",
            "",
            "",
            "Example",
            "Rangefinder",
            "SERIAL-LEGACY",
            "2020-01-01",
            "500",
            "Camera shop",
            "",
            "legacy possession",
        );
        legacy.fields.remove("category");
        legacy.fields.remove("location");
        let id = legacy.id;
        {
            let session = lock_session(&runtime).expect("lock session");
            session
                .as_ref()
                .expect("unlocked session")
                .put_item(&legacy, 1)
                .expect("store old-shaped possession");
        }

        let listed = list_vault_items_impl(&runtime).expect("list old-shaped possession");
        assert!(listed.iter().any(|view| matches!(
            view,
            VaultItemView::Possession {
                id: listed_id,
                category,
                location,
                ..
            } if listed_id == &id.to_string() && category.is_empty() && location.is_empty()
        )));
        let detail = get_possession_impl(&runtime, id.to_string(), 1)
            .expect("read old-shaped possession detail");
        assert!(detail.category.is_empty());
        assert!(detail.location.is_empty());

        let updated = update_possession_impl(
            &runtime,
            id.to_string(),
            1,
            "Legacy camera".to_owned(),
            "Photography".to_owned(),
            "Display cabinet".to_owned(),
            "Example".to_owned(),
            "Rangefinder".to_owned(),
            "SERIAL-LEGACY".to_owned(),
            "2020-01-01".to_owned(),
            "500".to_owned(),
            "Camera shop".to_owned(),
            String::new(),
            "legacy possession".to_owned(),
        )
        .expect("add inventory metadata to old-shaped possession");
        assert_eq!(updated.revision, 2);
        assert_eq!(updated.category, "Photography");
        assert_eq!(updated.location, "Display cabinet");

        let historical = get_item_history_detail_impl(&runtime, id.to_string(), 2, 1)
            .expect("read pre-inventory history snapshot");
        assert!(matches!(
            historical,
            ItemHistoryDetailView::Possession {
                category,
                location,
                ..
            } if category.is_empty() && location.is_empty()
        ));

        let trashed_revision =
            trash_item_impl(&runtime, id.to_string(), updated.revision).expect("trash possession");
        let restored_revision =
            restore_trashed_item_impl(&runtime, id.to_string(), trashed_revision)
                .expect("restore possession");
        let restored = get_possession_impl(&runtime, id.to_string(), restored_revision)
            .expect("read restored possession");
        assert_eq!(restored.category, "Photography");
        assert_eq!(restored.location, "Display cabinet");
        assert_eq!(
            list_item_history_impl(&runtime, id.to_string(), restored_revision)
                .expect("history survives possession lifecycle"),
            vec![1]
        );
    }

    #[test]
    fn receipt_records_redact_detail_fields_validate_and_preserve_links() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");

        assert!(
            create_receipt_impl(
                &runtime,
                "Bad status".to_owned(),
                "Store".to_owned(),
                "2026-09-15".to_owned(),
                "100".to_owned(),
                "USD".to_owned(),
                "SECRET".to_owned(),
                "maybe".to_owned(),
                "2026-09-30".to_owned(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(
            create_receipt_impl(
                &runtime,
                "Bad date".to_owned(),
                "Store".to_owned(),
                "2026/09/15".to_owned(),
                "100".to_owned(),
                "USD".to_owned(),
                "SECRET".to_owned(),
                "return_planned".to_owned(),
                "2026-09-30".to_owned(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert_eq!(
            create_receipt_impl(
                &runtime,
                "Missing return deadline".to_owned(),
                "Store".to_owned(),
                "2026-09-15".to_owned(),
                "100".to_owned(),
                "USD".to_owned(),
                "SECRET".to_owned(),
                "return_planned".to_owned(),
                String::new(),
                String::new(),
                String::new(),
            )
            .err()
            .expect("planned return without date must fail"),
            "Set a return deadline when a return is planned."
        );
        assert_eq!(
            create_receipt_impl(
                &runtime,
                "Missing refund due".to_owned(),
                "Store".to_owned(),
                "2026-09-15".to_owned(),
                "100".to_owned(),
                "USD".to_owned(),
                "SECRET".to_owned(),
                "refund_pending".to_owned(),
                "2026-09-30".to_owned(),
                String::new(),
                String::new(),
            )
            .err()
            .expect("pending refund without date must fail"),
            "Set a refund due date while a refund is pending."
        );

        let receipt = create_receipt_impl(
            &runtime,
            "MacBook receipt".to_owned(),
            "Apple".to_owned(),
            "2026-09-15".to_owned(),
            "199900".to_owned(),
            "INR".to_owned(),
            "INV-SECRET-123".to_owned(),
            "return_planned".to_owned(),
            "2026-09-29".to_owned(),
            String::new(),
            "private receipt note".to_owned(),
        )
        .expect("create receipt");
        assert_eq!(receipt.revision, 1);
        assert!(receipt.has_receipt_reference);

        assert_eq!(
            update_receipt_impl(
                &runtime,
                receipt.id.clone(),
                receipt.revision,
                receipt.title.clone(),
                receipt.merchant.clone(),
                receipt.purchase_date.clone(),
                receipt.amount.clone(),
                receipt.currency.clone(),
                "INV-SECRET-123".to_owned(),
                "refund_pending".to_owned(),
                receipt.return_by.clone(),
                String::new(),
                "private receipt note".to_owned(),
            )
            .err()
            .expect("pending refund update without date must fail"),
            "Set a refund due date while a refund is pending."
        );
        let unchanged = get_receipt_impl(&runtime, receipt.id.clone(), receipt.revision)
            .expect("invalid update must not change receipt revision");
        assert_eq!(unchanged.tracking_status, "return_planned");

        let serialized =
            serde_json::to_string(&list_vault_items_impl(&runtime).expect("list with receipt"))
                .expect("serialize receipt list");
        assert!(serialized.contains("\"kind\":\"receipt\""));
        assert!(serialized.contains("has_receipt_reference"));
        assert!(!serialized.contains("INV-SECRET-123"));
        assert!(!serialized.contains("private receipt note"));

        let detail = get_receipt_impl(&runtime, receipt.id.clone(), receipt.revision)
            .expect("get receipt detail");
        assert_eq!(detail.receipt_reference, "INV-SECRET-123");
        assert_eq!(detail.notes, "private receipt note");
        assert!(get_receipt_impl(&runtime, receipt.id.clone(), 2).is_err());

        let target = create_note_impl(&runtime, "Purchase context".to_owned(), "Body".to_owned())
            .expect("create link target");
        let linked_revision = set_item_links_impl(
            &runtime,
            receipt.id.clone(),
            receipt.revision,
            vec![target.id],
        )
        .expect("link receipt");
        assert_eq!(linked_revision, 2);

        let updated = update_receipt_impl(
            &runtime,
            receipt.id.clone(),
            linked_revision,
            "MacBook receipt".to_owned(),
            "Apple".to_owned(),
            "2026-09-15".to_owned(),
            "199900".to_owned(),
            "INR".to_owned(),
            "INV-SECRET-456".to_owned(),
            "refund_pending".to_owned(),
            "2026-09-29".to_owned(),
            "2026-10-05".to_owned(),
            "refund requested".to_owned(),
        )
        .expect("update receipt");
        assert_eq!(updated.revision, 3);
        assert_eq!(updated.tracking_status, "refund_pending");
        assert_eq!(updated.links.len(), 1);
        assert!(
            update_receipt_impl(
                &runtime,
                receipt.id.clone(),
                linked_revision,
                "Stale receipt".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
            .is_err()
        );

        let trash_revision =
            trash_item_impl(&runtime, updated.id.clone(), updated.revision).expect("trash receipt");
        let restore_revision =
            restore_trashed_item_impl(&runtime, updated.id.clone(), trash_revision)
                .expect("restore receipt");
        let restored = get_receipt_impl(&runtime, updated.id.clone(), restore_revision)
            .expect("get restored receipt");
        assert_eq!(restored.receipt_reference, "INV-SECRET-456");

        lock_vault_impl(&runtime).expect("lock vault");
        assert!(get_receipt_impl(&runtime, updated.id.clone(), restore_revision).is_err());
        assert!(
            create_receipt_impl(
                &runtime,
                "Locked".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn version_history_ipc_is_redacted_exact_revision_and_locked_safe() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let credential = create_credential_impl(
            &runtime,
            "Primary email".to_owned(),
            "old-user@example.com".to_owned(),
            "HISTORY-SECRET-ALPHA".to_owned(),
            "https://example.com".to_owned(),
            "old private note".to_owned(),
        )
        .expect("create credential");
        let revision_two = set_item_legacy_disposition_impl(
            &runtime,
            credential.id.clone(),
            credential.revision,
            LegacyDisposition::PrivateForever,
        )
        .expect("advance credential revision");

        assert_eq!(
            list_item_history_impl(&runtime, credential.id.clone(), revision_two)
                .expect("list history"),
            vec![1]
        );
        let redacted =
            get_item_history_detail_impl(&runtime, credential.id.clone(), revision_two, 1)
                .expect("load redacted history");
        let serialized = serde_json::to_string(&redacted).expect("serialize history detail");
        assert!(serialized.contains("\"kind\":\"password\""));
        assert!(serialized.contains("\"has_password\":true"));
        assert!(!serialized.contains("HISTORY-SECRET-ALPHA"));

        assert_eq!(
            reveal_item_history_sensitive_impl(
                &runtime,
                credential.id.clone(),
                revision_two,
                1,
                ItemHistorySensitiveField::Password,
            )
            .expect("reveal historical password"),
            "HISTORY-SECRET-ALPHA"
        );
        assert!(
            reveal_item_history_sensitive_impl(
                &runtime,
                credential.id.clone(),
                revision_two,
                1,
                ItemHistorySensitiveField::AccountNumber,
            )
            .is_err()
        );

        let revision_three = set_credential_closure_plan_impl(
            &runtime,
            credential.id.clone(),
            revision_two,
            AccountClosurePlan {
                disposition: vault_models::AccountClosureDisposition::CloseAccount,
                instructions: "Close manually after exporting statements.".to_owned(),
            },
        )
        .expect("advance support revision");
        assert_eq!(
            list_item_history_impl(&runtime, credential.id.clone(), revision_three)
                .expect("list refreshed history"),
            vec![2, 1]
        );
        assert!(list_item_history_impl(&runtime, credential.id.clone(), revision_two).is_err());
        assert!(
            get_item_history_detail_impl(&runtime, credential.id.clone(), revision_two, 1).is_err()
        );

        let trashed_revision = trash_item_impl(&runtime, credential.id.clone(), revision_three)
            .expect("trash credential");
        assert!(
            list_item_history_impl(&runtime, credential.id.clone(), trashed_revision).is_err(),
            "Trash must retain history without exposing historical secrets"
        );
        let restored_revision =
            restore_trashed_item_impl(&runtime, credential.id.clone(), trashed_revision)
                .expect("restore credential");
        assert_eq!(
            list_item_history_impl(&runtime, credential.id.clone(), restored_revision)
                .expect("history is readable again after restore"),
            vec![2, 1]
        );

        lock_vault_impl(&runtime).expect("lock vault");
        assert!(list_item_history_impl(&runtime, credential.id, restored_revision).is_err());
    }

    #[test]
    fn historical_detail_projection_never_serializes_protected_fields() {
        let cases = vec![
            (
                VaultItem::password(
                    "Credential",
                    "user",
                    "SECRET-PASSWORD",
                    "example.com",
                    "note",
                ),
                "SECRET-PASSWORD",
            ),
            (
                VaultItem::document("Passport", "SECRET-DOCUMENT", "Issuer", "", "note"),
                "SECRET-DOCUMENT",
            ),
            (
                VaultItem::receipt(
                    "Receipt",
                    "Merchant",
                    "",
                    "100",
                    "USD",
                    "SECRET-RECEIPT",
                    "kept",
                    "",
                    "",
                    "note",
                ),
                "SECRET-RECEIPT",
            ),
            (
                VaultItem::insurance("Policy", "Provider", "Home", "SECRET-POLICY", "", "note"),
                "SECRET-POLICY",
            ),
            (
                VaultItem::financial(
                    "Account",
                    "Bank",
                    "Checking",
                    "USD",
                    "SECRET-ACCOUNT",
                    "note",
                ),
                "SECRET-ACCOUNT",
            ),
            (
                VaultItem::property(
                    "Home",
                    "House",
                    "SECRET-ADDRESS",
                    "Owned",
                    "property-ref",
                    "note",
                ),
                "SECRET-ADDRESS",
            ),
            (
                VaultItem::vehicle(
                    "Car",
                    "Make",
                    "Model",
                    "2026",
                    "SECRET-REGISTRATION",
                    "vin-value",
                    "",
                    "note",
                ),
                "SECRET-REGISTRATION",
            ),
            (
                VaultItem::possession(
                    "Laptop",
                    "Electronics",
                    "Home office",
                    "Brand",
                    "Model",
                    "SECRET-SERIAL",
                    "",
                    "",
                    "",
                    "",
                    "note",
                ),
                "SECRET-SERIAL",
            ),
        ];

        for (item, protected) in cases {
            let projected = item_history_detail_view(item, 7).expect("project historical item");
            let serialized = serde_json::to_string(&projected).expect("serialize projected item");
            assert!(
                !serialized.contains(protected),
                "protected historical field leaked into detail projection"
            );
        }

        let attachment_id = "12345678-1234-4234-8234-123456789abc";
        let mut with_attachment =
            VaultItem::password("Credential", "user", "password", "example.com", "");
        with_attachment
            .attachments
            .push(attachment_id.parse().expect("attachment id"));
        let projected =
            item_history_detail_view(with_attachment, 9).expect("project attachment summary");
        let serialized = serde_json::to_string(&projected).expect("serialize attachment summary");
        assert!(serialized.contains("\"attachment_count\":1"));
        assert!(!serialized.contains(attachment_id));
    }

    #[test]
    fn emergency_card_round_trip_and_stale_rejected() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");

        assert!(
            get_emergency_card_impl(&runtime)
                .expect("load empty card")
                .is_none()
        );

        let stale_before_create =
            update_emergency_card_impl(&runtime, Some(1), Vec::new(), Vec::new(), String::new())
                .expect_err("create with revision must be stale");
        assert_eq!(
            stale_before_create,
            "The emergency card changed since you opened it. Reload it before saving."
        );

        let note = create_note_impl(&runtime, "Card target".to_owned(), "Body".to_owned())
            .expect("create note");
        let contact = ContactPayload {
            name: "Ada".to_owned(),
            relation: "Sibling".to_owned(),
            phone: "+1-555-0100".to_owned(),
            email: "ada@example.test".to_owned(),
            notes: "Call first".to_owned(),
        };
        let rev1 = update_emergency_card_impl(
            &runtime,
            None,
            vec![note.id.clone()],
            vec![contact.clone()],
            "Follow the printed steps".to_owned(),
        )
        .expect("create emergency card");
        assert_eq!(rev1, 1);

        let loaded = get_emergency_card_impl(&runtime)
            .expect("load card")
            .expect("card present");
        assert_eq!(loaded.revision, 1);
        assert_eq!(loaded.card.selected_item_ids, vec![note.id.clone()]);
        assert_eq!(loaded.card.contacts.len(), 1);
        assert_eq!(loaded.card.contacts[0].name, "Ada");
        assert_eq!(loaded.card.contacts[0].email, "ada@example.test");
        assert_eq!(loaded.card.instructions, "Follow the printed steps");

        let second = create_note_impl(&runtime, "Second target".to_owned(), "Body".to_owned())
            .expect("create second note");
        let updated_contact = ContactPayload {
            name: "Bob".to_owned(),
            relation: "Friend".to_owned(),
            phone: "+1-555-0200".to_owned(),
            email: String::new(),
            notes: String::new(),
        };
        let rev2 = update_emergency_card_impl(
            &runtime,
            Some(1),
            vec![note.id.clone(), second.id.clone()],
            vec![updated_contact.clone()],
            "Updated instructions".to_owned(),
        )
        .expect("update emergency card");
        assert_eq!(rev2, 2);

        let loaded = get_emergency_card_impl(&runtime)
            .expect("load updated card")
            .expect("card present");
        assert_eq!(loaded.revision, 2);
        assert_eq!(loaded.card.selected_item_ids.len(), 2);
        assert_eq!(loaded.card.contacts[0].name, "Bob");
        assert_eq!(loaded.card.instructions, "Updated instructions");

        let stale = update_emergency_card_impl(
            &runtime,
            Some(1),
            vec![note.id.clone()],
            Vec::new(),
            "stale".to_owned(),
        )
        .expect_err("stale card update must fail");
        assert_eq!(
            stale,
            "The emergency card changed since you opened it. Reload it before saving."
        );

        let missing_revision =
            update_emergency_card_impl(&runtime, None, Vec::new(), Vec::new(), "stale".to_owned())
                .expect_err("missing revision must be stale");
        assert_eq!(
            missing_revision,
            "The emergency card changed since you opened it. Reload it before saving."
        );

        let invalid = update_emergency_card_impl(
            &runtime,
            Some(2),
            vec!["not-a-uuid".to_owned()],
            Vec::new(),
            String::new(),
        )
        .expect_err("invalid selected id must fail");
        assert_eq!(invalid, "One of the selected records is invalid.");
    }

    #[test]
    fn item_titles_skip_invalid_missing_and_card_singleton() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");

        let note = create_note_impl(&runtime, "Titled note".to_owned(), "Body".to_owned())
            .expect("create note");
        let credential = create_credential_impl(
            &runtime,
            "Titled login".to_owned(),
            "user".to_owned(),
            "secret".to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create credential");
        let missing = "00000000-0000-0000-0000-000000000099".to_owned();
        let card_singleton = EMERGENCY_CARD_ID.to_string();

        let titles = get_item_titles_impl(
            &runtime,
            vec![
                note.id.clone(),
                "not-a-uuid".to_owned(),
                missing,
                card_singleton,
                credential.id.clone(),
            ],
        )
        .expect("get titles");
        assert_eq!(titles.len(), 2);
        assert_eq!(titles[0].id, note.id);
        assert_eq!(titles[0].title, "Titled note");
        assert_eq!(titles[1].id, credential.id);
        assert_eq!(titles[1].title, "Titled login");
    }

    #[test]
    fn item_links_set_persist_bump_and_rejections() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");

        let first = create_note_impl(&runtime, "First".to_owned(), "Body".to_owned())
            .expect("create first");
        let second = create_note_impl(&runtime, "Second".to_owned(), "Body".to_owned())
            .expect("create second");
        assert!(first.links.is_empty());

        let rev2 = set_item_links_impl(
            &runtime,
            first.id.clone(),
            first.revision,
            vec![second.id.clone()],
        )
        .expect("set links");
        assert_eq!(rev2, 2);

        {
            let session = lock_session(&runtime).expect("lock session");
            let session = session.as_ref().expect("unlocked");
            let parsed = first.id.parse().expect("parse id");
            let (item, revision) = session
                .get_item_with_revision(parsed)
                .expect("load linked item");
            assert_eq!(revision, 2);
            assert_eq!(item.links.len(), 1);
            assert_eq!(item.links[0].to_string(), second.id);
        }

        let listed = list_vault_items_impl(&runtime).expect("list items");
        let linked = listed
            .iter()
            .find_map(|item| match item {
                VaultItemView::SecureNote { id, links, .. } if id == &first.id => Some(links),
                _ => None,
            })
            .expect("linked note in list");
        assert_eq!(linked, &vec![second.id.clone()]);

        let stale = set_item_links_impl(&runtime, first.id.clone(), first.revision, Vec::new())
            .expect_err("stale links update must fail");
        assert_eq!(
            stale,
            "This record changed since you opened it. Reload it before saving."
        );

        let card_as_target =
            set_item_links_impl(&runtime, EMERGENCY_CARD_ID.to_string(), 1, Vec::new())
                .expect_err("card target must fail");
        assert_eq!(card_as_target, "The emergency card cannot be linked.");

        let card_as_link = set_item_links_impl(
            &runtime,
            first.id.clone(),
            rev2,
            vec![EMERGENCY_CARD_ID.to_string()],
        )
        .expect_err("card link must fail");
        assert_eq!(card_as_link, "The emergency card cannot be linked.");

        let bad_link = set_item_links_impl(
            &runtime,
            first.id.clone(),
            rev2,
            vec!["not-a-uuid".to_owned()],
        )
        .expect_err("bad link must fail");
        assert_eq!(bad_link, "One of the linked records is invalid.");
    }

    #[test]
    fn legacy_disposition_is_detail_only_and_stale_safe() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let note = create_note_impl(&runtime, "Legacy record".to_owned(), "Body".to_owned())
            .expect("create note");

        assert_eq!(
            get_item_legacy_disposition_impl(&runtime, note.id.clone(), note.revision)
                .expect("get initial disposition"),
            LegacyDisposition::Unspecified
        );
        let revision = set_item_legacy_disposition_impl(
            &runtime,
            note.id.clone(),
            note.revision,
            LegacyDisposition::SelectedForLegacy,
        )
        .expect("set disposition");
        assert_eq!(revision, note.revision + 1);
        assert_eq!(
            get_item_legacy_disposition_impl(&runtime, note.id.clone(), revision)
                .expect("get updated disposition"),
            LegacyDisposition::SelectedForLegacy
        );

        let stale = set_item_legacy_disposition_impl(
            &runtime,
            note.id.clone(),
            note.revision,
            LegacyDisposition::PrivateForever,
        )
        .expect_err("stale disposition update must fail");
        assert_eq!(
            stale,
            "This record changed since you opened it. Reload it before saving."
        );

        let serialized = serde_json::to_string(
            &list_vault_items_impl(&runtime).expect("list items after disposition update"),
        )
        .expect("serialize list projection");
        assert!(!serialized.contains("legacy_disposition"));
        assert!(!serialized.contains("selected_for_legacy"));
    }

    #[test]
    fn credential_closure_plan_is_detail_only_stale_safe_and_survives_credential_edit() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let credential = create_credential_impl(
            &runtime,
            "Primary email".to_owned(),
            "owner@example.test".to_owned(),
            "secret-password".to_owned(),
            "https://example.test".to_owned(),
            "private note".to_owned(),
        )
        .expect("create credential");

        assert_eq!(
            get_credential_closure_plan_impl(&runtime, credential.id.clone(), credential.revision,)
                .expect("get initial closure plan"),
            AccountClosurePlan::default()
        );
        let plan = AccountClosurePlan {
            disposition: vault_models::AccountClosureDisposition::CloseAccount,
            instructions: "CLOSURE-PRIVATE-MARKER export statements before closing.".to_owned(),
        };
        let revision = set_credential_closure_plan_impl(
            &runtime,
            credential.id.clone(),
            credential.revision,
            plan.clone(),
        )
        .expect("set closure plan");
        assert_eq!(revision, credential.revision + 1);
        assert_eq!(
            get_credential_closure_plan_impl(&runtime, credential.id.clone(), revision)
                .expect("get updated closure plan"),
            plan
        );

        let stale = set_credential_closure_plan_impl(
            &runtime,
            credential.id.clone(),
            credential.revision,
            AccountClosurePlan::default(),
        )
        .expect_err("stale closure update must fail");
        assert_eq!(
            stale,
            "This credential changed since you opened it. Reload it before saving."
        );

        let note = create_note_impl(&runtime, "Not an account".to_owned(), "Body".to_owned())
            .expect("create note");
        assert!(
            get_credential_closure_plan_impl(&runtime, note.id.clone(), note.revision).is_err()
        );
        assert!(
            set_credential_closure_plan_impl(&runtime, note.id, note.revision, plan.clone(),)
                .is_err()
        );

        let edited = update_credential_impl(
            &runtime,
            credential.id.clone(),
            revision,
            "Primary email updated".to_owned(),
            "new-owner@example.test".to_owned(),
            "new-secret-password".to_owned(),
            "https://example.test/account".to_owned(),
            "updated note".to_owned(),
        )
        .expect("edit credential after setting closure plan");
        assert_eq!(
            get_credential_closure_plan_impl(&runtime, credential.id.clone(), edited.revision)
                .expect("closure plan survives credential edit"),
            plan
        );

        let serialized = serde_json::to_string(
            &list_vault_items_impl(&runtime).expect("list items after closure update"),
        )
        .expect("serialize list projection");
        assert!(!serialized.contains("account_closure_plan"));
        assert!(!serialized.contains("CLOSURE-PRIVATE-MARKER"));
        assert!(!serialized.contains("close_account"));
    }

    #[test]
    fn deadlines_include_vehicle_and_possession_and_skip_garbage() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");

        let vehicle = create_vehicle_impl(
            &runtime,
            "Deadline car".to_owned(),
            "Toyota".to_owned(),
            "Innova".to_owned(),
            "2021".to_owned(),
            String::new(),
            String::new(),
            "2099-06-01".to_owned(),
            String::new(),
        )
        .expect("create vehicle");
        let possession = create_possession_impl(
            &runtime,
            "Deadline laptop".to_owned(),
            "Electronics".to_owned(),
            "Office".to_owned(),
            "Apple".to_owned(),
            "Pro 14".to_owned(),
            String::new(),
            "2024-01-15".to_owned(),
            "100".to_owned(),
            "Store".to_owned(),
            "2099-01-15".to_owned(),
            String::new(),
        )
        .expect("create possession");
        let _garbage = create_document_impl(
            &runtime,
            "Garbage doc".to_owned(),
            String::new(),
            "Issuer".to_owned(),
            "not-a-date".to_owned(),
            String::new(),
        )
        .expect("create garbage document");
        let _note = create_note_impl(&runtime, "Plain note".to_owned(), "Body".to_owned())
            .expect("create note");

        let deadlines = list_deadlines_impl(&runtime, 2026, 9, 15).expect("list deadlines");
        assert!(deadlines.len() >= 2);
        let vehicle_deadline = deadlines
            .iter()
            .find(|deadline| deadline.item_id == vehicle.id)
            .expect("vehicle deadline");
        assert_eq!(vehicle_deadline.title, "Deadline car");
        assert_eq!(vehicle_deadline.label, "Vehicle renewal");
        assert_eq!(vehicle_deadline.date, "2099-06-01");
        let possession_deadline = deadlines
            .iter()
            .find(|deadline| deadline.item_id == possession.id)
            .expect("possession deadline");
        assert_eq!(possession_deadline.title, "Deadline laptop");
        assert_eq!(possession_deadline.label, "Warranty expiry");
        assert_eq!(possession_deadline.date, "2099-01-15");
        assert!(
            !deadlines
                .iter()
                .any(|deadline| deadline.title == "Garbage doc")
        );
        assert!(
            !deadlines
                .iter()
                .any(|deadline| deadline.title == "Plain note")
        );
    }

    #[test]
    fn subscription_is_local_revision_safe_historical_and_deadline_aware() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");

        assert!(
            create_subscription_impl(
                &runtime,
                " ".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(
            create_subscription_impl(
                &runtime,
                "Bad cycle".to_owned(),
                "Provider".to_owned(),
                "Plan".to_owned(),
                "10".to_owned(),
                "USD".to_owned(),
                "weekly".to_owned(),
                "2099-01-15".to_owned(),
                String::new(),
            )
            .is_err()
        );
        assert!(
            create_subscription_impl(
                &runtime,
                "Bad date".to_owned(),
                "Provider".to_owned(),
                "Plan".to_owned(),
                "10".to_owned(),
                "USD".to_owned(),
                "monthly".to_owned(),
                "2099-02-30".to_owned(),
                String::new(),
            )
            .is_err()
        );

        let created = create_subscription_impl(
            &runtime,
            "Local streaming".to_owned(),
            "Example Media".to_owned(),
            "Family".to_owned(),
            "19.99".to_owned(),
            "USD".to_owned(),
            "monthly".to_owned(),
            "2099-01-15".to_owned(),
            "Cancel manually if no longer needed.".to_owned(),
        )
        .expect("create subscription");
        assert_eq!(created.revision, 1);
        assert_eq!(created.provider, "Example Media");

        let serialized = serde_json::to_string(
            &list_vault_items_impl(&runtime).expect("list items with subscription"),
        )
        .expect("serialize item list");
        assert!(serialized.contains("\"kind\":\"subscription\""));
        assert!(serialized.contains("Local streaming"));

        let updated = update_subscription_impl(
            &runtime,
            created.id.clone(),
            created.revision,
            "Local streaming".to_owned(),
            "Example Media".to_owned(),
            "Family Plus".to_owned(),
            "24.99".to_owned(),
            "USD".to_owned(),
            "yearly".to_owned(),
            "2099-02-15".to_owned(),
            "Still tracked locally only.".to_owned(),
        )
        .expect("update subscription");
        assert_eq!(updated.revision, 2);
        assert_eq!(updated.plan, "Family Plus");
        assert!(
            update_subscription_impl(
                &runtime,
                created.id.clone(),
                1,
                "Stale".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
            .is_err()
        );

        assert_eq!(
            list_item_history_impl(&runtime, created.id.clone(), updated.revision)
                .expect("subscription history"),
            vec![1]
        );
        let historical =
            get_item_history_detail_impl(&runtime, created.id.clone(), updated.revision, 1)
                .expect("historical subscription detail");
        let historical = serde_json::to_string(&historical).expect("serialize history");
        assert!(historical.contains("\"kind\":\"subscription\""));
        assert!(historical.contains("Family"));

        let trashed_revision = trash_item_impl(&runtime, updated.id.clone(), updated.revision)
            .expect("trash subscription");
        assert!(get_subscription_impl(&runtime, updated.id.clone(), trashed_revision).is_err());
        let restored_revision =
            restore_trashed_item_impl(&runtime, updated.id.clone(), trashed_revision)
                .expect("restore subscription");
        let restored = get_subscription_impl(&runtime, updated.id.clone(), restored_revision)
            .expect("get restored subscription");
        assert_eq!(restored.plan, "Family Plus");
        assert_eq!(restored.next_renewal, "2099-02-15");
        assert_eq!(
            list_item_history_impl(&runtime, updated.id.clone(), restored_revision)
                .expect("restored subscription history"),
            vec![1]
        );

        let deadlines = list_deadlines_impl(&runtime, 2099, 2, 14).expect("list deadlines");
        let renewal = deadlines
            .iter()
            .find(|deadline| deadline.item_id == updated.id)
            .expect("subscription renewal deadline");
        assert_eq!(renewal.label, "Subscription renewal");
        assert_eq!(renewal.date, "2099-02-15");
        assert_eq!(renewal.days_until, 1);

        lock_vault_impl(&runtime).expect("lock vault");
        assert!(get_subscription_impl(&runtime, updated.id, restored_revision).is_err());
    }

    #[test]
    fn deadlines_use_supplied_device_local_calendar_day() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let document = create_document_impl(
            &runtime,
            "Local-day document".to_owned(),
            String::new(),
            "Issuer".to_owned(),
            "2026-09-16".to_owned(),
            String::new(),
        )
        .expect("create document");

        let before = list_deadlines_impl(&runtime, 2026, 9, 15).expect("deadlines before due day");
        let before = before
            .iter()
            .find(|deadline| deadline.item_id == document.id)
            .expect("document deadline before due day");
        assert_eq!(before.days_until, 1);

        let due = list_deadlines_impl(&runtime, 2026, 9, 16).expect("deadlines on due day");
        let due = due
            .iter()
            .find(|deadline| deadline.item_id == document.id)
            .expect("document deadline on due day");
        assert_eq!(due.days_until, 0);

        let invalid = match list_deadlines_impl(&runtime, 2026, 2, 30) {
            Ok(_) => panic!("invalid local date must fail"),
            Err(error) => error,
        };
        assert_eq!(invalid, "The device local calendar date is invalid.");
    }

    #[test]
    fn recovery_kit_generate_confirm_lock_unlock() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");

        let status = get_recovery_status_impl(&runtime).expect("initial status");
        assert!(!status.configured);

        let generated = generate_recovery_secret_impl(&runtime).expect("generate secret");
        assert_eq!(generated.secret.len(), 64);
        assert!(
            generated
                .secret
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        let still_empty = get_recovery_status_impl(&runtime).expect("status after generate");
        assert!(!still_empty.configured);

        let bad =
            confirm_recovery_secret_impl(&runtime, "not-a-secret".to_owned(), generated.generation)
                .expect_err("bad secret must fail");
        assert_eq!(
            bad,
            "The recovery secret is invalid. Check all 64 characters and try again."
        );

        confirm_recovery_secret_impl(&runtime, generated.secret.to_string(), generated.generation)
            .expect("confirm secret");
        let configured = get_recovery_status_impl(&runtime).expect("configured status");
        assert!(configured.configured);

        lock_vault_impl(&runtime).expect("lock vault");
        unlock_vault_with_recovery_kit_impl(&runtime, generated.secret.to_string())
            .expect("unlock with kit");
        assert!(vault_status_impl(&runtime).expect("status").unlocked);

        lock_vault_impl(&runtime).expect("lock again");
        let mut wrong_bytes = generated.secret.to_string();
        let first = wrong_bytes.remove(0);
        let flipped = if first == 'a' { 'b' } else { 'a' };
        wrong_bytes.insert(0, flipped);
        let wrong_error = match unlock_vault_with_recovery_kit_impl(&runtime, wrong_bytes) {
            Ok(_) => panic!("wrong recovery kit unexpectedly unlocked the vault"),
            Err(error) => error,
        };
        assert_eq!(
            wrong_error,
            "Unable to unlock with this recovery kit. Check the secret and try again."
        );
        assert!(!vault_status_impl(&runtime).expect("locked status").unlocked);
    }

    #[test]
    fn recovery_key_save_is_exact_and_stale_generation_cannot_publish() {
        let (directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let generated = generate_recovery_secret_impl(&runtime).expect("generate secret");
        let destination = directory.path().join("recovery-key.txt");

        save_recovery_secret_impl_for_generation(
            &runtime,
            &generated.secret,
            generated.generation,
            &destination,
        )
        .expect("save recovery key");
        assert_eq!(
            fs::read_to_string(&destination).expect("read recovery key"),
            format!("{}\n", generated.secret.as_str())
        );

        let existing = directory.path().join("existing-recovery-key.txt");
        fs::write(&existing, b"existing recovery file\n").expect("seed existing file");
        assert!(
            save_recovery_secret_impl_for_generation(
                &runtime,
                &generated.secret,
                generated.generation,
                &existing,
            )
            .is_err()
        );
        assert_eq!(
            fs::read_to_string(&existing).expect("existing destination survives"),
            "existing recovery file\n"
        );

        lock_vault_impl(&runtime).expect("lock vault");
        unlock_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("unlock vault");
        let stale_destination = directory.path().join("stale-recovery-key.txt");
        let error = save_recovery_secret_impl_for_generation(
            &runtime,
            &generated.secret,
            generated.generation,
            &stale_destination,
        )
        .expect_err("stale recovery key publication must fail");
        assert!(error.contains("session changed"));
        assert!(!stale_destination.exists());
    }

    #[test]
    fn stale_generated_recovery_key_cannot_be_confirmed_after_reunlock() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let generated = generate_recovery_secret_impl(&runtime).expect("generate secret");

        lock_vault_impl(&runtime).expect("lock vault");
        unlock_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("unlock vault");
        let error = confirm_recovery_secret_impl(
            &runtime,
            generated.secret.to_string(),
            generated.generation,
        )
        .expect_err("stale generated key must fail");
        assert!(error.contains("session changed"));
        assert!(
            !get_recovery_status_impl(&runtime)
                .expect("recovery status")
                .configured
        );
    }

    #[test]
    fn recovery_key_self_test_is_read_only_and_returns_only_match_status() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let generated = generate_recovery_secret_impl(&runtime).expect("generate secret");
        confirm_recovery_secret_impl(&runtime, generated.secret.to_string(), generated.generation)
            .expect("install recovery key");
        let generation = capture_session_generation(&runtime);

        assert!(
            verify_recovery_secret_impl(&runtime, generated.secret.to_string())
                .expect("verify installed recovery key")
        );
        assert!(
            !verify_recovery_secret_impl(&runtime, "not-a-recovery-key".to_owned())
                .expect("malformed key is a mismatch")
        );
        let mut wrong = generated.secret.to_string();
        let first = wrong.remove(0);
        wrong.insert(0, if first == 'a' { 'b' } else { 'a' });
        assert!(!verify_recovery_secret_impl(&runtime, wrong).expect("wrong key is a mismatch"));
        assert_eq!(capture_session_generation(&runtime), generation);
        assert!(vault_status_impl(&runtime).expect("vault status").unlocked);
    }

    #[test]
    fn plan_readiness_is_metadata_only_and_detects_stale_card_references() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let active = create_note_impl(&runtime, "Executor packet".to_owned(), "secret".to_owned())
            .expect("create active note");
        let stale = create_note_impl(&runtime, "Old packet".to_owned(), "secret".to_owned())
            .expect("create stale note");
        update_emergency_card_impl(
            &runtime,
            None,
            vec![active.id.clone(), stale.id.clone()],
            vec![ContactPayload {
                name: "Private Contact Name".to_owned(),
                relation: "Sibling".to_owned(),
                phone: "+1-555-0199".to_owned(),
                email: "private@example.test".to_owned(),
                notes: "Private contact notes".to_owned(),
            }],
            "Private emergency instructions".to_owned(),
        )
        .expect("set emergency card");
        trash_item_impl(&runtime, stale.id, stale.revision).expect("trash selected record");
        let active_revision = set_item_legacy_disposition_impl(
            &runtime,
            active.id.clone(),
            active.revision,
            LegacyDisposition::SelectedForLegacy,
        )
        .expect("set active legacy preference");
        assert_eq!(active_revision, active.revision + 1);
        let generated = generate_recovery_secret_impl(&runtime).expect("generate recovery key");
        confirm_recovery_secret_impl(&runtime, generated.secret.to_string(), generated.generation)
            .expect("install recovery key");

        let readiness = get_plan_readiness_impl(&runtime).expect("plan readiness");
        assert!(readiness.recovery_configured);
        assert!(readiness.has_selected_records);
        assert!(readiness.has_contacts);
        assert!(readiness.has_instructions);
        assert!(readiness.has_stale_selected_records);
        assert!(readiness.has_legacy_preferences);
        assert!(!readiness.has_unspecified_legacy_items);
        let serialized = serde_json::to_string(&readiness).expect("serialize readiness");
        assert!(!serialized.contains("Private Contact Name"));
        assert!(!serialized.contains("Private emergency instructions"));
        assert!(!serialized.contains("Executor packet"));
    }

    #[test]
    fn plan_readiness_does_not_count_a_blank_emergency_contact() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        update_emergency_card_impl(
            &runtime,
            None,
            Vec::new(),
            vec![ContactPayload {
                name: String::new(),
                relation: String::new(),
                phone: String::new(),
                email: String::new(),
                notes: String::new(),
            }],
            String::new(),
        )
        .expect("set blank emergency contact");

        let readiness = get_plan_readiness_impl(&runtime).expect("plan readiness");
        assert!(!readiness.has_contacts);
    }

    #[test]
    fn plan_readiness_counts_named_email_only_emergency_contact() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        update_emergency_card_impl(
            &runtime,
            None,
            Vec::new(),
            vec![ContactPayload {
                name: "Email Contact".to_owned(),
                relation: "Friend".to_owned(),
                phone: String::new(),
                email: "helper@example.test".to_owned(),
                notes: String::new(),
            }],
            String::new(),
        )
        .expect("set email-only emergency contact");

        let readiness = get_plan_readiness_impl(&runtime).expect("plan readiness");
        assert!(readiness.has_contacts);
        let serialized = serde_json::to_string(&readiness).expect("serialize readiness");
        assert!(!serialized.contains("helper@example.test"));
    }

    #[test]
    fn export_and_backup_copy_contain_seeded_data() {
        let (directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");

        let note = create_note_impl(
            &runtime,
            "Seeded Export Title".to_owned(),
            "Export body".to_owned(),
        )
        .expect("create note");
        set_item_legacy_disposition_impl(
            &runtime,
            note.id.clone(),
            note.revision,
            LegacyDisposition::SelectedForLegacy,
        )
        .expect("set export legacy preference");
        let credential = create_credential_impl(
            &runtime,
            "Export account plan".to_owned(),
            "owner".to_owned(),
            "secret".to_owned(),
            "https://example.test".to_owned(),
            String::new(),
        )
        .expect("create export credential");
        set_credential_closure_plan_impl(
            &runtime,
            credential.id.clone(),
            credential.revision,
            AccountClosurePlan {
                disposition: vault_models::AccountClosureDisposition::ReviewManually,
                instructions: "EXPORT-CLOSURE-MARKER review tax documents first.".to_owned(),
            },
        )
        .expect("set export account closure plan");
        create_subscription_impl(
            &runtime,
            "Export subscription".to_owned(),
            "EXPORT-SUBSCRIPTION-PROVIDER".to_owned(),
            "Annual".to_owned(),
            "99".to_owned(),
            "USD".to_owned(),
            "yearly".to_owned(),
            "2099-12-31".to_owned(),
            "Export subscription note".to_owned(),
        )
        .expect("create export subscription");
        create_possession_impl(
            &runtime,
            "Export camera".to_owned(),
            "Photography".to_owned(),
            "Display cabinet".to_owned(),
            "Example".to_owned(),
            "Rangefinder".to_owned(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "export possession note".to_owned(),
        )
        .expect("create export possession");
        update_emergency_card_impl(
            &runtime,
            None,
            vec![note.id.clone()],
            vec![ContactPayload {
                name: "Export Contact".to_owned(),
                relation: "Sibling".to_owned(),
                phone: String::new(),
                email: "export-contact@example.test".to_owned(),
                notes: String::new(),
            }],
            "Export card instructions".to_owned(),
        )
        .expect("create card");

        let export_path = directory
            .path()
            .join("export.json")
            .to_string_lossy()
            .to_string();
        let exported =
            export_human_readable_impl(&runtime, export_path.clone()).expect("export vault");
        assert_eq!(exported.path, export_path);
        assert!(exported.items >= 1);
        assert_eq!(
            get_device_settings_impl(&runtime)
                .expect("settings after readable export")
                .last_successful_encrypted_backup_at_ms,
            None
        );
        let bytes = fs::read(&export_path).expect("read export");
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("export is valid JSON");
        assert_eq!(parsed["app"], serde_json::json!("safeory"));
        assert_eq!(parsed["format"], serde_json::json!(1));
        let serialized = serde_json::to_string(&parsed).expect("serialize export");
        assert!(serialized.contains("Seeded Export Title"));
        assert!(serialized.contains("Export card instructions"));
        assert!(serialized.contains("export-contact@example.test"));
        assert!(serialized.contains("selected_for_legacy"));
        assert!(serialized.contains("EXPORT-CLOSURE-MARKER"));
        assert!(serialized.contains("review_manually"));
        assert!(serialized.contains("EXPORT-SUBSCRIPTION-PROVIDER"));
        assert!(serialized.contains("\"kind\":\"subscription\""));
        assert!(serialized.contains("Photography"));
        assert!(serialized.contains("Display cabinet"));

        let backup_path = directory
            .path()
            .join("backup.sqlite3")
            .to_string_lossy()
            .to_string();
        let before_backup_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock before backup")
                .as_millis(),
        )
        .expect("backup time fits u64");
        let backed_up =
            backup_database_copy_impl(&runtime, backup_path.clone()).expect("backup database");
        let after_backup_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after backup")
                .as_millis(),
        )
        .expect("backup time fits u64");
        let recorded_backup_ms = backed_up
            .settings
            .expect("backup status recorded")
            .last_successful_encrypted_backup_at_ms
            .expect("backup timestamp recorded");
        assert!((before_backup_ms..=after_backup_ms).contains(&recorded_backup_ms));
        let settings_text = fs::read_to_string(&runtime.settings_path).expect("read settings");
        assert!(!settings_text.contains(&backup_path));
        assert!(!settings_text.contains("backup.sqlite3"));
        let backup_bytes = fs::read(&backup_path).expect("read backup");
        assert!(!backup_bytes.is_empty());
        assert!(backup_bytes.len() >= 16);
        assert_eq!(&backup_bytes[..16], b"SQLite format 3\0");
        let backup_session = VaultSession::unlock(&backup_path, PASSPHRASE)
            .expect("encrypted backup unlocks with its master passphrase");
        backup_session
            .validate_persisted_state()
            .expect("encrypted backup validates completely");
        assert!(
            backup_session
                .list_items()
                .expect("list backup items")
                .iter()
                .any(|item| item.kind == ItemKind::Subscription)
        );
        assert!(
            backup_session
                .list_items()
                .expect("list backup possessions")
                .iter()
                .any(|item| item.kind == ItemKind::Possession
                    && item.fields.get("category").map(String::as_str) == Some("Photography")
                    && item.fields.get("location").map(String::as_str) == Some("Display cabinet"))
        );
        let backup_card = backup_session
            .get_emergency_card()
            .expect("read backup emergency card")
            .expect("backup emergency card present")
            .0;
        assert_eq!(backup_card.contacts[0].email, "export-contact@example.test");
    }

    #[test]
    fn human_readable_export_lock_after_capture_prevents_publish_and_cleans_stage() {
        let (directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        create_note_impl(
            &runtime,
            "Export race marker".to_owned(),
            "plaintext body".to_owned(),
        )
        .expect("create export marker");

        let destination = directory.path().join("generation-fenced-export.json");
        let HumanReadableExportSnapshot {
            items,
            emergency_card,
            generation,
        } = capture_human_readable_export(&runtime).expect("capture export snapshot");
        let (staged, _) = stage_human_readable_export(&items, emergency_card, &destination)
            .expect("stage plaintext export");
        assert!(staged.exists());

        lock_vault_impl(&runtime).expect("lock after export capture");
        let error = commit_human_readable_export(&runtime, generation, &staged, &destination)
            .expect_err("stale export must not publish");

        assert_eq!(
            error,
            "The vault session changed while creating the export. Try again."
        );
        assert!(!staged.exists());
        assert!(!destination.exists());
    }

    #[test]
    fn human_readable_export_cancels_and_cleans_partial_plaintext_stage() {
        let (directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        create_note_impl(
            &runtime,
            "Cancellation marker".to_owned(),
            "Plaintext must not survive a stale generation.".to_owned(),
        )
        .expect("create export marker");
        let destination = directory.path().join("cancelled-readable-export.json");
        let HumanReadableExportSnapshot {
            items,
            emergency_card,
            generation,
        } = capture_human_readable_export(&runtime).expect("capture export snapshot");
        let checks = std::cell::Cell::new(0usize);

        let result =
            stage_human_readable_export_with_cancel(&items, emergency_card, &destination, || {
                let next = checks.get() + 1;
                checks.set(next);
                if next == 5 {
                    advance_session_generation(&runtime.session_generation);
                }
                !is_session_generation_current(&runtime, generation)
            });

        assert_eq!(
            result.expect_err("stale generation must cancel plaintext staging"),
            "The vault session changed while creating the export. Try again."
        );
        assert!(checks.get() >= 5);
        assert!(!destination.exists());
        let stage_prefix = ".cancelled-readable-export.json.export-";
        assert!(
            fs::read_dir(directory.path())
                .expect("list export directory")
                .filter_map(Result::ok)
                .all(|entry| {
                    !entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(stage_prefix)
                })
        );
    }

    #[test]
    fn export_paths_cannot_replace_the_active_database() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        create_note_impl(
            &runtime,
            "Self-target guard".to_owned(),
            "Still encrypted".to_owned(),
        )
        .expect("create guarded record");
        let database_path = runtime.database_path.to_string_lossy().to_string();

        let readable_error = match export_human_readable_impl(&runtime, database_path.clone()) {
            Ok(_) => panic!("readable export must reject active database"),
            Err(error) => error,
        };
        assert_eq!(
            readable_error,
            "Choose an export path other than the active Safeory database."
        );
        let backup_error = match backup_database_copy_impl(&runtime, database_path.clone()) {
            Ok(_) => panic!("encrypted backup must reject active database"),
            Err(error) => error,
        };
        assert_eq!(
            backup_error,
            "Choose a backup path other than the active Safeory database."
        );
        assert_eq!(
            get_device_settings_impl(&runtime)
                .expect("settings after rejected backup")
                .last_successful_encrypted_backup_at_ms,
            None
        );

        let bytes = fs::read(&database_path).expect("read live database after rejected exports");
        assert!(bytes.len() >= 16);
        assert_eq!(&bytes[..16], b"SQLite format 3\0");
        assert!(
            list_vault_items_impl(&runtime)
                .expect("live vault remains readable")
                .iter()
                .any(|item| matches!(item, VaultItemView::SecureNote { title, .. } if title == "Self-target guard"))
        );
    }

    #[test]
    fn export_selection_generation_is_fenced_before_capture() {
        let (directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        create_note_impl(
            &runtime,
            "Generation-fenced save dialog".to_owned(),
            "Body".to_owned(),
        )
        .expect("create record");
        let stale_generation =
            capture_export_generation(&runtime, "exporting records").expect("capture generation");
        lock_vault_impl(&runtime).expect("lock before simulated dialog selection");
        unlock_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("reunlock after dialog opened");

        let readable_destination = directory.path().join("stale-readable-export.json");
        assert!(
            export_human_readable_impl_for_generation(
                &runtime,
                readable_destination.to_string_lossy().to_string(),
                stale_generation,
            )
            .is_err()
        );
        assert!(!readable_destination.exists());

        let backup_destination = directory.path().join("stale-encrypted-backup.sqlite3");
        assert_eq!(
            get_device_settings_impl(&runtime)
                .expect("settings before stale backup")
                .last_successful_encrypted_backup_at_ms,
            None
        );
        assert!(
            backup_database_copy_impl_for_generation(
                &runtime,
                backup_destination.to_string_lossy().to_string(),
                stale_generation,
            )
            .is_err()
        );
        assert!(!backup_destination.exists());
        assert_eq!(
            get_device_settings_impl(&runtime)
                .expect("settings after stale backup")
                .last_successful_encrypted_backup_at_ms,
            None
        );
    }

    #[test]
    fn backup_status_persistence_failure_keeps_created_backup_and_old_status() {
        let (directory, mut runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        create_note_impl(
            &runtime,
            "Partial success marker".to_owned(),
            "Body".to_owned(),
        )
        .expect("create record");
        runtime.settings_path = directory
            .path()
            .join("missing-settings-parent")
            .join("device-settings.json");
        let destination = directory.path().join("partial-success-backup.sqlite3");

        let result = backup_database_copy_impl(&runtime, destination.to_string_lossy().to_string())
            .expect("backup creation itself succeeds");
        assert!(result.settings.is_none());
        assert!(destination.exists());
        VaultSession::unlock(&destination, PASSPHRASE)
            .expect("published backup remains valid")
            .validate_persisted_state()
            .expect("published backup fully validates");
        assert_eq!(
            get_device_settings_impl(&runtime)
                .expect("in-memory settings remain readable")
                .last_successful_encrypted_backup_at_ms,
            None
        );
    }

    #[test]
    fn backup_preparation_allows_lock_and_stale_generation_cannot_publish() {
        let (directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        create_note_impl(&runtime, "Backup race marker".to_owned(), "body".to_owned())
            .expect("create marker");
        let destination = directory.path().join("race-backup.sqlite3");
        let staged = temporary_sibling_path(&destination, "backup-race").expect("staged path");
        let (plan, generation) = capture_database_backup_plan(&runtime).expect("capture plan");
        let checks = std::cell::Cell::new(0usize);

        let result = plan.write_validated_to(&staged, || {
            let next = checks.get() + 1;
            checks.set(next);
            if next == 2 {
                lock_vault_impl(&runtime).expect("lock during backup preparation");
            }
            !is_session_generation_current(&runtime, generation)
        });

        assert!(matches!(result, Err(VaultError::OperationCancelled)));
        assert!(!is_session_generation_current(&runtime, generation));
        assert!(commit_database_backup_copy(&runtime, generation, &staged, &destination).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn encrypted_backup_restore_preserves_lifecycle_recovery_and_revisions() {
        const TARGET_PASSPHRASE: &str = "a different existing target passphrase";
        const CHANGED_SOURCE_PASSPHRASE: &str = "a later changed source passphrase";

        let (source_directory, source) = runtime();
        initialize_vault_impl(&source, PASSPHRASE.to_owned()).expect("initialize source vault");
        let active = create_note_impl(
            &source,
            "Active backup record".to_owned(),
            "active body".to_owned(),
        )
        .expect("create active backup record");
        let trashed = create_note_impl(
            &source,
            "Recoverable trash record".to_owned(),
            "trash body".to_owned(),
        )
        .expect("create trash record");
        let trashed_revision =
            trash_item_impl(&source, trashed.id.clone(), trashed.revision).expect("trash record");
        let purged = create_note_impl(
            &source,
            "Purged backup record".to_owned(),
            "purged body".to_owned(),
        )
        .expect("create purge record");
        let purge_trash_revision = trash_item_impl(&source, purged.id.clone(), purged.revision)
            .expect("trash purge record");
        let tombstone_revision =
            purge_trashed_item_impl(&source, purged.id.clone(), purge_trash_revision)
                .expect("purge record into tombstone");
        let recovery = generate_recovery_secret_impl(&source).expect("generate recovery secret");
        confirm_recovery_secret_impl(&source, recovery.secret.to_string(), recovery.generation)
            .expect("install recovery secret");
        let recovery_secret = recovery.secret.to_string();

        let backup_path = source_directory.path().join("restore-source.sqlite3");
        backup_database_copy_impl(&source, backup_path.to_string_lossy().to_string())
            .expect("create encrypted backup");
        change_master_passphrase_impl(
            &source,
            PASSPHRASE.to_owned(),
            CHANGED_SOURCE_PASSPHRASE.to_owned(),
        )
        .expect("change source passphrase after backup");

        let (_target_directory, target) = runtime();
        initialize_vault_impl(&target, TARGET_PASSPHRASE.to_owned())
            .expect("initialize existing target vault");
        update_device_settings_impl(&target, 30, false).expect("set target lock preferences");
        let target_settings = mutate_device_settings(&target, |current| DeviceSettings {
            last_successful_encrypted_backup_at_ms: Some(123_456_789),
            ..current
        })
        .expect("seed target device backup activity");
        create_note_impl(
            &target,
            "Target-only record".to_owned(),
            "must disappear after restore".to_owned(),
        )
        .expect("create target marker");

        let restored = restore_database_backup_impl(
            &target,
            backup_path.to_string_lossy().to_string(),
            PASSPHRASE.to_owned(),
        )
        .expect("restore encrypted backup");
        assert!(restored.initialized);
        assert!(!restored.unlocked);
        assert_eq!(
            get_device_settings_impl(&target)
                .expect("device settings survive restore")
                .last_successful_encrypted_backup_at_ms,
            target_settings.last_successful_encrypted_backup_at_ms
        );
        assert_eq!(
            get_device_settings_impl(&target)
                .expect("lock settings survive restore")
                .auto_lock_minutes,
            30
        );
        assert!(list_vault_items_impl(&target).is_err());
        assert!(unlock_vault_impl(&target, TARGET_PASSPHRASE.to_owned()).is_err());
        unlock_vault_impl(&target, PASSPHRASE.to_owned()).expect("unlock restored vault");

        let active_items = list_vault_items_impl(&target).expect("list restored active records");
        let active_json = serde_json::to_string(&active_items).expect("serialize active records");
        assert!(active_json.contains("Active backup record"));
        assert!(!active_json.contains("Target-only record"));
        assert!(!active_json.contains("Recoverable trash record"));
        assert!(!active_json.contains("Purged backup record"));
        let restored_active_revision = active_items
            .iter()
            .find_map(|item| match item {
                VaultItemView::SecureNote { id, revision, .. } if id == &active.id => {
                    Some(*revision)
                }
                _ => None,
            })
            .expect("restored active note is listed");
        assert_eq!(restored_active_revision, active.revision);

        let trash = list_trashed_items_impl(&target).expect("list restored trash");
        let restored_trash = trash
            .iter()
            .find(|item| item.id == trashed.id)
            .expect("recoverable trash preserved");
        assert_eq!(restored_trash.revision, trashed_revision);
        assert!(restore_trashed_item_impl(&target, purged.id.clone(), tombstone_revision).is_err());

        lock_vault_impl(&target).expect("lock restored vault");
        unlock_vault_with_recovery_kit_impl(&target, recovery_secret)
            .expect("restored recovery wrap remains usable");
    }

    #[test]
    fn failed_backup_restore_leaves_current_vault_unchanged() {
        const TARGET_PASSPHRASE: &str = "a target vault passphrase for restore";
        let (source_directory, source) = runtime();
        initialize_vault_impl(&source, PASSPHRASE.to_owned()).expect("initialize source vault");
        create_note_impl(
            &source,
            "Source backup record".to_owned(),
            "source body".to_owned(),
        )
        .expect("create source record");
        let backup_path = source_directory.path().join("wrong-passphrase.sqlite3");
        backup_database_copy_impl(&source, backup_path.to_string_lossy().to_string())
            .expect("create backup");

        let (_target_directory, target) = runtime();
        initialize_vault_impl(&target, TARGET_PASSPHRASE.to_owned())
            .expect("initialize target vault");
        let marker = create_note_impl(
            &target,
            "Current target record".to_owned(),
            "target body".to_owned(),
        )
        .expect("create target marker");

        let error = match restore_database_backup_impl(
            &target,
            backup_path.to_string_lossy().to_string(),
            "definitely the wrong backup passphrase".to_owned(),
        ) {
            Ok(_) => panic!("wrong backup passphrase unexpectedly replaced current vault"),
            Err(error) => error,
        };
        assert!(error.contains("Unable to validate this backup"));
        let current_items =
            list_vault_items_impl(&target).expect("current vault stays unlocked and unchanged");
        assert!(current_items.iter().any(|item| matches!(
            item,
            VaultItemView::SecureNote {
                id,
                revision,
                title,
                ..
            } if id == &marker.id && *revision == marker.revision && title == "Current target record"
        )));
    }

    #[test]
    fn stale_restore_generation_cannot_commit_after_preparation() {
        const TARGET_PASSPHRASE: &str = "a target passphrase for stale restore";
        let (source_directory, source) = runtime();
        initialize_vault_impl(&source, PASSPHRASE.to_owned()).expect("initialize source vault");
        create_note_impl(
            &source,
            "Source restore marker".to_owned(),
            "source".to_owned(),
        )
        .expect("create source marker");
        let backup_path = source_directory.path().join("stale-restore-source.sqlite3");
        backup_database_copy_impl(&source, backup_path.to_string_lossy().to_string())
            .expect("create source backup");

        let (_target_directory, target) = runtime();
        initialize_vault_impl(&target, TARGET_PASSPHRASE.to_owned()).expect("initialize target");
        let marker = create_note_impl(
            &target,
            "Target restore marker".to_owned(),
            "target".to_owned(),
        )
        .expect("create target marker");
        let generation = authorize_database_restore(&target, true).expect("authorize restore");
        let passphrase = Zeroizing::new(PASSPHRASE.to_owned());
        let (candidate, prepared) =
            prepare_database_restore_candidate(&target, generation, &backup_path, &passphrase)
                .expect("prepare restore candidate");
        drop(passphrase);
        lock_vault_impl(&target).expect("lock after restore preparation");

        let result = commit_database_restore(&target, true, generation, &candidate, prepared);
        assert!(result.is_err());
        assert!(!candidate.exists());
        unlock_vault_impl(&target, TARGET_PASSPHRASE.to_owned()).expect("unlock unchanged target");
        let items = list_vault_items_impl(&target).expect("list unchanged target");
        assert!(items.iter().any(|item| matches!(
            item,
            VaultItemView::SecureNote { id, title, .. }
                if id == &marker.id && title == "Target restore marker"
        )));
    }

    #[test]
    fn lock_during_candidate_validation_cancels_after_root_auth() {
        const TARGET_PASSPHRASE: &str = "a target passphrase for validation cancellation";
        let (source_directory, source) = runtime();
        initialize_vault_impl(&source, PASSPHRASE.to_owned()).expect("initialize source vault");
        create_note_impl(
            &source,
            "Validation cancellation source".to_owned(),
            "source".to_owned(),
        )
        .expect("create source marker");
        let backup_path = source_directory
            .path()
            .join("validation-cancel-source.sqlite3");
        backup_database_copy_impl(&source, backup_path.to_string_lossy().to_string())
            .expect("create source backup");

        let (_target_directory, target) = runtime();
        initialize_vault_impl(&target, TARGET_PASSPHRASE.to_owned()).expect("initialize target");
        let marker = create_note_impl(
            &target,
            "Validation cancellation target".to_owned(),
            "target".to_owned(),
        )
        .expect("create target marker");
        let generation = authorize_database_restore(&target, true).expect("authorize restore");
        let mut cancellation_checks = 0usize;

        let result = VaultSession::prepare_restore_with_cancel(&backup_path, PASSPHRASE, || {
            cancellation_checks += 1;
            if cancellation_checks == 3 {
                lock_vault_impl(&target).expect("lock during authenticated candidate validation");
            }
            !is_session_generation_current(&target, generation)
        });

        assert!(matches!(result, Err(VaultError::OperationCancelled)));
        assert!(cancellation_checks >= 3);
        assert!(
            !vault_status_impl(&target)
                .expect("locked target status")
                .unlocked
        );
        unlock_vault_impl(&target, TARGET_PASSPHRASE.to_owned()).expect("unlock unchanged target");
        let items = list_vault_items_impl(&target).expect("list unchanged target");
        assert!(items.iter().any(|item| matches!(
            item,
            VaultItemView::SecureNote { id, title, .. }
                if id == &marker.id && title == "Validation cancellation target"
        )));
    }

    #[test]
    fn first_run_restore_still_finishes_initialized_and_locked() {
        let (source_directory, source) = runtime();
        initialize_vault_impl(&source, PASSPHRASE.to_owned()).expect("initialize source vault");
        create_note_impl(
            &source,
            "First-run restore marker".to_owned(),
            "body".to_owned(),
        )
        .expect("create source marker");
        let backup_path = source_directory.path().join("first-run-restore.sqlite3");
        backup_database_copy_impl(&source, backup_path.to_string_lossy().to_string())
            .expect("create source backup");

        let (_target_directory, target) = runtime();
        let restored = restore_database_backup_impl(
            &target,
            backup_path.to_string_lossy().to_string(),
            PASSPHRASE.to_owned(),
        )
        .expect("restore into first-run target");
        assert!(restored.initialized);
        assert!(!restored.unlocked);
        unlock_vault_impl(&target, PASSPHRASE.to_owned()).expect("unlock restored target");
        let items = list_vault_items_impl(&target).expect("list restored target");
        assert!(items.iter().any(|item| matches!(
            item,
            VaultItemView::SecureNote { title, .. } if title == "First-run restore marker"
        )));
    }

    #[test]
    fn first_run_recovery_restore_sets_new_passphrase_and_preserves_backup_key() {
        const NEW_PASSPHRASE: &str = "a new disaster recovery passphrase";

        let (source_directory, source) = runtime();
        initialize_vault_impl(&source, PASSPHRASE.to_owned()).expect("initialize source vault");
        let marker = create_note_impl(
            &source,
            "Recovery restore marker".to_owned(),
            "body".to_owned(),
        )
        .expect("create source marker");
        let recovery = generate_recovery_secret_impl(&source).expect("generate recovery key");
        confirm_recovery_secret_impl(&source, recovery.secret.to_string(), recovery.generation)
            .expect("install recovery key");
        let recovery_secret = recovery.secret.to_string();
        let backup_path = source_directory
            .path()
            .join("first-run-recovery-restore.sqlite3");
        backup_database_copy_impl(&source, backup_path.to_string_lossy().to_string())
            .expect("create encrypted backup");
        let original_backup = fs::read(&backup_path).expect("read source backup");

        let (_target_directory, target) = runtime();
        let restored = restore_database_backup_with_recovery_kit_impl(
            &target,
            backup_path.to_string_lossy().to_string(),
            recovery_secret.clone(),
            NEW_PASSPHRASE.to_owned(),
        )
        .expect("restore backup with recovery key");
        assert!(restored.initialized);
        assert!(!restored.unlocked);
        assert_eq!(
            fs::read(&backup_path).expect("read unchanged source backup"),
            original_backup
        );
        assert!(unlock_vault_impl(&target, PASSPHRASE.to_owned()).is_err());
        unlock_vault_impl(&target, NEW_PASSPHRASE.to_owned())
            .expect("new passphrase unlocks restored vault");
        let items = list_vault_items_impl(&target).expect("list restored items");
        assert!(items.iter().any(|item| matches!(
            item,
            VaultItemView::SecureNote { id, title, .. }
                if id == &marker.id && title == "Recovery restore marker"
        )));
        lock_vault_impl(&target).expect("lock recovered vault");
        unlock_vault_with_recovery_kit_impl(&target, recovery_secret)
            .expect("captured recovery key remains usable");
    }

    #[test]
    fn historical_recovery_key_replaces_existing_vault_and_rotated_key_does_not() {
        const TARGET_PASSPHRASE: &str = "an existing vault master passphrase";
        const NEW_PASSPHRASE: &str = "a new passphrase for the historical backup";

        let (source_directory, source) = runtime();
        initialize_vault_impl(&source, PASSPHRASE.to_owned()).expect("initialize source vault");
        let marker = create_note_impl(
            &source,
            "Historical recovery marker".to_owned(),
            "historical body".to_owned(),
        )
        .expect("create historical marker");
        let old_recovery = generate_recovery_secret_impl(&source).expect("generate old key");
        confirm_recovery_secret_impl(
            &source,
            old_recovery.secret.to_string(),
            old_recovery.generation,
        )
        .expect("install old recovery key");
        let old_recovery_secret = old_recovery.secret.to_string();
        let backup_path = source_directory
            .path()
            .join("historical-recovery-restore.sqlite3");
        backup_database_copy_impl(&source, backup_path.to_string_lossy().to_string())
            .expect("create historical encrypted backup");
        let original_backup = fs::read(&backup_path).expect("read historical backup");

        let new_recovery = generate_recovery_secret_impl(&source).expect("generate rotated key");
        confirm_recovery_secret_impl(
            &source,
            new_recovery.secret.to_string(),
            new_recovery.generation,
        )
        .expect("rotate source recovery key");
        let new_recovery_secret = new_recovery.secret.to_string();

        let (_target_directory, target) = runtime();
        initialize_vault_impl(&target, TARGET_PASSPHRASE.to_owned()).expect("initialize target");
        create_note_impl(
            &target,
            "Target to replace".to_owned(),
            "target body".to_owned(),
        )
        .expect("create target marker");

        let rotated_error = restore_database_backup_with_recovery_kit_impl(
            &target,
            backup_path.to_string_lossy().to_string(),
            new_recovery_secret.clone(),
            NEW_PASSPHRASE.to_owned(),
        );
        assert!(rotated_error.is_err());
        assert!(vault_status_impl(&target).expect("target status").unlocked);

        let restored = restore_database_backup_with_recovery_kit_impl(
            &target,
            backup_path.to_string_lossy().to_string(),
            old_recovery_secret.clone(),
            NEW_PASSPHRASE.to_owned(),
        )
        .expect("restore historical backup with captured key");
        assert!(restored.initialized);
        assert!(!restored.unlocked);
        assert_eq!(
            fs::read(&backup_path).expect("read unchanged historical backup"),
            original_backup
        );
        assert!(unlock_vault_impl(&target, TARGET_PASSPHRASE.to_owned()).is_err());
        unlock_vault_impl(&target, NEW_PASSPHRASE.to_owned())
            .expect("new passphrase unlocks historical restore");
        let items = list_vault_items_impl(&target).expect("list historical restore");
        assert!(items.iter().any(|item| matches!(
            item,
            VaultItemView::SecureNote { id, title, .. }
                if id == &marker.id && title == "Historical recovery marker"
        )));
        lock_vault_impl(&target).expect("lock historical restore");
        assert!(
            unlock_vault_with_recovery_kit_impl(&target, new_recovery_secret).is_err(),
            "rotated current key must not unlock the older backup snapshot"
        );
        unlock_vault_with_recovery_kit_impl(&target, old_recovery_secret)
            .expect("captured historical key remains usable after restore");
    }

    #[test]
    fn failed_recovery_restore_leaves_existing_vault_unchanged() {
        const TARGET_PASSPHRASE: &str = "an existing target passphrase";
        const NEW_PASSPHRASE: &str = "a replacement recovery passphrase";

        let (source_directory, source) = runtime();
        initialize_vault_impl(&source, PASSPHRASE.to_owned()).expect("initialize source vault");
        let recovery = generate_recovery_secret_impl(&source).expect("generate recovery key");
        confirm_recovery_secret_impl(&source, recovery.secret.to_string(), recovery.generation)
            .expect("install recovery key");
        let backup_path = source_directory.path().join("wrong-recovery-key.sqlite3");
        backup_database_copy_impl(&source, backup_path.to_string_lossy().to_string())
            .expect("create encrypted backup");
        let original_backup = fs::read(&backup_path).expect("read source backup");

        let (_target_directory, target) = runtime();
        initialize_vault_impl(&target, TARGET_PASSPHRASE.to_owned()).expect("initialize target");
        let marker = create_note_impl(
            &target,
            "Existing target marker".to_owned(),
            "target body".to_owned(),
        )
        .expect("create target marker");
        let wrong = RecoverySecret::generate().expect("wrong recovery key");
        let error = match restore_database_backup_with_recovery_kit_impl(
            &target,
            backup_path.to_string_lossy().to_string(),
            wrong.to_hex(),
            NEW_PASSPHRASE.to_owned(),
        ) {
            Ok(_) => panic!("wrong recovery key unexpectedly replaced current vault"),
            Err(error) => error,
        };
        assert!(error.contains("Unable to validate this backup with the recovery key"));
        assert_eq!(
            fs::read(&backup_path).expect("read unchanged source backup"),
            original_backup
        );
        let items = list_vault_items_impl(&target).expect("target remains unlocked");
        assert!(items.iter().any(|item| matches!(
            item,
            VaultItemView::SecureNote { id, title, .. }
                if id == &marker.id && title == "Existing target marker"
        )));
    }

    #[test]
    fn new_commands_require_unlocked() {
        let (directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let note = create_note_impl(&runtime, "Locked gate".to_owned(), "Body".to_owned())
            .expect("create note");
        let subscription = create_subscription_impl(
            &runtime,
            "Locked subscription".to_owned(),
            "Provider".to_owned(),
            "Plan".to_owned(),
            "10".to_owned(),
            "USD".to_owned(),
            "monthly".to_owned(),
            "2099-01-15".to_owned(),
            String::new(),
        )
        .expect("create subscription before lock");
        let source_path = directory.path().join("locked-attachment.txt");
        fs::write(&source_path, b"locked attachment bytes").expect("write locked attachment");
        let destination_path = directory.path().join("locked-export.txt");
        lock_vault_impl(&runtime).expect("lock vault");

        assert!(get_emergency_card_impl(&runtime).is_err());
        assert!(
            update_emergency_card_impl(&runtime, None, Vec::new(), Vec::new(), String::new())
                .is_err()
        );
        assert!(get_item_titles_impl(&runtime, vec![note.id.clone()]).is_err());
        assert!(set_item_links_impl(&runtime, note.id.clone(), note.revision, Vec::new()).is_err());
        assert!(
            get_item_legacy_disposition_impl(&runtime, note.id.clone(), note.revision).is_err()
        );
        assert!(
            set_item_legacy_disposition_impl(
                &runtime,
                note.id.clone(),
                note.revision,
                LegacyDisposition::PrivateForever,
            )
            .is_err()
        );
        assert!(
            get_credential_closure_plan_impl(&runtime, note.id.clone(), note.revision).is_err()
        );
        assert!(
            set_credential_closure_plan_impl(
                &runtime,
                note.id.clone(),
                note.revision,
                AccountClosurePlan::default(),
            )
            .is_err()
        );
        assert!(list_deadlines_impl(&runtime, 2026, 9, 15).is_err());
        assert!(
            get_subscription_impl(&runtime, subscription.id.clone(), subscription.revision)
                .is_err()
        );
        assert!(
            create_subscription_impl(
                &runtime,
                "Locked create".to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
            .is_err()
        );
        assert!(generate_recovery_secret_impl(&runtime).is_err());
        assert!(confirm_recovery_secret_impl(&runtime, "secret".to_owned(), 0).is_err());
        assert!(
            save_recovery_secret_impl_for_generation(
                &runtime,
                "00",
                0,
                &directory.path().join("locked-recovery-key.txt"),
            )
            .is_err()
        );
        assert!(get_recovery_status_impl(&runtime).is_err());
        assert!(verify_recovery_secret_impl(&runtime, "00".to_owned()).is_err());
        assert!(get_plan_readiness_impl(&runtime).is_err());
        assert!(export_human_readable_impl(&runtime, "export.json".to_owned()).is_err());
        assert!(backup_database_copy_impl(&runtime, "backup.sqlite3".to_owned()).is_err());
        assert!(export_human_readable_impl(&runtime, String::new()).is_err());
        assert!(
            add_attachment_impl(&runtime, note.id.clone(), note.revision, source_path,).is_err()
        );
        assert!(list_attachments_impl(&runtime, note.id.clone()).is_err());
        assert!(
            export_attachment_impl(&runtime, note.id.clone(), note.id.clone(), destination_path,)
                .is_err()
        );
        assert!(
            delete_attachment_impl(&runtime, note.id.clone(), note.id.clone(), note.revision, 1,)
                .is_err()
        );

        unlock_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("unlock vault");
        assert!(get_emergency_card_impl(&runtime).is_ok());
    }

    #[test]
    fn attachment_commands_round_trip_paths_and_metadata_only() {
        let (directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let note = create_note_impl(
            &runtime,
            "Attachment owner".to_owned(),
            "Owner body".to_owned(),
        )
        .expect("create attachment owner");
        let source_path = directory.path().join("private-receipt.txt");
        let plaintext = b"private attachment payload 7A41";
        fs::write(&source_path, plaintext).expect("write attachment source");

        let added = add_attachment_impl(&runtime, note.id.clone(), note.revision, source_path)
            .expect("add attachment");
        assert_eq!(added.item_revision, 2);
        assert_eq!(added.attachment.revision, 1);
        assert_eq!(added.attachment.filename, "private-receipt.txt");
        assert_eq!(
            added.attachment.plaintext_size,
            u64::try_from(plaintext.len()).expect("plaintext length")
        );

        let listed = list_attachments_impl(&runtime, note.id.clone()).expect("list attachments");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, added.attachment.id);
        assert_eq!(listed[0].revision, added.attachment.revision);
        assert_eq!(listed[0].filename, added.attachment.filename);
        assert_eq!(listed[0].plaintext_size, added.attachment.plaintext_size);
        let metadata = serde_json::to_value(&listed[0]).expect("serialize attachment metadata");
        let metadata = metadata.as_object().expect("attachment metadata object");
        assert_eq!(metadata.len(), 4);
        assert!(metadata.contains_key("id"));
        assert!(metadata.contains_key("revision"));
        assert!(metadata.contains_key("filename"));
        assert!(metadata.contains_key("plaintext_size"));
        assert!(
            !serde_json::to_string(metadata)
                .expect("serialize attachment metadata object")
                .contains("private attachment payload")
        );

        let destination_path = directory.path().join("exported-receipt.txt");
        export_attachment_impl(
            &runtime,
            note.id.clone(),
            added.attachment.id.clone(),
            destination_path.clone(),
        )
        .expect("export attachment");
        assert_eq!(fs::read(&destination_path).expect("read export"), plaintext);

        let item_revision = delete_attachment_impl(
            &runtime,
            note.id.clone(),
            added.attachment.id.clone(),
            added.item_revision,
            added.attachment.revision,
        )
        .expect("delete attachment");
        assert_eq!(item_revision, 3);
        assert!(
            list_attachments_impl(&runtime, note.id.clone())
                .expect("list after delete")
                .is_empty()
        );
        assert!(
            export_attachment_impl(
                &runtime,
                note.id,
                added.attachment.id,
                directory.path().join("deleted-export.txt"),
            )
            .is_err()
        );
    }

    #[test]
    fn list_views_expose_links() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");

        let note = create_note_impl(&runtime, "Link source".to_owned(), "Body".to_owned())
            .expect("create source");
        let target = create_note_impl(&runtime, "Link target".to_owned(), "Body".to_owned())
            .expect("create target");
        set_item_links_impl(
            &runtime,
            note.id.clone(),
            note.revision,
            vec![target.id.clone()],
        )
        .expect("set links");
        let listed = list_vault_items_impl(&runtime).expect("list items");
        let serialized = serde_json::to_string(&listed).expect("serialize list");
        assert!(serialized.contains(&target.id));

        let credential = create_credential_impl(
            &runtime,
            "Cred".to_owned(),
            "user".to_owned(),
            "secret".to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create credential");
        assert!(credential.links.is_empty());
        let document = create_document_impl(
            &runtime,
            "Doc".to_owned(),
            String::new(),
            "Issuer".to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create document");
        assert!(document.links.is_empty());
        let insurance = create_insurance_impl(
            &runtime,
            "Ins".to_owned(),
            "Provider".to_owned(),
            "Type".to_owned(),
            String::new(),
            String::new(),
            String::new(),
        )
        .expect("create insurance");
        assert!(insurance.links.is_empty());
        let financial = create_financial_impl(
            &runtime,
            "Fin".to_owned(),
            "Bank".to_owned(),
            "Savings".to_owned(),
            "USD".to_owned(),
            String::new(),
            String::new(),
        )
        .expect("create financial");
        assert!(financial.links.is_empty());
        let property = create_property_impl(
            &runtime,
            "Prop".to_owned(),
            "House".to_owned(),
            "Addr".to_owned(),
            "Owned".to_owned(),
            "Ref".to_owned(),
            String::new(),
        )
        .expect("create property");
        assert!(property.links.is_empty());
        let vehicle = create_vehicle_impl(
            &runtime,
            "Veh".to_owned(),
            "Make".to_owned(),
            "Model".to_owned(),
            "2021".to_owned(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        )
        .expect("create vehicle");
        assert!(vehicle.links.is_empty());
        let possession = create_possession_impl(
            &runtime,
            "Pos".to_owned(),
            String::new(),
            String::new(),
            "Brand".to_owned(),
            "Model".to_owned(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        )
        .expect("create possession");
        assert!(possession.links.is_empty());
    }
}
