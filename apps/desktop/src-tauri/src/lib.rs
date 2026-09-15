#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State};
use vault_core::{
    VaultSession, generate_strong_password,
    reminders::{civil_from_days, collect_deadlines},
};
use vault_crypto::RecoverySecret;
use vault_models::{EMERGENCY_CARD_ID, EmergencyCard, EmergencyContact, ItemKind, VaultItem};
use zeroize::Zeroizing;

const LEGACY_PRE_SAFEORY_APP_IDENTIFIER: &str = "com.lifevault.desktop";

struct VaultRuntime {
    database_path: PathBuf,
    settings_path: PathBuf,
    session: Arc<Mutex<Option<VaultSession>>>,
    settings: Arc<Mutex<DeviceSettings>>,
    last_activity: Arc<Mutex<Instant>>,
}

#[derive(Clone, Copy, serde::Deserialize, serde::Serialize)]
struct DeviceSettings {
    auto_lock_minutes: u64,
    lock_on_background: bool,
}

impl Default for DeviceSettings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 10,
            lock_on_background: true,
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
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ContactPayload {
    name: String,
    relation: String,
    phone: String,
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
struct ExportView {
    items: u64,
    path: String,
}

#[derive(serde::Serialize)]
struct PathView {
    path: String,
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
fn list_deadlines(state: State<'_, VaultRuntime>) -> Result<Vec<DeadlineView>, String> {
    list_deadlines_impl(&state)
}

#[tauri::command]
fn generate_recovery_secret(state: State<'_, VaultRuntime>) -> Result<String, String> {
    generate_recovery_secret_impl(&state)
}

#[tauri::command]
fn confirm_recovery_secret(state: State<'_, VaultRuntime>, secret: String) -> Result<(), String> {
    confirm_recovery_secret_impl(&state, secret)
}

#[tauri::command]
fn get_recovery_status(state: State<'_, VaultRuntime>) -> Result<RecoveryStatusView, String> {
    get_recovery_status_impl(&state)
}

#[tauri::command]
fn unlock_vault_with_recovery_kit(
    state: State<'_, VaultRuntime>,
    secret: String,
) -> Result<VaultStatus, String> {
    unlock_vault_with_recovery_kit_impl(&state, secret)
}

#[tauri::command]
fn export_human_readable(
    state: State<'_, VaultRuntime>,
    path: String,
) -> Result<ExportView, String> {
    export_human_readable_impl(&state, path)
}

#[tauri::command]
fn backup_database_copy(state: State<'_, VaultRuntime>, path: String) -> Result<PathView, String> {
    backup_database_copy_impl(&state, path)
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
    *lock_session(state)? = Some(opened);
    Ok(VaultStatus {
        initialized: true,
        unlocked: true,
        cloud_sync_enabled: false,
    })
}

fn lock_vault_impl(state: &VaultRuntime) -> Result<(), String> {
    *lock_session(state)? = None;
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
    let settings = DeviceSettings {
        auto_lock_minutes,
        lock_on_background,
    };
    validate_device_settings(settings)?;
    let encoded = serde_json::to_vec_pretty(&settings)
        .map_err(|_| "Unable to encode local device settings.".to_owned())?;
    fs::write(&state.settings_path, encoded)
        .map_err(|_| "Unable to save local device settings.".to_owned())?;
    *state
        .settings
        .lock()
        .map_err(|_| "The local device settings are unavailable.".to_owned())? = settings;
    Ok(settings)
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

fn load_device_settings(path: &Path) -> DeviceSettings {
    let Ok(bytes) = fs::read(path) else {
        return DeviceSettings::default();
    };
    let Ok(settings) = serde_json::from_slice::<DeviceSettings>(&bytes) else {
        return DeviceSettings::default();
    };
    validate_device_settings(settings)
        .map(|()| settings)
        .unwrap_or_default()
}

fn spawn_auto_lock_watchdog(
    session: Arc<Mutex<Option<VaultSession>>>,
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
            if let Ok(mut session) = session.lock() {
                *session = None;
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
    let mut fields = BTreeMap::new();
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

fn list_deadlines_impl(state: &VaultRuntime) -> Result<Vec<DeadlineView>, String> {
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before reading reminders.".to_owned())?;
    let items = session.list_items().map_err(safe_vault_error)?;
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(safe_vault_error)?
        .as_secs();
    let now_secs = i64::try_from(now_secs).map_err(safe_vault_error)?;
    let today = civil_from_days(now_secs.div_euclid(86400));
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

fn generate_recovery_secret_impl(state: &VaultRuntime) -> Result<String, String> {
    let session = lock_session(state)?;
    if session.is_none() {
        return Err("Unlock the vault before generating a recovery secret.".to_owned());
    }
    drop(session);
    Ok(RecoverySecret::generate()
        .map_err(safe_vault_error)?
        .to_hex())
}

fn confirm_recovery_secret_impl(state: &VaultRuntime, secret: String) -> Result<(), String> {
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before confirming the recovery secret.".to_owned())?;
    let parsed = RecoverySecret::from_hex(secret.trim()).map_err(|_| {
        "The recovery secret is invalid. Check all 64 characters and try again.".to_owned()
    })?;
    session
        .install_recovery_kit(&parsed)
        .map_err(safe_vault_error)
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
    *lock_session(state)? = Some(opened);
    Ok(VaultStatus {
        initialized: true,
        unlocked: true,
        cloud_sync_enabled: false,
    })
}

fn export_human_readable_impl(state: &VaultRuntime, path: String) -> Result<ExportView, String> {
    if path.trim().is_empty() {
        return Err("Choose a location for the export.".to_owned());
    }
    let session = lock_session(state)?;
    let session = session
        .as_ref()
        .ok_or_else(|| "Unlock the vault before exporting records.".to_owned())?;
    let items = session
        .list_items_with_revisions()
        .map_err(safe_vault_error)?;
    let card = session.get_emergency_card().map_err(safe_vault_error)?;
    let exported_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(safe_vault_error)?
        .as_millis();
    let exported_at_ms =
        u64::try_from(exported_at_ms).map_err(|_| "The system clock is unavailable.".to_owned())?;
    let mut export_items = Vec::with_capacity(items.len());
    for (item, revision) in &items {
        export_items.push(serde_json::json!({
            "id": item.id.to_string(),
            "kind": item.kind,
            "title": item.title,
            "links": item.links.iter().map(ToString::to_string).collect::<Vec<_>>(),
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
    let document = serde_json::json!({
        "app": "safeory",
        "format": 1,
        "exported_at_ms": exported_at_ms,
        "items": export_items,
        "emergency_card": emergency_card,
    });
    let encoded = serde_json::to_vec_pretty(&document).map_err(safe_vault_error)?;
    fs::write(&path, encoded).map_err(|_| {
        "Unable to write the export file. Choose a different location and try again.".to_owned()
    })?;
    Ok(ExportView {
        items: u64::try_from(items.len()).map_err(safe_vault_error)?,
        path,
    })
}

fn backup_database_copy_impl(state: &VaultRuntime, path: String) -> Result<PathView, String> {
    let session = lock_session(state)?;
    if session.is_none() {
        return Err("Unlock the vault before backing up the vault.".to_owned());
    }
    fs::copy(&state.database_path, &path).map_err(|_| {
        "Unable to write the backup file. Choose a different location and try again.".to_owned()
    })?;
    Ok(PathView { path })
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

fn validate_property_ownership(value: &str) -> Result<(), String> {
    match value {
        "" | "Owned" | "Rented" | "Leased" | "Shared" | "Other" => Ok(()),
        _ => Err("Choose a supported property ownership status.".to_owned()),
    }
}

fn lock_session(state: &VaultRuntime) -> Result<MutexGuard<'_, Option<VaultSession>>, String> {
    expire_session_if_needed(state)?;
    *state
        .last_activity
        .lock()
        .map_err(|_| "The local activity tracker is unavailable.".to_owned())? = Instant::now();
    state
        .session
        .lock()
        .map_err(|_| "The local vault session is unavailable.".to_owned())
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
        *state
            .session
            .lock()
            .map_err(|_| "The local vault session is unavailable.".to_owned())? = None;
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
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let directory = app.path().app_data_dir()?;
            prepare_app_data_directory(&directory)?;
            let settings_path = directory.join("device-settings.json");
            let settings = Arc::new(Mutex::new(load_device_settings(&settings_path)));
            let session = Arc::new(Mutex::new(None));
            let last_activity = Arc::new(Mutex::new(Instant::now()));
            spawn_auto_lock_watchdog(
                Arc::clone(&session),
                Arc::clone(&settings),
                Arc::clone(&last_activity),
            );
            app.manage(VaultRuntime {
                database_path: directory.join("vault.sqlite3"),
                settings_path,
                session,
                settings,
                last_activity,
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
            generate_password,
            update_credential,
            create_document,
            get_document,
            update_document,
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
            get_emergency_card,
            update_emergency_card,
            get_item_titles,
            set_item_links,
            list_deadlines,
            generate_recovery_secret,
            confirm_recovery_secret,
            get_recovery_status,
            unlock_vault_with_recovery_kit,
            export_human_readable,
            backup_database_copy
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Safeory desktop shell");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const PASSPHRASE: &str = "a long adapter test passphrase";

    fn runtime() -> (tempfile::TempDir, VaultRuntime) {
        let directory = tempdir().expect("temp directory");
        let settings_path = directory.path().join("device-settings.json");
        let runtime = VaultRuntime {
            database_path: directory.path().join("vault.sqlite3"),
            settings_path,
            session: Arc::new(Mutex::new(None)),
            settings: Arc::new(Mutex::new(DeviceSettings::default())),
            last_activity: Arc::new(Mutex::new(Instant::now())),
        };
        (directory, runtime)
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
        let persisted = load_device_settings(&runtime.settings_path);
        assert_eq!(persisted.auto_lock_minutes, 15);
        assert!(!persisted.lock_on_background);
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
                | VaultItemView::Insurance { .. }
                | VaultItemView::Financial { .. }
                | VaultItemView::Property { .. }
                | VaultItemView::Vehicle { .. }
                | VaultItemView::Possession { .. } => None,
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

        let empty_possession = create_possession_impl(
            &runtime,
            "Desk".to_owned(),
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
        }
        let possession_detail =
            get_possession_impl(&runtime, possession.id.clone(), possession.revision)
                .expect("get updated possession detail");
        assert_eq!(possession_detail.serial_number, "SN654321");

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
        assert_eq!(loaded.card.instructions, "Follow the printed steps");

        let second = create_note_impl(&runtime, "Second target".to_owned(), "Body".to_owned())
            .expect("create second note");
        let updated_contact = ContactPayload {
            name: "Bob".to_owned(),
            relation: "Friend".to_owned(),
            phone: "+1-555-0200".to_owned(),
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

        let deadlines = list_deadlines_impl(&runtime).expect("list deadlines");
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
    fn recovery_kit_generate_confirm_lock_unlock() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");

        let status = get_recovery_status_impl(&runtime).expect("initial status");
        assert!(!status.configured);

        let secret = generate_recovery_secret_impl(&runtime).expect("generate secret");
        assert_eq!(secret.len(), 64);
        assert!(secret.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let still_empty = get_recovery_status_impl(&runtime).expect("status after generate");
        assert!(!still_empty.configured);

        let bad = confirm_recovery_secret_impl(&runtime, "not-a-secret".to_owned())
            .expect_err("bad secret must fail");
        assert_eq!(
            bad,
            "The recovery secret is invalid. Check all 64 characters and try again."
        );

        confirm_recovery_secret_impl(&runtime, secret.clone()).expect("confirm secret");
        let configured = get_recovery_status_impl(&runtime).expect("configured status");
        assert!(configured.configured);

        lock_vault_impl(&runtime).expect("lock vault");
        unlock_vault_with_recovery_kit_impl(&runtime, secret.clone()).expect("unlock with kit");
        assert!(vault_status_impl(&runtime).expect("status").unlocked);

        lock_vault_impl(&runtime).expect("lock again");
        let mut wrong_bytes = secret.clone();
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
    fn export_and_backup_copy_contain_seeded_data() {
        let (directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");

        let note = create_note_impl(
            &runtime,
            "Seeded Export Title".to_owned(),
            "Export body".to_owned(),
        )
        .expect("create note");
        update_emergency_card_impl(
            &runtime,
            None,
            vec![note.id.clone()],
            Vec::new(),
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
        let bytes = fs::read(&export_path).expect("read export");
        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("export is valid JSON");
        assert_eq!(parsed["app"], serde_json::json!("safeory"));
        assert_eq!(parsed["format"], serde_json::json!(1));
        let serialized = serde_json::to_string(&parsed).expect("serialize export");
        assert!(serialized.contains("Seeded Export Title"));
        assert!(serialized.contains("Export card instructions"));

        let backup_path = directory
            .path()
            .join("backup.sqlite3")
            .to_string_lossy()
            .to_string();
        let backed_up =
            backup_database_copy_impl(&runtime, backup_path.clone()).expect("backup database");
        assert_eq!(backed_up.path, backup_path);
        let backup_bytes = fs::read(&backup_path).expect("read backup");
        assert!(!backup_bytes.is_empty());
        assert!(backup_bytes.len() >= 16);
        assert_eq!(&backup_bytes[..16], b"SQLite format 3\0");
    }

    #[test]
    fn new_commands_require_unlocked() {
        let (_directory, runtime) = runtime();
        initialize_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("initialize vault");
        let note = create_note_impl(&runtime, "Locked gate".to_owned(), "Body".to_owned())
            .expect("create note");
        lock_vault_impl(&runtime).expect("lock vault");

        assert!(get_emergency_card_impl(&runtime).is_err());
        assert!(
            update_emergency_card_impl(&runtime, None, Vec::new(), Vec::new(), String::new())
                .is_err()
        );
        assert!(get_item_titles_impl(&runtime, vec![note.id.clone()]).is_err());
        assert!(set_item_links_impl(&runtime, note.id.clone(), note.revision, Vec::new()).is_err());
        assert!(list_deadlines_impl(&runtime).is_err());
        assert!(generate_recovery_secret_impl(&runtime).is_err());
        assert!(confirm_recovery_secret_impl(&runtime, "secret".to_owned()).is_err());
        assert!(get_recovery_status_impl(&runtime).is_err());
        assert!(export_human_readable_impl(&runtime, "export.json".to_owned()).is_err());
        assert!(backup_database_copy_impl(&runtime, "backup.sqlite3".to_owned()).is_err());
        assert!(export_human_readable_impl(&runtime, String::new()).is_err());

        unlock_vault_impl(&runtime, PASSPHRASE.to_owned()).expect("unlock vault");
        assert!(get_emergency_card_impl(&runtime).is_ok());
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
