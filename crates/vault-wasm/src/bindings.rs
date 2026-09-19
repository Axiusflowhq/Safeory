//! `wasm-bindgen` boundary. Methods take/return JSON strings so rich Rust
//! types cross cleanly. Only ciphertext snapshots and explicitly
//! decrypted-on-request plaintext cross to JS; the root key never does.

use wasm_bindgen::prelude::*;

use vault_crypto::RecoverySecret;

use crate::{BrowserVault, DeadlineEntry, WasmVaultError, generate_strong_password};

fn js_err(e: WasmVaultError) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn ser_err() -> JsValue {
    JsValue::from_str("serialization failed")
}

#[wasm_bindgen]
pub struct WasmVault {
    inner: BrowserVault,
}

#[wasm_bindgen]
impl WasmVault {
    /// New empty vault (not yet initialized).
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: BrowserVault::new_empty(),
        }
    }

    /// Load from a previously saved snapshot JSON.
    #[wasm_bindgen(js_name = fromSnapshotJson)]
    pub fn from_snapshot_json(snapshot_json: &str) -> Result<WasmVault, JsValue> {
        let snapshot = serde_json::from_str(snapshot_json).map_err(|_| ser_err())?;
        let inner = BrowserVault::from_snapshot(snapshot).map_err(js_err)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(js_name = isInitialized)]
    pub fn is_initialized(&self) -> bool {
        self.inner.is_initialized()
    }

    #[wasm_bindgen(js_name = isUnlocked)]
    pub fn is_unlocked(&self) -> bool {
        self.inner.is_unlocked()
    }

    /// Create + unlock a new vault. Rejects passphrases under 12 chars.
    pub fn create(&mut self, passphrase: &str) -> Result<(), JsValue> {
        self.inner.create(passphrase).map_err(js_err)
    }

    pub fn unlock(&mut self, passphrase: &str) -> Result<(), JsValue> {
        self.inner.unlock(passphrase).map_err(js_err)
    }

    pub fn lock(&mut self) {
        self.inner.lock();
    }

    /// Serialize the ciphertext store for IndexedDB persistence.
    #[wasm_bindgen(js_name = snapshotJson)]
    pub fn snapshot_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.inner.to_snapshot()).map_err(|_| ser_err())
    }

    /// Insert a new item (JSON-encoded `VaultItem`) at revision 0.
    #[wasm_bindgen(js_name = putItemJson)]
    pub fn put_item_json(&self, item_json: &str) -> Result<(), JsValue> {
        let item = serde_json::from_str(item_json).map_err(|_| ser_err())?;
        self.inner.put_item(&item).map_err(js_err)
    }

    /// Get an active item as JSON by id (UUID string).
    #[wasm_bindgen(js_name = getItemJson)]
    pub fn get_item_json(&self, id: &str) -> Result<String, JsValue> {
        let id = parse_uuid(id)?;
        let item = self.inner.get_item(id).map_err(js_err)?;
        serde_json::to_string(&item).map_err(|_| ser_err())
    }

    /// List active items as redacted JSON summaries.
    ///
    /// Secret-bearing fields and notes never cross the WASM boundary here;
    /// callers must explicitly fetch one item with `getItemJson` when opening
    /// its detail/editor surface.
    #[wasm_bindgen(js_name = listItemsJson)]
    pub fn list_items_json(&self) -> Result<String, JsValue> {
        let items = self.inner.list_items().map_err(js_err)?;
        let projected: Vec<ListEntry> = items
            .into_iter()
            .map(|(item, revision)| ListEntry {
                item: ListItemSummary {
                    id: item.id,
                    kind: item.kind,
                    title: item.title,
                },
                revision,
            })
            .collect();
        serde_json::to_string(&projected).map_err(|_| ser_err())
    }

    /// List redacted local deadline metadata for an explicitly supplied local
    /// calendar date. Full record fields remain inside WASM.
    #[wasm_bindgen(js_name = listDeadlinesJson)]
    pub fn list_deadlines_json(&self, today_ymd: &str) -> Result<String, JsValue> {
        let today = vault_models::reminders::parse_ymd(today_ymd)
            .ok_or_else(|| JsValue::from_str("invalid local date"))?;
        let deadlines = self.inner.list_deadlines(today).map_err(js_err)?;
        deadline_entries_json(deadlines).map_err(|_| ser_err())
    }

    /// List only the non-secret credential metadata needed for matching and
    /// selection. Passwords and notes remain inside WASM until an explicit
    /// credential fetch/fill request.
    #[wasm_bindgen(js_name = listCredentialsJson)]
    pub fn list_credentials_json(&self) -> Result<String, JsValue> {
        let items = self.inner.list_items().map_err(js_err)?;
        let projected: Vec<CredentialListEntry> = items
            .into_iter()
            .filter(|(item, _)| item.kind == vault_models::ItemKind::Password)
            .map(|(item, revision)| CredentialListEntry {
                id: item.id,
                title: item.title,
                username: item.fields.get("username").cloned().unwrap_or_default(),
                website: item.fields.get("website").cloned().unwrap_or_default(),
                revision,
            })
            .collect();
        serde_json::to_string(&projected).map_err(|_| ser_err())
    }

    /// Update an item; returns the new revision.
    #[wasm_bindgen(js_name = updateItemJson)]
    pub fn update_item_json(
        &self,
        item_json: &str,
        expected_revision: u64,
    ) -> Result<u64, JsValue> {
        let item = serde_json::from_str(item_json).map_err(|_| ser_err())?;
        self.inner
            .update_item(&item, expected_revision)
            .map_err(js_err)
    }

    /// Trash an item; returns the new revision.
    #[wasm_bindgen(js_name = trashItem)]
    pub fn trash_item(
        &self,
        id: &str,
        expected_revision: u64,
        deleted_at_ms: u64,
    ) -> Result<u64, JsValue> {
        let id = parse_uuid(id)?;
        self.inner
            .trash_item(id, expected_revision, deleted_at_ms)
            .map_err(js_err)
    }

    /// Get the Emergency Card as `{ card, revision }` JSON, or `null`.
    #[wasm_bindgen(js_name = getEmergencyCardJson)]
    pub fn get_emergency_card_json(&self) -> Result<JsValue, JsValue> {
        match self.inner.get_emergency_card().map_err(js_err)? {
            Some((card, revision)) => {
                let payload = EmergencyCardEntry { card, revision };
                let json = serde_json::to_string(&payload).map_err(|_| ser_err())?;
                Ok(JsValue::from_str(&json))
            }
            None => Ok(JsValue::NULL),
        }
    }

    /// Set the Emergency Card (JSON-encoded `EmergencyCard`); returns revision.
    #[wasm_bindgen(js_name = setEmergencyCardJson)]
    pub fn set_emergency_card_json(&self, card_json: &str) -> Result<u64, JsValue> {
        let card = serde_json::from_str(card_json).map_err(|_| ser_err())?;
        self.inner.set_emergency_card(&card).map_err(js_err)
    }

    /// Install a recovery kit from a hex-encoded secret.
    #[wasm_bindgen(js_name = installRecoveryKit)]
    pub fn install_recovery_kit(&self, secret_hex: &str) -> Result<(), JsValue> {
        let secret = parse_secret(secret_hex)?;
        self.inner.install_recovery_kit(&secret).map_err(js_err)
    }

    #[wasm_bindgen(js_name = hasRecoveryKit)]
    pub fn has_recovery_kit(&self) -> Result<bool, JsValue> {
        self.inner.has_recovery_kit().map_err(js_err)
    }

    /// Verify a recovery secret against the installed kit (read-only).
    #[wasm_bindgen(js_name = verifyRecoveryKit)]
    pub fn verify_recovery_kit(&self, secret_hex: &str) -> Result<bool, JsValue> {
        let secret = parse_secret(secret_hex)?;
        self.inner.verify_recovery_kit(&secret).map_err(js_err)
    }

    /// Unlock using a recovery kit secret instead of the master passphrase.
    #[wasm_bindgen(js_name = unlockWithRecoveryKit)]
    pub fn unlock_with_recovery_kit(&mut self, secret_hex: &str) -> Result<(), JsValue> {
        let secret = parse_secret(secret_hex)?;
        self.inner.unlock_with_recovery_kit(&secret).map_err(js_err)
    }

    /// Generate a fresh recovery secret (hex) for the printable kit.
    #[wasm_bindgen(js_name = generateRecoverySecret)]
    pub fn generate_recovery_secret() -> Result<String, JsValue> {
        BrowserVault::generate_recovery_secret().map_err(js_err)
    }

    /// Generate a strong password (12..=128 chars, all character classes).
    #[wasm_bindgen(js_name = generatePassword)]
    pub fn generate_password(length: usize) -> Result<String, JsValue> {
        generate_strong_password(length).map_err(js_err)
    }
}

impl Default for WasmVault {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(serde::Serialize)]
struct ListEntry {
    item: ListItemSummary,
    revision: u64,
}

#[derive(serde::Serialize)]
struct ListItemSummary {
    id: uuid::Uuid,
    kind: vault_models::ItemKind,
    title: String,
}

#[derive(serde::Serialize)]
struct CredentialListEntry {
    id: uuid::Uuid,
    title: String,
    username: String,
    website: String,
    revision: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct DeadlineListEntry {
    item_id: uuid::Uuid,
    kind: vault_models::ItemKind,
    title: String,
    label: &'static str,
    date: String,
    days_until: i64,
    revision: u64,
}

#[derive(serde::Serialize)]
struct EmergencyCardEntry {
    card: vault_models::EmergencyCard,
    revision: u64,
}

fn deadline_entries_json(entries: Vec<DeadlineEntry>) -> Result<String, serde_json::Error> {
    let projected: Vec<DeadlineListEntry> = entries
        .into_iter()
        .map(|entry| DeadlineListEntry {
            item_id: entry.deadline.item_id,
            kind: entry.deadline.kind,
            title: entry.deadline.title,
            label: entry.deadline.label,
            date: entry.deadline.date,
            days_until: entry.deadline.days_until,
            revision: entry.revision,
        })
        .collect();
    serde_json::to_string(&projected)
}

fn parse_uuid(s: &str) -> Result<uuid::Uuid, JsValue> {
    uuid::Uuid::parse_str(s).map_err(|_| JsValue::from_str("invalid item id"))
}

fn parse_secret(hex: &str) -> Result<RecoverySecret, JsValue> {
    RecoverySecret::from_hex(hex).map_err(|_| JsValue::from_str("invalid recovery secret"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_models::VaultItem;

    #[test]
    fn deadline_projection_excludes_secret_fields_and_notes() {
        const SECRET: &str = "SECRET-SENTINEL-MUST-NOT-CROSS";
        let mut vault = BrowserVault::new_empty();
        vault.create("correct horse battery").expect("create");
        let mut item = VaultItem::document("Passport", SECRET, "Issuer", "2026-09-20", SECRET);
        item.fields
            .insert("private_extra".to_owned(), SECRET.to_owned());
        vault.put_item(&item).expect("put");

        let json = deadline_entries_json(
            vault
                .list_deadlines((2026, 9, 19))
                .expect("deadline projection"),
        )
        .expect("serialize deadline projection");
        assert!(!json.contains(SECRET));

        let rows: Vec<serde_json::Value> = serde_json::from_str(&json).expect("parse projection");
        let object = rows[0].as_object().expect("deadline object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "date",
                "daysUntil",
                "itemId",
                "kind",
                "label",
                "revision",
                "title",
            ]
        );
    }
}
