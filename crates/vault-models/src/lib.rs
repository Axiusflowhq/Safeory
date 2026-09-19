#![forbid(unsafe_code)]

pub mod reminders;

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const MAX_ACCESS_GRANTS: usize = 64;
pub const MAX_GRANT_WHAT_CHARS: usize = 128;
pub const MAX_GRANT_APPROVERS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    SecureNote,
    Password,
    Insurance,
    Financial,
    Property,
    Document,
    Receipt,
    Vehicle,
    Possession,
    Subscription,
    EmergencyInstruction,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyDisposition {
    #[default]
    Unspecified,
    SelectedForLegacy,
    PrivateForever,
    DestroyOnDeath,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountClosureDisposition {
    #[default]
    Unspecified,
    KeepOpen,
    CloseAccount,
    ReviewManually,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountClosurePlan {
    pub disposition: AccountClosureDisposition,
    pub instructions: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessCondition {
    Normal,
    Emergency,
    Incapacity,
    Death,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    View,
    Edit,
    Download,
    Share,
    Manage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitPeriod {
    Immediate,
    OneHour,
    OneDay,
    SevenDays,
    Custom(u64),
}

impl WaitPeriod {
    #[must_use]
    pub fn seconds(self) -> u64 {
        match self {
            Self::Immediate => 0,
            Self::OneHour => 3_600,
            Self::OneDay => 86_400,
            Self::SevenDays => 604_800,
            Self::Custom(seconds) => seconds,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantDuration {
    UntilRevoked,
    OneHour,
    OneDay,
    SevenDays,
    Custom(u64),
}

impl GrantDuration {
    #[must_use]
    pub fn seconds(self) -> Option<u64> {
        match self {
            Self::UntilRevoked => None,
            Self::OneHour => Some(3_600),
            Self::OneDay => Some(86_400),
            Self::SevenDays => Some(604_800),
            Self::Custom(seconds) => Some(seconds),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyCondition {
    Death,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessGrant {
    pub trustee_id: Uuid,
    pub what: String,
    pub permission: Permission,
    pub condition: AccessCondition,
    pub wait_period: WaitPeriod,
    pub duration: GrantDuration,
    pub approvals_required: u8,
    pub approver_ids: BTreeSet<Uuid>,
}

impl AccessGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trustee_id: Uuid,
        what: impl Into<String>,
        permission: Permission,
        condition: AccessCondition,
        wait_period: WaitPeriod,
        duration: GrantDuration,
        approvals_required: u8,
        approver_ids: BTreeSet<Uuid>,
    ) -> Result<Self, AccessPolicyValidationError> {
        let grant = Self {
            trustee_id,
            what: what.into(),
            permission,
            condition,
            wait_period,
            duration,
            approvals_required,
            approver_ids,
        };
        validate_access_grant(&grant)?;
        Ok(grant)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicy {
    pub owner_only_default: bool,
    pub grants: Vec<AccessGrant>,
    pub private_forever: bool,
    pub destruction: Option<LegacyCondition>,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self::new(true)
    }
}

impl AccessPolicy {
    #[must_use]
    pub fn new(owner_only_default: bool) -> Self {
        Self {
            owner_only_default,
            grants: Vec::new(),
            private_forever: false,
            destruction: None,
        }
    }

    pub fn add_grant(&mut self, grant: AccessGrant) -> Result<(), AccessPolicyValidationError> {
        validate_access_grant(&grant)?;
        if let Some(existing) = self.grants.iter_mut().find(|existing| {
            existing.trustee_id == grant.trustee_id
                && existing.what == grant.what
                && existing.condition == grant.condition
        }) {
            *existing = grant;
            return Ok(());
        }
        if self.grants.len() >= MAX_ACCESS_GRANTS {
            return Err(AccessPolicyValidationError::TooManyGrants);
        }
        self.grants.push(grant);
        Ok(())
    }

    pub fn set_private_forever(&mut self) {
        self.private_forever = true;
    }

    pub fn destroy_on(&mut self, condition: LegacyCondition) {
        self.destruction = Some(condition);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessPolicyValidationError {
    InvalidGrant,
    TooManyGrants,
}

pub fn validate_access_grant(grant: &AccessGrant) -> Result<(), AccessPolicyValidationError> {
    if grant.what.is_empty() || grant.what.chars().count() > MAX_GRANT_WHAT_CHARS {
        return Err(AccessPolicyValidationError::InvalidGrant);
    }
    if grant.approver_ids.len() > MAX_GRANT_APPROVERS
        || matches!(grant.wait_period, WaitPeriod::Custom(0))
        || (grant.approvals_required > 0
            && (usize::from(grant.approvals_required) > grant.approver_ids.len()
                || grant.approver_ids.contains(&grant.trustee_id)))
    {
        return Err(AccessPolicyValidationError::InvalidGrant);
    }
    Ok(())
}

pub fn validate_access_policy(policy: &AccessPolicy) -> Result<(), AccessPolicyValidationError> {
    if policy.grants.len() > MAX_ACCESS_GRANTS {
        return Err(AccessPolicyValidationError::TooManyGrants);
    }
    for (index, grant) in policy.grants.iter().enumerate() {
        validate_access_grant(grant)?;
        if policy.grants[..index].iter().any(|existing| {
            existing.trustee_id == grant.trustee_id
                && existing.what == grant.what
                && existing.condition == grant.condition
        }) {
            return Err(AccessPolicyValidationError::InvalidGrant);
        }
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultItem {
    pub id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    pub links: Vec<Uuid>,
    pub attachments: Vec<Uuid>,
    pub legacy_disposition: LegacyDisposition,
    pub account_closure_plan: AccountClosurePlan,
    #[serde(default)]
    pub access_policy: AccessPolicy,
    pub fields: BTreeMap<String, String>,
    #[serde(deserialize_with = "deserialize_present_optional_string")]
    pub notes: Option<String>,
}

fn deserialize_present_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

/// "EMGCARD" prefix + 1, singleton id for the encrypted emergency-card record.
pub const EMERGENCY_CARD_ID: Uuid = Uuid::from_bytes([
    0x45, 0x4D, 0x47, 0x43, 0x41, 0x52, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
]);

pub const MAX_ITEM_TITLE_CHARS: usize = 256;
pub const MAX_ITEM_FIELDS: usize = 32;
pub const MAX_ITEM_LINKS: usize = 64;
pub const MAX_ITEM_ATTACHMENTS: usize = 16;
pub const MAX_FIELD_NAME_CHARS: usize = 64;
pub const MAX_FIELD_VALUE_CHARS: usize = 100_000;
pub const MAX_ITEM_NOTES_CHARS: usize = 100_000;
pub const MAX_CARD_ITEMS: usize = 128;
pub const MAX_CARD_CONTACTS: usize = 32;
pub const MAX_TRUSTED_PRINCIPALS: usize = 32;
pub const MAX_TRUSTED_DEVICES_PER_PRINCIPAL: usize = 8;
// Total lifetime identity budgets include enough reserve for every currently
// active identity to be retired. The larger v10 limits preserve every state
// allowed by v9's previous 256-principal / 1024-device retired-ID caps while
// preventing a full tombstone set from making an active identity non-revocable.
pub const MAX_RETIRED_TRUSTED_PRINCIPALS: usize = 288;
pub const MAX_RETIRED_TRUSTED_DEVICES: usize = 1280;
pub const MAX_RETIRED_TRUSTED_SIGNING_KEYS: usize = 1280;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultItemValidationError {
    InvalidLegacyDisposition,
    InvalidAccountClosurePlan,
    InvalidAccessPolicy,
    InvalidTrustedPrincipal,
    TooLarge,
}

/// Validate the portable item invariants shared by native and browser vaults.
/// Storage adapters may enforce additional lifecycle rules (for example,
/// attachment references can only be changed by attachment operations).
pub fn validate_vault_item(item: &VaultItem) -> Result<(), VaultItemValidationError> {
    let unique_attachments = item.attachments.iter().copied().collect::<BTreeSet<_>>();
    if item.id == EMERGENCY_CARD_ID && item.legacy_disposition != LegacyDisposition::Unspecified {
        return Err(VaultItemValidationError::InvalidLegacyDisposition);
    }
    if item.kind != ItemKind::Password && item.account_closure_plan != AccountClosurePlan::default()
    {
        return Err(VaultItemValidationError::InvalidAccountClosurePlan);
    }
    if validate_access_policy(&item.access_policy).is_err() {
        return Err(VaultItemValidationError::InvalidAccessPolicy);
    }
    if item.title.chars().count() > MAX_ITEM_TITLE_CHARS
        || item.fields.len() > MAX_ITEM_FIELDS
        || item.links.len() > MAX_ITEM_LINKS
        || item.attachments.len() > MAX_ITEM_ATTACHMENTS
        || unique_attachments.len() != item.attachments.len()
        || item.fields.iter().any(|(name, value)| {
            name.chars().count() > MAX_FIELD_NAME_CHARS
                || value.chars().count() > MAX_FIELD_VALUE_CHARS
        })
        || item
            .notes
            .as_ref()
            .is_some_and(|notes| notes.chars().count() > MAX_ITEM_NOTES_CHARS)
        || item.account_closure_plan.instructions.chars().count() > MAX_ITEM_NOTES_CHARS
    {
        return Err(VaultItemValidationError::TooLarge);
    }
    Ok(())
}

pub fn validate_emergency_card(card: &EmergencyCard) -> Result<(), VaultItemValidationError> {
    let active_device_count = card
        .principals
        .iter()
        .map(|principal| principal.devices.len())
        .sum::<usize>();
    let active_signing_key_count = card
        .principals
        .iter()
        .flat_map(|principal| principal.devices.iter())
        .filter(|device| device.signing_public_key_hex.is_some())
        .count();
    if card.selected_item_ids.len() > MAX_CARD_ITEMS
        || card.contacts.len() > MAX_CARD_CONTACTS
        || card.principals.len() > MAX_TRUSTED_PRINCIPALS
        || card.retired_principal_ids.len() > MAX_RETIRED_TRUSTED_PRINCIPALS
        || card.retired_device_ids.len() > MAX_RETIRED_TRUSTED_DEVICES
        || card.retired_signing_public_key_hexes.len() > MAX_RETIRED_TRUSTED_SIGNING_KEYS
        || card.retired_principal_ids.len() + card.principals.len() > MAX_RETIRED_TRUSTED_PRINCIPALS
        || card.retired_device_ids.len() + active_device_count > MAX_RETIRED_TRUSTED_DEVICES
        || card.retired_signing_public_key_hexes.len() + active_signing_key_count
            > MAX_RETIRED_TRUSTED_SIGNING_KEYS
        || card.instructions.chars().count() > MAX_ITEM_NOTES_CHARS
    {
        return Err(VaultItemValidationError::TooLarge);
    }
    for contact in &card.contacts {
        if contact.name.chars().count() > MAX_ITEM_TITLE_CHARS
            || contact.relation.chars().count() > MAX_ITEM_TITLE_CHARS
            || contact.phone.chars().count() > MAX_ITEM_TITLE_CHARS
            || contact.email.chars().count() > MAX_ITEM_TITLE_CHARS
            || contact.notes.chars().count() > MAX_ITEM_NOTES_CHARS
        {
            return Err(VaultItemValidationError::TooLarge);
        }
    }

    let mut principal_ids = BTreeSet::new();
    let mut device_ids = BTreeSet::new();
    let mut encryption_keys = BTreeSet::new();
    let mut signing_keys = BTreeSet::new();
    if card
        .retired_signing_public_key_hexes
        .iter()
        .any(|key| key != &key.to_ascii_lowercase() || !valid_signing_public_key_hex(key))
    {
        return Err(VaultItemValidationError::InvalidTrustedPrincipal);
    }
    for principal in &card.principals {
        if principal.id.is_nil()
            || principal.id == EMERGENCY_CARD_ID
            || card.retired_principal_ids.contains(&principal.id)
            || principal.name.trim().is_empty()
            || principal.name.chars().count() > MAX_ITEM_TITLE_CHARS
            || principal.relation.chars().count() > MAX_ITEM_TITLE_CHARS
            || principal.devices.len() > MAX_TRUSTED_DEVICES_PER_PRINCIPAL
            || !principal_ids.insert(principal.id)
        {
            return Err(VaultItemValidationError::InvalidTrustedPrincipal);
        }

        for device in &principal.devices {
            if device.id.is_nil()
                || device.id == EMERGENCY_CARD_ID
                || card.retired_device_ids.contains(&device.id)
                || device.label.chars().count() > MAX_ITEM_TITLE_CHARS
                || !device_ids.insert(device.id)
                || !valid_device_public_key_hex(&device.encryption_public_key_hex)
            {
                return Err(VaultItemValidationError::InvalidTrustedPrincipal);
            }
            if !encryption_keys.insert(device.encryption_public_key_hex.to_ascii_lowercase()) {
                return Err(VaultItemValidationError::InvalidTrustedPrincipal);
            }
            if let Some(signing_public_key_hex) = device.signing_public_key_hex.as_deref()
                && (!valid_signing_public_key_hex(signing_public_key_hex)
                    || card
                        .retired_signing_public_key_hexes
                        .contains(&signing_public_key_hex.to_ascii_lowercase())
                    || !signing_keys.insert(signing_public_key_hex.to_ascii_lowercase()))
            {
                return Err(VaultItemValidationError::InvalidTrustedPrincipal);
            }
        }
    }
    Ok(())
}

/// Generic Emergency Card creation/editing cannot manufacture authenticated
/// device bindings. A signing key may only be introduced by the dedicated
/// pairing-completion mutation after its dual-key proof verifies.
pub fn validate_trusted_devices_unpaired(
    card: &EmergencyCard,
) -> Result<(), VaultItemValidationError> {
    if card
        .principals
        .iter()
        .flat_map(|principal| principal.devices.iter())
        .any(|device| device.signing_public_key_hex.is_some())
    {
        return Err(VaultItemValidationError::InvalidTrustedPrincipal);
    }
    Ok(())
}

/// Carries forward retired identity tombstones and records IDs removed by this
/// update. Tombstones are encrypted with the Emergency Card and prevent a
/// future principal/device from inheriting old grants by reusing a removed UUID.
pub fn carry_forward_trusted_identity_retirements(
    previous: &EmergencyCard,
    next: &mut EmergencyCard,
) {
    next.retired_principal_ids
        .extend(previous.retired_principal_ids.iter().copied());
    next.retired_device_ids
        .extend(previous.retired_device_ids.iter().copied());
    next.retired_signing_public_key_hexes
        .extend(previous.retired_signing_public_key_hexes.iter().cloned());

    let next_principal_ids = next
        .principals
        .iter()
        .map(|principal| principal.id)
        .collect::<BTreeSet<_>>();
    for principal in &previous.principals {
        if !next_principal_ids.contains(&principal.id) {
            next.retired_principal_ids.insert(principal.id);
        }
    }

    let next_device_ids = next
        .principals
        .iter()
        .flat_map(|principal| principal.devices.iter().map(|device| device.id))
        .collect::<BTreeSet<_>>();
    for device in previous
        .principals
        .iter()
        .flat_map(|principal| principal.devices.iter())
    {
        if !next_device_ids.contains(&device.id) {
            next.retired_device_ids.insert(device.id);
            if let Some(signing_public_key_hex) = device.signing_public_key_hex.as_deref() {
                next.retired_signing_public_key_hexes
                    .insert(signing_public_key_hex.to_ascii_lowercase());
            }
        }
    }
}

/// Existing trusted UUIDs are immutable bindings. A caller may edit display
/// metadata, remove an identity, or add a fresh UUID, but it cannot reassign an
/// existing device UUID to another principal/key or revive any retired ID.
pub fn validate_trusted_identity_continuity(
    previous: &EmergencyCard,
    next: &EmergencyCard,
) -> Result<(), VaultItemValidationError> {
    if !previous
        .retired_principal_ids
        .is_subset(&next.retired_principal_ids)
        || !previous
            .retired_device_ids
            .is_subset(&next.retired_device_ids)
        || !previous
            .retired_signing_public_key_hexes
            .is_subset(&next.retired_signing_public_key_hexes)
        || next.principals.iter().any(|principal| {
            previous.retired_principal_ids.contains(&principal.id)
                || principal
                    .devices
                    .iter()
                    .any(|device| previous.retired_device_ids.contains(&device.id))
        })
    {
        return Err(VaultItemValidationError::InvalidTrustedPrincipal);
    }

    let mut previous_devices = BTreeMap::new();
    for principal in &previous.principals {
        for device in &principal.devices {
            previous_devices.insert(
                device.id,
                (
                    principal.id,
                    device.encryption_public_key_hex.to_ascii_lowercase(),
                    device
                        .signing_public_key_hex
                        .as_deref()
                        .map(str::to_ascii_lowercase),
                ),
            );
        }
    }

    for principal in &next.principals {
        for device in &principal.devices {
            let Some((previous_principal_id, previous_key, previous_signing_key)) =
                previous_devices.get(&device.id)
            else {
                if device.signing_public_key_hex.is_some() {
                    return Err(VaultItemValidationError::InvalidTrustedPrincipal);
                }
                continue;
            };
            if *previous_principal_id != principal.id
                || *previous_key != device.encryption_public_key_hex.to_ascii_lowercase()
                || *previous_signing_key
                    != device
                        .signing_public_key_hex
                        .as_deref()
                        .map(str::to_ascii_lowercase)
            {
                return Err(VaultItemValidationError::InvalidTrustedPrincipal);
            }
        }
    }
    Ok(())
}

fn valid_device_public_key_hex(value: &str) -> bool {
    let Some(public_key) = decode_public_key_hex(value) else {
        return false;
    };
    if !is_canonical_x25519_u_coordinate(&public_key) {
        return false;
    }
    // X25519 low-order public keys produce the identity for every clamped
    // scalar. Reject them at registry validation time so a principal cannot be
    // considered device-bound with a key that can never derive a contributory
    // recipient secret.
    x25519_dalek::x25519([0x42; 32], public_key) != [0u8; 32]
}

fn valid_signing_public_key_hex(value: &str) -> bool {
    let Some(public_key) = decode_public_key_hex(value) else {
        return false;
    };
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&public_key) else {
        return false;
    };
    !verifying_key.is_weak()
}

fn is_canonical_x25519_u_coordinate(public_key: &[u8; 32]) -> bool {
    // Canonical little-endian field encoding must be strictly less than
    // p = 2^255 - 19. Requiring the canonical representation prevents distinct
    // input byte strings (for example one differing only in the ignored top
    // bit) from naming the same effective X25519 recipient key.
    const FIELD_MODULUS: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    for index in (0..32).rev() {
        if public_key[index] < FIELD_MODULUS[index] {
            return true;
        }
        if public_key[index] > FIELD_MODULUS[index] {
            return false;
        }
    }
    false
}

fn decode_public_key_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; 32];
    let encoded = value.as_bytes();
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = hex_nibble(encoded[index * 2])?;
        let low = hex_nibble(encoded[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Some(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyContact {
    pub name: String,
    pub relation: String,
    pub phone: String,
    #[serde(default)]
    pub email: String,
    pub notes: String,
}

/// Stable local identity used by encrypted access grants.
///
/// This is intentionally separate from [`EmergencyContact`]. A continuity
/// contact does not become an access principal unless the owner explicitly
/// creates one. Grants bind this principal id, never a device id, so device
/// changes do not silently rewrite access intent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedPrincipal {
    pub id: Uuid,
    pub name: String,
    pub relation: String,
    #[serde(default)]
    pub devices: Vec<TrustedDevice>,
}

/// Recipient-encryption device binding for a trusted principal.
///
/// The X25519 key is unverified local metadata until a future pairing/signing
/// protocol proves device possession. It must never be treated as sender
/// authentication or as proof of the human principal's identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedDevice {
    pub id: Uuid,
    pub label: String,
    pub encryption_public_key_hex: String,
    /// Ed25519 verification key installed only after the dedicated pairing
    /// proof demonstrates control of both this signing key and the X25519
    /// recipient key. `None` means recipient-only / not paired.
    #[serde(default)]
    pub signing_public_key_hex: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyCard {
    pub selected_item_ids: Vec<Uuid>,
    pub contacts: Vec<EmergencyContact>,
    #[serde(default)]
    pub principals: Vec<TrustedPrincipal>,
    #[serde(default)]
    pub retired_principal_ids: BTreeSet<Uuid>,
    #[serde(default)]
    pub retired_device_ids: BTreeSet<Uuid>,
    #[serde(default)]
    pub retired_signing_public_key_hexes: BTreeSet<String>,
    pub instructions: String,
}

impl EmergencyCard {
    pub fn empty() -> Self {
        Self {
            selected_item_ids: Vec::new(),
            contacts: Vec::new(),
            principals: Vec::new(),
            retired_principal_ids: BTreeSet::new(),
            retired_device_ids: BTreeSet::new(),
            retired_signing_public_key_hexes: BTreeSet::new(),
            instructions: String::new(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum VaultItemState {
    Active { item: VaultItem },
    Trashed { item: VaultItem, deleted_at_ms: u64 },
    Tombstone { id: Uuid, deleted_at_ms: u64 },
}

impl VaultItem {
    pub fn secure_note(title: impl Into<String>, body: impl Into<String>) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("body".to_owned(), body.into());
        Self {
            id: Uuid::new_v4(),
            kind: ItemKind::SecureNote,
            title: title.into(),
            links: Vec::new(),
            attachments: Vec::new(),
            legacy_disposition: LegacyDisposition::Unspecified,
            account_closure_plan: AccountClosurePlan::default(),
            access_policy: AccessPolicy::default(),
            fields,
            notes: None,
        }
    }

    pub fn password(
        title: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        website: impl Into<String>,
        notes: impl Into<String>,
    ) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("username".to_owned(), username.into());
        fields.insert("password".to_owned(), password.into());
        fields.insert("website".to_owned(), website.into());
        let notes = notes.into();
        Self {
            id: Uuid::new_v4(),
            kind: ItemKind::Password,
            title: title.into(),
            links: Vec::new(),
            attachments: Vec::new(),
            legacy_disposition: LegacyDisposition::Unspecified,
            account_closure_plan: AccountClosurePlan::default(),
            access_policy: AccessPolicy::default(),
            fields,
            notes: (!notes.is_empty()).then_some(notes),
        }
    }

    pub fn document(
        title: impl Into<String>,
        document_number: impl Into<String>,
        issuer: impl Into<String>,
        expiry: impl Into<String>,
        notes: impl Into<String>,
    ) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("document_number".to_owned(), document_number.into());
        fields.insert("issuer".to_owned(), issuer.into());
        fields.insert("expiry".to_owned(), expiry.into());
        let notes = notes.into();
        Self {
            id: Uuid::new_v4(),
            kind: ItemKind::Document,
            title: title.into(),
            links: Vec::new(),
            attachments: Vec::new(),
            legacy_disposition: LegacyDisposition::Unspecified,
            account_closure_plan: AccountClosurePlan::default(),
            access_policy: AccessPolicy::default(),
            fields,
            notes: (!notes.is_empty()).then_some(notes),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn receipt(
        title: impl Into<String>,
        merchant: impl Into<String>,
        purchase_date: impl Into<String>,
        amount: impl Into<String>,
        currency: impl Into<String>,
        receipt_reference: impl Into<String>,
        tracking_status: impl Into<String>,
        return_by: impl Into<String>,
        refund_due: impl Into<String>,
        notes: impl Into<String>,
    ) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("merchant".to_owned(), merchant.into());
        fields.insert("purchase_date".to_owned(), purchase_date.into());
        fields.insert("amount".to_owned(), amount.into());
        fields.insert("currency".to_owned(), currency.into());
        fields.insert("receipt_reference".to_owned(), receipt_reference.into());
        fields.insert("tracking_status".to_owned(), tracking_status.into());
        fields.insert("return_by".to_owned(), return_by.into());
        fields.insert("refund_due".to_owned(), refund_due.into());
        let notes = notes.into();
        Self {
            id: Uuid::new_v4(),
            kind: ItemKind::Receipt,
            title: title.into(),
            links: Vec::new(),
            attachments: Vec::new(),
            legacy_disposition: LegacyDisposition::Unspecified,
            account_closure_plan: AccountClosurePlan::default(),
            access_policy: AccessPolicy::default(),
            fields,
            notes: (!notes.is_empty()).then_some(notes),
        }
    }

    pub fn insurance(
        title: impl Into<String>,
        provider: impl Into<String>,
        policy_type: impl Into<String>,
        policy_number: impl Into<String>,
        renewal: impl Into<String>,
        notes: impl Into<String>,
    ) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("provider".to_owned(), provider.into());
        fields.insert("policy_type".to_owned(), policy_type.into());
        fields.insert("policy_number".to_owned(), policy_number.into());
        fields.insert("renewal".to_owned(), renewal.into());
        let notes = notes.into();
        Self {
            id: Uuid::new_v4(),
            kind: ItemKind::Insurance,
            title: title.into(),
            links: Vec::new(),
            attachments: Vec::new(),
            legacy_disposition: LegacyDisposition::Unspecified,
            account_closure_plan: AccountClosurePlan::default(),
            access_policy: AccessPolicy::default(),
            fields,
            notes: (!notes.is_empty()).then_some(notes),
        }
    }

    pub fn financial(
        title: impl Into<String>,
        institution: impl Into<String>,
        account_type: impl Into<String>,
        currency: impl Into<String>,
        account_number: impl Into<String>,
        notes: impl Into<String>,
    ) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("institution".to_owned(), institution.into());
        fields.insert("account_type".to_owned(), account_type.into());
        fields.insert("currency".to_owned(), currency.into());
        fields.insert("account_number".to_owned(), account_number.into());
        let notes = notes.into();
        Self {
            id: Uuid::new_v4(),
            kind: ItemKind::Financial,
            title: title.into(),
            links: Vec::new(),
            attachments: Vec::new(),
            legacy_disposition: LegacyDisposition::Unspecified,
            account_closure_plan: AccountClosurePlan::default(),
            access_policy: AccessPolicy::default(),
            fields,
            notes: (!notes.is_empty()).then_some(notes),
        }
    }

    pub fn property(
        title: impl Into<String>,
        property_type: impl Into<String>,
        address: impl Into<String>,
        ownership: impl Into<String>,
        property_reference: impl Into<String>,
        notes: impl Into<String>,
    ) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("property_type".to_owned(), property_type.into());
        fields.insert("address".to_owned(), address.into());
        fields.insert("ownership".to_owned(), ownership.into());
        fields.insert("property_reference".to_owned(), property_reference.into());
        let notes = notes.into();
        Self {
            id: Uuid::new_v4(),
            kind: ItemKind::Property,
            title: title.into(),
            links: Vec::new(),
            attachments: Vec::new(),
            legacy_disposition: LegacyDisposition::Unspecified,
            account_closure_plan: AccountClosurePlan::default(),
            access_policy: AccessPolicy::default(),
            fields,
            notes: (!notes.is_empty()).then_some(notes),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn vehicle(
        title: impl Into<String>,
        make: impl Into<String>,
        model: impl Into<String>,
        year: impl Into<String>,
        registration_number: impl Into<String>,
        vin: impl Into<String>,
        renewal: impl Into<String>,
        notes: impl Into<String>,
    ) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("make".to_owned(), make.into());
        fields.insert("model".to_owned(), model.into());
        fields.insert("year".to_owned(), year.into());
        fields.insert("registration_number".to_owned(), registration_number.into());
        fields.insert("vin".to_owned(), vin.into());
        fields.insert("renewal".to_owned(), renewal.into());
        let notes = notes.into();
        Self {
            id: Uuid::new_v4(),
            kind: ItemKind::Vehicle,
            title: title.into(),
            links: Vec::new(),
            attachments: Vec::new(),
            legacy_disposition: LegacyDisposition::Unspecified,
            account_closure_plan: AccountClosurePlan::default(),
            access_policy: AccessPolicy::default(),
            fields,
            notes: (!notes.is_empty()).then_some(notes),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn possession(
        title: impl Into<String>,
        category: impl Into<String>,
        location: impl Into<String>,
        brand: impl Into<String>,
        model: impl Into<String>,
        serial_number: impl Into<String>,
        purchase_date: impl Into<String>,
        purchase_price: impl Into<String>,
        store: impl Into<String>,
        warranty_expiry: impl Into<String>,
        notes: impl Into<String>,
    ) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("category".to_owned(), category.into().trim().to_owned());
        fields.insert("location".to_owned(), location.into().trim().to_owned());
        fields.insert("brand".to_owned(), brand.into());
        fields.insert("model".to_owned(), model.into());
        fields.insert("serial_number".to_owned(), serial_number.into());
        fields.insert("purchase_date".to_owned(), purchase_date.into());
        fields.insert("purchase_price".to_owned(), purchase_price.into());
        fields.insert("store".to_owned(), store.into());
        fields.insert("warranty_expiry".to_owned(), warranty_expiry.into());
        let notes = notes.into();
        Self {
            id: Uuid::new_v4(),
            kind: ItemKind::Possession,
            title: title.into(),
            links: Vec::new(),
            attachments: Vec::new(),
            legacy_disposition: LegacyDisposition::Unspecified,
            account_closure_plan: AccountClosurePlan::default(),
            access_policy: AccessPolicy::default(),
            fields,
            notes: (!notes.is_empty()).then_some(notes),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn subscription(
        title: impl Into<String>,
        provider: impl Into<String>,
        plan: impl Into<String>,
        amount: impl Into<String>,
        currency: impl Into<String>,
        billing_cycle: impl Into<String>,
        next_renewal: impl Into<String>,
        notes: impl Into<String>,
    ) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert("provider".to_owned(), provider.into());
        fields.insert("plan".to_owned(), plan.into());
        fields.insert("amount".to_owned(), amount.into());
        fields.insert("currency".to_owned(), currency.into());
        fields.insert("billing_cycle".to_owned(), billing_cycle.into());
        fields.insert("next_renewal".to_owned(), next_renewal.into());
        let notes = notes.into();
        Self {
            id: Uuid::new_v4(),
            kind: ItemKind::Subscription,
            title: title.into(),
            links: Vec::new(),
            attachments: Vec::new(),
            legacy_disposition: LegacyDisposition::Unspecified,
            account_closure_plan: AccountClosurePlan::default(),
            access_policy: AccessPolicy::default(),
            fields,
            notes: (!notes.is_empty()).then_some(notes),
        }
    }

    pub fn emergency_card(card: &EmergencyCard) -> Self {
        let mut fields = BTreeMap::new();
        fields.insert(
            "card".to_owned(),
            serde_json::to_string(card).expect("emergency card serialization cannot fail"),
        );
        Self {
            id: EMERGENCY_CARD_ID,
            kind: ItemKind::EmergencyInstruction,
            title: "Emergency Card".to_owned(),
            links: Vec::new(),
            attachments: Vec::new(),
            legacy_disposition: LegacyDisposition::Unspecified,
            account_closure_plan: AccountClosurePlan::default(),
            access_policy: AccessPolicy::default(),
            fields,
            notes: None,
        }
    }

    pub fn parse_emergency_card(&self) -> Option<EmergencyCard> {
        if self.kind != ItemKind::EmergencyInstruction {
            return None;
        }
        let raw = self.fields.get("card")?;
        serde_json::from_str(raw).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vehicle_constructor_sets_ownership_fields() {
        let item = VaultItem::vehicle(
            "Family Car",
            "Toyota",
            "Innova",
            "2021",
            "KA01AB1234",
            "VIN1234567890",
            "2026-10-02",
            "",
        );
        assert_eq!(item.kind, ItemKind::Vehicle);
        assert!(item.links.is_empty());
        assert_eq!(
            item.fields.get("registration_number").map(String::as_str),
            Some("KA01AB1234")
        );
        assert_eq!(
            item.fields.get("vin").map(String::as_str),
            Some("VIN1234567890")
        );
    }

    #[test]
    fn possession_constructor_sets_warranty_fields() {
        let item = VaultItem::possession(
            "MacBook",
            "  Electronics  ",
            " Home office ",
            "Apple",
            "Pro 14",
            "SN123",
            "2024-01-15",
            "199900",
            "Amazon",
            "2027-01-15",
            "",
        );
        assert_eq!(item.kind, ItemKind::Possession);
        assert_eq!(
            item.fields.get("category").map(String::as_str),
            Some("Electronics")
        );
        assert_eq!(
            item.fields.get("location").map(String::as_str),
            Some("Home office")
        );
        assert_eq!(
            item.fields.get("warranty_expiry").map(String::as_str),
            Some("2027-01-15")
        );
    }

    #[test]
    fn subscription_constructor_sets_tracking_fields() {
        let item = VaultItem::subscription(
            "Music",
            "Example Media",
            "Family",
            "19.99",
            "USD",
            "monthly",
            "2026-10-15",
            "cancel before travel",
        );
        assert_eq!(item.kind, ItemKind::Subscription);
        assert_eq!(
            item.fields.get("provider").map(String::as_str),
            Some("Example Media")
        );
        assert_eq!(
            item.fields.get("billing_cycle").map(String::as_str),
            Some("monthly")
        );
        assert_eq!(
            item.fields.get("next_renewal").map(String::as_str),
            Some("2026-10-15")
        );
        assert_eq!(item.notes.as_deref(), Some("cancel before travel"));
    }

    #[test]
    fn receipt_constructor_sets_return_tracking_fields() {
        let item = VaultItem::receipt(
            "MacBook receipt",
            "Apple",
            "2026-09-15",
            "199900",
            "INR",
            "INV-123",
            "return_planned",
            "2026-09-29",
            "",
            "private note",
        );
        assert_eq!(item.kind, ItemKind::Receipt);
        assert_eq!(
            item.fields.get("receipt_reference").map(String::as_str),
            Some("INV-123")
        );
        assert_eq!(
            item.fields.get("return_by").map(String::as_str),
            Some("2026-09-29")
        );
        assert_eq!(
            item.fields.get("tracking_status").map(String::as_str),
            Some("return_planned")
        );
        assert_eq!(item.notes.as_deref(), Some("private note"));
    }

    #[test]
    fn current_item_payload_requires_current_planning_fields() {
        let incomplete = serde_json::json!({
            "id": Uuid::new_v4(),
            "kind": "secure_note",
            "title": "current",
            "links": [],
            "attachments": [],
            "account_closure_plan": {"disposition": "unspecified", "instructions": ""},
            "fields": {"body": "hello"},
            "notes": null
        });
        assert!(serde_json::from_value::<VaultItem>(incomplete).is_err());

        let missing_closure_plan = serde_json::json!({
            "id": Uuid::new_v4(),
            "kind": "secure_note",
            "title": "current",
            "links": [],
            "attachments": [],
            "legacy_disposition": "unspecified",
            "fields": {"body": "hello"},
            "notes": null
        });
        assert!(serde_json::from_value::<VaultItem>(missing_closure_plan).is_err());

        let missing_links = serde_json::json!({
            "id": Uuid::new_v4(),
            "kind": "secure_note",
            "title": "current",
            "attachments": [],
            "legacy_disposition": "unspecified",
            "account_closure_plan": {"disposition": "unspecified", "instructions": ""},
            "fields": {"body": "hello"},
            "notes": null
        });
        assert!(serde_json::from_value::<VaultItem>(missing_links).is_err());

        let missing_attachments = serde_json::json!({
            "id": Uuid::new_v4(),
            "kind": "secure_note",
            "title": "current",
            "links": [],
            "legacy_disposition": "unspecified",
            "account_closure_plan": {"disposition": "unspecified", "instructions": ""},
            "fields": {"body": "hello"},
            "notes": null
        });
        assert!(serde_json::from_value::<VaultItem>(missing_attachments).is_err());

        let missing_notes = serde_json::json!({
            "id": Uuid::new_v4(),
            "kind": "secure_note",
            "title": "current",
            "links": [],
            "attachments": [],
            "legacy_disposition": "unspecified",
            "account_closure_plan": {"disposition": "unspecified", "instructions": ""},
            "fields": {"body": "hello"}
        });
        assert!(serde_json::from_value::<VaultItem>(missing_notes).is_err());

        let unexpected = serde_json::json!({
            "id": Uuid::new_v4(),
            "kind": "secure_note",
            "title": "current",
            "links": [],
            "attachments": [],
            "legacy_disposition": "unspecified",
            "account_closure_plan": {"disposition": "unspecified", "instructions": ""},
            "fields": {"body": "hello"},
            "notes": null,
            "future_policy": {"unexpected": true}
        });
        assert!(serde_json::from_value::<VaultItem>(unexpected).is_err());
    }

    #[test]
    fn current_item_payload_round_trips_planning_metadata() {
        let current = serde_json::json!({
            "id": Uuid::new_v4(),
            "kind": "password",
            "title": "current",
            "links": [Uuid::new_v4()],
            "attachments": [],
            "legacy_disposition": "private_forever",
            "account_closure_plan": {"disposition": "close_account", "instructions": "Cancel after exporting statements."},
            "fields": {"username": "u", "password": "p", "website": "https://example.test"},
            "notes": null
        });
        let item: VaultItem = serde_json::from_value(current).expect("current payload decodes");
        assert_eq!(item.links.len(), 1);
        assert!(item.attachments.is_empty());
        assert_eq!(item.legacy_disposition, LegacyDisposition::PrivateForever);
        assert_eq!(
            item.account_closure_plan.disposition,
            AccountClosureDisposition::CloseAccount
        );
        assert_eq!(
            item.account_closure_plan.instructions,
            "Cancel after exporting statements."
        );
        assert_eq!(item.access_policy, AccessPolicy::default());
    }

    #[test]
    fn access_policy_round_trips_inside_vault_item() {
        let trustee = Uuid::new_v4();
        let mut item = VaultItem::secure_note("continuity", "private");
        item.access_policy
            .add_grant(
                AccessGrant::new(
                    trustee,
                    "record",
                    Permission::Download,
                    AccessCondition::Emergency,
                    WaitPeriod::OneDay,
                    GrantDuration::SevenDays,
                    0,
                    BTreeSet::new(),
                )
                .expect("valid grant"),
            )
            .expect("add grant");

        validate_vault_item(&item).expect("valid item policy");
        let encoded = serde_json::to_vec(&item).expect("serialize item");
        let decoded: VaultItem = serde_json::from_slice(&encoded).expect("deserialize item");
        assert_eq!(decoded.access_policy, item.access_policy);
    }

    #[test]
    fn malformed_deserialized_access_policy_is_rejected_by_item_validation() {
        let mut item = VaultItem::secure_note("continuity", "private");
        item.access_policy.grants.push(AccessGrant {
            trustee_id: Uuid::new_v4(),
            what: String::new(),
            permission: Permission::View,
            condition: AccessCondition::Emergency,
            wait_period: WaitPeriod::Immediate,
            duration: GrantDuration::UntilRevoked,
            approvals_required: 0,
            approver_ids: BTreeSet::new(),
        });

        assert_eq!(
            validate_vault_item(&item),
            Err(VaultItemValidationError::InvalidAccessPolicy)
        );
    }

    #[test]
    fn emergency_card_constructor_and_parse_round_trip() {
        let card = EmergencyCard {
            selected_item_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
            contacts: vec![EmergencyContact {
                name: "Ada".to_owned(),
                relation: "Sibling".to_owned(),
                phone: "+1-555-0100".to_owned(),
                email: "ada@example.test".to_owned(),
                notes: "Call first".to_owned(),
            }],
            principals: vec![TrustedPrincipal {
                id: Uuid::new_v4(),
                name: "Ada".to_owned(),
                relation: "Sibling".to_owned(),
                devices: vec![TrustedDevice {
                    id: Uuid::new_v4(),
                    label: "Phone".to_owned(),
                    encryption_public_key_hex:
                        "1111111111111111111111111111111111111111111111111111111111111111"
                            .to_owned(),
                    signing_public_key_hex: None,
                }],
            }],
            retired_principal_ids: BTreeSet::new(),
            retired_device_ids: BTreeSet::new(),
            retired_signing_public_key_hexes: BTreeSet::new(),
            instructions: "Follow the printed steps".to_owned(),
        };
        let item = VaultItem::emergency_card(&card);
        assert_eq!(item.id, EMERGENCY_CARD_ID);
        assert_eq!(item.kind, ItemKind::EmergencyInstruction);
        assert_eq!(item.title, "Emergency Card");
        assert_eq!(item.parse_emergency_card(), Some(card));
    }

    #[test]
    fn emergency_card_missing_contact_email_defaults_empty() {
        let mut item = VaultItem::emergency_card(&EmergencyCard::empty());
        item.fields.insert(
            "card".to_owned(),
            serde_json::json!({
                "selected_item_ids": [],
                "contacts": [{
                    "name": "Ada",
                    "relation": "Sibling",
                    "phone": "+1-555-0100",
                    "notes": "Call first"
                }],
                "instructions": "Use the phone."
            })
            .to_string(),
        );
        let card = item
            .parse_emergency_card()
            .expect("parse legacy emergency card");
        assert_eq!(card.contacts[0].email, "");
        assert!(card.principals.is_empty());
    }

    #[test]
    fn trusted_principal_registry_requires_unique_stable_ids_and_device_keys() {
        let principal_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let device_key = "2222222222222222222222222222222222222222222222222222222222222222";
        let mut card = EmergencyCard::empty();
        card.principals.push(TrustedPrincipal {
            id: principal_id,
            name: "Ada".to_owned(),
            relation: "Sibling".to_owned(),
            devices: vec![TrustedDevice {
                id: device_id,
                label: "Laptop".to_owned(),
                encryption_public_key_hex: device_key.to_owned(),
                signing_public_key_hex: None,
            }],
        });
        validate_emergency_card(&card).expect("valid trusted principal registry");

        let mut duplicate_principal = card.clone();
        duplicate_principal.principals.push(TrustedPrincipal {
            id: principal_id,
            name: "Duplicate".to_owned(),
            relation: String::new(),
            devices: Vec::new(),
        });
        assert_eq!(
            validate_emergency_card(&duplicate_principal),
            Err(VaultItemValidationError::InvalidTrustedPrincipal)
        );

        let mut duplicate_device_key = card.clone();
        duplicate_device_key.principals.push(TrustedPrincipal {
            id: Uuid::new_v4(),
            name: "Grace".to_owned(),
            relation: "Friend".to_owned(),
            devices: vec![TrustedDevice {
                id: Uuid::new_v4(),
                label: "Phone".to_owned(),
                encryption_public_key_hex: device_key.to_ascii_uppercase(),
                signing_public_key_hex: None,
            }],
        });
        assert_eq!(
            validate_emergency_card(&duplicate_device_key),
            Err(VaultItemValidationError::InvalidTrustedPrincipal)
        );

        let mut zero_key = card;
        zero_key.principals[0].devices[0].encryption_public_key_hex = "0".repeat(64);
        assert_eq!(
            validate_emergency_card(&zero_key),
            Err(VaultItemValidationError::InvalidTrustedPrincipal)
        );

        let mut low_order_key = EmergencyCard::empty();
        low_order_key.principals.push(TrustedPrincipal {
            id: Uuid::new_v4(),
            name: "Low order".to_owned(),
            relation: String::new(),
            devices: vec![TrustedDevice {
                id: Uuid::new_v4(),
                label: "Bad key".to_owned(),
                // Montgomery u=1 is a low-order X25519 public key.
                encryption_public_key_hex: format!("01{}", "00".repeat(31)),
                signing_public_key_hex: None,
            }],
        });
        assert_eq!(
            validate_emergency_card(&low_order_key),
            Err(VaultItemValidationError::InvalidTrustedPrincipal)
        );

        let mut alias_encoding = EmergencyCard::empty();
        alias_encoding.principals.push(TrustedPrincipal {
            id: Uuid::new_v4(),
            name: "Alias".to_owned(),
            relation: String::new(),
            devices: vec![TrustedDevice {
                id: Uuid::new_v4(),
                label: "Non-canonical key".to_owned(),
                encryption_public_key_hex:
                    "1111111111111111111111111111111111111111111111111111111111111191".to_owned(),
                signing_public_key_hex: None,
            }],
        });
        assert_eq!(
            validate_emergency_card(&alias_encoding),
            Err(VaultItemValidationError::InvalidTrustedPrincipal)
        );
    }

    #[test]
    fn trusted_device_uuid_cannot_be_rebound_to_a_new_key_or_principal() {
        let principal_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let mut previous = EmergencyCard::empty();
        previous.principals.push(TrustedPrincipal {
            id: principal_id,
            name: "Ada".to_owned(),
            relation: "Sibling".to_owned(),
            devices: vec![TrustedDevice {
                id: device_id,
                label: "Phone".to_owned(),
                encryption_public_key_hex:
                    "3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                signing_public_key_hex: None,
            }],
        });

        let mut renamed = previous.clone();
        renamed.principals[0].devices[0].label = "New label".to_owned();
        validate_trusted_identity_continuity(&previous, &renamed)
            .expect("labels may change without rebinding a device");

        let mut rekeyed = previous.clone();
        rekeyed.principals[0].devices[0].encryption_public_key_hex =
            "4444444444444444444444444444444444444444444444444444444444444444".to_owned();
        assert_eq!(
            validate_trusted_identity_continuity(&previous, &rekeyed),
            Err(VaultItemValidationError::InvalidTrustedPrincipal)
        );

        let mut reassigned = previous.clone();
        let device = reassigned.principals[0].devices.remove(0);
        reassigned.principals.push(TrustedPrincipal {
            id: Uuid::new_v4(),
            name: "Grace".to_owned(),
            relation: "Friend".to_owned(),
            devices: vec![device],
        });
        assert_eq!(
            validate_trusted_identity_continuity(&previous, &reassigned),
            Err(VaultItemValidationError::InvalidTrustedPrincipal)
        );
    }

    #[test]
    fn removed_trusted_ids_are_tombstoned_and_cannot_be_reused() {
        let principal_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let mut previous = EmergencyCard::empty();
        previous.principals.push(TrustedPrincipal {
            id: principal_id,
            name: "Ada".to_owned(),
            relation: "Sibling".to_owned(),
            devices: vec![TrustedDevice {
                id: device_id,
                label: "Phone".to_owned(),
                encryption_public_key_hex:
                    "5555555555555555555555555555555555555555555555555555555555555555".to_owned(),
                signing_public_key_hex: None,
            }],
        });

        let mut removed = EmergencyCard::empty();
        carry_forward_trusted_identity_retirements(&previous, &mut removed);
        assert!(removed.retired_principal_ids.contains(&principal_id));
        assert!(removed.retired_device_ids.contains(&device_id));
        validate_trusted_identity_continuity(&previous, &removed)
            .expect("removal records stable identity tombstones");

        let mut revived_principal = removed.clone();
        revived_principal.principals.push(TrustedPrincipal {
            id: principal_id,
            name: "Different person".to_owned(),
            relation: String::new(),
            devices: Vec::new(),
        });
        assert_eq!(
            validate_emergency_card(&revived_principal),
            Err(VaultItemValidationError::InvalidTrustedPrincipal)
        );

        let mut revived_device = removed;
        revived_device.principals.push(TrustedPrincipal {
            id: Uuid::new_v4(),
            name: "Grace".to_owned(),
            relation: "Friend".to_owned(),
            devices: vec![TrustedDevice {
                id: device_id,
                label: "Reused device".to_owned(),
                encryption_public_key_hex:
                    "6666666666666666666666666666666666666666666666666666666666666666".to_owned(),
                signing_public_key_hex: None,
            }],
        });
        assert_eq!(
            validate_emergency_card(&revived_device),
            Err(VaultItemValidationError::InvalidTrustedPrincipal)
        );
    }

    #[test]
    fn emergency_card_parse_returns_none_for_secure_note() {
        let item = VaultItem::secure_note("note", "body");
        assert_eq!(item.parse_emergency_card(), None);
    }

    #[test]
    fn emergency_card_parse_returns_none_for_corrupted_card_field() {
        let mut item = VaultItem::emergency_card(&EmergencyCard::empty());
        item.fields
            .insert("card".to_owned(), "not-valid-json{".to_owned());
        assert_eq!(item.parse_emergency_card(), None);
    }
}
