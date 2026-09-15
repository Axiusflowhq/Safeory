#![forbid(unsafe_code)]

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultItem {
    pub id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    pub links: Vec<Uuid>,
    pub attachments: Vec<Uuid>,
    pub legacy_disposition: LegacyDisposition,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyContact {
    pub name: String,
    pub relation: String,
    pub phone: String,
    pub notes: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyCard {
    pub selected_item_ids: Vec<Uuid>,
    pub contacts: Vec<EmergencyContact>,
    pub instructions: String,
}

impl EmergencyCard {
    pub fn empty() -> Self {
        Self {
            selected_item_ids: Vec::new(),
            contacts: Vec::new(),
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
            fields,
            notes: (!notes.is_empty()).then_some(notes),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn possession(
        title: impl Into<String>,
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
            item.fields.get("warranty_expiry").map(String::as_str),
            Some("2027-01-15")
        );
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
    fn current_item_payload_requires_legacy_disposition() {
        let incomplete = serde_json::json!({
            "id": Uuid::new_v4(),
            "kind": "secure_note",
            "title": "current",
            "links": [],
            "attachments": [],
            "fields": {"body": "hello"},
            "notes": null
        });
        assert!(serde_json::from_value::<VaultItem>(incomplete).is_err());

        let missing_links = serde_json::json!({
            "id": Uuid::new_v4(),
            "kind": "secure_note",
            "title": "current",
            "attachments": [],
            "legacy_disposition": "unspecified",
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
            "fields": {"body": "hello"},
            "notes": null,
            "future_policy": {"unexpected": true}
        });
        assert!(serde_json::from_value::<VaultItem>(unexpected).is_err());
    }

    #[test]
    fn current_item_payload_round_trips_legacy_disposition() {
        let current = serde_json::json!({
            "id": Uuid::new_v4(),
            "kind": "secure_note",
            "title": "current",
            "links": [Uuid::new_v4()],
            "attachments": [],
            "legacy_disposition": "private_forever",
            "fields": {"body": "hello"},
            "notes": null
        });
        let item: VaultItem = serde_json::from_value(current).expect("current payload decodes");
        assert_eq!(item.links.len(), 1);
        assert!(item.attachments.is_empty());
        assert_eq!(item.legacy_disposition, LegacyDisposition::PrivateForever);
    }

    #[test]
    fn emergency_card_constructor_and_parse_round_trip() {
        let card = EmergencyCard {
            selected_item_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
            contacts: vec![EmergencyContact {
                name: "Ada".to_owned(),
                relation: "Sibling".to_owned(),
                phone: "+1-555-0100".to_owned(),
                notes: "Call first".to_owned(),
            }],
            instructions: "Follow the printed steps".to_owned(),
        };
        let item = VaultItem::emergency_card(&card);
        assert_eq!(item.id, EMERGENCY_CARD_ID);
        assert_eq!(item.kind, ItemKind::EmergencyInstruction);
        assert_eq!(item.title, "Emergency Card");
        assert_eq!(item.parse_emergency_card(), Some(card));
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
