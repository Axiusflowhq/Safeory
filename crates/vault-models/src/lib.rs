#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
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
    Vehicle,
    Possession,
    EmergencyInstruction,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    #[serde(default)]
    pub links: Vec<Uuid>,
    #[serde(default)]
    pub attachments: Vec<Uuid>,
    pub fields: BTreeMap<String, String>,
    pub notes: Option<String>,
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
#[serde(tag = "state", rename_all = "snake_case")]
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
    fn pre_links_payload_still_decodes_with_empty_links() {
        let legacy = serde_json::json!({
            "id": Uuid::new_v4(),
            "kind": "secure_note",
            "title": "legacy",
            "fields": {"body": "hello"},
            "notes": null
        });
        let item: VaultItem =
            serde_json::from_value(legacy).expect("legacy payload without links decodes");
        assert!(item.links.is_empty());
        assert!(item.attachments.is_empty());
        assert_eq!(item.title, "legacy");
    }

    #[test]
    fn pre_attachments_payload_still_decodes_with_empty_attachments() {
        let legacy = serde_json::json!({
            "id": Uuid::new_v4(),
            "kind": "secure_note",
            "title": "legacy links",
            "links": [Uuid::new_v4()],
            "fields": {"body": "hello"},
            "notes": null
        });
        let item: VaultItem =
            serde_json::from_value(legacy).expect("payload without attachments decodes");
        assert_eq!(item.links.len(), 1);
        assert!(item.attachments.is_empty());
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
