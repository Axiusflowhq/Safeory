use bitwarden_core::key_management::BLOB_SECURITY_VERSION;
use safeory_foundation_sdk_behavior::fixture_support::{client, safeory_envelope_view};

#[tokio::main]
async fn main() {
    let client = client().await;
    client
        .0
        .internal
        .get_key_store()
        .set_security_state_version(BLOB_SECURITY_VERSION);

    let envelope = serde_json::json!({
        "marker": "safeory.life_record",
        "schema_version": 1,
        "record_id": "11111111-1111-4111-8111-111111111111",
        "record_kind": "insurance",
        "data": {
            "title": "Family health policy",
            "provider": "Example Mutual",
            "policy_number": "POL-123",
            "renewal": "2027-01-15",
            "notes": "Call before renewal."
        },
        "links": ["22222222-2222-4222-8222-222222222222"],
        "relationships": [{
            "target_record_id": "33333333-3333-4333-8333-333333333333",
            "relation": "covers_person"
        }],
        "reminders": [{
            "reminder_id": "44444444-4444-4444-8444-444444444444",
            "mode": "recurring",
            "next_date": "2027-01-01",
            "label": "Review insurance renewal",
            "recurrence": { "frequency": "yearly", "interval": 1, "end_date": null }
        }],
        "continuity": {
            "legacy_disposition": "selected_for_legacy",
            "policy_ref": "55555555-5555-4555-8555-555555555555"
        },
        "extensions": {
            "safeory.example.future": { "preserved": true, "version": 2 }
        }
    });
    let serialized = serde_json::to_string(&envelope).unwrap();
    let encrypted = client
        .vault()
        .ciphers()
        .encrypt(safeory_envelope_view(serialized.clone()))
        .await
        .unwrap()
        .cipher;

    let fixture = serde_json::json!({
        "fixture_version": 1,
        "record_id": "11111111-1111-4111-8111-111111111111",
        "envelope": serialized,
        "data": encrypted.data.unwrap(),
        "key": encrypted.key.unwrap().to_string()
    });
    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
}
