use bitwarden_core::key_management::BLOB_SECURITY_VERSION;
use safeory_foundation_sdk_behavior::fixture_support::{client, safeory_envelope_view};

#[tokio::main]
async fn main() {
    let updated = std::env::args().nth(1).as_deref() == Some("updated");
    let client = client().await;
    client
        .0
        .internal
        .get_key_store()
        .set_security_state_version(BLOB_SECURITY_VERSION);

    let title = if updated {
        "Family health policy renewed"
    } else {
        "Family health policy"
    };
    let renewal = if updated { "2028-01-15" } else { "2027-01-15" };
    let notes = if updated {
        "Renewed after annual review."
    } else {
        "Call before renewal."
    };

    let envelope = serde_json::json!({
        "marker": "safeory.life_record",
        "schema_version": 1,
        "record_id": "11111111-1111-4111-8111-111111111111",
        "record_kind": "insurance",
        "data": {
            "title": title,
            "provider": "Example Mutual",
            "policy_number": "POL-123",
            "renewal": renewal,
            "notes": notes
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
        "fixture_variant": if updated { "updated" } else { "initial" },
        "record_id": "11111111-1111-4111-8111-111111111111",
        "envelope": serialized,
        "data": encrypted.data.unwrap(),
        "key": encrypted.key.unwrap().to_string()
    });
    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
}
