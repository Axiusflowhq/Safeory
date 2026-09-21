#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use bitwarden_api_api::models::CipherDetailsResponseModel;
    use bitwarden_core::{
        Client, client::test_accounts::test_bitwarden_com_account,
        key_management::BLOB_SECURITY_VERSION,
    };
    use bitwarden_encoding::B64Url;
    use bitwarden_exporters::ExportFormat;
    use bitwarden_pm::PasswordManagerClient;
    use bitwarden_vault::{
        AttachmentView, CipherListViewType, CipherRepromptType, CipherType, CipherView,
        Fido2CredentialFullView, LoginUriView, LoginView, SecureNoteType, SecureNoteView,
        UriMatchType, generate_totp,
    };

    const TEST_FIDO_P256_KEY: &[u8] = &[
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0x06, 0x76, 0x5e, 0x85, 0xe0, 0x7f, 0xef, 0x43, 0xaa,
        0x17, 0xe0, 0x7a, 0xd7, 0x85, 0x63, 0x01, 0x80, 0x70, 0x8c, 0x6c, 0x61, 0x43, 0x7d, 0xc3,
        0xb1, 0xe6, 0xf9, 0x09, 0x24, 0xeb, 0x1f, 0xf5, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x35,
        0x9a, 0x52, 0xf3, 0x82, 0x44, 0x66, 0x5f, 0x3f, 0xe2, 0xc4, 0x0b, 0x1c, 0x16, 0x34, 0xc5,
        0x60, 0x07, 0x3a, 0x25, 0xfe, 0x7e, 0x7f, 0x7f, 0xda, 0xd4, 0x1c, 0x36, 0x90, 0x00, 0xee,
        0xb1, 0x8e, 0x92, 0xb3, 0xac, 0x91, 0x7f, 0xb1, 0x8c, 0xa4, 0x85, 0xe7, 0x03, 0x07, 0xd1,
        0xf5, 0x5b, 0xd3, 0x7b, 0xc3, 0x56, 0x11, 0xdf, 0xbc, 0x7a, 0x97, 0x70, 0x32, 0x4b, 0x3c,
        0x84, 0x05, 0x71,
    ];

    fn login_view() -> CipherView {
        CipherView {
            id: Some("b1d9d8a9-a540-4208-8f0d-aab305e622f6".parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: "Safeory foundation login".to_owned(),
            notes: Some("SDK/core proof".to_owned()),
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: Some("safeory-user".to_owned()),
                password: Some("safeory-password".to_owned()),
                password_revision_date: None,
                uris: Some(vec![LoginUriView {
                    uri: Some("https://vault.safeory.example/login".to_owned()),
                    r#match: Some(UriMatchType::Domain),
                    uri_checksum: None,
                }]),
                totp: Some("WQIQ25BRKZYCJVYP".to_owned()),
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            favorite: true,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
            fields: None,
            password_history: None,
            creation_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            archived_date: None,
        }
    }

    fn safeory_envelope_view(notes: String) -> CipherView {
        CipherView {
            id: Some("11111111-1111-4111-8111-111111111111".parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: "Safeory insurance record".to_owned(),
            notes: Some(notes),
            r#type: CipherType::SecureNote,
            login: None,
            identity: None,
            card: None,
            secure_note: Some(SecureNoteView {
                r#type: SecureNoteType::Generic,
            }),
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
            fields: None,
            password_history: None,
            creation_date: "2026-09-21T00:00:00Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2026-09-21T00:00:00Z".parse().unwrap(),
            archived_date: None,
        }
    }

    async fn client() -> PasswordManagerClient {
        PasswordManagerClient(Client::init_test_account(test_bitwarden_com_account()).await)
    }

    #[tokio::test]
    async fn login_crypto_totp_and_json_export_round_trip() {
        let client = client().await;
        let vault = client.vault();

        let encrypted = vault.ciphers().encrypt(login_view()).await.unwrap().cipher;
        assert!(encrypted.key.is_some());

        let decrypted = vault.ciphers().decrypt(encrypted.clone()).await.unwrap();
        assert_eq!(decrypted.name, "Safeory foundation login");
        let login = decrypted.login.as_ref().unwrap();
        assert_eq!(login.username.as_deref(), Some("safeory-user"));
        assert_eq!(login.password.as_deref(), Some("safeory-password"));
        assert_eq!(login.totp.as_deref(), Some("WQIQ25BRKZYCJVYP"));
        assert_eq!(
            login.uris.as_ref().unwrap()[0].uri.as_deref(),
            Some("https://vault.safeory.example/login")
        );

        let at = "2023-01-01T00:00:00.000Z".parse().unwrap();
        let totp = generate_totp(login.totp.clone().unwrap(), Some(at)).unwrap();
        assert_eq!(totp.code, "194506");
        assert_eq!(totp.period, 30);

        let exported = client
            .exporters()
            .export_vault(vec![], vec![encrypted], ExportFormat::Json)
            .await
            .unwrap();
        assert!(exported.contains("\"encrypted\": false"));
        assert!(exported.contains("\"name\": \"Safeory foundation login\""));
        assert!(exported.contains("\"username\": \"safeory-user\""));
        assert!(exported.contains("\"password\": \"safeory-password\""));
        assert!(exported.contains("\"totp\": \"WQIQ25BRKZYCJVYP\""));
    }

    #[tokio::test]
    async fn attachment_buffer_round_trip_uses_cipher_key() {
        let client = client().await;
        let vault = client.vault();
        let mut encrypted_cipher = vault.ciphers().encrypt(login_view()).await.unwrap().cipher;

        let plaintext = b"safeory foundation attachment";
        let encrypted_attachment = vault
            .attachments()
            .encrypt_buffer(
                encrypted_cipher.clone(),
                AttachmentView {
                    id: None,
                    url: None,
                    size: None,
                    size_name: None,
                    file_name: Some("proof.txt".to_owned()),
                    key: None,
                    decrypted_key: None,
                },
                plaintext,
            )
            .unwrap();

        assert_ne!(encrypted_attachment.contents, plaintext);
        assert!(encrypted_attachment.attachment.key.is_some());
        encrypted_cipher.attachments = Some(vec![encrypted_attachment.attachment]);

        let decrypted_cipher = vault
            .ciphers()
            .decrypt(encrypted_cipher.clone())
            .await
            .unwrap();
        let attachment = decrypted_cipher.attachments.unwrap().remove(0);
        assert_eq!(attachment.file_name.as_deref(), Some("proof.txt"));
        assert!(attachment.key.is_some());

        let decrypted = vault
            .attachments()
            .decrypt_buffer(encrypted_cipher, attachment, &encrypted_attachment.contents)
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn passkey_material_is_encrypted_under_the_cipher_key() {
        let client = client().await;
        let vault = client.vault();
        let encrypted = vault.ciphers().encrypt(login_view()).await.unwrap().cipher;
        let view = vault.ciphers().decrypt(encrypted).await.unwrap();
        assert!(view.key.is_some());

        let key_value = B64Url::from(TEST_FIDO_P256_KEY).to_string();
        let passkey = Fido2CredentialFullView {
            credential_id: "a36f3d35-5dae-4d07-8b24-f89e11082090".to_owned(),
            key_type: "public-key".to_owned(),
            key_algorithm: "ECDSA".to_owned(),
            key_curve: "P-256".to_owned(),
            key_value: key_value.clone(),
            rp_id: "vault.safeory.example".to_owned(),
            user_handle: Some("YWJjZA".to_owned()),
            user_name: Some("safeory-user".to_owned()),
            counter: "0".to_owned(),
            rp_name: Some("Safeory Foundation RP".to_owned()),
            user_display_name: Some("Safeory User".to_owned()),
            discoverable: "true".to_owned(),
            creation_date: "2024-06-07T14:12:36.150Z".parse().unwrap(),
        };

        let with_passkey = vault
            .ciphers()
            .set_fido2_credentials(view, vec![passkey])
            .unwrap();
        let stored = with_passkey
            .login
            .as_ref()
            .unwrap()
            .fido2_credentials
            .as_ref()
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert_ne!(
            stored[0].credential_id.to_string(),
            "a36f3d35-5dae-4d07-8b24-f89e11082090"
        );
        assert_ne!(stored[0].key_value.to_string(), key_value);

        let metadata = vault
            .ciphers()
            .decrypt_fido2_credentials(with_passkey.clone())
            .unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(
            metadata[0].credential_id,
            "a36f3d35-5dae-4d07-8b24-f89e11082090"
        );
        assert_eq!(metadata[0].rp_id, "vault.safeory.example");
        assert_eq!(metadata[0].user_handle.as_deref(), Some("YWJjZA"));
        assert_eq!(metadata[0].user_name.as_deref(), Some("safeory-user"));
        assert_eq!(metadata[0].counter, "0");
        assert_eq!(metadata[0].discoverable, "true");

        let recovered_private_key = vault
            .ciphers()
            .decrypt_fido2_private_key(with_passkey)
            .unwrap();
        assert_eq!(recovered_private_key, key_value);
    }

    #[tokio::test]
    async fn safeory_envelope_round_trips_through_server_compatible_blob_cipher() {
        let client = client().await;
        client
            .0
            .internal
            .get_key_store()
            .set_security_state_version(BLOB_SECURITY_VERSION);

        let large_extension_value = "x".repeat(60_000);
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
                "safeory.example.future": { "preserved": true, "version": 2 },
                "vendor.future.a": large_extension_value,
                "vendor.future.b": large_extension_value,
                "vendor.future.c": large_extension_value,
                "vendor.future.d": large_extension_value
            }
        });
        let serialized = serde_json::to_string(&envelope).unwrap();
        assert!(serialized.len() > 230_000);
        assert!(serialized.as_bytes().len() <= 256 * 1024);

        let vault = client.vault();
        let encrypted = vault
            .ciphers()
            .encrypt(safeory_envelope_view(serialized.clone()))
            .await
            .unwrap()
            .cipher;

        let data = encrypted
            .data
            .as_ref()
            .expect("blob cipher must carry opaque Data");
        assert!(data.starts_with('{'));
        assert!(data.len() < 500_000);
        let outer: serde_json::Value = serde_json::from_str(data).unwrap();
        assert_eq!(outer["format_version"], 1);
        assert!(outer["wrapped_cek"].is_string());
        assert!(outer["envelope"].is_string());
        assert!(encrypted.notes.is_none());
        assert!(encrypted.secure_note.is_none());

        let decrypted = vault.ciphers().decrypt(encrypted.clone()).await.unwrap();
        assert_eq!(decrypted.name, "Safeory insurance record");
        assert_eq!(decrypted.notes.as_deref(), Some(serialized.as_str()));
        assert_eq!(
            decrypted.secure_note.as_ref().unwrap().r#type,
            SecureNoteType::Generic
        );
        let restored: serde_json::Value =
            serde_json::from_str(decrypted.notes.as_deref().unwrap()).unwrap();
        assert_eq!(restored["marker"], "safeory.life_record");
        assert_eq!(
            restored["record_id"],
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(
            restored["extensions"]["safeory.example.future"]["version"],
            2
        );
        assert_eq!(
            restored["extensions"]["vendor.future.d"],
            large_extension_value
        );

        let batch = vault
            .ciphers()
            .decrypt_list_full_with_failures(vec![encrypted])
            .await;
        assert!(batch.failures.is_empty());
        assert_eq!(batch.successes.len(), 1);
        assert_eq!(
            batch.successes[0].notes.as_deref(),
            Some(serialized.as_str())
        );
    }

    #[tokio::test]
    async fn server_blob_response_without_legacy_fields_decrypts_and_lists() {
        let client = client().await;
        client
            .0
            .internal
            .get_key_store()
            .set_security_state_version(BLOB_SECURITY_VERSION);
        let vault = client.vault();
        let envelope = serde_json::json!({
            "marker": "safeory.life_record",
            "schema_version": 1,
            "record_id": "11111111-1111-4111-8111-111111111111",
            "record_kind": "insurance",
            "data": { "title": "Family health policy" },
            "links": [],
            "relationships": [],
            "reminders": [],
            "continuity": {
                "legacy_disposition": "private_forever",
                "policy_ref": null
            },
            "extensions": {}
        });
        let serialized = serde_json::to_string(&envelope).unwrap();
        let encrypted = vault
            .ciphers()
            .encrypt(safeory_envelope_view(serialized.clone()))
            .await
            .unwrap()
            .cipher;

        let request: bitwarden_api_api::models::CipherRequestModel =
            encrypted.clone().try_into().unwrap();
        assert_eq!(request.data.as_deref(), encrypted.data.as_deref());
        assert!(request.notes.is_none());
        assert!(request.secure_note.is_none());

        let response = CipherDetailsResponseModel {
            r#type: Some(CipherType::SecureNote.into()),
            data: encrypted.data.clone(),
            key: encrypted.key.as_ref().map(ToString::to_string),
            favorite: Some(encrypted.favorite),
            edit: Some(true),
            view_password: Some(true),
            organization_use_totp: Some(false),
            revision_date: Some("2026-09-21T00:00:01Z".to_owned()),
            creation_date: Some("2026-09-21T00:00:00Z".to_owned()),
            ..Default::default()
        };
        assert!(response.name.is_none());
        assert!(response.notes.is_none());
        assert!(response.secure_note.is_none());

        let synced: bitwarden_vault::Cipher = response.try_into().unwrap();
        let decrypted = vault.ciphers().decrypt(synced.clone()).await.unwrap();
        assert_eq!(decrypted.name, "Safeory insurance record");
        assert_eq!(decrypted.notes.as_deref(), Some(serialized.as_str()));

        let list = vault.ciphers().decrypt_list(vec![synced]).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Safeory insurance record");
        assert_eq!(list[0].r#type, CipherListViewType::SecureNote);
    }

    #[tokio::test]
    async fn one_password_cxf_fixture_imports_through_public_sdk_api() {
        let client = client().await;
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/bitwarden-exporters/resources/1p_export.json");
        let payload = fs::read_to_string(fixture).unwrap();

        let imported = client.exporters().import_cxf(payload).unwrap();
        assert!(imported.len() >= 10);

        let mut views = Vec::with_capacity(imported.len());
        for cipher in imported {
            views.push(client.vault().ciphers().decrypt(cipher).await.unwrap());
        }

        let facebook = views
            .iter()
            .find(|cipher| cipher.name == "Facebook")
            .expect("1Password fixture login should import");
        let facebook_login = facebook.login.as_ref().unwrap();
        assert_eq!(facebook_login.username.as_deref(), Some("johndoe"));
        assert_eq!(
            facebook_login.password.as_deref(),
            Some("securepassword123")
        );
        assert_eq!(
            facebook_login.uris.as_ref().unwrap()[0].uri.as_deref(),
            Some("https://facebook.com")
        );

        let card = views
            .iter()
            .find(|cipher| cipher.name == "Personal Credit Card")
            .expect("1Password fixture card should import");
        let card = card.card.as_ref().unwrap();
        assert_eq!(card.cardholder_name.as_deref(), Some("John doe"));
        assert_eq!(card.number.as_deref(), Some("4111111111111111"));
        assert_eq!(card.exp_month.as_deref(), Some("8"));
        assert_eq!(card.exp_year.as_deref(), Some("2027"));

        let wifi = views
            .iter()
            .find(|cipher| cipher.name == "Home Wifi")
            .expect("1Password fixture Wi-Fi record should import");
        assert_eq!(
            wifi.notes.as_deref(),
            Some("My notes heigfkfdkkcmdwkkfkckekfkjf")
        );
        let fields = wifi.fields.as_ref().unwrap();
        assert!(fields.iter().any(|field| {
            field.name.as_deref() == Some("SSID") && field.value.as_deref() == Some("Home_Network")
        }));
        assert!(fields.iter().any(|field| {
            field.name.as_deref() == Some("Passphrase")
                && field.value.as_deref() == Some("mypassword123")
        }));
    }

    #[tokio::test]
    async fn standard_and_dashlane_cxf_fixtures_import_through_public_sdk_api() {
        let client = client().await;
        let resources = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/bitwarden-exporters/resources");

        // The standard CXF sample is a header containing one or more accounts, while the SDK's
        // public import boundary accepts an account payload. Safeory only unwraps that standard
        // container; every account object is passed unchanged to the SDK importer.
        let standard_payload = fs::read_to_string(resources.join("cxf_example.json")).unwrap();
        let standard_header: serde_json::Value = serde_json::from_str(&standard_payload).unwrap();
        let accounts = standard_header["accounts"].as_array().unwrap();
        assert!(!accounts.is_empty());

        let mut standard_views = Vec::new();
        for account in accounts {
            let imported = client
                .exporters()
                .import_cxf(serde_json::to_string(account).unwrap())
                .unwrap();
            for cipher in imported {
                standard_views.push(client.vault().ciphers().decrypt(cipher).await.unwrap());
            }
        }

        let github = standard_views
            .iter()
            .find(|cipher| cipher.name == "GitHub Login")
            .expect("standard CXF login should import");
        let github_login = github.login.as_ref().unwrap();
        assert_eq!(github_login.username.as_deref(), Some("johndoe"));
        assert_eq!(github_login.password.as_deref(), Some("securepassword123"));
        assert_eq!(
            github_login.uris.as_ref().unwrap()[0].uri.as_deref(),
            Some("https://github.com")
        );
        let github_totp = github_login.totp.as_deref().unwrap();
        assert!(github_totp.starts_with("otpauth://totp/Google:"));
        assert!(github_totp.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(github_totp.contains("issuer=Google"));
        assert!(github_totp.contains("algorithm=SHA256"));

        let dashlane_payload = fs::read_to_string(resources.join("dashlane_export.json")).unwrap();
        let dashlane = client.exporters().import_cxf(dashlane_payload).unwrap();
        let mut dashlane_views = Vec::with_capacity(dashlane.len());
        for cipher in dashlane {
            dashlane_views.push(client.vault().ciphers().decrypt(cipher).await.unwrap());
        }

        let dashlane_login = dashlane_views
            .iter()
            .find(|cipher| cipher.name == "adobe.com")
            .expect("Dashlane CXF login should import")
            .login
            .as_ref()
            .unwrap();
        assert_eq!(
            dashlane_login.username.as_deref(),
            Some("dashlane@dashlane.com")
        );
        assert_eq!(dashlane_login.password.as_deref(), Some("asdfgh"));
        assert_eq!(
            dashlane_login.totp.as_deref(),
            Some("otpauth://totp?secret=JBSWY3DPEHPK3PXP")
        );

        let dashlane_card = dashlane_views
            .iter()
            .find(|cipher| cipher.name == "Dashlane CC")
            .expect("Dashlane CXF card should import")
            .card
            .as_ref()
            .unwrap();
        assert_eq!(
            dashlane_card.cardholder_name.as_deref(),
            Some("Dashlane CC")
        );
        assert_eq!(dashlane_card.number.as_deref(), Some("4111111111111111"));
        assert_eq!(dashlane_card.code.as_deref(), Some("999"));
        assert_eq!(dashlane_card.exp_month.as_deref(), Some("10"));
        assert_eq!(dashlane_card.exp_year.as_deref(), Some("2028"));
    }
}
