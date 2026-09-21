#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use bitwarden_core::{Client, client::test_accounts::test_bitwarden_com_account};
    use bitwarden_exporters::ExportFormat;
    use bitwarden_pm::PasswordManagerClient;
    use bitwarden_vault::{
        AttachmentView, CipherRepromptType, CipherType, CipherView, LoginUriView, LoginView,
        UriMatchType, generate_totp,
    };

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
}
