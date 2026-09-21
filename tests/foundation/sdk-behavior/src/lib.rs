pub mod fixture_support {
    use bitwarden_core::{Client, client::test_accounts::test_bitwarden_com_account};
    use bitwarden_pm::PasswordManagerClient;
    use bitwarden_vault::{
        CipherRepromptType, CipherType, CipherView, SecureNoteType, SecureNoteView,
    };

    pub async fn client() -> PasswordManagerClient {
        PasswordManagerClient(Client::init_test_account(test_bitwarden_com_account()).await)
    }

    pub fn safeory_envelope_view(notes: String) -> CipherView {
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
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use std::{fs, path::Path};

    use bitwarden_api_api::models::CipherDetailsResponseModel;
    use bitwarden_core::{
        Client, OrganizationId,
        client::test_accounts::test_bitwarden_com_account,
        key_management::{
            BLOB_SECURITY_VERSION, KeySlotIds, SymmetricKeySlotId, create_test_crypto_with_user_key,
        },
    };
    use bitwarden_crypto::{IdentifyKey, KeyStore, SymmetricCryptoKey};
    use bitwarden_encoding::B64Url;
    use bitwarden_exporters::ExportFormat;
    use bitwarden_pm::PasswordManagerClient;
    use bitwarden_vault::{
        AttachmentView, CipherListViewType, CipherRepromptType, CipherType, CipherView,
        Fido2CredentialFullView, FolderView, LoginUriView, LoginView, SecureNoteType,
        SecureNoteView, UriMatchType, generate_totp,
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

    fn space_id(index: u32) -> OrganizationId {
        format!("00000000-0000-4000-8000-{index:012x}")
            .parse()
            .unwrap()
    }

    #[allow(deprecated)]
    fn install_space_key(
        store: &KeyStore<KeySlotIds>,
        space_id: OrganizationId,
        key: SymmetricCryptoKey,
    ) {
        store
            .context_mut()
            .set_symmetric_key(SymmetricKeySlotId::Organization(space_id), key)
            .unwrap();
    }

    fn encrypt_space_item(
        store: &KeyStore<KeySlotIds>,
        space_id: Option<OrganizationId>,
        name: &str,
    ) -> bitwarden_vault::Cipher {
        let mut view = safeory_envelope_view(format!("space payload for {name}"));
        view.name = name.to_owned();
        view.organization_id = space_id;
        let wrapping_key = view.key_identifier();
        let mut ctx = store.context();
        view.generate_cipher_key(&mut ctx, wrapping_key).unwrap();
        drop(ctx);
        store.encrypt(view).unwrap()
    }

    #[test]
    fn independently_keyed_spaces_enforce_member_and_move_boundaries() {
        let alice_user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let bob_user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let carol_user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();

        let alice = create_test_crypto_with_user_key(alice_user_key.clone());
        let bob = create_test_crypto_with_user_key(bob_user_key.clone());
        let carol = create_test_crypto_with_user_key(carol_user_key.clone());

        let family_space = space_id(1);
        let advisor_space = space_id(2);
        let travel_space = space_id(3);

        let family_key_v1 = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let advisor_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let travel_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();

        install_space_key(&alice, family_space, family_key_v1.clone());
        install_space_key(&alice, advisor_space, advisor_key.clone());
        install_space_key(&alice, travel_space, travel_key.clone());
        install_space_key(&bob, family_space, family_key_v1.clone());
        install_space_key(&carol, advisor_space, advisor_key.clone());

        let personal = encrypt_space_item(&alice, None, "Alice personal");
        let family = encrypt_space_item(&alice, Some(family_space), "Family shared");
        let advisor = encrypt_space_item(&alice, Some(advisor_space), "Advisor shared");
        let travel = encrypt_space_item(&alice, Some(travel_space), "Alice travel");

        // Personal + Family + Advisor + Travel + 28 additional organization-backed spaces = 32.
        let mut all_space_items = vec![
            personal.clone(),
            family.clone(),
            advisor.clone(),
            travel.clone(),
        ];
        for index in 4..=31 {
            let id = space_id(index);
            install_space_key(&alice, id, SymmetricCryptoKey::make_aes256_cbc_hmac_key());
            all_space_items.push(encrypt_space_item(
                &alice,
                Some(id),
                &format!("Additional space {index}"),
            ));
        }
        assert_eq!(all_space_items.len(), 32);
        for cipher in &all_space_items {
            let view: CipherView = alice.decrypt(cipher).unwrap();
            assert!(!view.name.is_empty());
        }

        let bob_family: CipherView = bob.decrypt(&family).unwrap();
        assert_eq!(bob_family.name, "Family shared");
        let carol_advisor: CipherView = carol.decrypt(&advisor).unwrap();
        assert_eq!(carol_advisor.name, "Advisor shared");

        let bob_advisor: Result<CipherView, _> = bob.decrypt(&advisor);
        assert!(bob_advisor.is_err());
        let carol_family: Result<CipherView, _> = carol.decrypt(&family);
        assert!(carol_family.is_err());
        let bob_travel: Result<CipherView, _> = bob.decrypt(&travel);
        assert!(bob_travel.is_err());
        let carol_travel: Result<CipherView, _> = carol.decrypt(&travel);
        assert!(carol_travel.is_err());

        // Household/Family organization access alone does not grant Alice's Personal user key.
        let bob_personal: Result<CipherView, _> = bob.decrypt(&personal);
        assert!(bob_personal.is_err());

        // Folder membership is a navigation concern, not a Space key domain.
        let folder = FolderView {
            id: None,
            name: "Family navigation".to_owned(),
            revision_date: "2026-09-21T00:00:00Z".parse().unwrap(),
        };
        assert_eq!(folder.key_identifier(), SymmetricKeySlotId::User);
        let mut family_key_probe = safeory_envelope_view("family key probe".to_owned());
        family_key_probe.organization_id = Some(family_space);
        assert_eq!(
            family_key_probe.key_identifier(),
            SymmetricKeySlotId::Organization(family_space)
        );

        // Relabeling ciphertext as another Space does not make it decryptable there.
        let mut copied_to_advisor = family.clone();
        copied_to_advisor.organization_id = Some(advisor_space);
        let copied_result: Result<CipherView, _> = alice.decrypt(&copied_to_advisor);
        assert!(copied_result.is_err());

        // Removing Bob means a context with the same Bob user key but no Family key cannot
        // decrypt either existing or future Family Space records.
        let bob_after_removal = create_test_crypto_with_user_key(bob_user_key);
        let removed_existing: Result<CipherView, _> = bob_after_removal.decrypt(&family);
        assert!(removed_existing.is_err());

        // Rotating the Family Space key protects future writes from a holder of the old key.
        let family_key_v2 = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        install_space_key(&alice, family_space, family_key_v2);
        let family_after_rotation =
            encrypt_space_item(&alice, Some(family_space), "Family after rotation");
        let alice_future: CipherView = alice.decrypt(&family_after_rotation).unwrap();
        assert_eq!(alice_future.name, "Family after rotation");
        let bob_old_key: Result<CipherView, _> = bob.decrypt(&family_after_rotation);
        assert!(bob_old_key.is_err());
        let bob_removed_future: Result<CipherView, _> =
            bob_after_removal.decrypt(&family_after_rotation);
        assert!(bob_removed_future.is_err());

        // Moving a record between Spaces rewraps its per-record cipher key without exposing
        // plaintext or re-encrypting the payload fields.
        let mut moved_view: CipherView = alice.decrypt(&advisor).unwrap();
        let wrapped_key_before = moved_view.key.as_ref().unwrap().to_string();
        moved_view
            .move_to_organization(&mut alice.context(), travel_space)
            .unwrap();
        assert_eq!(moved_view.organization_id, Some(travel_space));
        assert_ne!(
            wrapped_key_before,
            moved_view.key.as_ref().unwrap().to_string()
        );
        let moved: bitwarden_vault::Cipher = alice.encrypt(moved_view).unwrap();
        let moved_decrypted: CipherView = alice.decrypt(&moved).unwrap();
        assert_eq!(moved_decrypted.name, "Advisor shared");
        let carol_after_move: Result<CipherView, _> = carol.decrypt(&moved);
        assert!(carol_after_move.is_err());
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

    #[test]
    fn safeory_spaces_use_independent_key_domains_and_rewrap_on_move() {
        const SPACE_TARGET: usize = 32;
        const KEY_MATERIAL_BUDGET_BYTES: usize = 2 * 1024;
        const UNLOCK_LIKE_DECRYPT_BUDGET: Duration = Duration::from_secs(2);

        let alice_user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let alice_user_key_bytes = alice_user_key.to_encoded().as_ref().len();
        let bob_user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let carol_user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();

        let alice = create_test_crypto_with_user_key(alice_user_key);
        let bob = create_test_crypto_with_user_key(bob_user_key);
        let carol = create_test_crypto_with_user_key(carol_user_key);

        // Personal is the user-key domain. Thirty-one additional organization-key domains bring
        // the proof to 32 total Safeory Spaces without treating folders/collections as crypto.
        let space_ids: Vec<OrganizationId> = (1..=31).map(space_id).collect();
        let space_keys: Vec<SymmetricCryptoKey> = (0..31)
            .map(|_| SymmetricCryptoKey::make_aes256_cbc_hmac_key())
            .collect();
        let retained_key_material_bytes = alice_user_key_bytes
            + space_keys
                .iter()
                .map(|key| key.to_encoded().as_ref().len())
                .sum::<usize>();
        assert!(
            retained_key_material_bytes <= KEY_MATERIAL_BUDGET_BYTES,
            "32-Space key material uses {retained_key_material_bytes} bytes, budget is {KEY_MATERIAL_BUDGET_BYTES}"
        );
        eprintln!(
            "32-Space key material: {retained_key_material_bytes} bytes / {KEY_MATERIAL_BUDGET_BYTES} byte budget"
        );
        for (id, key) in space_ids.iter().zip(space_keys.iter()) {
            install_space_key(&alice, *id, key.clone());
        }

        let family_id = space_ids[0];
        let advisor_id = space_ids[1];
        let travel_id = space_ids[2];
        install_space_key(&bob, family_id, space_keys[0].clone());
        install_space_key(&carol, advisor_id, space_keys[1].clone());

        // Metadata containers do not establish the cryptographic boundary. Folders always use the
        // user's key; a cipher's key domain is selected by organization_id only.
        let folder = FolderView {
            id: None,
            name: "Family folder".to_owned(),
            revision_date: "2026-09-21T00:00:00Z".parse().unwrap(),
        };
        assert_eq!(folder.key_identifier(), SymmetricKeySlotId::User);
        let mut metadata_probe = safeory_envelope_view("metadata probe".to_owned());
        metadata_probe.organization_id = Some(family_id);
        let family_slot = metadata_probe.key_identifier();
        metadata_probe.folder_id = Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".parse().unwrap());
        metadata_probe.collection_ids = vec![
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".parse().unwrap(),
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc".parse().unwrap(),
        ];
        assert_eq!(metadata_probe.key_identifier(), family_slot);
        assert_eq!(family_slot, SymmetricKeySlotId::Organization(family_id));

        let personal = encrypt_space_item(&alice, None, "Alice Personal");
        let family = encrypt_space_item(&alice, Some(family_id), "Alice + Bob Family");
        let advisor = encrypt_space_item(&alice, Some(advisor_id), "Alice + Carol Advisor");
        let travel = encrypt_space_item(&alice, Some(travel_id), "Alice Travel");

        let personal_for_alice: CipherView = alice.decrypt(&personal).unwrap();
        assert_eq!(personal_for_alice.name, "Alice Personal");
        let personal_for_bob: Result<CipherView, _> = bob.decrypt(&personal);
        assert!(personal_for_bob.is_err());

        let family_for_bob: CipherView = bob.decrypt(&family).unwrap();
        assert_eq!(family_for_bob.name, "Alice + Bob Family");
        let family_for_carol: Result<CipherView, _> = carol.decrypt(&family);
        assert!(family_for_carol.is_err());

        let advisor_for_carol: CipherView = carol.decrypt(&advisor).unwrap();
        assert_eq!(advisor_for_carol.name, "Alice + Carol Advisor");
        let advisor_for_bob: Result<CipherView, _> = bob.decrypt(&advisor);
        assert!(advisor_for_bob.is_err());
        let travel_for_bob: Result<CipherView, _> = bob.decrypt(&travel);
        let travel_for_carol: Result<CipherView, _> = carol.decrypt(&travel);
        assert!(travel_for_bob.is_err());
        assert!(travel_for_carol.is_err());

        // Copying authenticated ciphertext into another Space context cannot make it decryptable,
        // even for Alice who possesses both Space keys: the wrapped per-cipher key authenticates
        // against Family, not Advisor.
        let mut substituted = family.clone();
        substituted.organization_id = Some(advisor_id);
        let substituted_for_alice: Result<CipherView, _> = alice.decrypt(&substituted);
        assert!(substituted_for_alice.is_err());

        // A move is different from metadata substitution: decrypt, explicitly rewrap the cipher key
        // under Advisor, then re-encrypt. Carol can open the moved item and Family-only Bob cannot.
        let mut moved_view: CipherView = alice.decrypt(&family).unwrap();
        {
            let mut ctx = alice.context();
            moved_view
                .move_to_organization(&mut ctx, advisor_id)
                .unwrap();
        }
        let moved_to_advisor = alice.encrypt(moved_view).unwrap();
        let moved_for_carol: CipherView = carol.decrypt(&moved_to_advisor).unwrap();
        assert_eq!(moved_for_carol.name, "Alice + Bob Family");
        let moved_for_bob: Result<CipherView, _> = bob.decrypt(&moved_to_advisor);
        assert!(moved_for_bob.is_err());

        // Rotate Family. Alice receives K2; Bob keeps only the historical K1. Future Family writes
        // authenticate under K2 and are therefore unreadable to the removed member.
        let family_key_v2 = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        install_space_key(&alice, family_id, family_key_v2);
        let family_after_rotation =
            encrypt_space_item(&alice, Some(family_id), "Family after Bob removal");
        let family_after_rotation_for_alice: CipherView =
            alice.decrypt(&family_after_rotation).unwrap();
        assert_eq!(
            family_after_rotation_for_alice.name,
            "Family after Bob removal"
        );
        let future_family_for_bob: Result<CipherView, _> = bob.decrypt(&family_after_rotation);
        assert!(future_family_for_bob.is_err());
        // Historical ciphertext remains decryptable to a member who retained the historical key;
        // rotation is intentionally a future-write boundary, not retroactive key erasure.
        let historical_family_for_bob: CipherView = bob.decrypt(&family).unwrap();
        assert_eq!(historical_family_for_bob.name, "Alice + Bob Family");

        // Exercise all 32 domains (Personal + 31 independently keyed Spaces) in one unlock-like
        // context. Every organization ciphertext decrypts only because Alice has that exact slot.
        let mut all_space_items = Vec::with_capacity(SPACE_TARGET);
        all_space_items.push(personal);
        for (index, id) in space_ids.iter().enumerate() {
            all_space_items.push(encrypt_space_item(
                &alice,
                Some(*id),
                &format!("Space {:02}", index + 1),
            ));
        }
        assert_eq!(all_space_items.len(), SPACE_TARGET);
        let unlock_like_started = Instant::now();
        for cipher in &all_space_items {
            let decrypted: CipherView = alice.decrypt(cipher).unwrap();
            assert!(!decrypted.name.is_empty());
        }
        let unlock_like_elapsed = unlock_like_started.elapsed();
        assert!(
            unlock_like_elapsed <= UNLOCK_LIKE_DECRYPT_BUDGET,
            "32-Space decrypt sweep took {unlock_like_elapsed:?}, budget is {UNLOCK_LIKE_DECRYPT_BUDGET:?}"
        );
        eprintln!(
            "32-Space decrypt sweep: {unlock_like_elapsed:?} / {UNLOCK_LIKE_DECRYPT_BUDGET:?} budget"
        );
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
    async fn tracked_safeory_carrier_fixture_decrypts_to_representative_envelope() {
        for (file, expected_variant, expected_title, expected_renewal) in [
            (
                "safeory-insurance-carrier.json",
                "initial",
                "Family health policy",
                "2027-01-15",
            ),
            (
                "safeory-insurance-carrier-updated.json",
                "updated",
                "Family health policy renewed",
                "2028-01-15",
            ),
        ] {
            let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures")
                .join(file);
            let fixture: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(fixture_path).unwrap()).unwrap();
            assert_eq!(fixture["fixture_version"], 1);
            assert_eq!(fixture["fixture_variant"], expected_variant);
            assert_eq!(fixture["record_id"], "11111111-1111-4111-8111-111111111111");

            let response = CipherDetailsResponseModel {
                id: Some("11111111-1111-4111-8111-111111111111".parse().unwrap()),
                r#type: Some(CipherType::SecureNote.into()),
                data: Some(fixture["data"].as_str().unwrap().to_owned()),
                key: Some(fixture["key"].as_str().unwrap().to_owned()),
                favorite: Some(false),
                edit: Some(true),
                view_password: Some(true),
                organization_use_totp: Some(false),
                revision_date: Some("2026-09-21T00:00:01Z".to_owned()),
                creation_date: Some("2026-09-21T00:00:00Z".to_owned()),
                ..Default::default()
            };
            let cipher: bitwarden_vault::Cipher = response.try_into().unwrap();
            let decrypted = client()
                .await
                .vault()
                .ciphers()
                .decrypt(cipher)
                .await
                .unwrap();
            assert_eq!(decrypted.name, "Safeory insurance record");
            assert_eq!(decrypted.notes.as_deref(), fixture["envelope"].as_str());
            let envelope: serde_json::Value =
                serde_json::from_str(decrypted.notes.as_deref().unwrap()).unwrap();
            assert_eq!(envelope["marker"], "safeory.life_record");
            assert_eq!(envelope["record_kind"], "insurance");
            assert_eq!(envelope["data"]["title"], expected_title);
            assert_eq!(envelope["data"]["renewal"], expected_renewal);
            assert_eq!(
                envelope["extensions"]["safeory.example.future"]["preserved"],
                true
            );
        }
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
            id: encrypted.id.map(Into::into),
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

        let list = vault
            .ciphers()
            .decrypt_list(vec![synced.clone()])
            .await
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Safeory insurance record");
        assert_eq!(list[0].r#type, CipherListViewType::SecureNote);

        let mut corrupted = synced.clone();
        corrupted.data = Some("{\"format_version\":1}".to_owned());
        assert!(
            client
                .exporters()
                .export_vault(vec![], vec![corrupted], ExportFormat::Json)
                .await
                .is_err(),
            "corrupted carrier must fail export instead of being silently omitted"
        );

        let exported = client
            .exporters()
            .export_vault(vec![], vec![synced], ExportFormat::Json)
            .await
            .unwrap();
        let exported: serde_json::Value = serde_json::from_str(&exported).unwrap();
        let exported_item = &exported["items"][0];
        assert_eq!(exported_item["name"], "Safeory insurance record");
        let exported_notes = exported_item["notes"].as_str().unwrap();
        let exported_envelope: serde_json::Value = serde_json::from_str(exported_notes).unwrap();
        assert_eq!(exported_envelope["marker"], "safeory.life_record");
        assert_eq!(
            exported_envelope["record_id"],
            "11111111-1111-4111-8111-111111111111"
        );

        let reimported = vault
            .ciphers()
            .encrypt(safeory_envelope_view(exported_notes.to_owned()))
            .await
            .unwrap()
            .cipher;
        assert!(
            reimported
                .data
                .as_deref()
                .is_some_and(|data| data.starts_with('{'))
        );
        assert!(reimported.notes.is_none());
        let reimported_view = vault.ciphers().decrypt(reimported).await.unwrap();
        assert_eq!(reimported_view.notes.as_deref(), Some(exported_notes));
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
