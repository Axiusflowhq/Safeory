#[cfg(test)]
mod tests {
    use bitwarden_core::{
        OrganizationId,
        key_management::{KeySlotIds, SymmetricKeySlotId, create_test_crypto_with_user_key},
    };
    use bitwarden_crypto::{BitwardenLegacyKeyBytes, IdentifyKey, KeyStore, SymmetricCryptoKey};
    use bitwarden_vault::{
        Cipher, CipherRepromptType, CipherType, CipherView, SecureNoteType, SecureNoteView,
        with_record_key_for_continuity_proof, with_space_key_for_continuity_proof,
    };
    use sha2::{Digest, Sha256};
    use vault_sharing::{DeviceKeyPair, ShareEnvelopeV2, SharePurpose, open, seal};

    fn space_id() -> OrganizationId {
        "77777777-7777-4777-8777-777777777777".parse().unwrap()
    }

    #[allow(deprecated)]
    fn install_space_key(
        store: &KeyStore<KeySlotIds>,
        organization_id: OrganizationId,
        key: SymmetricCryptoKey,
    ) {
        store
            .context_mut()
            .set_symmetric_key(SymmetricKeySlotId::Organization(organization_id), key)
            .unwrap();
    }

    fn secure_note(name: &str, organization_id: Option<OrganizationId>) -> CipherView {
        let now = "2026-09-21T00:00:00Z".parse().unwrap();
        CipherView {
            id: Some("88888888-8888-4888-8888-888888888888".parse().unwrap()),
            organization_id,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: name.to_owned(),
            notes: Some("selected continuity proof body".to_owned()),
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
            creation_date: now,
            deleted_date: None,
            revision_date: now,
            archived_date: None,
        }
    }

    fn encrypt_with_record_key(store: &KeyStore<KeySlotIds>, mut view: CipherView) -> Cipher {
        let wrapping_key = view.key_identifier();
        view.generate_cipher_key(&mut store.context(), wrapping_key)
            .unwrap();
        store.encrypt(view).unwrap()
    }

    fn capsule_digest(capsule: &ShareEnvelopeV2) -> String {
        let encoded = serde_json::to_vec(capsule).unwrap();
        Sha256::digest(encoded)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn symmetric_key_from_capsule_bytes(bytes: &[u8]) -> SymmetricCryptoKey {
        SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(bytes)).unwrap()
    }

    #[test]
    fn selected_record_and_space_keys_release_as_opaque_trustee_capsules() {
        let owner =
            create_test_crypto_with_user_key(SymmetricCryptoKey::make_aes256_cbc_hmac_key());
        let family_space = space_id();
        install_space_key(
            &owner,
            family_space,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let personal_record =
            encrypt_with_record_key(&owner, secure_note("Personal continuity record", None));
        let family_record = encrypt_with_record_key(
            &owner,
            secure_note("Family continuity record", Some(family_space)),
        );

        let owner_device = DeviceKeyPair::generate().unwrap();
        let trustee_device = DeviceKeyPair::generate().unwrap();
        let outsider_device = DeviceKeyPair::generate().unwrap();

        let (record_capsule, record_key_digest) =
            with_record_key_for_continuity_proof(&personal_record, &owner, |selected_key| {
                let digest = Sha256::digest(selected_key).to_vec();
                let capsule = seal(
                    &owner_device,
                    &trustee_device.public_bytes(),
                    selected_key,
                    SharePurpose::ItemKey,
                )
                .unwrap();
                (capsule, digest)
            })
            .unwrap();

        let record_wire = serde_json::to_value(&record_capsule).unwrap();
        assert_eq!(record_wire["purpose"], "item-key:v1");
        assert!(record_wire.get("ciphertext").is_some());
        assert!(record_wire.get("key").is_none());
        assert!(record_wire.get("plaintext").is_none());
        assert!(
            open(
                &record_capsule,
                &outsider_device,
                &owner_device.public_bytes(),
                SharePurpose::ItemKey,
            )
            .is_err()
        );

        let opened_record_key = open(
            &record_capsule,
            &trustee_device,
            &owner_device.public_bytes(),
            SharePurpose::ItemKey,
        )
        .unwrap();
        assert_eq!(
            Sha256::digest(opened_record_key.as_slice()).as_slice(),
            record_key_digest
        );

        // A separate trustee foundation context can use only the released per-record key.
        let trustee_record_store =
            create_test_crypto_with_user_key(symmetric_key_from_capsule_bytes(&opened_record_key));
        let mut trustee_record = personal_record.clone();
        trustee_record.key = None;
        trustee_record.organization_id = None;
        let trustee_view: CipherView = trustee_record_store.decrypt(&trustee_record).unwrap();
        assert_eq!(trustee_view.name, "Personal continuity record");

        let (space_capsule, space_key_digest) =
            with_space_key_for_continuity_proof(family_space, &owner, |selected_key| {
                let digest = Sha256::digest(selected_key).to_vec();
                let capsule = seal(
                    &owner_device,
                    &trustee_device.public_bytes(),
                    selected_key,
                    SharePurpose::SpaceKey,
                )
                .unwrap();
                (capsule, digest)
            })
            .unwrap();

        assert!(
            open(
                &space_capsule,
                &outsider_device,
                &owner_device.public_bytes(),
                SharePurpose::SpaceKey,
            )
            .is_err()
        );
        let opened_space_key = open(
            &space_capsule,
            &trustee_device,
            &owner_device.public_bytes(),
            SharePurpose::SpaceKey,
        )
        .unwrap();
        assert_eq!(
            Sha256::digest(opened_space_key.as_slice()).as_slice(),
            space_key_digest
        );

        // The trustee receives only this Space key, not the owner's user key.
        let trustee_space_store =
            create_test_crypto_with_user_key(SymmetricCryptoKey::make_aes256_cbc_hmac_key());
        install_space_key(
            &trustee_space_store,
            family_space,
            symmetric_key_from_capsule_bytes(&opened_space_key),
        );
        let trustee_family_view: CipherView = trustee_space_store.decrypt(&family_record).unwrap();
        assert_eq!(trustee_family_view.name, "Family continuity record");
        let personal_from_space_only: Result<CipherView, _> =
            trustee_space_store.decrypt(&personal_record);
        assert!(personal_from_space_only.is_err());

        // The only durable/transportable artifact produced by this selected-key path is the
        // opaque authenticated capsule. Timed-release policy operates on a hash reference to
        // this serialized object in vault-emergency's separate state-machine test.
        assert_eq!(capsule_digest(&record_capsule).len(), 64);
    }
}
