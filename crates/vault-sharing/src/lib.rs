#![forbid(unsafe_code)]

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const SHARE_FORMAT_VERSION: u16 = 1;
const SHARE_ALGORITHM: &str = "xchacha20poly1305";
const SHARE_WRAP_INFO: &[u8] = b"safeory:v1:share-wrap";
const PUBLIC_KEY_FINGERPRINT_DOMAIN: &[u8] = b"safeory:v1:public-key-fingerprint";
const SHARE_AAD_DOMAIN: &[u8] = b"safeory:share:v1";
pub const MAX_SHARE_PLAINTEXT_BYTES: usize = 65_536;

#[derive(Error, Debug)]
pub enum SharingError {
    #[error("cryptographic random source failed")]
    Random,
    #[error("unsupported share envelope format")]
    UnsupportedFormat,
    #[error("share envelope is addressed to a different recipient device")]
    WrongRecipient,
    #[error("share envelope sender does not match the expected sender device")]
    WrongSender,
    #[error("share envelope purpose does not match the expected purpose")]
    WrongPurpose,
    #[error("authentication failed or the share envelope was tampered with")]
    Authentication,
    #[error("authenticated encryption failed")]
    Encryption,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("key exchange produced a degenerate shared secret")]
    DegenerateKeyExchange,
    #[error("share envelope plaintext exceeds the supported size limit")]
    PlaintextTooLarge,
    #[error("share envelope is internally inconsistent")]
    InconsistentEnvelope,
    #[error("serialization failed")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SharePurpose {
    ItemKey,
    RecoveryShare,
}

impl SharePurpose {
    #[must_use]
    pub fn as_label(self) -> &'static str {
        match self {
            Self::ItemKey => "item-key:v1",
            Self::RecoveryShare => "recovery-share:v1",
        }
    }
}

/// Long-term asymmetric identity of one device (owner or trusted person).
///
/// The private half stays on the device and is never transmitted. Every
/// share envelope is sealed to a recipient public key, so the synchronizing
/// backend can transport the envelope but can never open it.
pub struct DeviceKeyPair {
    secret: StaticSecret,
    public: [u8; 32],
}

impl DeviceKeyPair {
    pub fn generate() -> Result<Self, SharingError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SharingError::Random)?;
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret);
        Ok(Self {
            secret,
            public: public.to_bytes(),
        })
    }

    #[must_use]
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
    }

    /// 128-bit public-key fingerprint bound into every sealed envelope.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 16] {
        fingerprint(&self.public)
    }

    fn diffie_hellman(
        &self,
        their_public: &PublicKey,
    ) -> Result<Zeroizing<[u8; 32]>, SharingError> {
        let shared = self.secret.diffie_hellman(their_public);
        if !shared.was_contributory() {
            return Err(SharingError::DegenerateKeyExchange);
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(shared.as_bytes());
        Ok(bytes)
    }
}

#[must_use]
pub fn fingerprint(public_key: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(PUBLIC_KEY_FINGERPRINT_DOMAIN);
    hasher.update(public_key);
    let digest = hasher.finalize();
    let mut fingerprint = [0u8; 16];
    fingerprint.copy_from_slice(&digest[..16]);
    fingerprint
}

/// Envelope that transports one shared secret to exactly one recipient device.
///
/// The sender key is ephemeral for every seal, so repeated sharing of the same
/// value produces unlinkable ciphertexts while `sender_public` still binds the
/// sharer's long-term identity for authorization and audit.
#[derive(Clone, Serialize, Deserialize)]
pub struct ShareEnvelopeV1 {
    pub format_version: u16,
    pub algorithm: String,
    pub purpose: String,
    pub sender_public: [u8; 32],
    pub recipient_public: [u8; 32],
    pub recipient_fingerprint: [u8; 16],
    pub ephemeral_public: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Seals `plaintext` to `recipient_public` without ever exposing it to a server.
///
/// `sender_public` is self-asserted inside the authenticated envelope: `open`
/// only checks it against a caller-supplied expectation. Sender authorization
/// (whether this sender may share this item) belongs to the grant-policy
/// layer (`vault-emergency`), not to this transport envelope.
pub fn seal(
    sender_public: &[u8; 32],
    recipient_public: &[u8; 32],
    plaintext: &[u8],
    purpose: SharePurpose,
) -> Result<ShareEnvelopeV1, SharingError> {
    if plaintext.len() > MAX_SHARE_PLAINTEXT_BYTES {
        return Err(SharingError::PlaintextTooLarge);
    }
    let ephemeral = DeviceKeyPair::generate()?;
    let recipient = PublicKey::from(*recipient_public);
    let shared = ephemeral.diffie_hellman(&recipient)?;
    let wrap_key = derive_share_wrap_key(&shared, &ephemeral.public, recipient_public)?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| SharingError::Random)?;

    let recipient_fingerprint = fingerprint(recipient_public);
    let aad = share_aad(
        sender_public,
        recipient_public,
        &recipient_fingerprint,
        &ephemeral.public,
        purpose.as_label(),
    );
    let ciphertext = XChaCha20Poly1305::new((&*wrap_key).into())
        .encrypt(
            nonce_ref(&nonce)?,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| SharingError::Encryption)?;

    Ok(ShareEnvelopeV1 {
        format_version: SHARE_FORMAT_VERSION,
        algorithm: SHARE_ALGORITHM.to_owned(),
        purpose: purpose.as_label().to_owned(),
        sender_public: *sender_public,
        recipient_public: *recipient_public,
        recipient_fingerprint,
        ephemeral_public: ephemeral.public,
        nonce,
        ciphertext,
    })
}

/// Opens an envelope that was sealed for this device by the expected sender.
pub fn open(
    envelope: &ShareEnvelopeV1,
    recipient: &DeviceKeyPair,
    expected_sender_public: &[u8; 32],
    purpose: SharePurpose,
) -> Result<Zeroizing<Vec<u8>>, SharingError> {
    if envelope.format_version != SHARE_FORMAT_VERSION || envelope.algorithm != SHARE_ALGORITHM {
        return Err(SharingError::UnsupportedFormat);
    }
    if envelope.purpose != purpose.as_label() {
        return Err(SharingError::WrongPurpose);
    }
    if envelope.recipient_public != recipient.public {
        return Err(SharingError::WrongRecipient);
    }
    if envelope.recipient_fingerprint != fingerprint(&envelope.recipient_public)
        || envelope.recipient_fingerprint != recipient.fingerprint()
    {
        return Err(SharingError::InconsistentEnvelope);
    }
    if envelope.sender_public != *expected_sender_public {
        return Err(SharingError::WrongSender);
    }

    let ephemeral = PublicKey::from(envelope.ephemeral_public);
    let shared = recipient.diffie_hellman(&ephemeral)?;
    let wrap_key = derive_share_wrap_key(
        &shared,
        &envelope.ephemeral_public,
        &envelope.recipient_public,
    )?;
    let aad = share_aad(
        &envelope.sender_public,
        &envelope.recipient_public,
        &envelope.recipient_fingerprint,
        &envelope.ephemeral_public,
        purpose.as_label(),
    );
    let plaintext = XChaCha20Poly1305::new((&*wrap_key).into())
        .decrypt(
            nonce_ref(&envelope.nonce)?,
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| SharingError::Authentication)?;
    Ok(Zeroizing::new(plaintext))
}

fn derive_share_wrap_key(
    shared: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, SharingError> {
    let mut salt = Sha256::new();
    salt.update(ephemeral_public);
    salt.update(recipient_public);
    let salt = salt.finalize();
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut output = Zeroizing::new([0u8; 32]);
    hk.expand(SHARE_WRAP_INFO, output.as_mut())
        .map_err(|_| SharingError::KeyDerivation)?;
    Ok(output)
}

fn share_aad(
    sender_public: &[u8; 32],
    recipient_public: &[u8; 32],
    recipient_fingerprint: &[u8; 16],
    ephemeral_public: &[u8; 32],
    purpose: &str,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SHARE_AAD_DOMAIN.len() + purpose.len() + 112);
    aad.extend_from_slice(SHARE_AAD_DOMAIN);
    aad.extend_from_slice(purpose.as_bytes());
    aad.extend_from_slice(sender_public);
    aad.extend_from_slice(recipient_public);
    aad.extend_from_slice(recipient_fingerprint);
    aad.extend_from_slice(ephemeral_public);
    aad
}

fn nonce_ref(nonce: &[u8; 24]) -> Result<&XNonce, SharingError> {
    nonce
        .as_slice()
        .try_into()
        .map_err(|_| SharingError::InconsistentEnvelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_envelope_round_trips_to_expected_recipient() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");
        let item_key = [0x42u8; 32];

        let envelope = seal(
            &sender.public,
            &recipient.public_bytes(),
            &item_key,
            SharePurpose::ItemKey,
        )
        .expect("seal");
        let opened =
            open(&envelope, &recipient, &sender.public, SharePurpose::ItemKey).expect("open");

        assert_eq!(opened.as_slice(), item_key.as_slice());
    }

    #[test]
    fn another_recipient_cannot_open_the_envelope() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");
        let outsider = DeviceKeyPair::generate().expect("outsider key pair");

        let envelope = seal(
            &sender.public,
            &recipient.public_bytes(),
            &[7u8; 32],
            SharePurpose::ItemKey,
        )
        .expect("seal");

        assert!(matches!(
            open(&envelope, &outsider, &sender.public, SharePurpose::ItemKey),
            Err(SharingError::WrongRecipient)
        ));
    }

    #[test]
    fn wrong_expected_sender_is_rejected() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let impostor = DeviceKeyPair::generate().expect("impostor key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");

        let envelope = seal(
            &sender.public,
            &recipient.public_bytes(),
            &[7u8; 32],
            SharePurpose::ItemKey,
        )
        .expect("seal");

        assert!(matches!(
            open(
                &envelope,
                &recipient,
                &impostor.public,
                SharePurpose::ItemKey
            ),
            Err(SharingError::WrongSender)
        ));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");
        let mut envelope = seal(
            &sender.public,
            &recipient.public_bytes(),
            &[9u8; 32],
            SharePurpose::ItemKey,
        )
        .expect("seal");
        envelope.ciphertext[0] ^= 0x01;

        assert!(matches!(
            open(&envelope, &recipient, &sender.public, SharePurpose::ItemKey),
            Err(SharingError::Authentication)
        ));
    }

    #[test]
    fn swapped_purpose_is_rejected() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");

        let envelope = seal(
            &sender.public,
            &recipient.public_bytes(),
            &[1u8; 32],
            SharePurpose::ItemKey,
        )
        .expect("seal");

        assert!(matches!(
            open(
                &envelope,
                &recipient,
                &sender.public,
                SharePurpose::RecoveryShare
            ),
            Err(SharingError::WrongPurpose)
        ));
    }

    #[test]
    fn tampered_recipient_fingerprint_is_rejected() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");
        let mut envelope = seal(
            &sender.public,
            &recipient.public_bytes(),
            &[3u8; 32],
            SharePurpose::ItemKey,
        )
        .expect("seal");
        envelope.recipient_fingerprint[0] ^= 0xFF;

        assert!(matches!(
            open(&envelope, &recipient, &sender.public, SharePurpose::ItemKey),
            Err(SharingError::InconsistentEnvelope)
        ));
    }

    #[test]
    fn degenerate_recipient_public_key_is_rejected() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let zero_public = [0u8; 32];

        assert!(matches!(
            seal(
                &sender.public,
                &zero_public,
                &[5u8; 32],
                SharePurpose::ItemKey
            ),
            Err(SharingError::DegenerateKeyExchange)
        ));
    }

    #[test]
    fn oversized_plaintext_is_rejected_before_encryption() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");
        let oversized = vec![0u8; MAX_SHARE_PLAINTEXT_BYTES + 1];

        assert!(matches!(
            seal(
                &sender.public,
                &recipient.public_bytes(),
                &oversized,
                SharePurpose::ItemKey
            ),
            Err(SharingError::PlaintextTooLarge)
        ));
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral_key() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");

        let first = seal(
            &sender.public,
            &recipient.public_bytes(),
            &[8u8; 32],
            SharePurpose::ItemKey,
        )
        .expect("first seal");
        let second = seal(
            &sender.public,
            &recipient.public_bytes(),
            &[8u8; 32],
            SharePurpose::ItemKey,
        )
        .expect("second seal");

        assert_ne!(first.ephemeral_public, second.ephemeral_public);
        assert_ne!(first.ciphertext, second.ciphertext);
    }
}
