#![forbid(unsafe_code)]

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const SHARE_FORMAT_VERSION: u16 = 2;
const SHARE_ALGORITHM: &str = "x25519-hkdf-sha256+xchacha20poly1305";
const SHARE_WRAP_INFO: &[u8] = b"safeory:v2:share-wrap";
const PUBLIC_KEY_FINGERPRINT_DOMAIN: &[u8] = b"safeory:v1:public-key-fingerprint";
const SHARE_AAD_DOMAIN: &[u8] = b"safeory:share:v2";
const PAIRING_FORMAT_VERSION: u16 = 1;
const PAIRING_CHALLENGE_WRAP_INFO: &[u8] = b"safeory:v1:trusted-device-pairing-challenge-wrap";
const PAIRING_CHALLENGE_AAD_DOMAIN: &[u8] = b"safeory:trusted-device-pairing-challenge:v1";
const PAIRING_PROOF_DOMAIN: &[u8] = b"safeory:trusted-device-pairing:v1\0";
pub const MAX_SHARE_PLAINTEXT_BYTES: usize = 65_536;

#[derive(Error, Debug)]
pub enum SharingError {
    #[error("cryptographic random source failed")]
    Random,
    #[error("unsupported share envelope format")]
    UnsupportedFormat,
    #[error("share envelope is addressed to a different recipient device")]
    WrongRecipient,
    #[error("share envelope claimed sender does not match the expected claimed sender device")]
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
    #[error("trusted-device pairing package is internally inconsistent")]
    InvalidPairingContext,
    #[error("trusted-device pairing signing key is invalid or weak")]
    InvalidSigningKey,
    #[error("trusted-device pairing proof signature is invalid")]
    InvalidPairingSignature,
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

/// Dedicated Ed25519 key used only for device authentication/signing.
///
/// This key is deliberately distinct from [`DeviceKeyPair`], whose X25519 key
/// is for recipient encryption/key agreement and must not be treated as a
/// signing identity.
pub struct DeviceSigningKeyPair {
    signing: SigningKey,
}

impl DeviceSigningKeyPair {
    pub fn generate() -> Result<Self, SharingError> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SharingError::Random)?;
        Ok(Self {
            signing: SigningKey::from_bytes(&bytes),
        })
    }

    #[must_use]
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
}

/// Public challenge package sent by the vault owner to an unpaired recipient
/// device. The random challenge itself is encrypted to the device's X25519 key,
/// so producing a valid response proves possession of that recipient key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingChallengeV1 {
    pub format_version: u16,
    pub request_id: Uuid,
    pub principal_id: Uuid,
    pub device_id: Uuid,
    pub encryption_public: [u8; 32],
    pub verifier_ephemeral_public: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Verifier-only pending state. This never needs to leave the owner device and
/// is intentionally not serializable; dropping it cancels the one-shot pairing.
pub struct PairingVerifierState {
    request_id: Uuid,
    principal_id: Uuid,
    device_id: Uuid,
    encryption_public: [u8; 32],
    verifier_ephemeral_public: [u8; 32],
    challenge: Zeroizing<[u8; 32]>,
}

/// Recipient response proving Ed25519 signing-key possession and, because the
/// signed challenge was encrypted to `encryption_public`, possession of the
/// X25519 recipient private key at pairing time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingProofV1 {
    pub format_version: u16,
    pub request_id: Uuid,
    pub principal_id: Uuid,
    pub device_id: Uuid,
    pub signing_public: [u8; 32],
    pub encryption_public: [u8; 32],
    pub verifier_ephemeral_public: [u8; 32],
    pub challenge: [u8; 32],
    pub signature: Vec<u8>,
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

/// Create a one-shot pairing challenge for one existing unpaired trusted-device
/// slot. The returned verifier state must remain on the owner device and must be
/// consumed after one completion attempt.
pub fn create_pairing_challenge(
    principal_id: Uuid,
    device_id: Uuid,
    encryption_public: &[u8; 32],
) -> Result<(PairingChallengeV1, PairingVerifierState), SharingError> {
    let recipient = PublicKey::from(*encryption_public);
    let verifier_ephemeral = DeviceKeyPair::generate()?;
    let shared = verifier_ephemeral.diffie_hellman(&recipient)?;
    let request_id = Uuid::new_v4();
    let mut challenge = Zeroizing::new([0u8; 32]);
    getrandom::fill(challenge.as_mut()).map_err(|_| SharingError::Random)?;
    let verifier_ephemeral_public = verifier_ephemeral.public_bytes();
    let key = derive_pairing_challenge_key(
        &shared,
        request_id,
        principal_id,
        device_id,
        encryption_public,
        &verifier_ephemeral_public,
    )?;
    let aad = pairing_challenge_aad(
        request_id,
        principal_id,
        device_id,
        encryption_public,
        &verifier_ephemeral_public,
    );
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| SharingError::Random)?;
    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            nonce_ref(&nonce)?,
            Payload {
                msg: challenge.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| SharingError::Encryption)?;

    let package = PairingChallengeV1 {
        format_version: PAIRING_FORMAT_VERSION,
        request_id,
        principal_id,
        device_id,
        encryption_public: *encryption_public,
        verifier_ephemeral_public,
        nonce,
        ciphertext,
    };
    let state = PairingVerifierState {
        request_id,
        principal_id,
        device_id,
        encryption_public: *encryption_public,
        verifier_ephemeral_public,
        challenge,
    };
    Ok((package, state))
}

/// Produce the recipient side of a pairing proof. The X25519 key must decrypt
/// the owner's hidden challenge before the Ed25519 key can sign the transcript,
/// proving possession of both private keys at pairing time.
pub fn answer_pairing_challenge(
    package: &PairingChallengeV1,
    encryption_key: &DeviceKeyPair,
    signing_key: &DeviceSigningKeyPair,
) -> Result<PairingProofV1, SharingError> {
    if package.format_version != PAIRING_FORMAT_VERSION
        || package.encryption_public != encryption_key.public_bytes()
    {
        return Err(SharingError::InvalidPairingContext);
    }
    let verifier_ephemeral = PublicKey::from(package.verifier_ephemeral_public);
    let shared = encryption_key.diffie_hellman(&verifier_ephemeral)?;
    let key = derive_pairing_challenge_key(
        &shared,
        package.request_id,
        package.principal_id,
        package.device_id,
        &package.encryption_public,
        &package.verifier_ephemeral_public,
    )?;
    let aad = pairing_challenge_aad(
        package.request_id,
        package.principal_id,
        package.device_id,
        &package.encryption_public,
        &package.verifier_ephemeral_public,
    );
    let plaintext = XChaCha20Poly1305::new((&*key).into())
        .decrypt(
            nonce_ref(&package.nonce)?,
            Payload {
                msg: &package.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| SharingError::Authentication)?;
    let challenge: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| SharingError::InvalidPairingContext)?;
    let signing_public = signing_key.public_bytes();
    let transcript = pairing_proof_transcript(
        package.request_id,
        package.principal_id,
        package.device_id,
        &signing_public,
        &package.encryption_public,
        &package.verifier_ephemeral_public,
        &challenge,
    );
    let signature = signing_key.signing.sign(&transcript).to_bytes().to_vec();
    Ok(PairingProofV1 {
        format_version: PAIRING_FORMAT_VERSION,
        request_id: package.request_id,
        principal_id: package.principal_id,
        device_id: package.device_id,
        signing_public,
        encryption_public: package.encryption_public,
        verifier_ephemeral_public: package.verifier_ephemeral_public,
        challenge,
        signature,
    })
}

/// Verify one recipient response against verifier-owned pending state. Callers
/// must consume that pending state regardless of success or failure so a pairing
/// challenge cannot be replayed.
pub fn verify_pairing_proof(
    package: &PairingChallengeV1,
    state: &PairingVerifierState,
    proof: &PairingProofV1,
) -> Result<[u8; 32], SharingError> {
    if package.format_version != PAIRING_FORMAT_VERSION
        || proof.format_version != PAIRING_FORMAT_VERSION
        || state.request_id != package.request_id
        || state.principal_id != package.principal_id
        || state.device_id != package.device_id
        || state.encryption_public != package.encryption_public
        || state.verifier_ephemeral_public != package.verifier_ephemeral_public
        || proof.request_id != package.request_id
        || proof.principal_id != package.principal_id
        || proof.device_id != package.device_id
        || proof.encryption_public != package.encryption_public
        || proof.verifier_ephemeral_public != package.verifier_ephemeral_public
        || proof.challenge != *state.challenge
    {
        return Err(SharingError::InvalidPairingContext);
    }
    let verifying_key = VerifyingKey::from_bytes(&proof.signing_public)
        .map_err(|_| SharingError::InvalidSigningKey)?;
    if verifying_key.is_weak() {
        return Err(SharingError::InvalidSigningKey);
    }
    let signature_bytes: [u8; 64] = proof
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| SharingError::InvalidPairingSignature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let transcript = pairing_proof_transcript(
        proof.request_id,
        proof.principal_id,
        proof.device_id,
        &proof.signing_public,
        &proof.encryption_public,
        &proof.verifier_ephemeral_public,
        &proof.challenge,
    );
    verifying_key
        .verify_strict(&transcript, &signature)
        .map_err(|_| SharingError::InvalidPairingSignature)?;
    Ok(proof.signing_public)
}

fn derive_pairing_challenge_key(
    shared: &[u8; 32],
    request_id: Uuid,
    principal_id: Uuid,
    device_id: Uuid,
    encryption_public: &[u8; 32],
    verifier_ephemeral_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, SharingError> {
    let mut salt = Sha256::new();
    salt.update(PAIRING_CHALLENGE_AAD_DOMAIN);
    salt.update(request_id.as_bytes());
    salt.update(principal_id.as_bytes());
    salt.update(device_id.as_bytes());
    salt.update(encryption_public);
    salt.update(verifier_ephemeral_public);
    let salt = salt.finalize();
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut output = Zeroizing::new([0u8; 32]);
    hk.expand(PAIRING_CHALLENGE_WRAP_INFO, output.as_mut())
        .map_err(|_| SharingError::KeyDerivation)?;
    Ok(output)
}

fn pairing_challenge_aad(
    request_id: Uuid,
    principal_id: Uuid,
    device_id: Uuid,
    encryption_public: &[u8; 32],
    verifier_ephemeral_public: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PAIRING_CHALLENGE_AAD_DOMAIN.len() + 16 * 3 + 32 * 2 + 2);
    aad.extend_from_slice(PAIRING_CHALLENGE_AAD_DOMAIN);
    aad.extend_from_slice(&PAIRING_FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(request_id.as_bytes());
    aad.extend_from_slice(principal_id.as_bytes());
    aad.extend_from_slice(device_id.as_bytes());
    aad.extend_from_slice(encryption_public);
    aad.extend_from_slice(verifier_ephemeral_public);
    aad
}

fn pairing_proof_transcript(
    request_id: Uuid,
    principal_id: Uuid,
    device_id: Uuid,
    signing_public: &[u8; 32],
    encryption_public: &[u8; 32],
    verifier_ephemeral_public: &[u8; 32],
    challenge: &[u8; 32],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(PAIRING_PROOF_DOMAIN.len() + 2 + 16 * 3 + 32 * 4);
    transcript.extend_from_slice(PAIRING_PROOF_DOMAIN);
    transcript.extend_from_slice(&PAIRING_FORMAT_VERSION.to_be_bytes());
    transcript.extend_from_slice(request_id.as_bytes());
    transcript.extend_from_slice(principal_id.as_bytes());
    transcript.extend_from_slice(device_id.as_bytes());
    transcript.extend_from_slice(signing_public);
    transcript.extend_from_slice(encryption_public);
    transcript.extend_from_slice(verifier_ephemeral_public);
    transcript.extend_from_slice(challenge);
    transcript
}

/// Version 2 envelope that transports one shared secret to exactly one recipient
/// device and binds the claimed sender key into the key schedule and AAD.
#[derive(Clone, Serialize, Deserialize)]
pub struct ShareEnvelopeV2 {
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

/// Seals `plaintext` to `recipient_public` while requiring sender-key possession
/// from parties other than the intended recipient.
///
/// The key schedule combines a fresh ephemeral-to-recipient X25519 secret with
/// a sender-static-to-recipient X25519 secret. A party that knows only the
/// claimed sender public key and recipient public key cannot derive the v2 wrap
/// key. This is not sender authentication: because X25519 DH is symmetric, the
/// intended recipient can compute the static shared secret for any claimed
/// sender public key and therefore can forge an envelope to itself. Authorization
/// must not treat `sender_public` as a signature or proof of sender possession.
pub fn seal(
    sender: &DeviceKeyPair,
    recipient_public: &[u8; 32],
    plaintext: &[u8],
    purpose: SharePurpose,
) -> Result<ShareEnvelopeV2, SharingError> {
    if plaintext.len() > MAX_SHARE_PLAINTEXT_BYTES {
        return Err(SharingError::PlaintextTooLarge);
    }
    let ephemeral = DeviceKeyPair::generate()?;
    let recipient = PublicKey::from(*recipient_public);
    let ephemeral_shared = ephemeral.diffie_hellman(&recipient)?;
    let sender_shared = sender.diffie_hellman(&recipient)?;
    let sender_public = sender.public_bytes();
    let wrap_key = derive_share_wrap_key(
        &ephemeral_shared,
        &sender_shared,
        &sender_public,
        &ephemeral.public,
        recipient_public,
    )?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| SharingError::Random)?;

    let recipient_fingerprint = fingerprint(recipient_public);
    let aad = share_aad(
        &sender_public,
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

    Ok(ShareEnvelopeV2 {
        format_version: SHARE_FORMAT_VERSION,
        algorithm: SHARE_ALGORITHM.to_owned(),
        purpose: purpose.as_label().to_owned(),
        sender_public,
        recipient_public: *recipient_public,
        recipient_fingerprint,
        ephemeral_public: ephemeral.public,
        nonce,
        ciphertext,
    })
}

/// Opens an envelope for this device whose claimed sender matches the caller's
/// expected context. This equality check is not proof that the sender created
/// the envelope; the intended recipient can forge that claim.
pub fn open(
    envelope: &ShareEnvelopeV2,
    recipient: &DeviceKeyPair,
    expected_claimed_sender_public: &[u8; 32],
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
    if envelope.sender_public != *expected_claimed_sender_public {
        return Err(SharingError::WrongSender);
    }

    let ephemeral = PublicKey::from(envelope.ephemeral_public);
    let ephemeral_shared = recipient.diffie_hellman(&ephemeral)?;
    let sender = PublicKey::from(envelope.sender_public);
    let sender_shared = recipient.diffie_hellman(&sender)?;
    let wrap_key = derive_share_wrap_key(
        &ephemeral_shared,
        &sender_shared,
        &envelope.sender_public,
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
    ephemeral_shared: &[u8; 32],
    sender_shared: &[u8; 32],
    sender_public: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, SharingError> {
    let mut salt = Sha256::new();
    salt.update(sender_public);
    salt.update(ephemeral_public);
    salt.update(recipient_public);
    let salt = salt.finalize();
    let mut key_material = Zeroizing::new([0u8; 64]);
    key_material[..32].copy_from_slice(ephemeral_shared);
    key_material[32..].copy_from_slice(sender_shared);
    let hk = Hkdf::<Sha256>::new(Some(&salt), key_material.as_ref());
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
    let mut aad =
        Vec::with_capacity(SHARE_AAD_DOMAIN.len() + SHARE_ALGORITHM.len() + purpose.len() + 114);
    aad.extend_from_slice(SHARE_AAD_DOMAIN);
    aad.extend_from_slice(&SHARE_FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(SHARE_ALGORITHM.as_bytes());
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

    fn forge_envelope_claiming_sender(
        claimed_sender_shared: &[u8; 32],
        claimed_sender_public: &[u8; 32],
        recipient_public: &[u8; 32],
        plaintext: &[u8],
        purpose: SharePurpose,
    ) -> ShareEnvelopeV2 {
        let ephemeral = DeviceKeyPair::generate().expect("ephemeral key pair");
        let recipient = PublicKey::from(*recipient_public);
        let ephemeral_shared = ephemeral
            .diffie_hellman(&recipient)
            .expect("ephemeral recipient DH");
        let wrap_key = derive_share_wrap_key(
            &ephemeral_shared,
            claimed_sender_shared,
            claimed_sender_public,
            &ephemeral.public,
            recipient_public,
        )
        .expect("derive forged wrap key");
        let recipient_fingerprint = fingerprint(recipient_public);
        let aad = share_aad(
            claimed_sender_public,
            recipient_public,
            &recipient_fingerprint,
            &ephemeral.public,
            purpose.as_label(),
        );
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).expect("nonce");
        let ciphertext = XChaCha20Poly1305::new((&*wrap_key).into())
            .encrypt(
                nonce_ref(&nonce).expect("nonce ref"),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("forge ciphertext under impostor DH");

        ShareEnvelopeV2 {
            format_version: SHARE_FORMAT_VERSION,
            algorithm: SHARE_ALGORITHM.to_owned(),
            purpose: purpose.as_label().to_owned(),
            sender_public: *claimed_sender_public,
            recipient_public: *recipient_public,
            recipient_fingerprint,
            ephemeral_public: ephemeral.public,
            nonce,
            ciphertext,
        }
    }

    #[test]
    fn sealed_envelope_round_trips_to_expected_recipient() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");
        let item_key = [0x42u8; 32];

        let envelope = seal(
            &sender,
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
            &sender,
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
            &sender,
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
    fn impostor_with_public_keys_cannot_forge_claimed_sender() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let impostor = DeviceKeyPair::generate().expect("impostor key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");
        let sender_public = sender.public_bytes();
        let recipient_public = recipient.public_bytes();
        let recipient_key = PublicKey::from(recipient_public);
        let impostor_shared = impostor
            .diffie_hellman(&recipient_key)
            .expect("impostor recipient DH");

        let forged = forge_envelope_claiming_sender(
            &impostor_shared,
            &sender_public,
            &recipient_public,
            &[0xA5; 32],
            SharePurpose::ItemKey,
        );

        assert!(matches!(
            open(&forged, &recipient, &sender_public, SharePurpose::ItemKey),
            Err(SharingError::Authentication)
        ));
    }

    #[test]
    fn recipient_can_forge_claimed_sender_so_envelope_is_not_sender_authentication() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");
        let sender_public = sender.public_bytes();
        let recipient_public = recipient.public_bytes();
        let sender_key = PublicKey::from(sender_public);
        let forged_sender_shared = recipient
            .diffie_hellman(&sender_key)
            .expect("recipient claimed-sender DH");

        let forged = forge_envelope_claiming_sender(
            &forged_sender_shared,
            &sender_public,
            &recipient_public,
            &[0xC3; 32],
            SharePurpose::ItemKey,
        );

        let opened = open(&forged, &recipient, &sender_public, SharePurpose::ItemKey)
            .expect("recipient can derive the claimed-sender DH value");
        assert_eq!(opened.as_slice(), &[0xC3; 32]);
    }

    #[test]
    fn legacy_v1_envelope_is_rejected_fail_closed() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");
        let mut legacy = seal(
            &sender,
            &recipient.public_bytes(),
            &[0x11; 32],
            SharePurpose::ItemKey,
        )
        .expect("seal v2 envelope");
        legacy.format_version = 1;
        legacy.algorithm = "xchacha20poly1305".to_owned();
        let encoded = serde_json::to_vec(&legacy).expect("serialize legacy-shaped envelope");
        let parsed: ShareEnvelopeV2 =
            serde_json::from_slice(&encoded).expect("parse legacy-shaped envelope");

        assert!(matches!(
            open(
                &parsed,
                &recipient,
                &sender.public_bytes(),
                SharePurpose::ItemKey
            ),
            Err(SharingError::UnsupportedFormat)
        ));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");
        let mut envelope = seal(
            &sender,
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
            &sender,
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
            &sender,
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
            seal(&sender, &zero_public, &[5u8; 32], SharePurpose::ItemKey),
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
                &sender,
                &recipient.public_bytes(),
                &oversized,
                SharePurpose::ItemKey
            ),
            Err(SharingError::PlaintextTooLarge)
        ));
    }

    #[test]
    fn trusted_device_pairing_proves_both_x25519_and_ed25519_key_possession() {
        let principal_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let encryption_key = DeviceKeyPair::generate().expect("recipient encryption key");
        let signing_key = DeviceSigningKeyPair::generate().expect("device signing key");
        let (package, state) =
            create_pairing_challenge(principal_id, device_id, &encryption_key.public_bytes())
                .expect("create pairing challenge");
        let proof = answer_pairing_challenge(&package, &encryption_key, &signing_key)
            .expect("answer pairing challenge");

        let verified = verify_pairing_proof(&package, &state, &proof).expect("verify proof");
        assert_eq!(verified, signing_key.public_bytes());
    }

    #[test]
    fn pairing_challenge_cannot_be_answered_without_recipient_x25519_secret() {
        let recipient = DeviceKeyPair::generate().expect("recipient encryption key");
        let outsider = DeviceKeyPair::generate().expect("outsider encryption key");
        let signing_key = DeviceSigningKeyPair::generate().expect("device signing key");
        let (package, _state) =
            create_pairing_challenge(Uuid::new_v4(), Uuid::new_v4(), &recipient.public_bytes())
                .expect("create pairing challenge");

        assert!(matches!(
            answer_pairing_challenge(&package, &outsider, &signing_key),
            Err(SharingError::InvalidPairingContext)
        ));
    }

    #[test]
    fn pairing_proof_is_bound_to_all_identity_and_key_context() {
        let encryption_key = DeviceKeyPair::generate().expect("recipient encryption key");
        let signing_key = DeviceSigningKeyPair::generate().expect("device signing key");
        let (package, state) = create_pairing_challenge(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &encryption_key.public_bytes(),
        )
        .expect("create pairing challenge");
        let proof = answer_pairing_challenge(&package, &encryption_key, &signing_key)
            .expect("answer pairing challenge");

        let mut wrong_principal = proof.clone();
        wrong_principal.principal_id = Uuid::new_v4();
        assert!(matches!(
            verify_pairing_proof(&package, &state, &wrong_principal),
            Err(SharingError::InvalidPairingContext)
        ));

        let mut wrong_signing_key = proof.clone();
        wrong_signing_key.signing_public = DeviceSigningKeyPair::generate()
            .expect("other signing key")
            .public_bytes();
        assert!(matches!(
            verify_pairing_proof(&package, &state, &wrong_signing_key),
            Err(SharingError::InvalidPairingSignature)
        ));

        let mut wrong_challenge = proof.clone();
        wrong_challenge.challenge[0] ^= 1;
        assert!(matches!(
            verify_pairing_proof(&package, &state, &wrong_challenge),
            Err(SharingError::InvalidPairingContext)
        ));
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral_key() {
        let sender = DeviceKeyPair::generate().expect("sender key pair");
        let recipient = DeviceKeyPair::generate().expect("recipient key pair");

        let first = seal(
            &sender,
            &recipient.public_bytes(),
            &[8u8; 32],
            SharePurpose::ItemKey,
        )
        .expect("first seal");
        let second = seal(
            &sender,
            &recipient.public_bytes(),
            &[8u8; 32],
            SharePurpose::ItemKey,
        )
        .expect("second seal");

        assert_ne!(first.ephemeral_public, second.ephemeral_public);
        assert_ne!(first.ciphertext, second.ciphertext);
    }
}
