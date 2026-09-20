use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use vault_sharing::{DeviceKeyPair, ShareEnvelopeV2, SharePurpose, SharingError, open, seal};
use zeroize::Zeroizing;

use crate::{DeviceId, MAX_SPACE_MEMBERS, MAX_WIRE_INTEGER, MembershipId, SpaceId};

const SPACE_KEY_ENVELOPE_FORMAT_VERSION: u16 = 1;
const SPACE_KEY_PAYLOAD_DOMAIN: &[u8] = b"safeory:space-key-envelope:v1\0";
const SPACE_KEY_BYTES: usize = 32;
const UUID_BYTES: usize = 16;
const GENERATION_BYTES: usize = 8;
const AEAD_TAG_BYTES: usize = 16;
const SPACE_KEY_PAYLOAD_BYTES: usize =
    SPACE_KEY_PAYLOAD_DOMAIN.len() + 2 + UUID_BYTES * 4 + GENERATION_BYTES + SPACE_KEY_BYTES;

/// One independently rotatable symmetric space key. Secret bytes are
/// zeroized on drop and this type deliberately implements neither serialization
/// nor `Clone`.
pub struct SpaceKey(Zeroizing<[u8; SPACE_KEY_BYTES]>);

impl SpaceKey {
    pub fn generate() -> Result<Self, SpaceKeyError> {
        let mut bytes = Zeroizing::new([0u8; SPACE_KEY_BYTES]);
        getrandom::fill(bytes.as_mut()).map_err(|_| SpaceKeyError::Random)?;
        Ok(Self(bytes))
    }

    /// Restores a key only from reviewed secure local storage or an
    /// authenticated envelope opened for this device.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SPACE_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SPACE_KEY_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpaceKeyRecipient {
    pub membership_id: MembershipId,
    pub device_id: DeviceId,
    pub encryption_public: [u8; 32],
}

/// Opaque transport envelope for one space-key generation and one authorized
/// recipient device. All routing fields are duplicated inside the encrypted
/// payload and checked when opened, preventing cross-context transplantation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceKeyEnvelopeV1 {
    pub format_version: u16,
    pub space_id: SpaceId,
    pub key_generation: u64,
    pub membership_id: MembershipId,
    pub recipient_device_id: DeviceId,
    pub sender_device_id: DeviceId,
    pub wrapped_key: ShareEnvelopeV2,
}

/// Client-only result. The plaintext key must never be sent to the sync
/// service; only the envelopes are transport objects.
pub struct PreparedSpaceKeyGeneration {
    pub space_id: SpaceId,
    pub previous_generation: Option<u64>,
    pub key_generation: u64,
    pub key: SpaceKey,
    pub envelopes: Vec<SpaceKeyEnvelopeV1>,
}

pub fn prepare_initial_space_key(
    space_id: SpaceId,
    sender_device_id: DeviceId,
    sender: &DeviceKeyPair,
    recipients: &[SpaceKeyRecipient],
) -> Result<PreparedSpaceKeyGeneration, SpaceKeyError> {
    prepare_space_key_generation(space_id, None, sender_device_id, sender, recipients)
}

pub fn prepare_rotated_space_key(
    space_id: SpaceId,
    current_generation: u64,
    sender_device_id: DeviceId,
    sender: &DeviceKeyPair,
    recipients: &[SpaceKeyRecipient],
) -> Result<PreparedSpaceKeyGeneration, SpaceKeyError> {
    if current_generation == 0 || current_generation >= MAX_WIRE_INTEGER {
        return Err(SpaceKeyError::InvalidGeneration);
    }
    prepare_space_key_generation(
        space_id,
        Some(current_generation),
        sender_device_id,
        sender,
        recipients,
    )
}

fn prepare_space_key_generation(
    space_id: SpaceId,
    previous_generation: Option<u64>,
    sender_device_id: DeviceId,
    sender: &DeviceKeyPair,
    recipients: &[SpaceKeyRecipient],
) -> Result<PreparedSpaceKeyGeneration, SpaceKeyError> {
    validate_uuid("space ID", space_id.0)?;
    validate_uuid("sender device ID", sender_device_id.0)?;
    validate_recipients(recipients)?;

    let key_generation = previous_generation.map_or(1, |generation| generation + 1);
    let key = SpaceKey::generate()?;
    let envelopes = recipients
        .iter()
        .map(|recipient| {
            seal_space_key(
                space_id,
                key_generation,
                sender_device_id,
                sender,
                recipient,
                &key,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(PreparedSpaceKeyGeneration {
        space_id,
        previous_generation,
        key_generation,
        key,
        envelopes,
    })
}

fn seal_space_key(
    space_id: SpaceId,
    key_generation: u64,
    sender_device_id: DeviceId,
    sender: &DeviceKeyPair,
    recipient: &SpaceKeyRecipient,
    key: &SpaceKey,
) -> Result<SpaceKeyEnvelopeV1, SpaceKeyError> {
    let payload = encode_payload(
        space_id,
        key_generation,
        recipient.membership_id,
        recipient.device_id,
        sender_device_id,
        key,
    );
    let wrapped_key = seal(
        sender,
        &recipient.encryption_public,
        &payload,
        SharePurpose::SpaceKey,
    )?;
    Ok(SpaceKeyEnvelopeV1 {
        format_version: SPACE_KEY_ENVELOPE_FORMAT_VERSION,
        space_id,
        key_generation,
        membership_id: recipient.membership_id,
        recipient_device_id: recipient.device_id,
        sender_device_id,
        wrapped_key,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn open_space_key(
    envelope: &SpaceKeyEnvelopeV1,
    recipient: &DeviceKeyPair,
    expected_space_id: SpaceId,
    expected_generation: u64,
    expected_membership_id: MembershipId,
    expected_recipient_device_id: DeviceId,
    expected_sender_device_id: DeviceId,
    expected_claimed_sender_public: &[u8; 32],
) -> Result<SpaceKey, SpaceKeyError> {
    if envelope.format_version != SPACE_KEY_ENVELOPE_FORMAT_VERSION {
        return Err(SpaceKeyError::UnsupportedFormat);
    }
    if envelope.wrapped_key.ciphertext.len() != SPACE_KEY_PAYLOAD_BYTES + AEAD_TAG_BYTES {
        return Err(SpaceKeyError::InvalidPayload);
    }
    if expected_generation == 0 || expected_generation > MAX_WIRE_INTEGER {
        return Err(SpaceKeyError::InvalidGeneration);
    }
    if envelope.space_id != expected_space_id
        || envelope.key_generation != expected_generation
        || envelope.membership_id != expected_membership_id
        || envelope.recipient_device_id != expected_recipient_device_id
        || envelope.sender_device_id != expected_sender_device_id
    {
        return Err(SpaceKeyError::WrongContext);
    }

    let plaintext = open(
        &envelope.wrapped_key,
        recipient,
        expected_claimed_sender_public,
        SharePurpose::SpaceKey,
    )?;
    decode_payload(
        &plaintext,
        expected_space_id,
        expected_generation,
        expected_membership_id,
        expected_recipient_device_id,
        expected_sender_device_id,
    )
}

fn validate_recipients(recipients: &[SpaceKeyRecipient]) -> Result<(), SpaceKeyError> {
    if recipients.is_empty() || recipients.len() > MAX_SPACE_MEMBERS {
        return Err(SpaceKeyError::InvalidRecipientCount);
    }
    let mut devices = HashSet::new();
    for recipient in recipients {
        validate_uuid("membership ID", recipient.membership_id.0)?;
        validate_uuid("recipient device ID", recipient.device_id.0)?;
        if !devices.insert(recipient.device_id) {
            return Err(SpaceKeyError::DuplicateRecipient);
        }
    }
    Ok(())
}

fn validate_uuid(label: &'static str, value: Uuid) -> Result<(), SpaceKeyError> {
    if value.is_nil() {
        Err(SpaceKeyError::InvalidIdentifier(label))
    } else {
        Ok(())
    }
}

fn encode_payload(
    space_id: SpaceId,
    key_generation: u64,
    membership_id: MembershipId,
    recipient_device_id: DeviceId,
    sender_device_id: DeviceId,
    key: &SpaceKey,
) -> Zeroizing<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(SPACE_KEY_PAYLOAD_BYTES));
    payload.extend_from_slice(SPACE_KEY_PAYLOAD_DOMAIN);
    payload.extend_from_slice(&SPACE_KEY_ENVELOPE_FORMAT_VERSION.to_be_bytes());
    payload.extend_from_slice(space_id.0.as_bytes());
    payload.extend_from_slice(&key_generation.to_be_bytes());
    payload.extend_from_slice(membership_id.0.as_bytes());
    payload.extend_from_slice(recipient_device_id.0.as_bytes());
    payload.extend_from_slice(sender_device_id.0.as_bytes());
    payload.extend_from_slice(key.as_bytes());
    payload
}

fn decode_payload(
    payload: &[u8],
    expected_space_id: SpaceId,
    expected_generation: u64,
    expected_membership_id: MembershipId,
    expected_recipient_device_id: DeviceId,
    expected_sender_device_id: DeviceId,
) -> Result<SpaceKey, SpaceKeyError> {
    if payload.len() != SPACE_KEY_PAYLOAD_BYTES || !payload.starts_with(SPACE_KEY_PAYLOAD_DOMAIN) {
        return Err(SpaceKeyError::InvalidPayload);
    }
    let mut offset = SPACE_KEY_PAYLOAD_DOMAIN.len();
    let version = read_u16(payload, &mut offset)?;
    let space_id = SpaceId(read_uuid(payload, &mut offset)?);
    let key_generation = read_u64(payload, &mut offset)?;
    let membership_id = MembershipId(read_uuid(payload, &mut offset)?);
    let recipient_device_id = DeviceId(read_uuid(payload, &mut offset)?);
    let sender_device_id = DeviceId(read_uuid(payload, &mut offset)?);
    let key_bytes = Zeroizing::new(
        payload
            .get(offset..offset + SPACE_KEY_BYTES)
            .ok_or(SpaceKeyError::InvalidPayload)?
            .try_into()
            .map_err(|_| SpaceKeyError::InvalidPayload)?,
    );

    if version != SPACE_KEY_ENVELOPE_FORMAT_VERSION
        || space_id != expected_space_id
        || key_generation != expected_generation
        || membership_id != expected_membership_id
        || recipient_device_id != expected_recipient_device_id
        || sender_device_id != expected_sender_device_id
    {
        return Err(SpaceKeyError::WrongContext);
    }
    Ok(SpaceKey(key_bytes))
}

fn read_u16(payload: &[u8], offset: &mut usize) -> Result<u16, SpaceKeyError> {
    let bytes: [u8; 2] = take(payload, offset, 2)?
        .try_into()
        .map_err(|_| SpaceKeyError::InvalidPayload)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u64(payload: &[u8], offset: &mut usize) -> Result<u64, SpaceKeyError> {
    let bytes: [u8; 8] = take(payload, offset, 8)?
        .try_into()
        .map_err(|_| SpaceKeyError::InvalidPayload)?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_uuid(payload: &[u8], offset: &mut usize) -> Result<Uuid, SpaceKeyError> {
    let bytes: [u8; UUID_BYTES] = take(payload, offset, UUID_BYTES)?
        .try_into()
        .map_err(|_| SpaceKeyError::InvalidPayload)?;
    Ok(Uuid::from_bytes(bytes))
}

fn take<'a>(
    payload: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], SpaceKeyError> {
    let end = offset
        .checked_add(length)
        .ok_or(SpaceKeyError::InvalidPayload)?;
    let value = payload
        .get(*offset..end)
        .ok_or(SpaceKeyError::InvalidPayload)?;
    *offset = end;
    Ok(value)
}

#[derive(Debug, Error)]
pub enum SpaceKeyError {
    #[error("cryptographic random source failed")]
    Random,
    #[error("unsupported space-key envelope format")]
    UnsupportedFormat,
    #[error("space-key generation is invalid or exhausted")]
    InvalidGeneration,
    #[error("space-key recipient count is empty or exceeds the supported bound")]
    InvalidRecipientCount,
    #[error("space-key recipients contain a duplicate device")]
    DuplicateRecipient,
    #[error("{0} must be a non-nil UUID")]
    InvalidIdentifier(&'static str),
    #[error("space-key envelope does not match the expected routing context")]
    WrongContext,
    #[error("space-key envelope payload is malformed")]
    InvalidPayload,
    #[error(transparent)]
    Sharing(#[from] SharingError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipient(key: &DeviceKeyPair) -> SpaceKeyRecipient {
        SpaceKeyRecipient {
            membership_id: MembershipId::new(),
            device_id: DeviceId::new(),
            encryption_public: key.public_bytes(),
        }
    }

    #[test]
    fn initial_generation_round_trips_to_each_recipient() {
        let sender = DeviceKeyPair::generate().expect("sender key");
        let sender_device_id = DeviceId::new();
        let first_key = DeviceKeyPair::generate().expect("first recipient key");
        let second_key = DeviceKeyPair::generate().expect("second recipient key");
        let recipients = [recipient(&first_key), recipient(&second_key)];
        let space_id = SpaceId::new();

        let prepared = prepare_initial_space_key(space_id, sender_device_id, &sender, &recipients)
            .expect("prepare initial key");

        assert_eq!(prepared.previous_generation, None);
        assert_eq!(prepared.key_generation, 1);
        assert_eq!(prepared.envelopes.len(), 2);
        for (envelope, (binding, key_pair)) in prepared
            .envelopes
            .iter()
            .zip(recipients.iter().zip([&first_key, &second_key]))
        {
            let opened = open_space_key(
                envelope,
                key_pair,
                space_id,
                1,
                binding.membership_id,
                binding.device_id,
                sender_device_id,
                &sender.public_bytes(),
            )
            .expect("open space key");
            assert_eq!(opened.as_bytes(), prepared.key.as_bytes());
        }
    }

    #[test]
    fn rotation_advances_generation_and_uses_a_fresh_key() {
        let sender = DeviceKeyPair::generate().expect("sender key");
        let recipient_key = DeviceKeyPair::generate().expect("recipient key");
        let binding = recipient(&recipient_key);
        let space_id = SpaceId::new();
        let sender_device_id = DeviceId::new();
        let first = prepare_initial_space_key(space_id, sender_device_id, &sender, &[binding])
            .expect("initial key");
        let second = prepare_rotated_space_key(
            space_id,
            first.key_generation,
            sender_device_id,
            &sender,
            &[binding],
        )
        .expect("rotated key");

        assert_eq!(second.previous_generation, Some(1));
        assert_eq!(second.key_generation, 2);
        assert_ne!(first.key.as_bytes(), second.key.as_bytes());
        assert!(matches!(
            open_space_key(
                &second.envelopes[0],
                &recipient_key,
                space_id,
                1,
                binding.membership_id,
                binding.device_id,
                sender_device_id,
                &sender.public_bytes(),
            ),
            Err(SpaceKeyError::WrongContext)
        ));
    }

    #[test]
    fn envelope_transplant_and_wrong_recipient_fail_closed() {
        let sender = DeviceKeyPair::generate().expect("sender key");
        let recipient_key = DeviceKeyPair::generate().expect("recipient key");
        let outsider = DeviceKeyPair::generate().expect("outsider key");
        let binding = recipient(&recipient_key);
        let space_id = SpaceId::new();
        let sender_device_id = DeviceId::new();
        let prepared = prepare_initial_space_key(space_id, sender_device_id, &sender, &[binding])
            .expect("initial key");
        let envelope = &prepared.envelopes[0];

        assert!(matches!(
            open_space_key(
                envelope,
                &recipient_key,
                SpaceId::new(),
                1,
                binding.membership_id,
                binding.device_id,
                sender_device_id,
                &sender.public_bytes(),
            ),
            Err(SpaceKeyError::WrongContext)
        ));
        assert!(matches!(
            open_space_key(
                envelope,
                &outsider,
                space_id,
                1,
                binding.membership_id,
                binding.device_id,
                sender_device_id,
                &sender.public_bytes(),
            ),
            Err(SpaceKeyError::Sharing(SharingError::WrongRecipient))
        ));

        let mut oversized = envelope.clone();
        oversized.wrapped_key.ciphertext.push(0);
        assert!(matches!(
            open_space_key(
                &oversized,
                &recipient_key,
                space_id,
                1,
                binding.membership_id,
                binding.device_id,
                sender_device_id,
                &sender.public_bytes(),
            ),
            Err(SpaceKeyError::InvalidPayload)
        ));
    }

    #[test]
    fn recipient_and_generation_bounds_fail_before_key_creation() {
        let sender = DeviceKeyPair::generate().expect("sender key");
        let sender_device_id = DeviceId::new();
        let space_id = SpaceId::new();

        assert!(matches!(
            prepare_initial_space_key(space_id, sender_device_id, &sender, &[]),
            Err(SpaceKeyError::InvalidRecipientCount)
        ));
        let recipient_key = DeviceKeyPair::generate().expect("recipient key");
        let binding = recipient(&recipient_key);
        assert!(matches!(
            prepare_initial_space_key(space_id, sender_device_id, &sender, &[binding, binding],),
            Err(SpaceKeyError::DuplicateRecipient)
        ));
        assert!(matches!(
            prepare_rotated_space_key(
                space_id,
                MAX_WIRE_INTEGER,
                sender_device_id,
                &sender,
                &[binding],
            ),
            Err(SpaceKeyError::InvalidGeneration)
        ));
    }
}
