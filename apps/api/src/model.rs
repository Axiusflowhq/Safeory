use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::{hex_encode, parse_public_key_hex};

pub(crate) const MAX_LIST_LIMIT: u16 = 256;
pub(crate) const DEFAULT_LIST_LIMIT: u16 = 100;
/// Browser clients represent revisions as JSON/TypeScript numbers. Keep the
/// wire value within JavaScript's exact integer range so round-trips cannot
/// silently change a revision and so no client can exhaust an object at i64::MAX.
pub(crate) const MAX_WIRE_REVISION: i64 = vault_sync::MAX_WIRE_INTEGER as i64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObjectVersion {
    pub revision: i64,
    pub ciphertext_sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct StoredObject {
    pub object_id: Uuid,
    pub revision: i64,
    pub ciphertext_size_bytes: i64,
    pub ciphertext_sha256: [u8; 32],
    pub change_seq: i64,
    pub storage_key: String,
}

impl StoredObject {
    pub(crate) fn version(&self) -> ObjectVersion {
        ObjectVersion {
            revision: self.revision,
            ciphertext_sha256: self.ciphertext_sha256,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WritePrecondition {
    CreateOnly,
    Match(ObjectVersion),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum PolicyError {
    #[error("write precondition does not match current object")]
    PreconditionFailed,
    #[error("candidate revision does not advance current revision")]
    InvalidRevision,
}

pub(crate) fn validate_write_policy(
    current: Option<&StoredObject>,
    candidate_revision: i64,
    precondition: &WritePrecondition,
) -> Result<(), PolicyError> {
    if !(0..=MAX_WIRE_REVISION).contains(&candidate_revision) {
        return Err(PolicyError::InvalidRevision);
    }

    match (current, precondition) {
        (None, WritePrecondition::CreateOnly) => Ok(()),
        (Some(_), WritePrecondition::CreateOnly) | (None, WritePrecondition::Match(_)) => {
            Err(PolicyError::PreconditionFailed)
        }
        (Some(current), WritePrecondition::Match(expected)) => {
            if !(0..=MAX_WIRE_REVISION).contains(&current.revision) {
                return Err(PolicyError::InvalidRevision);
            }
            if current.version() != *expected {
                return Err(PolicyError::PreconditionFailed);
            }
            if candidate_revision <= current.revision {
                return Err(PolicyError::InvalidRevision);
            }
            Ok(())
        }
    }
}

pub(crate) fn strong_etag(version: &ObjectVersion) -> String {
    format!(
        "\"safeory-r{}-{}\"",
        version.revision,
        hex_encode(&version.ciphertext_sha256)
    )
}

pub(crate) fn parse_strong_etag(value: &str) -> Option<ObjectVersion> {
    if value.starts_with("W/") || !value.starts_with('"') || !value.ends_with('"') {
        return None;
    }
    let inner = &value[1..value.len() - 1];
    let payload = inner.strip_prefix("safeory-r")?;
    let (revision, hash) = payload.split_once('-')?;
    let revision = revision.parse::<i64>().ok()?;
    if !(0..=MAX_WIRE_REVISION).contains(&revision) {
        return None;
    }
    let ciphertext_sha256 = parse_public_key_hex(hash)?;
    Some(ObjectVersion {
        revision,
        ciphertext_sha256,
    })
}

#[derive(Debug, Serialize)]
pub(crate) struct ObjectMetadataResponse {
    pub object_id: Uuid,
    pub revision: u64,
    pub ciphertext_size_bytes: u64,
    pub change_seq: u64,
    pub etag: String,
}

impl TryFrom<&StoredObject> for ObjectMetadataResponse {
    type Error = ();

    fn try_from(value: &StoredObject) -> Result<Self, Self::Error> {
        if !(0..=MAX_WIRE_REVISION).contains(&value.revision) {
            return Err(());
        }
        Ok(Self {
            object_id: value.object_id,
            revision: u64::try_from(value.revision).map_err(|_| ())?,
            ciphertext_size_bytes: u64::try_from(value.ciphertext_size_bytes).map_err(|_| ())?,
            change_seq: u64::try_from(value.change_seq).map_err(|_| ())?,
            etag: strong_etag(&value.version()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(revision: i64, hash_byte: u8) -> StoredObject {
        StoredObject {
            object_id: Uuid::nil(),
            revision,
            ciphertext_size_bytes: 10,
            ciphertext_sha256: [hash_byte; 32],
            change_seq: 1,
            storage_key: "opaque".into(),
        }
    }

    #[test]
    fn strong_etag_round_trips_and_weak_etags_are_rejected() {
        let version = stored(7, 0x5a).version();
        let etag = strong_etag(&version);
        assert_eq!(parse_strong_etag(&etag), Some(version));
        assert!(parse_strong_etag(&format!("W/{etag}")).is_none());
        assert!(parse_strong_etag("\"not-safeory\"").is_none());
    }

    #[test]
    fn create_only_requires_an_absent_object() {
        assert_eq!(
            validate_write_policy(None, 0, &WritePrecondition::CreateOnly),
            Ok(())
        );
        assert_eq!(
            validate_write_policy(None, 9, &WritePrecondition::CreateOnly),
            Ok(())
        );
        assert_eq!(
            validate_write_policy(Some(&stored(1, 1)), 2, &WritePrecondition::CreateOnly),
            Err(PolicyError::PreconditionFailed)
        );
    }

    #[test]
    fn update_requires_matching_etag_and_strictly_newer_revision() {
        let current = stored(3, 2);
        let expected = WritePrecondition::Match(current.version());
        assert_eq!(validate_write_policy(Some(&current), 4, &expected), Ok(()));
        assert_eq!(validate_write_policy(Some(&current), 9, &expected), Ok(()));
        assert_eq!(
            validate_write_policy(Some(&current), 3, &expected),
            Err(PolicyError::InvalidRevision)
        );

        let wrong = WritePrecondition::Match(stored(3, 9).version());
        assert_eq!(
            validate_write_policy(Some(&current), 4, &wrong),
            Err(PolicyError::PreconditionFailed)
        );
    }

    #[test]
    fn revision_policy_is_bounded_to_exact_browser_integer_range() {
        assert_eq!(
            validate_write_policy(None, MAX_WIRE_REVISION, &WritePrecondition::CreateOnly),
            Ok(())
        );
        assert_eq!(
            validate_write_policy(None, MAX_WIRE_REVISION + 1, &WritePrecondition::CreateOnly),
            Err(PolicyError::InvalidRevision)
        );

        let current = stored(MAX_WIRE_REVISION, 3);
        let expected = WritePrecondition::Match(current.version());
        assert_eq!(
            validate_write_policy(Some(&current), MAX_WIRE_REVISION, &expected),
            Err(PolicyError::InvalidRevision)
        );

        let too_large = ObjectVersion {
            revision: MAX_WIRE_REVISION + 1,
            ciphertext_sha256: [0; 32],
        };
        assert!(parse_strong_etag(&strong_etag(&too_large)).is_none());
        assert!(ObjectMetadataResponse::try_from(&stored(MAX_WIRE_REVISION + 1, 4)).is_err());
    }
}
