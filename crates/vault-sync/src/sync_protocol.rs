use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AccountId, HouseholdId, MAX_WIRE_INTEGER, ObjectId, OperationId, SpaceId};

pub const SYNC_PROTOCOL_VERSION: u16 = 1;
pub const OBJECT_HEADER_FORMAT_VERSION: u16 = 1;
pub const OPAQUE_MUTATION_FORMAT_VERSION: u16 = 1;
pub const COMPATIBILITY_FORMAT_VERSION: u16 = 1;
pub const MAX_SYNC_CIPHERTEXT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRangeV1 {
    pub minimum: u16,
    pub maximum: u16,
}

impl VersionRangeV1 {
    #[must_use]
    pub const fn exact(version: u16) -> Self {
        Self {
            minimum: version,
            maximum: version,
        }
    }

    pub fn validate(self) -> Result<(), CompatibilityError> {
        if self.minimum == 0 || self.maximum < self.minimum {
            Err(CompatibilityError::InvalidRange)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub const fn contains(self, version: u16) -> bool {
        version >= self.minimum && version <= self.maximum
    }
}

/// Independent version ranges advertised by a client or server. Payload
/// schema support is carried per opaque object header because schemas differ by
/// object class; the service never interprets encrypted payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityAdvertisementV1 {
    pub format_version: u16,
    pub protocol_versions: VersionRangeV1,
    pub object_header_versions: VersionRangeV1,
    pub envelope_versions: VersionRangeV1,
}

impl CompatibilityAdvertisementV1 {
    #[must_use]
    pub const fn current() -> Self {
        Self {
            format_version: COMPATIBILITY_FORMAT_VERSION,
            protocol_versions: VersionRangeV1::exact(SYNC_PROTOCOL_VERSION),
            object_header_versions: VersionRangeV1::exact(OBJECT_HEADER_FORMAT_VERSION),
            envelope_versions: VersionRangeV1::exact(1),
        }
    }

    pub fn validate(self) -> Result<(), CompatibilityError> {
        if self.format_version != COMPATIBILITY_FORMAT_VERSION {
            return Err(CompatibilityError::UnsupportedFormat);
        }
        self.protocol_versions.validate()?;
        self.object_header_versions.validate()?;
        self.envelope_versions.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegotiatedCompatibility {
    pub protocol_version: u16,
    pub object_header_version: u16,
    pub envelope_version: u16,
}

pub fn negotiate_compatibility(
    local: CompatibilityAdvertisementV1,
    remote: CompatibilityAdvertisementV1,
) -> Result<NegotiatedCompatibility, CompatibilityError> {
    local.validate()?;
    remote.validate()?;
    Ok(NegotiatedCompatibility {
        protocol_version: highest_common(local.protocol_versions, remote.protocol_versions)?,
        object_header_version: highest_common(
            local.object_header_versions,
            remote.object_header_versions,
        )?,
        envelope_version: highest_common(local.envelope_versions, remote.envelope_versions)?,
    })
}

fn highest_common(left: VersionRangeV1, right: VersionRangeV1) -> Result<u16, CompatibilityError> {
    let minimum = left.minimum.max(right.minimum);
    let maximum = left.maximum.min(right.maximum);
    if maximum < minimum {
        Err(CompatibilityError::NoCommonVersion)
    } else {
        Ok(maximum)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectClassV1 {
    AccountBootstrap,
    DeviceBootstrap,
    HouseholdProfile,
    SpaceManifest,
    SpaceKeyEnvelope,
    Item,
    AttachmentManifest,
    AttachmentChunk,
    ItemHistory,
    Reminder,
    Activity,
    Inbox,
    SecureLinkCopy,
    RecoveryCapsule,
    EmergencyCapsule,
    SecurityEvent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjectScopeV1 {
    Account {
        account_id: AccountId,
    },
    Household {
        account_id: AccountId,
        household_id: HouseholdId,
    },
    Space {
        account_id: AccountId,
        household_id: HouseholdId,
        space_id: SpaceId,
    },
}

impl ObjectScopeV1 {
    fn validate(self) -> Result<(), ProtocolError> {
        match self {
            Self::Account { account_id } => non_nil("account ID", account_id.0),
            Self::Household {
                account_id,
                household_id,
            } => {
                non_nil("account ID", account_id.0)?;
                non_nil("household ID", household_id.0)
            }
            Self::Space {
                account_id,
                household_id,
                space_id,
            } => {
                non_nil("account ID", account_id.0)?;
                non_nil("household ID", household_id.0)?;
                non_nil("space ID", space_id.0)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueObjectHeaderV1 {
    pub format_version: u16,
    pub protocol_version: u16,
    pub object_id: ObjectId,
    pub class: ObjectClassV1,
    pub scope: ObjectScopeV1,
    pub revision: u64,
    pub payload_version: u16,
    pub envelope_version: u16,
    pub ciphertext_size_bytes: u64,
    pub ciphertext_sha256: [u8; 32],
    pub tombstone: bool,
}

impl OpaqueObjectHeaderV1 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.format_version != OBJECT_HEADER_FORMAT_VERSION {
            return Err(ProtocolError::UnsupportedHeaderFormat);
        }
        if self.protocol_version != SYNC_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedProtocol);
        }
        non_nil("object ID", self.object_id.0)?;
        self.scope.validate()?;
        safe_integer("object revision", self.revision)?;
        if self.payload_version == 0 || self.envelope_version == 0 {
            return Err(ProtocolError::InvalidVersion);
        }
        if self.ciphertext_size_bytes == 0 || self.ciphertext_size_bytes > MAX_SYNC_CIPHERTEXT_BYTES
        {
            return Err(ProtocolError::InvalidCiphertextSize);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "condition", rename_all = "snake_case", deny_unknown_fields)]
pub enum WritePreconditionV1 {
    CreateOnly,
    Match {
        revision: u64,
        ciphertext_sha256: [u8; 32],
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueMutationV1 {
    pub format_version: u16,
    pub operation_id: OperationId,
    pub object: OpaqueObjectHeaderV1,
    pub precondition: WritePreconditionV1,
}

impl OpaqueMutationV1 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.format_version != OPAQUE_MUTATION_FORMAT_VERSION {
            return Err(ProtocolError::UnsupportedMutationFormat);
        }
        non_nil("operation ID", self.operation_id.0)?;
        self.object.validate()?;
        match self.precondition {
            WritePreconditionV1::CreateOnly => Ok(()),
            WritePreconditionV1::Match { revision, .. } => {
                safe_integer("precondition revision", revision)?;
                if self.object.revision <= revision {
                    Err(ProtocolError::RevisionDidNotAdvance)
                } else {
                    Ok(())
                }
            }
        }
    }
}

fn non_nil(label: &'static str, value: uuid::Uuid) -> Result<(), ProtocolError> {
    if value.is_nil() {
        Err(ProtocolError::InvalidIdentifier(label))
    } else {
        Ok(())
    }
}

fn safe_integer(label: &'static str, value: u64) -> Result<(), ProtocolError> {
    if value > MAX_WIRE_INTEGER {
        Err(ProtocolError::IntegerOutOfRange(label))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CompatibilityError {
    #[error("unsupported compatibility advertisement format")]
    UnsupportedFormat,
    #[error("version range is empty, reversed, or contains version zero")]
    InvalidRange,
    #[error("peers have no common supported version")]
    NoCommonVersion,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unsupported opaque object header format")]
    UnsupportedHeaderFormat,
    #[error("unsupported sync protocol version")]
    UnsupportedProtocol,
    #[error("unsupported opaque mutation format")]
    UnsupportedMutationFormat,
    #[error("{0} must be a non-nil UUID")]
    InvalidIdentifier(&'static str),
    #[error("{0} exceeds the exact browser integer range")]
    IntegerOutOfRange(&'static str),
    #[error("payload and envelope versions must be positive")]
    InvalidVersion,
    #[error("ciphertext size is empty or exceeds the protocol bound")]
    InvalidCiphertextSize,
    #[error("candidate revision must advance the matched revision")]
    RevisionDidNotAdvance,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(revision: u64) -> OpaqueObjectHeaderV1 {
        OpaqueObjectHeaderV1 {
            format_version: OBJECT_HEADER_FORMAT_VERSION,
            protocol_version: SYNC_PROTOCOL_VERSION,
            object_id: ObjectId::new(),
            class: ObjectClassV1::Item,
            scope: ObjectScopeV1::Space {
                account_id: AccountId::new(),
                household_id: HouseholdId::new(),
                space_id: SpaceId::new(),
            },
            revision,
            payload_version: 10,
            envelope_version: 1,
            ciphertext_size_bytes: 512,
            ciphertext_sha256: [0x5a; 32],
            tombstone: false,
        }
    }

    #[test]
    fn compatibility_chooses_highest_common_independent_versions() {
        let local = CompatibilityAdvertisementV1 {
            format_version: COMPATIBILITY_FORMAT_VERSION,
            protocol_versions: VersionRangeV1 {
                minimum: 1,
                maximum: 3,
            },
            object_header_versions: VersionRangeV1 {
                minimum: 1,
                maximum: 2,
            },
            envelope_versions: VersionRangeV1 {
                minimum: 1,
                maximum: 4,
            },
        };
        let remote = CompatibilityAdvertisementV1 {
            format_version: COMPATIBILITY_FORMAT_VERSION,
            protocol_versions: VersionRangeV1 {
                minimum: 2,
                maximum: 4,
            },
            object_header_versions: VersionRangeV1::exact(1),
            envelope_versions: VersionRangeV1 {
                minimum: 2,
                maximum: 3,
            },
        };

        assert_eq!(
            negotiate_compatibility(local, remote),
            Ok(NegotiatedCompatibility {
                protocol_version: 3,
                object_header_version: 1,
                envelope_version: 3,
            })
        );
    }

    #[test]
    fn incompatible_or_malformed_ranges_fail_closed() {
        let current = CompatibilityAdvertisementV1::current();
        let incompatible = CompatibilityAdvertisementV1 {
            protocol_versions: VersionRangeV1::exact(2),
            ..current
        };
        assert_eq!(
            negotiate_compatibility(current, incompatible),
            Err(CompatibilityError::NoCommonVersion)
        );

        let malformed = CompatibilityAdvertisementV1 {
            envelope_versions: VersionRangeV1 {
                minimum: 2,
                maximum: 1,
            },
            ..current
        };
        assert_eq!(
            negotiate_compatibility(current, malformed),
            Err(CompatibilityError::InvalidRange)
        );
    }

    #[test]
    fn mutation_requires_non_nil_operation_and_advancing_safe_revision() {
        let mut mutation = OpaqueMutationV1 {
            format_version: OPAQUE_MUTATION_FORMAT_VERSION,
            operation_id: OperationId::new(),
            object: header(4),
            precondition: WritePreconditionV1::Match {
                revision: 3,
                ciphertext_sha256: [0x11; 32],
            },
        };
        assert!(mutation.validate().is_ok());

        mutation.precondition = WritePreconditionV1::Match {
            revision: 4,
            ciphertext_sha256: [0x11; 32],
        };
        assert_eq!(
            mutation.validate(),
            Err(ProtocolError::RevisionDidNotAdvance)
        );
        mutation.precondition = WritePreconditionV1::CreateOnly;
        mutation.operation_id = OperationId(uuid::Uuid::nil());
        assert_eq!(
            mutation.validate(),
            Err(ProtocolError::InvalidIdentifier("operation ID"))
        );
    }

    #[test]
    fn object_header_bounds_versions_scope_and_size() {
        let mut object = header(MAX_WIRE_INTEGER);
        assert!(object.validate().is_ok());

        object.revision += 1;
        assert_eq!(
            object.validate(),
            Err(ProtocolError::IntegerOutOfRange("object revision"))
        );
        object.revision = 0;
        object.ciphertext_size_bytes = MAX_SYNC_CIPHERTEXT_BYTES + 1;
        assert_eq!(object.validate(), Err(ProtocolError::InvalidCiphertextSize));
        object.ciphertext_size_bytes = 1;
        object.scope = ObjectScopeV1::Account {
            account_id: AccountId(uuid::Uuid::nil()),
        };
        assert_eq!(
            object.validate(),
            Err(ProtocolError::InvalidIdentifier("account ID"))
        );
    }

    #[test]
    fn wire_contract_rejects_unknown_fields() {
        let mutation = OpaqueMutationV1 {
            format_version: OPAQUE_MUTATION_FORMAT_VERSION,
            operation_id: OperationId::new(),
            object: header(0),
            precondition: WritePreconditionV1::CreateOnly,
        };
        let mut value = serde_json::to_value(mutation).expect("serialize mutation");
        value
            .as_object_mut()
            .expect("mutation object")
            .insert("future_required_field".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<OpaqueMutationV1>(value).is_err());
    }
}
