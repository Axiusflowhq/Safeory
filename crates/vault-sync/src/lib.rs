#![forbid(unsafe_code)]

//! Versioned client/server-neutral contracts for Safeory synchronization.
//!
//! These structures intentionally contain only opaque identifiers and routing
//! metadata. Human-readable account, household, space, and relationship names
//! belong in encrypted objects referenced by these contracts.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

mod space_keys;

pub use space_keys::{
    PreparedSpaceKeyGeneration, SpaceKey, SpaceKeyEnvelopeV1, SpaceKeyError, SpaceKeyRecipient,
    open_space_key, prepare_initial_space_key, prepare_rotated_space_key,
};

pub const DOMAIN_FORMAT_VERSION: u16 = 1;
pub const MAX_HOUSEHOLDS_PER_ACCOUNT: usize = 32;
pub const MAX_DEVICES_PER_ACCOUNT: usize = 64;
pub const MAX_ACCOUNTS_PER_HOUSEHOLD: usize = 256;
pub const MAX_MEMBERSHIPS_PER_HOUSEHOLD: usize = 256;
pub const MAX_SPACES_PER_HOUSEHOLD: usize = 256;
pub const MAX_SPACE_MEMBERS: usize = 256;
pub const MAX_MIGRATED_OBJECTS: usize = 100_000;
/// Largest integer that can round-trip exactly through browser JSON numbers.
pub const MAX_WIRE_INTEGER: u64 = 9_007_199_254_740_991;

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

opaque_id!(AccountId);
opaque_id!(HouseholdId);
opaque_id!(MembershipId);
opaque_id!(DeviceId);
opaque_id!(SpaceId);
opaque_id!(ObjectId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipRole {
    Owner,
    Organizer,
    Member,
    FullCollaborator,
    PartialCollaborator,
    LegacyCollaborator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    Invited,
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceKind {
    Private,
    Shared,
    Purpose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceAccess {
    Read,
    Edit,
    Manage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountV1 {
    pub format_version: u16,
    pub account_id: AccountId,
    pub household_ids: Vec<HouseholdId>,
    pub device_ids: Vec<DeviceId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HouseholdV1 {
    pub format_version: u16,
    pub household_id: HouseholdId,
    /// Points to the encrypted household profile. It is not a display name.
    pub encrypted_profile_object_id: ObjectId,
    pub membership_ids: Vec<MembershipId>,
    pub space_ids: Vec<SpaceId>,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipV1 {
    pub format_version: u16,
    pub membership_id: MembershipId,
    pub account_id: AccountId,
    pub household_id: HouseholdId,
    pub role: MembershipRole,
    pub state: MembershipState,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceV1 {
    pub format_version: u16,
    pub space_id: SpaceId,
    pub household_id: HouseholdId,
    pub kind: SpaceKind,
    /// Points to an encrypted object containing the display name and policy.
    pub encrypted_manifest_object_id: ObjectId,
    /// Generation zero is never valid. Rotation advances this monotonically.
    pub key_generation: u64,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpaceMemberV1 {
    pub format_version: u16,
    pub space_id: SpaceId,
    pub membership_id: MembershipId,
    pub access: SpaceAccess,
    /// The device-specific encrypted key envelope is an opaque sync object.
    pub envelope_object_id: ObjectId,
    pub device_id: DeviceId,
    pub key_generation: u64,
    pub revision: u64,
}

/// Complete bounded topology used for bootstrap and compatibility validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HouseholdTopologyV1 {
    pub format_version: u16,
    pub accounts: Vec<AccountV1>,
    pub household: HouseholdV1,
    pub memberships: Vec<MembershipV1>,
    pub spaces: Vec<SpaceV1>,
    pub space_members: Vec<SpaceMemberV1>,
}

/// Ciphertext-preserving assignment made while upgrading a local single-owner
/// vault. Existing object IDs and bodies stay unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectSpaceAssignmentV1 {
    pub object_id: ObjectId,
    pub space_id: SpaceId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SingleOwnerMigrationV1 {
    pub format_version: u16,
    pub topology: HouseholdTopologyV1,
    pub private_space_id: SpaceId,
    pub object_assignments: Vec<ObjectSpaceAssignmentV1>,
}

impl HouseholdTopologyV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.format_version)?;
        self.household.validate()?;
        bounded("accounts", self.accounts.len(), MAX_ACCOUNTS_PER_HOUSEHOLD)?;
        bounded(
            "memberships",
            self.memberships.len(),
            MAX_MEMBERSHIPS_PER_HOUSEHOLD,
        )?;
        bounded("spaces", self.spaces.len(), MAX_SPACES_PER_HOUSEHOLD)?;
        bounded("space members", self.space_members.len(), MAX_SPACE_MEMBERS)?;

        if self.accounts.is_empty() {
            return Err(ContractError::EmptyCollection("household accounts"));
        }

        unique(
            "account IDs",
            self.accounts.iter().map(|value| value.account_id),
        )?;
        unique(
            "membership IDs",
            self.memberships.iter().map(|value| value.membership_id),
        )?;
        unique("space IDs", self.spaces.iter().map(|value| value.space_id))?;
        unique(
            "space/device memberships",
            self.space_members
                .iter()
                .map(|value| (value.space_id, value.device_id)),
        )?;
        unique(
            "topology object IDs",
            std::iter::once(self.household.encrypted_profile_object_id)
                .chain(
                    self.spaces
                        .iter()
                        .map(|space| space.encrypted_manifest_object_id),
                )
                .chain(
                    self.space_members
                        .iter()
                        .map(|member| member.envelope_object_id),
                ),
        )?;

        let membership_ids: HashSet<_> = self
            .memberships
            .iter()
            .map(|value| value.membership_id)
            .collect();
        let space_ids: HashSet<_> = self.spaces.iter().map(|value| value.space_id).collect();
        let mut device_accounts = std::collections::HashMap::new();
        for account in &self.accounts {
            account.validate()?;
            if !account.household_ids.contains(&self.household.household_id) {
                return Err(ContractError::InconsistentReference("account households"));
            }
            for device_id in &account.device_ids {
                if device_accounts
                    .insert(*device_id, account.account_id)
                    .is_some()
                {
                    return Err(ContractError::DuplicateIdentifier(
                        "cross-account device IDs",
                    ));
                }
            }
        }

        if membership_ids != self.household.membership_ids.iter().copied().collect()
            || space_ids != self.household.space_ids.iter().copied().collect()
        {
            return Err(ContractError::InconsistentReference("household topology"));
        }

        let active_owners = self
            .memberships
            .iter()
            .filter(|membership| {
                membership.role == MembershipRole::Owner
                    && membership.state == MembershipState::Active
            })
            .count();
        if active_owners == 0 {
            return Err(ContractError::MissingActiveOwner);
        }

        for membership in &self.memberships {
            membership.validate()?;
            if !self
                .accounts
                .iter()
                .any(|account| account.account_id == membership.account_id)
                || membership.household_id != self.household.household_id
            {
                return Err(ContractError::InconsistentReference("membership scope"));
            }
        }

        for space in &self.spaces {
            space.validate()?;
            if space.household_id != self.household.household_id {
                return Err(ContractError::InconsistentReference("space household"));
            }
        }

        for member in &self.space_members {
            member.validate()?;
            let membership = self
                .memberships
                .iter()
                .find(|value| value.membership_id == member.membership_id)
                .ok_or(ContractError::InconsistentReference("space membership"))?;
            let space = self
                .spaces
                .iter()
                .find(|value| value.space_id == member.space_id)
                .ok_or(ContractError::InconsistentReference("space member space"))?;
            if membership.state != MembershipState::Active
                || device_accounts.get(&member.device_id) != Some(&membership.account_id)
                || member.key_generation != space.key_generation
            {
                return Err(ContractError::InconsistentReference("space member binding"));
            }
            if membership.role == MembershipRole::LegacyCollaborator
                || (member.access == SpaceAccess::Manage
                    && !matches!(
                        membership.role,
                        MembershipRole::Owner | MembershipRole::Organizer
                    ))
            {
                return Err(ContractError::InvalidRoleAccess);
            }
        }

        for space in self
            .spaces
            .iter()
            .filter(|space| space.kind == SpaceKind::Private)
        {
            let readable_members: HashSet<_> = self
                .space_members
                .iter()
                .filter(|member| member.space_id == space.space_id)
                .map(|member| member.membership_id)
                .collect();
            if readable_members.len() != 1 {
                return Err(ContractError::InvalidPrivateSpaceMembership);
            }
        }

        Ok(())
    }
}

impl SingleOwnerMigrationV1 {
    /// Builds the topology mapping for an existing local vault. The caller
    /// supplies existing opaque object IDs; no ciphertext or plaintext enters
    /// this function.
    #[must_use]
    pub fn new(existing_object_ids: impl IntoIterator<Item = ObjectId>) -> Self {
        let account_id = AccountId::new();
        let household_id = HouseholdId::new();
        let membership_id = MembershipId::new();
        let device_id = DeviceId::new();
        let space_id = SpaceId::new();
        let encrypted_profile_object_id = ObjectId::new();
        let encrypted_manifest_object_id = ObjectId::new();

        Self {
            format_version: DOMAIN_FORMAT_VERSION,
            topology: HouseholdTopologyV1 {
                format_version: DOMAIN_FORMAT_VERSION,
                accounts: vec![AccountV1 {
                    format_version: DOMAIN_FORMAT_VERSION,
                    account_id,
                    household_ids: vec![household_id],
                    device_ids: vec![device_id],
                }],
                household: HouseholdV1 {
                    format_version: DOMAIN_FORMAT_VERSION,
                    household_id,
                    encrypted_profile_object_id,
                    membership_ids: vec![membership_id],
                    space_ids: vec![space_id],
                    revision: 0,
                },
                memberships: vec![MembershipV1 {
                    format_version: DOMAIN_FORMAT_VERSION,
                    membership_id,
                    account_id,
                    household_id,
                    role: MembershipRole::Owner,
                    state: MembershipState::Active,
                    revision: 0,
                }],
                spaces: vec![SpaceV1 {
                    format_version: DOMAIN_FORMAT_VERSION,
                    space_id,
                    household_id,
                    kind: SpaceKind::Private,
                    encrypted_manifest_object_id,
                    key_generation: 1,
                    revision: 0,
                }],
                space_members: vec![SpaceMemberV1 {
                    format_version: DOMAIN_FORMAT_VERSION,
                    space_id,
                    membership_id,
                    access: SpaceAccess::Manage,
                    envelope_object_id: ObjectId::new(),
                    device_id,
                    key_generation: 1,
                    revision: 0,
                }],
            },
            private_space_id: space_id,
            object_assignments: existing_object_ids
                .into_iter()
                .map(|object_id| ObjectSpaceAssignmentV1 {
                    object_id,
                    space_id,
                })
                .collect(),
        }
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.format_version)?;
        self.topology.validate()?;
        bounded(
            "migrated objects",
            self.object_assignments.len(),
            MAX_MIGRATED_OBJECTS,
        )?;
        unique(
            "migrated object IDs",
            self.object_assignments.iter().map(|value| value.object_id),
        )?;
        for assignment in &self.object_assignments {
            require_non_nil("migrated object ID", assignment.object_id.0)?;
            require_non_nil("migration space ID", assignment.space_id.0)?;
        }
        let topology_object_ids: HashSet<_> =
            std::iter::once(self.topology.household.encrypted_profile_object_id)
                .chain(
                    self.topology
                        .spaces
                        .iter()
                        .map(|space| space.encrypted_manifest_object_id),
                )
                .chain(
                    self.topology
                        .space_members
                        .iter()
                        .map(|member| member.envelope_object_id),
                )
                .collect();
        if self
            .object_assignments
            .iter()
            .any(|assignment| topology_object_ids.contains(&assignment.object_id))
        {
            return Err(ContractError::DuplicateIdentifier(
                "migration/topology object IDs",
            ));
        }
        let private_space = self
            .topology
            .spaces
            .iter()
            .find(|space| space.space_id == self.private_space_id)
            .ok_or(ContractError::InconsistentReference(
                "migration private space",
            ))?;
        if private_space.kind != SpaceKind::Private
            || self
                .object_assignments
                .iter()
                .any(|assignment| assignment.space_id != self.private_space_id)
        {
            return Err(ContractError::InconsistentReference("migration assignment"));
        }
        Ok(())
    }
}

impl AccountV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.format_version)?;
        require_non_nil("account ID", self.account_id.0)?;
        bounded(
            "account households",
            self.household_ids.len(),
            MAX_HOUSEHOLDS_PER_ACCOUNT,
        )?;
        bounded(
            "account devices",
            self.device_ids.len(),
            MAX_DEVICES_PER_ACCOUNT,
        )?;
        if self.household_ids.is_empty() || self.device_ids.is_empty() {
            return Err(ContractError::EmptyCollection("account topology"));
        }
        unique("account household IDs", self.household_ids.iter().copied())?;
        unique("account device IDs", self.device_ids.iter().copied())?;
        for household_id in &self.household_ids {
            require_non_nil("account household ID", household_id.0)?;
        }
        for device_id in &self.device_ids {
            require_non_nil("account device ID", device_id.0)?;
        }
        Ok(())
    }
}

impl HouseholdV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.format_version)?;
        require_non_nil("household ID", self.household_id.0)?;
        require_non_nil(
            "encrypted household profile object ID",
            self.encrypted_profile_object_id.0,
        )?;
        validate_revision("household revision", self.revision)?;
        bounded(
            "household memberships",
            self.membership_ids.len(),
            MAX_MEMBERSHIPS_PER_HOUSEHOLD,
        )?;
        bounded(
            "household spaces",
            self.space_ids.len(),
            MAX_SPACES_PER_HOUSEHOLD,
        )?;
        if self.membership_ids.is_empty() || self.space_ids.is_empty() {
            return Err(ContractError::EmptyCollection("household topology"));
        }
        unique(
            "household membership IDs",
            self.membership_ids.iter().copied(),
        )?;
        unique("household space IDs", self.space_ids.iter().copied())?;
        for membership_id in &self.membership_ids {
            require_non_nil("household membership ID", membership_id.0)?;
        }
        for space_id in &self.space_ids {
            require_non_nil("household space ID", space_id.0)?;
        }
        Ok(())
    }
}

impl MembershipV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.format_version)?;
        require_non_nil("membership ID", self.membership_id.0)?;
        require_non_nil("membership account ID", self.account_id.0)?;
        require_non_nil("membership household ID", self.household_id.0)?;
        validate_revision("membership revision", self.revision)
    }
}

impl SpaceV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.format_version)?;
        require_non_nil("space ID", self.space_id.0)?;
        require_non_nil("space household ID", self.household_id.0)?;
        require_non_nil(
            "encrypted space manifest object ID",
            self.encrypted_manifest_object_id.0,
        )?;
        validate_key_generation(self.key_generation)?;
        validate_revision("space revision", self.revision)
    }
}

impl SpaceMemberV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.format_version)?;
        require_non_nil("space member space ID", self.space_id.0)?;
        require_non_nil("space member membership ID", self.membership_id.0)?;
        require_non_nil("space key envelope object ID", self.envelope_object_id.0)?;
        require_non_nil("space member device ID", self.device_id.0)?;
        validate_key_generation(self.key_generation)?;
        validate_revision("space member revision", self.revision)
    }
}

fn require_version(version: u16) -> Result<(), ContractError> {
    if version == DOMAIN_FORMAT_VERSION {
        Ok(())
    } else {
        Err(ContractError::UnsupportedFormat(version))
    }
}

fn require_non_nil(label: &'static str, value: Uuid) -> Result<(), ContractError> {
    if value.is_nil() {
        Err(ContractError::InvalidIdentifier(label))
    } else {
        Ok(())
    }
}

fn validate_revision(label: &'static str, value: u64) -> Result<(), ContractError> {
    if value <= MAX_WIRE_INTEGER {
        Ok(())
    } else {
        Err(ContractError::IntegerOutOfRange(label))
    }
}

fn validate_key_generation(value: u64) -> Result<(), ContractError> {
    if value == 0 {
        Err(ContractError::InvalidKeyGeneration)
    } else {
        validate_revision("space key generation", value)
    }
}

fn bounded(label: &'static str, actual: usize, maximum: usize) -> Result<(), ContractError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(ContractError::CollectionTooLarge {
            label,
            actual,
            maximum,
        })
    }
}

fn unique<T: Eq + std::hash::Hash>(
    label: &'static str,
    values: impl IntoIterator<Item = T>,
) -> Result<(), ContractError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(ContractError::DuplicateIdentifier(label));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("unsupported domain contract format version {0}")]
    UnsupportedFormat(u16),
    #[error("{label} contains {actual} entries; maximum is {maximum}")]
    CollectionTooLarge {
        label: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("{0} must not be empty")]
    EmptyCollection(&'static str),
    #[error("{0} contains a duplicate identifier")]
    DuplicateIdentifier(&'static str),
    #[error("{0} must be a non-nil UUID")]
    InvalidIdentifier(&'static str),
    #[error("inconsistent contract reference: {0}")]
    InconsistentReference(&'static str),
    #[error("a household must retain at least one active owner")]
    MissingActiveOwner,
    #[error("a private space must be readable by exactly one membership")]
    InvalidPrivateSpaceMembership,
    #[error("space key generation zero is reserved and invalid")]
    InvalidKeyGeneration,
    #[error("{0} exceeds the exact browser integer range")]
    IntegerOutOfRange(&'static str),
    #[error("membership role does not permit the requested space access")]
    InvalidRoleAccess,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_owner_migration_preserves_object_ids_and_validates() {
        let existing = vec![ObjectId::new(), ObjectId::new()];
        let migration = SingleOwnerMigrationV1::new(existing.clone());

        assert_eq!(
            migration
                .object_assignments
                .iter()
                .map(|assignment| assignment.object_id)
                .collect::<Vec<_>>(),
            existing
        );
        assert!(migration.validate().is_ok());
        assert_eq!(migration.topology.spaces[0].kind, SpaceKind::Private);
        assert_eq!(migration.topology.spaces[0].key_generation, 1);
    }

    #[test]
    fn contracts_serialize_without_human_readable_names() {
        let migration = SingleOwnerMigrationV1::new([ObjectId::new()]);
        let encoded = serde_json::to_string(&migration).expect("serialize migration");

        assert!(!encoded.contains("name"));
        assert!(!encoded.contains("email"));
        assert!(!encoded.contains("relationship"));
        assert!(encoded.contains("encrypted_profile_object_id"));
        assert!(encoded.contains("encrypted_manifest_object_id"));
    }

    #[test]
    fn unknown_fields_and_versions_fail_closed() {
        let migration = SingleOwnerMigrationV1::new([]);
        let mut value = serde_json::to_value(&migration).expect("serialize migration");
        value
            .as_object_mut()
            .expect("migration object")
            .insert("future_required_field".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<SingleOwnerMigrationV1>(value).is_err());

        let mut unsupported = migration;
        unsupported.format_version += 1;
        assert_eq!(
            unsupported.validate(),
            Err(ContractError::UnsupportedFormat(2))
        );
    }

    #[test]
    fn duplicate_assignments_are_rejected() {
        let object_id = ObjectId::new();
        let migration = SingleOwnerMigrationV1::new([object_id, object_id]);
        assert_eq!(
            migration.validate(),
            Err(ContractError::DuplicateIdentifier("migrated object IDs"))
        );
    }

    #[test]
    fn nil_ids_and_non_browser_safe_integers_are_rejected() {
        let mut migration = SingleOwnerMigrationV1::new([]);
        migration.topology.accounts[0].account_id = AccountId(Uuid::nil());
        assert_eq!(
            migration.validate(),
            Err(ContractError::InvalidIdentifier("account ID"))
        );

        let mut migration = SingleOwnerMigrationV1::new([]);
        migration.topology.household.revision = MAX_WIRE_INTEGER + 1;
        assert_eq!(
            migration.validate(),
            Err(ContractError::IntegerOutOfRange("household revision"))
        );

        let mut migration = SingleOwnerMigrationV1::new([]);
        migration.topology.spaces[0].key_generation = MAX_WIRE_INTEGER + 1;
        assert_eq!(
            migration.validate(),
            Err(ContractError::IntegerOutOfRange("space key generation"))
        );
    }

    #[test]
    fn private_spaces_reject_multiple_readable_memberships() {
        let mut migration = SingleOwnerMigrationV1::new([]);
        let second_membership = MembershipV1 {
            format_version: DOMAIN_FORMAT_VERSION,
            membership_id: MembershipId::new(),
            account_id: migration.topology.accounts[0].account_id,
            household_id: migration.topology.household.household_id,
            role: MembershipRole::Member,
            state: MembershipState::Active,
            revision: 0,
        };
        migration
            .topology
            .household
            .membership_ids
            .push(second_membership.membership_id);
        migration.topology.accounts[0]
            .device_ids
            .push(DeviceId::new());
        migration.topology.space_members.push(SpaceMemberV1 {
            format_version: DOMAIN_FORMAT_VERSION,
            space_id: migration.private_space_id,
            membership_id: second_membership.membership_id,
            access: SpaceAccess::Read,
            envelope_object_id: ObjectId::new(),
            device_id: migration.topology.accounts[0].device_ids[1],
            key_generation: 1,
            revision: 0,
        });
        migration.topology.memberships.push(second_membership);

        assert_eq!(
            migration.validate(),
            Err(ContractError::InvalidPrivateSpaceMembership)
        );
    }

    #[test]
    fn revoked_members_cannot_retain_space_envelopes() {
        let mut migration = SingleOwnerMigrationV1::new([]);
        migration.topology.memberships[0].state = MembershipState::Revoked;
        assert_eq!(migration.validate(), Err(ContractError::MissingActiveOwner));
    }

    #[test]
    fn key_generations_must_match_current_space_generation() {
        let mut migration = SingleOwnerMigrationV1::new([]);
        migration.topology.spaces[0].key_generation = 2;
        assert_eq!(
            migration.validate(),
            Err(ContractError::InconsistentReference("space member binding"))
        );
    }

    #[test]
    fn household_members_can_come_from_distinct_accounts() {
        let mut migration = SingleOwnerMigrationV1::new([]);
        let household_id = migration.topology.household.household_id;
        let collaborator_account_id = AccountId::new();
        let collaborator_device_id = DeviceId::new();
        let collaborator_membership_id = MembershipId::new();
        let shared_space_id = SpaceId::new();

        migration.topology.accounts.push(AccountV1 {
            format_version: DOMAIN_FORMAT_VERSION,
            account_id: collaborator_account_id,
            household_ids: vec![household_id],
            device_ids: vec![collaborator_device_id],
        });
        migration.topology.memberships.push(MembershipV1 {
            format_version: DOMAIN_FORMAT_VERSION,
            membership_id: collaborator_membership_id,
            account_id: collaborator_account_id,
            household_id,
            role: MembershipRole::FullCollaborator,
            state: MembershipState::Active,
            revision: 0,
        });
        migration
            .topology
            .household
            .membership_ids
            .push(collaborator_membership_id);
        migration.topology.spaces.push(SpaceV1 {
            format_version: DOMAIN_FORMAT_VERSION,
            space_id: shared_space_id,
            household_id,
            kind: SpaceKind::Shared,
            encrypted_manifest_object_id: ObjectId::new(),
            key_generation: 1,
            revision: 0,
        });
        migration.topology.household.space_ids.push(shared_space_id);
        migration.topology.space_members.push(SpaceMemberV1 {
            format_version: DOMAIN_FORMAT_VERSION,
            space_id: shared_space_id,
            membership_id: collaborator_membership_id,
            access: SpaceAccess::Edit,
            envelope_object_id: ObjectId::new(),
            device_id: collaborator_device_id,
            key_generation: 1,
            revision: 0,
        });

        assert!(migration.validate().is_ok());

        migration.topology.space_members[1].device_id =
            migration.topology.accounts[0].device_ids[0];
        assert_eq!(
            migration.validate(),
            Err(ContractError::InconsistentReference("space member binding"))
        );

        migration.topology.space_members[1].device_id = collaborator_device_id;
        migration.topology.space_members[1].access = SpaceAccess::Manage;
        assert_eq!(migration.validate(), Err(ContractError::InvalidRoleAccess));

        migration.topology.memberships[1].role = MembershipRole::LegacyCollaborator;
        migration.topology.space_members[1].access = SpaceAccess::Read;
        assert_eq!(migration.validate(), Err(ContractError::InvalidRoleAccess));
    }
}
