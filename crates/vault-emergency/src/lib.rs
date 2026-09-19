#![forbid(unsafe_code)]

//! Local Trust Engine: conditional access policies, waiting periods, and
//! threshold recovery. Evaluated in the portable Rust core on encrypted-payload
//! policy data; enforcement stays local-first. A self-hosted backend may later
//! coordinate release timing using durable transactional state, but it can
//! never decrypt vault contents.

use blahaj::{Share, Sharks};
use std::collections::BTreeSet;
use std::convert::TryFrom;
use thiserror::Error;
use uuid::Uuid;
use vault_crypto::{AccountRootKey, RecoverySecret};
use vault_models::validate_access_policy;
pub use vault_models::{
    AccessCondition, AccessGrant, AccessPolicy, GrantDuration, LegacyCondition, Permission,
    WaitPeriod,
};
use vault_sharing::{DeviceKeyPair, ShareEnvelopeV2, SharePurpose};
use zeroize::Zeroizing;

const MIN_SECRET_SHARES_LEN: usize = 2;

#[derive(Error, Debug)]
pub enum EmergencyError {
    #[error("threshold configuration is invalid")]
    InvalidThreshold,
    #[error("recovery share bytes are invalid")]
    InvalidShare,
    #[error("not enough distinct shares to reconstruct the secret")]
    InsufficientShares,
    #[error("reconstructed secret has an unexpected length")]
    InconsistentSecret,
    #[error("sharing operation failed")]
    Sharing(#[from] vault_sharing::SharingError),
    #[error("cryptographic operation failed")]
    Crypto(#[from] vault_crypto::CryptoError),
}

/// Distinct approvals presented when requesting access.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApprovalProof {
    pub approver_ids: BTreeSet<Uuid>,
}

impl ApprovalProof {
    #[must_use]
    pub fn new<I: IntoIterator<Item = Uuid>>(approver_ids: I) -> Self {
        Self {
            approver_ids: approver_ids.into_iter().collect(),
        }
    }
}

/// Fail-closed evaluation result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessDecision {
    Denied,
    AwaitingApprovals {
        required: u8,
        received: u8,
    },
    Waiting {
        seconds: u64,
    },
    Granted {
        permission: Permission,
        duration_seconds: Option<u64>,
    },
    Destroyed,
}

/// Evaluates the policy for `trustee_id` and object scope `what` under `condition`.
///
/// Enforcement order per the Trust Engine spec: destruction/deny wins over
/// release, private-forever blocks death grants, explicit grants only, then
/// approvals, then waiting period.
#[must_use]
pub fn evaluate(
    policy: &AccessPolicy,
    what: &str,
    condition: AccessCondition,
    trustee_id: Uuid,
    approvals: &ApprovalProof,
) -> AccessDecision {
    if validate_access_policy(policy).is_err() {
        return AccessDecision::Denied;
    }
    if policy.destruction == Some(LegacyCondition::Death) && condition == AccessCondition::Death {
        return AccessDecision::Destroyed;
    }
    if policy.private_forever && condition == AccessCondition::Death {
        return AccessDecision::Denied;
    }
    let Some(grant) = policy
        .grants
        .iter()
        .find(|g| g.trustee_id == trustee_id && g.what == what && g.condition == condition)
    else {
        return AccessDecision::Denied;
    };
    if grant.approvals_required > 0 {
        let received = u8::try_from(
            grant
                .approver_ids
                .intersection(&approvals.approver_ids)
                .count(),
        )
        .unwrap_or(u8::MAX);
        if received < grant.approvals_required {
            return AccessDecision::AwaitingApprovals {
                required: grant.approvals_required,
                received,
            };
        }
    }
    let seconds = grant.wait_period.seconds();
    if seconds > 0 {
        return AccessDecision::Waiting { seconds };
    }
    AccessDecision::Granted {
        permission: grant.permission,
        duration_seconds: grant.duration.seconds(),
    }
}

/// Splits a 32-byte secret (capsule key or recovery secret) into `total_shares`
/// Shamir shares with `threshold` required for reconstruction.
///
/// Standard Shamir secret sharing over GF(256) via the reviewed `blahaj`
/// crate (the maintained fork carrying the RUSTSEC-2024-0398 coefficient-bias
/// fix); no custom threshold crypto. Thresholds below 2 are rejected so a
/// single share can never reconstruct a secret.
pub fn split_secret(
    secret: &[u8; 32],
    threshold: u8,
    total_shares: u8,
) -> Result<Vec<Vec<u8>>, EmergencyError> {
    if threshold < MIN_SECRET_SHARES_LEN as u8 || total_shares < threshold {
        return Err(EmergencyError::InvalidThreshold);
    }
    let sharks = Sharks(threshold);
    Ok(sharks
        .dealer(secret.as_slice())
        .take(usize::from(total_shares))
        .map(|share| Vec::from(&share))
        .collect())
}

fn recover_secret_bytes<I>(threshold: u8, shares: I) -> Result<[u8; 32], EmergencyError>
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    if threshold < MIN_SECRET_SHARES_LEN as u8 {
        return Err(EmergencyError::InvalidThreshold);
    }
    let sharks = Sharks(threshold);
    let parsed: Vec<Share> = shares
        .into_iter()
        .map(|share| Share::try_from(share.as_ref()).map_err(|_| EmergencyError::InvalidShare))
        .collect::<Result<_, _>>()?;
    let secret = sharks
        .recover(&parsed)
        .map_err(|_| EmergencyError::InsufficientShares)?;
    if secret.len() != 32 {
        return Err(EmergencyError::InconsistentSecret);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&secret);
    Ok(key)
}

/// Reconstructs a 32-byte capsule key from at least `threshold` shares.
pub fn recover_capsule_key<I>(threshold: u8, shares: I) -> Result<[u8; 32], EmergencyError>
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    recover_secret_bytes(threshold, shares)
}

/// Reconstructs the recovery secret from threshold shares.
pub fn recover_recovery_secret<I>(
    threshold: u8,
    shares: I,
) -> Result<RecoverySecret, EmergencyError>
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    Ok(RecoverySecret::from_bytes(recover_secret_bytes(
        threshold, shares,
    )?))
}

/// Full no-backdoor recovery path: threshold shares of the recovery secret,
/// then unwrapping the root key from the recovery-kit envelope.
pub fn recover_root_key<I>(
    recovery_kit_wrap: &vault_crypto::RecoveryKitWrapV1,
    threshold: u8,
    shares: I,
) -> Result<AccountRootKey, EmergencyError>
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    let secret = recover_recovery_secret(threshold, shares)?;
    Ok(vault_crypto::unwrap_root_key_with_recovery_secret(
        &secret,
        recovery_kit_wrap,
    )?)
}

/// Seals one recovery share to a trusted person's device public key. The
/// backend only ever transports the returned envelope.
pub fn seal_recovery_share(
    sender: &DeviceKeyPair,
    recipient_public: &[u8; 32],
    share_bytes: &[u8],
) -> Result<ShareEnvelopeV2, EmergencyError> {
    if share_bytes.len() < MIN_SECRET_SHARES_LEN {
        return Err(EmergencyError::InvalidShare);
    }
    Ok(vault_sharing::seal(
        sender,
        recipient_public,
        share_bytes,
        SharePurpose::RecoveryShare,
    )?)
}

/// Opens a recovery-share envelope that was sealed for this device.
pub fn open_recovery_share(
    envelope: &ShareEnvelopeV2,
    recipient: &DeviceKeyPair,
    sender_public: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, EmergencyError> {
    Ok(vault_sharing::open(
        envelope,
        recipient,
        sender_public,
        SharePurpose::RecoveryShare,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_crypto::{decrypt_item, encrypt_item};
    use vault_models::VaultItem;

    fn grant(
        trustee_id: Uuid,
        condition: AccessCondition,
        wait_period: WaitPeriod,
        approvals_required: u8,
        approver_ids: &[Uuid],
    ) -> AccessGrant {
        AccessGrant::new(
            trustee_id,
            "life-insurance",
            Permission::View,
            condition,
            wait_period,
            GrantDuration::UntilRevoked,
            approvals_required,
            approver_ids.iter().copied().collect(),
        )
        .expect("valid grant")
    }

    #[test]
    fn owner_only_default_denies_every_trustee() {
        let policy = AccessPolicy::new(true);
        assert_eq!(
            evaluate(
                &policy,
                "life-insurance",
                AccessCondition::Emergency,
                Uuid::new_v4(),
                &ApprovalProof::default()
            ),
            AccessDecision::Denied
        );
    }

    #[test]
    fn hospitalized_wife_gets_immediate_view_access() {
        let wife = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        policy
            .add_grant(grant(
                wife,
                AccessCondition::Emergency,
                WaitPeriod::Immediate,
                0,
                &[],
            ))
            .expect("add grant");

        assert_eq!(
            evaluate(
                &policy,
                "life-insurance",
                AccessCondition::Emergency,
                wife,
                &ApprovalProof::default()
            ),
            AccessDecision::Granted {
                permission: Permission::View,
                duration_seconds: None,
            }
        );
        // Normal life stays private, and an unrelated trustee is denied.
        assert_eq!(
            evaluate(
                &policy,
                "life-insurance",
                AccessCondition::Normal,
                wife,
                &ApprovalProof::default()
            ),
            AccessDecision::Denied
        );
        assert_eq!(
            evaluate(
                &policy,
                "life-insurance",
                AccessCondition::Emergency,
                Uuid::new_v4(),
                &ApprovalProof::default()
            ),
            AccessDecision::Denied
        );
    }

    #[test]
    fn manual_emergency_request_waits_configured_period() {
        let wife = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        policy
            .add_grant(grant(
                wife,
                AccessCondition::Emergency,
                WaitPeriod::Custom(48 * 3_600),
                0,
                &[],
            ))
            .expect("add grant");

        assert_eq!(
            evaluate(
                &policy,
                "life-insurance",
                AccessCondition::Emergency,
                wife,
                &ApprovalProof::default()
            ),
            AccessDecision::Waiting {
                seconds: 48 * 3_600
            }
        );
    }

    #[test]
    fn multi_person_approval_requires_the_full_threshold() {
        let trustee = Uuid::new_v4();
        let father = Uuid::new_v4();
        let brother = Uuid::new_v4();
        let lawyer = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        policy
            .add_grant(grant(
                trustee,
                AccessCondition::Incapacity,
                WaitPeriod::Immediate,
                2,
                &[father, brother, lawyer],
            ))
            .expect("add grant");

        let one = evaluate(
            &policy,
            "life-insurance",
            AccessCondition::Incapacity,
            trustee,
            &ApprovalProof::new([father]),
        );
        assert_eq!(
            one,
            AccessDecision::AwaitingApprovals {
                required: 2,
                received: 1
            }
        );

        // An outsider's approval does not count toward the declared pool.
        let outsider = Uuid::new_v4();
        let with_outsider = evaluate(
            &policy,
            "life-insurance",
            AccessCondition::Incapacity,
            trustee,
            &ApprovalProof::new([father, outsider]),
        );
        assert_eq!(
            with_outsider,
            AccessDecision::AwaitingApprovals {
                required: 2,
                received: 1
            }
        );

        let two = evaluate(
            &policy,
            "life-insurance",
            AccessCondition::Incapacity,
            trustee,
            &ApprovalProof::new([lawyer, brother]),
        );
        assert_eq!(
            two,
            AccessDecision::Granted {
                permission: Permission::View,
                duration_seconds: None,
            }
        );
    }

    #[test]
    fn death_grants_are_permanent_but_private_forever_blocks_them() {
        let wife = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        policy
            .add_grant(grant(
                wife,
                AccessCondition::Death,
                WaitPeriod::Immediate,
                0,
                &[],
            ))
            .expect("add grant");
        assert_eq!(
            evaluate(
                &policy,
                "life-insurance",
                AccessCondition::Death,
                wife,
                &ApprovalProof::default()
            ),
            AccessDecision::Granted {
                permission: Permission::View,
                duration_seconds: None,
            }
        );

        let mut private_policy = AccessPolicy::new(true);
        private_policy.set_private_forever();
        private_policy
            .add_grant(grant(
                wife,
                AccessCondition::Death,
                WaitPeriod::Immediate,
                0,
                &[],
            ))
            .expect("add grant");
        assert_eq!(
            evaluate(
                &private_policy,
                "life-insurance",
                AccessCondition::Death,
                wife,
                &ApprovalProof::default()
            ),
            AccessDecision::Denied
        );
    }

    #[test]
    fn destruction_wins_over_release() {
        let wife = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        policy.destroy_on(LegacyCondition::Death);
        policy
            .add_grant(grant(
                wife,
                AccessCondition::Death,
                WaitPeriod::Immediate,
                0,
                &[],
            ))
            .expect("add grant");
        assert_eq!(
            evaluate(
                &policy,
                "life-insurance",
                AccessCondition::Death,
                wife,
                &ApprovalProof::default()
            ),
            AccessDecision::Destroyed
        );
        assert_eq!(
            evaluate(
                &policy,
                "life-insurance",
                AccessCondition::Emergency,
                wife,
                &ApprovalProof::default()
            ),
            AccessDecision::Denied
        );
    }

    #[test]
    fn invalid_grants_are_rejected() {
        let trustee = Uuid::new_v4();
        let approver = Uuid::new_v4();

        // Empty `what`.
        assert!(
            AccessGrant::new(
                trustee,
                "",
                Permission::View,
                AccessCondition::Emergency,
                WaitPeriod::Immediate,
                GrantDuration::UntilRevoked,
                0,
                BTreeSet::new(),
            )
            .is_err()
        );

        // Threshold above the declared approver pool.
        assert!(
            AccessGrant::new(
                trustee,
                "vault",
                Permission::View,
                AccessCondition::Incapacity,
                WaitPeriod::Immediate,
                GrantDuration::UntilRevoked,
                2,
                [approver].into_iter().collect(),
            )
            .is_err()
        );

        // Self-approval is not allowed.
        assert!(
            AccessGrant::new(
                trustee,
                "vault",
                Permission::View,
                AccessCondition::Incapacity,
                WaitPeriod::Immediate,
                GrantDuration::UntilRevoked,
                1,
                [trustee].into_iter().collect(),
            )
            .is_err()
        );

        // Degenerate custom waiting period.
        assert!(
            AccessGrant::new(
                trustee,
                "vault",
                Permission::View,
                AccessCondition::Emergency,
                WaitPeriod::Custom(0),
                GrantDuration::UntilRevoked,
                0,
                BTreeSet::new(),
            )
            .is_err()
        );

        // Oversized approver pool is rejected so counting stays exact.
        let pool: BTreeSet<Uuid> = (0..17).map(|_| Uuid::new_v4()).collect();
        assert!(
            AccessGrant::new(
                trustee,
                "vault",
                Permission::View,
                AccessCondition::Emergency,
                WaitPeriod::Immediate,
                GrantDuration::UntilRevoked,
                2,
                pool,
            )
            .is_err()
        );
    }

    #[test]
    fn regranting_same_scope_replaces_the_old_rule() {
        let wife = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        policy
            .add_grant(grant(
                wife,
                AccessCondition::Emergency,
                WaitPeriod::SevenDays,
                0,
                &[],
            ))
            .expect("add grant");
        policy
            .add_grant(grant(
                wife,
                AccessCondition::Emergency,
                WaitPeriod::OneDay,
                0,
                &[],
            ))
            .expect("replace grant");

        assert_eq!(policy.grants.len(), 1);
        assert_eq!(
            evaluate(
                &policy,
                "life-insurance",
                AccessCondition::Emergency,
                wife,
                &ApprovalProof::default()
            ),
            AccessDecision::Waiting { seconds: 86_400 }
        );
    }

    #[test]
    fn evaluation_selects_the_requested_grant_scope() {
        let trustee = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        policy
            .add_grant(
                AccessGrant::new(
                    trustee,
                    "life-insurance",
                    Permission::View,
                    AccessCondition::Emergency,
                    WaitPeriod::Immediate,
                    GrantDuration::UntilRevoked,
                    0,
                    BTreeSet::new(),
                )
                .expect("first grant"),
            )
            .expect("add first grant");
        policy
            .add_grant(
                AccessGrant::new(
                    trustee,
                    "house-deed",
                    Permission::Download,
                    AccessCondition::Emergency,
                    WaitPeriod::Immediate,
                    GrantDuration::UntilRevoked,
                    0,
                    BTreeSet::new(),
                )
                .expect("second grant"),
            )
            .expect("add second grant");

        assert_eq!(
            evaluate(
                &policy,
                "house-deed",
                AccessCondition::Emergency,
                trustee,
                &ApprovalProof::default(),
            ),
            AccessDecision::Granted {
                permission: Permission::Download,
                duration_seconds: None,
            }
        );
        assert_eq!(
            evaluate(
                &policy,
                "missing-scope",
                AccessCondition::Emergency,
                trustee,
                &ApprovalProof::default(),
            ),
            AccessDecision::Denied
        );
    }

    #[test]
    fn replacing_existing_scope_succeeds_at_grant_limit() {
        let trustee = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        for index in 0..vault_models::MAX_ACCESS_GRANTS {
            policy
                .add_grant(
                    AccessGrant::new(
                        trustee,
                        format!("scope-{index}"),
                        Permission::View,
                        AccessCondition::Emergency,
                        WaitPeriod::Immediate,
                        GrantDuration::UntilRevoked,
                        0,
                        BTreeSet::new(),
                    )
                    .expect("valid grant"),
                )
                .expect("fill grant capacity");
        }

        policy
            .add_grant(
                AccessGrant::new(
                    trustee,
                    "scope-0",
                    Permission::Manage,
                    AccessCondition::Emergency,
                    WaitPeriod::Immediate,
                    GrantDuration::UntilRevoked,
                    0,
                    BTreeSet::new(),
                )
                .expect("replacement grant"),
            )
            .expect("replacement at capacity");

        assert_eq!(policy.grants.len(), vault_models::MAX_ACCESS_GRANTS);
        assert_eq!(policy.grants[0].permission, Permission::Manage);
        assert!(
            policy
                .add_grant(
                    AccessGrant::new(
                        trustee,
                        "overflow",
                        Permission::View,
                        AccessCondition::Emergency,
                        WaitPeriod::Immediate,
                        GrantDuration::UntilRevoked,
                        0,
                        BTreeSet::new(),
                    )
                    .expect("overflow grant shape"),
                )
                .is_err()
        );
    }

    #[test]
    fn threshold_secret_sharing_recovers_with_any_two_of_three() {
        let secret = [0x37u8; 32];
        let shares = split_secret(&secret, 2, 3).expect("split");
        assert_eq!(shares.len(), 3);

        let combo_a = recover_capsule_key(2, [&shares[0], &shares[1]]).expect("recover a");
        let combo_b = recover_capsule_key(2, [&shares[1], &shares[2]]).expect("recover b");
        let combo_c = recover_capsule_key(2, [&shares[0], &shares[2]]).expect("recover c");
        assert_eq!(combo_a, secret);
        assert_eq!(combo_b, secret);
        assert_eq!(combo_c, secret);

        assert!(recover_capsule_key(2, [&shares[0]]).is_err());
        assert!(split_secret(&secret, 1, 3).is_err());
        assert!(split_secret(&secret, 4, 3).is_err());
        assert!(recover_capsule_key(2, [&shares[0], &shares[0]]).is_err());
        assert!(recover_capsule_key(2, [vec![1u8], vec![2u8]]).is_err());
    }

    #[test]
    fn end_to_end_social_recovery_without_vendor_assistance() {
        use vault_crypto::RecoverySecret;

        let root = AccountRootKey::generate().expect("root key");
        let secret = RecoverySecret::generate().expect("recovery secret");
        let kit_wrap =
            vault_crypto::wrap_root_key_with_recovery_secret(&secret, &root).expect("kit wrap");
        let item = VaultItem::secure_note("house deed", "readable only after recovery");
        let encrypted = encrypt_item(&root, &item, 1).expect("encrypt item");

        let shares = split_secret(secret.as_bytes(), 2, 3).expect("split recovery secret");
        let owner = DeviceKeyPair::generate().expect("owner device");
        let wife = DeviceKeyPair::generate().expect("wife device");
        let brother = DeviceKeyPair::generate().expect("brother device");
        let lawyer = DeviceKeyPair::generate().expect("lawyer device");

        let wife_envelope =
            seal_recovery_share(&owner, &wife.public_bytes(), &shares[0]).expect("seal wife share");
        let brother_envelope = seal_recovery_share(&owner, &brother.public_bytes(), &shares[1])
            .expect("seal brother share");
        let lawyer_envelope = seal_recovery_share(&owner, &lawyer.public_bytes(), &shares[2])
            .expect("seal lawyer share");

        // Each device can only open its own envelope.
        let wife_share =
            open_recovery_share(&wife_envelope, &wife, &owner.public_bytes()).expect("open wife");
        let lawyer_share = open_recovery_share(&lawyer_envelope, &lawyer, &owner.public_bytes())
            .expect("open lawyer");
        assert!(
            open_recovery_share(&brother_envelope, &wife, &owner.public_bytes()).is_err(),
            "wife must not open the brother's envelope"
        );

        // One share alone is not enough; two distinct shares recover the vault.
        assert!(recover_root_key(&kit_wrap, 2, [wife_share.as_slice()]).is_err());
        let recovered_root = recover_root_key(
            &kit_wrap,
            2,
            [wife_share.as_slice(), lawyer_share.as_slice()],
        )
        .expect("recover root key");
        let decrypted =
            decrypt_item(&recovered_root, &encrypted).expect("decrypt with recovered root");
        assert_eq!(decrypted.title, "house deed");
    }
}
