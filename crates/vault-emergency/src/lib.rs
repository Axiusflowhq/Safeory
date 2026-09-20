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
    #[error("access policy does not authorize this release request")]
    ReleaseDenied,
    #[error("release request time moved backwards")]
    TimeRewind,
    #[error("release request time overflowed")]
    TimeOverflow,
    #[error("approval is not authorized for this release request")]
    UnauthorizedApprover,
    #[error("release request transition conflicts with terminal state")]
    InvalidReleaseTransition,
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

/// Durable-state shape for a local timed-release simulation. The future server
/// coordinator may persist an equivalent state machine, but this portable core
/// intentionally performs no I/O and never handles vault decryption keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseRequest {
    request_id: Uuid,
    trustee_id: Uuid,
    what: String,
    condition: AccessCondition,
    item_revision: u64,
    requested_at: u64,
    last_event_at: u64,
    state_revision: u64,
    grant: AccessGrant,
    approvals: BTreeSet<Uuid>,
    state: ReleaseRequestState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseRequestState {
    Pending,
    Released {
        released_at: u64,
        expires_at: Option<u64>,
    },
    Denied {
        denied_at: u64,
    },
    Revoked {
        revoked_at: u64,
    },
}

/// Effective access state after applying policy/revision fencing and time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseStatus {
    PolicyChanged,
    AwaitingApprovals {
        required: u8,
        received: u8,
    },
    Waiting {
        not_before: u64,
        remaining_seconds: u64,
    },
    Eligible,
    Released {
        permission: Permission,
        released_at: u64,
        expires_at: Option<u64>,
    },
    Expired {
        expired_at: u64,
    },
    Denied,
    Revoked,
}

impl ReleaseRequest {
    #[must_use]
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    #[must_use]
    pub fn trustee_id(&self) -> Uuid {
        self.trustee_id
    }

    #[must_use]
    pub fn what(&self) -> &str {
        &self.what
    }

    #[must_use]
    pub fn condition(&self) -> AccessCondition {
        self.condition
    }

    #[must_use]
    pub fn item_revision(&self) -> u64 {
        self.item_revision
    }

    #[must_use]
    pub fn requested_at(&self) -> u64 {
        self.requested_at
    }

    #[must_use]
    pub fn state_revision(&self) -> u64 {
        self.state_revision
    }

    #[must_use]
    pub fn state(&self) -> ReleaseRequestState {
        self.state
    }

    #[must_use]
    pub fn approvals(&self) -> &BTreeSet<Uuid> {
        &self.approvals
    }

    fn check_time(&self, now: u64) -> Result<(), EmergencyError> {
        if now < self.last_event_at {
            return Err(EmergencyError::TimeRewind);
        }
        Ok(())
    }

    fn policy_matches(&self, policy: &AccessPolicy, current_item_revision: u64) -> bool {
        if current_item_revision != self.item_revision || validate_access_policy(policy).is_err() {
            return false;
        }
        if policy.destruction == Some(LegacyCondition::Death)
            && self.condition == AccessCondition::Death
        {
            return false;
        }
        if policy.private_forever && self.condition == AccessCondition::Death {
            return false;
        }
        policy.grants.iter().any(|grant| grant == &self.grant)
    }

    pub fn status(
        &self,
        policy: &AccessPolicy,
        current_item_revision: u64,
        now: u64,
    ) -> Result<ReleaseStatus, EmergencyError> {
        self.check_time(now)?;
        match self.state {
            ReleaseRequestState::Denied { .. } => return Ok(ReleaseStatus::Denied),
            ReleaseRequestState::Revoked { .. } => return Ok(ReleaseStatus::Revoked),
            ReleaseRequestState::Pending | ReleaseRequestState::Released { .. } => {}
        }
        if !self.policy_matches(policy, current_item_revision) {
            return Ok(ReleaseStatus::PolicyChanged);
        }
        match self.state {
            ReleaseRequestState::Released {
                released_at,
                expires_at,
            } => {
                if let Some(expired_at) = expires_at
                    && now >= expired_at
                {
                    return Ok(ReleaseStatus::Expired { expired_at });
                }
                return Ok(ReleaseStatus::Released {
                    permission: self.grant.permission,
                    released_at,
                    expires_at,
                });
            }
            ReleaseRequestState::Pending => {}
            ReleaseRequestState::Denied { .. } | ReleaseRequestState::Revoked { .. } => {
                unreachable!("terminal release states return before policy validation")
            }
        }

        if self.grant.approvals_required > 0 {
            let received = u8::try_from(
                self.grant
                    .approver_ids
                    .intersection(&self.approvals)
                    .count(),
            )
            .unwrap_or(u8::MAX);
            if received < self.grant.approvals_required {
                return Ok(ReleaseStatus::AwaitingApprovals {
                    required: self.grant.approvals_required,
                    received,
                });
            }
        }

        let not_before = self
            .requested_at
            .checked_add(self.grant.wait_period.seconds())
            .ok_or(EmergencyError::TimeOverflow)?;
        if now < not_before {
            return Ok(ReleaseStatus::Waiting {
                not_before,
                remaining_seconds: not_before - now,
            });
        }
        Ok(ReleaseStatus::Eligible)
    }

    /// Add one configured approver. Repeating the same approval is an
    /// idempotent no-op and does not advance the request revision.
    pub fn approve(&mut self, approver_id: Uuid, now: u64) -> Result<bool, EmergencyError> {
        self.check_time(now)?;
        if !matches!(self.state, ReleaseRequestState::Pending) {
            return Err(EmergencyError::InvalidReleaseTransition);
        }
        if !self.grant.approver_ids.contains(&approver_id) {
            return Err(EmergencyError::UnauthorizedApprover);
        }
        if !self.approvals.insert(approver_id) {
            return Ok(false);
        }
        self.last_event_at = now;
        self.state_revision = self
            .state_revision
            .checked_add(1)
            .ok_or(EmergencyError::TimeOverflow)?;
        Ok(true)
    }

    /// Owner-side denial is terminal. Retrying denial is idempotent.
    pub fn deny(&mut self, now: u64) -> Result<bool, EmergencyError> {
        self.check_time(now)?;
        match self.state {
            ReleaseRequestState::Denied { .. } => return Ok(false),
            ReleaseRequestState::Pending => {}
            ReleaseRequestState::Released { .. } | ReleaseRequestState::Revoked { .. } => {
                return Err(EmergencyError::InvalidReleaseTransition);
            }
        }
        self.state = ReleaseRequestState::Denied { denied_at: now };
        self.last_event_at = now;
        self.state_revision = self
            .state_revision
            .checked_add(1)
            .ok_or(EmergencyError::TimeOverflow)?;
        Ok(true)
    }

    /// Revocation is terminal and may cancel either a pending or already
    /// released request. Retrying revocation is idempotent.
    pub fn revoke(&mut self, now: u64) -> Result<bool, EmergencyError> {
        self.check_time(now)?;
        match self.state {
            ReleaseRequestState::Revoked { .. } => return Ok(false),
            ReleaseRequestState::Denied { .. } => {
                return Err(EmergencyError::InvalidReleaseTransition);
            }
            ReleaseRequestState::Pending | ReleaseRequestState::Released { .. } => {}
        }
        self.state = ReleaseRequestState::Revoked { revoked_at: now };
        self.last_event_at = now;
        self.state_revision = self
            .state_revision
            .checked_add(1)
            .ok_or(EmergencyError::TimeOverflow)?;
        Ok(true)
    }

    /// Release only when the exact original item revision/policy still matches,
    /// every required approval exists, and the waiting period has elapsed.
    /// Repeating release after success is an idempotent no-op.
    pub fn release(
        &mut self,
        policy: &AccessPolicy,
        current_item_revision: u64,
        now: u64,
    ) -> Result<ReleaseStatus, EmergencyError> {
        self.check_time(now)?;
        let status = self.status(policy, current_item_revision, now)?;
        if !matches!(status, ReleaseStatus::Eligible) {
            return Ok(status);
        }
        let expires_at = self
            .grant
            .duration
            .seconds()
            .map(|seconds| now.checked_add(seconds).ok_or(EmergencyError::TimeOverflow))
            .transpose()?;
        self.state = ReleaseRequestState::Released {
            released_at: now,
            expires_at,
        };
        self.last_event_at = now;
        self.state_revision = self
            .state_revision
            .checked_add(1)
            .ok_or(EmergencyError::TimeOverflow)?;
        Ok(ReleaseStatus::Released {
            permission: self.grant.permission,
            released_at: now,
            expires_at,
        })
    }
}

/// Start a local release simulation for the exact current item revision.
/// Invalid/denied policy never creates a request object.
pub fn begin_release_request(
    policy: &AccessPolicy,
    what: &str,
    condition: AccessCondition,
    trustee_id: Uuid,
    item_revision: u64,
    requested_at: u64,
) -> Result<ReleaseRequest, EmergencyError> {
    if validate_access_policy(policy).is_err()
        || (policy.destruction == Some(LegacyCondition::Death)
            && condition == AccessCondition::Death)
        || (policy.private_forever && condition == AccessCondition::Death)
    {
        return Err(EmergencyError::ReleaseDenied);
    }
    let grant = policy
        .grants
        .iter()
        .find(|grant| {
            grant.trustee_id == trustee_id && grant.what == what && grant.condition == condition
        })
        .cloned()
        .ok_or(EmergencyError::ReleaseDenied)?;
    requested_at
        .checked_add(grant.wait_period.seconds())
        .ok_or(EmergencyError::TimeOverflow)?;
    if let Some(duration) = grant.duration.seconds() {
        requested_at
            .checked_add(grant.wait_period.seconds())
            .and_then(|not_before| not_before.checked_add(duration))
            .ok_or(EmergencyError::TimeOverflow)?;
    }
    Ok(ReleaseRequest {
        request_id: Uuid::new_v4(),
        trustee_id,
        what: what.to_owned(),
        condition,
        item_revision,
        requested_at,
        last_event_at: requested_at,
        state_revision: 1,
        grant,
        approvals: BTreeSet::new(),
        state: ReleaseRequestState::Pending,
    })
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

    fn timed_grant(
        trustee_id: Uuid,
        condition: AccessCondition,
        wait_period: WaitPeriod,
        duration: GrantDuration,
        approvals_required: u8,
        approver_ids: &[Uuid],
    ) -> AccessGrant {
        AccessGrant::new(
            trustee_id,
            "record",
            Permission::View,
            condition,
            wait_period,
            duration,
            approvals_required,
            approver_ids.iter().copied().collect(),
        )
        .expect("valid timed grant")
    }

    #[test]
    fn timed_release_waits_then_releases_and_expires() {
        let trustee = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        policy
            .add_grant(timed_grant(
                trustee,
                AccessCondition::Emergency,
                WaitPeriod::OneHour,
                GrantDuration::OneHour,
                0,
                &[],
            ))
            .expect("add grant");

        let mut request = begin_release_request(
            &policy,
            "record",
            AccessCondition::Emergency,
            trustee,
            7,
            1_000,
        )
        .expect("begin request");
        assert_eq!(request.state_revision(), 1);
        assert_eq!(
            request.status(&policy, 7, 1_100).expect("status"),
            ReleaseStatus::Waiting {
                not_before: 4_600,
                remaining_seconds: 3_500,
            }
        );
        assert_eq!(
            request.release(&policy, 7, 4_599).expect("not ready"),
            ReleaseStatus::Waiting {
                not_before: 4_600,
                remaining_seconds: 1,
            }
        );
        assert_eq!(request.state_revision(), 1);
        assert_eq!(
            request.release(&policy, 7, 4_600).expect("release"),
            ReleaseStatus::Released {
                permission: Permission::View,
                released_at: 4_600,
                expires_at: Some(8_200),
            }
        );
        assert_eq!(request.state_revision(), 2);
        assert_eq!(
            request
                .release(&policy, 7, 4_700)
                .expect("idempotent release"),
            ReleaseStatus::Released {
                permission: Permission::View,
                released_at: 4_600,
                expires_at: Some(8_200),
            }
        );
        assert_eq!(request.state_revision(), 2);
        assert_eq!(
            request.status(&policy, 7, 8_200).expect("expired"),
            ReleaseStatus::Expired { expired_at: 8_200 }
        );
    }

    #[test]
    fn timed_release_requires_distinct_configured_approvals() {
        let trustee = Uuid::new_v4();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let outsider = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        policy
            .add_grant(timed_grant(
                trustee,
                AccessCondition::Incapacity,
                WaitPeriod::Immediate,
                GrantDuration::UntilRevoked,
                2,
                &[first, second],
            ))
            .expect("add grant");
        let mut request = begin_release_request(
            &policy,
            "record",
            AccessCondition::Incapacity,
            trustee,
            3,
            500,
        )
        .expect("begin request");

        assert_eq!(
            request.status(&policy, 3, 500).expect("status"),
            ReleaseStatus::AwaitingApprovals {
                required: 2,
                received: 0,
            }
        );
        assert!(matches!(
            request.approve(outsider, 501),
            Err(EmergencyError::UnauthorizedApprover)
        ));
        assert!(request.approve(first, 501).expect("first approval"));
        let revision_after_first = request.state_revision();
        assert!(!request.approve(first, 501).expect("duplicate approval"));
        assert_eq!(request.state_revision(), revision_after_first);
        assert_eq!(
            request.status(&policy, 3, 501).expect("one approval"),
            ReleaseStatus::AwaitingApprovals {
                required: 2,
                received: 1,
            }
        );
        assert!(request.approve(second, 502).expect("second approval"));
        assert_eq!(
            request.status(&policy, 3, 502).expect("eligible"),
            ReleaseStatus::Eligible
        );
    }

    #[test]
    fn item_revision_or_grant_change_invalidates_pending_and_released_requests() {
        let trustee = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        policy
            .add_grant(timed_grant(
                trustee,
                AccessCondition::Emergency,
                WaitPeriod::Immediate,
                GrantDuration::UntilRevoked,
                0,
                &[],
            ))
            .expect("add grant");
        let mut request = begin_release_request(
            &policy,
            "record",
            AccessCondition::Emergency,
            trustee,
            12,
            100,
        )
        .expect("begin request");

        assert_eq!(
            request
                .release(&policy, 13, 100)
                .expect("revision mismatch"),
            ReleaseStatus::PolicyChanged
        );
        assert!(matches!(request.state(), ReleaseRequestState::Pending));

        let mut changed_policy = policy.clone();
        changed_policy.grants[0].permission = Permission::Download;
        assert_eq!(
            request
                .release(&changed_policy, 12, 100)
                .expect("grant mismatch"),
            ReleaseStatus::PolicyChanged
        );

        assert!(matches!(
            request.release(&policy, 12, 100).expect("release"),
            ReleaseStatus::Released { .. }
        ));
        assert_eq!(
            request.status(&policy, 13, 101).expect("post-release edit"),
            ReleaseStatus::PolicyChanged
        );
    }

    #[test]
    fn owner_deny_and_revoke_are_terminal_and_idempotent() {
        let trustee = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        policy
            .add_grant(timed_grant(
                trustee,
                AccessCondition::Emergency,
                WaitPeriod::OneDay,
                GrantDuration::UntilRevoked,
                0,
                &[],
            ))
            .expect("add grant");
        let mut denied = begin_release_request(
            &policy,
            "record",
            AccessCondition::Emergency,
            trustee,
            1,
            10,
        )
        .expect("begin denied request");
        assert!(denied.deny(11).expect("deny"));
        let denied_revision = denied.state_revision();
        assert!(!denied.deny(12).expect("idempotent deny"));
        assert_eq!(denied.state_revision(), denied_revision);
        assert_eq!(
            denied
                .status(&AccessPolicy::new(true), 999, 13)
                .expect("terminal deny"),
            ReleaseStatus::Denied
        );
        assert!(matches!(
            denied.revoke(13),
            Err(EmergencyError::InvalidReleaseTransition)
        ));

        let mut released = begin_release_request(
            &policy,
            "record",
            AccessCondition::Emergency,
            trustee,
            1,
            100,
        )
        .expect("begin revoke request");
        assert!(released.revoke(101).expect("revoke pending"));
        let revoked_revision = released.state_revision();
        assert!(!released.revoke(102).expect("idempotent revoke"));
        assert_eq!(released.state_revision(), revoked_revision);
        assert_eq!(
            released
                .status(&AccessPolicy::new(true), 999, 103)
                .expect("terminal revoke"),
            ReleaseStatus::Revoked
        );
    }

    #[test]
    fn released_access_can_be_revoked_before_duration_expires() {
        let trustee = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        policy
            .add_grant(timed_grant(
                trustee,
                AccessCondition::Emergency,
                WaitPeriod::Immediate,
                GrantDuration::SevenDays,
                0,
                &[],
            ))
            .expect("add grant");
        let mut request = begin_release_request(
            &policy,
            "record",
            AccessCondition::Emergency,
            trustee,
            5,
            1_000,
        )
        .expect("begin request");
        assert!(matches!(
            request.release(&policy, 5, 1_000).expect("release"),
            ReleaseStatus::Released { .. }
        ));
        assert!(request.revoke(1_001).expect("revoke released"));
        assert_eq!(
            request.status(&policy, 5, 1_002).expect("revoked status"),
            ReleaseStatus::Revoked
        );
    }

    #[test]
    fn release_request_rejects_time_rewind_and_overflow() {
        let trustee = Uuid::new_v4();
        let approver = Uuid::new_v4();
        let mut policy = AccessPolicy::new(true);
        policy
            .add_grant(timed_grant(
                trustee,
                AccessCondition::Emergency,
                WaitPeriod::OneHour,
                GrantDuration::UntilRevoked,
                1,
                &[approver],
            ))
            .expect("add grant");
        let mut request = begin_release_request(
            &policy,
            "record",
            AccessCondition::Emergency,
            trustee,
            2,
            1_000,
        )
        .expect("begin request");
        request.approve(approver, 1_100).expect("approve");
        assert!(matches!(
            request.status(&policy, 2, 1_099),
            Err(EmergencyError::TimeRewind)
        ));
        assert!(matches!(
            request.release(&policy, 2, 1_099),
            Err(EmergencyError::TimeRewind)
        ));

        let mut overflow_policy = AccessPolicy::new(true);
        overflow_policy
            .add_grant(timed_grant(
                trustee,
                AccessCondition::Emergency,
                WaitPeriod::OneHour,
                GrantDuration::UntilRevoked,
                0,
                &[],
            ))
            .expect("add overflow grant");
        assert!(matches!(
            begin_release_request(
                &overflow_policy,
                "record",
                AccessCondition::Emergency,
                trustee,
                1,
                u64::MAX - 100,
            ),
            Err(EmergencyError::TimeOverflow)
        ));
    }

    #[test]
    fn release_request_creation_fails_closed_for_ungranted_or_destroyed_access() {
        let trustee = Uuid::new_v4();
        assert!(matches!(
            begin_release_request(
                &AccessPolicy::new(true),
                "record",
                AccessCondition::Emergency,
                trustee,
                1,
                0,
            ),
            Err(EmergencyError::ReleaseDenied)
        ));

        let mut destroy = AccessPolicy::new(true);
        destroy
            .add_grant(timed_grant(
                trustee,
                AccessCondition::Death,
                WaitPeriod::Immediate,
                GrantDuration::UntilRevoked,
                0,
                &[],
            ))
            .expect("add death grant");
        destroy.destroy_on(LegacyCondition::Death);
        assert!(matches!(
            begin_release_request(&destroy, "record", AccessCondition::Death, trustee, 1, 0,),
            Err(EmergencyError::ReleaseDenied)
        ));
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
