use std::collections::{HashMap, HashSet};

use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use crate::model::{OperationOutcome, StoredObject, WritePrecondition, validate_write_policy};
use vault_sync::{
    AccountId, DeviceId, HouseholdTopologyV1, MAX_DEVICES_PER_ACCOUNT, ObjectScopeV1,
    OpaqueMutationV1, TopologyAction,
};

#[derive(Clone)]
pub(crate) struct MetadataStore {
    pool: PgPool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthContext {
    pub account_id: Uuid,
    pub device_id: Uuid,
}

pub(crate) struct CommitResult {
    pub object: StoredObject,
    pub previous_storage_key: Option<String>,
    pub created: bool,
    pub replayed: bool,
}

pub(crate) struct RegisteredDevice {
    pub device_id: Uuid,
    pub encryption_public_key: Option<[u8; 32]>,
    pub signing_public_key: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TopologyWriteOutcome {
    Created,
    Updated,
    Replayed,
}

impl MetadataStore {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub(crate) async fn authenticate(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<AuthContext>, StoreError> {
        let row = sqlx::query(
            "SELECT device_id::text AS device_id, account_id::text AS account_id FROM devices \
             WHERE auth_token_sha256 = $1 AND revoked_at IS NULL",
        )
        .bind(token_hash.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(AuthContext {
                device_id: parse_uuid_column(&row, "device_id")?,
                account_id: parse_uuid_column(&row, "account_id")?,
            })
        })
        .transpose()
    }

    pub(crate) async fn create_account_with_device(
        &self,
        device_id: Uuid,
        encryption_public_key: &[u8; 32],
        signing_public_key: &[u8; 32],
        token_hash: &[u8; 32],
    ) -> Result<(Uuid, Uuid), AccountCreateError> {
        let account_id = Uuid::new_v4();
        let mut transaction = self.pool.begin().await?;
        sqlx::query("INSERT INTO accounts(account_id) VALUES ($1::uuid)")
            .bind(account_id.to_string())
            .execute(&mut *transaction)
            .await?;
        let insert = sqlx::query(
            "INSERT INTO devices( \
                device_id, account_id, device_public_key, signing_public_key, auth_token_sha256 \
             ) VALUES ($1::uuid, $2::uuid, $3, $4, $5)",
        )
        .bind(device_id.to_string())
        .bind(account_id.to_string())
        .bind(encryption_public_key.as_slice())
        .bind(signing_public_key.as_slice())
        .bind(token_hash.as_slice())
        .execute(&mut *transaction)
        .await;
        if let Err(error) = insert {
            if is_unique_violation(&error) {
                return Err(AccountCreateError::IdentifierConflict);
            }
            return Err(AccountCreateError::Database(error));
        }
        transaction.commit().await?;
        Ok((account_id, device_id))
    }

    pub(crate) async fn create_device(
        &self,
        account_id: Uuid,
        device_id: Uuid,
        encryption_public_key: &[u8; 32],
        signing_public_key: &[u8; 32],
        token_hash: &[u8; 32],
    ) -> Result<Uuid, DeviceCreateError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT account_id FROM accounts WHERE account_id = $1::uuid FOR UPDATE")
            .bind(account_id.to_string())
            .fetch_one(&mut *transaction)
            .await?;
        let active_devices = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM devices WHERE account_id = $1::uuid AND revoked_at IS NULL",
        )
        .bind(account_id.to_string())
        .fetch_one(&mut *transaction)
        .await?;
        if active_devices >= i64::try_from(MAX_DEVICES_PER_ACCOUNT).unwrap_or(i64::MAX) {
            return Err(DeviceCreateError::LimitReached);
        }
        let insert = sqlx::query(
            "INSERT INTO devices( \
                device_id, account_id, device_public_key, signing_public_key, auth_token_sha256 \
             ) VALUES ($1::uuid, $2::uuid, $3, $4, $5)",
        )
        .bind(device_id.to_string())
        .bind(account_id.to_string())
        .bind(encryption_public_key.as_slice())
        .bind(signing_public_key.as_slice())
        .bind(token_hash.as_slice())
        .execute(&mut *transaction)
        .await;
        if let Err(error) = insert {
            if is_unique_violation(&error) {
                return Err(DeviceCreateError::IdentifierConflict);
            }
            return Err(DeviceCreateError::Database(error));
        }
        transaction.commit().await?;
        Ok(device_id)
    }

    pub(crate) async fn list_active_devices(
        &self,
        account_id: Uuid,
    ) -> Result<Vec<RegisteredDevice>, StoreError> {
        let rows = sqlx::query(
            "SELECT device_id::text AS device_id, device_public_key, signing_public_key \
             FROM devices WHERE account_id = $1::uuid AND revoked_at IS NULL \
             ORDER BY created_at ASC, device_id ASC LIMIT $2",
        )
        .bind(account_id.to_string())
        .bind(i64::try_from(MAX_DEVICES_PER_ACCOUNT).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_registered_device).collect()
    }

    pub(crate) async fn revoke_device(
        &self,
        account_id: Uuid,
        device_id: Uuid,
    ) -> Result<bool, DeviceRevokeError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT account_id FROM accounts WHERE account_id = $1::uuid FOR UPDATE")
            .bind(account_id.to_string())
            .fetch_one(&mut *transaction)
            .await?;
        let target_active = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS( \
                SELECT 1 FROM devices \
                WHERE account_id = $1::uuid AND device_id = $2::uuid AND revoked_at IS NULL \
             )",
        )
        .bind(account_id.to_string())
        .bind(device_id.to_string())
        .fetch_one(&mut *transaction)
        .await?;
        if !target_active {
            return Ok(false);
        }
        let active_devices = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM devices WHERE account_id = $1::uuid AND revoked_at IS NULL",
        )
        .bind(account_id.to_string())
        .fetch_one(&mut *transaction)
        .await?;
        if active_devices <= 1 {
            return Err(DeviceRevokeError::LastActiveDevice);
        }
        let result = sqlx::query(
            "UPDATE devices SET revoked_at = now() \
             WHERE account_id = $1::uuid AND device_id = $2::uuid AND revoked_at IS NULL",
        )
        .bind(account_id.to_string())
        .bind(device_id.to_string())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub(crate) async fn get_household_topology(
        &self,
        household_id: Uuid,
    ) -> Result<Option<HouseholdTopologyV1>, StoreError> {
        let row = sqlx::query(
            "SELECT household_id::text AS household_id, revision, topology_json \
             FROM household_topologies WHERE household_id = $1::uuid",
        )
        .bind(household_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_topology).transpose()
    }

    pub(crate) async fn put_household_topology(
        &self,
        auth: AuthContext,
        topology: &HouseholdTopologyV1,
    ) -> Result<TopologyWriteOutcome, TopologyWriteError> {
        topology
            .validate()
            .map_err(|_| TopologyWriteError::InvalidContract)?;
        let household_id = topology.household.household_id.0;
        let candidate_revision = i64::try_from(topology.household.revision)
            .map_err(|_| TopologyWriteError::InvalidContract)?;
        let topology_json =
            serde_json::to_string(topology).map_err(|_| TopologyWriteError::InvalidContract)?;
        if topology_json.len() > 1024 * 1024 {
            return Err(TopologyWriteError::InvalidContract);
        }

        let mut transaction = self.pool.begin().await?;
        let current_row = sqlx::query(
            "SELECT household_id::text AS household_id, revision, topology_json \
             FROM household_topologies WHERE household_id = $1::uuid FOR UPDATE",
        )
        .bind(household_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?;
        let current = current_row.map(row_to_topology).transpose()?;

        if let Some(current) = &current {
            if !current
                .authorizes_device_scope(
                    AccountId(auth.account_id),
                    DeviceId(auth.device_id),
                    ObjectScopeV1::Household {
                        account_id: AccountId(auth.account_id),
                        household_id: current.household.household_id,
                    },
                    TopologyAction::Manage,
                )
                .map_err(|_| TopologyWriteError::InvalidContract)?
            {
                return Err(TopologyWriteError::Unauthorized);
            }
            match topology_update_outcome(current, topology)? {
                TopologyWriteOutcome::Replayed => {
                    transaction.commit().await?;
                    return Ok(TopologyWriteOutcome::Replayed);
                }
                TopologyWriteOutcome::Updated => {}
                TopologyWriteOutcome::Created => unreachable!("an existing topology is not new"),
            }
        } else {
            let bootstraps_auth = topology.accounts.len() == 1
                && topology.accounts[0].account_id.0 == auth.account_id
                && topology.household.revision == 0
                && topology
                    .authorizes_device_scope(
                        AccountId(auth.account_id),
                        DeviceId(auth.device_id),
                        ObjectScopeV1::Household {
                            account_id: AccountId(auth.account_id),
                            household_id: topology.household.household_id,
                        },
                        TopologyAction::Manage,
                    )
                    .map_err(|_| TopologyWriteError::InvalidContract)?;
            if !bootstraps_auth {
                return Err(TopologyWriteError::Unauthorized);
            }
        }

        let expected_accounts: HashSet<_> = topology
            .accounts
            .iter()
            .map(|account| account.account_id.0.to_string())
            .collect();
        let expected_devices: HashMap<_, _> = topology
            .accounts
            .iter()
            .flat_map(|account| {
                let account_id = account.account_id.0.to_string();
                account
                    .device_ids
                    .iter()
                    .map(move |device_id| (device_id.0.to_string(), account_id.clone()))
            })
            .collect();
        let account_ids: Vec<_> = expected_accounts.iter().cloned().collect();
        let actual_accounts = sqlx::query_scalar::<_, String>(
            "SELECT accounts.account_id::text \
             FROM unnest($1::text[]) AS requested(account_id) \
             JOIN accounts ON accounts.account_id = requested.account_id::uuid \
             ORDER BY accounts.account_id \
             FOR SHARE OF accounts",
        )
        .bind(&account_ids)
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .collect();
        let actual_devices = if expected_devices.is_empty() {
            HashMap::new()
        } else {
            let device_ids: Vec<_> = expected_devices.keys().cloned().collect();
            sqlx::query(
                "SELECT devices.device_id::text AS device_id, \
                        devices.account_id::text AS account_id \
                 FROM unnest($1::text[]) AS requested(device_id) \
                 JOIN devices ON devices.device_id = requested.device_id::uuid \
                 WHERE devices.revoked_at IS NULL \
                 ORDER BY devices.device_id \
                 FOR SHARE OF devices",
            )
            .bind(&device_ids)
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .map(|row| (row.get("device_id"), row.get("account_id")))
            .collect()
        };
        if !principal_sets_match(
            &expected_accounts,
            &expected_devices,
            &actual_accounts,
            &actual_devices,
        ) {
            return Err(TopologyWriteError::UnknownPrincipal);
        }

        if current.is_some() {
            sqlx::query(
                "UPDATE household_topologies \
                 SET revision = $2, topology_json = $3, updated_at = now() \
                 WHERE household_id = $1::uuid",
            )
            .bind(household_id.to_string())
            .bind(candidate_revision)
            .bind(&topology_json)
            .execute(&mut *transaction)
            .await?;
        } else {
            sqlx::query(
                "INSERT INTO household_topologies(household_id, revision, topology_json) \
                 VALUES ($1::uuid, $2, $3)",
            )
            .bind(household_id.to_string())
            .bind(candidate_revision)
            .bind(&topology_json)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(if current.is_some() {
            TopologyWriteOutcome::Updated
        } else {
            TopologyWriteOutcome::Created
        })
    }

    pub(crate) async fn get_object(
        &self,
        account_id: Uuid,
        object_id: Uuid,
    ) -> Result<Option<StoredObject>, StoreError> {
        let row = sqlx::query(
            "SELECT account_id::text AS account_id, object_id::text AS object_id, revision, ciphertext_size_bytes, ciphertext_sha256, \
                    change_seq, storage_key, object_header_json \
             FROM ciphertext_objects WHERE account_id = $1::uuid AND object_id = $2::uuid",
        )
        .bind(account_id.to_string())
        .bind(object_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_object).transpose()
    }

    pub(crate) async fn list_objects(
        &self,
        account_id: Uuid,
        after: i64,
        limit: i64,
    ) -> Result<Vec<StoredObject>, StoreError> {
        let rows = sqlx::query(
            "SELECT account_id::text AS account_id, object_id::text AS object_id, revision, ciphertext_size_bytes, ciphertext_sha256, \
                    change_seq, storage_key, object_header_json \
             FROM ciphertext_objects \
             WHERE account_id = $1::uuid AND change_seq > $2 \
             ORDER BY change_seq ASC LIMIT $3",
        )
        .bind(account_id.to_string())
        .bind(after)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_object).collect()
    }

    pub(crate) async fn get_operation(
        &self,
        account_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Option<OperationOutcome>, StoreError> {
        let row = sqlx::query(
            "SELECT account_id::text AS account_id, object_id::text AS object_id, request_sha256, object_header_json, storage_key, change_seq, created \
             FROM sync_operations \
             WHERE account_id = $1::uuid AND operation_id = $2::uuid",
        )
        .bind(account_id.to_string())
        .bind(operation_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_operation).transpose()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn commit_object(
        &self,
        auth: AuthContext,
        mutation: &OpaqueMutationV1,
        precondition: &WritePrecondition,
        ciphertext_size_bytes: i64,
        ciphertext_sha256: [u8; 32],
        storage_key: &str,
        request_sha256: [u8; 32],
    ) -> Result<CommitResult, CommitError> {
        let object_id = mutation.object.object_id.0;
        let account_id = auth.account_id;
        let candidate_revision =
            i64::try_from(mutation.object.revision).map_err(|_| CommitError::PreconditionFailed)?;
        let header_json =
            serde_json::to_string(&mutation.object).map_err(|_| CommitError::InvalidContract)?;
        let mut transaction = self.pool.begin().await?;

        let account_exists = sqlx::query_scalar::<_, i64>(
            "SELECT sync_cursor FROM accounts WHERE account_id = $1::uuid FOR UPDATE",
        )
        .bind(account_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?;
        if account_exists.is_none() {
            return Err(CommitError::AccountMissing);
        }

        match mutation.object.scope {
            ObjectScopeV1::Account { account_id: scope } if scope.0 == account_id => {}
            ObjectScopeV1::Household { household_id, .. }
            | ObjectScopeV1::Space { household_id, .. } => {
                let topology_row = sqlx::query(
                    "SELECT household_id::text AS household_id, revision, topology_json \
                     FROM household_topologies WHERE household_id = $1::uuid FOR SHARE",
                )
                .bind(household_id.0.to_string())
                .fetch_optional(&mut *transaction)
                .await?;
                let topology = topology_row.map(row_to_topology).transpose()?;
                let authorized = topology
                    .as_ref()
                    .map(|topology| {
                        topology.authorizes_device_scope(
                            AccountId(account_id),
                            DeviceId(auth.device_id),
                            mutation.object.scope,
                            TopologyAction::Write,
                        )
                    })
                    .transpose()
                    .map_err(|_| CommitError::InvalidContract)?
                    .unwrap_or(false);
                if !authorized {
                    return Err(CommitError::UnauthorizedScope);
                }
            }
            ObjectScopeV1::Account { .. } => return Err(CommitError::UnauthorizedScope),
        }

        let operation_row = sqlx::query(
            "SELECT account_id::text AS account_id, object_id::text AS object_id, request_sha256, object_header_json, storage_key, change_seq, created \
             FROM sync_operations \
             WHERE account_id = $1::uuid AND operation_id = $2::uuid FOR UPDATE",
        )
        .bind(account_id.to_string())
        .bind(mutation.operation_id.0.to_string())
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(row) = operation_row {
            let outcome = row_to_operation(row)?;
            if outcome.request_sha256 != request_sha256 {
                return Err(CommitError::OperationConflict);
            }
            return Ok(CommitResult {
                object: StoredObject {
                    object_id: outcome.header.object_id.0,
                    revision: i64::try_from(outcome.header.revision)
                        .map_err(|_| CommitError::InvalidContract)?,
                    ciphertext_size_bytes: i64::try_from(outcome.header.ciphertext_size_bytes)
                        .map_err(|_| CommitError::InvalidContract)?,
                    ciphertext_sha256: outcome.header.ciphertext_sha256,
                    change_seq: outcome.change_seq,
                    storage_key: outcome.storage_key,
                    header: outcome.header,
                },
                previous_storage_key: None,
                created: outcome.created,
                replayed: true,
            });
        }

        let current_row = sqlx::query(
            "SELECT account_id::text AS account_id, object_id::text AS object_id, revision, ciphertext_size_bytes, ciphertext_sha256, \
                    change_seq, storage_key, object_header_json \
             FROM ciphertext_objects \
             WHERE account_id = $1::uuid AND object_id = $2::uuid FOR UPDATE",
        )
        .bind(account_id.to_string())
        .bind(object_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?;
        let current = current_row.map(row_to_object).transpose()?;
        validate_write_policy(current.as_ref(), candidate_revision, precondition)
            .map_err(|_| CommitError::PreconditionFailed)?;

        let change_seq = sqlx::query_scalar::<_, i64>(
            "UPDATE accounts SET sync_cursor = sync_cursor + 1, updated_at = now() \
             WHERE account_id = $1::uuid RETURNING sync_cursor",
        )
        .bind(account_id.to_string())
        .fetch_one(&mut *transaction)
        .await?;

        if current.is_some() {
            sqlx::query(
                "UPDATE ciphertext_objects \
                 SET revision = $3, ciphertext_size_bytes = $4, ciphertext_sha256 = $5, \
                     change_seq = $6, storage_key = $7, object_header_json = $8, updated_at = now() \
                 WHERE account_id = $1::uuid AND object_id = $2::uuid",
            )
            .bind(account_id.to_string())
            .bind(object_id.to_string())
            .bind(candidate_revision)
            .bind(ciphertext_size_bytes)
            .bind(ciphertext_sha256.as_slice())
            .bind(change_seq)
            .bind(storage_key)
            .bind(&header_json)
            .execute(&mut *transaction)
            .await?;
        } else {
            sqlx::query(
                "INSERT INTO ciphertext_objects( \
                    account_id, object_id, revision, ciphertext_size_bytes, ciphertext_sha256, \
                    change_seq, storage_key, object_header_json \
                 ) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)",
            )
            .bind(account_id.to_string())
            .bind(object_id.to_string())
            .bind(candidate_revision)
            .bind(ciphertext_size_bytes)
            .bind(ciphertext_sha256.as_slice())
            .bind(change_seq)
            .bind(storage_key)
            .bind(&header_json)
            .execute(&mut *transaction)
            .await?;
        }

        sqlx::query(
            "INSERT INTO sync_operations( \
                account_id, operation_id, request_sha256, object_id, object_header_json, storage_key, change_seq, created \
             ) VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6, $7, $8)",
        )
        .bind(account_id.to_string())
        .bind(mutation.operation_id.0.to_string())
        .bind(request_sha256.as_slice())
        .bind(object_id.to_string())
        .bind(&header_json)
        .bind(storage_key)
        .bind(change_seq)
        .bind(current.is_none())
        .execute(&mut *transaction)
        .await?;

        transaction
            .commit()
            .await
            .map_err(CommitError::CommitOutcomeUnknown)?;
        let previous_storage_key = current.as_ref().map(|object| object.storage_key.clone());
        Ok(CommitResult {
            object: StoredObject {
                object_id,
                revision: candidate_revision,
                ciphertext_size_bytes,
                ciphertext_sha256,
                change_seq,
                storage_key: storage_key.to_owned(),
                header: mutation.object.clone(),
            },
            previous_storage_key,
            created: current.is_none(),
            replayed: false,
        })
    }
}

fn topology_update_outcome(
    current: &HouseholdTopologyV1,
    candidate: &HouseholdTopologyV1,
) -> Result<TopologyWriteOutcome, TopologyWriteError> {
    if candidate == current {
        return Ok(TopologyWriteOutcome::Replayed);
    }
    if current.household.revision.checked_add(1) == Some(candidate.household.revision) {
        return Ok(TopologyWriteOutcome::Updated);
    }
    Err(TopologyWriteError::PreconditionFailed)
}

fn row_to_object(row: sqlx::postgres::PgRow) -> Result<StoredObject, StoreError> {
    let hash: Vec<u8> = row.get("ciphertext_sha256");
    let ciphertext_sha256 = hash
        .try_into()
        .map_err(|_| StoreError::InvalidCiphertextHash)?;
    let account_id = parse_uuid_column(&row, "account_id")?;
    let object_id = parse_uuid_column(&row, "object_id")?;
    let revision = row.get("revision");
    let ciphertext_size_bytes = row.get("ciphertext_size_bytes");
    let header = parse_header(row.get("object_header_json"))?;
    if header.scope.account_id().0 != account_id
        || header.object_id.0 != object_id
        || i64::try_from(header.revision).ok() != Some(revision)
        || i64::try_from(header.ciphertext_size_bytes).ok() != Some(ciphertext_size_bytes)
        || header.ciphertext_sha256 != ciphertext_sha256
    {
        return Err(StoreError::InvalidObjectHeader);
    }
    Ok(StoredObject {
        object_id,
        revision,
        ciphertext_size_bytes,
        ciphertext_sha256,
        change_seq: row.get("change_seq"),
        storage_key: row.get("storage_key"),
        header,
    })
}

fn row_to_operation(row: sqlx::postgres::PgRow) -> Result<OperationOutcome, StoreError> {
    let hash: Vec<u8> = row.get("request_sha256");
    let account_id = parse_uuid_column(&row, "account_id")?;
    let object_id = parse_uuid_column(&row, "object_id")?;
    let header = parse_header(row.get("object_header_json"))?;
    if header.scope.account_id().0 != account_id || header.object_id.0 != object_id {
        return Err(StoreError::InvalidObjectHeader);
    }
    Ok(OperationOutcome {
        request_sha256: hash
            .try_into()
            .map_err(|_| StoreError::InvalidCiphertextHash)?,
        header,
        change_seq: row.get("change_seq"),
        created: row.get("created"),
        storage_key: row.get("storage_key"),
    })
}

fn row_to_topology(row: sqlx::postgres::PgRow) -> Result<HouseholdTopologyV1, StoreError> {
    let household_id = parse_uuid_column(&row, "household_id")?;
    let revision: i64 = row.get("revision");
    let topology: HouseholdTopologyV1 = serde_json::from_str(row.get("topology_json"))
        .map_err(|_| StoreError::InvalidHouseholdTopology)?;
    topology
        .validate()
        .map_err(|_| StoreError::InvalidHouseholdTopology)?;
    if topology.household.household_id.0 != household_id
        || i64::try_from(topology.household.revision).ok() != Some(revision)
    {
        return Err(StoreError::InvalidHouseholdTopology);
    }
    Ok(topology)
}

fn row_to_registered_device(row: sqlx::postgres::PgRow) -> Result<RegisteredDevice, StoreError> {
    Ok(RegisteredDevice {
        device_id: parse_uuid_column(&row, "device_id")?,
        encryption_public_key: parse_optional_32_bytes(&row, "device_public_key")?,
        signing_public_key: parse_optional_32_bytes(&row, "signing_public_key")?,
    })
}

fn principal_sets_match(
    expected_accounts: &HashSet<String>,
    expected_devices: &HashMap<String, String>,
    actual_accounts: &HashSet<String>,
    actual_devices: &HashMap<String, String>,
) -> bool {
    expected_accounts == actual_accounts && expected_devices == actual_devices
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database| database.code())
        .as_deref()
        == Some("23505")
}

fn parse_optional_32_bytes(
    row: &sqlx::postgres::PgRow,
    column: &'static str,
) -> Result<Option<[u8; 32]>, StoreError> {
    let value: Option<Vec<u8>> = row.get(column);
    value
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| StoreError::InvalidDevicePublicKey)
        })
        .transpose()
}

fn parse_header(value: String) -> Result<vault_sync::OpaqueObjectHeaderV1, StoreError> {
    let header = serde_json::from_str(&value).map_err(|_| StoreError::InvalidObjectHeader)?;
    vault_sync::OpaqueObjectHeaderV1::validate(&header)
        .map_err(|_| StoreError::InvalidObjectHeader)?;
    Ok(header)
}

fn parse_uuid_column(
    row: &sqlx::postgres::PgRow,
    column: &'static str,
) -> Result<Uuid, StoreError> {
    let value: String = row.get(column);
    Uuid::parse_str(&value).map_err(|_| StoreError::InvalidUuid)
}

#[derive(Debug, Error)]
pub(crate) enum StoreError {
    #[error("PostgreSQL operation failed")]
    Database(#[from] sqlx::Error),
    #[error("stored ciphertext hash has invalid length")]
    InvalidCiphertextHash,
    #[error("stored UUID metadata is invalid")]
    InvalidUuid,
    #[error("stored opaque object header is invalid")]
    InvalidObjectHeader,
    #[error("stored household topology is invalid")]
    InvalidHouseholdTopology,
    #[error("stored device public key is invalid")]
    InvalidDevicePublicKey,
}

#[derive(Debug, Error)]
pub(crate) enum AccountCreateError {
    #[error("PostgreSQL operation failed")]
    Database(#[from] sqlx::Error),
    #[error("the device identifier is already registered")]
    IdentifierConflict,
}

#[derive(Debug, Error)]
pub(crate) enum DeviceCreateError {
    #[error("PostgreSQL operation failed")]
    Database(#[from] sqlx::Error),
    #[error("the active device limit was reached")]
    LimitReached,
    #[error("the device identifier is already registered")]
    IdentifierConflict,
}

#[derive(Debug, Error)]
pub(crate) enum DeviceRevokeError {
    #[error("PostgreSQL operation failed")]
    Database(#[from] sqlx::Error),
    #[error("the account must retain an active device")]
    LastActiveDevice,
}

#[derive(Debug, Error)]
pub(crate) enum TopologyWriteError {
    #[error("PostgreSQL operation failed")]
    Database(#[from] sqlx::Error),
    #[error("stored topology metadata is invalid")]
    Store(#[from] StoreError),
    #[error("topology contract is invalid")]
    InvalidContract,
    #[error("device is not authorized to manage the household")]
    Unauthorized,
    #[error("topology revision precondition failed")]
    PreconditionFailed,
    #[error("topology references an unknown or revoked principal")]
    UnknownPrincipal,
}

#[derive(Debug, Error)]
pub(crate) enum CommitError {
    #[error("PostgreSQL operation failed")]
    Database(#[from] sqlx::Error),
    #[error("PostgreSQL commit outcome is unknown")]
    CommitOutcomeUnknown(sqlx::Error),
    #[error("stored ciphertext metadata is invalid")]
    Store(#[from] StoreError),
    #[error("write precondition failed")]
    PreconditionFailed,
    #[error("authenticated account no longer exists")]
    AccountMissing,
    #[error("operation ID was already used for a different mutation")]
    OperationConflict,
    #[error("device is not authorized for the object scope")]
    UnauthorizedScope,
    #[error("mutation contract could not be persisted")]
    InvalidContract,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topology() -> HouseholdTopologyV1 {
        serde_json::from_str(include_str!(
            "../../../crates/vault-sync/fixtures/household_topology_v1.json"
        ))
        .expect("parse shared topology fixture")
    }

    #[test]
    fn topology_transition_accepts_exact_replay_and_only_the_next_revision() {
        let current = topology();
        assert_eq!(
            topology_update_outcome(&current, &current).ok(),
            Some(TopologyWriteOutcome::Replayed)
        );

        let mut next = current.clone();
        next.household.revision = 1;
        assert_eq!(
            topology_update_outcome(&current, &next).ok(),
            Some(TopologyWriteOutcome::Updated)
        );

        let mut divergent = current.clone();
        divergent.spaces[0].revision = 1;
        assert!(matches!(
            topology_update_outcome(&current, &divergent),
            Err(TopologyWriteError::PreconditionFailed)
        ));

        let mut skipped = current.clone();
        skipped.household.revision = 2;
        assert!(matches!(
            topology_update_outcome(&current, &skipped),
            Err(TopologyWriteError::PreconditionFailed)
        ));
    }

    #[test]
    fn topology_principal_comparison_requires_exact_account_and_device_ownership() {
        let expected_accounts = HashSet::from(["account-a".to_owned(), "account-b".to_owned()]);
        let expected_devices = HashMap::from([
            ("device-a".to_owned(), "account-a".to_owned()),
            ("device-b".to_owned(), "account-b".to_owned()),
        ]);

        assert!(principal_sets_match(
            &expected_accounts,
            &expected_devices,
            &expected_accounts,
            &expected_devices,
        ));

        let missing_account = HashSet::from(["account-a".to_owned()]);
        assert!(!principal_sets_match(
            &expected_accounts,
            &expected_devices,
            &missing_account,
            &expected_devices,
        ));

        let wrong_owner = HashMap::from([
            ("device-a".to_owned(), "account-b".to_owned()),
            ("device-b".to_owned(), "account-b".to_owned()),
        ]);
        assert!(!principal_sets_match(
            &expected_accounts,
            &expected_devices,
            &expected_accounts,
            &wrong_owner,
        ));
    }
}
