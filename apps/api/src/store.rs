use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use crate::model::{OperationOutcome, StoredObject, WritePrecondition, validate_write_policy};
use vault_sync::OpaqueMutationV1;

#[derive(Clone)]
pub(crate) struct MetadataStore {
    pool: PgPool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthContext {
    pub account_id: Uuid,
    pub _device_id: Uuid,
}

pub(crate) struct CommitResult {
    pub object: StoredObject,
    pub previous_storage_key: Option<String>,
    pub created: bool,
    pub replayed: bool,
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
                _device_id: parse_uuid_column(&row, "device_id")?,
                account_id: parse_uuid_column(&row, "account_id")?,
            })
        })
        .transpose()
    }

    pub(crate) async fn create_account_with_device(
        &self,
        public_key: &[u8; 32],
        token_hash: &[u8; 32],
    ) -> Result<(Uuid, Uuid), StoreError> {
        let account_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let mut transaction = self.pool.begin().await?;
        sqlx::query("INSERT INTO accounts(account_id) VALUES ($1::uuid)")
            .bind(account_id.to_string())
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "INSERT INTO devices(device_id, account_id, device_public_key, auth_token_sha256) \
             VALUES ($1::uuid, $2::uuid, $3, $4)",
        )
        .bind(device_id.to_string())
        .bind(account_id.to_string())
        .bind(public_key.as_slice())
        .bind(token_hash.as_slice())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok((account_id, device_id))
    }

    pub(crate) async fn create_device(
        &self,
        account_id: Uuid,
        public_key: &[u8; 32],
        token_hash: &[u8; 32],
    ) -> Result<Uuid, StoreError> {
        let device_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO devices(device_id, account_id, device_public_key, auth_token_sha256) \
             VALUES ($1::uuid, $2::uuid, $3, $4)",
        )
        .bind(device_id.to_string())
        .bind(account_id.to_string())
        .bind(public_key.as_slice())
        .bind(token_hash.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(device_id)
    }

    pub(crate) async fn revoke_device(
        &self,
        account_id: Uuid,
        device_id: Uuid,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE devices SET revoked_at = now() \
             WHERE account_id = $1::uuid AND device_id = $2::uuid AND revoked_at IS NULL",
        )
        .bind(account_id.to_string())
        .bind(device_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
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
        account_id: Uuid,
        mutation: &OpaqueMutationV1,
        precondition: &WritePrecondition,
        ciphertext_size_bytes: i64,
        ciphertext_sha256: [u8; 32],
        storage_key: &str,
        request_sha256: [u8; 32],
    ) -> Result<CommitResult, CommitError> {
        let object_id = mutation.object.object_id.0;
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
    #[error("mutation contract could not be persisted")]
    InvalidContract,
}
