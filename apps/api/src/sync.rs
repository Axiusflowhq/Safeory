use std::collections::HashMap;

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, ETAG},
    },
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;
use uuid::Uuid;
use vault_sync::{
    AccountId, DeviceId, HouseholdId, HouseholdTopologyV1, ObjectId, ObjectScopeV1,
    OpaqueMutationV1, TopologyAction,
};

use crate::{
    AppState,
    auth::{
        bearer_token, constant_time_eq, device_token_hash, generate_device_token, hex_encode,
        parse_public_key_hex, registration_token_hash,
    },
    model::{
        DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT, ObjectMetadataResponse, OperationOutcome, PolicyError,
        StoredObject, WritePrecondition, strong_etag, validate_write_policy,
    },
    store::{
        AccountCreateError, AuthContext, CommitError, DeviceCreateError, DeviceRevokeError,
        StoreError, TopologyWriteError, TopologyWriteOutcome,
    },
};

pub(crate) const MAX_CIPHERTEXT_OBJECT_BYTES: usize =
    vault_sync::MAX_SYNC_CIPHERTEXT_BYTES as usize;
pub(crate) const MAX_TOPOLOGY_BYTES: usize = 1024 * 1024;
const MUTATION_HEADER: &str = "x-safeory-mutation";
const CHANGE_SEQ_HEADER: &str = "x-safeory-change-seq";
const MAX_MUTATION_HEADER_BYTES: usize = 8 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegisterDeviceRequest {
    device_id: Uuid,
    encryption_public_key: String,
    signing_public_key: String,
}

#[derive(Debug, Serialize)]
struct DeviceCredentialsResponse {
    account_id: Uuid,
    device_id: Uuid,
    device_token: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct DeviceInventoryEntry {
    device_id: Uuid,
    encryption_public_key: Option<String>,
    signing_public_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DeviceInventoryResponse {
    current_device_id: Uuid,
    devices: Vec<DeviceInventoryEntry>,
}

pub(crate) async fn create_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<impl IntoResponse, ApiError> {
    authorize_registration(&state, &headers)?;
    let (device_id, encryption_public_key, signing_public_key) =
        parse_device_registration(&request)?;
    let (device_token, token_hash) = generate_device_token().map_err(|_| ApiError::Internal)?;
    let (account_id, device_id) = state
        .metadata
        .create_account_with_device(
            device_id,
            &encryption_public_key,
            &signing_public_key,
            &token_hash,
        )
        .await
        .map_err(account_create_error)?;

    Ok((
        StatusCode::CREATED,
        Json(DeviceCredentialsResponse {
            account_id,
            device_id,
            device_token,
        }),
    ))
}

pub(crate) async fn create_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let auth = authenticate_device(&state, &headers).await?;
    let (device_id, encryption_public_key, signing_public_key) =
        parse_device_registration(&request)?;
    let (device_token, token_hash) = generate_device_token().map_err(|_| ApiError::Internal)?;
    let device_id = state
        .metadata
        .create_device(
            auth.account_id,
            device_id,
            &encryption_public_key,
            &signing_public_key,
            &token_hash,
        )
        .await
        .map_err(device_create_error)?;

    Ok((
        StatusCode::CREATED,
        Json(DeviceCredentialsResponse {
            account_id: auth.account_id,
            device_id,
            device_token,
        }),
    ))
}

pub(crate) async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<DeviceInventoryResponse>, ApiError> {
    let auth = authenticate_device(&state, &headers).await?;
    let devices = state
        .metadata
        .list_active_devices(auth.account_id)
        .await
        .map_err(|error| backend_store_error("list devices", error))?
        .into_iter()
        .map(|device| DeviceInventoryEntry {
            device_id: device.device_id,
            encryption_public_key: device.encryption_public_key.map(|key| hex_encode(&key)),
            signing_public_key: device.signing_public_key.map(|key| hex_encode(&key)),
        })
        .collect();
    Ok(Json(DeviceInventoryResponse {
        current_device_id: auth.device_id,
        devices,
    }))
}

pub(crate) async fn revoke_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let auth = authenticate_device(&state, &headers).await?;
    let revoked = state
        .metadata
        .revoke_device(auth.account_id, device_id)
        .await
        .map_err(device_revoke_error)?;
    if !revoked {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn get_household_topology(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(household_id): Path<Uuid>,
) -> Result<Json<HouseholdTopologyV1>, ApiError> {
    let auth = authenticate_device(&state, &headers).await?;
    let topology = state
        .metadata
        .get_household_topology(household_id)
        .await
        .map_err(|error| backend_store_error("read household topology", error))?
        .ok_or(ApiError::NotFound)?;
    let authorized = topology
        .authorizes_device_scope(
            AccountId(auth.account_id),
            DeviceId(auth.device_id),
            ObjectScopeV1::Household {
                account_id: AccountId(auth.account_id),
                household_id: HouseholdId(household_id),
            },
            TopologyAction::Read,
        )
        .map_err(|_| ApiError::Internal)?;
    if !authorized {
        return Err(ApiError::Forbidden);
    }
    Ok(Json(topology))
}

pub(crate) async fn put_household_topology(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(household_id): Path<Uuid>,
    Json(topology): Json<HouseholdTopologyV1>,
) -> Result<StatusCode, ApiError> {
    let auth = authenticate_device(&state, &headers).await?;
    topology
        .validate()
        .map_err(|_| ApiError::BadRequest("invalid household topology"))?;
    if topology.household.household_id.0 != household_id {
        return Err(ApiError::BadRequest("household topology path mismatch"));
    }
    let outcome = state
        .metadata
        .put_household_topology(auth, &topology)
        .await
        .map_err(topology_write_error)?;
    Ok(match outcome {
        TopologyWriteOutcome::Created => StatusCode::CREATED,
        TopologyWriteOutcome::Updated | TopologyWriteOutcome::Replayed => StatusCode::NO_CONTENT,
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct ListObjectsQuery {
    after: Option<i64>,
    limit: Option<u16>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ListObjectsResponse {
    objects: Vec<ObjectMetadataResponse>,
    next_change_seq: u64,
}

pub(crate) async fn list_objects(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListObjectsQuery>,
) -> Result<Json<ListObjectsResponse>, ApiError> {
    let auth = authenticate_device(&state, &headers).await?;
    let after = query.after.unwrap_or(0);
    if after < 0 {
        return Err(ApiError::BadRequest("after must be nonnegative"));
    }
    let limit = query.limit.unwrap_or(DEFAULT_LIST_LIMIT);
    if limit == 0 || limit > MAX_LIST_LIMIT {
        return Err(ApiError::BadRequest("limit must be between 1 and 256"));
    }

    let candidates = state
        .metadata
        .list_objects(auth.account_id, after, i64::from(limit))
        .await
        .map_err(|error| backend_store_error("list objects", error))?;
    let next_change_seq = candidates.last().map_or(after, |object| object.change_seq);
    let mut topology_cache = HashMap::new();
    let mut objects = Vec::with_capacity(candidates.len());
    for object in &candidates {
        if scope_authorized_cached(
            &state,
            auth,
            object.header.scope,
            TopologyAction::Read,
            &mut topology_cache,
        )
        .await?
        {
            objects.push(ObjectMetadataResponse::try_from(object).map_err(|_| ApiError::Internal)?);
        }
    }

    Ok(Json(ListObjectsResponse {
        objects,
        next_change_seq: u64::try_from(next_change_seq).map_err(|_| ApiError::Internal)?,
    }))
}

pub(crate) async fn put_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(object_id): Path<Uuid>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let auth = authenticate_device(&state, &headers).await?;
    require_octet_stream(&headers)?;
    if body.is_empty() {
        return Err(ApiError::BadRequest("ciphertext body must not be empty"));
    }
    let mutation = parse_mutation(&headers)?;
    let ciphertext_size = u64::try_from(body.len()).map_err(|_| ApiError::PayloadTooLarge)?;
    let ciphertext_sha256: [u8; 32] = Sha256::digest(&body).into();
    mutation
        .validate_upload_binding(
            AccountId(auth.account_id),
            ObjectId(object_id),
            ciphertext_size,
            ciphertext_sha256,
        )
        .map_err(|_| ApiError::BadRequest("invalid opaque mutation binding"))?;
    if !scope_authorized(&state, auth, mutation.object.scope, TopologyAction::Write).await? {
        return Err(ApiError::Forbidden);
    }
    let canonical_mutation = serde_json::to_vec(&mutation).map_err(|_| ApiError::Internal)?;
    let request_sha256: [u8; 32] = Sha256::digest(&canonical_mutation).into();

    if let Some(outcome) = state
        .metadata
        .get_operation(auth.account_id, mutation.operation_id.0)
        .await
        .map_err(|error| backend_store_error("read mutation operation", error))?
    {
        if outcome.request_sha256 != request_sha256 {
            return Err(ApiError::OperationConflict);
        }
        return operation_outcome_response(&outcome);
    }

    let candidate_revision = i64::try_from(mutation.object.revision)
        .map_err(|_| ApiError::BadRequest("revision is outside the supported range"))?;
    let precondition = WritePrecondition::try_from(&mutation.precondition).map_err(|_| {
        ApiError::BadRequest("precondition revision is outside the supported range")
    })?;

    let current = state
        .metadata
        .get_object(auth.account_id, object_id)
        .await
        .map_err(|error| backend_store_error("read object metadata", error))?;
    validate_write_policy(current.as_ref(), candidate_revision, &precondition)
        .map_err(policy_error)?;

    let ciphertext_size_bytes =
        i64::try_from(ciphertext_size).map_err(|_| ApiError::PayloadTooLarge)?;
    let storage_key = candidate_storage_key(auth.account_id, object_id, Uuid::new_v4());

    state
        .blobs
        .put(&storage_key, body)
        .await
        .map_err(|error| blob_error("upload object", error))?;

    let committed = match state
        .metadata
        .commit_object(
            auth,
            &mutation,
            &precondition,
            ciphertext_size_bytes,
            ciphertext_sha256,
            &storage_key,
            request_sha256,
        )
        .await
    {
        Ok(committed) => committed,
        Err(CommitError::CommitOutcomeUnknown(_error)) => {
            warn!(
                "PostgreSQL commit acknowledgement failed; reconciling ciphertext metadata before cleanup"
            );
            match state
                .metadata
                .get_operation(auth.account_id, mutation.operation_id.0)
                .await
            {
                Ok(Some(outcome)) if outcome.request_sha256 == request_sha256 => {
                    if outcome.storage_key != storage_key {
                        best_effort_delete(&state, &storage_key, "discard duplicate upload").await;
                    }
                    return operation_outcome_response(&outcome);
                }
                Ok(_) => {
                    warn!(
                        "PostgreSQL commit reconciliation did not yet expose the candidate; retaining ciphertext because commit outcome is unknown"
                    );
                    return Err(ApiError::Unavailable);
                }
                Err(_error) => {
                    warn!(
                        "PostgreSQL commit reconciliation failed; retaining candidate ciphertext because it may be committed"
                    );
                    return Err(ApiError::Unavailable);
                }
            }
        }
        Err(error) => {
            best_effort_delete(&state, &storage_key, "discard uncommitted object").await;
            return Err(match error {
                CommitError::PreconditionFailed => ApiError::PreconditionFailed,
                CommitError::AccountMissing => ApiError::Unauthorized,
                CommitError::OperationConflict => ApiError::OperationConflict,
                CommitError::UnauthorizedScope => ApiError::Forbidden,
                CommitError::InvalidContract => ApiError::Internal,
                CommitError::Database(error) => {
                    backend_store_error("commit object", StoreError::Database(error))
                }
                CommitError::Store(error) => backend_store_error("commit object", error),
                CommitError::CommitOutcomeUnknown(_) => unreachable!("handled above"),
            });
        }
    };

    if committed.replayed {
        best_effort_delete(&state, &storage_key, "discard replay upload").await;
    }
    if !committed.replayed
        && let Some(previous_key) = &committed.previous_storage_key
    {
        best_effort_delete(&state, previous_key, "retire replaced object").await;
    }

    object_metadata_response(
        if committed.created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        &committed.object,
    )
}

pub(crate) async fn get_object(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(object_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let auth = authenticate_device(&state, &headers).await?;
    let object = state
        .metadata
        .get_object(auth.account_id, object_id)
        .await
        .map_err(|error| backend_store_error("read object metadata", error))?
        .ok_or(ApiError::NotFound)?;
    if !scope_authorized(&state, auth, object.header.scope, TopologyAction::Read).await? {
        return Err(ApiError::Forbidden);
    }
    let body = state
        .blobs
        .get(&object.storage_key)
        .await
        .map_err(|error| blob_error("download object", error))?;

    let actual_size = i64::try_from(body.len()).map_err(|_| ApiError::Internal)?;
    let actual_hash: [u8; 32] = Sha256::digest(&body).into();
    if actual_size != object.ciphertext_size_bytes || actual_hash != object.ciphertext_sha256 {
        warn!(object_id = %object_id, "object storage payload failed metadata integrity check");
        return Err(ApiError::Unavailable);
    }

    let etag = strong_etag(&object.version());
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CACHE_CONTROL, "no-store")
        .header(ETAG, etag)
        .header(CHANGE_SEQ_HEADER, object.change_seq.to_string())
        .body(Body::from(body))
        .map_err(|_| ApiError::Internal)
}

async fn scope_authorized(
    state: &AppState,
    auth: AuthContext,
    scope: ObjectScopeV1,
    action: TopologyAction,
) -> Result<bool, ApiError> {
    match scope {
        ObjectScopeV1::Account { account_id } => Ok(account_id.0 == auth.account_id),
        ObjectScopeV1::Household { household_id, .. }
        | ObjectScopeV1::Space { household_id, .. } => {
            let topology = state
                .metadata
                .get_household_topology(household_id.0)
                .await
                .map_err(|error| backend_store_error("authorize object scope", error))?;
            evaluate_scope(topology.as_ref(), auth, scope, action)
        }
    }
}

async fn scope_authorized_cached(
    state: &AppState,
    auth: AuthContext,
    scope: ObjectScopeV1,
    action: TopologyAction,
    cache: &mut HashMap<Uuid, Option<HouseholdTopologyV1>>,
) -> Result<bool, ApiError> {
    let household_id = match scope {
        ObjectScopeV1::Account { account_id } => return Ok(account_id.0 == auth.account_id),
        ObjectScopeV1::Household { household_id, .. }
        | ObjectScopeV1::Space { household_id, .. } => household_id.0,
    };
    if let std::collections::hash_map::Entry::Vacant(entry) = cache.entry(household_id) {
        let topology = state
            .metadata
            .get_household_topology(household_id)
            .await
            .map_err(|error| backend_store_error("authorize object feed", error))?;
        entry.insert(topology);
    }
    evaluate_scope(
        cache.get(&household_id).and_then(Option::as_ref),
        auth,
        scope,
        action,
    )
}

fn evaluate_scope(
    topology: Option<&HouseholdTopologyV1>,
    auth: AuthContext,
    scope: ObjectScopeV1,
    action: TopologyAction,
) -> Result<bool, ApiError> {
    let Some(topology) = topology else {
        return Ok(false);
    };
    topology
        .authorizes_device_scope(
            AccountId(auth.account_id),
            DeviceId(auth.device_id),
            scope,
            action,
        )
        .map_err(|_| ApiError::Internal)
}

async fn authenticate_device(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthContext, ApiError> {
    let token = bearer_token(headers).ok_or(ApiError::Unauthorized)?;
    let token_hash = device_token_hash(token);
    state
        .metadata
        .authenticate(&token_hash)
        .await
        .map_err(|error| backend_store_error("authenticate device", error))?
        .ok_or(ApiError::Unauthorized)
}

fn authorize_registration(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let token = bearer_token(headers).ok_or(ApiError::Unauthorized)?;
    let supplied_hash = registration_token_hash(token);
    if !constant_time_eq(&state.registration_token_hash, &supplied_hash) {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

fn parse_device_registration(
    request: &RegisterDeviceRequest,
) -> Result<(Uuid, [u8; 32], [u8; 32]), ApiError> {
    if request.device_id.is_nil() {
        return Err(ApiError::BadRequest("device_id must be a non-nil UUID"));
    }
    let encryption_public_key = parse_public_key_hex(&request.encryption_public_key).ok_or(
        ApiError::BadRequest("encryption_public_key must be 32-byte hex"),
    )?;
    let signing_public_key = parse_public_key_hex(&request.signing_public_key).ok_or(
        ApiError::BadRequest("signing_public_key must be 32-byte hex"),
    )?;
    Ok((request.device_id, encryption_public_key, signing_public_key))
}

fn require_octet_stream(headers: &HeaderMap) -> Result<(), ApiError> {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if content_type != Some("application/octet-stream") {
        return Err(ApiError::UnsupportedMediaType);
    }
    Ok(())
}

fn parse_mutation(headers: &HeaderMap) -> Result<OpaqueMutationV1, ApiError> {
    let value = headers
        .get(MUTATION_HEADER)
        .ok_or(ApiError::BadRequest("x-safeory-mutation is required"))?
        .to_str()
        .map_err(|_| ApiError::BadRequest("x-safeory-mutation must be UTF-8 JSON"))?;
    if value.len() > MAX_MUTATION_HEADER_BYTES {
        return Err(ApiError::BadRequest("x-safeory-mutation is too large"));
    }
    serde_json::from_str(value).map_err(|_| ApiError::BadRequest("x-safeory-mutation is invalid"))
}

fn candidate_storage_key(account_id: Uuid, object_id: Uuid, upload_id: Uuid) -> String {
    format!("accounts/{account_id}/objects/{object_id}/{upload_id}")
}

fn object_metadata_response(
    status: StatusCode,
    object: &StoredObject,
) -> Result<Response, ApiError> {
    let metadata = ObjectMetadataResponse::try_from(object).map_err(|_| ApiError::Internal)?;
    let etag = HeaderValue::from_str(&metadata.etag).map_err(|_| ApiError::Internal)?;
    let change_seq =
        HeaderValue::from_str(&metadata.change_seq.to_string()).map_err(|_| ApiError::Internal)?;
    let mut response = (status, Json(metadata)).into_response();
    response.headers_mut().insert(ETAG, etag);
    response.headers_mut().insert(CHANGE_SEQ_HEADER, change_seq);
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

fn operation_outcome_response(outcome: &OperationOutcome) -> Result<Response, ApiError> {
    let stored = StoredObject {
        object_id: outcome.header.object_id.0,
        revision: i64::try_from(outcome.header.revision).map_err(|_| ApiError::Internal)?,
        ciphertext_size_bytes: i64::try_from(outcome.header.ciphertext_size_bytes)
            .map_err(|_| ApiError::Internal)?,
        ciphertext_sha256: outcome.header.ciphertext_sha256,
        change_seq: outcome.change_seq,
        storage_key: String::new(),
        header: outcome.header.clone(),
    };
    object_metadata_response(
        if outcome.created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        &stored,
    )
}

async fn best_effort_delete(state: &AppState, key: &str, operation: &'static str) {
    if state.blobs.delete(key).await.is_err() {
        warn!(
            operation,
            "object-store cleanup failed; ciphertext blob is unreachable"
        );
    }
}

fn policy_error(error: PolicyError) -> ApiError {
    match error {
        PolicyError::PreconditionFailed => ApiError::PreconditionFailed,
        PolicyError::InvalidRevision => ApiError::BadRequest("revision must increase"),
    }
}

fn topology_write_error(error: TopologyWriteError) -> ApiError {
    match error {
        TopologyWriteError::InvalidContract => ApiError::BadRequest("invalid household topology"),
        TopologyWriteError::Unauthorized => ApiError::Forbidden,
        TopologyWriteError::PreconditionFailed => ApiError::PreconditionFailed,
        TopologyWriteError::UnknownPrincipal => {
            ApiError::BadRequest("household topology references an unknown principal")
        }
        TopologyWriteError::Database(_) | TopologyWriteError::Store(_) => {
            warn!("household topology persistence failed");
            ApiError::Unavailable
        }
    }
}

fn device_create_error(error: DeviceCreateError) -> ApiError {
    match error {
        DeviceCreateError::LimitReached => ApiError::LimitReached,
        DeviceCreateError::IdentifierConflict => ApiError::IdentifierConflict,
        DeviceCreateError::Database(error) => {
            backend_store_error("create device", StoreError::Database(error))
        }
    }
}

fn account_create_error(error: AccountCreateError) -> ApiError {
    match error {
        AccountCreateError::IdentifierConflict => ApiError::IdentifierConflict,
        AccountCreateError::Database(error) => {
            backend_store_error("create account", StoreError::Database(error))
        }
    }
}

fn device_revoke_error(error: DeviceRevokeError) -> ApiError {
    match error {
        DeviceRevokeError::LastActiveDevice => ApiError::LastActiveDevice,
        DeviceRevokeError::Database(error) => {
            backend_store_error("revoke device", StoreError::Database(error))
        }
    }
}

fn backend_store_error(operation: &'static str, _error: StoreError) -> ApiError {
    warn!(operation, "PostgreSQL metadata operation failed");
    ApiError::Unavailable
}

fn blob_error(operation: &'static str, _error: crate::blob::BlobStoreError) -> ApiError {
    warn!(operation, "S3-compatible object store operation failed");
    ApiError::Unavailable
}

#[derive(Debug)]
pub(crate) enum ApiError {
    Unauthorized,
    Forbidden,
    NotFound,
    BadRequest(&'static str),
    UnsupportedMediaType,
    PayloadTooLarge,
    PreconditionFailed,
    OperationConflict,
    IdentifierConflict,
    LimitReached,
    LastActiveDevice,
    Unavailable,
    Internal,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::UnsupportedMediaType => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "application/octet-stream is required",
            ),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::PreconditionFailed => {
                (StatusCode::PRECONDITION_FAILED, "write_precondition_failed")
            }
            Self::OperationConflict => (StatusCode::CONFLICT, "operation_conflict"),
            Self::IdentifierConflict => (StatusCode::CONFLICT, "device_identifier_conflict"),
            Self::LimitReached => (StatusCode::UNPROCESSABLE_ENTITY, "device_limit_reached"),
            Self::LastActiveDevice => (StatusCode::CONFLICT, "last_active_device"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "backend_unavailable"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        (status, Json(ErrorResponse { error })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use vault_sync::{
        OBJECT_HEADER_FORMAT_VERSION, OPAQUE_MUTATION_FORMAT_VERSION, ObjectClassV1, ObjectScopeV1,
        OperationId, SYNC_PROTOCOL_VERSION, WritePreconditionV1,
    };

    fn mutation() -> OpaqueMutationV1 {
        let account_id = AccountId::new();
        OpaqueMutationV1 {
            format_version: OPAQUE_MUTATION_FORMAT_VERSION,
            operation_id: OperationId::new(),
            object: vault_sync::OpaqueObjectHeaderV1 {
                format_version: OBJECT_HEADER_FORMAT_VERSION,
                protocol_version: SYNC_PROTOCOL_VERSION,
                object_id: ObjectId::new(),
                class: ObjectClassV1::Item,
                scope: ObjectScopeV1::Account { account_id },
                revision: 0,
                payload_version: 1,
                envelope_version: 1,
                ciphertext_size_bytes: 3,
                ciphertext_sha256: Sha256::digest(b"abc").into(),
                tombstone: false,
            },
            precondition: WritePreconditionV1::CreateOnly,
        }
    }

    #[test]
    fn storage_keys_are_opaque_unique_versions_under_the_authenticated_account() {
        let account = Uuid::new_v4();
        let object = Uuid::new_v4();
        let first = candidate_storage_key(account, object, Uuid::new_v4());
        let second = candidate_storage_key(account, object, Uuid::new_v4());
        assert!(first.starts_with(&format!("accounts/{account}/objects/{object}/")));
        assert_ne!(first, second);
    }

    #[test]
    fn mutation_header_is_required_and_decodes_canonical_contract() {
        let mut headers = HeaderMap::new();
        assert!(parse_mutation(&headers).is_err());

        let expected = mutation();
        let json = serde_json::to_string(&expected).expect("serialize mutation");
        headers.insert(
            MUTATION_HEADER,
            HeaderValue::from_str(&json).expect("mutation header"),
        );
        assert_eq!(parse_mutation(&headers).ok(), Some(expected));

        headers.insert(MUTATION_HEADER, HeaderValue::from_static("{}"));
        assert!(parse_mutation(&headers).is_err());
    }

    #[test]
    fn ciphertext_upload_requires_octet_stream() {
        let mut headers = HeaderMap::new();
        assert!(require_octet_stream(&headers).is_err());
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert!(require_octet_stream(&headers).is_err());
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream; charset=binary"),
        );
        assert!(require_octet_stream(&headers).is_ok());
    }

    #[test]
    fn device_registration_binds_a_non_nil_id_and_both_public_keys() {
        let device_id = Uuid::new_v4();
        let request: RegisterDeviceRequest = serde_json::from_value(serde_json::json!({
            "device_id": device_id,
            "encryption_public_key": "11".repeat(32),
            "signing_public_key": "22".repeat(32),
        }))
        .expect("parse registration");
        let parsed = parse_device_registration(&request).expect("valid registration");
        assert_eq!(parsed.0, device_id);
        assert_eq!(parsed.1, [0x11; 32]);
        assert_eq!(parsed.2, [0x22; 32]);

        let invalid: RegisterDeviceRequest = serde_json::from_value(serde_json::json!({
            "device_id": Uuid::nil(),
            "encryption_public_key": "11".repeat(32),
            "signing_public_key": "22".repeat(32),
        }))
        .expect("parse registration");
        assert!(parse_device_registration(&invalid).is_err());
    }
}
