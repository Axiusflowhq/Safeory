use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_MATCH, IF_NONE_MATCH},
    },
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;
use uuid::Uuid;

use crate::{
    AppState,
    auth::{
        bearer_token, constant_time_eq, device_token_hash, generate_device_token,
        parse_public_key_hex, registration_token_hash,
    },
    model::{
        DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT, MAX_WIRE_REVISION, ObjectMetadataResponse, PolicyError,
        StoredObject, WritePrecondition, parse_strong_etag, strong_etag, validate_write_policy,
    },
    store::{AuthContext, CommitError, StoreError},
};

pub(crate) const MAX_CIPHERTEXT_OBJECT_BYTES: usize =
    vault_sync::MAX_SYNC_CIPHERTEXT_BYTES as usize;
const REVISION_HEADER: &str = "x-safeory-revision";
const CHANGE_SEQ_HEADER: &str = "x-safeory-change-seq";

#[derive(Debug, Deserialize)]
pub(crate) struct RegisterDeviceRequest {
    device_public_key: String,
}

#[derive(Debug, Serialize)]
struct DeviceCredentialsResponse {
    account_id: Uuid,
    device_id: Uuid,
    device_token: String,
}

pub(crate) async fn create_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<impl IntoResponse, ApiError> {
    authorize_registration(&state, &headers)?;
    let public_key = parse_device_public_key(&request.device_public_key)?;
    let (device_token, token_hash) = generate_device_token().map_err(|_| ApiError::Internal)?;
    let (account_id, device_id) = state
        .metadata
        .create_account_with_device(&public_key, &token_hash)
        .await
        .map_err(|error| backend_store_error("create account", error))?;

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
    let public_key = parse_device_public_key(&request.device_public_key)?;
    let (device_token, token_hash) = generate_device_token().map_err(|_| ApiError::Internal)?;
    let device_id = state
        .metadata
        .create_device(auth.account_id, &public_key, &token_hash)
        .await
        .map_err(|error| backend_store_error("create device", error))?;

    Ok((
        StatusCode::CREATED,
        Json(DeviceCredentialsResponse {
            account_id: auth.account_id,
            device_id,
            device_token,
        }),
    ))
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
        .map_err(|error| backend_store_error("revoke device", error))?;
    if !revoked {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
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

    let objects = state
        .metadata
        .list_objects(auth.account_id, after, i64::from(limit))
        .await
        .map_err(|error| backend_store_error("list objects", error))?;
    let next_change_seq = objects.last().map_or(after, |object| object.change_seq);
    let objects = objects
        .iter()
        .map(ObjectMetadataResponse::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::Internal)?;

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
    let candidate_revision = parse_candidate_revision(&headers)?;
    let precondition = parse_write_precondition(&headers)?;

    let current = state
        .metadata
        .get_object(auth.account_id, object_id)
        .await
        .map_err(|error| backend_store_error("read object metadata", error))?;
    validate_write_policy(current.as_ref(), candidate_revision, &precondition)
        .map_err(policy_error)?;

    let ciphertext_size_bytes = i64::try_from(body.len()).map_err(|_| ApiError::PayloadTooLarge)?;
    let ciphertext_sha256: [u8; 32] = Sha256::digest(&body).into();
    let storage_key = candidate_storage_key(auth.account_id, object_id, Uuid::new_v4());

    state
        .blobs
        .put(&storage_key, body)
        .await
        .map_err(|error| blob_error("upload object", error))?;

    let committed = match state
        .metadata
        .commit_object(
            auth.account_id,
            object_id,
            candidate_revision,
            &precondition,
            ciphertext_size_bytes,
            ciphertext_sha256,
            &storage_key,
        )
        .await
    {
        Ok(committed) => committed,
        Err(CommitError::CommitOutcomeUnknown(_error)) => {
            warn!(
                "PostgreSQL commit acknowledgement failed; reconciling ciphertext metadata before cleanup"
            );
            match state.metadata.get_object(auth.account_id, object_id).await {
                Ok(Some(object))
                    if object_matches_candidate(
                        &object,
                        candidate_revision,
                        ciphertext_size_bytes,
                        ciphertext_sha256,
                        &storage_key,
                    ) =>
                {
                    crate::store::CommitResult {
                        object,
                        previous_storage_key: current
                            .as_ref()
                            .map(|object| object.storage_key.clone()),
                        created: current.is_none(),
                    }
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
                CommitError::Database(error) => {
                    backend_store_error("commit object", StoreError::Database(error))
                }
                CommitError::Store(error) => backend_store_error("commit object", error),
                CommitError::CommitOutcomeUnknown(_) => unreachable!("handled above"),
            });
        }
    };

    if let Some(previous_key) = &committed.previous_storage_key {
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
        .header(REVISION_HEADER, object.revision.to_string())
        .header(CHANGE_SEQ_HEADER, object.change_seq.to_string())
        .body(Body::from(body))
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

fn parse_device_public_key(value: &str) -> Result<[u8; 32], ApiError> {
    parse_public_key_hex(value).ok_or(ApiError::BadRequest(
        "device_public_key must be 32-byte hex",
    ))
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

fn parse_candidate_revision(headers: &HeaderMap) -> Result<i64, ApiError> {
    let value = headers
        .get(REVISION_HEADER)
        .ok_or(ApiError::BadRequest("x-safeory-revision is required"))?
        .to_str()
        .map_err(|_| ApiError::BadRequest("x-safeory-revision is invalid"))?;
    let revision = value
        .parse::<i64>()
        .map_err(|_| ApiError::BadRequest("x-safeory-revision is invalid"))?;
    if !(0..=MAX_WIRE_REVISION).contains(&revision) {
        return Err(ApiError::BadRequest(
            "x-safeory-revision is outside the supported range",
        ));
    }
    Ok(revision)
}

fn parse_write_precondition(headers: &HeaderMap) -> Result<WritePrecondition, ApiError> {
    let if_match = headers.get(IF_MATCH);
    let if_none_match = headers.get(IF_NONE_MATCH);
    match (if_match, if_none_match) {
        (Some(_), Some(_)) => Err(ApiError::BadRequest(
            "send exactly one of If-Match or If-None-Match",
        )),
        (None, None) => Err(ApiError::PreconditionRequired),
        (None, Some(value)) => {
            if value.to_str().ok() == Some("*") {
                Ok(WritePrecondition::CreateOnly)
            } else {
                Err(ApiError::BadRequest("If-None-Match must be *"))
            }
        }
        (Some(value), None) => {
            let value = value
                .to_str()
                .map_err(|_| ApiError::BadRequest("If-Match is invalid"))?;
            let version = parse_strong_etag(value).ok_or(ApiError::BadRequest(
                "If-Match must be one Safeory strong ETag",
            ))?;
            Ok(WritePrecondition::Match(version))
        }
    }
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
    let revision =
        HeaderValue::from_str(&metadata.revision.to_string()).map_err(|_| ApiError::Internal)?;
    let change_seq =
        HeaderValue::from_str(&metadata.change_seq.to_string()).map_err(|_| ApiError::Internal)?;
    let mut response = (status, Json(metadata)).into_response();
    response.headers_mut().insert(ETAG, etag);
    response.headers_mut().insert(REVISION_HEADER, revision);
    response.headers_mut().insert(CHANGE_SEQ_HEADER, change_seq);
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn best_effort_delete(state: &AppState, key: &str, operation: &'static str) {
    if state.blobs.delete(key).await.is_err() {
        warn!(
            operation,
            "object-store cleanup failed; ciphertext blob is unreachable"
        );
    }
}

fn object_matches_candidate(
    object: &StoredObject,
    revision: i64,
    ciphertext_size_bytes: i64,
    ciphertext_sha256: [u8; 32],
    storage_key: &str,
) -> bool {
    object.revision == revision
        && object.ciphertext_size_bytes == ciphertext_size_bytes
        && object.ciphertext_sha256 == ciphertext_sha256
        && object.storage_key == storage_key
}

fn policy_error(error: PolicyError) -> ApiError {
    match error {
        PolicyError::PreconditionFailed => ApiError::PreconditionFailed,
        PolicyError::InvalidRevision => ApiError::BadRequest("revision must increase"),
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
    NotFound,
    BadRequest(&'static str),
    UnsupportedMediaType,
    PayloadTooLarge,
    PreconditionRequired,
    PreconditionFailed,
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
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::UnsupportedMediaType => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "application/octet-stream is required",
            ),
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::PreconditionRequired => (
                StatusCode::PRECONDITION_REQUIRED,
                "write_precondition_required",
            ),
            Self::PreconditionFailed => {
                (StatusCode::PRECONDITION_FAILED, "write_precondition_failed")
            }
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "backend_unavailable"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        (status, Json(ErrorResponse { error })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

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
    fn write_precondition_requires_exactly_one_supported_header() {
        let mut headers = HeaderMap::new();
        assert!(matches!(
            parse_write_precondition(&headers),
            Err(ApiError::PreconditionRequired)
        ));

        headers.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
        assert_eq!(
            parse_write_precondition(&headers).ok(),
            Some(WritePrecondition::CreateOnly)
        );

        headers.insert(
            IF_MATCH,
            HeaderValue::from_static(
                "\"safeory-r0-0000000000000000000000000000000000000000000000000000000000000000\"",
            ),
        );
        assert!(parse_write_precondition(&headers).is_err());
    }

    #[test]
    fn candidate_revision_rejects_missing_negative_or_non_numeric_values() {
        let mut headers = HeaderMap::new();
        assert!(parse_candidate_revision(&headers).is_err());
        headers.insert(
            HeaderName::from_static(REVISION_HEADER),
            HeaderValue::from_static("-1"),
        );
        assert!(parse_candidate_revision(&headers).is_err());
        headers.insert(
            HeaderName::from_static(REVISION_HEADER),
            HeaderValue::from_static("7"),
        );
        assert_eq!(parse_candidate_revision(&headers).ok(), Some(7));
        headers.insert(
            HeaderName::from_static(REVISION_HEADER),
            HeaderValue::from_static("9007199254740992"),
        );
        assert!(parse_candidate_revision(&headers).is_err());
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
    fn commit_reconciliation_requires_the_exact_uploaded_candidate() {
        let candidate = StoredObject {
            object_id: Uuid::new_v4(),
            revision: 7,
            ciphertext_size_bytes: 123,
            ciphertext_sha256: [0x5a; 32],
            change_seq: 9,
            storage_key: "opaque-candidate".to_owned(),
        };

        assert!(object_matches_candidate(
            &candidate,
            7,
            123,
            [0x5a; 32],
            "opaque-candidate"
        ));

        let mut different = candidate.clone();
        different.storage_key = "newer-object".to_owned();
        assert!(!object_matches_candidate(
            &different,
            7,
            123,
            [0x5a; 32],
            "opaque-candidate"
        ));

        different = candidate.clone();
        different.ciphertext_sha256[0] ^= 1;
        assert!(!object_matches_candidate(
            &different,
            7,
            123,
            [0x5a; 32],
            "opaque-candidate"
        ));
    }
}
