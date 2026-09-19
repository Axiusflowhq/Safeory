mod auth;
mod blob;
mod model;
mod store;
mod sync;

use std::{env, net::SocketAddr, time::Duration};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    routing::{get, post},
};
use redis::AsyncCommands;
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use thiserror::Error;
use tokio::time::timeout;
use tracing::warn;

use crate::{
    auth::registration_token_hash, blob::S3BlobStore, store::MetadataStore,
    sync::MAX_CIPHERTEXT_OBJECT_BYTES,
};

const READINESS_TIMEOUT: Duration = Duration::from_secs(2);
const MIN_REGISTRATION_TOKEN_BYTES: usize = 32;

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub valkey_url: String,
    pub bind_addr: SocketAddr,
    registration_token_hash: [u8; 32],
    s3_endpoint: String,
    s3_region: String,
    s3_bucket: String,
    s3_access_key_id: String,
    s3_secret_access_key: String,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = required_env("DATABASE_URL")?;
        let valkey_url = required_env("VALKEY_URL")?;
        let bind_addr = required_env("BIND_ADDR")?
            .parse()
            .map_err(ConfigError::InvalidBindAddress)?;
        let registration_token = required_env("ACCOUNT_REGISTRATION_TOKEN")?;
        if registration_token.len() < MIN_REGISTRATION_TOKEN_BYTES {
            return Err(ConfigError::RegistrationTokenTooShort);
        }

        Ok(Self {
            database_url,
            valkey_url,
            bind_addr,
            registration_token_hash: registration_token_hash(&registration_token),
            s3_endpoint: required_env("S3_ENDPOINT")?,
            s3_region: required_env("S3_REGION")?,
            s3_bucket: required_env("S3_BUCKET")?,
            s3_access_key_id: required_env("S3_ACCESS_KEY_ID")?,
            s3_secret_access_key: required_env("S3_SECRET_ACCESS_KEY")?,
        })
    }
}

fn required_env(name: &'static str) -> Result<String, ConfigError> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(ConfigError::MissingEnvironmentVariable(name)),
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("required environment variable {0} is missing or empty")]
    MissingEnvironmentVariable(&'static str),
    #[error("BIND_ADDR is not a valid socket address")]
    InvalidBindAddress(#[source] std::net::AddrParseError),
    #[error("ACCOUNT_REGISTRATION_TOKEN must contain at least 32 bytes")]
    RegistrationTokenTooShort,
}

#[derive(Clone)]
pub struct AppState {
    pub(crate) metadata: MetadataStore,
    pub(crate) valkey: redis::Client,
    pub(crate) blobs: S3BlobStore,
    pub(crate) registration_token_hash: [u8; 32],
}

impl AppState {
    pub fn from_config(config: &Config) -> Result<Self, StartupError> {
        let postgres = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(READINESS_TIMEOUT)
            .connect_lazy(&config.database_url)?;
        let valkey = redis::Client::open(config.valkey_url.as_str())?;
        let blobs = S3BlobStore::new(
            &config.s3_endpoint,
            &config.s3_region,
            &config.s3_bucket,
            &config.s3_access_key_id,
            &config.s3_secret_access_key,
        )
        .map_err(|_| StartupError::ObjectStore)?;

        Ok(Self {
            metadata: MetadataStore::new(postgres),
            valkey,
            blobs,
            registration_token_hash: config.registration_token_hash,
        })
    }
}

#[derive(Debug, Error)]
pub enum StartupError {
    #[error("DATABASE_URL is invalid")]
    Database(#[from] sqlx::Error),
    #[error("VALKEY_URL is invalid")]
    Valkey(#[from] redis::RedisError),
    #[error("S3-compatible object store configuration is invalid")]
    ObjectStore,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/v1/accounts", post(sync::create_account))
        .route("/v1/devices", post(sync::create_device))
        .route(
            "/v1/devices/{device_id}",
            axum::routing::delete(sync::revoke_device),
        )
        .route("/v1/objects", get(sync::list_objects))
        .route(
            "/v1/objects/{object_id}",
            get(sync::get_object)
                .put(sync::put_object)
                .layer(DefaultBodyLimit::max(MAX_CIPHERTEXT_OBJECT_BYTES)),
        )
        .with_state(state)
}

#[derive(Debug, Serialize)]
struct LiveResponse {
    status: &'static str,
}

async fn health_live() -> Json<LiveResponse> {
    Json(LiveResponse { status: "live" })
}

#[derive(Debug, Serialize)]
struct ReadyResponse {
    status: &'static str,
    postgres: &'static str,
    valkey: &'static str,
    garage: &'static str,
}

async fn health_ready(State(state): State<AppState>) -> (StatusCode, Json<ReadyResponse>) {
    let postgres_check = check_postgres(&state.metadata);
    let valkey_check = check_valkey(&state.valkey);
    let garage_check = check_garage(&state.blobs);
    let (postgres_ready, valkey_ready, garage_ready) =
        tokio::join!(postgres_check, valkey_check, garage_check);

    let ready = postgres_ready && valkey_ready && garage_ready;
    let response = ReadyResponse {
        status: if ready { "ready" } else { "not_ready" },
        postgres: if postgres_ready { "ok" } else { "unavailable" },
        valkey: if valkey_ready { "ok" } else { "unavailable" },
        garage: if garage_ready { "ok" } else { "unavailable" },
    };

    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(response),
    )
}

async fn check_postgres(metadata: &MetadataStore) -> bool {
    match timeout(
        READINESS_TIMEOUT,
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(metadata.pool()),
    )
    .await
    {
        Ok(Ok(1)) => true,
        Ok(Ok(_)) => false,
        Ok(Err(_)) => {
            warn!("PostgreSQL readiness check failed");
            false
        }
        Err(_) => {
            warn!("PostgreSQL readiness check timed out");
            false
        }
    }
}

async fn check_valkey(client: &redis::Client) -> bool {
    let check = async {
        let mut connection = client.get_multiplexed_async_connection().await?;
        let pong: String = connection.ping().await?;
        Ok::<bool, redis::RedisError>(pong == "PONG")
    };

    match timeout(READINESS_TIMEOUT, check).await {
        Ok(Ok(true)) => true,
        Ok(Ok(false)) => false,
        Ok(Err(_)) => {
            warn!("Valkey readiness check failed");
            false
        }
        Err(_) => {
            warn!("Valkey readiness check timed out");
            false
        }
    }
}

async fn check_garage(blobs: &S3BlobStore) -> bool {
    match timeout(READINESS_TIMEOUT, blobs.ready()).await {
        Ok(Ok(())) => true,
        Ok(Err(_)) => {
            warn!("Garage readiness check failed");
            false
        }
        Err(_) => {
            warn!("Garage readiness check timed out");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn liveness_does_not_depend_on_external_state() {
        let Json(response) = health_live().await;
        assert_eq!(response.status, "live");
    }
}
