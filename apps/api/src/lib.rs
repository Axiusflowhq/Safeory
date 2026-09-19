use std::{env, net::SocketAddr, time::Duration};

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use redis::AsyncCommands;
use serde::Serialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use thiserror::Error;
use tokio::time::timeout;
use tracing::warn;

const READINESS_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub valkey_url: String,
    pub bind_addr: SocketAddr,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = required_env("DATABASE_URL")?;
        let valkey_url = required_env("VALKEY_URL")?;
        let bind_addr = required_env("BIND_ADDR")?
            .parse()
            .map_err(ConfigError::InvalidBindAddress)?;

        Ok(Self {
            database_url,
            valkey_url,
            bind_addr,
        })
    }
}

fn required_env(name: &'static str) -> Result<String, ConfigError> {
    env::var(name).map_err(|_| ConfigError::MissingEnvironmentVariable(name))
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("required environment variable {0} is missing")]
    MissingEnvironmentVariable(&'static str),
    #[error("BIND_ADDR is not a valid socket address")]
    InvalidBindAddress(#[source] std::net::AddrParseError),
}

#[derive(Clone)]
pub struct AppState {
    postgres: PgPool,
    valkey: redis::Client,
}

impl AppState {
    pub fn from_config(config: &Config) -> Result<Self, StartupError> {
        let postgres = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(READINESS_TIMEOUT)
            .connect_lazy(&config.database_url)?;
        let valkey = redis::Client::open(config.valkey_url.as_str())?;

        Ok(Self { postgres, valkey })
    }
}

#[derive(Debug, Error)]
pub enum StartupError {
    #[error("DATABASE_URL is invalid")]
    Database(#[from] sqlx::Error),
    #[error("VALKEY_URL is invalid")]
    Valkey(#[from] redis::RedisError),
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
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
}

async fn health_ready(State(state): State<AppState>) -> (StatusCode, Json<ReadyResponse>) {
    let postgres_check = check_postgres(&state.postgres);
    let valkey_check = check_valkey(&state.valkey);
    let (postgres_ready, valkey_ready) = tokio::join!(postgres_check, valkey_check);

    let ready = postgres_ready && valkey_ready;
    let response = ReadyResponse {
        status: if ready { "ready" } else { "not_ready" },
        postgres: if postgres_ready { "ok" } else { "unavailable" },
        valkey: if valkey_ready { "ok" } else { "unavailable" },
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

async fn check_postgres(pool: &PgPool) -> bool {
    match timeout(
        READINESS_TIMEOUT,
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(pool),
    )
    .await
    {
        Ok(Ok(1)) => true,
        Ok(Ok(_)) => false,
        Ok(Err(error)) => {
            warn!(error = %error, "PostgreSQL readiness check failed");
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
        Ok(Err(error)) => {
            warn!(error = %error, "Valkey readiness check failed");
            false
        }
        Err(_) => {
            warn!("Valkey readiness check timed out");
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
