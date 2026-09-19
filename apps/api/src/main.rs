use std::error::Error;

use safeory_api::{AppState, Config, router};
use tokio::{net::TcpListener, signal};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "safeory_api=info".into()),
        )
        .init();

    let config = Config::from_env()?;
    let state = AppState::from_config(&config)?;
    let listener = TcpListener::bind(config.bind_addr).await?;

    info!(bind_addr = %config.bind_addr, "Safeory API listening");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
