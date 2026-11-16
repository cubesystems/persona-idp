use std::error::Error;
use std::sync::Arc;

use persona_idp::config::Config;
use persona_idp::routes::router;
use persona_idp::state::PersonaIdpState;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt().json().init();

    let config = Config::from_env()?;
    let state = PersonaIdpState::connect(&config).await?;

    let bind_address = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&bind_address).await?;
    tracing::info!("listening on http://{bind_address}");

    axum::serve(listener, router(Arc::new(state)))
        .with_graceful_shutdown(terminated())
        .await?;
    Ok(())
}

/// Resolves on SIGTERM or SIGINT.
async fn terminated() {
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}
