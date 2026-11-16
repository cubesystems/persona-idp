use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

use crate::handlers;
use crate::state::PersonaIdpState;

/// Every endpoint under the issuer URL's path, plus `/health` at the root.
pub fn router(state: Arc<PersonaIdpState>) -> Router {
    let prefix = PersonaIdpState::path_prefix(&state.issuer);
    let endpoints = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(handlers::discovery),
        )
        .route("/jwks", get(handlers::jwks))
        .route("/authorize", get(handlers::authorize))
        .route("/callback", get(handlers::callback))
        .route("/pick", post(handlers::pick))
        .route("/token", post(handlers::token))
        .with_state(state);

    let router = if prefix.is_empty() {
        endpoints
    } else {
        Router::new().nest(&prefix, endpoints)
    };
    router.route("/health", get(|| async { "ok" }))
}
