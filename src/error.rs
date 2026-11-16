use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Failures of the broker, answered as an OAuth error body.
#[derive(Debug, thiserror::Error)]
pub enum PersonaIdpError {
    #[error("{0}")]
    InvalidRequest(&'static str),
    #[error("client authentication failed")]
    InvalidClient,
    #[error("{0}")]
    InvalidGrant(&'static str),
    #[error("upstream sign-in failed: {0}")]
    Upstream(String),
    #[error("{0}")]
    Internal(String),
}

impl PersonaIdpError {
    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            Self::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::InvalidClient => (StatusCode::UNAUTHORIZED, "invalid_client"),
            Self::InvalidGrant(_) => (StatusCode::BAD_REQUEST, "invalid_grant"),
            Self::Upstream(_) => (StatusCode::BAD_GATEWAY, "temporarily_unavailable"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        }
    }
}

impl IntoResponse for PersonaIdpError {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();
        if status.is_server_error() {
            tracing::error!("{self}");
        }
        (
            status,
            Json(json!({"error": code, "error_description": self.to_string()})),
        )
            .into_response()
    }
}
