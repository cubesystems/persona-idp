use std::sync::{Arc, Mutex, RwLock};

use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use axum::{Router, serve};
use chrono::{Duration, Utc};
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreResponseType, CoreRsaPrivateSigningKey, CoreSubjectIdentifierType,
};
use openidconnect::{
    Audience, AuthUrl, EmptyAdditionalClaims, EmptyAdditionalProviderMetadata, EndUserEmail,
    IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl, Nonce, PrivateSigningKey, ResponseTypes,
    StandardClaims, SubjectIdentifier, TokenUrl,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const OLD_KEY_PEM: &str = include_str!("../fixtures/upstream-key-old.pem");
const NEW_KEY_PEM: &str = include_str!("../fixtures/upstream-key-new.pem");
const OLD_KEY_ID: &str = "old-key";
const NEW_KEY_ID: &str = "new-key";

pub const CLIENT_ID: &str = "upstream-client";
pub const CLIENT_SECRET: &str = "upstream-secret";
pub const EMAIL: &str = "person@example.com";

fn key(pem: &str, key_id: &str) -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(pem, Some(JsonWebKeyId::new(key_id.to_string()))).unwrap()
}

struct State_ {
    base_url: String,
    /// The key `/token` signs id_tokens with.
    signing: RwLock<(&'static str, &'static str)>,
    /// The keys `/jwks` publishes.
    published: RwLock<Vec<(&'static str, &'static str)>>,
    nonce: RwLock<String>,
    jwks_requests: Mutex<usize>,
}

/// A mock upstream OpenID Connect provider: discovery, JWKS and a token
/// endpoint that returns a signed id_token, so a test can rotate its signing key.
pub struct UpstreamIssuer {
    state: Arc<State_>,
    handle: JoinHandle<()>,
    pub issuer_url: String,
}

impl UpstreamIssuer {
    /// Signs and publishes with the old key.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(State_ {
            base_url: base_url.clone(),
            signing: RwLock::new((OLD_KEY_PEM, OLD_KEY_ID)),
            published: RwLock::new(vec![(OLD_KEY_PEM, OLD_KEY_ID)]),
            nonce: RwLock::new(String::new()),
            jwks_requests: Mutex::new(0),
        });
        let router = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(state.clone());
        let handle = tokio::spawn(async move {
            let _ = serve(listener, router).await;
        });

        Self {
            state,
            handle,
            issuer_url: base_url,
        }
    }

    /// Sign with the new key and publish only it, as a provider does when it rotates.
    pub fn rotate_signing_key(&self) {
        *self.state.signing.write().unwrap() = (NEW_KEY_PEM, NEW_KEY_ID);
        *self.state.published.write().unwrap() = vec![(NEW_KEY_PEM, NEW_KEY_ID)];
    }

    /// Sign with the new key but keep publishing only the old one.
    pub fn sign_with_unpublished_key(&self) {
        *self.state.signing.write().unwrap() = (NEW_KEY_PEM, NEW_KEY_ID);
    }

    /// The nonce the next id_token carries.
    pub fn expect_nonce(&self, nonce: &str) {
        *self.state.nonce.write().unwrap() = nonce.to_string();
    }

    pub fn jwks_request_count(&self) -> usize {
        *self.state.jwks_requests.lock().unwrap()
    }
}

impl Drop for UpstreamIssuer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn discovery(State(state): State<Arc<State_>>) -> Json<Value> {
    let metadata = CoreProviderMetadata::new(
        IssuerUrl::new(state.base_url.clone()).unwrap(),
        AuthUrl::new(format!("{}/authorize", state.base_url)).unwrap(),
        JsonWebKeySetUrl::new(format!("{}/jwks", state.base_url)).unwrap(),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Public],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(
        TokenUrl::new(format!("{}/token", state.base_url)).unwrap(),
    ));

    Json(serde_json::to_value(metadata).unwrap())
}

async fn jwks(State(state): State<Arc<State_>>) -> Json<Value> {
    *state.jwks_requests.lock().unwrap() += 1;
    let keys = state
        .published
        .read()
        .unwrap()
        .iter()
        .map(|(pem, key_id)| key(pem, key_id).as_verification_key())
        .collect();

    Json(serde_json::to_value(CoreJsonWebKeySet::new(keys)).unwrap())
}

async fn token(State(state): State<Arc<State_>>) -> Json<Value> {
    let (pem, key_id) = *state.signing.read().unwrap();
    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new(state.base_url.clone()).unwrap(),
        vec![Audience::new(CLIENT_ID.to_string())],
        Utc::now() + Duration::minutes(5),
        Utc::now(),
        StandardClaims::new(SubjectIdentifier::new("upstream-subject".to_string()))
            .set_email(Some(EndUserEmail::new(EMAIL.to_string()))),
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(state.nonce.read().unwrap().clone())));
    let id_token = CoreIdToken::new(
        claims,
        &key(pem, key_id),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap();

    Json(json!({
        "access_token": "upstream-access-token",
        "token_type": "bearer",
        "expires_in": 3600,
        "id_token": id_token.to_string(),
    }))
}
