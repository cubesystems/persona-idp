use persona_idp::config::UpstreamConfig;
use persona_idp::flow::{AuthorizationRequest, UpstreamState};
use persona_idp::upstream::UpstreamGate;

use crate::support::upstream_issuer::{CLIENT_ID, CLIENT_SECRET, EMAIL, UpstreamIssuer};

const NONCE: &str = "upstream-nonce";

async fn connect(issuer: &UpstreamIssuer) -> UpstreamGate {
    UpstreamGate::connect(
        &UpstreamConfig {
            issuer_url: issuer.issuer_url.clone(),
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
        },
        "https://app.example/auth",
    )
    .await
    .expect("discovery against the mock upstream should succeed")
}

fn state() -> UpstreamState {
    UpstreamState {
        request: AuthorizationRequest {
            redirect_uri: "https://app.example/sign-in".to_string(),
            state: "state".to_string(),
            nonce: "nonce".to_string(),
            code_challenge: "challenge".to_string(),
        },
        upstream_nonce: NONCE.to_string(),
        upstream_code_verifier: "verifier".to_string(),
        browser_binding: "binding".to_string(),
    }
}

/// The upstream rotates its signing key after the broker fetched the key set at
/// startup. Sign-in must recover on its own rather than failing until a restart.
#[tokio::test]
async fn a_rotated_signing_key_is_picked_up_without_a_restart() {
    let issuer = UpstreamIssuer::start().await;
    let gate = connect(&issuer).await;
    let requests_after_discovery = issuer.jwks_request_count();
    issuer.rotate_signing_key();
    issuer.expect_nonce(NONCE);

    let label = gate.identify("code", &state()).await.unwrap();

    assert_eq!(label, EMAIL);
    assert_eq!(issuer.jwks_request_count(), requests_after_discovery + 1);
}

#[tokio::test]
async fn the_refreshed_key_set_serves_later_sign_ins() {
    let issuer = UpstreamIssuer::start().await;
    let gate = connect(&issuer).await;
    issuer.rotate_signing_key();
    issuer.expect_nonce(NONCE);
    gate.identify("code", &state()).await.unwrap();
    let requests_after_refresh = issuer.jwks_request_count();

    gate.identify("code", &state()).await.unwrap();

    assert_eq!(issuer.jwks_request_count(), requests_after_refresh);
}

#[tokio::test]
async fn an_unrotated_key_verifies_without_refetching_the_key_set() {
    let issuer = UpstreamIssuer::start().await;
    let gate = connect(&issuer).await;
    let requests_after_discovery = issuer.jwks_request_count();
    issuer.expect_nonce(NONCE);

    gate.identify("code", &state()).await.unwrap();

    assert_eq!(issuer.jwks_request_count(), requests_after_discovery);
}

#[tokio::test]
async fn a_key_the_upstream_never_publishes_stays_rejected() {
    let issuer = UpstreamIssuer::start().await;
    let gate = connect(&issuer).await;
    issuer.sign_with_unpublished_key();
    issuer.expect_nonce(NONCE);

    assert!(gate.identify("code", &state()).await.is_err());
}
