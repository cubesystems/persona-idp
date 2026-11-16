use std::collections::HashMap;
use std::sync::Arc;

use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, IssuerUrl, Nonce, PkceCodeVerifier, RedirectUrl,
    TokenResponse, reqwest,
};
use tokio::net::TcpListener;

use persona_idp::config::Config;
use persona_idp::flow::s256_challenge;
use persona_idp::personas;
use persona_idp::routes::router;
use persona_idp::state::PersonaIdpState;

const PERSONAS_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/personas.json");
const CLIENT_ID: &str = "example-app";
const CLIENT_SECRET: &str = "broker-secret";
const REDIRECT_URI: &str = "http://localhost:3000/sign-in";
const NONCE: &str = "the-nonce";
const VERIFIER: &str = "the-code-verifier";
const FRONTEND_STATE: &str = "frontend-state";
const ADMIN_EMAIL: &str = "admin@example.test";

struct Broker {
    issuer: String,
    http: reqwest::Client,
}

async fn start_broker() -> Broker {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}/auth", listener.local_addr().unwrap());
    let config = Config {
        host: "127.0.0.1".to_string(),
        port: 0,
        issuer_url: issuer.clone(),
        client_id: CLIENT_ID.to_string(),
        client_secret: CLIENT_SECRET.to_string(),
        redirect_uri: REDIRECT_URI.to_string(),
        personas: personas::load(PERSONAS_FILE).unwrap(),
        upstream: None,
    };
    let state = PersonaIdpState::connect(&config).await.unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(Arc::new(state))).await;
    });

    Broker {
        issuer,
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}

async fn metadata(broker: &Broker) -> CoreProviderMetadata {
    CoreProviderMetadata::discover_async(
        IssuerUrl::new(broker.issuer.clone()).unwrap(),
        &broker.http,
    )
    .await
    .expect("a client should discover the broker")
}

/// The authorize request the frontend builds.
async fn authorize(broker: &Broker, redirect_uri: &str) -> reqwest::Response {
    let mut url = url::Url::parse(&format!("{}/authorize", broker.issuer)).unwrap();
    url.query_pairs_mut()
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid email profile")
        .append_pair("state", FRONTEND_STATE)
        .append_pair("nonce", NONCE)
        .append_pair("code_challenge", &s256_challenge(VERIFIER))
        .append_pair("code_challenge_method", "S256");
    broker.http.get(url).send().await.unwrap()
}

fn flow_token(page: &str) -> String {
    let marker = r#"name="flow" value=""#;
    let start = page.find(marker).expect("the page carries a flow token") + marker.len();
    page[start..].split('"').next().unwrap().to_string()
}

async fn pick(broker: &Broker, flow: &str, email: &str) -> reqwest::Response {
    broker
        .http
        .post(format!("{}/pick", broker.issuer))
        .form(&[("flow", flow), ("email", email)])
        .send()
        .await
        .unwrap()
}

fn code_from(response: &reqwest::Response) -> String {
    let location = response.headers()["location"].to_str().unwrap();
    let query: HashMap<_, _> = url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect();
    assert_eq!(query["state"], FRONTEND_STATE);
    query["code"].clone()
}

async fn code_for(broker: &Broker, email: &str) -> String {
    let page = authorize(broker, REDIRECT_URI).await.text().await.unwrap();
    code_from(&pick(broker, &flow_token(&page), email).await)
}

/// What the Rust API does with a code: exchange it with PKCE and verify the id_token.
async fn exchange(broker: &Broker, code: &str, verifier: &str) -> Result<(String, String), String> {
    let client = CoreClient::from_provider_metadata(
        metadata(broker).await,
        ClientId::new(CLIENT_ID.to_string()),
        Some(ClientSecret::new(CLIENT_SECRET.to_string())),
    )
    .set_redirect_uri(RedirectUrl::new(REDIRECT_URI.to_string()).unwrap());
    let response = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .unwrap()
        .set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()))
        .request_async(&broker.http)
        .await
        .map_err(|error| error.to_string())?;
    let id_token = response.id_token().expect("an id_token");
    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(NONCE.to_string()))
        .map_err(|error| error.to_string())?;

    Ok((
        claims.subject().to_string(),
        claims
            .email()
            .map(|email| email.to_string())
            .unwrap_or_default(),
    ))
}

#[tokio::test]
async fn a_client_signs_in_as_the_persona_picked() {
    let broker = start_broker().await;

    let page = authorize(&broker, REDIRECT_URI).await;
    assert_eq!(page.status(), 200);
    let page = page.text().await.unwrap();
    assert!(page.contains(ADMIN_EMAIL) && page.contains("lab-engineer@example.test"));

    let redirect = pick(&broker, &flow_token(&page), ADMIN_EMAIL).await;
    assert_eq!(redirect.status(), 303);
    let code = code_from(&redirect);

    let (subject, email) = exchange(&broker, &code, VERIFIER).await.unwrap();
    assert_eq!(subject, ADMIN_EMAIL);
    assert_eq!(email, ADMIN_EMAIL);
}

#[tokio::test]
async fn a_code_is_bound_to_its_code_verifier() {
    let broker = start_broker().await;
    let code = code_for(&broker, ADMIN_EMAIL).await;

    assert!(exchange(&broker, &code, "another-verifier").await.is_err());
}

#[tokio::test]
async fn refuses_a_redirect_uri_that_is_not_the_clients() {
    let broker = start_broker().await;

    let response = authorize(&broker, "https://evil.example.com/sign-in").await;

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn pick_refuses_a_forged_flow_token_and_an_unknown_persona() {
    let broker = start_broker().await;
    let page = authorize(&broker, REDIRECT_URI).await.text().await.unwrap();

    assert_eq!(
        pick(&broker, "forged-token", ADMIN_EMAIL).await.status(),
        400
    );
    assert_eq!(
        pick(&broker, &flow_token(&page), "nobody@example.com")
            .await
            .status(),
        400
    );
}
