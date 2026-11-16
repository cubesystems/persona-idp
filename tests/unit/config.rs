use std::collections::HashMap;

use persona_idp::config::Config;

const PERSONAS_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/personas.json");

fn config_from(extra: &[(&str, &str)]) -> Result<Config, String> {
    let mut env: HashMap<&str, &str> = HashMap::from([
        ("OAUTH_ISSUER_URL", "https://app.example/auth"),
        ("OAUTH_CLIENT_ID", "example-app"),
        ("OAUTH_CLIENT_SECRET", "secret"),
        ("OAUTH_REDIRECT_URI", "https://app.example/sign-in"),
        ("PERSONA_IDP_PERSONAS_FILE", PERSONAS_FILE),
    ]);
    env.extend(extra.iter().copied());
    Config::from_lookup(&|key| env.get(key).map(|value| value.to_string()))
        .map_err(|error| error.to_string())
}

const UPSTREAM: [(&str, &str); 3] = [
    (
        "PERSONA_IDP_UPSTREAM_ISSUER_URL",
        "https://login.example/v2.0",
    ),
    ("PERSONA_IDP_UPSTREAM_CLIENT_ID", "client"),
    ("PERSONA_IDP_UPSTREAM_CLIENT_SECRET", "upstream-secret"),
];

#[test]
fn an_upstream_turns_the_sign_in_on() {
    let config = config_from(&UPSTREAM).unwrap();

    assert_eq!(config.upstream.unwrap().client_id, "client");
    assert_eq!(config.port, 8080);
}

#[test]
fn no_upstream_must_be_said_explicitly() {
    assert!(
        config_from(&[])
            .unwrap_err()
            .contains("PERSONA_IDP_NO_UPSTREAM")
    );
    assert!(
        config_from(&[("PERSONA_IDP_NO_UPSTREAM", "true")])
            .unwrap()
            .upstream
            .is_none()
    );
    assert!(config_from(&[("PERSONA_IDP_NO_UPSTREAM", "yes")]).is_err());
}

#[test]
fn a_half_set_upstream_stops_the_broker() {
    let error =
        config_from(&[("PERSONA_IDP_UPSTREAM_ISSUER_URL", "https://login.example")]).unwrap_err();

    assert!(error.contains("PERSONA_IDP_UPSTREAM_CLIENT_ID"));
}

#[test]
fn a_port_that_is_not_a_number_stops_the_broker() {
    let mut env = UPSTREAM.to_vec();
    env.push(("PERSONA_IDP_LISTEN_PORT", "80a0"));

    assert!(
        config_from(&env)
            .unwrap_err()
            .contains("PERSONA_IDP_LISTEN_PORT")
    );
    env.pop();
    env.push(("PERSONA_IDP_LISTEN_PORT", "9090"));
    assert_eq!(config_from(&env).unwrap().port, 9090);
}

#[test]
fn the_personas_file_is_required() {
    let mut env = HashMap::from([
        ("OAUTH_ISSUER_URL", "https://app.example/auth"),
        ("OAUTH_CLIENT_ID", "example-app"),
        ("OAUTH_CLIENT_SECRET", "secret"),
        ("OAUTH_REDIRECT_URI", "https://app.example/sign-in"),
        ("PERSONA_IDP_NO_UPSTREAM", "true"),
    ]);
    let lookup = |key: &str| env.get(key).map(|value| value.to_string());

    let error = Config::from_lookup(&lookup).unwrap_err().to_string();
    assert!(error.contains("PERSONA_IDP_PERSONAS_FILE"));

    env.insert("PERSONA_IDP_PERSONAS_FILE", PERSONAS_FILE);
    let lookup = |key: &str| env.get(key).map(|value| value.to_string());
    assert_eq!(Config::from_lookup(&lookup).unwrap().personas.len(), 2);
}
