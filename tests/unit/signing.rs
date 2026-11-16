use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use persona_idp::personas::Persona;
use persona_idp::signing::SigningKey;

#[test]
fn publishes_the_key_that_signs() {
    let jwks = serde_json::to_value(SigningKey::generate().unwrap().jwks()).unwrap();

    assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
    assert_eq!(jwks["keys"][0]["kid"], "persona-idp");
}

#[test]
fn id_token_names_the_persona_and_echoes_the_nonce() {
    let key = SigningKey::generate().unwrap();
    let persona = Persona {
        name: "Ada".to_string(),
        email: "ada@example.test".to_string(),
    };

    let token = key
        .id_token("https://x.example/auth", "client", "the-nonce", &persona)
        .unwrap();
    let payload = URL_SAFE_NO_PAD
        .decode(token.split('.').nth(1).unwrap())
        .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();

    assert_eq!(payload["iss"], "https://x.example/auth");
    assert_eq!(payload["aud"][0], "client");
    assert_eq!(payload["sub"], "ada@example.test");
    assert_eq!(payload["email"], "ada@example.test");
    assert_eq!(payload["email_verified"], true);
    assert_eq!(payload["name"], "Ada");
    assert_eq!(payload["nonce"], "the-nonce");
}
