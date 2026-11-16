use persona_idp::flow::{challenge_matches, is_local_sign_in, s256_challenge};

#[test]
fn challenge_matches_only_its_own_verifier() {
    let challenge = s256_challenge("verifier");

    assert!(challenge_matches("verifier", &challenge));
    assert!(!challenge_matches("another-verifier", &challenge));
}

#[test]
fn s256_challenge_is_the_rfc_7636_example() {
    assert_eq!(
        s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn local_sign_in_is_a_localhost_sign_in_page() {
    assert!(is_local_sign_in("http://localhost:3000/sign-in"));
    assert!(is_local_sign_in("http://127.0.0.1:8000/sign-in"));
    assert!(!is_local_sign_in("http://localhost:3000/elsewhere"));
    assert!(!is_local_sign_in("https://evil.example.com/sign-in"));
    assert!(!is_local_sign_in("not a url"));
}
