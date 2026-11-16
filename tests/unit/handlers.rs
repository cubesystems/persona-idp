use persona_idp::handlers::binding_cookie;

#[test]
fn the_cookie_path_follows_the_issuer_path() {
    let cookie = binding_cookie("https://app.example/auth", "value", 600);

    assert!(cookie.contains("Path=/auth/callback;"));
    assert!(cookie.ends_with("; Secure"));
}

#[test]
fn an_issuer_without_a_path_serves_the_callback_at_the_root() {
    let cookie = binding_cookie("http://localhost:8080", "value", 600);

    assert!(cookie.contains("Path=/callback;"));
    assert!(!cookie.contains("Secure"));
}
