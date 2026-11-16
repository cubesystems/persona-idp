use persona_idp::personas::Persona;
use persona_idp::picker::{escape, render};

fn persona(name: &str, email: &str) -> Persona {
    Persona {
        name: name.to_string(),
        email: email.to_string(),
    }
}

#[test]
fn lists_each_persona_with_the_flow_token() {
    let page = render(
        "https://x.example/auth/pick",
        "flow-token",
        "tester@lmt.lv",
        &[persona("Admin User", "admin@example.test")],
    );

    assert!(page.contains(r#"action="https://x.example/auth/pick""#));
    assert!(page.contains(r#"name="flow" value="flow-token""#));
    assert!(page.contains(r#"name="email" value="admin@example.test""#));
    assert!(page.contains("Admin User"));
    assert!(page.contains("tester@lmt.lv"));
}

#[test]
fn escapes_text_it_renders() {
    let page = render(
        "/pick",
        "flow",
        "who",
        &[persona(r#"<script>"x"</script>"#, "x@example.test")],
    );

    assert!(!page.contains("<script>"));
    assert!(page.contains("&lt;script&gt;&quot;x&quot;&lt;/script&gt;"));
    assert_eq!(escape("a&b'c"), "a&amp;b&#39;c");
}
