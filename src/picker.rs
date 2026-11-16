use std::fmt::Write;

use crate::personas::Persona;

/// The page that lists the personas. Each button posts the sealed `flow` token
/// and the chosen persona's email to `action`.
pub fn render(action: &str, flow: &str, signed_in_as: &str, personas: &[Persona]) -> String {
    let mut buttons = String::new();
    for persona in personas {
        let _ = write!(
            buttons,
            r#"<button name="email" value="{email}"><strong>{name}</strong><span>{email}</span></button>"#,
            email = escape(&persona.email),
            name = escape(&persona.name),
        );
    }

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Test sign-in</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem}}
form{{display:grid;gap:.5rem}}
button{{display:grid;text-align:left;padding:.75rem 1rem;border:1px solid #bbb;border-radius:.5rem;background:#fff;font:inherit;cursor:pointer}}
button:hover{{background:#f3f3f3}}
span{{color:#555;font-size:.9rem}}
</style></head><body>
<h1>Sign in as</h1>
<p>Signed in as {signed_in_as}. Choose the test user to continue as.</p>
<form method="post" action="{action}"><input type="hidden" name="flow" value="{flow}">{buttons}</form>
</body></html>"#,
        signed_in_as = escape(signed_in_as),
        action = escape(action),
        flow = escape(flow),
    )
}

pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
