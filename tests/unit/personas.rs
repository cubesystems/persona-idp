use persona_idp::personas::load;

const PERSONAS_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/personas.json");

#[test]
fn loads_the_name_and_email_of_each_persona() {
    let personas = load(PERSONAS_FILE).unwrap();

    assert_eq!(personas.len(), 2);
    assert_eq!(personas[0].name, "Admin User");
    assert_eq!(personas[0].email, "admin@example.test");
}

#[test]
fn a_missing_file_names_its_path() {
    let error = load("/nonexistent/personas.json").unwrap_err();

    assert!(error.to_string().contains("/nonexistent/personas.json"));
}
