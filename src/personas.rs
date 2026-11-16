use std::fs;

use serde::Deserialize;

use crate::error::PersonaIdpError;

/// A user a signed-in person can choose to be.
#[derive(Clone, Debug, Deserialize)]
pub struct Persona {
    pub name: String,
    pub email: String,
}

/// Reads the personas from a JSON file: a list of objects with `name` and `email`.
pub fn load(path: &str) -> Result<Vec<Persona>, PersonaIdpError> {
    let json = fs::read_to_string(path)
        .map_err(|error| PersonaIdpError::Internal(format!("{path}: {error}")))?;
    serde_json::from_str(&json)
        .map_err(|error| PersonaIdpError::Internal(format!("{path}: {error}")))
}
