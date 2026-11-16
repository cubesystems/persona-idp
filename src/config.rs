use std::env;

use crate::error::PersonaIdpError;
use crate::personas::{self, Persona};

const DEFAULT_HOST: &str = "0.0.0.0";
const DEFAULT_PORT: u16 = 8080;

/// The upstream OpenID Connect provider (Microsoft Entra ID, Authentik, ...) the broker signs people in through.
#[derive(Clone, Debug)]
pub struct UpstreamConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    /// The broker's own issuer URL: the application's `OAUTH_ISSUER_URL`.
    pub issuer_url: String,
    /// The one client the broker issues tokens to, an application's `OAUTH_CLIENT_ID`,
    /// `OAUTH_CLIENT_SECRET` and `OAUTH_REDIRECT_URI`.
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    /// The users offered on the picker page.
    pub personas: Vec<Persona>,
    /// `None` skips the upstream sign-in, for local development.
    pub upstream: Option<UpstreamConfig>,
}

impl Config {
    pub fn from_env() -> Result<Self, PersonaIdpError> {
        Self::from_lookup(&|key| env::var(key).ok())
    }

    /// `PERSONA_IDP_UPSTREAM_ISSUER_URL` turns the upstream sign-in on and then
    /// requires its client id and secret. Without it, `PERSONA_IDP_NO_UPSTREAM=true`
    /// must say that the personas are offered with no sign-in, so a missing or
    /// misnamed variable stops the broker instead of opening it.
    pub fn from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Self, PersonaIdpError> {
        let optional = |key: &str| lookup(key).filter(|value| !value.is_empty());
        let required = |key: &str| {
            optional(key).ok_or_else(|| PersonaIdpError::Internal(format!("{key} is not set")))
        };

        let upstream = match optional("PERSONA_IDP_UPSTREAM_ISSUER_URL") {
            Some(issuer_url) => Some(UpstreamConfig {
                issuer_url,
                client_id: required("PERSONA_IDP_UPSTREAM_CLIENT_ID")?,
                client_secret: required("PERSONA_IDP_UPSTREAM_CLIENT_SECRET")?,
            }),
            None if optional("PERSONA_IDP_NO_UPSTREAM").as_deref() == Some("true") => None,
            None => {
                return Err(PersonaIdpError::Internal(
                    "set PERSONA_IDP_UPSTREAM_ISSUER_URL, or PERSONA_IDP_NO_UPSTREAM=true to offer \
                     the personas without a sign-in"
                        .to_string(),
                ));
            }
        };
        let port = match optional("PERSONA_IDP_LISTEN_PORT") {
            Some(port) => port.parse().map_err(|_| {
                PersonaIdpError::Internal(format!("PERSONA_IDP_LISTEN_PORT is not a port: {port}"))
            })?,
            None => DEFAULT_PORT,
        };
        let personas = personas::load(&required("PERSONA_IDP_PERSONAS_FILE")?)?;

        Ok(Self {
            host: optional("PERSONA_IDP_LISTEN_HOST").unwrap_or_else(|| DEFAULT_HOST.to_string()),
            port,
            issuer_url: required("OAUTH_ISSUER_URL")?,
            client_id: required("OAUTH_CLIENT_ID")?,
            client_secret: required("OAUTH_CLIENT_SECRET")?,
            redirect_uri: required("OAUTH_REDIRECT_URI")?,
            personas,
            upstream,
        })
    }
}
