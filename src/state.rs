use url::Url;

use crate::config::Config;
use crate::error::PersonaIdpError;
use crate::flow::is_local_sign_in;
use crate::personas::Persona;
use crate::sealer::Sealer;
use crate::signing::SigningKey;
use crate::upstream::UpstreamGate;

/// Stands in for the upstream identity when the sign-in is off.
pub const LOCAL_IDENTITY: &str = "local";

pub struct PersonaIdpState {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// The one callback the client may use; local dev servers are also
    /// allowed while the upstream sign-in is off.
    pub redirect_uri: String,
    pub personas: Vec<Persona>,
    pub upstream: Option<UpstreamGate>,
    pub signing_key: SigningKey,
    pub sealer: Sealer,
}

impl PersonaIdpState {
    pub async fn connect(config: &Config) -> Result<Self, PersonaIdpError> {
        let upstream = match &config.upstream {
            Some(upstream) => Some(UpstreamGate::connect(upstream, &config.issuer_url).await?),
            None => None,
        };

        Ok(Self {
            issuer: config.issuer_url.clone(),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            redirect_uri: config.redirect_uri.clone(),
            personas: config.personas.clone(),
            upstream,
            signing_key: SigningKey::generate()?,
            sealer: Sealer::new(),
        })
    }

    pub fn redirect_allowed(&self, redirect_uri: &str) -> bool {
        redirect_uri == self.redirect_uri
            || (self.upstream.is_none() && is_local_sign_in(redirect_uri))
    }

    pub fn persona(&self, email: &str) -> Option<&Persona> {
        self.personas.iter().find(|persona| persona.email == email)
    }

    /// The issuer URL's path, under which every endpoint is served.
    pub fn path_prefix(issuer: &str) -> String {
        Url::parse(issuer)
            .map(|url| url.path().trim_end_matches('/').to_string())
            .unwrap_or_default()
    }
}
