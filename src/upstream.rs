use std::sync::{PoisonError, RwLock};
use std::time::Duration;

use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreIdTokenClaims, CoreJsonWebKeySet, CoreProviderMetadata,
};
use openidconnect::{
    AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, SignatureVerificationError, TokenResponse, reqwest,
};

use rand::RngExt;

use crate::config::UpstreamConfig;
use crate::error::PersonaIdpError;
use crate::flow::{AuthorizationRequest, UpstreamState};
use crate::sealer::{Purpose, Sealer};

pub const CALLBACK_PATH: &str = "/callback";
const UPSTREAM_STATE_LIFETIME: Duration = Duration::from_secs(600);

type UpstreamClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// The upstream sign-in in front of the picker. The provider only vouches that
/// the person belongs to the tenant; the persona they pick is theirs to choose.
pub struct UpstreamGate {
    /// Discovery metadata with the provider's keys. Providers rotate their signing
    /// keys, so `refresh_keys` swaps in a fresh key set when a token names an unknown key.
    metadata: RwLock<CoreProviderMetadata>,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http: reqwest::Client,
}

impl UpstreamGate {
    /// `issuer` is the broker's own issuer URL, under which the upstream
    /// callback is served.
    pub async fn connect(config: &UpstreamConfig, issuer: &str) -> Result<Self, PersonaIdpError> {
        let upstream_error =
            |error: &dyn std::fmt::Display| PersonaIdpError::Upstream(error.to_string());
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| upstream_error(&error))?;
        let issuer_url =
            IssuerUrl::new(config.issuer_url.clone()).map_err(|error| upstream_error(&error))?;
        let metadata = CoreProviderMetadata::discover_async(issuer_url, &http)
            .await
            .map_err(|error| upstream_error(&error))?;

        Ok(Self {
            metadata: RwLock::new(metadata),
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            redirect_uri: format!("{}{CALLBACK_PATH}", issuer.trim_end_matches('/')),
            http,
        })
    }

    fn metadata(&self) -> CoreProviderMetadata {
        self.metadata
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn client(&self, metadata: CoreProviderMetadata) -> Result<UpstreamClient, PersonaIdpError> {
        let redirect = RedirectUrl::new(self.redirect_uri.clone())
            .map_err(|error| PersonaIdpError::Internal(error.to_string()))?;
        Ok(CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.clone())),
        )
        .set_redirect_uri(redirect))
    }

    /// Where to send the browser to sign in upstream for `request`, and the binding value
    /// to set as a cookie in that browser.
    pub fn authorization_url(
        &self,
        sealer: &Sealer,
        request: AuthorizationRequest,
    ) -> Result<(String, String), PersonaIdpError> {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let nonce = Nonce::new_random();
        let mut binding = [0u8; 32];
        rand::rng().fill(&mut binding);
        let binding = hex::encode(binding);
        let state = sealer.seal(
            Purpose::UpstreamState,
            &UpstreamState {
                request,
                upstream_nonce: nonce.secret().clone(),
                upstream_code_verifier: verifier.secret().clone(),
                browser_binding: binding.clone(),
            },
            UPSTREAM_STATE_LIFETIME,
        )?;

        let (url, _, _) = self
            .client(self.metadata())?
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                || CsrfToken::new(state),
                || nonce,
            )
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(challenge)
            .url();
        Ok((url.to_string(), binding))
    }

    /// The person the upstream provider signed in, for the log: their email, else their subject.
    pub async fn identify(
        &self,
        code: &str,
        state: &UpstreamState,
    ) -> Result<String, PersonaIdpError> {
        let upstream_error =
            |error: &dyn std::fmt::Display| PersonaIdpError::Upstream(error.to_string());
        let metadata = self.metadata();
        let response = self
            .client(metadata.clone())?
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .map_err(|error| upstream_error(&error))?
            .set_pkce_verifier(PkceCodeVerifier::new(state.upstream_code_verifier.clone()))
            .request_async(&self.http)
            .await
            .map_err(|error| upstream_error(&error))?;
        let id_token = response
            .id_token()
            .ok_or_else(|| PersonaIdpError::Upstream("no id_token returned".to_string()))?;
        let nonce = Nonce::new(state.upstream_nonce.clone());
        let verify = |client: UpstreamClient| {
            id_token
                .claims(&client.id_token_verifier(), &nonce)
                .map(identity_label)
        };

        match verify(self.client(metadata.clone())?) {
            Ok(label) => Ok(label),
            Err(ClaimsVerificationError::SignatureVerification(
                SignatureVerificationError::NoMatchingKey,
            )) => {
                let refreshed = self.refresh_keys(metadata).await?;
                verify(self.client(refreshed)?).map_err(|error| upstream_error(&error))
            }
            Err(error) => Err(upstream_error(&error)),
        }
    }

    /// Fetch the provider's key set again and keep it for later sign-ins.
    async fn refresh_keys(
        &self,
        metadata: CoreProviderMetadata,
    ) -> Result<CoreProviderMetadata, PersonaIdpError> {
        let jwks = CoreJsonWebKeySet::fetch_async(metadata.jwks_uri(), &self.http)
            .await
            .map_err(|error| PersonaIdpError::Upstream(error.to_string()))?;
        let refreshed = metadata.set_jwks(jwks);
        *self
            .metadata
            .write()
            .unwrap_or_else(PoisonError::into_inner) = refreshed.clone();
        Ok(refreshed)
    }
}

fn identity_label(claims: &CoreIdTokenClaims) -> String {
    claims
        .email()
        .map(|email| email.to_string())
        .unwrap_or_else(|| claims.subject().to_string())
}
