use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use openidconnect::core::{
    CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
    CoreRsaPrivateSigningKey,
};
use openidconnect::{
    Audience, EmptyAdditionalClaims, EndUserEmail, EndUserName, IssuerUrl, JsonWebKeyId,
    LocalizedClaim, Nonce, PrivateSigningKey, StandardClaims, SubjectIdentifier,
};

use rand_core::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};

use crate::error::PersonaIdpError;
use crate::personas::Persona;

const RSA_KEY_BITS: usize = 2048;
const SIGNING_KEY_ID: &str = "persona-idp";
pub const ID_TOKEN_LIFETIME: Duration = Duration::from_secs(300);

/// The key that signs the broker's id_tokens.
pub struct SigningKey {
    key: CoreRsaPrivateSigningKey,
}

impl SigningKey {
    /// A random RSA key, kept in memory only: a restart publishes a new key.
    pub fn generate() -> Result<Self, PersonaIdpError> {
        let internal = |error: String| PersonaIdpError::Internal(format!("signing key: {error}"));
        let private_key = RsaPrivateKey::new(&mut OsRng, RSA_KEY_BITS)
            .map_err(|error| internal(error.to_string()))?;
        let pem = private_key
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|error| internal(error.to_string()))?;
        let key = CoreRsaPrivateSigningKey::from_pem(
            &pem,
            Some(JsonWebKeyId::new(SIGNING_KEY_ID.to_string())),
        )
        .map_err(|error| internal(error.to_string()))?;
        Ok(Self { key })
    }

    pub fn jwks(&self) -> CoreJsonWebKeySet {
        CoreJsonWebKeySet::new(vec![self.key.as_verification_key()])
    }

    /// An id_token naming `persona` for `client_id`. The email is the subject.
    pub fn id_token(
        &self,
        issuer: &str,
        client_id: &str,
        nonce: &str,
        persona: &Persona,
    ) -> Result<String, PersonaIdpError> {
        let internal = |error: String| PersonaIdpError::Internal(error);
        let mut name = LocalizedClaim::new();
        name.insert(None, EndUserName::new(persona.name.clone()));
        let now = Utc::now();
        let standard = StandardClaims::new(SubjectIdentifier::new(persona.email.clone()))
            .set_email(Some(EndUserEmail::new(persona.email.clone())))
            .set_email_verified(Some(true))
            .set_name(Some(name));
        let claims = CoreIdTokenClaims::new(
            IssuerUrl::new(issuer.to_string()).map_err(|error| internal(error.to_string()))?,
            vec![Audience::new(client_id.to_string())],
            now + ChronoDuration::seconds(ID_TOKEN_LIFETIME.as_secs() as i64),
            now,
            standard,
            EmptyAdditionalClaims {},
        )
        .set_nonce(Some(Nonce::new(nonce.to_string())));

        CoreIdToken::new(
            claims,
            &self.key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .map(|token| token.to_string())
        .map_err(|error| internal(error.to_string()))
    }
}
