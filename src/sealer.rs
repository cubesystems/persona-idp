use std::time::Duration;

use aes_gcm::aead::{Aead, Generate, Key, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::PersonaIdpError;

const NONCE_BYTES: usize = 12;
const ERR_SEAL: &str = "sealing a token failed";

/// What a sealed token is for. A token opens only under the purpose it was
/// sealed for, so a state handed to the upstream provider cannot stand in for a later step.
#[derive(Clone, Copy)]
pub enum Purpose {
    UpstreamState,
    Picker,
    Code,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Self::UpstreamState => b"upstream-state",
            Self::Picker => b"picker",
            Self::Code => b"code",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    expires_at: i64,
    value: T,
}

/// Authenticated, expiring tokens that carry the broker's flow state, so the
/// broker keeps nothing between requests.
pub struct Sealer {
    cipher: Aes256Gcm,
}

impl Sealer {
    /// A random key, kept in memory only: tokens do not outlive the process.
    pub fn new() -> Self {
        Self {
            cipher: Aes256Gcm::new(&Key::<Aes256Gcm>::generate()),
        }
    }

    pub fn seal<T: Serialize>(
        &self,
        purpose: Purpose,
        value: &T,
        lifetime: Duration,
    ) -> Result<String, PersonaIdpError> {
        let internal = || PersonaIdpError::Internal(ERR_SEAL.to_string());
        let envelope = Envelope {
            expires_at: Utc::now().timestamp() + lifetime.as_secs() as i64,
            value,
        };
        let plaintext = serde_json::to_vec(&envelope).map_err(|_| internal())?;
        let nonce = Nonce::generate();
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: purpose.label(),
                },
            )
            .map_err(|_| internal())?;

        let mut bytes = nonce.to_vec();
        bytes.extend_from_slice(&ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// `None` for a token that is forged, expired or sealed for another purpose.
    pub fn open<T: DeserializeOwned>(&self, purpose: Purpose, token: &str) -> Option<T> {
        let bytes = URL_SAFE_NO_PAD.decode(token).ok()?;
        let (nonce, ciphertext) = bytes.split_at_checked(NONCE_BYTES)?;
        let nonce = Nonce::try_from(nonce).ok()?;
        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: purpose.label(),
                },
            )
            .ok()?;
        let envelope: Envelope<T> = serde_json::from_slice(&plaintext).ok()?;

        (envelope.expires_at >= Utc::now().timestamp()).then_some(envelope.value)
    }
}

impl Default for Sealer {
    fn default() -> Self {
        Self::new()
    }
}
