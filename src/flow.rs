use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

const LOCAL_HOSTS: [&str; 2] = ["localhost", "127.0.0.1"];
const SIGN_IN_PATH: &str = "/sign-in";

/// What the application asked `/authorize` for.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
}

/// State sealed into the authorize request to the upstream provider.
#[derive(Serialize, Deserialize)]
pub struct UpstreamState {
    pub request: AuthorizationRequest,
    pub upstream_nonce: String,
    pub upstream_code_verifier: String,
    /// Random value also set as a cookie in the browser that started the sign-in, so only
    /// that browser can finish it.
    pub browser_binding: String,
}

/// Proof that the person signed in, carried by the picker page.
#[derive(Serialize, Deserialize)]
pub struct PickerToken {
    pub request: AuthorizationRequest,
    /// Who signed in upstream, for the log.
    pub signed_in_as: String,
}

/// The authorization code the application exchanges at `/token`.
#[derive(Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub request: AuthorizationRequest,
    pub email: String,
}

/// RFC 7636 `S256`: the challenge is the base64url SHA-256 of the verifier.
pub fn s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn challenge_matches(verifier: &str, challenge: &str) -> bool {
    s256_challenge(verifier) == challenge
}

/// A local dev server (any port, or a worktree's) at `/sign-in`.
pub fn is_local_sign_in(redirect_uri: &str) -> bool {
    Url::parse(redirect_uri).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url
                .host_str()
                .is_some_and(|host| LOCAL_HOSTS.contains(&host))
            && url.path() == SIGN_IN_PATH
    })
}
