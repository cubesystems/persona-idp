use std::sync::Arc;

use axum::Form;
use axum::Json;
use axum::extract::rejection::FormRejection;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use openidconnect::core::{
    CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::{
    AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySetUrl, ResponseTypes, TokenUrl,
};
use percent_encoding::percent_decode_str;
use rand::RngExt;
use serde::Deserialize;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use url::Url;

use crate::error::PersonaIdpError;
use crate::flow::{
    AuthorizationCode, AuthorizationRequest, PickerToken, UpstreamState, challenge_matches,
};
use crate::picker;
use crate::sealer::Purpose;
use crate::signing::ID_TOKEN_LIFETIME;
use crate::state::{LOCAL_IDENTITY, PersonaIdpState};

const FLOW_LIFETIME: std::time::Duration = std::time::Duration::from_secs(600);
const CODE_LIFETIME: std::time::Duration = std::time::Duration::from_secs(60);
const ACCESS_TOKEN_BYTES: usize = 32;
const AUTHORIZATION_CODE_GRANT: &str = "authorization_code";
const BINDING_COOKIE: &str = "persona_idp_binding";

type AppState = State<Arc<PersonaIdpState>>;

pub async fn discovery(State(app): AppState) -> Result<Json<Value>, PersonaIdpError> {
    let internal = |error: &dyn std::fmt::Display| PersonaIdpError::Internal(error.to_string());
    let endpoint = |path: &str| format!("{}{path}", app.issuer.trim_end_matches('/'));
    let metadata = CoreProviderMetadata::new(
        IssuerUrl::new(app.issuer.clone()).map_err(|error| internal(&error))?,
        AuthUrl::new(endpoint("/authorize")).map_err(|error| internal(&error))?,
        JsonWebKeySetUrl::new(endpoint("/jwks")).map_err(|error| internal(&error))?,
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Public],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(
        TokenUrl::new(endpoint("/token")).map_err(|error| internal(&error))?,
    ));

    serde_json::to_value(metadata)
        .map(Json)
        .map_err(|error| internal(&error))
}

pub async fn jwks(State(app): AppState) -> Result<Json<Value>, PersonaIdpError> {
    serde_json::to_value(app.signing_key.jwks())
        .map(Json)
        .map_err(|error| PersonaIdpError::Internal(error.to_string()))
}

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    state: String,
    nonce: String,
    code_challenge: String,
    code_challenge_method: String,
}

/// Sends the browser to the upstream provider, or straight to the picker while the
/// upstream sign-in is off.
pub async fn authorize(
    State(app): AppState,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Response, PersonaIdpError> {
    if query.client_id != app.client_id {
        return Err(PersonaIdpError::InvalidRequest("unknown client_id"));
    }
    if !app.redirect_allowed(&query.redirect_uri) {
        return Err(PersonaIdpError::InvalidRequest(
            "redirect_uri is not allowed",
        ));
    }
    if query.response_type != "code" || query.code_challenge_method != "S256" {
        return Err(PersonaIdpError::InvalidRequest(
            "only response_type=code with an S256 code_challenge is supported",
        ));
    }
    let request = AuthorizationRequest {
        redirect_uri: query.redirect_uri,
        state: query.state,
        nonce: query.nonce,
        code_challenge: query.code_challenge,
    };

    match &app.upstream {
        Some(upstream) => {
            let (url, binding) = upstream.authorization_url(&app.sealer, request)?;
            let cookie = binding_cookie(&app.issuer, &binding, FLOW_LIFETIME.as_secs());
            Ok(([(header::SET_COOKIE, cookie)], Redirect::to(&url)).into_response())
        }
        None => picker_page(&app, request, LOCAL_IDENTITY).await,
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    state: String,
    code: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// The upstream provider returns here; a verified sign-in leads to the picker.
pub async fn callback(
    State(app): AppState,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, PersonaIdpError> {
    let (Some(upstream), Some(state)) = (
        &app.upstream,
        app.sealer
            .open::<UpstreamState>(Purpose::UpstreamState, &query.state),
    ) else {
        return Err(PersonaIdpError::InvalidRequest(
            "unknown or expired sign-in",
        ));
    };
    if !cookie_value(&headers, BINDING_COOKIE)
        .is_some_and(|binding| constant_time_eq(&binding, &state.browser_binding))
    {
        return Err(PersonaIdpError::InvalidRequest(
            "this sign-in was not started in this browser",
        ));
    }
    let Some(code) = query.code else {
        return Err(PersonaIdpError::Upstream(
            query
                .error_description
                .or(query.error)
                .unwrap_or_else(|| "no authorization code returned".to_string()),
        ));
    };

    let signed_in_as = upstream.identify(&code, &state).await?;
    tracing::info!(upstream = signed_in_as, "signed in upstream");
    let mut response = picker_page(&app, state.request, &signed_in_as).await?;
    response.headers_mut().insert(
        header::SET_COOKIE,
        binding_cookie(&app.issuer, "", 0)
            .parse()
            .map_err(|_| PersonaIdpError::Internal("invalid cookie".to_string()))?,
    );
    Ok(response)
}

/// The cookie that ties an upstream sign-in to the browser that started it. It is only
/// sent to the issuer's `/callback`, and `Lax` lets it ride along when the upstream redirects back.
pub fn binding_cookie(issuer: &str, value: &str, max_age: u64) -> String {
    let secure = if issuer.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let path = PersonaIdpState::path_prefix(issuer);
    format!(
        "{BINDING_COOKIE}={value}; Path={path}/callback; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}"
    )
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then(|| value.to_string())
        })
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

async fn picker_page(
    app: &PersonaIdpState,
    request: AuthorizationRequest,
    signed_in_as: &str,
) -> Result<Response, PersonaIdpError> {
    let flow = app.sealer.seal(
        Purpose::Picker,
        &PickerToken {
            request,
            signed_in_as: signed_in_as.to_string(),
        },
        FLOW_LIFETIME,
    )?;
    let action = format!("{}/pick", app.issuer.trim_end_matches('/'));

    Ok(Html(picker::render(&action, &flow, signed_in_as, &app.personas)).into_response())
}

#[derive(Deserialize)]
pub struct PickForm {
    flow: String,
    email: String,
}

/// Hands the application an authorization code for the chosen user.
pub async fn pick(
    State(app): AppState,
    Form(form): Form<PickForm>,
) -> Result<Redirect, PersonaIdpError> {
    let Some(token) = app.sealer.open::<PickerToken>(Purpose::Picker, &form.flow) else {
        return Err(PersonaIdpError::InvalidRequest(
            "unknown or expired sign-in",
        ));
    };
    let chosen = app
        .persona(&form.email)
        .ok_or(PersonaIdpError::InvalidRequest("unknown user"))?;
    tracing::info!(
        upstream = token.signed_in_as,
        user = chosen.email,
        "chose a test user"
    );

    let request = token.request;
    let mut redirect = Url::parse(&request.redirect_uri)
        .map_err(|error| PersonaIdpError::Internal(error.to_string()))?;
    let state = request.state.clone();
    let code = app.sealer.seal(
        Purpose::Code,
        &AuthorizationCode {
            request,
            email: chosen.email.clone(),
        },
        CODE_LIFETIME,
    )?;
    redirect
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &state);

    Ok(Redirect::to(redirect.as_str()))
}

#[derive(Deserialize)]
pub struct TokenForm {
    grant_type: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// Exchanges a code for an id_token naming the chosen user.
pub async fn token(
    State(app): AppState,
    headers: HeaderMap,
    form: Result<Form<TokenForm>, FormRejection>,
) -> Result<impl IntoResponse, PersonaIdpError> {
    let Form(form) =
        form.map_err(|_| PersonaIdpError::InvalidRequest("malformed or incomplete token request"))?;
    let (client_id, client_secret) = client_credentials(&headers, &form);
    let id_matches = constant_time_eq(&client_id, &app.client_id);
    let secret_matches = constant_time_eq(&client_secret, &app.client_secret);
    if !(id_matches && secret_matches) {
        return Err(PersonaIdpError::InvalidClient);
    }
    if form.grant_type != AUTHORIZATION_CODE_GRANT {
        return Err(PersonaIdpError::InvalidRequest("unsupported grant_type"));
    }
    let Some(grant) = app
        .sealer
        .open::<AuthorizationCode>(Purpose::Code, &form.code)
    else {
        return Err(PersonaIdpError::InvalidGrant("unknown or expired code"));
    };
    let request = grant.request;
    if request.redirect_uri != form.redirect_uri
        || !challenge_matches(&form.code_verifier, &request.code_challenge)
    {
        return Err(PersonaIdpError::InvalidGrant(
            "redirect_uri or code_verifier mismatch",
        ));
    }
    let chosen = app
        .persona(&grant.email)
        .ok_or(PersonaIdpError::InvalidGrant(
            "the user is no longer offered",
        ))?;

    let id_token = app
        .signing_key
        .id_token(&app.issuer, &app.client_id, &request.nonce, chosen)?;
    let mut access_token = [0u8; ACCESS_TOKEN_BYTES];
    rand::rng().fill(&mut access_token);

    Ok((
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({
            "access_token": hex::encode(access_token),
            "token_type": "bearer",
            "expires_in": ID_TOKEN_LIFETIME.as_secs(),
            "id_token": id_token,
        })),
    ))
}

/// The client's id and secret from HTTP Basic (form-encoded per RFC 6749) or
/// the form body.
fn client_credentials(headers: &HeaderMap, form: &TokenForm) -> (String, String) {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"))
        .and_then(|(_, encoded)| STANDARD.decode(encoded.trim()).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|pair| {
            let (id, secret) = pair.split_once(':')?;
            let decode = |part: &str| {
                percent_decode_str(&part.replace('+', " "))
                    .decode_utf8_lossy()
                    .into_owned()
            };
            Some((decode(id), decode(secret)))
        });

    basic.unwrap_or_else(|| {
        (
            form.client_id.clone().unwrap_or_default(),
            form.client_secret.clone().unwrap_or_default(),
        )
    })
}
