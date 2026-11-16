# Persona IdP

An OpenID Connect provider for test environments. An application signs in against it exactly as
against a production identity provider (for example Microsoft Entra ID); the person picks one of
the users in a personas file and the application receives an id_token for that user's email. The
application keeps its own roles and permissions per email.

With `PERSONA_IDP_UPSTREAM_*` set, the person first signs in at that OpenID Connect provider;
without them (local development) the picker is the only step.

Never expose an instance without an upstream sign-in to untrusted users: anyone who reaches it can
become any persona.

## Image

```sh
docker run --rm -p 8080:8080 \
  -e OAUTH_ISSUER_URL=http://localhost:8080 \
  -e OAUTH_CLIENT_ID=example-app \
  -e OAUTH_CLIENT_SECRET=example-secret \
  -e OAUTH_REDIRECT_URI=http://localhost:8000/sign-in \
  -e PERSONA_IDP_NO_UPSTREAM=true \
  -e PERSONA_IDP_PERSONAS_FILE=/run/config/personas.json \
  -v "$PWD/personas.example.json:/run/config/personas.json:ro" \
  cubesystems/persona-idp:v1.0.0
```

Tags are listed in [RELEASING.md](RELEASING.md).

## Configuration

| Variable | Meaning |
| --- | --- |
| `OAUTH_ISSUER_URL`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_REDIRECT_URI` | The application's own OAuth client values; the issuer URL is this service's public URL |
| `PERSONA_IDP_NO_UPSTREAM` | `true` offers the personas without any sign-in (local development); required when no upstream is set |
| `PERSONA_IDP_PERSONAS_FILE` | JSON list of `{"name", "email"}` objects, see [personas.example.json](personas.example.json) |
| `PERSONA_IDP_UPSTREAM_ISSUER_URL`, `PERSONA_IDP_UPSTREAM_CLIENT_ID`, `PERSONA_IDP_UPSTREAM_CLIENT_SECRET` | The upstream provider's client; register `<issuer URL>/callback` as its redirect URI |
| `PERSONA_IDP_LISTEN_HOST`, `PERSONA_IDP_LISTEN_PORT` | Listen address, default `0.0.0.0:8080`. Not `PERSONA_IDP_PORT`: Kubernetes sets that for a Service named `persona-idp` |

## Limits

- An authorization code is a sealed token valid for 60 seconds and is not marked as used, so it can
  be exchanged more than once in that time. Exchanging it needs the client secret and the PKCE
  verifier.
- The id_token signing key and the key sealing codes and sign-in state are random and generated at
  startup, so a restart ends the sign-ins in progress and publishes a new signing key. Run a single
  instance.

## Development

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo audit
```
