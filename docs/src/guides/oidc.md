# OpenID Connect Provider

NeoZen includes a full OpenID Connect 1.0 Provider built on top of the OAuth 2.1 server. It provides discovery, JWKS, ID token signing, UserInfo, consent management, RP-initiated logout, and dynamic client registration.

## Installation

```bash
uv add "neozen[oidc]"
```

This installs `pyjwt[crypto]` for JWT signing.

## Quick Start

```python
from neozen.core.oidc import (
    InMemoryKeyManager,
    IDTokenGenerator,
    DefaultClaimsProvider,
)
from neozen.core.oidc.discovery import build_metadata_from_base_url
from neozen.web.oidc import (
    DiscoveryEndpoint,
    JWKSEndpoint,
    UserInfoEndpoint,
)

# Set up key management (rotates RSA signing keys)
key_manager = InMemoryKeyManager()  # use a persistent backend in prod

# ID token generator
id_token_gen = IDTokenGenerator(
    key_manager=key_manager,
    issuer="https://auth.example.com",
)

# Claims provider (reads attributes from your subject model)
claims_provider = DefaultClaimsProvider(my_subject_lookup)

# Discovery metadata
metadata = build_metadata_from_base_url(
    issuer="https://auth.example.com",
    base_url="https://auth.example.com",
)

# HTTP endpoints
discovery = DiscoveryEndpoint(metadata)
jwks = JWKSEndpoint(key_manager)
userinfo = UserInfoEndpoint(
    token_service=oauth_token_service,
    claims_provider=claims_provider,
)
```

Each adapter can mount discovery and JWKS for you: `create_oidc_router` (Litestar), `create_oidc_routes` (Starlette) and `create_oidc_blueprint` (Flask), from `neozen.ext.<framework>.oauth`. With a config file, `NeoZenFactory` builds the ID token generator and the discovery metadata from `[oauth_server]` (see the [configuration reference](../reference/configuration.md#oauth-server)), so the issuer and signing keys are the same everywhere.

## Endpoints

| Endpoint | Path | Returns |
|----------|------|---------|
| Discovery | `/.well-known/openid-configuration` | Provider metadata |
| JWKS | `/.well-known/jwks.json` | Public signing keys |
| UserInfo | `/userinfo` | Subject claims (Bearer auth) |
| End Session | `/oauth/end_session` | Logout flow |
| Registration | `/oauth/register` | Dynamic client registration |

## Consent Form

When a user hasn't yet granted a client access, the authorization endpoint answers with `requires_consent` and a `consent_data` object, and your app renders the consent page. Its form posts back to the authorization endpoint with every field of `consent_data` as a hidden input, plus the user's answer:

```html
<form method="post" action="/oauth/authorize">
  {% for name in ["client_id", "redirect_uri", "scope", "state",
                  "code_challenge", "code_challenge_method", "nonce",
                  "consent_token"] %}
    <input type="hidden" name="{{ name }}" value="{{ consent_data[name] or '' }}">
  {% endfor %}
  <button name="approved" value="true">Allow</button>
  <button name="approved" value="false">Deny</button>
</form>
```

`consent_token` is what makes the form safe against cross-site request forgery: it is signed, expires after ten minutes, and is bound to the signed-in user and to the exact request. A submission without a valid one is refused, whatever framework serves the page. Your other forms (login, logout, settings) need your framework's CSRF protection: see the [Flask](flask.md#csrf-protection) and [Litestar](litestar.md#csrf-protection) guides; with Starlette, use a middleware such as [starlette-csrf](https://github.com/frankie567/starlette-csrf). Empty values are fine: missing PKCE fields count as absent.

## Key Management

The `KeyManager` protocol manages RSA signing keys for ID tokens:

```python
manager = InMemoryKeyManager()

# Get current signing key
key = await manager.get_active_signing_key()

# Rotate (old key kept for verification of in-flight tokens)
new_key = await manager.rotate_key()

# Get all public keys (for JWKS)
jwks = await manager.get_jwks()
```

For production, implement `KeyManager` against a persistent store (database, file, or KMS).

## ID Tokens

ID tokens are returned automatically from the OAuth token endpoint when the request includes the `openid` scope:

```python
from neozen.web.oauth import TokenEndpoint

endpoint = TokenEndpoint(
    oauth_token_service,
    oauth_client_service,  # authenticates the client on every request
    id_token_generator=id_token_gen,
    claims_provider=claims_provider,
)
# Now POST /token with scope=openid email returns id_token in the response
```

## Scopes and Claims

Standard OIDC scope-to-claims mapping is built in:

| Scope | Claims |
|-------|--------|
| `openid` | `sub` |
| `profile` | name, family_name, given_name, preferred_username, picture, locale, ... |
| `email` | email, email_verified |
| `phone` | phone_number, phone_number_verified |
| `address` | address |

## Consent Management

```python
from neozen.core.oidc.consent import ConsentService

service = ConsentService(repository=consent_repo)

# Check before authorization
if not await service.has_consent(user_id, client_id, "openid email"):
    # Show consent screen
    ...

# Grant
await service.grant_consent(user_id, client_id, "openid email")

# List trusted apps
apps = await service.list_trusted_apps(user_id)

# Revoke
await service.revoke_consent(user_id, client_id)
```

## RP-Initiated Logout

```python
from neozen.web.oidc import EndSessionEndpoint

endpoint = EndSessionEndpoint(client_service)
result = await endpoint(query_params)

if result.post_logout_redirect_uri:
    # Destroy session, then redirect
    ...
```

## Dynamic Client Registration

```python
from neozen.web.oidc import RegistrationEndpoint

endpoint = RegistrationEndpoint(client_service)
response = await endpoint({
    "redirect_uris": ["https://app.example.com/callback"],
    "client_name": "My App",
})
# Returns client_id, client_secret, etc.
```

Registration accepts https redirect URIs, and http ones only on a loopback host (`localhost`, `127.0.0.1`, `::1`). A native client (`"application_type": "native"`) can also use a private-use scheme in reverse-domain form, such as `com.example.app:/callback`. A client can register only for the scopes in `allowed_scopes` (by default `openid profile email`), and gets all of them when it asks for none.

The endpoint is not authenticated: restrict access to it, for instance with an initial access token, before exposing it.

## CORS

```python
from neozen.web.oidc.cors import collect_allowed_origins

origins = await collect_allowed_origins(client_service)
# Use as CORS middleware allowed_origins
```

Every active client's redirect URIs become allowed origins, including those of dynamically registered clients. Don't allow credentials (cookies) in that CORS configuration: the token, UserInfo and JWKS endpoints don't need them.
