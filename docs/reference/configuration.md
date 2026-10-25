# Configuration Reference

## Session Configuration

Passed to `SessionServiceFactory` or `SessionService`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `token_prefix` | `nz_session_` | Prefix for session tokens |
| `session_lifetime_seconds` | `604800` (7 days) | Maximum session duration |
| `sliding_window_seconds` | `3600` (1 hour) | Extension on activity (None to disable) |
| `max_sessions_per_subject` | None (unlimited) | Maximum concurrent sessions |

## Password Factor

`PasswordFactor` accepts a `PasswordHasherProtocol` implementation.
The recommended hasher is `pwdlib.PasswordHash.recommended()` which
uses Argon2id.

Password policy is enforced at the application level. NeoZen provides
`PasswordPolicy` for validation:

| Setting | Default | Description |
|---------|---------|-------------|
| `min_length` | 8 | Minimum password length |
| `max_length` | 128 | Maximum password length |
| `require_uppercase` | false | Require uppercase letter |
| `require_lowercase` | false | Require lowercase letter |
| `require_digit` | false | Require digit |
| `require_special` | false | Require special character |

## Magic Link Configuration

`MagicLinkConfig` (frozen dataclass):

| Setting | Default | Description |
|---------|---------|-------------|
| `token_lifetime` | 15 minutes | Token validity period |
| `max_pending_per_subject` | 3 | Max pending tokens (rate limit) |
| `rate_limit_window` | 1 hour | Rate limit window |
| `token_prefix` | `nz_ml_` | Token prefix |
| `link_base_url` | `""` (required) | Base URL for verify endpoint |

## TOTP Configuration

`TOTPConfig` (frozen dataclass):

| Setting | Default | Description |
|---------|---------|-------------|
| `issuer` | (required) | App name in authenticator |
| `digits` | 6 | OTP code length |
| `interval` | 30 | Code rotation (seconds) |
| `backup_code_count` | 8 | Number of backup codes |
| `backup_code_length` | 8 | Backup code length |

## Password Reset Configuration

`PasswordResetConfig` (frozen dataclass):

| Setting | Default | Description |
|---------|---------|-------------|
| `token_lifetime` | 1 hour | Reset token validity |
| `max_pending_requests` | 3 | Max pending resets per subject |
| `rate_limit_window` | 24 hours | Rate limit window |
| `token_prefix` | `nz_pr_` | Token prefix |

## Rate Limiting

`RateLimitConfig`:

| Setting | Default | Description |
|---------|---------|-------------|
| `max_attempts` | 5 | Max attempts in window |
| `window_seconds` | 60 | Time window |

## Account Lockout

`LockoutConfig`:

| Setting | Default | Description |
|---------|---------|-------------|
| `max_attempts` | 5 | Failures before lockout |
| `lockout_duration_seconds` | 300 | Lockout period |
| `progressive` | true | Increase duration on repeat lockouts |

## OAuth Server

The `[oauth_server]` section of `neozen.toml`. `NeoZenFactory` turns it into configured services: `create_oauth_token_service(...)`, `create_authorization_endpoint(...)` and `create_key_manager()`. They raise `ConfigError` unless `enabled = true`. Token and code hashes are keyed with `security.secret_key`.

| Setting | Default | Description |
|---------|---------|-------------|
| `enabled` | false | Allow the factory to build OAuth services |
| `access_token_lifetime` | `1h` | Access token validity |
| `refresh_token_lifetime` | `30d` | Refresh token validity |
| `authorization_code_lifetime` | `10m` | Authorization code validity |
| `require_pkce` | true | When false, confidential clients may skip PKCE. Public clients always need S256 |
| `allow_refresh_token_rotation` | true | Issue a new refresh token on each refresh and revoke the old one |
| `jwt_issuer` | unset | When set, access tokens are RFC 9068 JWTs (`typ: at+jwt`) with this `iss`; otherwise they are opaque |
| `jwt_audience` | unset | `aud` claim of JWT access tokens; required when `jwt_issuer` is set |
| `jwt_algorithm` | `RS256` | Signing algorithm: `RS256` or `ES256` |

JWT access tokens are signed with the active key of the `KeyManager` passed to `create_oauth_token_service`, so resource servers can verify them against the JWKS. They are still stored hashed, so introspection and revocation work as for opaque tokens. `create_key_manager()` returns an in-memory key manager for development; keys are lost on restart, so pass a persistent `KeyManager` in production.

```toml
[oauth_server]
enabled = true
access_token_lifetime = "15m"
jwt_issuer = "https://auth.example.com"
jwt_audience = "https://api.example.com"
jwt_algorithm = "ES256"
```

```python
factory = NeoZenFactory(load_config())
key_manager = factory.create_key_manager()
token_service = factory.create_oauth_token_service(
    client_repo, code_repo, access_token_repo, refresh_token_repo,
    key_manager=key_manager,
)
authorization_endpoint = factory.create_authorization_endpoint(
    client_service, grant_repo, code_repo
)
```

## Token Prefixes

| Prefix | Purpose |
|--------|---------|
| `nz_session_` | Session token |
| `nz_ev_` | Email verification |
| `nz_ml_` | Magic link |
| `nz_pr_` | Password reset |
| `nz_at_` | OAuth access token |
| `nz_rt_` | OAuth refresh token |
| `nz_ac_` | OAuth authorization code |
