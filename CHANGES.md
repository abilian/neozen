# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions 0.1.0 to 0.8.0 were never tagged or published. They are reconstructed from the commit history, one per development milestone.

## [Unreleased]

Maintenance release: fixes, hardening, performance and cleanup.

### Fixed

- **Security: account recovery by email accepted any code.** `verify_recovery` never checked the emailed code. The code is now derived from the recovery session with the secret key and checked; a wrong one ends the session
- **Security: any admin console admin could make themselves superadmin**, by granting the `superuser` role or adding `*` to a role. Defining roles and permissions, granting or removing `superuser`, acting on a superadmin's account and CSV imports that update users are now superadmin only
- **Passkeys (WebAuthn) never worked**: registration and sign-in called a pydantic method on py_webauthn's dataclasses; a catch-all reported the error as "verification failed". Only the library's own errors are caught now. A registration started twice (a retry, a second tab) completes
- **The Docker image didn't build**: the license file was missing from the build stage. It now also ships the migrations, so `alembic upgrade head` runs in the container
- Admin console sign-in: the password check no longer blocks other requests, takes as long whether or not the email exists, and stops after five failures in 15 minutes
- `SessionService.revoke_all_sessions`, and email verification after a second token was sent, failed when several rows matched
- `RoleServiceFactory.has_role` and `get_subject_roles` counted expired and scoped role assignments
- The database health check always reported unhealthy
- CLI role commands committed what they had done before failing
- Flask's `fresh_login_required` didn't check freshness; it now wants a session started within `max_age` (15 minutes). Flask decorators work on `async def` views
- The Litestar rate-limit middleware didn't find a limiter set on `app.state` as documented, and let every request through; without a limiter it now fails
- `redirect_uri` was normalized before the exact comparison (`https://host` became `https://host/`), so some registered URIs never matched
- The Litestar and Starlette OAuth adapters didn't await an async `get_current_subject`, so a coroutine passed for a signed-in subject. Litestar's `/token`, `/introspect` and `/revoke` were refused by CSRF protection
- RP-initiated logout could be triggered from another site: it now needs confirmation unless the `id_token_hint` verifies, and refuses a `client_id` that isn't the hint's audience
- SCIM bodies of the wrong shape returned 500 where a 400 was due, and `"active": "false"` was read as true
- Dynamic registration accepted any `token_endpoint_auth_method` and `response_types`
- The admin audit log search only filtered the page shown, and its count ignored the search
- With several `neozen serve` workers, admin sign-ins were lost when a request reached another worker (sessions are now kept in `NEOZEN_SESSION_DIR`)
- `neozen serve` created tables without recording their Alembic revision, so a later `alembic upgrade head` clashed with them
- The admin dashboard showed the number of users as the number of role assignments
- **An authorization code from `AuthorizationEndpoint` could never be redeemed**: the endpoint stores the code's HMAC, but the token service looked up the code itself. `AuthorizationEndpoint`'s `code_hash_key` must be the token service's `token_hash_key` (`NeoZenFactory` already uses one key for both)
- Magic links, password reset, account recovery, WebAuthn challenges, group invitations, social login state and `SessionService.list_sessions` failed with SQL storage on SQLite, which returns datetimes without a time zone
- SCIM filters on a multi-valued attribute (`emails.value ew "example.com"`, or `emails` alone) matched nothing; one matching value is now enough (RFC 7644 §3.4.2.2)
- An existing grant no longer skips consent when a client asks for more scopes than it covers; consenting widens the grant
- An authorization request may omit `redirect_uri` only when the client has exactly one registered (RFC 6749 §3.1.2.3); the first of several was used before
- `code` and `state` are appended correctly to a redirect URI that already has a query string
- Introspection and revocation return 400 for `invalid_request`, and 401 with `WWW-Authenticate` only for `invalid_client`
- Without a consent template, the Starlette and Litestar adapters answer `consent_required` with a 403 (it was a 200, and the Starlette one failed to serialize it)
- Client credentials in the `Authorization: Basic` header are form-decoded (RFC 6749 §2.3.1)
- Introspection returns `token_type: Bearer` for access tokens, and no `token_type` for refresh tokens
- Discovery advertises `plain` PKCE, which the server accepts
- SCIM: `count=0` returns no resources, only the total, and no page holds more than the advertised `filter.maxResults` (200)
- SCIM `/ServiceProviderConfig` no longer claims `changePassword` support by default
- Dynamic client registration accepts only https redirect URIs (http on a loopback host), plus reverse-domain private-use schemes for native clients, and only the scopes in `allowed_scopes` (by default `openid profile email`); a client that asks for none gets `allowed_scopes`, where it used to get every scope
- The rate limiter counts an attempt before deciding, so concurrent requests can't all pass on the same count
- `max_sessions_per_subject` is enforced: a new session past the limit revokes the subject's oldest one
- The `next=` parameter of the Starlette and Litestar login redirects is URL-encoded
- The Flask extension no longer turns a request refused by an earlier `before_request` hook (a CSRF check, for instance) into a 500
- Errors no longer pass silently: the HIBP check accepts the password only when the API is unreachable, and logs it; the admin console skips only missing rows; RP-initiated logout ignores only unknown clients and malformed ID tokens
- Admin console: logout is POST only, and `page` and `per_page` are validated (a bad value is a 400, `per_page` is at most 200)
- Updated dependencies with known vulnerabilities, among them `pyjwt`, `cryptography` and `starlette`
- A `[session]` table without `sliding_window` turned the sliding window off; it now keeps the one-hour default
- One failed row in a bulk import no longer makes the rows after it fail
- The raw SQL repository refuses column names that aren't fields of its model; they used to go straight into the query
- An admin console widget that polls after the session expired sends the browser to the login page; it used to show that page inside the widget
- The admin console and `neozen serve` close their database connections on shutdown

### Changed

- Every admin console change writes an audit entry naming the admin, the action and its target, and so does the CSV export, which is no longer cached and escapes values a spreadsheet would run as formulas
- `neozen serve` checks the database's Alembic revision at startup: a new database is created and stamped, an older one is refused until migrated
- With `prompt=none`, the authorization endpoint answers `login_required` or `consent_required` to the client, with no page; a malformed PKCE parameter is also sent back to the client
- 401 and 403 JSON bodies are the same in every adapter (`{"error": "unauthorized" | "forbidden", "detail": ...}`); Starlette answers a visitor who isn't signed in with 401 (it was 403)
- UserInfo answers a request without a token with a bare `Bearer` challenge (RFC 6750 §3.1); introspection responses are never cached
- Social login providers: a missing HTTP client is a `RuntimeError`, and only transport and response errors become `OAuthTokenError` or `OAuthUserInfoError`
- Configuration errors name the value they got. Settings typed as a set of choices are all checked
- The admin sessions page is paged
- The admin console's lists, counts and dashboards query the database a fixed number of times, whatever the number of rows: filtering, sorting and paging happen in SQL, and related rows come from joins. A permission check loads a subject's roles in two queries
- The Litestar plugin sends a visitor that `login_required()` refuses to the login page (it answered 401 unless the app handled it); `redirect=False` still gives a 401, and a handler the app registers for `AuthenticationRequiredError` still wins
- `TOTPFactor` and `WebAuthnFactor` fail as soon as they are created if `pyotp` or `webauthn` is missing
- Result types are frozen dataclasses: `TokenPair`, `AccessTokenResult`, `TokenResponse`, `IntrospectionResponse`, `RateLimitResult`, `LockoutStatus`, `IDTokenClaims`, `AuthorizationResponse` and the other results NeoZen returns
- Every 429 response, from any adapter, carries `Retry-After` and the `X-RateLimit-*` headers
- `id_generator` parameters default to a function returning a random hex ID (the default was `None`)
- `neozen serve` logs its configuration warnings (they were printed)

### Removed

- `OAuthClientService.cleanup_expired_states`, which deleted nothing and returned 0
- The admin console's unused `SUPPORT` and `AUDITOR` roles, `require_permission`, `require_admin` and `AdminUser`'s `can_*` properties and `has_permission`

### Added

- `registration_reply`, the HTTP answer to a dynamic registration request
- `role_service(session)`, a `RoleService` on the SQLAlchemy repositories
- Admin console responses forbid framing (`Content-Security-Policy: frame-ancestors 'none'`, `X-Frame-Options: DENY`) and send `X-Content-Type-Options` and `Referrer-Policy`
- Starting and ending an impersonation writes an audit entry with both the admin and the subject
- A CI check of the locked dependencies against known vulnerabilities (`pip-audit`)
- Demos: CSRF protection on every form; the `/api/test/*` endpoints that hand out sign-in links and codes exist only when `NEOZEN_DEMO_TEST_API=1`; the Flask demo follows only local `next=` paths
- Docs: HSTS and security headers, a recommended session limit, and the dynamic registration and CORS rules
- Benchmarks of the hot paths (`bench/run.py`) and a Performance page with baseline numbers
- The docs are built in CI, with `--strict`

## [0.9.0] - 2026-10-29

**First public release.** The bar for 0.9 is "clean": the docs, tests, packaging and reference deployment are all in good shape. 0.9 is not yet semver-stable, so the API may still change before 1.0.

### Added

- **OAuth server configuration**: `NeoZenFactory` builds the token service, authorization endpoint and key manager from `[oauth_server]`: lifetimes, refresh-token rotation, and an `issuer` shared by ID tokens, JWT access tokens and discovery
- **JWT access tokens** (RFC 9068), signed RS256 or ES256, behind the `jwt_access_tokens` switch. The key manager now supports EC keys
- **Optional PKCE for confidential clients** (`require_pkce = false`); public clients still need it
- **OIDC `nonce`**: the ID token returns the `nonce` sent with the authorization request
- **Discovery and JWKS routes** for each adapter: `create_oidc_router` (Litestar), `create_oidc_routes` (Starlette), `create_oidc_blueprint` (Flask)
- **dishka providers**: `SQLAlchemyProvider` (engine, per-request session, a repository for any model) and providers for the identifiers
- **CSRF protection** for the admin console and the OIDC consent form, which now includes a signed `consent_token` valid for ten minutes
- An Alembic revision that creates missing OAuth tables, adds the `nonce` column and makes the PKCE columns nullable
- `flask` and `starlette` extras for the framework adapters
- A CI check that installs the built wheel with no extra and runs the CLI
- Documentation site built with Zensical, with "NeoZen, in six slides" on the home page, and guides on protecting apps' own forms against CSRF

### Changed

- Python requirement: 3.12.4+ (3.12.0–3.12.3 can't resolve PEP 695 type parameters in `typing.get_type_hints`, which the dependency-injection layer relies on)
- `pwdlib` and `dishka` are core dependencies
- `TokenEndpoint` takes the client service, and authenticates the client on every grant
- `oauth_server.issuer` and `jwt_access_tokens` replace `jwt_issuer`
- Custom authorization code models need a `nonce` attribute
- Public clients always rotate refresh tokens
- Token responses are sent with `Cache-Control: no-store`
- `neozen serve` sets the `Secure` cookie flag by default (`NEOZEN_COOKIE_SECURE`)
- The admin console shows a plain message when an action fails, and `/readyz` no longer returns database errors
- `phonenumbers` is imported only when a phone number is checked
- Build backend: `uv_build`
- Version: 0.1.0 → 0.9.0 across `pyproject.toml`, CLI `--version`, and `deploy/helm/Chart.yaml`

### Removed

- `AuthorizationCodeGrant`, an unvalidated second way of issuing authorization codes

### Fixed

- The admin console had no authentication and a hard-coded demo login. Every route except login and health checks now needs a superuser or admin
- The admin session ID is rotated at login. The admin is reloaded on each request, so a removed role takes effect at once
- The consent submission re-runs the checks of the original authorization request
- The token endpoint checks client secrets, and returns 401 for a bad client; public clients can't use the client credentials grant
- Revocation is limited to the caller's own tokens, and public clients can't introspect tokens
- Authorization codes are single-use under concurrency, and a replayed refresh token revokes the client's tokens for that subject
- Rate limits are keyed on the peer address: clients could pick their bucket with `X-Forwarded-For`. Behind a proxy, set `FORWARDED_ALLOW_IPS`
- Security checks fail closed: a crashing pre-hook stops the operation, and factor enrollment errors propagate
- Litestar role and permission guards always returned 401; they now load the user, and deny with 403
- Flask runs async calls on one event loop per thread, and closes it when the thread ends
- The admin CSV export includes every subject, not the first 50
- Five admin pages that failed to render
- The OAuth tables were missing from the Alembic baseline
- Repository deletes work whatever the model's primary key
- The wheel failed to import without the `phone` extra

## [0.8.0] - 2026-04-11

### Added

- **Reference deployment**: the `neozen.serve` package, with `ServeConfig` (environment variables, and a `_FILE` variant for mounted secrets), a first-run admin bootstrap with a grep-able credential banner, and `/healthz` and `/readyz` endpoints
- `neozen serve`, the production-mode CLI command
- Multi-stage `Dockerfile` (non-root user, healthcheck, OCI labels), `docker-compose.yml` with PostgreSQL 16, and a starter Helm chart
- Alembic migrations, with a 1.0 baseline and async-URL auto-translation
- **Account lockout email notification**, through `LockoutEmailNotifier`
- Admin console: bulk-operations UI, and live polling on the audit log, the security dashboard and the dashboard counters, via HTMX
- Demos: TOTP enrollment and 2FA login in the Litestar and Starlette demos, email OTP login in the Litestar demo
- Developer quickstart (5 minutes, embedded in your app) and self-hosted quickstart (10 minutes, `docker compose up`)

### Changed

- License: Apache 2.0, with the SPDX identifier and classifier in `pyproject.toml`

## [0.7.0] - 2026-04-10

### Added

- **SCIM 2.0 server**: User and Group resources, a recursive-descent filter parser (eq/ne/co/sw/ew/gt/ge/lt/le/pr, and/or/not), pagination and discovery endpoints
- **LDAP backend** (read-only) for OpenLDAP and Active Directory, through pure-Python `ldap3`, with bind-based password authentication
- **CSV bulk import and export** of subjects in the admin console, with a dry-run preview and per-row results
- End-to-end tests for the OIDC and SCIM flows
- Guides for OIDC, SCIM, LDAP, groups and email OTP

## [0.6.0] - 2026-04-10

### Added

- **OpenID Connect 1.0 provider**: signing keys, ID tokens, discovery, JWKS and UserInfo endpoints
- **OIDC extras**: consent management, RP-initiated logout, dynamic client registration (RFC 7591) and CORS helpers
- **Client credentials grant** for the OAuth server
- **Email templates** and `NotificationService`
- **Email OTP factor**: 6-digit codes by email, a 10-minute lifetime and constant-time verification
- **Groups**: membership with owner, admin and member roles, last-owner protection and cascade delete
- **Invitations** by email, with single-use tokens
- **i18n**: a framework-agnostic, catalog-based translator, with regional fallback (fr-CA → fr), `negotiate_locale` (RFC 4647) and `str.format` substitution, and built-in English and French catalogs
- `neozen data dump`, `restore` and `populate`, for JSON-based import and export and test data
- Cheat sheet

## [0.5.0] - 2026-04-09

### Added

- **Magic link factor**: passwordless email sign-in, with 15-minute tokens, rate limiting and protection against account enumeration
- Magic link sign-in in the demos
- **Bring your own model**: split `ReadableRepositoryProtocol` and `WritableRepositoryProtocol`, so consumers implement only what they need, and factory functions (`create_email_identifier`, `create_password_factor`) that need no `type: ignore`
- Documentation site with Material for MkDocs: architecture, factor protocols, storage abstraction, and guides for bringing your own model, Flask, Litestar, magic links, TOTP and RBAC

## [0.4.0] - 2026-03-24

### Added

- **Admin console**: sign-in, a dashboard, management of users, groups and organizations, permission tools (matrix, role builder, access analyzer), an audit log viewer, a security dashboard, and configuration pages
- **Audit logging**, with event types and persistence
- **Rate limiting**, per identifier and per IP, with middleware for Flask, Starlette and Litestar
- **Account lockout**
- **Password reset** and **account recovery** flows
- Health checks
- A GitHub Actions workflow, and Playwright browser tests

### Changed

- The shared authentication factories moved to `neozen.storage.sqlalchemy`

## [0.3.0] - 2026-03-22

### Added

- **TOTP factor** (RFC 6238), with QR code enrollment and optional backup codes
- **WebAuthn / passkey factor**, through the `webauthn` library
- **Social login** through `oauth_client`, with ready-made configurations for Google and GitHub, and OAuth routes in each adapter
- **Password policy**
- **Factor protocols** and a factor registry
- **Events and hooks**: an event bus and a hook manager
- **Configuration system**: `NeoZenConfig` from TOML and environment variables, validation, `NeoZenFactory`, and `neozen config`
- OAuth server: authorization, introspection (RFC 7662) and revocation (RFC 7009) endpoints, and a client service
- TOTP 2FA in the Flask demo, with backup codes

## [0.2.0] - 2026-03-19

### Added

- **RBAC** with roles, permissions and resource scopes, and role lifecycle events
- **Policy-based authorization** for rules RBAC can't express
- A first admin console: a Litestar app with Jinja2 templates and Tailwind
- Peewee, Tortoise and raw SQL storage backends
- `neozen role`

## [0.1.0] - 2026-01-16

### Added

- **Subjects**, with email, username and phone identifiers and auto-detection
- **Password factor**, Argon2id through `pwdlib`, with timing-safe comparison and rehash on login
- **Email verification**, with GitHub-style prefixed tokens
- **Sessions**: server-side, with HMAC-protected tokens, a sliding expiry window, per-subject limits and revocation, and secure cookie defaults (`Secure`, `HttpOnly`, `SameSite=Lax`)
- **OAuth 2.1 server**: token endpoint with the authorization code grant (PKCE) and refresh tokens
- **Storage**: SQLAlchemy 2.0 with Advanced Alchemy, behind repository protocols
- **Framework adapters**: a Flask extension in the shape of Flask-Login, a Litestar plugin with guards, and Starlette middleware and backend
- `neozen subject` and `neozen client`
- Demo apps for Flask, Litestar and Starlette, running on SQLite with no external services
- CI on builds.sr.ht
