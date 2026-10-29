# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] — 2026-04-?? (unreleased)

**First public release.** 0.9 is not yet semver-stable — the API may
still evolve before 1.0 — but the bar is "clean": docs, tests,
packaging, and the reference deployment are all in good shape. See
[`notes/plan/release-0.9.md`](notes/plan/release-0.9.md) for the
full release checklist.

### Added

#### Core identity and authentication

- **Subjects**, email/username/phone identifiers with auto-detection
- **Password factor** using Argon2id via `pwdlib`, with timing-safe
  comparison and rehash-on-login
- **Magic link factor** — passwordless email login with 15-minute
  tokens, rate limiting, anti-enumeration
- **Email OTP factor** — 6-digit codes via email, 10-minute
  lifetime, constant-time verification
- **TOTP factor** (RFC 6238) with QR code enrollment and optional
  backup codes
- **WebAuthn/passkey factor** via `webauthn` library
- **Social login** via `oauth_client` with pre-built configs for
  Google and GitHub
- **Email verification flow** with GitHub-style prefixed tokens

#### Authorization

- **RBAC** with roles, permissions, and resource scopes
- **Policy-based authorization** for rules RBAC can't express
- **Guards and decorators** for Flask and Litestar
- Role lifecycle events (assigned, revoked)

#### Sessions

- Server-side sessions with HMAC-protected tokens
- Sliding-window expiration, per-subject limits, revocation
- Secure cookie defaults (`Secure`, `HttpOnly`, `SameSite=Lax`)

#### Protocol servers

- **OAuth 2.1 server**: authorization code (PKCE required for public clients, optional for confidential ones), refresh token with rotation and replay detection, client credentials, introspection (RFC 7662), revocation (RFC 7009), opaque or RFC 9068 JWT access tokens (RS256/ES256), configured from `[oauth_server]` via `NeoZenFactory`
- **OpenID Connect 1.0 Provider**: discovery, JWKS (mounted by each adapter's `create_oidc_*`), ID tokens with `nonce`, UserInfo, consent management, RP-initiated logout, dynamic client registration (RFC 7591), CORS helpers
- **dishka providers** for SQLAlchemy storage and the identifiers
- **SCIM 2.0 server**: User and Group resources, recursive-descent
  filter parser (eq/ne/co/sw/ew/gt/ge/lt/le/pr + and/or/not),
  pagination, discovery endpoints

#### Storage

- SQLAlchemy 2.0 + Advanced Alchemy (recommended)
- Peewee, Tortoise, raw SQL, in-memory backends
- **LDAP backend** (read-only) for OpenLDAP and Active Directory
  via pure-Python `ldap3`, with bind-based password authentication
- Split `ReadableRepositoryProtocol` and `WritableRepositoryProtocol`
  so consumers implement only what they need
- Factory functions (`create_email_identifier`,
  `create_password_factor`) for BYOM without `type: ignore`

#### Groups

- Group membership with owner/admin/member roles
- Last-owner protection, cascade delete
- Email-based invitation system with single-use tokens

#### i18n

- Framework-agnostic catalog-based translator
- Regional fallback (fr-CA → fr), `negotiate_locale` (RFC 4647),
  `str.format` substitution
- Built-in EN and FR catalogs for all built-in messages

#### Production hardening

- Rate limiting (per-identifier and per-IP)
- **Account lockout** with optional email notification via the
  new `LockoutEmailNotifier` bridge
- Audit logging
- Health checks

#### Admin console

- Litestar-based admin with Jinja2 templates and Tailwind/HTMX
- User management, roles, permissions, sessions, audit, groups,
  organizations
- **CSV bulk import/export** for subjects with dry-run preview
  and per-row results
- **Live polling** on audit log, security dashboard, and main
  dashboard counters via HTMX
- Security dashboard and configuration UI

#### Framework adapters

- **Flask** extension (Flask-Login shape)
- **Litestar** plugin with guards and subject loader
- **Starlette** middleware and backend

#### Reference deployment (0.9, new)

- `neozen.serve` package — `ServeConfig` with env + `_FILE`
  secret-mount variant, first-run admin bootstrap with grep-able
  credential banner, `/healthz` and `/readyz` endpoints
- `neozen serve` production-mode CLI command
- Multi-stage `Dockerfile` with non-root user, healthcheck, OCI labels
- `docker-compose.yml` with PostgreSQL 16
- Starter Helm chart
- Alembic migration tooling with async-URL auto-translation

#### Demo applications

- **Litestar demo**: password, magic link, TOTP 2FA, email OTP
- **Starlette demo**: password, TOTP 2FA
- **Flask demo**: password, magic link, TOTP 2FA with backup codes
- All demos runnable on SQLite with no external services

#### Documentation

- Documentation site built with Zensical, about 30 pages, with "NeoZen, in six slides" on the home page
- Developer quickstart (5 min embed-in-your-app)
- Self-hosted quickstart (10 min `docker compose up`)
- Architecture, factor protocols, storage abstraction
- Per-feature guides: BYOM, Flask, Litestar, magic link, TOTP,
  Email OTP, RBAC, groups, OIDC, SCIM, LDAP
- Cheat sheet

#### CLI

- `neozen subject`, `client`, `role`, `config`, `data`, `serve`
  command groups
- `neozen data dump/restore/populate` for JSON-based import/export
  and test data generation

### Changed

- License: Apache 2.0, with Apache-2.0 SPDX + classifier in
  `pyproject.toml`
- Python requirement: 3.12.4+ (3.12.0–3.12.3 can't resolve PEP 695 type parameters in `typing.get_type_hints`, which the dependency-injection layer relies on)
- Version: 0.1.0 → 0.9.0 across `pyproject.toml`, CLI `--version`,
  and `deploy/helm/Chart.yaml`

### Not in 0.9 (deferred to later 0.x or a future major version)

See [`notes/plan/release-0.9.md`](notes/plan/release-0.9.md) for the
full reasoning.

- **SAML 2.0 SP** — later 0.x point release
- **Approval workflows** — later 0.x point release
- **Temporal RBAC + JIT elevation** — later 0.x point release
- **OIDC/SCIM endpoints mounted into `neozen serve`** — later 0.x
  follow-up (the library half has full OIDC and SCIM support today)
- **Multi-tenancy** — future major version
- **SAML 2.0 IdP** — future major version

---

*No prior public releases.*
