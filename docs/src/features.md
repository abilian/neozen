# Features

## Authentication

- **Passwords**: Argon2id hashing, a configurable password policy, and an optional check against Have I Been Pwned
- **Magic links**: one-time sign-in links sent by email ([guide](guides/magic-link.md))
- **TOTP**: authenticator apps, with backup codes ([guide](guides/totp.md))
- **Email OTP**: one-time codes sent by email ([guide](guides/email-otp.md))
- **WebAuthn / passkeys**: platform and roaming authenticators
- **Social login**: Google and GitHub, through the OAuth client ([reference](reference/oauth-client.md))
- **Identifiers**: email, username or phone number

## Sessions

- Token-based sessions, stored hashed, with a sliding expiry window ([reference](reference/sessions.md))
- Revocation of one session or of all of a user's sessions

## Authorization

- **Roles and permissions** (RBAC), with built-in roles and roles given to the first user ([guide](guides/authorization.md))
- **Policy-based checks** for rules that roles cannot express
- **Groups and invitations**: group membership, and invitations sent by email ([guide](guides/groups.md))

## Identity Provider

- **OAuth 2.1 server**: authorization code with PKCE, refresh token and client credentials grants; revocation and introspection; opaque or JWT access tokens
- **OpenID Connect 1.0 provider**: ID tokens, JWKS, UserInfo, discovery, consent, RP-initiated logout and dynamic client registration ([guide](guides/oidc.md))
- **SCIM 2.0 server**: User and Group resources, with filters and discovery ([guide](guides/scim.md))
- **LDAP backend**: a read-mostly LDAP or Active Directory subject store, with bind authentication ([guide](guides/ldap.md))

## Administration

- **Admin console**: a Litestar app to manage subjects, roles, groups, sessions and the audit log, with bulk import and export
- **`neozen serve`**: the console, the health checks and the database migrations in one self-hosted service ([quickstart](get-started/self-hosted.md))

## Security

- Timing-safe comparisons for secrets and tokens
- Rate limiting and account lockout ([configuration](reference/configuration.md))
- Audit logging
- CSRF protection in the admin console and the OIDC consent form
- Refresh-token rotation, with replay detection

## Integration

- **Frameworks**: adapters for [Flask](guides/flask.md), [Litestar](guides/litestar.md) and Starlette
- **Storage**: SQLAlchemy, Peewee, Tortoise ORM or plain SQL, behind one repository protocol ([architecture](developers/storage.md))
- **Your own model**: factory functions and protocols instead of base classes ([guide](guides/bring-your-own-model.md))
- **i18n**: catalog-based translations, with English and French built in
