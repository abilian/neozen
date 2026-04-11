# NeoZen

**Authentication and authorization for modern Python applications.**

NeoZen (**N**eoZe**N** = Auth**N** + Auth**Z**) is a framework-agnostic
authentication and authorization toolkit for Python — and, secondarily,
a lightweight self-hostable identity provider you can stand up in
front of one or more apps.

## Two ways to use NeoZen

<div class="grid cards" markdown>

-   :material-language-python:{ .lg .middle } **As a library**

    ---

    `pip install neozen` and embed it inside your own Litestar,
    Starlette, Flask, or other Python web app. Bring your own
    User model. Pick the factors and storage backend you need.

    [:octicons-arrow-right-24: Developer Quickstart (5 min)](getting-started/quickstart.md)

-   :material-server:{ .lg .middle } **As a self-hosted service**

    ---

    `docker compose up -d` to run NeoZen as its own IAM service
    with an admin console, OIDC provider, and SCIM endpoints.
    Other apps talk to it over standard protocols.

    [:octicons-arrow-right-24: Self-Hosted Quickstart (10 min)](getting-started/self-hosted.md)

</div>

The two paths share the same code. The library is the primary
shape; the self-hosted service is the same code wired into a
unified Litestar app via `neozen serve`.

## What NeoZen provides

- **Authentication**: passwords, magic links, TOTP, email OTP,
  WebAuthn/passkeys, social login (Google, GitHub)
- **Authorization**: role-based access control (RBAC), permissions,
  policy-based authorization
- **Groups & Invitations**: group membership management and
  email-based invitations
- **Session management**: secure token-based sessions with sliding
  window expiration
- **OAuth 2.1 server**: authorization code, refresh, and client
  credentials grants with PKCE
- **OpenID Connect 1.0 Provider**: ID tokens, JWKS, UserInfo,
  discovery, consent, RP-initiated logout, dynamic client
  registration
- **SCIM 2.0 server**: User and Group resources with filter parser
  and discovery
- **LDAP backend**: read-mostly LDAP/Active Directory subject store
  with bind authentication
- **Admin console**: a Litestar-based UI for managing subjects,
  roles, sessions, audit logs, and bulk import/export
- **i18n**: framework-agnostic catalog-based translation (EN/FR
  built-in)

## Design Principles

- **Framework-agnostic** — works with Flask, Litestar, Starlette,
  or any WSGI/ASGI app
- **Protocol-based** — depend on interfaces, not implementations
- **Bring Your Own Model** — factory functions and split protocols
  let you plug your own User model without inheriting from NeoZen
  base classes
- **Secure by default** — Argon2id hashing, timing-safe comparison,
  rate limiting, account lockout, audit logging
- **Modular** — use only the components you need

## Quick Example (library mode)

```python
from neozen.core.factors.password import create_password_factor
from neozen.core.identifiers.email import create_email_identifier

identifier = create_email_identifier(user_repo)
factor = create_password_factor(identifier, user_repo, hasher)

user = await factor.authenticate({
    "identifier": "alice@example.com",
    "password": "correct-horse-battery-staple",
})
```

For a complete runnable Litestar app, see the
[Developer Quickstart](getting-started/quickstart.md).

## License

NeoZen is **100% open source** under the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
No paid tier, no open-core gating.

## Project Status

NeoZen is preparing for the 1.0 release. Core authentication,
authorization, session management, framework integrations, OIDC
provider, SCIM server, LDAP backend, and admin console all ship
with extensive test coverage. The 1.0 release scope is documented
in [release-1.0.md](https://github.com/abilian/neozen/blob/main/notes/plan/release-1.0.md).

## Getting Started

Pick the path that matches your shape:

- **Embedding NeoZen in your app?** → [Developer Quickstart](getting-started/quickstart.md)
- **Running NeoZen as a service?** → [Self-Hosted Quickstart](getting-started/self-hosted.md)

Then dig into the guides:

- [Installation](getting-started/installation.md)
- [Bring Your Own Model](guides/bring-your-own-model.md)
- [Cheat Sheet](cheat-sheet.md) — common patterns at a glance
