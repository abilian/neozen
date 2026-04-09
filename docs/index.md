# NeoZen

**Authentication and authorization for modern Python applications.**

NeoZen (**N**eoZe**N** = Auth**N** + Auth**Z**) is a framework-agnostic
toolkit that provides:

- **Authentication**: Passwords, magic links, TOTP, WebAuthn/passkeys, social login (Google, GitHub)
- **Authorization**: Role-based access control (RBAC), permissions, policy-based authorization
- **Session management**: Secure token-based sessions with sliding window expiration
- **OAuth 2.1 server**: Authorization code grant with PKCE

## Design Principles

- **Framework-agnostic** -- works with Flask, Litestar, Starlette, or any WSGI/ASGI app
- **Protocol-based** -- depend on interfaces, not implementations
- **Secure by default** -- Argon2id hashing, timing-safe comparison, rate limiting
- **Modular** -- use only the components you need

## Quick Example

```python
from neozen.core.factors.password import PasswordFactor
from neozen.core.identifiers.email import EmailIdentifier

identifier = EmailIdentifier(email_storage=user_repo)
factor = PasswordFactor(
    identifier=identifier,
    subject_storage=user_repo,
    hasher=password_hasher,
)

# Authenticate
user = await factor.authenticate({
    "identifier": "alice@example.com",
    "password": "correct-horse-battery-staple",
})
```

## Project Status

NeoZen is in active development. Core authentication, authorization,
session management, and framework integrations are implemented with
900+ tests. See the [roadmap](architecture/overview.md#roadmap) for
what's next.

## Getting Started

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quickstart.md)
- [Bring Your Own Model](guides/bring-your-own-model.md)
