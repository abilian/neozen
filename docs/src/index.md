---
icon: lucide/shield-check
---

# NeoZen - Authentication and Authorization for Python

<p class="neozen-tagline">NeoZen gives any Python web app sign-in, sessions, roles and an identity provider.</p>

**NeoZen** (Auth**N** + Auth**Z**) is an open-source authentication and authorization toolkit for Python. Embed it in your Flask, Litestar or Starlette app, or run it as a self-hosted identity provider in front of several apps.

!!! warning "Development Status"
    NeoZen is preparing its first public release, 0.9. Its APIs can still change before 1.0.

## In six slides

<div class="deck" data-pdf="pdf/neozen.pdf"><a href="pdf/neozen.pdf">NeoZen, in six slides (PDF)</a></div>

## Quick Links

<div class="grid cards" markdown>

-   :material-language-python: **[Developer Quickstart](get-started/quickstart.md)**

    Embed NeoZen in your app, in five minutes

-   :material-server: **[Self-Hosted Quickstart](get-started/self-hosted.md)**

    Run NeoZen as its own service with Docker Compose

-   :material-account-cog: **[Bring Your Own Model](guides/bring-your-own-model.md)**

    Keep your own User model and database

-   :material-cog: **[Configuration](reference/configuration.md)**

    Every setting, with its default

</div>

## Two ways to use NeoZen

=== "As a library"

    `uv add neozen`, then embed it in your own Litestar, Starlette or Flask app. Bring your own User model, and pick the factors and the storage backend you need.

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

=== "As a self-hosted service"

    `docker compose up -d` runs NeoZen as its own identity service, with an admin console, an OpenID Connect provider and SCIM endpoints. Your other apps talk to it over standard protocols.

    ```bash
    cd deploy/docker
    docker compose up -d
    ```

Both share the same code: the service is the library, wired into one Litestar app by `neozen serve`.

## Why NeoZen?

### Framework-agnostic

The core has no web framework in it. Thin adapters connect it to Flask, Litestar and Starlette, and anything else can call the core directly.

### Your model, your database

NeoZen depends on protocols, not base classes. Keep your own User model, and store it with SQLAlchemy, Peewee, Tortoise or plain SQL.

### Secure by default

Argon2id password hashing, timing-safe comparisons, hashed session tokens, PKCE and refresh-token rotation come without configuration. Rate limiting, account lockout and audit logging are one setting each.

### Modular

Use only what you need: one sign-in factor and sessions, or the whole identity provider.

See all [Features](features.md).

## Getting Started

- **Embedding NeoZen in your app?** Start with the [Developer Quickstart](get-started/quickstart.md).
- **Running NeoZen as a service?** Start with the [Self-Hosted Quickstart](get-started/self-hosted.md).
- **Looking for a pattern?** The [Cheat Sheet](guides/cheat-sheet.md) has the common ones.

## License

NeoZen is open source under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). There is no paid tier and no open-core gating.

## Community

- **GitHub**: [github.com/abilian/neozen](https://github.com/abilian/neozen)
- **SourceHut**: [git.sr.ht/~sfermigier/neozen](https://git.sr.ht/~sfermigier/neozen)

---

*Copyright © 2026 [Abilian SAS](https://www.abilian.com/).*
