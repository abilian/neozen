# NeoZen

**Authentication and authorization for modern Python applications.**

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)

NeoZen (**N**eoZe**N** = Auth**N** + Auth**Z**) is a framework-agnostic
authentication and authorization toolkit for Python — and, secondarily,
a lightweight self-hostable identity provider you can stand up in
front of one or more apps.

> **Status**: preparing the **0.9 first public release**. The bar is
> "clean": docs, tests, packaging, and the reference deployment are
> all in good shape. 0.9 is not yet semver-stable — the API may
> evolve before 1.0. See
> [`notes/plan/release-0.9.md`](notes/plan/release-0.9.md) for the
> release checklist.

## Two ways to use NeoZen

### As a library

`pip install neozen` and embed it in your own Litestar, Starlette,
Flask, or other Python web app. Bring your own User model. Pick
the factors and storage backend you need.

```bash
pip install "neozen[sqlalchemy,password]"
```

See the [Developer Quickstart](docs/src/get-started/quickstart.md) —
a runnable 80-line Litestar app in under five minutes.

### As a self-hosted service

`docker compose up -d` to run NeoZen as its own IAM service with
an admin console. Other apps talk to it over standard protocols.

```bash
cd deploy/docker
docker compose up -d
docker compose logs neozen | grep NEOZEN-BOOTSTRAP-CREDENTIALS -A 6
```

See the [Self-Hosted Quickstart](docs/src/get-started/self-hosted.md) —
a working self-hosted IAM in under ten minutes.

## What NeoZen provides

- **Authentication**: passwords (Argon2id), magic links, TOTP,
  email OTP, WebAuthn/passkeys, social login (Google, GitHub)
- **Authorization**: role-based access control (RBAC), permissions,
  policy-based authorization
- **OAuth 2.1 server**: authorization code with PKCE, refresh,
  client credentials
- **OpenID Connect 1.0 Provider**: discovery, JWKS, ID tokens,
  UserInfo, consent, RP-initiated logout, dynamic client registration
- **SCIM 2.0 server**: User and Group resources with filter parser
- **LDAP backend**: read-mostly LDAP/Active Directory with
  bind-based password authentication
- **Sessions, groups, invitations, rate limiting, account lockout,
  audit logging, i18n**
- **Framework adapters** for Flask, Litestar, Starlette
- **Admin console** (Litestar) with user management, bulk
  import/export, live audit log, security dashboard
- **Reference deployment**: Dockerfile, docker-compose, starter
  Helm chart, `neozen serve` production-mode CLI

## Design principles

- **Framework-agnostic** — works with Flask, Litestar, Starlette,
  or any WSGI/ASGI app
- **Protocol-based** — depend on interfaces, not implementations
- **Bring Your Own Model** — factory functions and split protocols
  let you plug your own User model without inheriting from NeoZen
  base classes
- **Secure by default** — Argon2id hashing, timing-safe comparison,
  rate limiting, account lockout, audit logging
- **Modular** — use only the components you need
- **Type-checked** across mypy, ty, and pyrefly

## Documentation

Full docs at <https://neozen.abilian.com/> (or build locally with
`make -C docs serve`).

- [Developer Quickstart (5 min)](docs/src/get-started/quickstart.md)
- [Self-Hosted Quickstart (10 min)](docs/src/get-started/self-hosted.md)
- [Cheat Sheet](docs/src/guides/cheat-sheet.md)
- [Bring Your Own Model](docs/src/guides/bring-your-own-model.md)

## Development

```bash
# Clone
git clone https://github.com/abilian/neozen.git
cd neozen

# Install with all extras
uv sync --all-extras

# Run the full test suite
uv run pytest tests/a_unit tests/b_integration tests/c_e2e

# Lint
uv run ruff check

# Build the docs
make -C docs serve
```

See [`notes/playbooks/INDEX.md`](notes/playbooks/INDEX.md) for the
project's development playbooks, and
[`notes/plan.md`](notes/plan.md) for the staged development plan.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).

NeoZen is sponsored by [Abilian SAS](https://abilian.com). Abilian's
interest in NeoZen is in consulting and integration services around
the OSS, not in a product upsell. There is no paid tier and no
open-core gating.
