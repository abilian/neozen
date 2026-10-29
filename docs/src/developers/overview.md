# Architecture Overview

## Design Principles

1. **Framework-agnostic core** -- All authentication logic lives in `neozen.core`, with no framework imports. Framework-specific code lives in `neozen.ext`.

2. **Protocol-based** -- Components depend on protocols (interfaces), not implementations. Storage, email sending, password hashing are all pluggable.

3. **Functional core / imperative shell** -- Pure logic in the core, I/O at the edges. Factors, policies, and validators are stateless functions operating on data.

4. **Frozen dataclasses** -- Configuration and models use `@dataclass(frozen=True)` for immutability.

## Package Structure

```
src/neozen/
├── core/                   # Framework-agnostic core
│   ├── factors/            # Password, TOTP, WebAuthn, Magic Link
│   ├── identifiers/        # Email, Username, Phone
│   ├── session/            # Session management
│   ├── authz/              # RBAC, permissions, policies
│   ├── oauth/              # OAuth 2.1 server
│   ├── oauth_client/       # Social login (Google, GitHub)
│   ├── email/              # Email sender protocol + implementations
│   ├── security/           # Rate limiting, account lockout
│   ├── audit/              # Audit logging
│   ├── events/             # Event bus
│   ├── recovery/           # Password reset
│   ├── verification/       # Email verification
│   └── crypto.py           # Token generation, HMAC hashing
├── storage/
│   └── sqlalchemy/         # SQLAlchemy repositories + models
├── ext/
│   ├── flask/              # Flask extension
│   ├── starlette/          # Starlette middleware
│   └── litestar/           # Litestar plugin
├── admin/                  # Admin console (services + UI)
└── cli/                    # Command-line interface
```

## Data Flow

```
Request ──> Framework Extension ──> Core Factor ──> Storage
                   │                    │               │
                   │                    ▼               │
                   │              Verify / Create       │
                   │                    │               │
                   ◀────────────────────◀───────────────┘
                   │
              Response (session token, redirect, etc.)
```

## Key Abstractions

### RepositoryProtocol

All storage operations go through protocols:

```python
class ReadableRepositoryProtocol[Model](Protocol):
    async def get_one_by(self, **filters) -> Model: ...
    async def get_many_by(self, **filters) -> list[Model]: ...

class WritableRepositoryProtocol[Model](Protocol):
    async def create(self, **data) -> Model: ...
    async def update_obj(self, obj, **data) -> Model: ...

class RepositoryProtocol[Model](
    ReadableRepositoryProtocol[Model],
    WritableRepositoryProtocol[Model],
): ...
```

### FactorProtocol

Authentication methods implement one of three protocols:

- `AuthenticatingFactorProtocol` -- single-step (password)
- `ChallengingFactorProtocol` -- two-step (WebAuthn, magic link)
- `EnrollableFactorProtocol` -- requires setup (TOTP)

See [Factor Protocols](factors.md) for details.

### EmailSenderProtocol

```python
class EmailSenderProtocol(Protocol):
    async def send(self, message: EmailMessage) -> None: ...
```

Implementations: `ConsoleEmailSender` (dev), `SMTPEmailSender` (prod).

## Token Format

All tokens follow a GitHub-inspired format:

- 37 random characters (base62)
- 6-character CRC32 checksum
- Prefix identifying the token type

| Prefix | Purpose |
|--------|---------|
| `nz_session_` | Session token |
| `nz_ev_` | Email verification |
| `nz_ml_` | Magic link |
| `nz_pr_` | Password reset |
| `nz_at_` | OAuth access token |
| `nz_rt_` | OAuth refresh token |

Only the HMAC-SHA256 hash is stored in the database.

## Roadmap

Planned for later 0.x releases:

- SAML 2.0 service provider
- Approval workflows
- Temporal RBAC and just-in-time elevation
- OIDC and SCIM endpoints mounted into `neozen serve` (the library supports both today)

Planned for a future major version: multi-tenancy, and a SAML 2.0 identity provider.
