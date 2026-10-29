# Bring Your Own Model

NeoZen's factors and identifiers use generic protocols. If your
application has its own User model (e.g., an SQLAlchemy model from
Advanced Alchemy), you don't need to inherit from NeoZen's base
classes. You just need to satisfy the structural interface.

## The Problem

NeoZen's `PasswordFactor` is generic:

```python
class PasswordFactor[S: PasswordSubjectModel]:
    def __init__(
        self,
        identifier: IdentifierProtocol[S],
        subject_storage: RepositoryProtocol[S],
        hasher: PasswordHasherProtocol,
    ) -> None: ...
```

If your `User` class doesn't inherit from `PasswordSubjectModel`,
type checkers complain even though it has all the right fields.

## Solution: Factory Functions

NeoZen provides factory functions that accept `Any`-typed storage,
so you don't need `type: ignore`:

```python
from neozen.core.identifiers.email import create_email_identifier
from neozen.core.factors.password import create_password_factor

# Your model -- no NeoZen inheritance needed
class User:
    id: str
    email: str
    hashed_password: str | None
    is_active: bool

# Your repository adapter
class UserRepoAdapter:
    async def get_one_by(self, **filters) -> User:
        # Wrap your ORM query
        ...
    async def update_obj(self, obj: User, **data) -> User:
        for k, v in data.items():
            setattr(obj, k, v)
        return obj
    # Other methods can raise NotImplementedError if unused

# Wire it up -- no type: ignore needed
adapter = UserRepoAdapter()
identifier = create_email_identifier(adapter)
factor = create_password_factor(identifier, adapter, hasher)

user = await factor.authenticate({
    "identifier": "alice@example.com",
    "password": "secret",
})
```

## Required Fields

Your model must structurally match these fields:

### For `EmailIdentifier`

| Field | Type | Used For |
|-------|------|----------|
| `email` | `str` | Lookup by email |
| `id` | `str` | Subject identifier |

### For `PasswordFactor`

| Field | Type | Used For |
|-------|------|----------|
| `hashed_password` | `str \| None` | Password verification |
| `id` | `str` | Subject identifier |

### For `TOTPFactor`

| Field | Type | Used For |
|-------|------|----------|
| `totp_secret` | `str \| None` | TOTP secret storage |
| `totp_enabled` | `bool` | Whether TOTP is active |
| `id` | `str` | Subject identifier |

## Repository Protocol

You only need to implement the methods that your factor actually calls.
NeoZen provides split protocols to make this explicit:

```python
from neozen.core.repository import ReadableRepositoryProtocol, WritableRepositoryProtocol

# PasswordFactor only needs these:
class MinimalAdapter:
    async def get_one_by(self, **filters) -> User:
        """Required: lookup user by email."""
        ...

    async def update_obj(self, obj: User, **data) -> User:
        """Required: update hashed_password after hash upgrade."""
        ...
```

### Which Methods Each Factor Uses

| Factor | `get_one_by` | `update_obj` | `create` | `get_many_by` | `count` | `exists` | `delete` |
|--------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| PasswordFactor | Yes | Yes | -- | -- | -- | -- | -- |
| TOTPFactor | Yes | Yes | -- | -- | -- | -- | -- |
| MagicLinkFactor | -- | -- | Yes | -- | Yes* | -- | -- |

*Via the token repository, not the subject repository.

## Dependency Injection with Dishka

If your app uses [dishka](https://dishka.readthedocs.io/), NeoZen ships providers instead of factory functions. `SQLAlchemyProvider` supplies the engine, one session per request and a `RepositoryProtocol[Model]` for any mapped model. The session never commits on its own: commit what you mean to keep. Anything uncommitted is rolled back when the request scope closes. The identifier providers build on it:

```python
import dishka
from sqlalchemy.ext.asyncio import AsyncSession

from neozen.core.identifiers import EmailIdentifierProvider, IdentifierProtocol
from neozen.storage.sqlalchemy import SQLAlchemyProvider, Subject

container = dishka.make_async_container(
    SQLAlchemyProvider("postgresql+asyncpg://localhost/app"),
    EmailIdentifierProvider(),
)

async with container() as request:
    identifier = await request.get(IdentifierProtocol[Subject])
    subject = await identifier.get_by_identifier("ada@example.com")
    ...
    await (await request.get(AsyncSession)).commit()
```

The email, username and phone providers all provide `IdentifierProtocol[M]` for any model, so register only one of them per container (or per dishka component).

For the OAuth authorization endpoint, build it from your configuration with `NeoZenFactory.create_authorization_endpoint(...)` (see the [configuration reference](../reference/configuration.md#oauth-server)) inside a provider of your own, passing it the repositories from `SQLAlchemyProvider`.
