# Storage Abstraction

NeoZen uses protocol-based storage so any database backend can be used. The primary implementation is SQLAlchemy 2.0 with async support.

## Repository Protocols

The repository abstraction is split into three levels:

### ReadableRepositoryProtocol

Components that only need lookups depend on this protocol:

```python
class ReadableRepositoryProtocol[Model](Protocol):
    async def get_one_by(self, **filters) -> Model:
        """Get one object. Raises DoesNotExist if not found."""

    async def get_many_by(
        self, *, offset: int = 0, limit: int | None = None, **filters
    ) -> list[Model]:
        """Get multiple objects with pagination."""

    async def count(self, **filters) -> int:
        """Count matching objects."""

    async def exists(self, **filters) -> bool:
        """Check existence."""
```

### WritableRepositoryProtocol

Components that need mutations depend on this protocol:

```python
class WritableRepositoryProtocol[Model](Protocol):
    async def create(self, **data) -> Model: ...
    async def update_obj(self, obj: Model, **data) -> Model: ...
    async def delete(self, obj: Model) -> None: ...
```

### RepositoryProtocol

This protocol combines the two, and stays backwards compatible:

```python
class RepositoryProtocol[Model](
    ReadableRepositoryProtocol[Model],
    WritableRepositoryProtocol[Model],
    Protocol,
):
    model_type: type[Model]
```

All three are `@runtime_checkable`, so you can use `isinstance()` checks at runtime.

## Why Split?

The split addresses a common integration pain point: `PasswordFactor` only calls `get_one_by` and `update_obj`, but the old monolithic protocol required implementing 7 methods. Now consumers can implement just `ReadableRepositoryProtocol` or `WritableRepositoryProtocol` depending on what's needed.

## SQLAlchemy Implementation

NeoZen ships with a full SQLAlchemy implementation using Advanced Alchemy's repository pattern:

```python
from neozen.storage.sqlalchemy.repositories import (
    SubjectRepository,
    SessionRepository,
    RoleRepository,
)
from neozen.storage.sqlalchemy.base import Base

# Create tables
async with engine.begin() as conn:
    await conn.run_sync(Base.metadata.create_all)

# Use repositories
async with session_factory() as db_session:
    repo = SubjectRepository(session=db_session)
    subject = await repo.get_one_by(email="alice@example.com")
```

### Available Repositories

| Repository | Model | Table |
|-----------|-------|-------|
| `SubjectRepository` | `Subject` | `subjects` |
| `SessionRepository` | `Session` | `sessions` |
| `RoleRepository` | `Role` | `roles` |
| `RoleAssignmentRepository` | `RoleAssignment` | `role_assignments` |
| `EmailVerificationTokenRepository` | `EmailVerificationToken` | `email_verification_tokens` |
| `PasswordResetTokenRepository` | `PasswordResetToken` | `password_reset_tokens` |
| `MagicLinkTokenRepository` | `MagicLinkToken` | `magic_link_tokens` |
| `LoginAttemptRepository` | `LoginAttempt` | `login_attempts` |
| `AuditLogRepository` | `AuditLog` | `audit_logs` |

## Writing an Adapter

If you have your own ORM models, write an adapter:

```python
from neozen.core.repository import DoesNotExist

class UserRepoAdapter:
    def __init__(self, my_repo):
        self._repo = my_repo

    async def get_one_by(self, **filters):
        result = await self._repo.find_one(**filters)
        if result is None:
            raise DoesNotExist()
        return result

    async def update_obj(self, obj, **data):
        for k, v in data.items():
            setattr(obj, k, v)
        await self._repo.save(obj)
        return obj
```

See [Bring Your Own Model](../guides/bring-your-own-model.md) for a complete example.
