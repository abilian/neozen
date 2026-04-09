# Quick Start

This guide shows how to set up email+password authentication with
NeoZen in a Litestar application.

## 1. Set Up the Database

```python
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.repositories import SubjectRepository

engine = create_async_engine("sqlite+aiosqlite:///data/app.db")

async with engine.begin() as conn:
    await conn.run_sync(Base.metadata.create_all)

session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
```

## 2. Create Session and Role Services

```python
from neozen.storage.sqlalchemy import SessionServiceFactory, RoleServiceFactory

session_service = SessionServiceFactory(session_factory, secret_key="change-me")
role_service = RoleServiceFactory(session_factory)
```

## 3. Register a User

```python
import secrets
from pwdlib import PasswordHash

hasher = PasswordHash.recommended()

async def register(email: str, password: str) -> str:
    async with session_factory() as db_session:
        repo = SubjectRepository(session=db_session)
        subject_id = f"user_{secrets.token_hex(8)}"

        await repo.create(
            id=subject_id,
            email=email,
            hashed_password=hasher.hash(password),
            is_active=True,
            is_verified=False,
        )
        await db_session.commit()

    # Assign default role
    await role_service.assign_role(subject_id, "user")
    return subject_id
```

## 4. Authenticate

```python
from neozen.core.factors.password import create_password_factor
from neozen.core.identifiers.email import create_email_identifier

async def login(email: str, password: str) -> str | None:
    async with session_factory() as db_session:
        repo = SubjectRepository(session=db_session)
        identifier = create_email_identifier(repo)
        factor = create_password_factor(identifier, repo, hasher)

        try:
            user = await factor.authenticate({
                "identifier": email,
                "password": password,
            })
        except Exception:
            return None

    # Create a session
    token = await session_service.create_session(
        user.id, ip_address="127.0.0.1"
    )
    return token
```

## 5. Validate a Session

```python
async def get_current_user(token: str):
    session = await session_service.validate_session(token)
    if session is None:
        return None
    # Load the user from the session's subject_id
    return session.subject_id
```

## Next Steps

- [Flask Integration](../guides/flask.md) -- full Flask app with login UI
- [Litestar Integration](../guides/litestar.md) -- full Litestar app
- [Magic Link Authentication](../guides/magic-link.md) -- passwordless login
- [TOTP / MFA](../guides/totp.md) -- two-factor authentication
- [Authorization](../guides/authorization.md) -- roles and permissions
