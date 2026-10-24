# Installation

## Requirements

- Python 3.12.4+
- A database backend (SQLite for development, PostgreSQL for production)

## Install with uv

```bash
uv add neozen
```

## Optional Dependencies

NeoZen uses optional dependencies to keep the core lightweight:

```bash
# Password hashing (Argon2id)
uv add "neozen[password]"

# TOTP / MFA
uv add "neozen[totp]"

# WebAuthn / Passkeys
uv add "neozen[webauthn]"

# Social login (Google, GitHub)
uv add "neozen[oauth]"

# Everything
uv add "neozen[password,totp,webauthn,oauth]"
```

## Database Setup

NeoZen uses SQLAlchemy 2.0 with async support. For development,
SQLite works out of the box:

```python
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from neozen.storage.sqlalchemy.base import Base

engine = create_async_engine("sqlite+aiosqlite:///data/neozen.db")

async with engine.begin() as conn:
    await conn.run_sync(Base.metadata.create_all)

session_factory = async_sessionmaker(engine, class_=AsyncSession)
```

For production, use PostgreSQL:

```python
engine = create_async_engine(
    "postgresql+asyncpg://user:pass@localhost/neozen",
    pool_size=20,
)
```

## Verify Installation

```python
import neozen
print("NeoZen installed successfully")
```
