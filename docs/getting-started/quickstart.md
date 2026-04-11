# Developer Quickstart

**Audience**: a Python developer who wants `pip install neozen` to
handle authentication inside their app.

**Goal**: a runnable Litestar app with email+password login, in
under five minutes.

If instead you want to run NeoZen as a standalone IAM service that
your apps talk to over OIDC, see the
[Self-Hosted Quickstart](self-hosted.md).

---

## 1. Install

```bash
pip install "neozen[sqlalchemy,password,demo]"
```

The extras pull in:

- **`sqlalchemy`** — Advanced Alchemy + repositories (the recommended storage)
- **`password`** — Argon2id password hashing via `pwdlib`
- **`demo`** — Litestar + Jinja2 + uvicorn for the example below

You can swap `[sqlalchemy]` for `[peewee]`, `[tortoise]`, or
`[databases]` if you prefer a different ORM. NeoZen's storage
protocols are backend-agnostic.

## 2. Write the app

Create `app.py`:

```python
from __future__ import annotations

import secrets
from contextlib import asynccontextmanager

from litestar import Litestar, get, post
from litestar.exceptions import NotAuthorizedException
from litestar.response import Redirect
from pwdlib import PasswordHash
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.repositories import SubjectRepository
from neozen.storage.sqlalchemy import SessionServiceFactory

SECRET_KEY = "change-me-in-production"  # noqa: S105
DB_URL = "sqlite+aiosqlite:///./neozen.db"

engine = create_async_engine(DB_URL)
session_factory = async_sessionmaker(engine, expire_on_commit=False)
session_service = SessionServiceFactory(session_factory, SECRET_KEY)
hasher = PasswordHash.recommended()


@asynccontextmanager
async def lifespan(_app: Litestar):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


@post("/register")
async def register(data: dict) -> dict:
    async with session_factory() as db:
        repo = SubjectRepository(session=db)
        subject_id = f"user_{secrets.token_hex(8)}"
        await repo.create(
            id=subject_id,
            email=data["email"].lower(),
            hashed_password=hasher.hash(data["password"]),
            is_active=True,
            is_verified=False,
        )
        await db.commit()
    return {"id": subject_id}


@post("/login")
async def login(data: dict) -> dict:
    async with session_factory() as db:
        repo = SubjectRepository(session=db)
        try:
            subject = await repo.get_one_by(email=data["email"].lower())
        except Exception as exc:
            raise NotAuthorizedException("Invalid credentials") from exc
        valid, _ = hasher.verify_and_update(data["password"], subject.hashed_password)
        if not valid:
            raise NotAuthorizedException("Invalid credentials")
    token = await session_service.create_session(subject.id)
    return {"token": token}


@get("/me")
async def me(token: str) -> dict:
    session = await session_service.validate_session(token)
    if session is None:
        raise NotAuthorizedException("Invalid or expired session")
    return {"subject_id": session.subject_id}


app = Litestar(
    route_handlers=[register, login, me],
    lifespan=[lifespan],
)
```

## 3. Run it

```bash
uvicorn app:app --reload
```

In another terminal:

```bash
# Register
curl -X POST http://localhost:8000/register \
  -H 'Content-Type: application/json' \
  -d '{"email": "alice@example.com", "password": "correct-horse-battery"}'
# → {"id":"user_..."}

# Login
TOKEN=$(curl -sX POST http://localhost:8000/login \
  -H 'Content-Type: application/json' \
  -d '{"email": "alice@example.com", "password": "correct-horse-battery"}' \
  | python -c 'import sys, json; print(json.load(sys.stdin)["token"])')

# Authenticated request
curl "http://localhost:8000/me?token=$TOKEN"
# → {"subject_id":"user_..."}
```

That's the whole login flow: registration, password verification with
Argon2id, session token issuance, and session validation. ~80 lines
of application code, no boilerplate.

## What you got for free

- **Argon2id password hashing** with timing-safe comparison
- **Server-side sessions** with HMAC-protected tokens, sliding
  expiration, and revocation
- **SQLAlchemy 2.0 async** repositories via Advanced Alchemy
- **Bring Your Own Model** — `SubjectRepository` just speaks the
  `WritableRepositoryProtocol` interface; you can swap it for your
  own if you have an existing User model

## Where to go next

Once login works, layer on what you need. Each guide is independent:

- [Bring Your Own Model](../guides/bring-your-own-model.md) — plug
  NeoZen into an existing User model
- [Litestar Integration](../guides/litestar.md) — full Litestar
  app with login forms and protected routes
- [Flask Integration](../guides/flask.md) — Flask-Login-shaped
  experience with the same backend
- [Magic Link Authentication](../guides/magic-link.md) — passwordless
  login via email
- [TOTP / MFA](../guides/totp.md) — two-factor authentication
- [Authorization (RBAC)](../guides/authorization.md) — roles and
  permissions
- [OpenID Connect Provider](../guides/oidc.md) — turn your app into
  an OIDC provider for downstream services

If you outgrow the embed-in-your-app shape and want to run NeoZen as
its own service, jump to the [Self-Hosted Quickstart](self-hosted.md).
