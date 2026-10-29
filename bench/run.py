"""NeoZen microbenchmarks: the hot paths, against SQLite on disk.

Run from the repository root:

    uv run python bench/run.py            # every benchmark
    uv run python bench/run.py token scim # only those whose name matches

Each benchmark runs a few warm-up iterations, then reports the median and
95th percentile of one operation, in milliseconds.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import statistics
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
from pwdlib import PasswordHash
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from neozen.core.authz.services import AuthorizationService, RoleService
from neozen.core.email.base import EmailMessage
from neozen.core.factors.magic_link import MagicLinkConfig, MagicLinkFactor
from neozen.core.oauth.client_service import OAuthClientService
from neozen.core.oauth.services import OAuthTokenService
from neozen.core.scim.models import Email, User
from neozen.core.scim.service import SCIMUserService
from neozen.storage.sqlalchemy import Base
from neozen.storage.sqlalchemy.oauth_repositories import (
    OAuthAccessTokenRepository,
    OAuthAuthorizationCodeRepository,
    OAuthClientRepository,
    OAuthGrantRepository,
    OAuthRefreshTokenRepository,
)
from neozen.storage.sqlalchemy.repositories import (
    RoleAssignmentRepository,
    RoleRepository,
)
from neozen.storage.sqlalchemy.security_repositories import (
    SQLAlchemyMagicLinkTokenRepository,
)
from neozen.web.oauth import AuthorizationEndpoint, TokenEndpoint

SECRET = "bench-secret-key"
REDIRECT_URI = "https://app.example.com/callback"
PASSWORD = "correct horse battery staple"

type Operation = Callable[[], Awaitable[Any]]


@dataclass(frozen=True)
class Result:
    name: str
    iterations: int
    median_ms: float
    p95_ms: float


async def measure(name: str, operation: Operation, iterations: int) -> Result:
    for _ in range(3):  # warm-up
        await operation()
    timings = []
    for _ in range(iterations):
        start = time.perf_counter()
        await operation()
        timings.append((time.perf_counter() - start) * 1000)
    timings.sort()
    return Result(
        name=name,
        iterations=iterations,
        median_ms=statistics.median(timings),
        p95_ms=timings[int(len(timings) * 0.95) - 1],
    )


# -----------------------------------------------------------------------------
# Benchmarks: each returns the operation to time.
# -----------------------------------------------------------------------------


async def password_hash(_: async_sessionmaker[AsyncSession]) -> Operation:
    hasher = PasswordHash.recommended()

    async def operation() -> None:
        hasher.hash(PASSWORD)

    return operation


async def password_verify(_: async_sessionmaker[AsyncSession]) -> Operation:
    hasher = PasswordHash.recommended()
    hashed = hasher.hash(PASSWORD)

    async def operation() -> None:
        assert hasher.verify(PASSWORD, hashed)

    return operation


class _CapturingSender:
    def __init__(self) -> None:
        self.last: EmailMessage | None = None

    async def send(self, message: EmailMessage) -> None:
        self.last = message


class _EmailLookup:
    async def get_email(self, subject_id: str) -> str | None:
        return f"{subject_id}@example.com"

    async def subject_exists(self, subject_id: str) -> bool:
        return True


async def magic_link(sessions: async_sessionmaker[AsyncSession]) -> Operation:
    """Issue a link (store the token, send the email), then sign in with it."""
    sender = _CapturingSender()
    factor = MagicLinkFactor(
        config=MagicLinkConfig(link_base_url="https://app.example.com/magic"),
        token_repository=SQLAlchemyMagicLinkTokenRepository(sessions),
        subject_email_lookup=_EmailLookup(),
        email_sender=sender,
        token_hash_key=SECRET,
    )

    async def operation() -> None:
        subject_id = f"user-{secrets.token_hex(4)}"  # fresh: no rate limit
        await factor.begin_authentication(subject_id)
        assert sender.last is not None
        token = re.search(r"token=([\w-]+)", sender.last.body_text)
        assert token
        assert await factor.complete_authentication(subject_id, token.group(1))

    return operation


async def oauth_code_flow(sessions: async_sessionmaker[AsyncSession]) -> Operation:
    """Authorization request (existing grant) and token exchange, PKCE S256.

    A public client: a confidential one adds an Argon2 secret check, which
    `password_verify` measures.
    """
    async with sessions() as session:
        client_service = OAuthClientService(
            OAuthClientRepository(session=session), PasswordHash.recommended()
        )
        client, _ = await client_service.create_client(
            "Bench", [REDIRECT_URI], client_type="public"
        )
        await session.commit()
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64
        .urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    request = {
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    @dataclass(frozen=True)
    class Subject:
        id: str = "user-1"

    def endpoints(session: AsyncSession) -> tuple[AuthorizationEndpoint, TokenEndpoint]:
        clients = OAuthClientService(
            OAuthClientRepository(session=session), PasswordHash.recommended()
        )
        codes = OAuthAuthorizationCodeRepository(session=session)
        authorize = AuthorizationEndpoint(
            client_service=clients,
            grant_repository=OAuthGrantRepository(session=session),
            authorization_code_repository=codes,
            code_hash_key=SECRET,
        )
        token = TokenEndpoint(
            OAuthTokenService(
                client_repository=OAuthClientRepository(session=session),
                authorization_code_repository=codes,
                access_token_repository=OAuthAccessTokenRepository(session=session),
                refresh_token_repository=OAuthRefreshTokenRepository(session=session),
                token_hash_key=SECRET,
            ),
            clients,
        )
        return authorize, token

    # Consent once, so later requests go straight to a code.
    async with sessions() as session:
        authorize, _ = endpoints(session)
        page = await authorize.handle_authorization_request(request, Subject())
        assert page.consent_data
        await authorize.handle_consent(
            {
                **request,
                "approved": True,
                "consent_token": page.consent_data.consent_token,
            },
            Subject(),
        )
        await session.commit()

    async def operation() -> None:
        async with sessions() as session:
            authorize, token = endpoints(session)
            response = await authorize.handle_authorization_request(request, Subject())
            assert response.code
            tokens = await token(
                {
                    "grant_type": "authorization_code",
                    "code": response.code,
                    "redirect_uri": REDIRECT_URI,
                    "code_verifier": verifier,
                },
                client_id=client.client_id,
            )
            assert tokens.access_token
            await session.commit()

    return operation


class _MemoryUsers:
    """A SCIM adapter over a list: the benchmark measures NeoZen's filtering."""

    def __init__(self, users: list[User]) -> None:
        self.users = users

    async def list_all(self) -> list[User]:
        return self.users


async def scim_list(_: async_sessionmaker[AsyncSession]) -> Operation:
    """`GET /Users?filter=...` over 1,000 users, one page of 100."""
    users = [
        User(
            id=str(i),
            user_name=f"user{i}",
            emails=[Email(value=f"user{i}@{'example' if i % 2 else 'corp'}.com")],
            active=i % 3 != 0,
        )
        for i in range(1000)
    ]
    service = SCIMUserService(_MemoryUsers(users))

    async def operation() -> None:
        result = await service.list_users(
            filter_expr='emails.value ew "corp.com" and active eq true', count=100
        )
        assert result.total_results

    return operation


async def permission_check(sessions: async_sessionmaker[AsyncSession]) -> Operation:
    """`has_permission` for a subject with five roles, the match in the last."""
    async with sessions() as session:
        roles = RoleService(
            role_repository=RoleRepository(session=session),
            role_assignment_repository=RoleAssignmentRepository(session=session),
        )
        for resource in ["invoice", "order", "report", "ticket", "doc"]:
            await roles.create_role(f"{resource}-reader", [f"{resource}:read"])
            await roles.assign_role("user-1", f"{resource}-reader")
        await session.commit()

    async def operation() -> None:
        async with sessions() as session:
            authz = AuthorizationService(
                RoleService(
                    role_repository=RoleRepository(session=session),
                    role_assignment_repository=RoleAssignmentRepository(
                        session=session
                    ),
                )
            )
            assert await authz.has_permission("user-1", "doc:read")

    return operation


BENCHMARKS: dict[
    str, tuple[Callable[[async_sessionmaker[AsyncSession]], Awaitable[Operation]], int]
] = {
    "password_hash": (password_hash, 50),
    "password_verify": (password_verify, 50),
    "magic_link": (magic_link, 200),
    "oauth_code_flow": (oauth_code_flow, 200),
    "scim_list": (scim_list, 200),
    "permission_check": (permission_check, 500),
}


async def main(patterns: list[str]) -> None:
    selected = [n for n in BENCHMARKS if not patterns or any(p in n for p in patterns)]
    print(f"{'benchmark':<20} {'runs':>6} {'median ms':>10} {'p95 ms':>9}")
    for name in selected:
        with tempfile.TemporaryDirectory() as tmp:
            engine = create_async_engine(
                f"sqlite+aiosqlite:///{Path(tmp) / 'bench.db'}"
            )
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            sessions = async_sessionmaker(engine, expire_on_commit=False)
            setup, iterations = BENCHMARKS[name]
            result = await measure(name, await setup(sessions), iterations)
            await engine.dispose()
        print(
            f"{result.name:<20} {result.iterations:>6} "
            f"{result.median_ms:>10.2f} {result.p95_ms:>9.2f}"
        )


if __name__ == "__main__":
    anyio.run(main, sys.argv[1:])
