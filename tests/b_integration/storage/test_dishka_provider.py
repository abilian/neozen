"""Building a dishka container from the SQLAlchemy and NeoZen providers."""

from __future__ import annotations

import contextlib
import typing
from datetime import UTC, datetime, timedelta

import dishka
import pytest
from sqlalchemy import String
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from neozen.core.identifiers import (
    EmailIdentifierProvider,
    IdentifierProtocol,
    PhoneIdentifierProvider,
    PhoneSubjectModel,
    UsernameIdentifierProvider,
)
from neozen.core.repository import RepositoryProtocol
from neozen.storage.sqlalchemy import Base, Subject
from neozen.storage.sqlalchemy.oauth_models import (
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthGrant,
)
from neozen.storage.sqlalchemy.provider import SQLAlchemyProvider

if typing.TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

pytestmark = pytest.mark.anyio


class PhoneBase(DeclarativeBase):
    pass


class PhoneUser(PhoneBase, PhoneSubjectModel):
    """An app model inheriting a NeoZen base (the built-in Subject has no phone).

    Also guards against a metaclass on the NeoZen bases, which would make
    this class definition fail.
    """

    __tablename__ = "phone_users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    phone: Mapped[str] = mapped_column(String(32))


@contextlib.asynccontextmanager
async def make_container(
    db_url: str, *providers: dishka.Provider
) -> AsyncIterator[dishka.AsyncContainer]:
    container = dishka.make_async_container(SQLAlchemyProvider(db_url), *providers)
    try:
        yield container
    finally:
        await container.close()


@pytest.fixture
async def db_url(tmp_path: Path) -> str:
    """A database holding one subject and one phone user."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'di.db'}"
    async with make_container(url) as container:
        engine = await container.get(AsyncEngine)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.run_sync(PhoneBase.metadata.create_all)
        async with container() as request:
            subjects = await request.get(RepositoryProtocol[Subject])
            await subjects.create(id="s1", email="ada@example.com", username="ada")
            phones = await request.get(RepositoryProtocol[PhoneUser])
            await phones.create(id="p1", phone="+33612345678")
            await (await request.get(AsyncSession)).commit()
    return url


async def test_email_identifier(db_url: str) -> None:
    async with (
        make_container(db_url, EmailIdentifierProvider()) as container,
        container() as request,
    ):
        identifier = await request.get(IdentifierProtocol[Subject])
        subject = await identifier.get_by_identifier("ada@example.com")
    assert subject.id == "s1"


async def test_username_identifier(db_url: str) -> None:
    async with (
        make_container(db_url, UsernameIdentifierProvider()) as container,
        container() as request,
    ):
        identifier = await request.get(IdentifierProtocol[Subject])
        subject = await identifier.get_by_identifier("ada")
    assert subject.id == "s1"


async def test_phone_identifier(db_url: str) -> None:
    provider = PhoneIdentifierProvider(default_region="FR")
    async with make_container(db_url, provider) as container, container() as request:
        identifier = await request.get(IdentifierProtocol[PhoneUser])
        subject = await identifier.get_by_identifier("+33612345678")
    assert subject.id == "p1"


async def test_uncommitted_writes_are_discarded(db_url: str) -> None:
    """The provider never commits: a request that doesn't commit leaves no trace,
    whether it fails or not."""

    async def create(*, fail: bool) -> None:
        async with make_container(db_url) as container, container() as request:
            subjects = await request.get(RepositoryProtocol[Subject])
            await subjects.create(id="s2", email="bob@example.com")
            if fail:
                raise RuntimeError

    with pytest.raises(RuntimeError):
        await create(fail=True)
    await create(fail=False)
    async with make_container(db_url) as container, container() as request:
        session = await request.get(AsyncSession)
        assert await session.get(Subject, "s2") is None


async def test_delete_uses_each_models_primary_key(db_url: str) -> None:
    async with make_container(db_url) as container, container() as request:
        clients = await request.get(RepositoryProtocol[OAuthClient])
        await clients.create(
            client_id="app",
            client_name="App",
            client_type="public",
            redirect_uris="[]",
            allowed_scopes="",
            allowed_grant_types="authorization_code",
            token_endpoint_auth_method="none",
        )
        codes = await request.get(RepositoryProtocol[OAuthAuthorizationCode])
        code = await codes.create(
            code="c1",
            client_id="app",
            subject_id="s1",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            response_type="code",
            scope="",
        )
        grants = await request.get(RepositoryProtocol[OAuthGrant])
        grant = await grants.create(
            client_id="app", subject_id="s1", granted_at=datetime.now(UTC), scope=""
        )

        await codes.delete(code)  # keyed on `code`
        await grants.delete(grant)  # composite key

        assert await codes.count() == 0
        assert await grants.count() == 0
