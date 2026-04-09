"""Integration tests for SQLAlchemy magic link token repository."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.repositories import SubjectRepository
from neozen.storage.sqlalchemy.security_repositories import (
    SQLAlchemyMagicLinkTokenRepository,
)


@pytest.fixture
async def session_factory():
    """Create an in-memory SQLite database and session factory."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    await engine.dispose()


@pytest.fixture
async def subject_id(session_factory: async_sessionmaker) -> str:
    """Create a test subject and return its ID."""
    sid = f"user_{secrets.token_hex(8)}"
    async with session_factory() as session:
        repo = SubjectRepository(session=session)
        await repo.create(
            id=sid,
            email=f"{sid}@test.com",
            hashed_password="hashed_pw",
            is_active=True,
            is_verified=False,
        )
        await session.commit()
    return sid


@pytest.fixture
def token_repo(
    session_factory: async_sessionmaker,
) -> SQLAlchemyMagicLinkTokenRepository:
    """Create a magic link token repository."""
    return SQLAlchemyMagicLinkTokenRepository(session_factory)


class TestSQLAlchemyMagicLinkTokenRepository:
    """Integration tests for MagicLinkToken SQLAlchemy repository."""

    @pytest.mark.anyio
    async def test_create_token(
        self,
        token_repo: SQLAlchemyMagicLinkTokenRepository,
        subject_id: str,
    ) -> None:
        now = datetime.now(UTC)
        token = await token_repo.create(
            subject_id=subject_id,
            token_hash="hash_abc123",
            email=f"{subject_id}@test.com",
            created_at=now,
            expires_at=now + timedelta(minutes=15),
            used_at=None,
            ip_address="127.0.0.1",
        )

        assert token.id is not None
        assert token.subject_id == subject_id
        assert token.token_hash == "hash_abc123"
        assert token.email == f"{subject_id}@test.com"
        assert token.used_at is None

    @pytest.mark.anyio
    async def test_get_by_hash(
        self,
        token_repo: SQLAlchemyMagicLinkTokenRepository,
        subject_id: str,
    ) -> None:
        now = datetime.now(UTC)
        await token_repo.create(
            subject_id=subject_id,
            token_hash="hash_lookup_test",
            email="test@example.com",
            created_at=now,
            expires_at=now + timedelta(minutes=15),
            used_at=None,
            ip_address=None,
        )

        found = await token_repo.get_by_hash("hash_lookup_test")
        assert found is not None
        assert found.subject_id == subject_id

    @pytest.mark.anyio
    async def test_get_by_hash_not_found(
        self,
        token_repo: SQLAlchemyMagicLinkTokenRepository,
    ) -> None:
        found = await token_repo.get_by_hash("nonexistent_hash")
        assert found is None

    @pytest.mark.anyio
    async def test_mark_used(
        self,
        token_repo: SQLAlchemyMagicLinkTokenRepository,
        subject_id: str,
    ) -> None:
        now = datetime.now(UTC)
        token = await token_repo.create(
            subject_id=subject_id,
            token_hash="hash_mark_used",
            email="test@example.com",
            created_at=now,
            expires_at=now + timedelta(minutes=15),
            used_at=None,
            ip_address=None,
        )

        await token_repo.mark_used(token.id, now)

        found = await token_repo.get_by_hash("hash_mark_used")
        assert found is not None
        assert found.used_at is not None

    @pytest.mark.anyio
    async def test_count_pending(
        self,
        token_repo: SQLAlchemyMagicLinkTokenRepository,
        subject_id: str,
    ) -> None:
        now = datetime.now(UTC)
        since = now - timedelta(hours=1)

        # Create 2 pending tokens
        for i in range(2):
            await token_repo.create(
                subject_id=subject_id,
                token_hash=f"hash_pending_{i}",
                email="test@example.com",
                created_at=now,
                expires_at=now + timedelta(minutes=15),
                used_at=None,
                ip_address=None,
            )

        # Create 1 used token
        token = await token_repo.create(
            subject_id=subject_id,
            token_hash="hash_used",
            email="test@example.com",
            created_at=now,
            expires_at=now + timedelta(minutes=15),
            used_at=None,
            ip_address=None,
        )
        await token_repo.mark_used(token.id, now)

        count = await token_repo.count_pending(subject_id, since)
        assert count == 2

    @pytest.mark.anyio
    async def test_invalidate_all(
        self,
        token_repo: SQLAlchemyMagicLinkTokenRepository,
        subject_id: str,
    ) -> None:
        now = datetime.now(UTC)

        for i in range(3):
            await token_repo.create(
                subject_id=subject_id,
                token_hash=f"hash_invalidate_{i}",
                email="test@example.com",
                created_at=now,
                expires_at=now + timedelta(minutes=15),
                used_at=None,
                ip_address=None,
            )

        invalidated = await token_repo.invalidate_all(subject_id)
        assert invalidated == 3

        # All should now be marked as used
        since = now - timedelta(hours=1)
        count = await token_repo.count_pending(subject_id, since)
        assert count == 0

    @pytest.mark.anyio
    async def test_count_pending_ignores_other_subjects(
        self,
        token_repo: SQLAlchemyMagicLinkTokenRepository,
        session_factory: async_sessionmaker,
        subject_id: str,
    ) -> None:
        # Create a second subject
        other_id = f"user_{secrets.token_hex(8)}"
        async with session_factory() as session:
            repo = SubjectRepository(session=session)
            await repo.create(
                id=other_id,
                email=f"{other_id}@test.com",
                hashed_password="pw",
                is_active=True,
                is_verified=False,
            )
            await session.commit()

        now = datetime.now(UTC)
        since = now - timedelta(hours=1)

        # Token for subject_id
        await token_repo.create(
            subject_id=subject_id,
            token_hash="hash_subj1",
            email="a@test.com",
            created_at=now,
            expires_at=now + timedelta(minutes=15),
            used_at=None,
            ip_address=None,
        )

        # Token for other subject
        await token_repo.create(
            subject_id=other_id,
            token_hash="hash_subj2",
            email="b@test.com",
            created_at=now,
            expires_at=now + timedelta(minutes=15),
            used_at=None,
            ip_address=None,
        )

        count = await token_repo.count_pending(subject_id, since)
        assert count == 1
