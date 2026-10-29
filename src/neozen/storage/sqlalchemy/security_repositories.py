"""SQLAlchemy repositories for security models."""

from __future__ import annotations

import contextlib
import json
import typing
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from neozen.core.audit.types import AuditLogEntry
from neozen.core.security.rate_limit_store import RateLimitEntry
from neozen.core.utils import ensure_utc
from neozen.storage.sqlalchemy.repositories import NeoZenRepository
from neozen.storage.sqlalchemy.security_models import (
    AccountLockout,
    AuditLog,
    LoginAttempt,
    MagicLinkToken,
    PasswordResetToken,
    RateLimitLock,
)


class LoginAttemptRepository(NeoZenRepository[LoginAttempt]):
    """Repository for login attempts."""

    model_type = LoginAttempt


class AccountLockoutRepository(NeoZenRepository[AccountLockout]):
    """Repository for account lockouts."""

    model_type = AccountLockout


class AuditLogRepository(NeoZenRepository[AuditLog]):
    """Repository for audit logs."""

    model_type = AuditLog


class PasswordResetTokenRepository(NeoZenRepository[PasswordResetToken]):
    """Repository for password reset tokens."""

    model_type = PasswordResetToken


class MagicLinkTokenRepository(NeoZenRepository[MagicLinkToken]):
    """Repository for magic link tokens."""

    model_type = MagicLinkToken


# =============================================================================
# Rate Limit Store (SQLAlchemy Implementation)
# =============================================================================


class SQLAlchemyRateLimitStore:
    """SQLAlchemy-backed rate limit store.

    Uses the LoginAttempt model to track rate limiting data.
    """

    def __init__(self, session_factory: typing.Callable[[], AsyncSession]) -> None:
        """Initialize with session factory."""
        self._session_factory = session_factory

    async def get(self, key: str) -> RateLimitEntry | None:
        """Get rate limit entry for key."""
        async with self._session_factory() as session:
            # Get the count of attempts for this key
            stmt = select(
                func.count(LoginAttempt.id).label("attempts"),
                func.min(LoginAttempt.timestamp).label("first_attempt"),
                func.max(LoginAttempt.timestamp).label("last_attempt"),
            ).where(LoginAttempt.key == key)

            result = await session.execute(stmt)
            row = result.one_or_none()

            if row is None or row.attempts == 0:
                return None

            lock = await session.get(RateLimitLock, key)
            locked_until = ensure_utc(lock.locked_until) if lock else None

            return RateLimitEntry(
                attempts=row.attempts,
                first_attempt_at=ensure_utc(row.first_attempt),
                last_attempt_at=ensure_utc(row.last_attempt),
                locked_until=locked_until,
            )

    async def set(
        self,
        key: str,
        entry: RateLimitEntry,
        ttl: timedelta | None = None,
    ) -> None:
        """Record the entry's lock; attempts are rows kept by `increment`.

        ``ttl`` is not needed: the lock ends at ``entry.locked_until``.
        """
        async with self._session_factory() as session:
            if entry.locked_until is None:
                await session.execute(
                    delete(RateLimitLock).where(RateLimitLock.key == key)
                )
            else:
                await session.merge(
                    RateLimitLock(key=key, locked_until=entry.locked_until)
                )
            await session.commit()

    async def increment(self, key: str) -> RateLimitEntry:
        """Increment attempt count."""
        async with self._session_factory() as session:
            now = datetime.now(UTC)
            attempt = LoginAttempt(
                key=key,
                success=False,
                timestamp=now,
            )
            session.add(attempt)
            await session.commit()

            # Get updated count
            stmt = select(
                func.count(LoginAttempt.id).label("attempts"),
                func.min(LoginAttempt.timestamp).label("first_attempt"),
                func.max(LoginAttempt.timestamp).label("last_attempt"),
            ).where(LoginAttempt.key == key)

            result = await session.execute(stmt)
            row = result.one()

            return RateLimitEntry(
                attempts=row.attempts,
                first_attempt_at=ensure_utc(row.first_attempt),
                last_attempt_at=ensure_utc(row.last_attempt),
            )

    async def delete(self, key: str) -> None:
        """Delete rate limit entry."""
        async with self._session_factory() as session:
            await session.execute(delete(LoginAttempt).where(LoginAttempt.key == key))
            await session.execute(delete(RateLimitLock).where(RateLimitLock.key == key))
            await session.commit()


# =============================================================================
# Audit Log Store (SQLAlchemy Implementation)
# =============================================================================


class SQLAlchemyAuditLogStore:
    """SQLAlchemy-backed audit log store."""

    def __init__(self, session_factory: typing.Callable[[], AsyncSession]) -> None:
        """Initialize with session factory."""
        self._session_factory = session_factory

    async def append(self, entry: AuditLogEntry) -> None:
        """Append an audit log entry."""
        async with self._session_factory() as session:
            log = AuditLog(
                id=entry.id,
                timestamp=entry.timestamp,
                event_type=entry.event_type,
                action=entry.action,
                outcome=entry.outcome,
                subject_id=entry.subject_id,
                actor_id=entry.actor_id,
                ip_address=entry.ip_address,
                user_agent=entry.user_agent,
                resource_type=entry.resource_type,
                resource_id=entry.resource_id,
                details=json.dumps(entry.details) if entry.details else None,
                request_id=entry.request_id,
            )
            session.add(log)
            await session.commit()

    def _apply_filters(
        self,
        stmt: typing.Any,
        *,
        subject_id: str | None = None,
        actor_id: str | None = None,
        event_type: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        ip_address: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> typing.Any:
        """Apply filters to an audit log query."""
        filters = [
            (subject_id, AuditLog.subject_id),
            (actor_id, AuditLog.actor_id),
            (event_type, AuditLog.event_type),
            (action, AuditLog.action),
            (outcome, AuditLog.outcome),
            (ip_address, AuditLog.ip_address),
            (resource_type, AuditLog.resource_type),
            (resource_id, AuditLog.resource_id),
        ]
        for value, column in filters:
            if value:
                stmt = stmt.where(column == value)

        if start_time:
            stmt = stmt.where(AuditLog.timestamp >= start_time)
        if end_time:
            stmt = stmt.where(AuditLog.timestamp <= end_time)

        return stmt

    async def query(
        self,
        *,
        subject_id: str | None = None,
        actor_id: str | None = None,
        event_type: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        ip_address: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLogEntry]:
        """Query audit logs with filters."""
        async with self._session_factory() as session:
            stmt = select(AuditLog).order_by(AuditLog.timestamp.desc())
            stmt = self._apply_filters(
                stmt,
                subject_id=subject_id,
                actor_id=actor_id,
                event_type=event_type,
                action=action,
                outcome=outcome,
                start_time=start_time,
                end_time=end_time,
                ip_address=ip_address,
                resource_type=resource_type,
                resource_id=resource_id,
            )
            stmt = stmt.offset(offset).limit(limit)

            result = await session.execute(stmt)
            logs = result.scalars().all()

            return [self._to_entry(log) for log in logs]

    async def count(
        self,
        *,
        subject_id: str | None = None,
        event_type: str | None = None,
        action: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """Count audit log entries matching filters."""
        async with self._session_factory() as session:
            stmt = select(func.count(AuditLog.id))

            if subject_id:
                stmt = stmt.where(AuditLog.subject_id == subject_id)
            if event_type:
                stmt = stmt.where(AuditLog.event_type == event_type)
            if action:
                stmt = stmt.where(AuditLog.action == action)
            if start_time:
                stmt = stmt.where(AuditLog.timestamp >= start_time)
            if end_time:
                stmt = stmt.where(AuditLog.timestamp <= end_time)

            result = await session.execute(stmt)
            return result.scalar() or 0

    async def get_by_id(self, entry_id: str) -> AuditLogEntry | None:
        """Get a specific audit log entry by ID."""
        async with self._session_factory() as session:
            stmt = select(AuditLog).where(AuditLog.id == entry_id)
            result = await session.execute(stmt)
            log = result.scalar_one_or_none()

            if log is None:
                return None

            return self._to_entry(log)

    def _to_entry(self, log: AuditLog) -> AuditLogEntry:
        """Convert SQLAlchemy model to AuditLogEntry."""
        details = {}
        if log.details:
            with contextlib.suppress(json.JSONDecodeError):
                details = json.loads(log.details)

        return AuditLogEntry(
            id=log.id,
            timestamp=log.timestamp,
            event_type=log.event_type,
            action=log.action,
            outcome=log.outcome,
            subject_id=log.subject_id,
            actor_id=log.actor_id,
            ip_address=log.ip_address,
            user_agent=log.user_agent,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            details=details,
            request_id=log.request_id,
        )


# =============================================================================
# Password Reset Token Repository (Enhanced)
# =============================================================================


class SQLAlchemyPasswordResetTokenRepository:
    """SQLAlchemy-backed password reset token repository.

    Implements the PasswordResetTokenRepository protocol.
    """

    def __init__(self, session_factory: typing.Callable[[], AsyncSession]) -> None:
        """Initialize with session factory."""
        self._session_factory = session_factory

    async def create(self, **kwargs: typing.Any) -> PasswordResetToken:
        """Create a new reset token."""
        async with self._session_factory() as session:
            token = PasswordResetToken(
                id=str(uuid.uuid4()),
                **kwargs,
            )
            session.add(token)
            await session.commit()
            await session.refresh(token)
            return token

    async def get_by_hash(self, token_hash: str) -> PasswordResetToken | None:
        """Get token by hash."""
        async with self._session_factory() as session:
            stmt = select(PasswordResetToken).where(
                PasswordResetToken.token_hash == token_hash
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def mark_used(self, token_id: str, used_at: datetime) -> None:
        """Mark token as used."""
        async with self._session_factory() as session:
            stmt = (
                update(PasswordResetToken)
                .where(PasswordResetToken.id == token_id)
                .values(used_at=used_at)
            )
            await session.execute(stmt)
            await session.commit()

    async def count_pending(
        self,
        subject_id: str,
        since: datetime,
    ) -> int:
        """Count pending (unused, unexpired) tokens for subject since time."""
        async with self._session_factory() as session:
            now = datetime.now(UTC)
            stmt = select(func.count(PasswordResetToken.id)).where(
                PasswordResetToken.subject_id == subject_id,
                PasswordResetToken.created_at >= since,
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.expires_at > now,
            )
            result = await session.execute(stmt)
            return result.scalar() or 0

    async def invalidate_all(self, subject_id: str) -> int:
        """Invalidate all pending tokens for subject."""
        async with self._session_factory() as session:
            now = datetime.now(UTC)
            stmt = (
                update(PasswordResetToken)
                .where(
                    PasswordResetToken.subject_id == subject_id,
                    PasswordResetToken.used_at.is_(None),
                )
                .values(used_at=now)
            )
            result = await session.execute(stmt)
            await session.commit()
            return result.rowcount or 0  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]


# =============================================================================
# Magic Link Token Repository (Enhanced)
# =============================================================================


class SQLAlchemyMagicLinkTokenRepository:
    """SQLAlchemy-backed magic link token repository.

    Implements the MagicLinkTokenRepository protocol.
    """

    def __init__(self, session_factory: typing.Callable[[], AsyncSession]) -> None:
        """Initialize with session factory."""
        self._session_factory = session_factory

    async def create(self, **kwargs: typing.Any) -> MagicLinkToken:
        """Create a new magic link token."""
        async with self._session_factory() as session:
            token = MagicLinkToken(
                id=str(uuid.uuid4()),
                **kwargs,
            )
            session.add(token)
            await session.commit()
            await session.refresh(token)
            return token

    async def get_by_hash(self, token_hash: str) -> MagicLinkToken | None:
        """Get token by hash."""
        async with self._session_factory() as session:
            stmt = select(MagicLinkToken).where(MagicLinkToken.token_hash == token_hash)
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def mark_used(self, token_id: str, used_at: datetime) -> None:
        """Mark token as used."""
        async with self._session_factory() as session:
            stmt = (
                update(MagicLinkToken)
                .where(MagicLinkToken.id == token_id)
                .values(used_at=used_at)
            )
            await session.execute(stmt)
            await session.commit()

    async def count_pending(
        self,
        subject_id: str,
        since: datetime,
    ) -> int:
        """Count pending (unused, unexpired) tokens for subject since time."""
        async with self._session_factory() as session:
            now = datetime.now(UTC)
            stmt = select(func.count(MagicLinkToken.id)).where(
                MagicLinkToken.subject_id == subject_id,
                MagicLinkToken.created_at >= since,
                MagicLinkToken.used_at.is_(None),
                MagicLinkToken.expires_at > now,
            )
            result = await session.execute(stmt)
            return result.scalar() or 0

    async def invalidate_all(self, subject_id: str) -> int:
        """Invalidate all pending tokens for subject."""
        async with self._session_factory() as session:
            now = datetime.now(UTC)
            stmt = (
                update(MagicLinkToken)
                .where(
                    MagicLinkToken.subject_id == subject_id,
                    MagicLinkToken.used_at.is_(None),
                )
                .values(used_at=now)
            )
            result = await session.execute(stmt)
            await session.commit()
            return result.rowcount or 0  # type: ignore[attr-defined]  # ty: ignore[unresolved-attribute]


__all__ = [
    "AccountLockoutRepository",
    "AuditLogRepository",
    "LoginAttemptRepository",
    "MagicLinkTokenRepository",
    "PasswordResetTokenRepository",
    "SQLAlchemyAuditLogStore",
    "SQLAlchemyMagicLinkTokenRepository",
    "SQLAlchemyPasswordResetTokenRepository",
    "SQLAlchemyRateLimitStore",
]
