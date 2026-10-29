"""SQLAlchemy models for production security features.

This module contains SQLAlchemy ORM models for:
- LoginAttempt: Track login attempts for rate limiting and lockout
- AuditLog: Security audit trail
- PasswordResetToken: Password reset tokens
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from neozen.storage.sqlalchemy.base import Base


class LoginAttempt(Base):
    """Track login attempts for rate limiting and lockout.

    Used by both RateLimiter and LockoutManager to track failed
    authentication attempts per IP and subject.
    """

    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    subject_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    ip_address: Mapped[str | None] = mapped_column(
        String(45), nullable=True, index=True
    )
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (Index("ix_login_attempts_key_timestamp", "key", "timestamp"),)

    def __repr__(self) -> str:
        return f"<LoginAttempt key={self.key} success={self.success}>"


class RateLimitLock(Base):
    """A rate-limit key locked out until a given time.

    The key is the limiter's (``login:ip:...``, say), not a subject ID.
    """

    __tablename__ = "rate_limit_locks"

    key: Mapped[str] = mapped_column(String(256), primary_key=True)
    locked_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class AccountLockout(Base):
    """Track account lockout state.

    Stores the current lockout state for subjects, including
    the number of lockout occurrences for progressive lockout.
    """

    __tablename__ = "account_lockouts"

    subject_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        primary_key=True,
    )
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    first_failed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_failed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    lockout_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    def __repr__(self) -> str:
        return f"<AccountLockout subject_id={self.subject_id} locked_until={self.locked_until}>"


class AuditLog(Base):
    """Security audit log entries.

    Stores all security-relevant events for compliance and
    forensic analysis.
    """

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    subject_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    ip_address: Mapped[str | None] = mapped_column(
        String(45), nullable=True, index=True
    )
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    request_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )

    __table_args__ = (
        Index("ix_audit_logs_timestamp_event", "timestamp", "event_type"),
        Index("ix_audit_logs_subject_timestamp", "subject_id", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action} outcome={self.outcome}>"


class PasswordResetToken(Base):
    """Password reset tokens.

    Stores hashed tokens for password reset with expiration
    and one-time use tracking.
    """

    __tablename__ = "password_reset_tokens"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    __table_args__ = (
        Index("ix_password_reset_subject_created", "subject_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<PasswordResetToken id={self.id} subject_id={self.subject_id}>"


class MagicLinkToken(Base):
    """Magic link authentication tokens.

    Stores hashed tokens for passwordless email authentication
    with expiration and one-time use tracking.
    """

    __tablename__ = "magic_link_tokens"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    __table_args__ = (
        Index("ix_magic_link_subject_created", "subject_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<MagicLinkToken id={self.id} subject_id={self.subject_id}>"


__all__ = [
    "AccountLockout",
    "AuditLog",
    "LoginAttempt",
    "MagicLinkToken",
    "PasswordResetToken",
    "RateLimitLock",
]
