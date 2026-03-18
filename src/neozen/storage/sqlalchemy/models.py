"""SQLAlchemy models for NeoZen.

This module contains all SQLAlchemy ORM models used by NeoZen:
- Subject: Authentication subjects (users)
- Session: Authentication sessions
- EmailVerificationToken: Email verification tokens
- Role: Authorization roles
- RoleAssignment: Role assignments to subjects
"""

from __future__ import annotations

from datetime import UTC, datetime

from advanced_alchemy.base import AuditColumns
from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from neozen.core.authz.models import ScopeType
from neozen.storage.sqlalchemy.base import Base


class Subject(AuditColumns, Base):
    """SQLAlchemy model for authentication subjects (users).

    Implements the fields required by:
    - EmailSubjectModel (email)
    - UsernameSubjectModel (username)
    - PasswordSubjectModel (hashed_password)
    """

    __tablename__ = "subjects"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    username: Mapped[str | None] = mapped_column(
        String(32), unique=True, nullable=True, index=True
    )
    hashed_password: Mapped[str | None] = mapped_column(Text(), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean(), default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)

    def __repr__(self) -> str:
        return f"<Subject id={self.id} email={self.email}>"


class Session(Base):
    """SQLAlchemy model for authentication sessions.

    Implements the fields required by SessionModel.
    """

    __tablename__ = "sessions"

    token_hash: Mapped[str] = mapped_column(String(128), primary_key=True)
    subject_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def __repr__(self) -> str:
        return f"<Session token_hash={self.token_hash[:8]}... subject_id={self.subject_id}>"


class EmailVerificationToken(Base):
    """SQLAlchemy model for email verification tokens.

    Implements the fields required by EmailVerificationTokenModel.
    """

    __tablename__ = "email_verification_tokens"

    token_hash: Mapped[str] = mapped_column(String(128), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    def __repr__(self) -> str:
        return (
            f"<EmailVerificationToken email={self.email} subject_id={self.subject_id}>"
        )


class Role(AuditColumns, Base):
    """SQLAlchemy model for authorization roles.

    A role is a named collection of permissions that can be assigned
    to subjects.
    """

    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    description: Mapped[str] = mapped_column(Text(), nullable=False, default="")
    permissions: Mapped[str] = mapped_column(
        Text(), nullable=False, default=""
    )  # Comma-separated permission strings
    is_system: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)

    def __repr__(self) -> str:
        return f"<Role id={self.id} name={self.name}>"

    def get_permissions_list(self) -> list[str]:
        """Return permissions as a list."""
        if not self.permissions:
            return []
        return [p.strip() for p in self.permissions.split(",") if p.strip()]

    def set_permissions_list(self, permissions: list[str]) -> None:
        """Set permissions from a list."""
        self.permissions = ",".join(permissions)


class RoleAssignment(Base):
    """SQLAlchemy model for role assignments.

    Links a subject to a role with optional scoping.
    """

    __tablename__ = "role_assignments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scope_type: Mapped[ScopeType] = mapped_column(
        Enum(ScopeType),
        default=ScopeType.GLOBAL,
        nullable=False,
    )
    scope_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    granted_by: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="SET NULL"),
        nullable=True,
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def __repr__(self) -> str:
        return f"<RoleAssignment subject={self.subject_id} role={self.role_id}>"


__all__ = [
    "EmailVerificationToken",
    "Role",
    "RoleAssignment",
    "Session",
    "Subject",
]
