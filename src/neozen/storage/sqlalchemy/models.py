"""SQLAlchemy models for NeoZen.

This module contains all SQLAlchemy ORM models used by NeoZen:
- Subject: Authentication subjects (users)
- Session: Authentication sessions
- EmailVerificationToken: Email verification tokens
- Role: Authorization roles
- RoleAssignment: Role assignments to subjects
- PasswordHistory: Password history for reuse prevention
- BackupCode: TOTP backup codes
- SocialAccount: OAuth social login accounts
- OAuthState: OAuth authorization state for PKCE
- WebAuthnCredential: WebAuthn/Passkey credentials
- WebAuthnChallenge: WebAuthn challenge storage
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
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean(), default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)
    # TOTP fields
    totp_secret: Mapped[str | None] = mapped_column(Text(), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)
    totp_confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

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


class PasswordHistory(Base):
    """SQLAlchemy model for password history.

    Tracks previously used passwords to prevent reuse.
    """

    __tablename__ = "password_history"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    hashed_password: Mapped[str] = mapped_column(Text(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<PasswordHistory id={self.id} subject_id={self.subject_id}>"


class BackupCode(Base):
    """SQLAlchemy model for TOTP backup codes.

    One-time use codes for account recovery when TOTP device is unavailable.
    """

    __tablename__ = "backup_codes"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    code_hash: Mapped[str] = mapped_column(Text(), nullable=False)
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
        return f"<BackupCode id={self.id} subject_id={self.subject_id}>"


class SocialAccount(AuditColumns, Base):
    """SQLAlchemy model for OAuth social login accounts.

    Links a subject to an external OAuth provider account.
    """

    __tablename__ = "social_accounts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider_id: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # e.g., "google", "github"
    provider_user_id: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    access_token: Mapped[str | None] = mapped_column(Text(), nullable=True)
    refresh_token: Mapped[str | None] = mapped_column(Text(), nullable=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return (
            f"<SocialAccount provider={self.provider_id} subject_id={self.subject_id}>"
        )


class OAuthState(Base):
    """SQLAlchemy model for OAuth authorization state.

    Stores temporary state for OAuth flows with PKCE support.
    """

    __tablename__ = "oauth_states"

    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    code_verifier: Mapped[str] = mapped_column(String(128), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(Text(), nullable=False)
    provider_id: Mapped[str] = mapped_column(String(32), nullable=False)
    existing_subject_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    def __repr__(self) -> str:
        return f"<OAuthState state={self.state[:8]}... provider={self.provider_id}>"


class WebAuthnCredential(Base):
    """SQLAlchemy model for WebAuthn/Passkey credentials.

    Stores public keys for passwordless authentication.
    """

    __tablename__ = "webauthn_credentials"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    subject_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    credential_id: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    public_key: Mapped[str] = mapped_column(Text(), nullable=False)
    sign_count: Mapped[int] = mapped_column(nullable=False, default=0)
    transports: Mapped[str] = mapped_column(
        String(255), nullable=False, default=""
    )  # Comma-separated
    device_type: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    backed_up: Mapped[bool] = mapped_column(Boolean(), default=False, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<WebAuthnCredential id={self.id} subject_id={self.subject_id}>"


class WebAuthnChallenge(Base):
    """SQLAlchemy model for WebAuthn challenges.

    Temporary storage for registration/authentication challenges.
    """

    __tablename__ = "webauthn_challenges"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    challenge: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    subject_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    operation: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # "registration" or "authentication"
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    def __repr__(self) -> str:
        return f"<WebAuthnChallenge id={self.id} operation={self.operation}>"


class Group(AuditColumns, Base):
    """SQLAlchemy model for user groups.

    Groups allow organizing users and assigning roles collectively.
    Supports nested groups via parent_id.
    """

    __tablename__ = "groups"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text(), nullable=False, default="")
    parent_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("groups.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    organization_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean(), default=True, nullable=False)

    def __repr__(self) -> str:
        return f"<Group id={self.id} name={self.name}>"


class GroupMembership(Base):
    """SQLAlchemy model for group membership.

    Links subjects to groups with a membership role.
    """

    __tablename__ = "group_memberships"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    group_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    subject_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(
        String(32), nullable=False, default="member"
    )  # member, admin, owner
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    added_by: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="SET NULL"),
        nullable=True,
    )

    def __repr__(self) -> str:
        return f"<GroupMembership group={self.group_id} subject={self.subject_id}>"


class GroupRoleAssignment(Base):
    """SQLAlchemy model for assigning roles to groups.

    All members of the group inherit these roles.
    """

    __tablename__ = "group_role_assignments"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    group_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    granted_by: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("subjects.id", ondelete="SET NULL"),
        nullable=True,
    )

    def __repr__(self) -> str:
        return f"<GroupRoleAssignment group={self.group_id} role={self.role_id}>"


class Organization(AuditColumns, Base):
    """SQLAlchemy model for organizations (multi-tenancy).

    Organizations scope users, groups, and resources for multi-tenant deployments.
    """

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    slug: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    domain: Mapped[str | None] = mapped_column(
        String(255), unique=True, nullable=True, index=True
    )
    plan: Mapped[str] = mapped_column(
        String(32), nullable=False, default="free"
    )  # free, pro, enterprise
    is_active: Mapped[bool] = mapped_column(Boolean(), default=True, nullable=False)
    # Settings stored as JSON
    settings_json: Mapped[str] = mapped_column(Text(), nullable=False, default="{}")

    def __repr__(self) -> str:
        return f"<Organization id={self.id} name={self.name}>"


__all__ = [
    "BackupCode",
    "EmailVerificationToken",
    "Group",
    "GroupMembership",
    "GroupRoleAssignment",
    "OAuthState",
    "Organization",
    "PasswordHistory",
    "Role",
    "RoleAssignment",
    "Session",
    "SocialAccount",
    "Subject",
    "WebAuthnChallenge",
    "WebAuthnCredential",
]
