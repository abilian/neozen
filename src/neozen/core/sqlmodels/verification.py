"""SQLAlchemy EmailVerificationToken model for NeoZen."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from neozen.core.storage.sqlalchemy import Base


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
        return f"<EmailVerificationToken email={self.email} subject_id={self.subject_id}>"


__all__ = ["EmailVerificationToken"]
