"""SQLAlchemy storage backend for NeoZen.

This package provides SQLAlchemy 2.0 async storage implementation
using Advanced-Alchemy repositories.
"""

from __future__ import annotations

from neozen.storage.sqlalchemy.base import Base
from neozen.storage.sqlalchemy.factories import (
    RoleServiceFactory,
    SessionServiceFactory,
    create_subject_loader,
    get_subject_roles,
)
from neozen.storage.sqlalchemy.models import (
    EmailVerificationToken,
    Session,
    Subject,
)
from neozen.storage.sqlalchemy.repositories import (
    EmailVerificationTokenRepository,
    NeoZenRepository,
    SessionRepository,
    SubjectRepository,
    get_email_verification_token_repository,
    get_session_repository,
    get_subject_repository,
)

__all__ = [
    "Base",
    "EmailVerificationToken",
    "EmailVerificationTokenRepository",
    "NeoZenRepository",
    "RoleServiceFactory",
    "Session",
    "SessionRepository",
    "SessionServiceFactory",
    "Subject",
    "SubjectRepository",
    "create_subject_loader",
    "get_email_verification_token_repository",
    "get_session_repository",
    "get_subject_repository",
    "get_subject_roles",
]
