"""Identifier providers for NeoZen."""

from __future__ import annotations

from neozen.core.identifiers.base import (
    IdentifierError,
    IdentifierProtocol,
    IdentifierProvider,
    IdentifierVerificationError,
    InvalidIdentifierFormat,
)
from neozen.core.identifiers.email import (
    EmailIdentifier,
    EmailIdentifierProvider,
    EmailSubjectModel,
)
from neozen.core.identifiers.phone import (
    PhoneIdentifier,
    PhoneIdentifierProvider,
    PhoneSubjectModel,
)
from neozen.core.identifiers.lookup import (
    IdentifierLookupService,
    IdentifierType,
)
from neozen.core.identifiers.username import (
    DEFAULT_RESERVED_USERNAMES,
    USERNAME_PATTERN,
    UsernameIdentifier,
    UsernameIdentifierProvider,
    UsernameSubjectModel,
)

__all__ = [
    "DEFAULT_RESERVED_USERNAMES",
    "EmailIdentifier",
    "EmailIdentifierProvider",
    "EmailSubjectModel",
    "IdentifierError",
    "IdentifierLookupService",
    "IdentifierProtocol",
    "IdentifierProvider",
    "IdentifierType",
    "IdentifierVerificationError",
    "InvalidIdentifierFormat",
    "PhoneIdentifier",
    "PhoneIdentifierProvider",
    "PhoneSubjectModel",
    "USERNAME_PATTERN",
    "UsernameIdentifier",
    "UsernameIdentifierProvider",
    "UsernameSubjectModel",
]
