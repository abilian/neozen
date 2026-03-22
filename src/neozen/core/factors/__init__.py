"""Authentication factors for NeoZen."""

from __future__ import annotations

from neozen.core.factors.password import (
    InvalidCredentialsError,
    PasswordAuthenticateRequest,
    PasswordEnrollRequest,
    PasswordFactor,
    PasswordFactorError,
    PasswordHasherProtocol,
    PasswordSubjectModel,
)
from neozen.core.factors.protocol import (
    AuthenticatingFactorProtocol,
    ChallengingFactorProtocol,
    EnrollableFactorProtocol,
    FactorProtocol,
)
from neozen.core.factors.registry import (
    FactorAlreadyRegisteredError,
    FactorNotFoundError,
    FactorRegistry,
)

__all__ = [
    # Password factor
    "InvalidCredentialsError",
    "PasswordAuthenticateRequest",
    "PasswordEnrollRequest",
    "PasswordFactor",
    "PasswordFactorError",
    "PasswordHasherProtocol",
    "PasswordSubjectModel",
    # Protocols
    "AuthenticatingFactorProtocol",
    "ChallengingFactorProtocol",
    "EnrollableFactorProtocol",
    "FactorProtocol",
    # Registry
    "FactorAlreadyRegisteredError",
    "FactorNotFoundError",
    "FactorRegistry",
]
