"""Authentication factors for NeoZen."""

from __future__ import annotations

from neozen.core.factors.email_otp import (
    EmailOTPCode,
    EmailOTPCodeRepository,
    EmailOTPConfig,
    EmailOTPFactor,
)
from neozen.core.factors.magic_link import (
    MagicLinkConfig,
    MagicLinkFactor,
    MagicLinkToken,
    MagicLinkTokenRepository,
    SubjectEmailLookup,
)
from neozen.core.factors.password import (
    InvalidCredentialsError,
    PasswordAuthenticateRequest,
    PasswordEnrollRequest,
    PasswordFactor,
    PasswordFactorError,
    PasswordHasherProtocol,
    PasswordSubjectModel,
    create_password_factor,
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
    # Email OTP factor
    "EmailOTPCode",
    "EmailOTPCodeRepository",
    "EmailOTPConfig",
    "EmailOTPFactor",
    # Magic link factor
    "MagicLinkConfig",
    "MagicLinkFactor",
    "MagicLinkToken",
    "MagicLinkTokenRepository",
    "SubjectEmailLookup",
    # Password factor
    "InvalidCredentialsError",
    "PasswordAuthenticateRequest",
    "PasswordEnrollRequest",
    "PasswordFactor",
    "PasswordFactorError",
    "PasswordHasherProtocol",
    "PasswordSubjectModel",
    "create_password_factor",
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
