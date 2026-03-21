"""NeoZen Configuration System.

This module provides TOML-based configuration loading for NeoZen applications.

Example:
    from neozen.config import load_config, NeoZenFactory

    # Load configuration (auto-discovers neozen.toml)
    config = load_config()

    # Create factory for service instances
    factory = NeoZenFactory(config)

    # Use config values
    engine = factory.create_engine()
    totp_config = factory.create_totp_config()
    secret_key = config.security.secret_key

"""

from __future__ import annotations

from .exceptions import ConfigError, ConfigValidationError
from .factory import NeoZenFactory
from .loader import (
    expand_env_vars,
    find_config_file,
    load_config,
    parse_duration,
)
from .types import (
    AdminConfig,
    AuthorizationConfig,
    DatabaseConfig,
    EmailConfig,
    EmailSMTPConfig,
    LockoutConfig,
    LoggingConfig,
    NeoZenConfig,
    OAuthConfig,
    OAuthProviderConfig,
    OAuthServerConfig,
    PasswordConfig,
    RateLimitConfig,
    SecurityConfig,
    SessionConfig,
    TOTPConfig,
    WebAuthnConfig,
)
from .validation import validate_config

__all__ = [
    # Main entry points
    "load_config",
    "find_config_file",
    "validate_config",
    "NeoZenFactory",
    # Config types
    "AdminConfig",
    "AuthorizationConfig",
    "DatabaseConfig",
    "EmailConfig",
    "EmailSMTPConfig",
    "LockoutConfig",
    "LoggingConfig",
    "NeoZenConfig",
    "OAuthConfig",
    "OAuthProviderConfig",
    "OAuthServerConfig",
    "PasswordConfig",
    "RateLimitConfig",
    "SecurityConfig",
    "SessionConfig",
    "TOTPConfig",
    "WebAuthnConfig",
    # Exceptions
    "ConfigError",
    "ConfigValidationError",
    # Utilities
    "expand_env_vars",
    "parse_duration",
]
