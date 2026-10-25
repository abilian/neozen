"""Configuration validation for NeoZen.

Validates configuration values and provides clear error messages.
"""

from __future__ import annotations

from .exceptions import ConfigValidationError
from .types import NeoZenConfig


def validate_config(config: NeoZenConfig, *, require_secret_key: bool = True) -> None:  # noqa: C901
    """Validate configuration values.

    Args:
        config: The configuration to validate.
        require_secret_key: Whether to require a secret key. Set to False for
            development or testing.

    Raises:
        ConfigValidationError: If any values are invalid.

    """
    errors: list[str] = []

    # Security: secret_key is required for production
    if require_secret_key:
        if not config.security.secret_key:
            errors.append("security.secret_key is required")
        elif len(config.security.secret_key) < 32:
            errors.append("security.secret_key must be at least 32 characters")

    # Password policy
    if config.password.min_length < 1:
        errors.append("password.min_length must be at least 1")
    if config.password.max_length < config.password.min_length:
        errors.append("password.max_length must be >= min_length")
    if config.password.hibp_threshold < 1:
        errors.append("password.hibp_threshold must be at least 1")
    if config.password.history_count < 0:
        errors.append("password.history_count must be non-negative")

    # TOTP
    if config.totp.digits not in (6, 8):
        errors.append("totp.digits must be 6 or 8")
    if config.totp.interval < 10:
        errors.append("totp.interval must be at least 10 seconds")
    if config.totp.algorithm not in ("SHA1", "SHA256", "SHA512"):
        errors.append("totp.algorithm must be SHA1, SHA256, or SHA512")
    if config.totp.backup_code_count < 0:
        errors.append("totp.backup_code_count must be non-negative")
    if config.totp.backup_code_length < 4:
        errors.append("totp.backup_code_length must be at least 4")

    # WebAuthn
    if not config.webauthn.rp_id:
        errors.append("webauthn.rp_id is required")
    if not config.webauthn.origin:
        errors.append("webauthn.origin is required")
    if not config.webauthn.origin.startswith(("http://", "https://")):
        errors.append("webauthn.origin must start with http:// or https://")
    if config.webauthn.user_verification not in (
        "required",
        "preferred",
        "discouraged",
    ):
        errors.append(
            "webauthn.user_verification must be required, preferred, or discouraged"
        )
    if config.webauthn.resident_key not in ("required", "preferred", "discouraged"):
        errors.append(
            "webauthn.resident_key must be required, preferred, or discouraged"
        )

    # OAuth providers
    for name, provider in config.oauth.providers.items():
        if provider.enabled:
            if not provider.client_id:
                errors.append(
                    f"oauth.providers.{name}.client_id is required when enabled"
                )
            if not provider.client_secret:
                errors.append(
                    f"oauth.providers.{name}.client_secret is required when enabled"
                )

    # OAuth Server
    oauth_server = config.oauth_server
    # Tokens are verified with the public JWKS, so no shared-secret HS256.
    if oauth_server.enabled and oauth_server.jwt_algorithm not in ("RS256", "ES256"):
        errors.append("oauth_server.jwt_algorithm must be RS256 or ES256")
    if (
        oauth_server.enabled
        and oauth_server.jwt_issuer
        and not oauth_server.jwt_audience
    ):
        errors.append("oauth_server.jwt_audience is required when jwt_issuer is set")

    # Session
    if config.session.lifetime.total_seconds() < 60:
        errors.append("session.lifetime must be at least 60 seconds")
    if config.session.cookie_samesite not in ("strict", "lax", "none"):
        errors.append("session.cookie_samesite must be strict, lax, or none")

    # Rate limiting
    if config.security.rate_limit.enabled:
        if config.security.rate_limit.login_attempts < 1:
            errors.append("security.rate_limit.login_attempts must be at least 1")
        if config.security.rate_limit.registration_attempts < 1:
            errors.append(
                "security.rate_limit.registration_attempts must be at least 1"
            )

    # Lockout
    if config.security.lockout.enabled and config.security.lockout.threshold < 1:
        errors.append("security.lockout.threshold must be at least 1")

    # Logging
    if config.logging.level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
        errors.append("logging.level must be DEBUG, INFO, WARNING, or ERROR")

    # Admin
    if config.admin.enabled and not config.admin.path_prefix.startswith("/"):
        errors.append("admin.path_prefix must start with /")

    if errors:
        raise ConfigValidationError(errors)


__all__ = ["validate_config"]
