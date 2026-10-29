"""Configuration validation for NeoZen.

Validates configuration values and provides clear error messages, each
naming the setting and the value it got.
"""

from __future__ import annotations

import dataclasses
import typing

from .exceptions import ConfigValidationError
from .types import NeoZenConfig

# Below these, a setting is a mistake rather than a choice.
MIN_SECRET_KEY_LENGTH = 32
MIN_TOTP_INTERVAL_SECONDS = 10
MIN_BACKUP_CODE_LENGTH = 4
MIN_SESSION_LIFETIME_SECONDS = 60
TOTP_DIGITS = (6, 8)


def validate_config(config: NeoZenConfig, *, require_secret_key: bool = True) -> None:
    """Validate configuration values.

    Args:
        config: The configuration to validate.
        require_secret_key: Whether to require a secret key. Set to False for
            development or testing.

    Raises:
        ConfigValidationError: If any values are invalid.

    """
    errors = [
        *_choice_errors(config),
        *_minimum_errors(config),
        *_secret_key_errors(config, required=require_secret_key),
        *_other_errors(config),
    ]
    if errors:
        raise ConfigValidationError(errors)


def _choice_errors(config: NeoZenConfig) -> list[str]:
    """Every ``Literal``-typed setting must hold one of its values."""
    errors = []
    for section in dataclasses.fields(config):
        value = getattr(config, section.name)
        hints = typing.get_type_hints(type(value))
        for f in dataclasses.fields(value):
            allowed = _literal_values(hints[f.name])
            setting = getattr(value, f.name)
            if allowed and setting not in allowed:
                choices = ", ".join(repr(a) for a in allowed if a is not None)
                errors.append(
                    f"{section.name}.{f.name} must be one of {choices}, got {setting!r}"
                )
    return errors


def _literal_values(hint: object) -> tuple[object, ...]:
    """The values of a ``Literal`` (optional or not), or () for other types."""
    if typing.get_origin(hint) is typing.Literal:
        return typing.get_args(hint)
    literals = [
        a for a in typing.get_args(hint) if typing.get_origin(a) is typing.Literal
    ]
    if not literals:
        return ()
    allowed = tuple(v for lit in literals for v in typing.get_args(lit))
    return (*allowed, None) if type(None) in typing.get_args(hint) else allowed


def _minimum_errors(config: NeoZenConfig) -> list[str]:
    rate_limit = config.security.rate_limit
    minimums: list[tuple[str, float, float, bool]] = [
        # (setting, value, minimum, checked)
        ("password.min_length", config.password.min_length, 1, True),
        ("password.hibp_threshold", config.password.hibp_threshold, 1, True),
        ("password.history_count", config.password.history_count, 0, True),
        ("totp.interval", config.totp.interval, MIN_TOTP_INTERVAL_SECONDS, True),
        ("totp.backup_code_count", config.totp.backup_code_count, 0, True),
        (
            "totp.backup_code_length",
            config.totp.backup_code_length,
            MIN_BACKUP_CODE_LENGTH,
            True,
        ),
        (
            "session.lifetime (seconds)",
            config.session.lifetime.total_seconds(),
            MIN_SESSION_LIFETIME_SECONDS,
            True,
        ),
        (
            "security.rate_limit.login_attempts",
            rate_limit.login_attempts,
            1,
            rate_limit.enabled,
        ),
        (
            "security.rate_limit.registration_attempts",
            rate_limit.registration_attempts,
            1,
            rate_limit.enabled,
        ),
        (
            "security.lockout.threshold",
            config.security.lockout.threshold,
            1,
            config.security.lockout.enabled,
        ),
    ]
    return [
        f"{name} must be at least {minimum}, got {value}"
        for name, value, minimum, checked in minimums
        if checked and value < minimum
    ]


def _secret_key_errors(config: NeoZenConfig, *, required: bool) -> list[str]:
    key = config.security.secret_key
    if not required:
        return []
    if not key:
        return ["security.secret_key is required"]
    if len(key) < MIN_SECRET_KEY_LENGTH:
        message = (
            f"security.secret_key must be at least {MIN_SECRET_KEY_LENGTH} "
            f"characters, got {len(key)}"
        )
        return [message]
    return []


def _other_errors(config: NeoZenConfig) -> list[str]:
    errors = []
    password, totp, webauthn = config.password, config.totp, config.webauthn
    if password.max_length < password.min_length:
        errors.append(
            f"password.max_length must be >= min_length ({password.min_length}), "
            f"got {password.max_length}"
        )
    if totp.digits not in TOTP_DIGITS:
        errors.append(f"totp.digits must be 6 or 8, got {totp.digits}")
    if config.admin.enabled and not config.admin.path_prefix.startswith("/"):
        errors.append(
            f"admin.path_prefix must start with /, got {config.admin.path_prefix!r}"
        )
    if not webauthn.rp_id:
        errors.append("webauthn.rp_id is required")
    if not webauthn.origin.startswith(("http://", "https://")):
        errors.append(
            f"webauthn.origin must start with http:// or https://, "
            f"got {webauthn.origin!r}"
        )
    return [*errors, *_oauth_errors(config)]


def _oauth_errors(config: NeoZenConfig) -> list[str]:
    errors = []
    for name, provider in config.oauth.providers.items():
        if provider.enabled and not provider.client_id:
            errors.append(f"oauth.providers.{name}.client_id is required when enabled")
        if provider.enabled and not provider.client_secret:
            errors.append(
                f"oauth.providers.{name}.client_secret is required when enabled"
            )
    oauth_server = config.oauth_server
    if oauth_server.enabled and oauth_server.jwt_access_tokens:
        if not oauth_server.issuer:
            errors.append("oauth_server.issuer is required for JWT access tokens")
        if not oauth_server.jwt_audience:
            errors.append("oauth_server.jwt_audience is required for JWT access tokens")
    return errors


__all__ = ["validate_config"]
