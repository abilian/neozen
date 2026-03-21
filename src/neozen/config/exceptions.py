"""Configuration exceptions for NeoZen."""

from __future__ import annotations

from neozen.core.exceptions import NeoZenException


class ConfigError(NeoZenException):
    """Configuration loading or parsing error."""


class ConfigValidationError(ConfigError):
    """Configuration value validation error."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        message = "Configuration validation failed:\n" + "\n".join(
            f"  - {e}" for e in errors
        )
        super().__init__(message)


__all__ = ["ConfigError", "ConfigValidationError"]
