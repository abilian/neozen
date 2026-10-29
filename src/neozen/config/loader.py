"""Configuration loader for NeoZen.

Handles TOML loading, environment variable expansion, and duration parsing.
"""

from __future__ import annotations

import dataclasses
import os
import re
import tomllib
import typing
from datetime import timedelta
from pathlib import Path
from typing import Any

if typing.TYPE_CHECKING:
    from neozen.core.utils import DataclassInstance

from .exceptions import ConfigError
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

# Duration parsing regex: "30s", "5m", "1h", "7d", "2w"
DURATION_PATTERN = re.compile(r"^(\d+)(s|m|h|d|w)$", re.IGNORECASE)

# Environment variable pattern: ${VAR}, ${VAR:default}, ${VAR_FILE:file}
ENV_VAR_PATTERN = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::([^}]*))?\}")


def parse_duration(value: str | int | None) -> timedelta | None:
    """Parse a duration string into a timedelta.

    Formats:
        - "30s" -> 30 seconds
        - "5m" -> 5 minutes
        - "1h" -> 1 hour
        - "7d" -> 7 days
        - "2w" -> 2 weeks
        - 3600 -> 3600 seconds (int)
        - None -> None

    Args:
        value: Duration string, integer seconds, or None.

    Returns:
        timedelta or None.

    Raises:
        ConfigError: If the format is invalid.

    """
    if value is None:
        return None

    if isinstance(value, int):
        return timedelta(seconds=value)

    match = DURATION_PATTERN.match(value.lower())
    if not match:
        msg = f"Invalid duration format: {value}"
        raise ConfigError(msg)

    amount = int(match.group(1))
    unit = match.group(2)

    units = {
        "s": timedelta(seconds=amount),
        "m": timedelta(minutes=amount),
        "h": timedelta(hours=amount),
        "d": timedelta(days=amount),
        "w": timedelta(weeks=amount),
    }

    return units[unit]


def expand_env_vars(value: str) -> str:
    """Expand environment variables in a string.

    Syntax:
        ${VAR} - required, error if not set
        ${VAR:default} - optional with default
        ${VAR:null} - optional, returns empty string if not set
        ${VAR_FILE:file} - read content from file path in VAR_FILE

    Args:
        value: String potentially containing env var references.

    Returns:
        String with env vars expanded.

    Raises:
        ConfigError: If a required env var is not set or file cannot be read.

    """

    def replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        default = match.group(2)

        # File-based secret
        if default == "file":
            file_path = os.environ.get(var_name)
            if file_path:
                try:
                    return Path(file_path).read_text(encoding="utf-8").strip()
                except OSError as e:
                    msg = f"Cannot read secret file {file_path}: {e}"
                    raise ConfigError(msg) from e
            msg = f"Environment variable {var_name} not set (file reference)"
            raise ConfigError(msg)

        # Regular env var
        env_value = os.environ.get(var_name)

        if env_value is not None:
            return env_value

        if default is not None:
            if default == "null":
                return ""
            return default

        msg = f"Required environment variable {var_name} not set"
        raise ConfigError(msg)

    return ENV_VAR_PATTERN.sub(replace, value)


def expand_env_vars_recursive(data: Any) -> Any:
    """Recursively expand environment variables in a data structure.

    Args:
        data: Any data structure (dict, list, str, etc.).

    Returns:
        Data structure with all string values expanded.

    """
    if isinstance(data, str):
        return expand_env_vars(data)
    if isinstance(data, dict):
        return {k: expand_env_vars_recursive(v) for k, v in data.items()}
    if isinstance(data, list):
        return [expand_env_vars_recursive(item) for item in data]
    return data


def find_config_file() -> Path | None:
    """Find the configuration file using priority order.

    Priority:
        1. Environment variable: NEOZEN_CONFIG
        2. Current directory: ./neozen.toml
        3. Project root (pyproject.toml location): {project}/neozen.toml
        4. User config: ~/.config/neozen/config.toml

    Returns:
        Path to config file, or None if not found.

    Raises:
        ConfigError: If NEOZEN_CONFIG is set but file doesn't exist.

    """
    # 1. Environment variable
    env_path = os.environ.get("NEOZEN_CONFIG")
    if env_path:
        path = Path(env_path)
        if path.exists():
            return path
        msg = f"Config file not found: {env_path}"
        raise ConfigError(msg)

    # 2. Current directory
    cwd_config = Path.cwd() / "neozen.toml"
    if cwd_config.exists():
        return cwd_config

    # 3. Look for pyproject.toml and check sibling
    current = Path.cwd()
    while current != current.parent:
        pyproject = current / "pyproject.toml"
        if pyproject.exists():
            config = current / "neozen.toml"
            if config.exists():
                return config
            break
        current = current.parent

    # 4. User config directory
    user_config = Path.home() / ".config" / "neozen" / "config.toml"
    if user_config.exists():
        return user_config

    return None


def load_config(path: Path | str | None = None) -> NeoZenConfig:
    """Load configuration from a TOML file.

    Args:
        path: Explicit path to config file. If None, uses find_config_file().

    Returns:
        Validated NeoZenConfig instance.

    Raises:
        ConfigError: If config file not found or invalid.

    """
    if path is None:
        config_path = find_config_file()
        if config_path is None:
            # Return defaults if no config file
            return NeoZenConfig()
    else:
        config_path = Path(path)
        if not config_path.exists():
            msg = f"Config file not found: {config_path}"
            raise ConfigError(msg)

    # Load TOML
    try:
        with config_path.open("rb") as f:
            raw_config = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        msg = f"Invalid TOML in {config_path}: {e}"
        raise ConfigError(msg) from e

    # Expand environment variables
    config_data = expand_env_vars_recursive(raw_config)

    # Build config objects
    return _build_config(config_data)


def _section[C: DataclassInstance](
    cls: type[C], table: dict[str, Any], **values: Any
) -> C:
    """Build a config dataclass from its TOML table.

    Each field the table sets replaces the default: durations are parsed,
    lists become tuples. ``values`` are fields built by the caller (nested
    tables).
    """
    hints = typing.get_type_hints(cls)
    for f in dataclasses.fields(cls):
        if f.name in values or f.name not in table:
            continue
        value = table[f.name]
        hint = hints[f.name]
        if hint is timedelta or timedelta in typing.get_args(hint):
            value = parse_duration(value)
        elif isinstance(value, list):
            value = tuple(value)
        values[f.name] = value
    return cls(**values)


def _oauth_provider(table: dict[str, Any]) -> OAuthProviderConfig:
    """A provider: its known keys, everything else in `extra`."""
    known = {f.name for f in dataclasses.fields(OAuthProviderConfig)} - {"extra"}
    return _section(
        OAuthProviderConfig,
        table,
        extra={k: v for k, v in table.items() if k not in known},
    )


def _build_config(data: dict[str, Any]) -> NeoZenConfig:
    """Build NeoZenConfig from raw dictionary.

    Args:
        data: Dictionary from TOML parsing with env vars expanded.

    Returns:
        NeoZenConfig instance.

    """
    simple = {
        "database": DatabaseConfig,
        "session": SessionConfig,
        "password": PasswordConfig,
        "totp": TOTPConfig,
        "webauthn": WebAuthnConfig,
        "oauth_server": OAuthServerConfig,
        "authorization": AuthorizationConfig,
        "admin": AdminConfig,
        "logging": LoggingConfig,
    }
    parts: dict[str, Any] = {
        name: _section(cls, data[name]) for name, cls in simple.items() if name in data
    }

    if "oauth" in data:
        oauth = data["oauth"]
        parts["oauth"] = _section(
            OAuthConfig,
            oauth,
            providers={
                name: _oauth_provider(table)
                for name, table in oauth.get("providers", {}).items()
            },
        )

    if "security" in data:
        sec = data["security"]
        parts["security"] = _section(
            SecurityConfig,
            sec,
            rate_limit=_section(RateLimitConfig, sec.get("rate_limit", {})),
            lockout=_section(LockoutConfig, sec.get("lockout", {})),
        )

    if "email" in data:
        email = data["email"]
        parts["email"] = _section(
            EmailConfig,
            email,
            smtp=_section(EmailSMTPConfig, email.get("smtp", {})),
            sendgrid_api_key=email.get("sendgrid", {}).get("api_key", ""),
            postmark_api_key=email.get("postmark", {}).get("api_key", ""),
        )

    return NeoZenConfig(**parts)


__all__ = [
    "expand_env_vars",
    "expand_env_vars_recursive",
    "find_config_file",
    "load_config",
    "parse_duration",
]
