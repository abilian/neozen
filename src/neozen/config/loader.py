"""Configuration loader for NeoZen.

Handles TOML loading, environment variable expansion, and duration parsing.
"""

from __future__ import annotations

import os
import re
import tomllib
from datetime import timedelta
from pathlib import Path
from typing import Any

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


def _build_config(data: dict[str, Any]) -> NeoZenConfig:  # noqa: C901
    """Build NeoZenConfig from raw dictionary.

    Args:
        data: Dictionary from TOML parsing with env vars expanded.

    Returns:
        NeoZenConfig instance.

    """
    config_parts: dict[str, Any] = {}

    # Database
    if "database" in data:
        db = data["database"]
        config_parts["database"] = DatabaseConfig(
            url=db.get("url", DatabaseConfig.url),
            pool_size=db.get("pool_size", DatabaseConfig.pool_size),
            pool_recycle=db.get("pool_recycle", DatabaseConfig.pool_recycle),
            echo=db.get("echo", DatabaseConfig.echo),
        )

    # Session
    if "session" in data:
        sess = data["session"]
        default_session = SessionConfig()
        config_parts["session"] = SessionConfig(
            lifetime=parse_duration(sess.get("lifetime")) or default_session.lifetime,
            sliding_window=parse_duration(sess.get("sliding_window")),
            cookie_name=sess.get("cookie_name", default_session.cookie_name),
            cookie_secure=sess.get("cookie_secure", default_session.cookie_secure),
            cookie_httponly=sess.get(
                "cookie_httponly", default_session.cookie_httponly
            ),
            cookie_samesite=sess.get(
                "cookie_samesite", default_session.cookie_samesite
            ),
            cookie_domain=sess.get("cookie_domain"),
            cookie_path=sess.get("cookie_path", default_session.cookie_path),
        )

    # Password
    if "password" in data:
        pwd = data["password"]
        default_pwd = PasswordConfig()
        config_parts["password"] = PasswordConfig(
            min_length=pwd.get("min_length", default_pwd.min_length),
            max_length=pwd.get("max_length", default_pwd.max_length),
            require_uppercase=pwd.get(
                "require_uppercase", default_pwd.require_uppercase
            ),
            require_lowercase=pwd.get(
                "require_lowercase", default_pwd.require_lowercase
            ),
            require_digit=pwd.get("require_digit", default_pwd.require_digit),
            require_special=pwd.get("require_special", default_pwd.require_special),
            special_characters=pwd.get(
                "special_characters", default_pwd.special_characters
            ),
            check_hibp=pwd.get("check_hibp", default_pwd.check_hibp),
            hibp_threshold=pwd.get("hibp_threshold", default_pwd.hibp_threshold),
            history_count=pwd.get("history_count", default_pwd.history_count),
        )

    # TOTP
    if "totp" in data:
        totp = data["totp"]
        default_totp = TOTPConfig()
        config_parts["totp"] = TOTPConfig(
            issuer=totp.get("issuer", default_totp.issuer),
            digits=totp.get("digits", default_totp.digits),
            interval=totp.get("interval", default_totp.interval),
            algorithm=totp.get("algorithm", default_totp.algorithm),
            backup_code_count=totp.get(
                "backup_code_count", default_totp.backup_code_count
            ),
            backup_code_length=totp.get(
                "backup_code_length", default_totp.backup_code_length
            ),
        )

    # WebAuthn
    if "webauthn" in data:
        wa = data["webauthn"]
        default_wa = WebAuthnConfig()
        config_parts["webauthn"] = WebAuthnConfig(
            rp_id=wa.get("rp_id", default_wa.rp_id),
            rp_name=wa.get("rp_name", default_wa.rp_name),
            origin=wa.get("origin", default_wa.origin),
            challenge_timeout=parse_duration(wa.get("challenge_timeout"))
            or default_wa.challenge_timeout,
            user_verification=wa.get("user_verification", default_wa.user_verification),
            authenticator_attachment=wa.get("authenticator_attachment"),
            resident_key=wa.get("resident_key", default_wa.resident_key),
        )

    # OAuth (client)
    if "oauth" in data:
        oauth_data = data["oauth"]
        providers: dict[str, OAuthProviderConfig] = {}
        for name, prov in oauth_data.get("providers", {}).items():
            scopes = prov.get("scopes", [])
            providers[name] = OAuthProviderConfig(
                enabled=prov.get("enabled", False),
                client_id=prov.get("client_id", ""),
                client_secret=prov.get("client_secret", ""),
                scopes=tuple(scopes) if isinstance(scopes, list) else scopes,
                extra={
                    k: v
                    for k, v in prov.items()
                    if k not in ("enabled", "client_id", "client_secret", "scopes")
                },
            )
        default_oauth = OAuthConfig()
        default_scopes = oauth_data.get(
            "default_scopes", list(default_oauth.default_scopes)
        )
        config_parts["oauth"] = OAuthConfig(
            state_lifetime=parse_duration(oauth_data.get("state_lifetime"))
            or default_oauth.state_lifetime,
            default_scopes=tuple(default_scopes)
            if isinstance(default_scopes, list)
            else default_scopes,
            providers=providers,
        )

    # OAuth Server
    if "oauth_server" in data:
        os_data = data["oauth_server"]
        default_os = OAuthServerConfig()
        config_parts["oauth_server"] = OAuthServerConfig(
            enabled=os_data.get("enabled", False),
            access_token_lifetime=parse_duration(os_data.get("access_token_lifetime"))
            or default_os.access_token_lifetime,
            refresh_token_lifetime=parse_duration(os_data.get("refresh_token_lifetime"))
            or default_os.refresh_token_lifetime,
            authorization_code_lifetime=parse_duration(
                os_data.get("authorization_code_lifetime")
            )
            or default_os.authorization_code_lifetime,
            require_pkce=os_data.get("require_pkce", default_os.require_pkce),
            allow_refresh_token_rotation=os_data.get(
                "allow_refresh_token_rotation", default_os.allow_refresh_token_rotation
            ),
            jwt_algorithm=os_data.get("jwt_algorithm", default_os.jwt_algorithm),
            jwt_issuer=os_data.get("jwt_issuer"),
            jwt_audience=os_data.get("jwt_audience"),
        )

    # Security
    if "security" in data:
        sec = data["security"]
        rate_limit = RateLimitConfig()
        lockout = LockoutConfig()

        if "rate_limit" in sec:
            rl = sec["rate_limit"]
            rate_limit = RateLimitConfig(
                enabled=rl.get("enabled", False),
                login_attempts=rl.get("login_attempts", rate_limit.login_attempts),
                login_window=parse_duration(rl.get("login_window"))
                or rate_limit.login_window,
                registration_attempts=rl.get(
                    "registration_attempts", rate_limit.registration_attempts
                ),
                registration_window=parse_duration(rl.get("registration_window"))
                or rate_limit.registration_window,
            )

        if "lockout" in sec:
            lo = sec["lockout"]
            lockout = LockoutConfig(
                enabled=lo.get("enabled", False),
                threshold=lo.get("threshold", lockout.threshold),
                duration=parse_duration(lo.get("duration")) or lockout.duration,
                reset_on_success=lo.get("reset_on_success", lockout.reset_on_success),
            )

        config_parts["security"] = SecurityConfig(
            secret_key=sec.get("secret_key", ""),
            rate_limit=rate_limit,
            lockout=lockout,
        )

    # Email
    if "email" in data:
        em = data["email"]
        smtp_config = EmailSMTPConfig()
        if "smtp" in em:
            smtp = em["smtp"]
            smtp_config = EmailSMTPConfig(
                host=smtp.get("host", smtp_config.host),
                port=smtp.get("port", smtp_config.port),
                username=smtp.get("username", smtp_config.username),
                password=smtp.get("password", smtp_config.password),
                use_tls=smtp.get("use_tls", smtp_config.use_tls),
            )
        default_email = EmailConfig()
        config_parts["email"] = EmailConfig(
            provider=em.get("provider", default_email.provider),
            from_address=em.get("from_address", default_email.from_address),
            from_name=em.get("from_name", default_email.from_name),
            smtp=smtp_config,
            sendgrid_api_key=em.get("sendgrid", {}).get("api_key", ""),
            postmark_api_key=em.get("postmark", {}).get("api_key", ""),
        )

    # Authorization
    if "authorization" in data:
        auth = data["authorization"]
        default_auth = AuthorizationConfig()
        builtin_roles = auth.get("builtin_roles", list(default_auth.builtin_roles))
        first_user_roles = auth.get(
            "first_user_roles", list(default_auth.first_user_roles)
        )
        config_parts["authorization"] = AuthorizationConfig(
            builtin_roles=tuple(builtin_roles)
            if isinstance(builtin_roles, list)
            else builtin_roles,
            first_user_roles=tuple(first_user_roles)
            if isinstance(first_user_roles, list)
            else first_user_roles,
            superuser_permission=auth.get(
                "superuser_permission", default_auth.superuser_permission
            ),
        )

    # Admin
    if "admin" in data:
        adm = data["admin"]
        default_admin = AdminConfig()
        config_parts["admin"] = AdminConfig(
            enabled=adm.get("enabled", default_admin.enabled),
            path_prefix=adm.get("path_prefix", default_admin.path_prefix),
            require_role=adm.get("require_role", default_admin.require_role),
        )

    # Logging
    if "logging" in data:
        log = data["logging"]
        default_log = LoggingConfig()
        audit_events = log.get("audit_events", list(default_log.audit_events))
        config_parts["logging"] = LoggingConfig(
            level=log.get("level", default_log.level),
            audit_enabled=log.get("audit_enabled", default_log.audit_enabled),
            audit_events=tuple(audit_events)
            if isinstance(audit_events, list)
            else audit_events,
        )

    return NeoZenConfig(**config_parts)


__all__ = [
    "expand_env_vars",
    "expand_env_vars_recursive",
    "find_config_file",
    "load_config",
    "parse_duration",
]
