"""Configuration types for NeoZen.

All configuration is represented as frozen dataclasses with sensible defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal


@dataclass(frozen=True)
class DatabaseConfig:
    """Database connection configuration."""

    url: str = "sqlite+aiosqlite:///data/neozen.db"
    pool_size: int = 5
    pool_recycle: int = 3600
    echo: bool = False


@dataclass(frozen=True)
class SessionConfig:
    """Session management configuration."""

    lifetime: timedelta = field(default_factory=lambda: timedelta(days=7))
    sliding_window: timedelta | None = field(default_factory=lambda: timedelta(hours=1))
    cookie_name: str = "neozen_session"
    cookie_secure: bool = True
    cookie_httponly: bool = True
    cookie_samesite: Literal["strict", "lax", "none"] = "lax"
    cookie_domain: str | None = None
    cookie_path: str = "/"


@dataclass(frozen=True)
class PasswordConfig:
    """Password policy configuration."""

    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = False
    special_characters: str = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
    check_hibp: bool = False
    hibp_threshold: int = 1
    history_count: int = 0


@dataclass(frozen=True)
class TOTPConfig:
    """TOTP two-factor authentication configuration."""

    issuer: str = "NeoZen"
    digits: int = 6
    interval: int = 30
    algorithm: Literal["SHA1", "SHA256", "SHA512"] = "SHA1"
    backup_code_count: int = 10
    backup_code_length: int = 8


@dataclass(frozen=True)
class WebAuthnConfig:
    """WebAuthn/Passkey configuration."""

    rp_id: str = "localhost"
    rp_name: str = "NeoZen"
    origin: str = "http://localhost:8000"
    challenge_timeout: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    user_verification: Literal["required", "preferred", "discouraged"] = "preferred"
    authenticator_attachment: Literal["platform", "cross-platform"] | None = None
    resident_key: Literal["required", "preferred", "discouraged"] = "preferred"


@dataclass(frozen=True)
class OAuthProviderConfig:
    """OAuth provider configuration."""

    enabled: bool = False
    client_id: str = ""
    client_secret: str = ""
    scopes: tuple[str, ...] = ()
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class OAuthConfig:
    """OAuth client configuration."""

    state_lifetime: timedelta = field(default_factory=lambda: timedelta(minutes=10))
    default_scopes: tuple[str, ...] = ("openid", "email", "profile")
    providers: dict[str, OAuthProviderConfig] = field(default_factory=dict)


@dataclass(frozen=True)
class OAuthServerConfig:
    """OAuth authorization server configuration."""

    enabled: bool = False
    access_token_lifetime: timedelta = field(default_factory=lambda: timedelta(hours=1))
    refresh_token_lifetime: timedelta = field(
        default_factory=lambda: timedelta(days=30)
    )
    authorization_code_lifetime: timedelta = field(
        default_factory=lambda: timedelta(minutes=10)
    )
    require_pkce: bool = True
    allow_refresh_token_rotation: bool = True
    jwt_algorithm: Literal["RS256", "ES256", "HS256"] = "RS256"
    jwt_issuer: str | None = None
    jwt_audience: str | None = None


@dataclass(frozen=True)
class RateLimitConfig:
    """Rate limiting configuration."""

    enabled: bool = False
    login_attempts: int = 5
    login_window: timedelta = field(default_factory=lambda: timedelta(minutes=15))
    registration_attempts: int = 3
    registration_window: timedelta = field(default_factory=lambda: timedelta(hours=1))


@dataclass(frozen=True)
class LockoutConfig:
    """Account lockout configuration."""

    enabled: bool = False
    threshold: int = 5
    duration: timedelta = field(default_factory=lambda: timedelta(minutes=30))
    reset_on_success: bool = True


@dataclass(frozen=True)
class SecurityConfig:
    """Security configuration."""

    secret_key: str = ""
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    lockout: LockoutConfig = field(default_factory=LockoutConfig)


@dataclass(frozen=True)
class EmailSMTPConfig:
    """SMTP email configuration."""

    host: str = "localhost"
    port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True


@dataclass(frozen=True)
class EmailConfig:
    """Email configuration."""

    provider: Literal["smtp", "sendgrid", "postmark", "console"] = "console"
    from_address: str = "noreply@example.com"
    from_name: str = "NeoZen"
    smtp: EmailSMTPConfig = field(default_factory=EmailSMTPConfig)
    sendgrid_api_key: str = ""
    postmark_api_key: str = ""


@dataclass(frozen=True)
class AuthorizationConfig:
    """Authorization configuration."""

    builtin_roles: tuple[str, ...] = ("admin", "user")
    first_user_roles: tuple[str, ...] = ("admin", "user")
    superuser_permission: str = "*:*"


@dataclass(frozen=True)
class AdminConfig:
    """Admin UI configuration."""

    enabled: bool = True
    path_prefix: str = "/admin"
    require_role: str = "admin"


@dataclass(frozen=True)
class LoggingConfig:
    """Logging configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    audit_enabled: bool = False
    audit_events: tuple[str, ...] = ()


@dataclass(frozen=True)
class NeoZenConfig:
    """Root configuration for NeoZen."""

    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    session: SessionConfig = field(default_factory=SessionConfig)
    password: PasswordConfig = field(default_factory=PasswordConfig)
    totp: TOTPConfig = field(default_factory=TOTPConfig)
    webauthn: WebAuthnConfig = field(default_factory=WebAuthnConfig)
    oauth: OAuthConfig = field(default_factory=OAuthConfig)
    oauth_server: OAuthServerConfig = field(default_factory=OAuthServerConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    email: EmailConfig = field(default_factory=EmailConfig)
    authorization: AuthorizationConfig = field(default_factory=AuthorizationConfig)
    admin: AdminConfig = field(default_factory=AdminConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


__all__ = [
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
]
