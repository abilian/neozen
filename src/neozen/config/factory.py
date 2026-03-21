"""Service factory for NeoZen.

Creates NeoZen services from configuration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .types import NeoZenConfig

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

    from neozen.core.factors.password_policy import PasswordPolicy
    from neozen.core.factors.totp import TOTPConfig as CoreTOTPConfig
    from neozen.core.factors.webauthn import WebAuthnConfig as CoreWebAuthnConfig


class NeoZenFactory:
    """Factory for creating NeoZen services from configuration.

    This factory provides methods to create properly configured service
    instances from a NeoZenConfig object. It handles the translation
    between config file values and the internal service configuration types.

    Example:
        config = load_config()
        factory = NeoZenFactory(config)

        engine = factory.create_engine()
        totp_config = factory.create_totp_config()
        webauthn_config = factory.create_webauthn_config()

    """

    def __init__(self, config: NeoZenConfig) -> None:
        """Initialize the factory.

        Args:
            config: The NeoZen configuration.

        """
        self.config = config
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker | None = None

    def create_engine(self) -> AsyncEngine:
        """Create SQLAlchemy async engine.

        Returns:
            Configured AsyncEngine instance.

        """
        from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415

        if self._engine is None:
            self._engine = create_async_engine(
                self.config.database.url,
                pool_size=self.config.database.pool_size,
                pool_recycle=self.config.database.pool_recycle,
                echo=self.config.database.echo,
            )
        return self._engine

    def create_session_factory(self) -> async_sessionmaker:
        """Create SQLAlchemy session factory.

        Returns:
            Configured async_sessionmaker instance.

        """
        from sqlalchemy.ext.asyncio import async_sessionmaker  # noqa: PLC0415

        if self._session_factory is None:
            engine = self.create_engine()
            self._session_factory = async_sessionmaker(engine, expire_on_commit=False)
        return self._session_factory

    def create_password_policy(self) -> PasswordPolicy:
        """Create password policy from config.

        Returns:
            Configured PasswordPolicy instance.

        """
        from neozen.core.factors.password_policy import PasswordPolicy  # noqa: PLC0415

        cfg = self.config.password
        return PasswordPolicy(
            min_length=cfg.min_length,
            max_length=cfg.max_length,
            require_uppercase=cfg.require_uppercase,
            require_lowercase=cfg.require_lowercase,
            require_digit=cfg.require_digit,
            require_special=cfg.require_special,
            special_characters=cfg.special_characters,
            check_hibp=cfg.check_hibp,
            password_history_count=cfg.history_count,
        )

    def create_totp_config(self) -> CoreTOTPConfig:
        """Create TOTP config from config.

        Returns:
            Configured TOTPConfig instance for the TOTP factor.

        """
        from neozen.core.factors.totp import TOTPConfig  # noqa: PLC0415

        cfg = self.config.totp
        return TOTPConfig(
            issuer=cfg.issuer,
            digits=cfg.digits,
            interval=cfg.interval,
            algorithm=cfg.algorithm,
            backup_code_count=cfg.backup_code_count,
            backup_code_length=cfg.backup_code_length,
        )

    def create_webauthn_config(self) -> CoreWebAuthnConfig:
        """Create WebAuthn config from config.

        Returns:
            Configured WebAuthnConfig instance for the WebAuthn factor.

        """
        from neozen.core.factors.webauthn import WebAuthnConfig  # noqa: PLC0415

        cfg = self.config.webauthn
        return WebAuthnConfig(
            rp_id=cfg.rp_id,
            rp_name=cfg.rp_name,
            origin=cfg.origin,
            challenge_timeout_seconds=int(cfg.challenge_timeout.total_seconds()),
            user_verification=cfg.user_verification,
        )

    def get_session_lifetime_seconds(self) -> int:
        """Get session lifetime in seconds.

        Returns:
            Session lifetime as integer seconds.

        """
        return int(self.config.session.lifetime.total_seconds())

    def get_sliding_window_seconds(self) -> int | None:
        """Get sliding window in seconds.

        Returns:
            Sliding window as integer seconds, or None if disabled.

        """
        if self.config.session.sliding_window is None:
            return None
        return int(self.config.session.sliding_window.total_seconds())

    def get_enabled_oauth_providers(self) -> list[str]:
        """Get list of enabled OAuth providers.

        Returns:
            List of provider names that are enabled.

        """
        return [
            name
            for name, provider in self.config.oauth.providers.items()
            if provider.enabled
        ]

    def get_oauth_provider_config(self, provider_name: str) -> dict[str, str]:
        """Get OAuth provider configuration.

        Args:
            provider_name: Name of the provider (e.g., "google", "github").

        Returns:
            Dictionary with client_id, client_secret, and scopes.

        Raises:
            KeyError: If provider is not configured.

        """
        provider = self.config.oauth.providers[provider_name]
        return {
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
            "scopes": ",".join(provider.scopes),
            **provider.extra,
        }


__all__ = ["NeoZenFactory"]
