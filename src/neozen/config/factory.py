"""Service factory for NeoZen.

Creates NeoZen services from configuration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .exceptions import ConfigError
from .types import NeoZenConfig, OAuthServerConfig

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

    from neozen.core.factors.password_policy import PasswordPolicy
    from neozen.core.factors.totp import TOTPConfig as CoreTOTPConfig
    from neozen.core.factors.webauthn import WebAuthnConfig as CoreWebAuthnConfig
    from neozen.core.oauth.client_service import OAuthClientService
    from neozen.core.oauth.models import (
        OAuthAccessTokenModel,
        OAuthAuthorizationCodeModel,
        OAuthClientModel,
        OAuthGrantModel,
        OAuthRefreshTokenModel,
    )
    from neozen.core.oauth.services import OAuthTokenService
    from neozen.core.oidc.discovery import OIDCProviderMetadata
    from neozen.core.oidc.id_token import IDTokenGenerator
    from neozen.core.oidc.keys import KeyManager
    from neozen.core.repository import RepositoryProtocol
    from neozen.web.oauth.authorization_endpoint import AuthorizationEndpoint


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

    def __init__(
        self, config: NeoZenConfig, *, key_manager: KeyManager | None = None
    ) -> None:
        """Initialize the factory.

        Args:
            config: The NeoZen configuration.
            key_manager: Signing keys for ID tokens and JWT access tokens. It
                must sign with `oauth_server.jwt_algorithm`. Defaults to an
                in-memory manager, whose keys are lost on restart: pass a
                persistent one in production.

        """
        self.config = config
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker | None = None
        self._key_manager = key_manager

    def create_engine(self) -> AsyncEngine:
        """Create SQLAlchemy async engine.

        Returns:
            Configured AsyncEngine instance.

        """
        from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415

        if self._engine is None:
            database = self.config.database
            self._engine = create_async_engine(
                database.url, **database.engine_options()
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

    def _oauth_server(self) -> OAuthServerConfig:
        cfg = self.config.oauth_server
        if not cfg.enabled:
            msg = "oauth_server is not enabled"
            raise ConfigError(msg)
        return cfg

    @property
    def key_manager(self) -> KeyManager:
        """The one key manager behind ID tokens, JWT access tokens and the JWKS."""
        if self._key_manager is None:
            from neozen.core.oidc.keys import InMemoryKeyManager  # noqa: PLC0415

            self._key_manager = InMemoryKeyManager(self._oauth_server().jwt_algorithm)
        return self._key_manager

    def _issuer(self) -> str:
        issuer = self._oauth_server().issuer
        if not issuer:
            msg = "oauth_server.issuer is not set"
            raise ConfigError(msg)
        return issuer

    def create_oauth_token_service[
        OC: OAuthClientModel,
        OAC: OAuthAuthorizationCodeModel,
        OAT: OAuthAccessTokenModel,
        ORT: OAuthRefreshTokenModel,
    ](
        self,
        client_repository: RepositoryProtocol[OC],
        authorization_code_repository: RepositoryProtocol[OAC],
        access_token_repository: RepositoryProtocol[OAT],
        refresh_token_repository: RepositoryProtocol[ORT],
    ) -> OAuthTokenService[OC, OAC, OAT, ORT]:
        """Create the token service with the configured lifetimes and rotation.

        With `oauth_server.jwt_access_tokens`, access tokens are JWTs signed
        by `key_manager`.
        """
        from neozen.core.oauth.jwt_access_token import (  # noqa: PLC0415
            JWTAccessTokenSigner,
        )
        from neozen.core.oauth.services import OAuthTokenService  # noqa: PLC0415

        cfg = self._oauth_server()
        signer = None
        if cfg.jwt_access_tokens:
            if not cfg.jwt_audience:
                msg = "JWT access tokens need oauth_server.jwt_audience"
                raise ConfigError(msg)
            signer = JWTAccessTokenSigner(
                key_manager=self.key_manager,
                issuer=self._issuer(),
                audience=cfg.jwt_audience,
            )
        return OAuthTokenService(
            client_repository=client_repository,
            authorization_code_repository=authorization_code_repository,
            access_token_repository=access_token_repository,
            refresh_token_repository=refresh_token_repository,
            token_hash_key=self.config.security.secret_key,
            access_token_lifetime=cfg.access_token_lifetime,
            refresh_token_lifetime=cfg.refresh_token_lifetime,
            rotate_refresh_tokens=cfg.allow_refresh_token_rotation,
            access_token_signer=signer,
        )

    def create_authorization_endpoint[
        OC: OAuthClientModel,
        OG: OAuthGrantModel,
        OAC: OAuthAuthorizationCodeModel,
    ](
        self,
        client_service: OAuthClientService[OC],
        grant_repository: RepositoryProtocol[OG],
        authorization_code_repository: RepositoryProtocol[OAC],
    ) -> AuthorizationEndpoint[OC, OG, OAC]:
        """Create the authorization endpoint with the configured code lifetime and PKCE rule."""
        from neozen.web.oauth.authorization_endpoint import (  # noqa: PLC0415
            AuthorizationEndpoint,
        )

        cfg = self._oauth_server()
        return AuthorizationEndpoint(
            client_service=client_service,
            grant_repository=grant_repository,
            authorization_code_repository=authorization_code_repository,
            code_hash_key=self.config.security.secret_key,
            code_lifetime=cfg.authorization_code_lifetime,
            require_pkce=cfg.require_pkce,
        )

    def create_id_token_generator(self) -> IDTokenGenerator:
        """Create the OIDC ID token generator (issuer and keys from the config)."""
        from neozen.core.oidc.id_token import IDTokenGenerator  # noqa: PLC0415

        return IDTokenGenerator(key_manager=self.key_manager, issuer=self._issuer())

    def create_discovery_metadata(self, base_url: str) -> OIDCProviderMetadata:
        """Create the discovery document for a server reachable at `base_url`."""
        from neozen.core.oidc.discovery import (  # noqa: PLC0415
            build_metadata_from_base_url,
        )

        return build_metadata_from_base_url(
            issuer=self._issuer(),
            base_url=base_url,
            signing_algorithm=self._oauth_server().jwt_algorithm,
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
