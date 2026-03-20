"""OAuth client service for managing social login flows."""

from __future__ import annotations

import secrets
import typing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from neozen.core.oauth_client.exceptions import (
    OAuthCallbackError,
    OAuthProviderNotFoundError,
    OAuthStateError,
)
from neozen.core.oauth_client.models import (
    AuthorizationResult,
    CallbackResult,
    OAuthProviderConfig,
    OAuthStateRepositoryProtocol,
    SocialAccountRepositoryProtocol,
)
from neozen.core.oauth_client.providers.base import OAuthProvider
from neozen.core.repository import DoesNotExist

# Error messages
_INVALID_STATE = "Invalid state parameter"
_STATE_EXPIRED = "State has expired"
_PROVIDER_MISMATCH = "Provider mismatch"


@dataclass
class OAuthClientService:
    """Service for managing OAuth social login flows.

    Handles:
    - Provider registration
    - Authorization flow initiation
    - Callback handling with PKCE
    - Social account linking/unlinking
    """

    state_repository: OAuthStateRepositoryProtocol[typing.Any]
    social_account_repository: SocialAccountRepositoryProtocol[typing.Any]
    http_client: typing.Any = field(default=None, repr=False)
    state_expiry_seconds: int = 600  # 10 minutes
    id_generator: typing.Callable[[], str] | None = None
    _providers: dict[str, OAuthProvider] = field(default_factory=dict, repr=False)

    def _generate_id(self) -> str:
        """Generate a unique ID."""
        if self.id_generator:
            return self.id_generator()
        return secrets.token_hex(16)

    def register_provider(self, config: OAuthProviderConfig) -> OAuthProvider:
        """Register an OAuth provider.

        Args:
            config: The provider configuration.

        Returns:
            The registered provider instance.

        """
        provider = OAuthProvider(config=config, http_client=self.http_client)
        self._providers[config.provider_id] = provider
        return provider

    def register_provider_instance(self, provider: OAuthProvider) -> None:
        """Register a pre-configured OAuth provider instance.

        Args:
            provider: The provider instance to register.

        """
        self._providers[provider.config.provider_id] = provider

    def get_provider(self, provider_id: str) -> OAuthProvider:
        """Get a registered OAuth provider.

        Args:
            provider_id: The provider ID.

        Returns:
            The provider instance.

        Raises:
            OAuthProviderNotFoundError: If the provider is not registered.

        """
        provider = self._providers.get(provider_id)
        if provider is None:
            raise OAuthProviderNotFoundError(provider_id)
        return provider

    async def begin_authorization(
        self,
        provider_id: str,
        redirect_uri: str,
        *,
        existing_subject_id: str | None = None,
    ) -> AuthorizationResult:
        """Begin an OAuth authorization flow.

        Args:
            provider_id: The provider ID to authorize with.
            redirect_uri: The redirect URI for the callback.
            existing_subject_id: Optional subject ID for account linking.

        Returns:
            The authorization result with URL and state.

        Raises:
            OAuthProviderNotFoundError: If the provider is not registered.

        """
        provider = self.get_provider(provider_id)

        # Generate state and PKCE code verifier
        state = provider.generate_state()
        code_verifier = provider.generate_code_verifier()
        code_challenge = (
            provider.generate_code_challenge(code_verifier)
            if provider.config.use_pkce
            else None
        )

        # Store state for callback validation
        expires_at = datetime.now(UTC) + timedelta(seconds=self.state_expiry_seconds)
        await self.state_repository.create(
            state=state,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            provider_id=provider_id,
            existing_subject_id=existing_subject_id,
            expires_at=expires_at,
        )

        # Build authorization URL
        authorization_url = provider.get_authorization_url(
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
        )

        return AuthorizationResult(
            authorization_url=authorization_url,
            state=state,
        )

    async def handle_callback(
        self,
        provider_id: str,
        code: str,
        state: str,
        error: str | None = None,
        error_description: str | None = None,
    ) -> CallbackResult:
        """Handle an OAuth callback.

        Args:
            provider_id: The provider ID.
            code: The authorization code.
            state: The state parameter.
            error: Optional error code from the provider.
            error_description: Optional error description.

        Returns:
            The callback result with tokens and user info.

        Raises:
            OAuthCallbackError: If there was an error from the provider.
            OAuthStateError: If state validation fails.
            OAuthProviderNotFoundError: If the provider is not registered.

        """
        # Check for error from provider
        if error:
            msg = error_description or error
            raise OAuthCallbackError(msg, error_code=error)

        # Validate and retrieve state
        try:
            state_record = await self.state_repository.get_one_by(state=state)
        except DoesNotExist:
            raise OAuthStateError(_INVALID_STATE) from None

        # Check expiration
        if datetime.now(UTC) > state_record.expires_at:
            await self.state_repository.delete(state_record)
            raise OAuthStateError(_STATE_EXPIRED)

        # Check provider matches
        if state_record.provider_id != provider_id:
            raise OAuthStateError(_PROVIDER_MISMATCH)

        provider = self.get_provider(provider_id)

        # Exchange code for tokens
        tokens = await provider.exchange_code(
            code=code,
            redirect_uri=state_record.redirect_uri,
            code_verifier=(
                state_record.code_verifier if provider.config.use_pkce else None
            ),
        )

        # Get user info
        user_info = await provider.get_user_info(tokens.access_token)

        # Clean up state
        await self.state_repository.delete(state_record)

        return CallbackResult(
            tokens=tokens,
            user_info=user_info,
            existing_subject_id=state_record.existing_subject_id,
        )

    async def link_account(
        self,
        subject_id: str,
        callback_result: CallbackResult,
    ) -> typing.Any:
        """Link a social account to a subject.

        Args:
            subject_id: The subject ID to link to.
            callback_result: The callback result from handle_callback.

        Returns:
            The created social account.

        """
        user_info = callback_result.user_info
        tokens = callback_result.tokens

        # Calculate token expiration
        token_expires_at = None
        if tokens.expires_in:
            token_expires_at = datetime.now(UTC) + timedelta(seconds=tokens.expires_in)

        return await self.social_account_repository.create(
            id=self._generate_id(),
            subject_id=subject_id,
            provider_id=user_info.provider_id,
            provider_user_id=user_info.provider_user_id,
            email=user_info.email,
            display_name=user_info.display_name,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            token_expires_at=token_expires_at,
        )

    async def get_or_create_subject_id(
        self,
        callback_result: CallbackResult,
    ) -> tuple[str | None, bool]:
        """Find an existing subject by social account or return None.

        Args:
            callback_result: The callback result from handle_callback.

        Returns:
            Tuple of (subject_id or None, is_new).

        """
        user_info = callback_result.user_info

        try:
            social_account = await self.social_account_repository.get_one_by(
                provider_id=user_info.provider_id,
                provider_user_id=user_info.provider_user_id,
            )
            return social_account.subject_id, False
        except DoesNotExist:
            return None, True

    async def update_tokens(
        self,
        subject_id: str,
        provider_id: str,
        callback_result: CallbackResult,
    ) -> typing.Any:
        """Update tokens for an existing social account.

        Args:
            subject_id: The subject ID.
            provider_id: The provider ID.
            callback_result: The callback result with new tokens.

        Returns:
            The updated social account.

        """
        tokens = callback_result.tokens

        social_account = await self.social_account_repository.get_one_by(
            subject_id=subject_id,
            provider_id=provider_id,
        )

        token_expires_at = None
        if tokens.expires_in:
            token_expires_at = datetime.now(UTC) + timedelta(seconds=tokens.expires_in)

        return await self.social_account_repository.update_obj(
            social_account,
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token or social_account.refresh_token,
            token_expires_at=token_expires_at,
        )

    async def unlink_account(
        self,
        subject_id: str,
        provider_id: str,
    ) -> None:
        """Unlink a social account from a subject.

        Args:
            subject_id: The subject ID.
            provider_id: The provider ID to unlink.

        """
        try:
            social_account = await self.social_account_repository.get_one_by(
                subject_id=subject_id,
                provider_id=provider_id,
            )
            await self.social_account_repository.delete(social_account)
        except DoesNotExist:
            pass  # Already unlinked

    async def get_linked_accounts(
        self,
        subject_id: str,
    ) -> list[typing.Any]:
        """Get all social accounts linked to a subject.

        Args:
            subject_id: The subject ID.

        Returns:
            List of social accounts.

        """
        return await self.social_account_repository.get_many_by(
            subject_id=subject_id,
        )

    async def cleanup_expired_states(self) -> int:
        """Clean up expired OAuth states.

        Returns:
            Number of states cleaned up.

        Note:
            This is a maintenance operation that should be run periodically.
            Currently not implemented as it requires a custom query.

        """
        # This would require a custom query to delete expired states
        # For now, states are cleaned up on callback or on failed validation
        return 0


__all__ = ["OAuthClientService"]
