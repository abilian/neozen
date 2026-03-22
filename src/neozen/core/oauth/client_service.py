"""OAuth 2.1 client management service for NeoZen.

This module provides services for managing OAuth clients, including:
- Client creation and registration
- Client authentication (Basic auth, POST body)
- Redirect URI validation
- Client secret rotation
- Client deactivation
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from neozen.core.factors.password import PasswordHasherProtocol
from neozen.core.oauth.exceptions import (
    ClientAuthenticationError,
    ClientInactiveError,
    ClientNotFoundError,
    InvalidGrantTypeError,
    InvalidRedirectUriError,
    InvalidScopeError,
)
from neozen.core.oauth.models import OAuthClientModel
from neozen.core.repository import DoesNotExist, RepositoryProtocol


@dataclass
class ClientCredentials:
    """Result of client creation with credentials."""

    client_id: str
    client_secret: str | None  # None for public clients


class OAuthClientService[OC: OAuthClientModel]:
    """Service for OAuth client management.

    Handles:
    - Client registration and creation
    - Client authentication
    - Redirect URI validation
    - Secret rotation
    - Client deactivation
    """

    def __init__(
        self,
        client_repository: RepositoryProtocol[OC],
        hasher: PasswordHasherProtocol,
        *,
        client_id_length: int = 32,
        client_secret_length: int = 48,
    ) -> None:
        """Initialize the client service.

        Args:
            client_repository: Repository for OAuth client storage.
            hasher: Password hasher for client secrets.
            client_id_length: Length of generated client IDs in bytes.
            client_secret_length: Length of generated client secrets in bytes.
        """
        self.client_repository = client_repository
        self.hasher = hasher
        self.client_id_length = client_id_length
        self.client_secret_length = client_secret_length

    def _generate_client_id(self) -> str:
        """Generate a unique client ID."""
        return secrets.token_hex(self.client_id_length)

    def _generate_client_secret(self) -> str:
        """Generate a client secret."""
        return secrets.token_urlsafe(self.client_secret_length)

    async def create_client(
        self,
        client_name: str,
        redirect_uris: list[str],
        *,
        client_type: str = "confidential",
        allowed_scopes: list[str] | None = None,
        allowed_grant_types: list[str] | None = None,
        token_endpoint_auth_method: str = "client_secret_basic",
    ) -> tuple[OC, ClientCredentials]:
        """Create a new OAuth client.

        Args:
            client_name: Human-readable name for the client.
            redirect_uris: List of allowed redirect URIs.
            client_type: "public" or "confidential".
            allowed_scopes: List of allowed scopes (None means all).
            allowed_grant_types: List of allowed grant types.
            token_endpoint_auth_method: Auth method for token endpoint.

        Returns:
            Tuple of (client, credentials).
        """
        client_id = self._generate_client_id()

        # Generate secret for confidential clients
        client_secret: str | None = None
        client_secret_hash: str | None = None
        if client_type == "confidential":
            client_secret = self._generate_client_secret()
            client_secret_hash = self.hasher.hash(client_secret)

        # Default grant types
        if allowed_grant_types is None:
            allowed_grant_types = ["authorization_code", "refresh_token"]

        now = datetime.now(UTC)

        client = await self.client_repository.create(
            client_id=client_id,
            client_name=client_name,
            client_secret_hash=client_secret_hash,
            client_type=client_type,
            redirect_uris=json.dumps(redirect_uris),
            allowed_scopes=" ".join(allowed_scopes) if allowed_scopes else "",
            allowed_grant_types=" ".join(allowed_grant_types),
            token_endpoint_auth_method=token_endpoint_auth_method,
            is_active=True,
            created_at=now,
            updated_at=None,
        )

        credentials = ClientCredentials(
            client_id=client_id,
            client_secret=client_secret,
        )

        return client, credentials

    async def get_client(self, client_id: str) -> OC:
        """Get a client by ID.

        Args:
            client_id: The client ID.

        Returns:
            The OAuth client.

        Raises:
            ClientNotFoundError: If client not found.
        """
        try:
            return await self.client_repository.get_one_by(client_id=client_id)
        except DoesNotExist as e:
            raise ClientNotFoundError(client_id) from e

    async def get_active_client(self, client_id: str) -> OC:
        """Get an active client by ID.

        Args:
            client_id: The client ID.

        Returns:
            The OAuth client.

        Raises:
            ClientNotFoundError: If client not found.
            ClientInactiveError: If client is inactive.
        """
        client = await self.get_client(client_id)
        if not client.is_active:
            raise ClientInactiveError(client_id)
        return client

    async def authenticate_client(
        self,
        client_id: str,
        client_secret: str | None,
    ) -> OC:
        """Authenticate a client using client credentials.

        Args:
            client_id: The client ID.
            client_secret: The client secret (None for public clients).

        Returns:
            The authenticated client.

        Raises:
            ClientNotFoundError: If client not found.
            ClientInactiveError: If client is inactive.
            ClientAuthenticationError: If authentication fails.
        """
        client = await self.get_active_client(client_id)

        # Public clients don't need secret authentication
        if client.client_type == "public":
            return client

        # Confidential clients must provide valid secret
        if client_secret is None:
            msg = "Client secret is required."
            raise ClientAuthenticationError(msg)

        if client.client_secret_hash is None:
            msg = "Client has no secret configured."
            raise ClientAuthenticationError(msg)

        is_valid, _ = self.hasher.verify_and_update(
            client_secret, client.client_secret_hash
        )
        if not is_valid:
            msg = "Invalid client secret."
            raise ClientAuthenticationError(msg)

        return client

    def validate_redirect_uri(self, client: OC, redirect_uri: str) -> None:
        """Validate that a redirect URI is allowed for the client.

        Args:
            client: The OAuth client.
            redirect_uri: The redirect URI to validate.

        Raises:
            InvalidRedirectUriError: If redirect URI is not allowed.
        """
        if not client.is_redirect_uri_allowed(redirect_uri):
            raise InvalidRedirectUriError(redirect_uri)

    def validate_scope(self, client: OC, scope: str) -> None:
        """Validate that a scope is allowed for the client.

        Args:
            client: The OAuth client.
            scope: Space-separated scopes to validate.

        Raises:
            InvalidScopeError: If any scope is not allowed.
        """
        if not scope:
            return

        for s in scope.split():
            if not client.is_scope_allowed(s):
                raise InvalidScopeError(s)

    def validate_grant_type(self, client: OC, grant_type: str) -> None:
        """Validate that a grant type is allowed for the client.

        Args:
            client: The OAuth client.
            grant_type: The grant type to validate.

        Raises:
            InvalidGrantTypeError: If grant type is not allowed.
        """
        if not client.is_grant_type_allowed(grant_type):
            raise InvalidGrantTypeError(grant_type)

    async def rotate_secret(self, client_id: str) -> str:
        """Rotate the client secret.

        Args:
            client_id: The client ID.

        Returns:
            The new plain-text secret.

        Raises:
            ClientNotFoundError: If client not found.
            ClientAuthenticationError: If client is public.
        """
        client = await self.get_client(client_id)

        if client.client_type == "public":
            msg = "Cannot rotate secret for public clients."
            raise ClientAuthenticationError(msg)

        new_secret = self._generate_client_secret()
        new_hash = self.hasher.hash(new_secret)

        await self.client_repository.update_obj(
            client,
            client_secret_hash=new_hash,
            updated_at=datetime.now(UTC),
        )

        return new_secret

    async def deactivate_client(self, client_id: str) -> OC:
        """Deactivate a client.

        Args:
            client_id: The client ID.

        Returns:
            The deactivated client.

        Raises:
            ClientNotFoundError: If client not found.
        """
        client = await self.get_client(client_id)

        return await self.client_repository.update_obj(
            client,
            is_active=False,
            updated_at=datetime.now(UTC),
        )

    async def activate_client(self, client_id: str) -> OC:
        """Activate a client.

        Args:
            client_id: The client ID.

        Returns:
            The activated client.

        Raises:
            ClientNotFoundError: If client not found.
        """
        client = await self.get_client(client_id)

        return await self.client_repository.update_obj(
            client,
            is_active=True,
            updated_at=datetime.now(UTC),
        )

    async def update_client(
        self,
        client_id: str,
        *,
        client_name: str | None = None,
        redirect_uris: list[str] | None = None,
        allowed_scopes: list[str] | None = None,
        allowed_grant_types: list[str] | None = None,
    ) -> OC:
        """Update client settings.

        Args:
            client_id: The client ID.
            client_name: New name (if provided).
            redirect_uris: New redirect URIs (if provided).
            allowed_scopes: New allowed scopes (if provided).
            allowed_grant_types: New allowed grant types (if provided).

        Returns:
            The updated client.

        Raises:
            ClientNotFoundError: If client not found.
        """
        client = await self.get_client(client_id)

        updates: dict[str, str | datetime | None] = {"updated_at": datetime.now(UTC)}

        if client_name is not None:
            updates["client_name"] = client_name
        if redirect_uris is not None:
            updates["redirect_uris"] = json.dumps(redirect_uris)
        if allowed_scopes is not None:
            updates["allowed_scopes"] = " ".join(allowed_scopes)
        if allowed_grant_types is not None:
            updates["allowed_grant_types"] = " ".join(allowed_grant_types)

        return await self.client_repository.update_obj(client, **updates)

    async def list_clients(
        self,
        *,
        active_only: bool = False,
    ) -> list[OC]:
        """List all OAuth clients.

        Args:
            active_only: If True, only return active clients.

        Returns:
            List of OAuth clients.
        """
        if active_only:
            return await self.client_repository.get_many_by(is_active=True)
        return await self.client_repository.get_many_by()


__all__ = [
    "ClientCredentials",
    "OAuthClientService",
]
