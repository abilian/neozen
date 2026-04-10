"""RP-Initiated Logout endpoint (OIDC RP-Initiated Logout 1.0).

Allows a relying party to log a user out of the OIDC Provider.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from neozen.core.oauth.client_service import OAuthClientService
    from neozen.core.oauth.models import OAuthClientModel


class EndSessionError(Exception):
    """Raised when an end-session request is malformed."""


class InvalidPostLogoutRedirectError(EndSessionError):
    """Raised when post_logout_redirect_uri is not registered for the client."""


@dataclass
class EndSessionRequest:
    """Parsed end-session request parameters.

    Per OIDC RP-Initiated Logout 1.0:
    - id_token_hint: previously issued ID Token (recommended)
    - logout_hint: hint about the user (optional)
    - client_id: the client requesting logout (required if no id_token_hint)
    - post_logout_redirect_uri: where to redirect after logout
    - state: opaque value to maintain state
    - ui_locales: preferred locales for the logout UI
    """

    id_token_hint: str | None = None
    logout_hint: str | None = None
    client_id: str | None = None
    post_logout_redirect_uri: str | None = None
    state: str | None = None
    ui_locales: str | None = None


@dataclass
class EndSessionResult:
    """Result of processing an end-session request.

    The framework adapter is responsible for actually destroying the
    user's session and performing the redirect.
    """

    # The validated client (if any) -- useful for showing the client name
    client: Any = None
    # The validated post-logout redirect URI (or None to show a default page)
    post_logout_redirect_uri: str | None = None
    # State to append to the redirect URI
    state: str | None = None
    # Whether a confirmation page should be shown
    require_confirmation: bool = False


class EndSessionEndpoint:
    """HTTP adapter for /oauth/end_session.

    The endpoint:
    1. Parses the request parameters
    2. Validates the client and post_logout_redirect_uri
    3. Returns a result describing what should happen next

    The framework adapter is responsible for:
    - Looking up the user's session and destroying it
    - Showing a confirmation page (if `require_confirmation` is True)
    - Performing the redirect or rendering a default logged-out page

    Example:
        endpoint = EndSessionEndpoint(client_service)
        result = await endpoint(request_params)

        if result.post_logout_redirect_uri:
            # Build redirect URL with optional state
            url = result.post_logout_redirect_uri
            if result.state:
                url += f"?state={result.state}"
            return redirect(url)
        else:
            return render_template("logged_out.html")
    """

    def __init__(
        self,
        client_service: OAuthClientService[OAuthClientModel],
        *,
        require_confirmation: bool = False,
    ) -> None:
        """Initialize the end-session endpoint.

        Args:
            client_service: For looking up the client.
            require_confirmation: If True, the result will indicate
                that a confirmation page should be shown before logout.
        """
        self.client_service = client_service
        self.require_confirmation = require_confirmation

    async def __call__(self, params: dict[str, Any]) -> EndSessionResult:
        """Process an end-session request.

        Args:
            params: Query string or form parameters.

        Returns:
            EndSessionResult describing what should happen next.

        Raises:
            InvalidPostLogoutRedirectError: If post_logout_redirect_uri
                is not registered for the client.
        """
        request = self._parse_request(params)

        # Look up client
        client = await self._resolve_client(request)

        # Validate post_logout_redirect_uri if provided
        post_logout_uri: str | None = None
        if request.post_logout_redirect_uri:
            if client is None:
                msg = "post_logout_redirect_uri requires client_id or id_token_hint"
                raise InvalidPostLogoutRedirectError(msg)

            if not client.is_redirect_uri_allowed(request.post_logout_redirect_uri):
                msg = "post_logout_redirect_uri is not registered for this client"
                raise InvalidPostLogoutRedirectError(msg)
            post_logout_uri = request.post_logout_redirect_uri

        return EndSessionResult(
            client=client,
            post_logout_redirect_uri=post_logout_uri,
            state=request.state,
            require_confirmation=self.require_confirmation,
        )

    def _parse_request(self, params: dict[str, Any]) -> EndSessionRequest:
        """Parse the raw parameters into an EndSessionRequest."""
        return EndSessionRequest(
            id_token_hint=params.get("id_token_hint"),
            logout_hint=params.get("logout_hint"),
            client_id=params.get("client_id"),
            post_logout_redirect_uri=params.get("post_logout_redirect_uri"),
            state=params.get("state"),
            ui_locales=params.get("ui_locales"),
        )

    async def _resolve_client(self, request: EndSessionRequest) -> Any | None:
        """Look up the client from client_id or id_token_hint."""
        client_id = request.client_id

        # If no explicit client_id, try to extract from id_token_hint
        if not client_id and request.id_token_hint:
            client_id = self._client_id_from_id_token(request.id_token_hint)

        if not client_id:
            return None

        try:
            return await self.client_service.get_active_client(client_id)
        except Exception:
            return None

    def _client_id_from_id_token(self, id_token: str) -> str | None:
        """Extract the client_id (aud claim) from an ID token without verifying.

        We don't verify the signature here because the token may have
        already expired (the user is logging out, after all). We only
        use it to identify the client for redirect URI validation.
        """
        try:
            import jwt  # noqa: PLC0415

            unverified = jwt.decode(
                id_token,
                options={"verify_signature": False},
            )
            aud = unverified.get("aud")
            if isinstance(aud, list):
                return aud[0] if aud else None
            return aud
        except Exception:
            return None


__all__ = [
    "EndSessionEndpoint",
    "EndSessionError",
    "EndSessionRequest",
    "EndSessionResult",
    "InvalidPostLogoutRedirectError",
]
