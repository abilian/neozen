"""Dynamic Client Registration endpoint (RFC 7591).

Allows clients to register themselves with the OAuth/OIDC server
via a POST request, without requiring an admin to create them
out-of-band.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, ValidationError

if TYPE_CHECKING:
    from neozen.core.oauth.client_service import OAuthClientService
    from neozen.core.oauth.models import OAuthClientModel


class RegistrationError(Exception):
    """Base exception for registration errors."""

    def __init__(self, error: str, description: str) -> None:
        self.error = error
        self.description = description
        super().__init__(description)


class InvalidClientMetadataError(RegistrationError):
    """Raised when the registration request is malformed."""

    def __init__(self, description: str) -> None:
        super().__init__("invalid_client_metadata", description)


class InvalidRedirectUriError(RegistrationError):
    """Raised when redirect_uris is missing or invalid."""

    def __init__(self, description: str) -> None:
        super().__init__("invalid_redirect_uri", description)


# Scopes a client may register for unless the endpoint is told otherwise.
DEFAULT_REGISTRATION_SCOPES = ("openid", "profile", "email")

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _is_allowed_redirect_uri(uri: str, *, native: bool) -> bool:
    """Whether a client may register this redirect URI.

    Web clients: https, or http on a loopback host (OAuth 2.1 §2.3.1).
    Native clients may also use a private-use scheme in reverse-domain
    form, such as ``com.example.app:/callback`` (RFC 8252 §7.1); the
    required dot rules out ``javascript:``, ``data:`` and the like.
    """
    try:
        parts = urlsplit(uri)
    except ValueError:
        return False
    if parts.fragment:
        return False
    if parts.scheme == "https":
        return bool(parts.hostname)
    if parts.scheme == "http":
        return parts.hostname in _LOOPBACK_HOSTS
    return native and "." in parts.scheme


class RegistrationRequest(BaseModel):
    """Client registration request (RFC 7591 Section 2)."""

    redirect_uris: list[str] = Field(min_length=1)
    client_name: str | None = None
    client_uri: str | None = None
    logo_uri: str | None = None
    scope: str | None = None
    grant_types: list[str] | None = None
    response_types: list[str] | None = None
    token_endpoint_auth_method: str | None = None
    contacts: list[str] | None = None
    tos_uri: str | None = None
    policy_uri: str | None = None
    application_type: str | None = None  # "web" or "native"


@dataclass(frozen=True)
class RegistrationResponse:
    """Successful client registration response (RFC 7591 Section 3.2.1)."""

    client_id: str
    client_secret: str | None
    client_id_issued_at: int
    client_secret_expires_at: int  # 0 = never
    redirect_uris: list[str]
    grant_types: list[str]
    response_types: list[str]
    token_endpoint_auth_method: str
    client_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to a dict suitable for JSON encoding (omits None)."""
        result = asdict(self)
        return {k: v for k, v in result.items() if v is not None}


class RegistrationEndpoint:
    """HTTP adapter for /oauth/register (RFC 7591).

    Validates the registration request, creates an OAuth client via
    `OAuthClientService`, and returns the client credentials.

    Example:
        endpoint = RegistrationEndpoint(client_service)

        try:
            response = await endpoint(payload)
            return JSONResponse(response.to_dict(), status_code=201)
        except RegistrationError as e:
            return JSONResponse(
                {"error": e.error, "error_description": e.description},
                status_code=400,
            )

    Production deployments should restrict access to this endpoint
    (e.g., require an initial bearer token) to prevent abuse.

    A client can register only for the scopes in ``allowed_scopes``, and
    gets all of them when it asks for none.
    """

    def __init__(
        self,
        client_service: OAuthClientService[OAuthClientModel],
        *,
        allowed_grant_types: list[str] | None = None,
        default_grant_types: list[str] | None = None,
        allowed_scopes: list[str] | None = None,
    ) -> None:
        """Initialize the registration endpoint.

        Args:
            client_service: For creating clients.
            allowed_grant_types: Restrict which grant types clients
                can request. None means all NeoZen-supported grants.
            default_grant_types: Grants to assign when the request
                doesn't specify any. Defaults to ["authorization_code",
                "refresh_token"].
            allowed_scopes: The scopes a client may register for. Defaults
                to ``DEFAULT_REGISTRATION_SCOPES``.
        """
        self.client_service = client_service
        self.allowed_grant_types = allowed_grant_types or [
            "authorization_code",
            "refresh_token",
            "client_credentials",
        ]
        self.default_grant_types = default_grant_types or [
            "authorization_code",
            "refresh_token",
        ]
        self.allowed_scopes = allowed_scopes or list(DEFAULT_REGISTRATION_SCOPES)

    async def __call__(self, payload: dict[str, Any]) -> RegistrationResponse:
        """Process a registration request.

        Args:
            payload: The JSON request body.

        Returns:
            A RegistrationResponse with the new client's credentials.

        Raises:
            InvalidClientMetadataError: If the request is malformed.
            InvalidRedirectUriError: If redirect_uris is invalid.
        """
        request = self._parse_request(payload)

        # Application type → client type: native clients are public
        application_type = (request.application_type or "web").lower()
        native = application_type == "native"
        client_type = "public" if native else "confidential"

        for uri in request.redirect_uris:
            if not _is_allowed_redirect_uri(uri, native=native):
                msg = f"redirect_uri not allowed: {uri}"
                raise InvalidRedirectUriError(msg)

        scopes = request.scope.split() if request.scope else self.allowed_scopes
        if not_allowed := set(scopes) - set(self.allowed_scopes):
            msg = f"scope not allowed: {' '.join(sorted(not_allowed))}"
            raise InvalidClientMetadataError(msg)

        # Determine grant types
        grant_types = request.grant_types or list(self.default_grant_types)
        for gt in grant_types:
            if gt not in self.allowed_grant_types:
                msg = f"grant_type '{gt}' is not allowed"
                raise InvalidClientMetadataError(msg)

        # Response types: derive from grant types if not provided
        response_types = request.response_types or self._default_response_types(
            grant_types
        )

        # Token endpoint auth method
        auth_method = request.token_endpoint_auth_method or "client_secret_basic"
        if client_type == "public":
            auth_method = "none"

        # Create the client
        _client, credentials = await self.client_service.create_client(
            client_name=request.client_name or "Dynamically Registered Client",
            redirect_uris=request.redirect_uris,
            client_type=client_type,
            allowed_scopes=scopes,
            allowed_grant_types=grant_types,
            token_endpoint_auth_method=auth_method,
        )

        now = int(datetime.now(UTC).timestamp())

        return RegistrationResponse(
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            client_id_issued_at=now,
            client_secret_expires_at=0,  # never expires
            redirect_uris=list(request.redirect_uris),
            grant_types=list(grant_types),
            response_types=list(response_types),
            token_endpoint_auth_method=auth_method,
            client_name=request.client_name,
        )

    def _parse_request(self, payload: dict[str, Any]) -> RegistrationRequest:
        try:
            return RegistrationRequest.model_validate(payload)
        except ValidationError as e:
            errors = e.errors()
            if errors:
                first = errors[0]
                loc = first.get("loc", ("",))
                field_name = str(loc[0]) if loc else "unknown"
                if field_name == "redirect_uris":
                    msg = "redirect_uris is required and must be a non-empty list"
                    raise InvalidRedirectUriError(msg) from e
                msg = f"Invalid {field_name}: {first.get('msg', 'invalid')}"
                raise InvalidClientMetadataError(msg) from e
            msg = "Invalid request body"
            raise InvalidClientMetadataError(msg) from e

    def _default_response_types(self, grant_types: list[str]) -> list[str]:
        """Derive default response types from grant types."""
        if "authorization_code" in grant_types:
            return ["code"]
        return []


__all__ = [
    "InvalidClientMetadataError",
    "InvalidRedirectUriError",
    "RegistrationEndpoint",
    "RegistrationError",
    "RegistrationRequest",
    "RegistrationResponse",
]
