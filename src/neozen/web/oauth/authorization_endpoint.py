"""OAuth 2.1 authorization endpoint HTTP adapter for NeoZen.

This module provides the HTTP adapter for the OAuth authorization endpoint.
It handles request parsing, response formatting, and delegates to
the core services for business logic.
"""

from __future__ import annotations

import typing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from pydantic import AnyUrl, BaseModel, Field, ValidationError, model_validator

from neozen.core.crypto import generate_token_hash_pair
from neozen.core.oauth.client_service import OAuthClientService
from neozen.core.oauth.exceptions import (
    ClientInactiveError,
    ClientNotFoundError,
    InvalidGrantTypeError,
    InvalidRedirectUriError,
    InvalidScopeError,
)
from neozen.core.oauth.models import (
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthGrantModel,
)
from neozen.core.oauth.types import CodeChallengeMethod
from neozen.core.repository import DoesNotExist, RepositoryProtocol
from neozen.core.subject import Subject

# =============================================================================
# Request Models
# =============================================================================


class AuthorizationRequest(BaseModel):
    """Request model for authorization endpoint."""

    response_type: str
    client_id: str
    redirect_uri: AnyUrl | None = None
    scope: str | None = None
    state: str | None = None
    code_challenge: (
        typing.Annotated[str, Field(pattern=r"^[A-Za-z0-9\-\._~]{43,128}$")] | None
    ) = None
    code_challenge_method: CodeChallengeMethod = "S256"

    @model_validator(mode="before")
    @classmethod
    def _empty_pkce_fields_are_absent(cls, data: typing.Any) -> typing.Any:
        """HTML forms send an empty hidden field as ``""``."""
        if isinstance(data, dict):
            return {
                key: value
                for key, value in data.items()
                if not (key.startswith("code_challenge") and value == "")
            }
        return data


class ConsentRequest(AuthorizationRequest):
    """Consent submission: the original request echoed back, plus the answer.

    Parsing it applies every check the authorization request had, so a
    tampered form cannot change redirect_uri, scope or the PKCE method.
    """

    response_type: str = "code"
    approved: bool


# =============================================================================
# Response Models
# =============================================================================


@dataclass
class AuthorizationResponse:
    """Response from authorization endpoint."""

    # For redirects
    redirect_uri: str | None = None
    code: str | None = None
    state: str | None = None

    # For errors
    error: str | None = None
    error_description: str | None = None

    # For intermediate states
    requires_login: bool = False
    requires_consent: bool = False
    consent_data: ConsentData | None = None

    def get_redirect_url(self) -> str | None:
        """Build the redirect URL with query parameters."""
        if not self.redirect_uri:
            return None

        params: dict[str, str] = {}
        if self.code:
            params["code"] = self.code
        if self.state:
            params["state"] = self.state
        if self.error:
            params["error"] = self.error
        if self.error_description:
            params["error_description"] = self.error_description

        if params:
            return f"{self.redirect_uri}?{urlencode(params)}"
        return self.redirect_uri


@dataclass
class ConsentData:
    """Data needed to render consent page."""

    client_id: str
    client_name: str
    scope: str | None
    redirect_uri: str | None
    state: str | None
    code_challenge: str | None
    code_challenge_method: CodeChallengeMethod | None


# =============================================================================
# Authorization Endpoint
# =============================================================================


_DEFAULT_CODE_PREFIX = "nz_ac_"


def _challenge_method(request: AuthorizationRequest) -> CodeChallengeMethod | None:
    """The PKCE method, or None when the request carries no challenge."""
    return request.code_challenge_method if request.code_challenge else None


class AuthorizationEndpoint[
    OC: OAuthClientModel,
    OG: OAuthGrantModel,
    OAC: OAuthAuthorizationCodeModel,
]:
    """OAuth 2.1 authorization endpoint HTTP adapter.

    Handles:
    - Authorization request validation
    - Client validation (redirect URI, scope)
    - Consent flow management
    - Authorization code generation

    Example:
        client_service = OAuthClientService(...)
        endpoint = AuthorizationEndpoint(
            client_service=client_service,
            grant_repository=grant_repo,
            authorization_code_repository=auth_code_repo,
            code_hash_key="secret",
        )

        # Handle GET request
        response = await endpoint.handle_authorization_request(
            payload=request.query_params,
            subject=current_user,
        )

        # Handle consent
        response = await endpoint.handle_consent(
            payload=form_data,
            subject=current_user,
        )
    """

    def __init__(
        self,
        client_service: OAuthClientService[OC],
        grant_repository: RepositoryProtocol[OG],
        authorization_code_repository: RepositoryProtocol[OAC],
        code_hash_key: str,
        code_prefix: str = _DEFAULT_CODE_PREFIX,
        code_lifetime: timedelta = timedelta(minutes=10),
        *,
        require_pkce: bool = True,
    ) -> None:
        """Initialize the authorization endpoint.

        Args:
            client_service: Service for client management.
            grant_repository: Repository for OAuth grants.
            authorization_code_repository: Repository for authorization codes.
            code_hash_key: Key for hashing authorization codes.
            code_prefix: Prefix for generated codes.
            code_lifetime: How long codes are valid.
            require_pkce: Require PKCE from confidential clients too. Public
                clients must always use it.
        """
        self.client_service = client_service
        self.grant_repository = grant_repository
        self.authorization_code_repository = authorization_code_repository
        self.code_hash_key = code_hash_key
        self.code_prefix = code_prefix
        self.code_lifetime = code_lifetime
        self.require_pkce = require_pkce

    async def handle_authorization_request[S: Subject](
        self,
        payload: dict[str, typing.Any],
        subject: S | None,
    ) -> AuthorizationResponse:
        """Handle an authorization request (typically GET /oauth/authorize).

        Args:
            payload: Request query parameters.
            subject: The authenticated subject, or None if not authenticated.

        Returns:
            Authorization response indicating next action.
        """
        # Parse and validate request
        try:
            request = AuthorizationRequest.model_validate(payload)
        except ValidationError as e:
            return AuthorizationResponse(
                error="invalid_request",
                error_description=self._format_validation_error(e),
            )

        # Validate client and get redirect URI
        client, redirect_uri, error = await self._validate_client_and_redirect(request)
        if error:
            return error

        # At this point, client and redirect_uri are guaranteed to be set
        assert client is not None
        assert redirect_uri is not None

        # Validate request parameters against client
        error = self._validate_request_params(client, request, redirect_uri)
        if error:
            return error

        # Build consent data for potential use
        consent_data = ConsentData(
            client_id=client.client_id,
            client_name=client.client_name,
            scope=request.scope,
            redirect_uri=redirect_uri,
            state=request.state,
            code_challenge=request.code_challenge,
            code_challenge_method=_challenge_method(request),
        )

        # Check if subject is authenticated
        if subject is None:
            return AuthorizationResponse(requires_login=True, consent_data=consent_data)

        # Check for existing grant and handle accordingly
        return await self._handle_grant_check(
            client, subject, redirect_uri, request, consent_data
        )

    async def _validate_client_and_redirect(
        self, request: AuthorizationRequest
    ) -> tuple[OC | None, str | None, AuthorizationResponse | None]:
        """Validate client and resolve redirect URI.

        Returns:
            Tuple of (client, redirect_uri, error_response).
            If error_response is not None, return it immediately.
        """
        # Get and validate client
        try:
            client = await self.client_service.get_active_client(request.client_id)
        except ClientNotFoundError:
            return (
                None,
                None,
                AuthorizationResponse(
                    error="invalid_request",
                    error_description="Unknown client_id.",
                ),
            )
        except ClientInactiveError:
            return (
                None,
                None,
                AuthorizationResponse(
                    error="invalid_request",
                    error_description="Client is inactive.",
                ),
            )

        # Validate redirect_uri
        redirect_uri = str(request.redirect_uri) if request.redirect_uri else None
        if redirect_uri:
            try:
                self.client_service.validate_redirect_uri(client, redirect_uri)
            except InvalidRedirectUriError:
                return (
                    None,
                    None,
                    AuthorizationResponse(
                        error="invalid_request",
                        error_description="Invalid redirect_uri.",
                    ),
                )
        else:
            # Use first registered redirect URI as default
            uris = client.get_redirect_uris()
            if not uris:
                return (
                    None,
                    None,
                    AuthorizationResponse(
                        error="invalid_request",
                        error_description="No redirect_uri registered.",
                    ),
                )
            redirect_uri = uris[0]

        return client, redirect_uri, None

    def _validate_request_params(
        self,
        client: OC,
        request: AuthorizationRequest,
        redirect_uri: str,
    ) -> AuthorizationResponse | None:
        """Validate request parameters against client configuration.

        Returns:
            Error response if validation fails, None if valid.
        """
        # Validate response_type
        if request.response_type != "code":
            return self._error_response(
                redirect_uri,
                request.state,
                "unsupported_response_type",
                "Only 'code' response type is supported.",
            )

        # Validate scope
        if request.scope:
            try:
                self.client_service.validate_scope(client, request.scope)
            except InvalidScopeError as e:
                return self._error_response(
                    redirect_uri, request.state, "invalid_scope", str(e)
                )

        # Validate grant type is allowed
        try:
            self.client_service.validate_grant_type(client, "authorization_code")
        except InvalidGrantTypeError:
            return self._error_response(
                redirect_uri,
                request.state,
                "unauthorized_client",
                "Client is not authorized for authorization_code grant.",
            )

        # PKCE: always for public clients (S256 only), optional for
        # confidential clients when require_pkce is off.
        if request.code_challenge is None:
            if self.require_pkce or client.is_public_client():
                return self._error_response(
                    redirect_uri,
                    request.state,
                    "invalid_request",
                    "code_challenge is required.",
                )
        elif client.is_public_client() and request.code_challenge_method != "S256":
            return self._error_response(
                redirect_uri,
                request.state,
                "invalid_request",
                "Public clients must use S256 code_challenge_method.",
            )

        return None

    async def _handle_grant_check[S: Subject](
        self,
        client: OC,
        subject: S,
        redirect_uri: str,
        request: AuthorizationRequest,
        consent_data: ConsentData,
    ) -> AuthorizationResponse:
        """Check for existing grant and generate code or require consent."""
        try:
            await self.grant_repository.get_one_by(
                client_id=client.client_id,
                subject_id=subject.id,
            )
            # Grant exists - generate code immediately
            return await self._generate_authorization_code(
                client=client,
                subject_id=subject.id,
                redirect_uri=redirect_uri,
                request=request,
            )
        except DoesNotExist:
            # Need consent
            return AuthorizationResponse(
                requires_consent=True, consent_data=consent_data
            )

    async def handle_consent[S: Subject](
        self,
        payload: dict[str, typing.Any],
        subject: S,
    ) -> AuthorizationResponse:
        """Handle consent form submission.

        Args:
            payload: Form data from consent submission.
            subject: The authenticated subject.

        Returns:
            Authorization response with redirect.
        """
        try:
            request = ConsentRequest.model_validate(payload)
        except ValidationError as e:
            return AuthorizationResponse(
                error="invalid_request",
                error_description=self._format_validation_error(e),
            )

        client, redirect_uri, error = await self._validate_client_and_redirect(request)
        if error:
            return error
        assert client is not None
        assert redirect_uri is not None

        error = self._validate_request_params(client, request, redirect_uri)
        if error:
            return error

        # Handle denial
        if not request.approved:
            return self._error_response(
                redirect_uri,
                request.state,
                "access_denied",
                "The user denied the authorization request.",
            )

        try:
            await self.grant_repository.get_one_by(
                client_id=client.client_id, subject_id=subject.id
            )
        except DoesNotExist:
            await self.grant_repository.create(
                client_id=client.client_id,
                subject_id=subject.id,
                granted_at=datetime.now(UTC),
                scope=request.scope or "",
            )

        # Generate authorization code
        return await self._generate_authorization_code(
            client=client,
            subject_id=subject.id,
            redirect_uri=redirect_uri,
            request=request,
        )

    async def _generate_authorization_code(
        self,
        client: OC,
        subject_id: typing.Any,
        redirect_uri: str,
        request: AuthorizationRequest,
    ) -> AuthorizationResponse:
        """Generate an authorization code and return redirect response.

        The code records the redirect URI only if the client sent one: the
        token request must then repeat it (RFC 6749 §4.1.3), and need not
        otherwise.
        """
        code, code_hash = generate_token_hash_pair(
            self.code_hash_key, prefix=self.code_prefix
        )

        await self.authorization_code_repository.create(
            code=code_hash,
            client_id=client.client_id,
            subject_id=subject_id,
            expires_at=datetime.now(UTC) + self.code_lifetime,
            response_type="code",
            redirect_uri=str(request.redirect_uri) if request.redirect_uri else None,
            scope=request.scope or "",
            code_challenge=request.code_challenge,
            code_challenge_method=_challenge_method(request),
        )

        return AuthorizationResponse(
            redirect_uri=redirect_uri,
            code=code,
            state=request.state,
        )

    def _error_response(
        self,
        redirect_uri: str | None,
        state: str | None,
        error: str,
        error_description: str,
    ) -> AuthorizationResponse:
        """Create an error response that redirects to the client."""
        return AuthorizationResponse(
            redirect_uri=redirect_uri,
            state=state,
            error=error,
            error_description=error_description,
        )

    def _format_validation_error(self, e: ValidationError) -> str:
        """Format a Pydantic validation error for OAuth response."""
        errors = e.errors()
        if errors:
            first = errors[0]
            field = first.get("loc", ("unknown",))[0]
            return f"Invalid parameter: {field}"
        return "Invalid request"


__all__ = [
    "AuthorizationEndpoint",
    "AuthorizationRequest",
    "AuthorizationResponse",
    "ConsentData",
    "ConsentRequest",
]
