"""Litestar OAuth 2.1 Server Routes.

Provides OAuth 2.1 server endpoints for Litestar applications.

Example:
    from litestar import Litestar, Router
    from neozen.ext.litestar.oauth import create_oauth_router

    oauth_router = create_oauth_router(
        client_service=client_service,
        token_service=token_service,
        authorization_endpoint=auth_endpoint,
    )
    app = Litestar(route_handlers=[oauth_router])
"""

from __future__ import annotations

import typing

from litestar import Request, Response, Router, get, post
from litestar.datastructures import FormMultiDict
from litestar.response import Redirect

from neozen.core.oauth.client_service import OAuthClientService
from neozen.core.oauth.exceptions import TokenError
from neozen.core.oauth.models import (
    OAuthAccessTokenModel,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthGrantModel,
    OAuthRefreshTokenModel,
)
from neozen.core.oauth.services import OAuthTokenService
from neozen.web.oauth import (
    NO_STORE_HEADERS,
    AuthorizationEndpoint,
    IntrospectionEndpoint,
    RevocationEndpoint,
    TokenEndpoint,
    parse_basic_auth,
    token_error_headers,
    token_error_status,
)


def _get_client_credentials(
    request: Request, form: FormMultiDict
) -> tuple[str | None, str | None]:
    """Extract client credentials from request (header or form)."""
    client_id, client_secret = parse_basic_auth(request.headers.get("Authorization"))
    if not client_id:
        client_id = typing.cast(str | None, form.get("client_id"))
        client_secret = typing.cast(str | None, form.get("client_secret"))
    return client_id, client_secret


def _json_response(content: dict, status_code: int = 200) -> Response:
    """Create a JSON response."""
    return Response(
        content=content, status_code=status_code, media_type="application/json"
    )


def _error_response(error: str, description: str | None, status_code: int) -> Response:
    """Create an OAuth error response."""
    return _json_response(
        {"error": error, "error_description": description}, status_code
    )


def _create_token_handler(token_ep: TokenEndpoint) -> typing.Callable:
    """Create the token endpoint handler."""

    @post("/token")
    async def token_handler(request: Request) -> Response:
        """OAuth 2.1 Token Endpoint."""
        form = await request.form()
        client_id, client_secret = _get_client_credentials(request, form)
        try:
            response = await token_ep(
                dict(form), client_id=client_id, client_secret=client_secret
            )
        except TokenError as e:
            error = _error_response(
                e.error, e.error_description, token_error_status(e.error)
            )
            error.headers.update(token_error_headers(e.error))
            return error
        success = _json_response(response.to_dict())
        success.headers.update(NO_STORE_HEADERS)
        return success

    return token_handler


def _create_introspect_handler(
    introspection_ep: IntrospectionEndpoint,
) -> typing.Callable:
    """Create the introspection endpoint handler."""

    @post("/introspect")
    async def introspect_handler(request: Request) -> Response:
        """OAuth 2.1 Token Introspection Endpoint (RFC 7662)."""
        form = await request.form()
        client_id, client_secret = _get_client_credentials(request, form)
        try:
            response = await introspection_ep(
                dict(form), client_id=client_id, client_secret=client_secret
            )
            return _json_response(response.to_dict())
        except TokenError as e:
            return _error_response(e.error, e.error_description, 401)

    return introspect_handler


def _create_revoke_handler(revocation_ep: RevocationEndpoint) -> typing.Callable:
    """Create the revocation endpoint handler."""

    @post("/revoke")
    async def revoke_handler(request: Request) -> Response:
        """OAuth 2.1 Token Revocation Endpoint (RFC 7009)."""
        form = await request.form()
        client_id, client_secret = _get_client_credentials(request, form)
        try:
            await revocation_ep(
                dict(form), client_id=client_id, client_secret=client_secret
            )
            return Response(content=None, status_code=200)
        except TokenError as e:
            return _error_response(e.error, e.error_description, 401)

    return revoke_handler


def _create_authorize_handler(
    authorization_endpoint: AuthorizationEndpoint,
    get_current_subject: typing.Callable[[Request], typing.Any] | None,
    login_url: str,
    consent_template_func: typing.Callable[[Request, typing.Any], Response] | None,
) -> typing.Callable:
    """Create the authorization endpoint GET handler."""

    @get("/authorize")
    async def authorize_handler(request: Request) -> Response:
        """OAuth 2.1 Authorization Endpoint."""
        subject = get_current_subject(request) if get_current_subject else None
        payload = dict(request.query_params)
        response = await authorization_endpoint.handle_authorization_request(
            payload, subject
        )

        if response.requires_login:
            request.session["oauth_params"] = payload
            return Redirect(path=login_url)

        if response.requires_consent:
            if consent_template_func:
                return consent_template_func(request, response.consent_data)
            return _json_response({
                "error": "consent_required",
                "consent_data": response.consent_data,
            })

        if response.error:
            redirect_url = response.get_redirect_url()
            if redirect_url:
                return Redirect(path=redirect_url)
            return _error_response(response.error, response.error_description, 400)

        redirect_url = response.get_redirect_url()
        if redirect_url:
            return Redirect(path=redirect_url)
        return _json_response({"error": "invalid_request"}, 400)

    return authorize_handler


def _create_authorize_consent_handler(
    authorization_endpoint: AuthorizationEndpoint,
    get_current_subject: typing.Callable[[Request], typing.Any] | None,
) -> typing.Callable:
    """Create the authorization consent POST handler."""

    @post("/authorize")
    async def authorize_consent_handler(request: Request) -> Response:
        """Handle consent form submission."""
        subject = get_current_subject(request) if get_current_subject else None
        if not subject:
            return _json_response({"error": "Not authenticated"}, 401)

        form = await request.form()
        response = await authorization_endpoint.handle_consent(dict(form), subject)

        redirect_url = response.get_redirect_url()
        if redirect_url:
            return Redirect(path=redirect_url)

        return _error_response(
            response.error or "unknown_error", response.error_description, 400
        )

    return authorize_consent_handler


def create_oauth_router[
    OC: OAuthClientModel,
    OG: OAuthGrantModel,
    OAC: OAuthAuthorizationCodeModel,
    OAT: OAuthAccessTokenModel,
    ORT: OAuthRefreshTokenModel,
](
    client_service: OAuthClientService[OC],
    token_service: OAuthTokenService[OC, OAC, OAT, ORT],
    authorization_endpoint: AuthorizationEndpoint[OC, OG, OAC] | None = None,
    *,
    get_current_subject: typing.Callable[[Request], typing.Any] | None = None,
    login_url: str = "/login",
    consent_template_func: typing.Callable[[Request, typing.Any], Response]
    | None = None,
    path: str = "/oauth",
) -> Router:
    """Create a Litestar Router for OAuth 2.1 server endpoints.

    Args:
        client_service: Service for client management.
        token_service: Service for token operations.
        authorization_endpoint: Optional authorization endpoint.
        get_current_subject: Function to get current subject from request.
        login_url: URL to redirect unauthenticated users.
        consent_template_func: Function to render consent page.
        path: Router path prefix.

    Returns:
        Litestar Router with OAuth endpoints.
    """
    # Create endpoint adapters
    token_ep = TokenEndpoint(token_service, client_service)
    introspection_ep = IntrospectionEndpoint(
        client_service=client_service, token_service=token_service
    )
    revocation_ep = RevocationEndpoint(
        client_service=client_service, token_service=token_service
    )

    # Build route handlers list
    route_handlers: list[typing.Any] = [
        _create_token_handler(token_ep),
        _create_introspect_handler(introspection_ep),
        _create_revoke_handler(revocation_ep),
    ]

    # Add authorization handlers if provided
    if authorization_endpoint:
        route_handlers.extend([
            _create_authorize_handler(
                authorization_endpoint,
                get_current_subject,
                login_url,
                consent_template_func,
            ),
            _create_authorize_consent_handler(
                authorization_endpoint, get_current_subject
            ),
        ])

    return Router(path=path, route_handlers=route_handlers)


__all__ = [
    "create_oauth_router",
    "parse_basic_auth",
]
