"""Starlette OAuth 2.1 Server Routes.

Provides OAuth 2.1 server endpoints for Starlette applications.

Example:
    from starlette.applications import Starlette
    from starlette.routing import Mount
    from neozen.ext.starlette.oauth import create_oauth_routes

    oauth_routes = create_oauth_routes(
        client_service=client_service,
        token_service=token_service,
        authorization_endpoint=auth_endpoint,
    )
    app = Starlette(routes=[
        Mount("/oauth", routes=oauth_routes),
        ...
    ])
"""

from __future__ import annotations

import typing

from starlette.datastructures import ImmutableMultiDict
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

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
    AuthorizationEndpoint,
    IntrospectionEndpoint,
    RevocationEndpoint,
    TokenEndpoint,
    parse_basic_auth,
)


def _get_client_credentials(
    request: Request, form: ImmutableMultiDict
) -> tuple[str | None, str | None]:
    """Extract client credentials from request (header or form)."""
    client_id, client_secret = parse_basic_auth(request.headers.get("Authorization"))
    if not client_id:
        client_id = typing.cast(str | None, form.get("client_id"))
        client_secret = typing.cast(str | None, form.get("client_secret"))
    return client_id, client_secret


def _error_response(
    error: str, description: str | None, status_code: int
) -> JSONResponse:
    """Create an OAuth error response."""
    return JSONResponse(
        {"error": error, "error_description": description}, status_code=status_code
    )


def _create_token_handler(token_ep: TokenEndpoint) -> typing.Callable:
    """Create the token endpoint handler."""

    async def token_handler(request: Request) -> Response:
        """OAuth 2.1 Token Endpoint."""
        form = await request.form()
        client_id, client_secret = _get_client_credentials(request, form)
        try:
            response = await token_ep(
                dict(form), client_id=client_id, client_secret=client_secret
            )
            return JSONResponse(response.to_dict())
        except TokenError as e:
            return _error_response(e.error, e.error_description, 400)

    return token_handler


def _create_introspect_handler(
    introspection_ep: IntrospectionEndpoint,
) -> typing.Callable:
    """Create the introspection endpoint handler."""

    async def introspect_handler(request: Request) -> Response:
        """OAuth 2.1 Token Introspection Endpoint (RFC 7662)."""
        form = await request.form()
        client_id, client_secret = _get_client_credentials(request, form)
        try:
            response = await introspection_ep(
                dict(form), client_id=client_id, client_secret=client_secret
            )
            return JSONResponse(response.to_dict())
        except TokenError as e:
            return _error_response(e.error, e.error_description, 401)

    return introspect_handler


def _create_revoke_handler(revocation_ep: RevocationEndpoint) -> typing.Callable:
    """Create the revocation endpoint handler."""

    async def revoke_handler(request: Request) -> Response:
        """OAuth 2.1 Token Revocation Endpoint (RFC 7009)."""
        form = await request.form()
        client_id, client_secret = _get_client_credentials(request, form)
        try:
            await revocation_ep(
                dict(form), client_id=client_id, client_secret=client_secret
            )
            return Response(status_code=200)
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

    async def authorize_handler(request: Request) -> Response:
        """OAuth 2.1 Authorization Endpoint."""
        subject = get_current_subject(request) if get_current_subject else None
        payload = dict(request.query_params)
        response = await authorization_endpoint.handle_authorization_request(
            payload, subject
        )

        if response.requires_login:
            request.session["oauth_params"] = payload
            return RedirectResponse(login_url, status_code=302)

        if response.requires_consent:
            if consent_template_func:
                return consent_template_func(request, response.consent_data)
            return JSONResponse({
                "error": "consent_required",
                "consent_data": response.consent_data,
            })

        if response.error:
            redirect_url = response.get_redirect_url()
            if redirect_url:
                return RedirectResponse(redirect_url, status_code=302)
            return _error_response(response.error, response.error_description, 400)

        redirect_url = response.get_redirect_url()
        if redirect_url:
            return RedirectResponse(redirect_url, status_code=302)
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    return authorize_handler


def _create_authorize_consent_handler(
    authorization_endpoint: AuthorizationEndpoint,
    get_current_subject: typing.Callable[[Request], typing.Any] | None,
) -> typing.Callable:
    """Create the authorization consent POST handler."""

    async def authorize_consent_handler(request: Request) -> Response:
        """Handle consent form submission."""
        subject = get_current_subject(request) if get_current_subject else None
        if not subject:
            return JSONResponse({"error": "Not authenticated"}, status_code=401)

        form = await request.form()
        response = await authorization_endpoint.handle_consent(dict(form), subject)

        redirect_url = response.get_redirect_url()
        if redirect_url:
            return RedirectResponse(redirect_url, status_code=302)

        return _error_response(
            response.error or "unknown_error", response.error_description, 400
        )

    return authorize_consent_handler


def create_oauth_routes[
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
) -> list[Route]:
    """Create Starlette routes for OAuth 2.1 server endpoints.

    Args:
        client_service: Service for client management.
        token_service: Service for token operations.
        authorization_endpoint: Optional authorization endpoint.
        get_current_subject: Function to get current subject from request.
        login_url: URL to redirect unauthenticated users.
        consent_template_func: Function to render consent page.

    Returns:
        List of Starlette Route objects.
    """
    # Create endpoint adapters
    token_ep = TokenEndpoint(token_service)
    introspection_ep = IntrospectionEndpoint(
        client_service=client_service, token_service=token_service
    )
    revocation_ep = RevocationEndpoint(
        client_service=client_service, token_service=token_service
    )

    # Build routes list
    routes = [
        Route("/token", _create_token_handler(token_ep), methods=["POST"]),
        Route(
            "/introspect",
            _create_introspect_handler(introspection_ep),
            methods=["POST"],
        ),
        Route("/revoke", _create_revoke_handler(revocation_ep), methods=["POST"]),
    ]

    # Add authorization routes if provided
    if authorization_endpoint:
        routes.extend([
            Route(
                "/authorize",
                _create_authorize_handler(
                    authorization_endpoint,
                    get_current_subject,
                    login_url,
                    consent_template_func,
                ),
                methods=["GET"],
            ),
            Route(
                "/authorize",
                _create_authorize_consent_handler(
                    authorization_endpoint, get_current_subject
                ),
                methods=["POST"],
            ),
        ])

    return routes


__all__ = [
    "create_oauth_routes",
    "parse_basic_auth",
]
