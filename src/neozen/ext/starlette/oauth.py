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

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from neozen.core.oauth.client_service import OAuthClientService
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
from neozen.web.oauth.http import (
    NOT_SIGNED_IN,
    ConsentNeeded,
    HttpReply,
    LoginNeeded,
    authorize_outcome,
    consent_page_missing,
    current_subject,
    introspection_reply,
    revocation_reply,
    token_reply,
)
from neozen.web.oidc import DiscoveryEndpoint, JWKSEndpoint

# The app's signed-in subject, from the request; sync or async.
type SubjectGetter = typing.Callable[[Request], typing.Any]


def _error_response(
    error: str, description: str | None, status_code: int
) -> JSONResponse:
    """Create an OAuth error response."""
    return JSONResponse(
        {"error": error, "error_description": description}, status_code=status_code
    )


def _response(reply: HttpReply) -> Response:
    if reply.body is None:
        return Response(status_code=reply.status, headers=reply.headers)
    return JSONResponse(reply.body, status_code=reply.status, headers=reply.headers)


def _create_token_handler(token_ep: TokenEndpoint) -> typing.Callable:
    """Create the token endpoint handler."""

    async def token_handler(request: Request) -> Response:
        """OAuth 2.1 Token Endpoint."""
        form = await request.form()
        auth = request.headers.get("Authorization")
        return _response(await token_reply(token_ep, form, auth))

    return token_handler


def _create_introspect_handler(
    introspection_ep: IntrospectionEndpoint,
) -> typing.Callable:
    """Create the introspection endpoint handler."""

    async def introspect_handler(request: Request) -> Response:
        """OAuth 2.1 Token Introspection Endpoint (RFC 7662)."""
        form = await request.form()
        auth = request.headers.get("Authorization")
        return _response(await introspection_reply(introspection_ep, form, auth))

    return introspect_handler


def _create_revoke_handler(revocation_ep: RevocationEndpoint) -> typing.Callable:
    """Create the revocation endpoint handler."""

    async def revoke_handler(request: Request) -> Response:
        """OAuth 2.1 Token Revocation Endpoint (RFC 7009)."""
        form = await request.form()
        auth = request.headers.get("Authorization")
        return _response(await revocation_reply(revocation_ep, form, auth))

    return revoke_handler


def _create_authorize_handler(
    authorization_endpoint: AuthorizationEndpoint,
    get_current_subject: SubjectGetter | None,
    login_url: str,
    consent_template_func: typing.Callable[[Request, typing.Any], Response] | None,
) -> typing.Callable:
    """Create the authorization endpoint GET handler."""

    async def authorize_handler(request: Request) -> Response:
        """OAuth 2.1 Authorization Endpoint."""
        payload = dict(request.query_params)
        response = await authorization_endpoint.handle_authorization_request(
            payload, await current_subject(get_current_subject, request)
        )
        outcome = authorize_outcome(response)
        if isinstance(outcome, LoginNeeded):
            request.session["oauth_params"] = payload
            return RedirectResponse(login_url, status_code=302)
        if isinstance(outcome, ConsentNeeded):
            if consent_template_func:
                return consent_template_func(request, outcome.data)
            return _response(consent_page_missing(outcome.data))
        if isinstance(outcome, str):
            return RedirectResponse(outcome, status_code=302)
        return _response(outcome)

    return authorize_handler


def _create_authorize_consent_handler(
    authorization_endpoint: AuthorizationEndpoint,
    get_current_subject: SubjectGetter | None,
) -> typing.Callable:
    """Create the authorization consent POST handler."""

    async def authorize_consent_handler(request: Request) -> Response:
        """Handle consent form submission (CSRF-checked by its consent_token)."""
        subject = await current_subject(get_current_subject, request)
        if not subject:
            return _response(NOT_SIGNED_IN)
        form = await request.form()
        response = await authorization_endpoint.handle_consent(dict(form), subject)
        match authorize_outcome(response):
            case str(url):
                return RedirectResponse(url, status_code=302)
            case HttpReply() as reply:
                return _response(reply)
            case _:  # handle_consent neither asks to sign in nor for consent
                return _response(NOT_SIGNED_IN)

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
    get_current_subject: SubjectGetter | None = None,
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
    token_ep = TokenEndpoint(token_service, client_service)
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


def create_oidc_routes(discovery: DiscoveryEndpoint, jwks: JWKSEndpoint) -> list[Route]:
    """Serve the OIDC discovery document and the JWKS under ``/.well-known``.

    Resource servers verify ID tokens and JWT access tokens against the
    JWKS, so mount this wherever the token endpoint is mounted.
    """

    async def discovery_handler(request: Request) -> Response:
        return JSONResponse(await discovery())

    async def jwks_handler(request: Request) -> Response:
        return JSONResponse(await jwks())

    return [
        Route("/.well-known/openid-configuration", discovery_handler, methods=["GET"]),
        Route("/.well-known/jwks.json", jwks_handler, methods=["GET"]),
    ]


__all__ = [
    "create_oauth_routes",
    "create_oidc_routes",
    "parse_basic_auth",
]
