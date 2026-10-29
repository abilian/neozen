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
from litestar.response import Redirect

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
    HttpReply,
    introspection_reply,
    revocation_reply,
    token_reply,
)
from neozen.web.oidc import DiscoveryEndpoint, JWKSEndpoint


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


def _response(reply: HttpReply) -> Response:
    if reply.body is None:
        return Response(content=None, status_code=reply.status, headers=reply.headers)
    response = _json_response(reply.body, reply.status)
    response.headers.update(reply.headers)
    return response


def _create_token_handler(token_ep: TokenEndpoint) -> typing.Callable:
    """Create the token endpoint handler."""

    @post("/token")
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

    @post("/introspect")
    async def introspect_handler(request: Request) -> Response:
        """OAuth 2.1 Token Introspection Endpoint (RFC 7662)."""
        form = await request.form()
        auth = request.headers.get("Authorization")
        return _response(await introspection_reply(introspection_ep, form, auth))

    return introspect_handler


def _create_revoke_handler(revocation_ep: RevocationEndpoint) -> typing.Callable:
    """Create the revocation endpoint handler."""

    @post("/revoke")
    async def revoke_handler(request: Request) -> Response:
        """OAuth 2.1 Token Revocation Endpoint (RFC 7009)."""
        form = await request.form()
        auth = request.headers.get("Authorization")
        return _response(await revocation_reply(revocation_ep, form, auth))

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
            return _json_response(
                {
                    "error": "consent_required",
                    "consent_data": response.consent_data,
                },
                403,
            )

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


def create_oidc_router(discovery: DiscoveryEndpoint, jwks: JWKSEndpoint) -> Router:
    """Serve the OIDC discovery document and the JWKS under ``/.well-known``.

    Resource servers verify ID tokens and JWT access tokens against the
    JWKS, so mount this wherever the token endpoint is mounted.
    """

    @get("/openid-configuration")
    async def discovery_handler() -> Response:
        return _json_response(await discovery())

    @get("/jwks.json")
    async def jwks_handler() -> Response:
        return _json_response(await jwks())

    return Router(path="/.well-known", route_handlers=[discovery_handler, jwks_handler])


__all__ = [
    "create_oauth_router",
    "create_oidc_router",
    "parse_basic_auth",
]
