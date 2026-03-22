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

import base64
import typing

from litestar import Request, Response, Router, get, post
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
    AuthorizationEndpoint,
    IntrospectionEndpoint,
    RevocationEndpoint,
    TokenEndpoint,
)


def parse_basic_auth(header: str | None) -> tuple[str | None, str | None]:
    """Parse Basic auth header to get client_id and client_secret."""
    if not header or not header.startswith("Basic "):
        return None, None

    try:
        encoded = header[6:]
        decoded = base64.b64decode(encoded).decode("utf-8")
        client_id, client_secret = decoded.split(":", 1)
        return client_id, client_secret
    except (ValueError, UnicodeDecodeError):
        return None, None


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
    token_ep = TokenEndpoint(token_service)
    introspection_ep = IntrospectionEndpoint(
        client_service=client_service,
        token_service=token_service,
    )
    revocation_ep = RevocationEndpoint(
        client_service=client_service,
        token_service=token_service,
    )

    @post("/token", sync_to_thread=False)
    async def token_handler(request: Request) -> Response:
        """OAuth 2.1 Token Endpoint.

        POST /oauth/token

        Supports:
        - authorization_code grant
        - refresh_token grant
        """
        # Get client credentials from Basic auth or POST body
        client_id, client_secret = parse_basic_auth(
            request.headers.get("Authorization")
        )

        # Get form data
        form = await request.form()
        payload = dict(form)

        # Fall back to POST body
        if not client_id:
            client_id = typing.cast(str | None, form.get("client_id"))
            client_secret = typing.cast(str | None, form.get("client_secret"))

        try:
            response = await token_ep(
                payload,
                client_id=client_id,
                client_secret=client_secret,
            )
            return Response(content=response.to_dict(), media_type="application/json")
        except TokenError as e:
            return Response(
                content={
                    "error": e.error,
                    "error_description": e.error_description,
                },
                status_code=400,
                media_type="application/json",
            )

    @post("/introspect", sync_to_thread=False)
    async def introspect_handler(request: Request) -> Response:
        """OAuth 2.1 Token Introspection Endpoint (RFC 7662).

        POST /oauth/introspect

        Requires client authentication.
        """
        client_id, client_secret = parse_basic_auth(
            request.headers.get("Authorization")
        )

        form = await request.form()
        payload = dict(form)

        if not client_id:
            client_id = typing.cast(str | None, form.get("client_id"))
            client_secret = typing.cast(str | None, form.get("client_secret"))

        try:
            response = await introspection_ep(
                payload,
                client_id=client_id,
                client_secret=client_secret,
            )
            return Response(content=response.to_dict(), media_type="application/json")
        except TokenError as e:
            return Response(
                content={
                    "error": e.error,
                    "error_description": e.error_description,
                },
                status_code=401,
                media_type="application/json",
            )

    @post("/revoke", sync_to_thread=False)
    async def revoke_handler(request: Request) -> Response:
        """OAuth 2.1 Token Revocation Endpoint (RFC 7009).

        POST /oauth/revoke

        Requires client authentication. Always returns 200 OK.
        """
        client_id, client_secret = parse_basic_auth(
            request.headers.get("Authorization")
        )

        form = await request.form()
        payload = dict(form)

        if not client_id:
            client_id = typing.cast(str | None, form.get("client_id"))
            client_secret = typing.cast(str | None, form.get("client_secret"))

        try:
            await revocation_ep(
                payload,
                client_id=client_id,
                client_secret=client_secret,
            )
            return Response(content=None, status_code=200)
        except TokenError as e:
            return Response(
                content={
                    "error": e.error,
                    "error_description": e.error_description,
                },
                status_code=401,
                media_type="application/json",
            )

    route_handlers: list[typing.Any] = [
        token_handler,
        introspect_handler,
        revoke_handler,
    ]

    if authorization_endpoint:

        @get("/authorize", sync_to_thread=False)
        async def authorize_handler(request: Request) -> Response:
            """OAuth 2.1 Authorization Endpoint.

            GET /oauth/authorize

            Initiates the authorization code flow.
            """
            # Get current subject
            subject = None
            if get_current_subject:
                subject = get_current_subject(request)

            payload = dict(request.query_params)
            response = await authorization_endpoint.handle_authorization_request(
                payload, subject
            )

            if response.requires_login:
                # Store OAuth parameters in session for after login
                request.session["oauth_params"] = payload
                return Redirect(path=login_url)

            if response.requires_consent:
                # Render consent page
                if consent_template_func:
                    return consent_template_func(request, response.consent_data)
                return Response(
                    content={
                        "error": "consent_required",
                        "consent_data": response.consent_data,
                    },
                    status_code=200,
                    media_type="application/json",
                )

            if response.error:
                redirect_url = response.get_redirect_url()
                if redirect_url:
                    return Redirect(path=redirect_url)
                return Response(
                    content={
                        "error": response.error,
                        "error_description": response.error_description,
                    },
                    status_code=400,
                    media_type="application/json",
                )

            # Success - redirect with code
            redirect_url = response.get_redirect_url()
            if redirect_url:
                return Redirect(path=redirect_url)
            return Response(
                content={"error": "invalid_request"},
                status_code=400,
                media_type="application/json",
            )

        @post("/authorize", sync_to_thread=False)
        async def authorize_consent_handler(request: Request) -> Response:
            """Handle consent form submission."""
            subject = None
            if get_current_subject:
                subject = get_current_subject(request)

            if not subject:
                return Response(
                    content={"error": "Not authenticated"},
                    status_code=401,
                    media_type="application/json",
                )

            form = await request.form()
            payload = dict(form)
            response = await authorization_endpoint.handle_consent(payload, subject)

            redirect_url = response.get_redirect_url()
            if redirect_url:
                return Redirect(path=redirect_url)

            return Response(
                content={
                    "error": response.error or "unknown_error",
                    "error_description": response.error_description,
                },
                status_code=400,
                media_type="application/json",
            )

        route_handlers.extend([
            authorize_handler,
            authorize_consent_handler,
        ])

    return Router(path=path, route_handlers=route_handlers)


__all__ = [
    "create_oauth_router",
    "parse_basic_auth",
]
