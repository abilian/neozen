"""Flask OAuth 2.1 Server Blueprint.

Provides OAuth 2.1 server endpoints for Flask applications.

Example:
    from flask import Flask
    from neozen.ext.flask.oauth import create_oauth_blueprint

    app = Flask(__name__)

    oauth = create_oauth_blueprint(
        client_service=client_service,
        token_service=token_service,
        authorization_endpoint=auth_endpoint,
    )
    app.register_blueprint(oauth, url_prefix="/oauth")
"""

from __future__ import annotations

import typing

from flask import (
    Blueprint,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
)
from werkzeug.wrappers import Response as WerkzeugResponse

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
    current_subject,
    introspection_reply,
    revocation_reply,
    token_reply,
)
from neozen.web.oidc import DiscoveryEndpoint, JWKSEndpoint

# Flask route return type - includes all valid Flask return types
ResponseValue = (
    Response | WerkzeugResponse | tuple[Response, int] | tuple[str, int] | str
)


def _response(reply: HttpReply) -> Response:
    response = jsonify(reply.body) if reply.body is not None else Response()
    response.status_code = reply.status
    response.headers.update(reply.headers)
    return response


def _create_token_handler(token_ep: TokenEndpoint) -> typing.Callable:
    """Create the token endpoint handler."""

    async def token() -> ResponseValue:
        """OAuth 2.1 Token Endpoint."""
        auth = request.headers.get("Authorization")
        return _response(await token_reply(token_ep, request.form, auth))

    return token


def _create_introspect_handler(
    introspection_ep: IntrospectionEndpoint,
) -> typing.Callable:
    """Create the introspection endpoint handler."""

    async def introspect() -> ResponseValue:
        """OAuth 2.1 Token Introspection Endpoint (RFC 7662)."""
        auth = request.headers.get("Authorization")
        return _response(
            await introspection_reply(introspection_ep, request.form, auth)
        )

    return introspect


def _create_revoke_handler(revocation_ep: RevocationEndpoint) -> typing.Callable:
    """Create the revocation endpoint handler."""

    async def revoke() -> ResponseValue:
        """OAuth 2.1 Token Revocation Endpoint (RFC 7009)."""
        auth = request.headers.get("Authorization")
        return _response(await revocation_reply(revocation_ep, request.form, auth))

    return revoke


def _create_authorize_handler(
    authorization_endpoint: AuthorizationEndpoint,
    get_current_subject: typing.Callable[[], typing.Any] | None,
    login_url: str,
    consent_template: str,
) -> typing.Callable:
    """Create the authorization endpoint GET handler."""

    async def authorize() -> ResponseValue:
        """OAuth 2.1 Authorization Endpoint."""
        payload = dict(request.args)
        response = await authorization_endpoint.handle_authorization_request(
            payload, await current_subject(get_current_subject)
        )
        outcome = authorize_outcome(response)
        if isinstance(outcome, LoginNeeded):
            session["oauth_params"] = payload
            return redirect(login_url)
        if isinstance(outcome, ConsentNeeded):
            return render_template(consent_template, consent_data=outcome.data)
        if isinstance(outcome, str):
            return redirect(outcome)
        return _response(outcome)

    return authorize


def _create_authorize_consent_handler(
    authorization_endpoint: AuthorizationEndpoint,
    get_current_subject: typing.Callable[[], typing.Any] | None,
) -> typing.Callable:
    """Create the authorization consent POST handler."""

    async def authorize_consent() -> ResponseValue:
        """Handle consent form submission (CSRF-checked by its consent_token)."""
        subject = await current_subject(get_current_subject)
        if not subject:
            return _response(NOT_SIGNED_IN)
        response = await authorization_endpoint.handle_consent(
            dict(request.form), subject
        )
        match authorize_outcome(response):
            case str(url):
                return redirect(url)
            case HttpReply() as reply:
                return _response(reply)
            case _:  # handle_consent neither asks to sign in nor for consent
                return _response(NOT_SIGNED_IN)

    return authorize_consent


def create_oauth_blueprint[
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
    get_current_subject: typing.Callable[[], typing.Any] | None = None,
    login_url: str = "/login",
    consent_template: str = "oauth/consent.html",
) -> Blueprint:
    """Create a Flask Blueprint with OAuth 2.1 server endpoints.

    Args:
        client_service: Service for client management.
        token_service: Service for token operations.
        authorization_endpoint: Optional authorization endpoint.
        get_current_subject: Function to get the current authenticated subject.
        login_url: URL to redirect unauthenticated users.
        consent_template: Template for the consent page.

    Returns:
        Flask Blueprint with OAuth endpoints.
    """
    bp = Blueprint("oauth", __name__)

    # Create endpoint adapters
    token_ep = TokenEndpoint(token_service, client_service)
    introspection_ep = IntrospectionEndpoint(
        client_service=client_service, token_service=token_service
    )
    revocation_ep = RevocationEndpoint(
        client_service=client_service, token_service=token_service
    )

    # Register core endpoints
    bp.route("/token", methods=["POST"])(_create_token_handler(token_ep))
    bp.route("/introspect", methods=["POST"])(
        _create_introspect_handler(introspection_ep)
    )
    bp.route("/revoke", methods=["POST"])(_create_revoke_handler(revocation_ep))

    # Register authorization endpoints if provided
    if authorization_endpoint:
        bp.route("/authorize", methods=["GET"])(
            _create_authorize_handler(
                authorization_endpoint, get_current_subject, login_url, consent_template
            )
        )
        bp.route("/authorize", methods=["POST"])(
            _create_authorize_consent_handler(
                authorization_endpoint, get_current_subject
            )
        )

    return bp


def create_oidc_blueprint(
    discovery: DiscoveryEndpoint, jwks: JWKSEndpoint
) -> Blueprint:
    """Serve the OIDC discovery document and the JWKS under ``/.well-known``.

    Resource servers verify ID tokens and JWT access tokens against the
    JWKS, so mount this wherever the token endpoint is mounted.
    """
    bp = Blueprint("oidc", __name__, url_prefix="/.well-known")

    @bp.get("/openid-configuration")
    async def openid_configuration() -> ResponseValue:
        return jsonify(await discovery())

    @bp.get("/jwks.json")
    async def jwks_json() -> ResponseValue:
        return jsonify(await jwks())

    return bp


__all__ = [
    "create_oauth_blueprint",
    "create_oidc_blueprint",
    "parse_basic_auth",
]
