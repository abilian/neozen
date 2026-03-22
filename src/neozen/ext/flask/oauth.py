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

import base64
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

# Flask route return type - includes all valid Flask return types
ResponseValue = (
    Response | WerkzeugResponse | tuple[Response, int] | tuple[str, int] | str
)

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

    # Create token endpoint adapter
    token_ep = TokenEndpoint(token_service)

    # Create introspection endpoint
    introspection_ep = IntrospectionEndpoint(
        client_service=client_service,
        token_service=token_service,
    )

    # Create revocation endpoint
    revocation_ep = RevocationEndpoint(
        client_service=client_service,
        token_service=token_service,
    )

    @bp.route("/token", methods=["POST"])
    async def token() -> ResponseValue:
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

        # Fall back to POST body
        if not client_id:
            client_id = request.form.get("client_id")
            client_secret = request.form.get("client_secret")

        try:
            payload = dict(request.form)
            response = await token_ep(
                payload,
                client_id=client_id,
                client_secret=client_secret,
            )
            return jsonify(response.to_dict())
        except TokenError as e:
            return jsonify({
                "error": e.error,
                "error_description": e.error_description,
            }), 400

    @bp.route("/introspect", methods=["POST"])
    async def introspect() -> ResponseValue:
        """OAuth 2.1 Token Introspection Endpoint (RFC 7662).

        POST /oauth/introspect

        Requires client authentication.
        """
        client_id, client_secret = parse_basic_auth(
            request.headers.get("Authorization")
        )

        if not client_id:
            client_id = request.form.get("client_id")
            client_secret = request.form.get("client_secret")

        try:
            payload = dict(request.form)
            response = await introspection_ep(
                payload,
                client_id=client_id,
                client_secret=client_secret,
            )
            return jsonify(response.to_dict())
        except TokenError as e:
            return jsonify({
                "error": e.error,
                "error_description": e.error_description,
            }), 401

    @bp.route("/revoke", methods=["POST"])
    async def revoke() -> ResponseValue:
        """OAuth 2.1 Token Revocation Endpoint (RFC 7009).

        POST /oauth/revoke

        Requires client authentication. Always returns 200 OK.
        """
        client_id, client_secret = parse_basic_auth(
            request.headers.get("Authorization")
        )

        if not client_id:
            client_id = request.form.get("client_id")
            client_secret = request.form.get("client_secret")

        try:
            payload = dict(request.form)
            await revocation_ep(
                payload,
                client_id=client_id,
                client_secret=client_secret,
            )
            return "", 200
        except TokenError as e:
            return jsonify({
                "error": e.error,
                "error_description": e.error_description,
            }), 401

    if authorization_endpoint:

        @bp.route("/authorize", methods=["GET"])
        async def authorize() -> ResponseValue:
            """OAuth 2.1 Authorization Endpoint.

            GET /oauth/authorize

            Initiates the authorization code flow.
            """
            # Get current subject
            subject = None
            if get_current_subject:
                subject = get_current_subject()

            payload = dict(request.args)
            response = await authorization_endpoint.handle_authorization_request(
                payload, subject
            )

            if response.requires_login:
                # Store OAuth parameters in session for after login
                session["oauth_params"] = payload
                return redirect(login_url)

            if response.requires_consent:
                # Render consent page
                return render_template(
                    consent_template,
                    consent_data=response.consent_data,
                )

            if response.error:
                redirect_url = response.get_redirect_url()
                if redirect_url:
                    return redirect(redirect_url)
                return jsonify({
                    "error": response.error,
                    "error_description": response.error_description,
                }), 400

            # Success - redirect with code
            redirect_url = response.get_redirect_url()
            if redirect_url:
                return redirect(redirect_url)
            return jsonify({"error": "invalid_request"}), 400

        @bp.route("/authorize", methods=["POST"])
        async def authorize_consent() -> ResponseValue:
            """Handle consent form submission."""
            subject = None
            if get_current_subject:
                subject = get_current_subject()

            if not subject:
                return jsonify({"error": "Not authenticated"}), 401

            payload = dict(request.form)
            response = await authorization_endpoint.handle_consent(payload, subject)

            redirect_url = response.get_redirect_url()
            if redirect_url:
                return redirect(redirect_url)

            return jsonify({
                "error": response.error or "unknown_error",
                "error_description": response.error_description,
            }), 400

    return bp


__all__ = [
    "create_oauth_blueprint",
    "parse_basic_auth",
]
