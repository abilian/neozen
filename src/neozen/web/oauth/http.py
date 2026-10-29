"""The OAuth endpoints, from request to reply, for every framework adapter.

Token, introspection and revocation take the request's form and
``Authorization`` header and return an `HttpReply`. The authorization
endpoint's answer becomes an `AuthorizeOutcome`. The framework adapters
only turn these into their own response types.
"""

from __future__ import annotations

import dataclasses
import inspect
import typing
from dataclasses import dataclass, field

from neozen.core.oauth.exceptions import TokenError
from neozen.web.auth.responses import unauthorized_body
from neozen.web.oauth.utils import (
    NO_STORE_HEADERS,
    parse_basic_auth,
    token_error_headers,
    token_error_status,
)

if typing.TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from neozen.web.oauth.authorization_endpoint import (
        AuthorizationResponse,
        ConsentData,
    )
    from neozen.web.oauth.introspection_endpoint import IntrospectionEndpoint
    from neozen.web.oauth.revocation_endpoint import RevocationEndpoint
    from neozen.web.oauth.token_endpoint import TokenEndpoint


@dataclass(frozen=True)
class HttpReply:
    """Status, JSON body (None for an empty body) and headers."""

    status: int
    body: dict[str, typing.Any] | None
    headers: dict[str, str] = field(default_factory=dict)


def client_credentials(
    authorization: str | None, form: Mapping[str, typing.Any]
) -> tuple[str | None, str | None]:
    """Client ID and secret, from Basic auth or else from the form."""
    client_id, client_secret = parse_basic_auth(authorization)
    if client_id:
        return client_id, client_secret
    return form.get("client_id"), form.get("client_secret")


def _error_reply(e: TokenError) -> HttpReply:
    return HttpReply(
        status=token_error_status(e.error),
        body={"error": e.error, "error_description": e.error_description},
        headers=token_error_headers(e.error),
    )


async def token_reply(
    endpoint: TokenEndpoint, form: Mapping[str, typing.Any], authorization: str | None
) -> HttpReply:
    """Token endpoint (RFC 6749 §3.2); responses are never cached."""
    client_id, client_secret = client_credentials(authorization, form)
    try:
        response = await endpoint(
            dict(form), client_id=client_id, client_secret=client_secret
        )
    except TokenError as e:
        return _error_reply(e)
    return HttpReply(200, response.to_dict(), NO_STORE_HEADERS)


async def introspection_reply(
    endpoint: IntrospectionEndpoint,
    form: Mapping[str, typing.Any],
    authorization: str | None,
) -> HttpReply:
    """Introspection endpoint (RFC 7662)."""
    client_id, client_secret = client_credentials(authorization, form)
    try:
        response = await endpoint(
            dict(form), client_id=client_id, client_secret=client_secret
        )
    except TokenError as e:
        return _error_reply(e)
    return HttpReply(200, response.to_dict(), NO_STORE_HEADERS)


async def revocation_reply(
    endpoint: RevocationEndpoint,
    form: Mapping[str, typing.Any],
    authorization: str | None,
) -> HttpReply:
    """Revocation endpoint (RFC 7009): an empty 200 unless the request fails."""
    client_id, client_secret = client_credentials(authorization, form)
    try:
        await endpoint(dict(form), client_id=client_id, client_secret=client_secret)
    except TokenError as e:
        return _error_reply(e)
    return HttpReply(200, None)


@dataclass(frozen=True)
class LoginNeeded:
    """Send the visitor to sign in, then back to the authorization request."""


@dataclass(frozen=True)
class ConsentNeeded:
    """Show the consent page for ``data``."""

    data: ConsentData


# A redirect URL, or one of the two pages, or an error to show.
type AuthorizeOutcome = str | LoginNeeded | ConsentNeeded | HttpReply


def authorize_outcome(response: AuthorizationResponse) -> AuthorizeOutcome:
    """What an adapter does with the authorization endpoint's answer."""
    if response.requires_login:
        return LoginNeeded()
    if response.requires_consent and response.consent_data is not None:
        return ConsentNeeded(response.consent_data)
    if url := response.get_redirect_url():
        return url
    # An error the client can't be told about: its redirect URI is unknown.
    return HttpReply(
        400,
        {
            "error": response.error or "invalid_request",
            "error_description": response.error_description,
        },
    )


def consent_page_missing(data: ConsentData) -> HttpReply:
    """The answer when the app has no consent page: the data, as JSON."""
    return HttpReply(
        403, {"error": "consent_required", "consent_data": dataclasses.asdict(data)}
    )


async def current_subject(
    get_current_subject: Callable[..., typing.Any] | None, *args: typing.Any
) -> typing.Any:
    """The app's signed-in subject; its getter may be sync or async."""
    if get_current_subject is None:
        return None
    subject = get_current_subject(*args)
    return await subject if inspect.isawaitable(subject) else subject


NOT_SIGNED_IN = HttpReply(401, unauthorized_body())


__all__ = [
    "NOT_SIGNED_IN",
    "AuthorizeOutcome",
    "ConsentNeeded",
    "HttpReply",
    "LoginNeeded",
    "authorize_outcome",
    "client_credentials",
    "consent_page_missing",
    "current_subject",
    "introspection_reply",
    "revocation_reply",
    "token_reply",
]
