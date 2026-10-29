"""The token, introspection and revocation endpoints, from form to reply.

Each function takes the request's form and ``Authorization`` header and
returns what to send back. The framework adapters only turn an
`HttpReply` into their own response type.
"""

from __future__ import annotations

import typing
from dataclasses import dataclass, field

from neozen.core.oauth.exceptions import TokenError
from neozen.web.oauth.utils import (
    NO_STORE_HEADERS,
    parse_basic_auth,
    token_error_headers,
    token_error_status,
)

if typing.TYPE_CHECKING:
    from collections.abc import Mapping

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
    return HttpReply(200, response.to_dict())


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


__all__ = [
    "HttpReply",
    "client_credentials",
    "introspection_reply",
    "revocation_reply",
    "token_reply",
]
