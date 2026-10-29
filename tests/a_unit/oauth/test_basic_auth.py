"""Client credentials from the Authorization header (RFC 6749 §2.3.1)."""

from __future__ import annotations

import base64

from neozen.web.oauth import parse_basic_auth


def _basic(credentials: str) -> str:
    return "Basic " + base64.b64encode(credentials.encode()).decode()


def test_credentials_are_form_decoded() -> None:
    assert parse_basic_auth(_basic("my%3Aclient:s%2Bcret+x")) == (
        "my:client",
        "s+cret x",
    )


def test_malformed_header_gives_no_credentials() -> None:
    assert parse_basic_auth("Basic !!!") == (None, None)
