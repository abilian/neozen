"""Rate-limit keys must come from the peer address, not client-set headers."""

from __future__ import annotations

from typing import Any, cast

from flask import Flask
from litestar.types import HTTPScope
from starlette.requests import Request

from neozen.ext.flask.rate_limit import get_client_ip as flask_client_ip
from neozen.ext.litestar.rate_limit import get_client_ip as litestar_client_ip
from neozen.ext.starlette.rate_limit import get_client_ip as starlette_client_ip

PEER = "10.0.0.1"
SPOOFED = [(b"x-forwarded-for", b"1.2.3.4"), (b"x-real-ip", b"5.6.7.8")]


def _scope() -> dict[str, Any]:
    return {"type": "http", "client": (PEER, 5000), "headers": SPOOFED}


def test_litestar_ignores_forwarded_headers() -> None:
    assert litestar_client_ip(cast("HTTPScope", _scope())) == PEER


def test_starlette_ignores_forwarded_headers() -> None:
    assert starlette_client_ip(Request(_scope())) == PEER


def test_flask_ignores_forwarded_headers() -> None:
    app = Flask(__name__)
    headers = {k.decode(): v.decode() for k, v in SPOOFED}
    with app.test_request_context(headers=headers, environ_base={"REMOTE_ADDR": PEER}):
        assert flask_client_ip() == PEER
