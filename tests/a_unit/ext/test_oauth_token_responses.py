"""Token and revocation responses: no caching, RFC 6749 §5.2 status codes."""

from __future__ import annotations

from typing import Any, cast

import pytest
from flask import Flask
from litestar import Litestar
from litestar.testing import TestClient as LitestarClient
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient as StarletteClient

from neozen.core.oauth.exceptions import (
    TokenError,
    TokenInvalidClientError,
    TokenInvalidRequestError,
)
from neozen.ext.flask.oauth import (
    _create_revoke_handler as flask_revoke,
    _create_token_handler as flask_handler,
)
from neozen.ext.litestar.oauth import (
    _create_revoke_handler as litestar_revoke,
    _create_token_handler as litestar_handler,
)
from neozen.ext.starlette.oauth import (
    _create_revoke_handler as starlette_revoke,
    _create_token_handler as starlette_handler,
)
from neozen.web.oauth import RevocationEndpoint, TokenEndpoint


class Tokens:
    def to_dict(self) -> dict[str, Any]:
        return {"access_token": "secret", "token_type": "Bearer"}


class StubTokenEndpoint:
    """Returns tokens, or raises the configured error."""

    def __init__(self, error: TokenError | None = None) -> None:
        self.error = error

    async def __call__(self, payload: dict, **_: Any) -> Tokens:
        if self.error:
            raise self.error
        return Tokens()


def _post_token(framework: str, endpoint: StubTokenEndpoint) -> Any:
    token_ep = cast("TokenEndpoint", endpoint)
    if framework == "litestar":
        app = Litestar(route_handlers=[litestar_handler(token_ep)])
        with LitestarClient(app) as client:
            return client.post("/token", data={"grant_type": "x"})
    if framework == "starlette":
        routes = [Route("/token", starlette_handler(token_ep), methods=["POST"])]
        with StarletteClient(Starlette(routes=routes)) as client:
            return client.post("/token", data={"grant_type": "x"})
    flask_app = Flask(__name__)
    flask_app.add_url_rule(
        "/token", view_func=flask_handler(token_ep), methods=["POST"]
    )
    return flask_app.test_client().post("/token", data={"grant_type": "x"})


FRAMEWORKS = ["litestar", "starlette", "flask"]


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_success_is_not_cacheable(framework: str) -> None:
    response = _post_token(framework, StubTokenEndpoint())
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_invalid_client_is_401_with_challenge(framework: str) -> None:
    response = _post_token(framework, StubTokenEndpoint(TokenInvalidClientError()))
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Basic")
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_other_errors_are_400(framework: str) -> None:
    response = _post_token(framework, StubTokenEndpoint(TokenInvalidRequestError("x")))
    assert response.status_code == 400
    assert response.headers["Cache-Control"] == "no-store"


def _post_revoke(framework: str, endpoint: StubTokenEndpoint) -> Any:
    revoke_ep = cast("RevocationEndpoint", endpoint)
    if framework == "litestar":
        app = Litestar(route_handlers=[litestar_revoke(revoke_ep)])
        with LitestarClient(app) as client:
            return client.post("/revoke", data={"token": "x"})
    if framework == "starlette":
        routes = [Route("/revoke", starlette_revoke(revoke_ep), methods=["POST"])]
        with StarletteClient(Starlette(routes=routes)) as client:
            return client.post("/revoke", data={"token": "x"})
    flask_app = Flask(__name__)
    flask_app.add_url_rule(
        "/revoke", view_func=flask_revoke(revoke_ep), methods=["POST"]
    )
    return flask_app.test_client().post("/revoke", data={"token": "x"})


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_revocation_invalid_request_is_400(framework: str) -> None:
    error = TokenInvalidRequestError("x")
    response = _post_revoke(framework, StubTokenEndpoint(error))
    assert response.status_code == 400


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_revocation_invalid_client_is_401_with_challenge(framework: str) -> None:
    response = _post_revoke(framework, StubTokenEndpoint(TokenInvalidClientError()))
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Basic")
