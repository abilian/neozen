"""The adapters serve discovery and JWKS, enough to verify JWT access tokens."""

from __future__ import annotations

import typing

import anyio
import jwt
import pytest
from flask import Flask
from litestar import Litestar
from litestar.testing import TestClient as LitestarClient
from starlette.applications import Starlette
from starlette.testclient import TestClient as StarletteClient

from neozen.config import NeoZenConfig, NeoZenFactory, OAuthServerConfig, SecurityConfig
from neozen.ext.flask.oauth import create_oidc_blueprint
from neozen.ext.litestar.oauth import create_oidc_router
from neozen.ext.starlette.oauth import create_oidc_routes
from neozen.web.oidc import DiscoveryEndpoint, JWKSEndpoint
from tests.a_unit.oauth.stubs import (
    MockOAuthAccessToken,
    MockOAuthAuthorizationCode,
    MockOAuthClient,
    MockOAuthRefreshToken,
)
from tests.conftest import MockStorage

ISSUER = "https://auth.test"
AUDIENCE = "https://api.test"
FRAMEWORKS = ["litestar", "starlette", "flask"]


@pytest.fixture
def factory() -> NeoZenFactory:
    return NeoZenFactory(
        NeoZenConfig(
            security=SecurityConfig(secret_key="s" * 32),
            oauth_server=OAuthServerConfig(
                enabled=True,
                issuer=ISSUER,
                jwt_access_tokens=True,
                jwt_audience=AUDIENCE,
                jwt_algorithm="ES256",
            ),
        )
    )


def _get(framework: str, factory: NeoZenFactory, path: str) -> dict[str, typing.Any]:
    discovery = DiscoveryEndpoint(factory.create_discovery_metadata(ISSUER))
    jwks = JWKSEndpoint(factory.key_manager)
    if framework == "litestar":
        app = Litestar(route_handlers=[create_oidc_router(discovery, jwks)])
        with LitestarClient(app) as client:
            return client.get(path).json()
    if framework == "starlette":
        starlette = Starlette(routes=create_oidc_routes(discovery, jwks))
        with StarletteClient(starlette) as client:
            return client.get(path).json()
    flask_app = Flask(__name__)
    flask_app.register_blueprint(create_oidc_blueprint(discovery, jwks))
    response = flask_app.test_client().get(path)
    return typing.cast("dict[str, typing.Any]", response.get_json())


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_discovery_document(framework: str, factory: NeoZenFactory) -> None:
    metadata = _get(framework, factory, "/.well-known/openid-configuration")
    assert metadata["issuer"] == ISSUER
    assert metadata["jwks_uri"] == f"{ISSUER}/.well-known/jwks.json"
    assert metadata["id_token_signing_alg_values_supported"] == ["ES256"]


@pytest.mark.parametrize("framework", FRAMEWORKS)
def test_access_token_verifies_against_served_jwks(
    framework: str, factory: NeoZenFactory
) -> None:
    # Sync test: Flask's async views can't run inside a running event loop.
    service = factory.create_oauth_token_service(
        MockStorage(MockOAuthClient),
        MockStorage(MockOAuthAuthorizationCode),
        MockStorage(MockOAuthAccessToken),
        MockStorage(MockOAuthRefreshToken),
    )
    result = anyio.run(
        service.issue_client_credentials_token, MockOAuthClient(client_id="app"), "read"
    )

    # What a resource server does: fetch the JWKS, pick the key by kid.
    jwk_set = jwt.PyJWKSet.from_dict(_get(framework, factory, "/.well-known/jwks.json"))
    kid = jwt.get_unverified_header(result.access_token)["kid"]
    claims = jwt.decode(
        result.access_token,
        jwk_set[kid].key,
        algorithms=["ES256"],
        audience=AUDIENCE,
        issuer=ISSUER,
    )
    assert claims["client_id"] == "app"
