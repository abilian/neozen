"""The [oauth_server] settings drive the OAuth services built by NeoZenFactory."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from pwdlib import PasswordHash

from neozen.config import (
    ConfigError,
    ConfigValidationError,
    NeoZenConfig,
    NeoZenFactory,
    OAuthServerConfig,
    SecurityConfig,
    load_config,
    validate_config,
)
from neozen.core.crypto import get_token_hash
from neozen.core.oauth import OAuthClientService, OAuthTokenService
from neozen.core.oidc import IDTokenGenerator, IDTokenVerifier, InMemoryKeyManager
from neozen.core.oidc.keys import KeyManager, SigningAlgorithm
from tests.conftest import MockStorage

from .stubs import (
    MockOAuthAccessToken,
    MockOAuthAuthorizationCode,
    MockOAuthClient,
    MockOAuthRefreshToken,
)
from .test_authorization_consent import AuthCode, Client, Grant

SECRET = "s" * 32
ALGORITHMS: list[SigningAlgorithm] = ["RS256", "ES256"]

TokenService = OAuthTokenService[
    MockOAuthClient,
    MockOAuthAuthorizationCode,
    MockOAuthAccessToken,
    MockOAuthRefreshToken,
]


def _config(oauth_server: OAuthServerConfig) -> NeoZenConfig:
    return NeoZenConfig(
        security=SecurityConfig(secret_key=SECRET), oauth_server=oauth_server
    )


def _token_service(factory: NeoZenFactory) -> TokenService:
    return factory.create_oauth_token_service(
        MockStorage(MockOAuthClient),
        MockStorage(MockOAuthAuthorizationCode),
        MockStorage(MockOAuthAccessToken),
        MockStorage(MockOAuthRefreshToken),
    )


def _factory(oauth_server: OAuthServerConfig) -> NeoZenFactory:
    return NeoZenFactory(_config(oauth_server))


async def _public_pem(key_manager: KeyManager) -> bytes:
    key = await key_manager.get_active_signing_key()
    private = serialization.load_pem_private_key(key.private_pem, password=None)
    return private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


class TestFactory:
    def test_token_service_uses_configured_lifetimes(self) -> None:
        service = _token_service(
            _factory(
                OAuthServerConfig(
                    enabled=True,
                    access_token_lifetime=timedelta(minutes=5),
                    refresh_token_lifetime=timedelta(days=2),
                    allow_refresh_token_rotation=False,
                )
            )
        )
        assert service.access_token_lifetime == timedelta(minutes=5)
        assert service.refresh_token_lifetime == timedelta(days=2)
        assert service.rotate_refresh_tokens is False
        assert service.token_hash_key == SECRET
        assert service.access_token_signer is None

    def test_authorization_endpoint_uses_code_lifetime_and_pkce_rule(self) -> None:
        factory = NeoZenFactory(
            _config(
                OAuthServerConfig(
                    enabled=True,
                    authorization_code_lifetime=timedelta(minutes=2),
                    require_pkce=False,
                )
            )
        )
        endpoint = factory.create_authorization_endpoint(
            OAuthClientService(MockStorage(Client), PasswordHash.recommended()),
            MockStorage(Grant),
            MockStorage(AuthCode),
        )
        assert endpoint.code_lifetime == timedelta(minutes=2)
        assert endpoint.require_pkce is False

    def test_disabled_oauth_server_is_refused(self) -> None:
        with pytest.raises(ConfigError):
            _token_service(_factory(OAuthServerConfig(enabled=False)))

    def test_jwt_access_tokens_need_an_issuer(self) -> None:
        factory = _factory(
            OAuthServerConfig(enabled=True, jwt_access_tokens=True, jwt_audience="api")
        )
        with pytest.raises(ConfigError):
            _token_service(factory)

    @pytest.mark.anyio
    async def test_one_key_manager_signs_everything(self) -> None:
        factory = _factory(
            OAuthServerConfig(
                enabled=True, issuer="https://auth.test", jwt_algorithm="ES256"
            )
        )
        key_manager = factory.key_manager
        assert factory.key_manager is key_manager
        assert factory.create_id_token_generator().key_manager is key_manager
        assert (await key_manager.get_active_signing_key()).alg == "ES256"

    def test_discovery_uses_the_issuer_and_algorithm(self) -> None:
        factory = _factory(
            OAuthServerConfig(
                enabled=True, issuer="https://auth.test", jwt_algorithm="ES256"
            )
        )
        metadata = factory.create_discovery_metadata("https://auth.test")
        assert metadata.issuer == "https://auth.test"
        assert metadata.id_token_signing_alg_values_supported == ["ES256"]


class TestValidation:
    def test_jwt_access_tokens_need_issuer_and_audience(self) -> None:
        config = _config(OAuthServerConfig(enabled=True, jwt_access_tokens=True))
        with pytest.raises(ConfigValidationError, match="issuer") as exc_info:
            validate_config(config)
        assert "jwt_audience" in str(exc_info.value)

    def test_unsupported_algorithm_from_toml_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "neozen.toml"
        path.write_text(
            f'[security]\nsecret_key = "{SECRET}"\n'
            '[oauth_server]\nenabled = true\njwt_algorithm = "HS256"\n'
        )
        with pytest.raises(ConfigValidationError, match="jwt_algorithm must be one of"):
            validate_config(load_config(path))


@pytest.mark.anyio
class TestJWTAccessTokens:
    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    async def test_access_token_is_a_signed_jwt(
        self, algorithm: SigningAlgorithm
    ) -> None:
        factory = _factory(
            OAuthServerConfig(
                enabled=True,
                issuer="https://auth.test",
                jwt_access_tokens=True,
                jwt_audience="https://api.test",
                jwt_algorithm=algorithm,
            )
        )
        key_manager = factory.key_manager
        service = _token_service(factory)
        client = MockOAuthClient(client_id="app")

        result = await service.issue_client_credentials_token(client, "read")

        header = jwt.get_unverified_header(result.access_token)
        assert header["typ"] == "at+jwt"
        assert header["alg"] == algorithm
        claims = jwt.decode(
            result.access_token,
            await _public_pem(key_manager),
            algorithms=[algorithm],
            audience="https://api.test",
            issuer="https://auth.test",
        )
        assert claims["client_id"] == "app"
        assert claims["sub"] == "app"
        assert claims["scope"] == "read"
        assert claims["jti"]
        assert claims["exp"] - claims["iat"] == 3600
        # Stored hashed like an opaque token, so introspection and revocation
        # find it the same way.
        assert result.access_token_hash == get_token_hash(
            result.access_token, key=SECRET
        )
        stored = await service.access_token_repository.get_one_by(
            token_hash=result.access_token_hash
        )
        assert stored.client_id == "app"


@pytest.mark.anyio
class TestES256Keys:
    async def test_jwk_has_full_length_coordinates(self) -> None:
        key = await InMemoryKeyManager("ES256").get_active_signing_key()
        jwk = key.public_jwk.to_dict()
        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert len(jwk["x"]) == len(jwk["y"]) == 43

    async def test_id_token_round_trip(self) -> None:
        key_manager = InMemoryKeyManager("ES256")
        token = await IDTokenGenerator(key_manager, "https://auth.test").generate(
            subject_id="alice", client_id="app", scopes=["openid"]
        )
        claims = await IDTokenVerifier(key_manager, "https://auth.test").verify(
            token, audience="app"
        )
        assert claims["sub"] == "alice"
        assert claims["iat"] <= int(datetime.now(UTC).timestamp())
