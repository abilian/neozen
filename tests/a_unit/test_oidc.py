"""Tests for OIDC core: keys, ID tokens, claims, discovery."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest

from neozen.core.oidc.claims import (
    SCOPE_CLAIMS,
    DefaultClaimsProvider,
    SubjectClaims,
    filter_claims_by_scopes,
)
from neozen.core.oidc.discovery import (
    OIDCProviderMetadata,
    build_metadata_from_base_url,
)
from neozen.core.oidc.id_token import (
    IDTokenClaims,
    IDTokenGenerator,
    IDTokenVerifier,
)
from neozen.core.oidc.keys import (
    JWK,
    JWKS,
    InMemoryKeyManager,
)

# =============================================================================
# Key Management
# =============================================================================


class TestJWK:
    def test_to_dict_omits_none(self) -> None:
        jwk = JWK(
            kty="RSA",
            kid="key-1",
            use="sig",
            alg="RS256",
            n="abc",
            e="AQAB",
        )
        d = jwk.to_dict()
        assert d == {
            "kty": "RSA",
            "kid": "key-1",
            "use": "sig",
            "alg": "RS256",
            "n": "abc",
            "e": "AQAB",
        }
        assert "crv" not in d
        assert "x" not in d


class TestJWKS:
    def test_empty(self) -> None:
        jwks = JWKS(keys=[])
        assert jwks.to_dict() == {"keys": []}

    def test_with_keys(self) -> None:
        jwk = JWK(kty="RSA", kid="k1", use="sig", alg="RS256", n="n", e="e")
        jwks = JWKS(keys=[jwk])
        d = jwks.to_dict()
        assert len(d["keys"]) == 1
        assert d["keys"][0]["kid"] == "k1"


class TestInMemoryKeyManager:
    @pytest.mark.anyio
    async def test_initial_key_generated_on_demand(self) -> None:
        manager = InMemoryKeyManager()
        key = await manager.get_active_signing_key()
        assert key.kid is not None
        assert key.alg == "RS256"
        assert key.private_pem.startswith(b"-----BEGIN ")
        assert b"PRIVATE" in key.private_pem
        assert key.is_active

    @pytest.mark.anyio
    async def test_get_jwks(self) -> None:
        manager = InMemoryKeyManager()
        jwks = await manager.get_jwks()
        assert len(jwks.keys) == 1
        assert jwks.keys[0].kty == "RSA"
        assert jwks.keys[0].use == "sig"

    @pytest.mark.anyio
    async def test_get_key_by_id(self) -> None:
        manager = InMemoryKeyManager()
        key = await manager.get_active_signing_key()
        found = await manager.get_key_by_id(key.kid)
        assert found is not None
        assert found.kid == key.kid

    @pytest.mark.anyio
    async def test_get_key_by_id_not_found(self) -> None:
        manager = InMemoryKeyManager()
        await manager.get_active_signing_key()
        assert await manager.get_key_by_id("nope") is None

    @pytest.mark.anyio
    async def test_rotate_key(self) -> None:
        manager = InMemoryKeyManager()
        old = await manager.get_active_signing_key()
        new = await manager.rotate_key()
        assert new.kid != old.kid

        # Both keys should still be in JWKS
        jwks = await manager.get_jwks()
        assert len(jwks.keys) == 2

        # Active should be the new one
        active = await manager.get_active_signing_key()
        assert active.kid == new.kid

        # Old key should be marked inactive
        old_retrieved = await manager.get_key_by_id(old.kid)
        assert old_retrieved is not None
        assert not old_retrieved.is_active


# =============================================================================
# ID Token Claims
# =============================================================================


class TestIDTokenClaims:
    def test_to_dict_required(self) -> None:
        claims = IDTokenClaims(
            iss="https://auth.example.com",
            sub="user_1",
            aud="client_1",
            exp=2000000000,
            iat=1999996400,
        )
        d = claims.to_dict()
        assert d["iss"] == "https://auth.example.com"
        assert d["sub"] == "user_1"
        assert d["aud"] == "client_1"
        assert d["exp"] == 2000000000
        assert d["iat"] == 1999996400
        # None fields should be omitted
        assert "nonce" not in d
        assert "auth_time" not in d

    def test_to_dict_with_optional(self) -> None:
        claims = IDTokenClaims(
            iss="https://auth.example.com",
            sub="user_1",
            aud="client_1",
            exp=2000000000,
            iat=1999996400,
            nonce="abc",
            email="user@example.com",
            email_verified=True,
        )
        d = claims.to_dict()
        assert d["nonce"] == "abc"
        assert d["email"] == "user@example.com"
        assert d["email_verified"] is True

    def test_to_dict_with_extra(self) -> None:
        claims = IDTokenClaims(
            iss="https://auth.example.com",
            sub="user_1",
            aud="client_1",
            exp=2000000000,
            iat=1999996400,
            extra={"custom_claim": "value"},
        )
        d = claims.to_dict()
        assert d["custom_claim"] == "value"


# =============================================================================
# ID Token Generation & Verification
# =============================================================================


@pytest.fixture
def key_manager() -> InMemoryKeyManager:
    return InMemoryKeyManager()


@pytest.fixture
def id_token_generator(
    key_manager: InMemoryKeyManager,
) -> IDTokenGenerator:
    return IDTokenGenerator(
        key_manager=key_manager,
        issuer="https://auth.example.com",
    )


@pytest.fixture
def id_token_verifier(
    key_manager: InMemoryKeyManager,
) -> IDTokenVerifier:
    return IDTokenVerifier(
        key_manager=key_manager,
        issuer="https://auth.example.com",
    )


class TestIDTokenGenerator:
    @pytest.mark.anyio
    async def test_generate_basic(
        self,
        id_token_generator: IDTokenGenerator,
        id_token_verifier: IDTokenVerifier,
    ) -> None:
        token = await id_token_generator.generate(
            subject_id="user_1",
            client_id="client_1",
            scopes=["openid"],
        )

        assert isinstance(token, str)
        # JWT has 3 segments
        assert token.count(".") == 2

        # Verify roundtrips
        claims = await id_token_verifier.verify(token, audience="client_1")
        assert claims["sub"] == "user_1"
        assert claims["aud"] == "client_1"
        assert claims["iss"] == "https://auth.example.com"

    @pytest.mark.anyio
    async def test_generate_requires_openid_scope(
        self,
        id_token_generator: IDTokenGenerator,
    ) -> None:
        with pytest.raises(ValueError, match="openid"):
            await id_token_generator.generate(
                subject_id="user_1",
                client_id="client_1",
                scopes=["profile"],  # Missing openid
            )

    @pytest.mark.anyio
    async def test_generate_with_nonce(
        self,
        id_token_generator: IDTokenGenerator,
        id_token_verifier: IDTokenVerifier,
    ) -> None:
        token = await id_token_generator.generate(
            subject_id="user_1",
            client_id="client_1",
            scopes=["openid"],
            nonce="n-0S6_WzA2Mj",
        )
        claims = await id_token_verifier.verify(token, audience="client_1")
        assert claims["nonce"] == "n-0S6_WzA2Mj"

    @pytest.mark.anyio
    async def test_generate_with_auth_time(
        self,
        id_token_generator: IDTokenGenerator,
        id_token_verifier: IDTokenVerifier,
    ) -> None:
        auth_time = datetime(2026, 4, 10, 12, 0, tzinfo=UTC)
        token = await id_token_generator.generate(
            subject_id="user_1",
            client_id="client_1",
            scopes=["openid"],
            auth_time=auth_time,
        )
        claims = await id_token_verifier.verify(token, audience="client_1")
        assert claims["auth_time"] == int(auth_time.timestamp())

    @pytest.mark.anyio
    async def test_generate_with_extra_claims(
        self,
        id_token_generator: IDTokenGenerator,
        id_token_verifier: IDTokenVerifier,
    ) -> None:
        token = await id_token_generator.generate(
            subject_id="user_1",
            client_id="client_1",
            scopes=["openid", "email"],
            claims={
                "email": "alice@example.com",
                "email_verified": True,
            },
        )
        claims = await id_token_verifier.verify(token, audience="client_1")
        assert claims["email"] == "alice@example.com"
        assert claims["email_verified"] is True

    @pytest.mark.anyio
    async def test_token_contains_kid_header(
        self,
        id_token_generator: IDTokenGenerator,
        key_manager: InMemoryKeyManager,
    ) -> None:
        import jwt

        token = await id_token_generator.generate(
            subject_id="user_1",
            client_id="client_1",
            scopes=["openid"],
        )
        header = jwt.get_unverified_header(token)
        active = await key_manager.get_active_signing_key()
        assert header["kid"] == active.kid

    @pytest.mark.anyio
    async def test_verify_wrong_audience(
        self,
        id_token_generator: IDTokenGenerator,
        id_token_verifier: IDTokenVerifier,
    ) -> None:
        import jwt

        token = await id_token_generator.generate(
            subject_id="user_1",
            client_id="client_1",
            scopes=["openid"],
        )
        with pytest.raises(jwt.InvalidAudienceError):
            await id_token_verifier.verify(token, audience="wrong_client")


# =============================================================================
# Claims Provider
# =============================================================================


@dataclass
class MockSubject:
    id: str
    email: str
    is_verified: bool = False
    name: str | None = None
    username: str | None = None
    locale: str | None = None


class MockSubjectLookup:
    def __init__(self, subjects: dict[str, MockSubject] | None = None) -> None:
        self._subjects = subjects or {}

    async def get_subject(self, subject_id: str) -> Any | None:
        return self._subjects.get(subject_id)


class TestClaimsProvider:
    @pytest.mark.anyio
    async def test_get_claims_known_subject(self) -> None:
        lookup = MockSubjectLookup({
            "u1": MockSubject(
                id="u1",
                email="alice@example.com",
                is_verified=True,
                name="Alice",
                username="alice",
                locale="en-US",
            )
        })
        provider = DefaultClaimsProvider(lookup)

        claims = await provider.get_claims("u1", ["openid", "email", "profile"])
        assert claims is not None
        assert claims.sub == "u1"
        assert claims.email == "alice@example.com"
        assert claims.email_verified is True
        assert claims.name == "Alice"
        assert claims.preferred_username == "alice"
        assert claims.locale == "en-US"

    @pytest.mark.anyio
    async def test_get_claims_unknown_subject(self) -> None:
        provider = DefaultClaimsProvider(MockSubjectLookup())
        assert await provider.get_claims("nope", ["openid"]) is None

    @pytest.mark.anyio
    async def test_get_claims_missing_attributes(self) -> None:
        # Subject without name/username
        lookup = MockSubjectLookup({"u1": MockSubject(id="u1", email="a@e.com")})
        provider = DefaultClaimsProvider(lookup)
        claims = await provider.get_claims("u1", ["openid", "email"])
        assert claims is not None
        assert claims.email == "a@e.com"
        assert claims.name is None


class TestSubjectClaims:
    def test_to_dict_omits_none(self) -> None:
        claims = SubjectClaims(sub="u1", email="a@e.com")
        d = claims.to_dict()
        assert d == {"sub": "u1", "email": "a@e.com"}


class TestScopeFiltering:
    def test_openid_only_returns_sub(self) -> None:
        result = filter_claims_by_scopes(
            {"sub": "u1", "email": "a@e.com", "name": "Alice"},
            ["openid"],
        )
        assert result == {"sub": "u1"}

    def test_email_scope(self) -> None:
        result = filter_claims_by_scopes(
            {
                "sub": "u1",
                "email": "a@e.com",
                "email_verified": True,
                "name": "Alice",
            },
            ["openid", "email"],
        )
        assert result == {
            "sub": "u1",
            "email": "a@e.com",
            "email_verified": True,
        }

    def test_profile_scope(self) -> None:
        result = filter_claims_by_scopes(
            {
                "sub": "u1",
                "name": "Alice",
                "preferred_username": "alice",
                "email": "a@e.com",
            },
            ["openid", "profile"],
        )
        assert "name" in result
        assert "preferred_username" in result
        assert "email" not in result

    def test_unknown_scope_ignored(self) -> None:
        result = filter_claims_by_scopes(
            {"sub": "u1", "email": "a@e.com"},
            ["openid", "made_up"],
        )
        assert result == {"sub": "u1"}

    def test_scope_claims_constant(self) -> None:
        # Sanity check on the constant
        assert "openid" in SCOPE_CLAIMS
        assert "email" in SCOPE_CLAIMS["email"]
        assert "name" in SCOPE_CLAIMS["profile"]


# =============================================================================
# Discovery
# =============================================================================


class TestOIDCProviderMetadata:
    def test_to_dict_required_fields(self) -> None:
        meta = OIDCProviderMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/oauth/authorize",
            token_endpoint="https://auth.example.com/oauth/token",
            userinfo_endpoint="https://auth.example.com/userinfo",
            jwks_uri="https://auth.example.com/.well-known/jwks.json",
        )
        d = meta.to_dict()
        assert d["issuer"] == "https://auth.example.com"
        assert d["authorization_endpoint"].endswith("/oauth/authorize")
        assert "openid" in d["scopes_supported"]
        assert "code" in d["response_types_supported"]
        assert "RS256" in d["id_token_signing_alg_values_supported"]
        assert "S256" in d["code_challenge_methods_supported"]

    def test_to_dict_omits_none(self) -> None:
        meta = OIDCProviderMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/oauth/authorize",
            token_endpoint="https://auth.example.com/oauth/token",
            userinfo_endpoint="https://auth.example.com/userinfo",
            jwks_uri="https://auth.example.com/.well-known/jwks.json",
        )
        d = meta.to_dict()
        # Optional endpoints not set
        assert "registration_endpoint" not in d
        assert "end_session_endpoint" not in d


class TestBuildMetadataFromBaseURL:
    def test_basic(self) -> None:
        meta = build_metadata_from_base_url(
            issuer="https://auth.example.com",
            base_url="https://auth.example.com",
        )
        assert meta.issuer == "https://auth.example.com"
        assert meta.token_endpoint == "https://auth.example.com/oauth/token"
        assert meta.userinfo_endpoint == "https://auth.example.com/userinfo"
        assert meta.jwks_uri.endswith("/jwks.json")
        assert meta.registration_endpoint is None

    def test_with_registration(self) -> None:
        meta = build_metadata_from_base_url(
            issuer="https://auth.example.com",
            base_url="https://auth.example.com",
            include_registration=True,
        )
        assert meta.registration_endpoint == ("https://auth.example.com/oauth/register")

    def test_strips_trailing_slash(self) -> None:
        meta = build_metadata_from_base_url(
            issuer="https://auth.example.com",
            base_url="https://auth.example.com/",
        )
        assert "//" not in meta.token_endpoint.replace("https://", "")
