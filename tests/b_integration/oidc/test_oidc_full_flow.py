"""End-to-end integration test for the full OIDC flow.

Exercises the complete OIDC Authorization Code Grant:
1. User authorizes (authorization code is created)
2. Client exchanges code for tokens at the token endpoint
3. Response includes a signed ID token
4. ID token is verified using keys from the JWKS endpoint
5. Client uses access token to call UserInfo
6. Client refreshes the token

This test wires together the real `OAuthTokenService`, `TokenEndpoint`,
`IDTokenGenerator`, `IDTokenVerifier`, `UserInfoEndpoint`,
`JWKSEndpoint`, and `DiscoveryEndpoint` -- all the pieces a real
OIDC Provider needs.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pwdlib import PasswordHash

from neozen.core.crypto import get_token_hash
from neozen.core.oauth.client_service import OAuthClientService
from neozen.core.oauth.models import (
    OAuthAccessTokenModel,
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthRefreshTokenModel,
)
from neozen.core.oauth.services import OAuthTokenService
from neozen.core.oidc import (
    DefaultClaimsProvider,
    IDTokenGenerator,
    IDTokenVerifier,
    InMemoryKeyManager,
)
from neozen.core.oidc.discovery import build_metadata_from_base_url
from neozen.web.oauth import TokenEndpoint
from neozen.web.oidc import (
    DiscoveryEndpoint,
    JWKSEndpoint,
    UserInfoEndpoint,
)
from tests.conftest import MockStorage

# =============================================================================
# Mock Models
# =============================================================================


@dataclasses.dataclass
class MockClient(OAuthClientModel):
    client_id: str
    redirect_uris: str = ""
    allowed_grant_types: str = "authorization_code refresh_token"
    allowed_scopes: str = "openid profile email"
    is_active: bool = True
    client_type: str = "confidential"
    client_secret_hash: str | None = dataclasses.field(
        default_factory=lambda: HASHER.hash(CLIENT_SECRET)
    )


@dataclasses.dataclass
class MockAuthCode(OAuthAuthorizationCodeModel):
    code: str
    client_id: str
    subject_id: str
    expires_at: datetime
    response_type: str
    redirect_uri: str | None
    scope: str
    code_challenge: str
    code_challenge_method: str
    nonce: str | None = None


@dataclasses.dataclass
class MockAccessToken(OAuthAccessTokenModel):
    token_hash: str
    client_id: str
    subject_id: str
    scope: str
    expires_at: datetime
    created_at: datetime
    revoked_at: datetime | None


@dataclasses.dataclass
class MockRefreshToken(OAuthRefreshTokenModel):
    token_hash: str
    client_id: str
    subject_id: str
    scope: str
    expires_at: datetime | None
    created_at: datetime
    revoked_at: datetime | None
    access_token_hash: str | None


@dataclasses.dataclass
class MockSubject:
    """The application's User model (no NeoZen inheritance)."""

    id: str
    email: str
    is_verified: bool = True
    name: str | None = None
    username: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    picture: str | None = None
    locale: str | None = None


class MockSubjectLookup:
    """Implements `SubjectAttributeLookup` for `DefaultClaimsProvider`."""

    def __init__(self, subjects: dict[str, MockSubject] | None = None) -> None:
        self._subjects = subjects or {}

    async def get_subject(self, subject_id: str) -> Any | None:
        return self._subjects.get(subject_id)


# =============================================================================
# Fixtures
# =============================================================================


TOKEN_HASH_KEY = "test-secret-key"
CLIENT_SECRET = "client-secret"
HASHER = PasswordHash.recommended()
ISSUER = "https://auth.example.com"


@pytest.fixture
def alice() -> MockSubject:
    return MockSubject(
        id="user_alice",
        email="alice@example.com",
        is_verified=True,
        name="Alice Smith",
        given_name="Alice",
        family_name="Smith",
        username="alice",
        locale="en-US",
    )


@pytest.fixture
def subject_lookup(alice: MockSubject) -> MockSubjectLookup:
    return MockSubjectLookup({alice.id: alice})


@pytest.fixture
def claims_provider(
    subject_lookup: MockSubjectLookup,
) -> DefaultClaimsProvider:
    return DefaultClaimsProvider(subject_lookup)


@pytest.fixture
def key_manager() -> InMemoryKeyManager:
    return InMemoryKeyManager()


@pytest.fixture
def id_token_generator(
    key_manager: InMemoryKeyManager,
) -> IDTokenGenerator:
    return IDTokenGenerator(
        key_manager=key_manager,
        issuer=ISSUER,
        default_lifetime=timedelta(hours=1),
    )


@pytest.fixture
def id_token_verifier(
    key_manager: InMemoryKeyManager,
) -> IDTokenVerifier:
    return IDTokenVerifier(key_manager=key_manager, issuer=ISSUER)


@pytest.fixture
def client_storage() -> MockStorage[MockClient]:
    return MockStorage(MockClient, [])


@pytest.fixture
def auth_code_storage() -> MockStorage[MockAuthCode]:
    return MockStorage(MockAuthCode, [])


@pytest.fixture
def access_token_storage() -> MockStorage[MockAccessToken]:
    return MockStorage(MockAccessToken, [])


@pytest.fixture
def refresh_token_storage() -> MockStorage[MockRefreshToken]:
    return MockStorage(MockRefreshToken, [])


@pytest.fixture
def oauth_service(
    client_storage: MockStorage[MockClient],
    auth_code_storage: MockStorage[MockAuthCode],
    access_token_storage: MockStorage[MockAccessToken],
    refresh_token_storage: MockStorage[MockRefreshToken],
) -> OAuthTokenService[MockClient, MockAuthCode, MockAccessToken, MockRefreshToken]:
    return OAuthTokenService(
        client_repository=client_storage,
        authorization_code_repository=auth_code_storage,
        access_token_repository=access_token_storage,
        refresh_token_repository=refresh_token_storage,
        token_hash_key=TOKEN_HASH_KEY,
    )


@pytest.fixture
def token_endpoint(
    oauth_service: OAuthTokenService,
    id_token_generator: IDTokenGenerator,
    claims_provider: DefaultClaimsProvider,
) -> TokenEndpoint:
    return TokenEndpoint(
        oauth_service,
        OAuthClientService(oauth_service.client_repository, HASHER),
        id_token_generator=id_token_generator,
        claims_provider=claims_provider,
    )


@pytest.fixture
def userinfo_endpoint(
    oauth_service: OAuthTokenService,
    claims_provider: DefaultClaimsProvider,
) -> UserInfoEndpoint:
    return UserInfoEndpoint(
        token_service=oauth_service,
        claims_provider=claims_provider,
    )


@pytest.fixture
def jwks_endpoint(key_manager: InMemoryKeyManager) -> JWKSEndpoint:
    return JWKSEndpoint(key_manager)


@pytest.fixture
def discovery_endpoint() -> DiscoveryEndpoint:
    metadata = build_metadata_from_base_url(
        issuer=ISSUER,
        base_url=ISSUER,
    )
    return DiscoveryEndpoint(metadata)


async def _seed_authorization_code(
    client_storage: MockStorage[MockClient],
    auth_code_storage: MockStorage[MockAuthCode],
    *,
    subject_id: str,
    scope: str,
) -> tuple[str, str]:
    """Insert a client and an authorization code; return (code, verifier)."""
    await client_storage.create(client_id="client_app")
    verifier = "a" * 43  # min length for code_verifier
    await auth_code_storage.create(
        code=get_token_hash("auth_code_xyz", key=TOKEN_HASH_KEY),
        client_id="client_app",
        subject_id=subject_id,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        response_type="code",
        redirect_uri="https://app.example.com/callback",
        scope=scope,
        code_challenge=verifier,
        code_challenge_method="plain",
    )
    return "auth_code_xyz", verifier


# =============================================================================
# Full OIDC Flow Test
# =============================================================================


@pytest.mark.anyio
class TestFullOIDCFlow:
    """Walk through the full OIDC authorization code grant flow."""

    async def test_authorization_code_to_userinfo(
        self,
        client_storage: MockStorage[MockClient],
        auth_code_storage: MockStorage[MockAuthCode],
        token_endpoint: TokenEndpoint,
        userinfo_endpoint: UserInfoEndpoint,
        id_token_verifier: IDTokenVerifier,
        jwks_endpoint: JWKSEndpoint,
        alice: MockSubject,
    ) -> None:
        # ---- 1. Authorization step (out of band: user clicked Approve) ----
        code, verifier = await _seed_authorization_code(
            client_storage,
            auth_code_storage,
            subject_id=alice.id,
            scope="openid email profile",
        )

        # ---- 2. Token exchange ----
        token_response = await token_endpoint(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example.com/callback",
                "client_id": "client_app",
                "code_verifier": verifier,
            },
            client_secret=CLIENT_SECRET,
        )

        assert token_response.access_token.startswith("nz_at_")
        assert token_response.refresh_token is not None
        assert token_response.refresh_token.startswith("nz_rt_")
        assert token_response.id_token is not None
        assert token_response.id_token.count(".") == 2  # JWT structure

        # ---- 3. ID token verification ----
        # Fetch JWKS and use it (verification is via key_manager which
        # is shared between the generator and verifier in the fixture)
        jwks = await jwks_endpoint()
        assert "keys" in jwks
        assert len(jwks["keys"]) >= 1

        claims = await id_token_verifier.verify(
            token_response.id_token, audience="client_app"
        )
        assert claims["iss"] == ISSUER
        assert claims["sub"] == alice.id
        assert claims["aud"] == "client_app"
        assert claims["email"] == "alice@example.com"
        assert claims["email_verified"] is True
        assert claims["name"] == "Alice Smith"
        assert claims["preferred_username"] == "alice"

        # ---- 4. UserInfo with the access token ----
        userinfo = await userinfo_endpoint(f"Bearer {token_response.access_token}")
        assert userinfo["sub"] == alice.id
        assert userinfo["email"] == "alice@example.com"
        assert userinfo["email_verified"] is True
        assert userinfo["name"] == "Alice Smith"
        # locale is in the profile scope, should be returned
        assert userinfo.get("locale") == "en-US"

    async def test_token_without_openid_no_id_token(
        self,
        client_storage: MockStorage[MockClient],
        auth_code_storage: MockStorage[MockAuthCode],
        token_endpoint: TokenEndpoint,
        alice: MockSubject,
    ) -> None:
        """No openid scope -> no id_token in response."""
        code, verifier = await _seed_authorization_code(
            client_storage,
            auth_code_storage,
            subject_id=alice.id,
            scope="profile",  # no openid
        )

        response = await token_endpoint(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example.com/callback",
                "client_id": "client_app",
                "code_verifier": verifier,
            },
            client_secret=CLIENT_SECRET,
        )

        assert response.access_token.startswith("nz_at_")
        assert response.id_token is None

    async def test_userinfo_filters_by_scope(
        self,
        client_storage: MockStorage[MockClient],
        auth_code_storage: MockStorage[MockAuthCode],
        token_endpoint: TokenEndpoint,
        userinfo_endpoint: UserInfoEndpoint,
        alice: MockSubject,
    ) -> None:
        """Only openid scope -> UserInfo returns just `sub`."""
        code, verifier = await _seed_authorization_code(
            client_storage,
            auth_code_storage,
            subject_id=alice.id,
            scope="openid",
        )

        response = await token_endpoint(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example.com/callback",
                "client_id": "client_app",
                "code_verifier": verifier,
            },
            client_secret=CLIENT_SECRET,
        )

        userinfo = await userinfo_endpoint(f"Bearer {response.access_token}")
        assert userinfo == {"sub": alice.id}
        assert "email" not in userinfo
        assert "name" not in userinfo

    async def test_refresh_grant_returns_new_id_token(
        self,
        client_storage: MockStorage[MockClient],
        auth_code_storage: MockStorage[MockAuthCode],
        token_endpoint: TokenEndpoint,
        id_token_verifier: IDTokenVerifier,
        alice: MockSubject,
    ) -> None:
        """The refresh_token grant should also return an id_token."""
        # First, get tokens via authorization_code
        code, verifier = await _seed_authorization_code(
            client_storage,
            auth_code_storage,
            subject_id=alice.id,
            scope="openid email",
        )
        first = await token_endpoint(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example.com/callback",
                "client_id": "client_app",
                "code_verifier": verifier,
            },
            client_secret=CLIENT_SECRET,
        )

        # Then refresh
        refreshed = await token_endpoint(
            {
                "grant_type": "refresh_token",
                "refresh_token": first.refresh_token,
                "client_id": "client_app",
            },
            client_secret=CLIENT_SECRET,
        )

        assert refreshed.access_token != first.access_token
        assert refreshed.id_token is not None

        # New ID token should still verify
        claims = await id_token_verifier.verify(
            refreshed.id_token, audience="client_app"
        )
        assert claims["sub"] == alice.id
        assert claims["email"] == "alice@example.com"


@pytest.mark.anyio
class TestDiscoveryAndJWKS:
    """Validate the discovery and JWKS endpoints serve correct metadata."""

    async def test_discovery_metadata(
        self, discovery_endpoint: DiscoveryEndpoint
    ) -> None:
        metadata = await discovery_endpoint()

        assert metadata["issuer"] == ISSUER
        assert metadata["authorization_endpoint"] == (f"{ISSUER}/oauth/authorize")
        assert metadata["token_endpoint"] == f"{ISSUER}/oauth/token"
        assert metadata["userinfo_endpoint"] == f"{ISSUER}/userinfo"
        assert metadata["jwks_uri"] == f"{ISSUER}/.well-known/jwks.json"
        assert "openid" in metadata["scopes_supported"]
        assert "code" in metadata["response_types_supported"]
        assert "RS256" in metadata["id_token_signing_alg_values_supported"]
        assert "S256" in metadata["code_challenge_methods_supported"]

    async def test_jwks_response(self, jwks_endpoint: JWKSEndpoint) -> None:
        jwks = await jwks_endpoint()

        assert "keys" in jwks
        assert len(jwks["keys"]) >= 1
        key = jwks["keys"][0]
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert "n" in key  # modulus
        assert "e" in key  # exponent
        assert "kid" in key  # key id

    async def test_jwks_serializable(self, jwks_endpoint: JWKSEndpoint) -> None:
        """JWKS response must round-trip through JSON."""
        jwks = await jwks_endpoint()
        json_text = json.dumps(jwks)
        parsed = json.loads(json_text)
        assert parsed == jwks


# =============================================================================
# Client Credentials Flow
# =============================================================================


@pytest.mark.anyio
class TestClientCredentialsFlow:
    async def test_machine_to_machine(
        self,
        client_storage: MockStorage[MockClient],
        access_token_storage: MockStorage[MockAccessToken],
        token_endpoint: TokenEndpoint,
    ) -> None:
        """Client credentials grant for service-to-service auth."""
        await client_storage.create(
            client_id="service_account",
            allowed_grant_types="client_credentials",
            allowed_scopes="api:read api:write",
        )

        response = await token_endpoint(
            {
                "grant_type": "client_credentials",
                "client_id": "service_account",
                "scope": "api:read",
            },
            client_secret=CLIENT_SECRET,
        )

        assert response.access_token.startswith("nz_at_")
        assert response.refresh_token is None  # not issued for cc grant
        assert response.id_token is None  # no openid scope
        assert response.scope == "api:read"

        # Verify the token's subject is the client itself
        token_hash = get_token_hash(response.access_token, key=TOKEN_HASH_KEY)
        stored = await access_token_storage.get_one_by(token_hash=token_hash)
        assert stored.subject_id == "service_account"


# =============================================================================
# Token Revocation
# =============================================================================


@pytest.mark.anyio
class TestTokenRevocation:
    async def test_revoke_access_token_breaks_userinfo(
        self,
        client_storage: MockStorage[MockClient],
        auth_code_storage: MockStorage[MockAuthCode],
        token_endpoint: TokenEndpoint,
        userinfo_endpoint: UserInfoEndpoint,
        oauth_service: OAuthTokenService,
        alice: MockSubject,
    ) -> None:
        """After revoking an access token, UserInfo should reject it."""
        from neozen.web.oidc.userinfo_endpoint import UserInfoError

        code, verifier = await _seed_authorization_code(
            client_storage,
            auth_code_storage,
            subject_id=alice.id,
            scope="openid email",
        )
        response = await token_endpoint(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app.example.com/callback",
                "client_id": "client_app",
                "code_verifier": verifier,
            },
            client_secret=CLIENT_SECRET,
        )

        # Works initially
        result = await userinfo_endpoint(f"Bearer {response.access_token}")
        assert result["sub"] == alice.id

        # Revoke
        await oauth_service.revoke_access_token(response.access_token, "client_app")

        # Now rejected
        with pytest.raises(UserInfoError) as exc_info:
            await userinfo_endpoint(f"Bearer {response.access_token}")
        assert exc_info.value.status_code == 401
