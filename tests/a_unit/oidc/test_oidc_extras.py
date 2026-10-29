"""Tests for OIDC Extras (Stage 11b): consent, end_session, registration, CORS."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from neozen.core.oauth.client_service import OAuthClientService
from neozen.core.oauth.models import OAuthClientModel
from neozen.core.oidc.consent import (
    ConsentRecord,
    ConsentService,
)
from neozen.core.oidc.id_token import IDTokenGenerator, IDTokenVerifier
from neozen.core.oidc.keys import InMemoryKeyManager
from neozen.web.oidc import (
    EndSessionEndpoint,
    EndSessionError,
    InvalidClientMetadataError,
    InvalidPostLogoutRedirectError,
    InvalidRedirectUriError,
    RegistrationEndpoint,
    collect_allowed_origins,
    is_origin_allowed,
    origin_from_url,
)
from neozen.web.oidc.registration_endpoint import registration_reply
from tests.conftest import MockStorage

# =============================================================================
# Consent Service
# =============================================================================


@dataclasses.dataclass
class MockConsentRecord:
    id: str
    subject_id: str
    client_id: str
    scopes: str
    granted_at: datetime
    updated_at: datetime
    revoked_at: datetime | None


class MockConsentRepository:
    def __init__(self) -> None:
        self._records: list[MockConsentRecord] = []

    async def create(self, **data: Any) -> ConsentRecord:
        record = MockConsentRecord(**data)
        self._records.append(record)
        return record  # type: ignore[return-value]

    async def get(self, subject_id: str, client_id: str) -> ConsentRecord | None:
        for r in self._records:
            if r.subject_id == subject_id and r.client_id == client_id:
                return r  # type: ignore[return-value]
        return None

    async def list_for_subject(
        self, subject_id: str, *, include_revoked: bool = False
    ) -> list[ConsentRecord]:
        return [
            r  # type: ignore[misc]
            for r in self._records
            if r.subject_id == subject_id
        ]

    async def update_obj(self, obj: ConsentRecord, **data: Any) -> ConsentRecord:
        for k, v in data.items():
            setattr(obj, k, v)
        return obj

    async def delete(self, obj: ConsentRecord) -> None:
        self._records.remove(obj)  # type: ignore[arg-type]


@pytest.fixture
def consent_service() -> ConsentService:
    return ConsentService(repository=MockConsentRepository())


class TestConsentService:
    @pytest.mark.anyio
    async def test_grant_consent(self, consent_service: ConsentService) -> None:
        record = await consent_service.grant_consent(
            "user_1", "client_1", "openid email"
        )
        assert record.subject_id == "user_1"
        assert record.client_id == "client_1"
        assert "openid" in record.scopes

    @pytest.mark.anyio
    async def test_has_consent_active(self, consent_service: ConsentService) -> None:
        await consent_service.grant_consent("user_1", "client_1", "openid email")
        assert await consent_service.has_consent("user_1", "client_1", "openid")
        assert await consent_service.has_consent("user_1", "client_1", "openid email")

    @pytest.mark.anyio
    async def test_has_consent_subset_only(
        self, consent_service: ConsentService
    ) -> None:
        await consent_service.grant_consent("user_1", "client_1", "openid")
        # Asking for more than granted -> False
        assert not await consent_service.has_consent(
            "user_1", "client_1", "openid email"
        )

    @pytest.mark.anyio
    async def test_has_consent_no_record(self, consent_service: ConsentService) -> None:
        assert not await consent_service.has_consent("user_1", "client_1", "openid")

    @pytest.mark.anyio
    async def test_grant_consent_merges_scopes(
        self, consent_service: ConsentService
    ) -> None:
        await consent_service.grant_consent("user_1", "client_1", "openid")
        record = await consent_service.grant_consent(
            "user_1", "client_1", "email profile"
        )
        scopes = set(record.scopes.split())
        assert scopes == {"openid", "email", "profile"}

    @pytest.mark.anyio
    async def test_revoke_consent(self, consent_service: ConsentService) -> None:
        await consent_service.grant_consent("user_1", "client_1", "openid")
        revoked = await consent_service.revoke_consent("user_1", "client_1")
        assert revoked is True
        assert not await consent_service.has_consent("user_1", "client_1", "openid")

    @pytest.mark.anyio
    async def test_revoke_nonexistent(self, consent_service: ConsentService) -> None:
        revoked = await consent_service.revoke_consent("user_1", "client_1")
        assert revoked is False

    @pytest.mark.anyio
    async def test_restore_consent(self, consent_service: ConsentService) -> None:
        await consent_service.grant_consent("user_1", "client_1", "openid")
        await consent_service.revoke_consent("user_1", "client_1")

        restored = await consent_service.restore_consent("user_1", "client_1")
        assert restored is True
        assert await consent_service.has_consent("user_1", "client_1", "openid")

    @pytest.mark.anyio
    async def test_restore_nonrevoked_returns_false(
        self, consent_service: ConsentService
    ) -> None:
        await consent_service.grant_consent("user_1", "client_1", "openid")
        restored = await consent_service.restore_consent("user_1", "client_1")
        assert restored is False

    @pytest.mark.anyio
    async def test_grant_after_revoke_reactivates(
        self, consent_service: ConsentService
    ) -> None:
        await consent_service.grant_consent("user_1", "client_1", "openid")
        await consent_service.revoke_consent("user_1", "client_1")

        # Granting again should reactivate
        await consent_service.grant_consent("user_1", "client_1", "openid")
        assert await consent_service.has_consent("user_1", "client_1", "openid")

    @pytest.mark.anyio
    async def test_list_trusted_apps(self, consent_service: ConsentService) -> None:
        await consent_service.grant_consent("user_1", "client_1", "openid")
        await consent_service.grant_consent("user_1", "client_2", "openid")
        await consent_service.grant_consent("user_2", "client_1", "openid")

        apps = await consent_service.list_trusted_apps("user_1")
        assert len(apps) == 2

    @pytest.mark.anyio
    async def test_list_trusted_apps_excludes_revoked(
        self, consent_service: ConsentService
    ) -> None:
        await consent_service.grant_consent("user_1", "client_1", "openid")
        await consent_service.grant_consent("user_1", "client_2", "openid")
        await consent_service.revoke_consent("user_1", "client_1")

        apps = await consent_service.list_trusted_apps("user_1")
        assert len(apps) == 1
        assert apps[0].client_id == "client_2"


# =============================================================================
# End Session Endpoint (RP-Initiated Logout)
# =============================================================================


@dataclasses.dataclass
class MockClient(OAuthClientModel):
    client_id: str
    client_name: str = ""
    client_secret_hash: str | None = None
    client_type: str = "confidential"
    redirect_uris: str = ""  # JSON-encoded list
    allowed_scopes: str = ""
    allowed_grant_types: str = ""
    token_endpoint_auth_method: str = "client_secret_basic"
    is_active: bool = True
    created_at: datetime = dataclasses.field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime | None = None


@pytest.fixture
def client_storage() -> MockStorage[MockClient]:
    return MockStorage(MockClient, [])


@pytest.fixture
def client_service(
    client_storage: MockStorage[MockClient],
) -> OAuthClientService[MockClient]:
    class StubHasher:
        def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
            return f"hashed:{password}"

        def verify_and_update(
            self, password: str | bytes, hash: str | bytes
        ) -> tuple[bool, str | None]:
            expected = f"hashed:{password}"
            return hash == expected, None

    return OAuthClientService(
        client_repository=client_storage,
        hasher=StubHasher(),
    )


@pytest.mark.anyio
class TestEndSessionEndpoint:
    async def test_no_client_no_redirect(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = EndSessionEndpoint(client_service)
        result = await endpoint({})
        assert result.client is None
        assert result.post_logout_redirect_uri is None

    async def test_with_client_id(
        self,
        client_storage: MockStorage[MockClient],
        client_service: OAuthClientService[MockClient],
    ) -> None:
        import json

        await client_storage.create(
            client_id="client_1",
            redirect_uris=json.dumps(["https://app.example.com/post_logout"]),
        )
        endpoint = EndSessionEndpoint(client_service)
        result = await endpoint({"client_id": "client_1"})
        assert result.client is not None
        assert result.client.client_id == "client_1"

    async def test_with_valid_post_logout_redirect(
        self,
        client_storage: MockStorage[MockClient],
        client_service: OAuthClientService[MockClient],
    ) -> None:
        import json

        await client_storage.create(
            client_id="client_1",
            redirect_uris=json.dumps(["https://app.example.com/post_logout"]),
        )
        endpoint = EndSessionEndpoint(client_service)
        result = await endpoint({
            "client_id": "client_1",
            "post_logout_redirect_uri": "https://app.example.com/post_logout",
            "state": "xyz",
        })
        assert result.post_logout_redirect_uri == "https://app.example.com/post_logout"
        assert result.state == "xyz"

    async def test_unregistered_redirect_uri_raises(
        self,
        client_storage: MockStorage[MockClient],
        client_service: OAuthClientService[MockClient],
    ) -> None:
        import json

        await client_storage.create(
            client_id="client_1",
            redirect_uris=json.dumps(["https://app.example.com/callback"]),
        )
        endpoint = EndSessionEndpoint(client_service)
        with pytest.raises(InvalidPostLogoutRedirectError):
            await endpoint({
                "client_id": "client_1",
                "post_logout_redirect_uri": "https://evil.example.com/",
            })

    async def test_redirect_without_client_raises(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = EndSessionEndpoint(client_service)
        with pytest.raises(InvalidPostLogoutRedirectError):
            await endpoint({
                "post_logout_redirect_uri": "https://app.example.com/",
            })

    async def test_unknown_client(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = EndSessionEndpoint(client_service)
        result = await endpoint({"client_id": "ghost"})
        # Unknown client just returns None (no exception)
        assert result.client is None

    async def test_malformed_id_token_hint(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = EndSessionEndpoint(client_service)
        result = await endpoint({"id_token_hint": "not-a-jwt"})
        assert result.client is None


# =============================================================================
# Registration Endpoint
# =============================================================================


@pytest.mark.anyio
class TestRegistrationEndpoint:
    async def test_minimal_registration(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = RegistrationEndpoint(client_service)
        response = await endpoint({
            "redirect_uris": ["https://app.example.com/callback"],
        })

        assert response.client_id is not None
        assert response.client_secret is not None  # confidential by default
        assert response.client_id_issued_at > 0
        assert response.client_secret_expires_at == 0
        assert response.redirect_uris == ["https://app.example.com/callback"]
        assert "authorization_code" in response.grant_types

    async def test_with_client_name(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = RegistrationEndpoint(client_service)
        response = await endpoint({
            "redirect_uris": ["https://app.example.com/callback"],
            "client_name": "My App",
        })
        assert response.client_name == "My App"

    async def test_native_client_is_public(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = RegistrationEndpoint(client_service)
        response = await endpoint({
            "redirect_uris": ["com.example.app:/callback"],
            "application_type": "native",
        })
        assert response.client_secret is None
        assert response.token_endpoint_auth_method == "none"

    async def test_with_scope(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = RegistrationEndpoint(client_service)
        response = await endpoint({
            "redirect_uris": ["https://app.example.com/callback"],
            "scope": "openid profile email",
        })
        # Successfully created
        assert response.client_id is not None

    async def test_missing_redirect_uris(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = RegistrationEndpoint(client_service)
        with pytest.raises(InvalidRedirectUriError):
            await endpoint({})

    async def test_empty_redirect_uris(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = RegistrationEndpoint(client_service)
        with pytest.raises(InvalidRedirectUriError):
            await endpoint({"redirect_uris": []})

    async def test_redirect_uri_with_fragment_rejected(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = RegistrationEndpoint(client_service)
        with pytest.raises(InvalidRedirectUriError):
            await endpoint({
                "redirect_uris": ["https://app.example.com/callback#frag"],
            })

    @pytest.mark.parametrize(
        ("uri", "application_type"),
        [
            ("http://app.example.com/callback", "web"),
            ("javascript:alert(1)", "web"),
            ("com.example.app:/callback", "web"),
            ("javascript:alert(1)", "native"),
            ("myapp://callback", "native"),
        ],
    )
    async def test_redirect_uri_scheme_rejected(
        self,
        client_service: OAuthClientService[MockClient],
        uri: str,
        application_type: str,
    ) -> None:
        endpoint = RegistrationEndpoint(client_service)
        with pytest.raises(InvalidRedirectUriError):
            await endpoint({
                "redirect_uris": [uri],
                "application_type": application_type,
            })

    async def test_loopback_http_redirect_uri_allowed(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = RegistrationEndpoint(client_service)
        response = await endpoint({"redirect_uris": ["http://127.0.0.1:8080/cb"]})
        assert response.client_id

    async def test_scope_beyond_allowed_rejected(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = RegistrationEndpoint(client_service)
        with pytest.raises(InvalidClientMetadataError):
            await endpoint({
                "redirect_uris": ["https://app.example.com/callback"],
                "scope": "openid admin",
            })

    async def test_no_scope_gets_the_allowed_scopes(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = RegistrationEndpoint(client_service, allowed_scopes=["openid"])
        response = await endpoint({"redirect_uris": ["https://app.example.com/cb"]})
        client = await client_service.get_client(response.client_id)
        assert client.allowed_scopes == "openid"

    @pytest.mark.parametrize(
        "metadata",
        [
            {"response_types": ["token"]},
            {"token_endpoint_auth_method": "private_key_jwt"},
            {"token_endpoint_auth_method": "none"},  # for a confidential client
        ],
    )
    async def test_unsupported_metadata_is_refused(
        self,
        client_service: OAuthClientService[MockClient],
        metadata: dict[str, object],
    ) -> None:
        reply = await registration_reply(
            RegistrationEndpoint(client_service),
            {"redirect_uris": ["https://app.example.com/cb"], **metadata},
        )
        assert reply.status == 400
        assert reply.body == {
            "error": "invalid_client_metadata",
            "error_description": reply.body["error_description"],
        }

    async def test_credentials_are_never_cached(
        self, client_service: OAuthClientService[MockClient]
    ) -> None:
        reply = await registration_reply(
            RegistrationEndpoint(client_service),
            {"redirect_uris": ["https://app.example.com/cb"]},
        )
        assert reply.status == 201
        assert reply.headers["Cache-Control"] == "no-store"

    async def test_disallowed_grant_type(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = RegistrationEndpoint(
            client_service,
            allowed_grant_types=["authorization_code"],
        )
        with pytest.raises(InvalidClientMetadataError):
            await endpoint({
                "redirect_uris": ["https://app.example.com/callback"],
                "grant_types": ["password"],  # Not allowed
            })

    async def test_response_includes_response_types(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = RegistrationEndpoint(client_service)
        response = await endpoint({
            "redirect_uris": ["https://app.example.com/callback"],
        })
        assert "code" in response.response_types

    async def test_response_to_dict(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        endpoint = RegistrationEndpoint(client_service)
        response = await endpoint({
            "redirect_uris": ["https://app.example.com/callback"],
            "client_name": "Test",
        })
        d = response.to_dict()
        assert d["client_id"] == response.client_id
        assert d["client_name"] == "Test"
        assert d["redirect_uris"] == ["https://app.example.com/callback"]


# =============================================================================
# CORS helpers
# =============================================================================


class TestOriginFromURL:
    def test_simple_https(self) -> None:
        assert origin_from_url("https://app.example.com/callback") == (
            "https://app.example.com"
        )

    def test_with_port(self) -> None:
        assert origin_from_url("https://app.example.com:8443/callback") == (
            "https://app.example.com:8443"
        )

    def test_http(self) -> None:
        assert origin_from_url("http://localhost:8000/callback") == (
            "http://localhost:8000"
        )

    def test_custom_scheme_returns_none(self) -> None:
        assert origin_from_url("myapp://callback") is None

    def test_invalid_url(self) -> None:
        assert origin_from_url("") is None

    def test_no_host(self) -> None:
        assert origin_from_url("https:///path") is None


class TestIsOriginAllowed:
    def test_allowed(self) -> None:
        allowed = {"https://app.example.com"}
        assert is_origin_allowed("https://app.example.com", allowed)

    def test_not_allowed(self) -> None:
        allowed = {"https://app.example.com"}
        assert not is_origin_allowed("https://evil.example.com", allowed)

    def test_case_insensitive_host(self) -> None:
        allowed = {"https://app.example.com"}
        assert is_origin_allowed("https://APP.example.COM", allowed)

    def test_empty_origin(self) -> None:
        assert not is_origin_allowed("", {"https://example.com"})


@pytest.mark.anyio
class TestCollectAllowedOrigins:
    async def test_empty_clients(
        self,
        client_service: OAuthClientService[MockClient],
    ) -> None:
        origins = await collect_allowed_origins(client_service)
        assert origins == set()

    async def test_with_clients(
        self,
        client_storage: MockStorage[MockClient],
        client_service: OAuthClientService[MockClient],
    ) -> None:
        import json

        await client_storage.create(
            client_id="client_1",
            redirect_uris=json.dumps([
                "https://app1.example.com/callback",
                "https://app1.example.com/other",
            ]),
        )
        await client_storage.create(
            client_id="client_2",
            redirect_uris=json.dumps(["https://app2.example.com/callback"]),
        )
        origins = await collect_allowed_origins(client_service)
        assert "https://app1.example.com" in origins
        assert "https://app2.example.com" in origins
        # Two clients, two unique origins (app1's two URIs share one origin)
        assert len(origins) == 2

    async def test_skips_inactive_clients(
        self,
        client_storage: MockStorage[MockClient],
        client_service: OAuthClientService[MockClient],
    ) -> None:
        import json

        await client_storage.create(
            client_id="active",
            is_active=True,
            redirect_uris=json.dumps(["https://active.example.com/cb"]),
        )
        await client_storage.create(
            client_id="inactive",
            is_active=False,
            redirect_uris=json.dumps(["https://inactive.example.com/cb"]),
        )
        origins = await collect_allowed_origins(client_service)
        assert "https://active.example.com" in origins
        assert "https://inactive.example.com" not in origins


@pytest.mark.anyio
class TestLogoutConfirmation:
    """A logout without a hint NeoZen signed needs the user's say-so."""

    ISSUER = "https://auth.example.com"

    @pytest.fixture
    def keys(self) -> InMemoryKeyManager:
        return InMemoryKeyManager()

    def _endpoint(
        self, client_service: OAuthClientService[MockClient], keys: InMemoryKeyManager
    ) -> EndSessionEndpoint:
        return EndSessionEndpoint(
            client_service, id_token_verifier=IDTokenVerifier(keys, self.ISSUER)
        )

    async def _hint(self, keys: InMemoryKeyManager, client_id: str) -> str:
        return await IDTokenGenerator(keys, self.ISSUER).generate(
            "alice", client_id, ["openid"], lifetime=timedelta(seconds=-60)
        )

    async def test_no_hint_needs_confirmation(
        self, client_service: OAuthClientService[MockClient], keys: InMemoryKeyManager
    ) -> None:
        result = await self._endpoint(client_service, keys)({})
        assert result.require_confirmation

    async def test_verified_hint_even_expired_skips_it(
        self, client_service: OAuthClientService[MockClient], keys: InMemoryKeyManager
    ) -> None:
        hint = await self._hint(keys, "client-1")
        result = await self._endpoint(client_service, keys)({"id_token_hint": hint})
        assert not result.require_confirmation

    async def test_forged_hint_needs_confirmation(
        self, client_service: OAuthClientService[MockClient], keys: InMemoryKeyManager
    ) -> None:
        hint = await self._hint(InMemoryKeyManager(), "client-1")  # other keys
        result = await self._endpoint(client_service, keys)({"id_token_hint": hint})
        assert result.require_confirmation

    async def test_client_id_must_match_the_hint(
        self, client_service: OAuthClientService[MockClient], keys: InMemoryKeyManager
    ) -> None:
        hint = await self._hint(keys, "client-1")
        with pytest.raises(EndSessionError):
            await self._endpoint(client_service, keys)({
                "id_token_hint": hint,
                "client_id": "client-2",
            })
