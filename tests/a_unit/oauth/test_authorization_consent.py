"""Consent submission must not trust the parameters echoed back by the form."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime

import pytest
from pwdlib import PasswordHash

from neozen.core.oauth.client_service import OAuthClientService
from neozen.core.oauth.models import (
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthGrantModel,
)
from neozen.web.oauth.authorization_endpoint import (
    AuthorizationEndpoint,
    AuthorizationRequest,
    AuthorizationResponse,
)
from tests.conftest import MockStorage

REGISTERED_URI = "https://app.example.com/callback"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@dataclasses.dataclass
class Client(OAuthClientModel):
    client_id: str
    client_name: str = "App"
    client_type: str = "confidential"
    redirect_uris: str = json.dumps([REGISTERED_URI])
    allowed_scopes: str = "openid profile"
    allowed_grant_types: str = "authorization_code"
    is_active: bool = True


@dataclasses.dataclass
class Grant(OAuthGrantModel):
    client_id: str
    subject_id: str
    granted_at: datetime
    scope: str


@dataclasses.dataclass
class AuthCode(OAuthAuthorizationCodeModel):
    code: str
    client_id: str
    subject_id: str
    expires_at: datetime
    response_type: str
    redirect_uri: str | None
    scope: str
    code_challenge: str | None
    code_challenge_method: str | None
    nonce: str | None = None


@dataclasses.dataclass
class User:
    id: str = "alice"


@pytest.fixture
def codes() -> MockStorage[AuthCode]:
    return MockStorage(AuthCode)


def _endpoint(
    client: Client, codes: MockStorage[AuthCode], *, require_pkce: bool = True
) -> AuthorizationEndpoint:
    return AuthorizationEndpoint(
        client_service=OAuthClientService(
            MockStorage(Client, [client]), PasswordHash.recommended()
        ),
        grant_repository=MockStorage(Grant),
        authorization_code_repository=codes,
        code_hash_key="test-key",
        require_pkce=require_pkce,
    )


def _consent(**overrides: str) -> dict[str, str | bool]:
    return {
        "client_id": "app",
        "redirect_uri": REGISTERED_URI,
        "scope": "openid",
        "state": "xyz",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        "approved": True,
        **overrides,
    }


async def _submit(
    endpoint: AuthorizationEndpoint,
    payload: dict[str, str | bool],
    subject: User,
) -> AuthorizationResponse:
    """Load the consent page as a browser would, then post the form back.

    The form carries the consent token the page was rendered with.
    """
    query = {k: v for k, v in payload.items() if k != "approved"}
    page = await endpoint.handle_authorization_request(
        {"response_type": "code", **query}, subject
    )
    if page.consent_data and page.consent_data.consent_token:
        payload = {"consent_token": page.consent_data.consent_token, **payload}
    return await endpoint.handle_consent(payload, subject)


@pytest.mark.anyio
class TestHandleConsent:
    async def test_valid_consent_issues_code(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        response = await _submit(_endpoint(Client("app"), codes), _consent(), User())
        assert response.error is None
        assert response.code
        assert response.redirect_uri == REGISTERED_URI

    async def test_unregistered_redirect_uri_is_rejected(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        response = await _submit(
            _endpoint(Client("app"), codes),
            _consent(redirect_uri="https://evil.example.com/steal"),
            User(),
        )
        assert response.error == "invalid_request"
        assert response.redirect_uri is None
        assert await codes.count() == 0

    async def test_denial_with_unregistered_redirect_uri_does_not_redirect(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        response = await _submit(
            _endpoint(Client("app"), codes),
            _consent(redirect_uri="https://evil.example.com/", approved=False),
            User(),
        )
        assert response.redirect_uri is None

    async def test_scope_beyond_client_allowance_is_rejected(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        response = await _submit(
            _endpoint(Client("app"), codes), _consent(scope="openid admin"), User()
        )
        assert response.error == "invalid_scope"
        assert await codes.count() == 0

    async def test_public_client_cannot_downgrade_to_plain(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        client = Client("app", client_type="public")
        response = await _submit(
            _endpoint(client, codes), _consent(code_challenge_method="plain"), User()
        )
        assert response.error == "invalid_request"
        assert await codes.count() == 0


def _consent_without_pkce() -> dict[str, str | bool]:
    payload = _consent()
    del payload["code_challenge"], payload["code_challenge_method"]
    return payload


@pytest.mark.anyio
class TestRequirePKCE:
    async def test_pkce_required_by_default(self, codes: MockStorage[AuthCode]) -> None:
        response = await _submit(
            _endpoint(Client("app"), codes), _consent_without_pkce(), User()
        )
        assert response.error == "invalid_request"
        assert await codes.count() == 0

    async def test_confidential_client_may_skip_pkce_when_not_required(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        endpoint = _endpoint(Client("app"), codes, require_pkce=False)
        response = await _submit(endpoint, _consent_without_pkce(), User())
        assert response.code
        [code] = await codes.get_many_by()
        assert code.code_challenge is None
        assert code.code_challenge_method is None

    async def test_public_client_always_needs_pkce(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        client = Client("app", client_type="public")
        endpoint = _endpoint(client, codes, require_pkce=False)
        response = await _submit(endpoint, _consent_without_pkce(), User())
        assert response.error == "invalid_request"
        assert await codes.count() == 0

    async def test_empty_pkce_form_fields_count_as_absent(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        """A consent form renders absent values as empty hidden fields."""
        endpoint = _endpoint(Client("app"), codes, require_pkce=False)
        payload = _consent(code_challenge="", code_challenge_method="")
        response = await _submit(endpoint, payload, User())
        assert response.code


@pytest.mark.anyio
class TestExistingGrant:
    """A grant skips consent only for the scopes it covers."""

    async def _authorize(
        self, endpoint: AuthorizationEndpoint, scope: str
    ) -> AuthorizationResponse:
        query = {k: v for k, v in _consent(scope=scope).items() if k != "approved"}
        return await endpoint.handle_authorization_request(
            {"response_type": "code", **query}, User()
        )

    async def test_covered_scope_skips_consent(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        endpoint = _endpoint(Client("app"), codes)
        await _submit(endpoint, _consent(scope="openid profile"), User())

        response = await self._authorize(endpoint, "openid")

        assert response.code

    async def test_wider_scope_needs_consent_again(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        endpoint = _endpoint(Client("app"), codes)
        await _submit(endpoint, _consent(scope="openid"), User())

        response = await self._authorize(endpoint, "openid profile")

        assert response.requires_consent
        assert response.code is None

    async def test_consent_widens_the_grant(self, codes: MockStorage[AuthCode]) -> None:
        endpoint = _endpoint(Client("app"), codes)
        await _submit(endpoint, _consent(scope="openid"), User())
        await _submit(endpoint, _consent(scope="profile"), User())

        response = await self._authorize(endpoint, "openid profile")

        assert response.code


@pytest.mark.anyio
async def test_defaulted_redirect_uri_is_not_recorded(
    codes: MockStorage[AuthCode],
) -> None:
    """The token request need not repeat a redirect_uri it never sent."""
    payload = _consent()
    del payload["redirect_uri"]
    response = await _submit(_endpoint(Client("app"), codes), payload, User())
    assert response.redirect_uri == REGISTERED_URI
    [code] = await codes.get_many_by()
    assert code.redirect_uri is None


@pytest.mark.anyio
async def test_redirect_uri_is_required_with_several_registered(
    codes: MockStorage[AuthCode],
) -> None:
    client = Client(
        "app", redirect_uris=json.dumps([REGISTERED_URI, "https://app.example.com/b"])
    )
    payload = _consent()
    del payload["redirect_uri"]
    response = await _submit(_endpoint(client, codes), payload, User())
    assert response.error == "invalid_request"
    assert response.redirect_uri is None


def test_redirect_keeps_the_registered_query_string() -> None:
    response = AuthorizationResponse(
        redirect_uri="https://app.example.com/cb?tenant=a", code="c", state="s"
    )
    assert (
        response.get_redirect_url()
        == "https://app.example.com/cb?tenant=a&code=c&state=s"
    )


@pytest.mark.anyio
async def test_nonce_is_recorded_on_the_code(codes: MockStorage[AuthCode]) -> None:
    payload = _consent(nonce="n-0S6_WzA2Mj")
    await _submit(_endpoint(Client("app"), codes), payload, User())
    [code] = await codes.get_many_by()
    assert code.nonce == "n-0S6_WzA2Mj"


@pytest.mark.anyio
class TestConsentToken:
    """The consent POST must come from the page NeoZen rendered (CSRF)."""

    async def _token(
        self, endpoint: AuthorizationEndpoint, subject: User, **overrides: str
    ) -> str:
        query = {k: v for k, v in _consent(**overrides).items() if k != "approved"}
        page = await endpoint.handle_authorization_request(
            {"response_type": "code", **query}, subject
        )
        assert page.consent_data
        assert page.consent_data.consent_token
        return page.consent_data.consent_token

    async def test_missing_token_is_refused(self, codes: MockStorage[AuthCode]) -> None:
        endpoint = _endpoint(Client("app"), codes)
        response = await endpoint.handle_consent(_consent(), User())
        assert response.error == "invalid_request"
        assert response.redirect_uri is None
        assert await codes.count() == 0

    async def test_token_of_another_subject_is_refused(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        endpoint = _endpoint(Client("app"), codes)
        token = await self._token(endpoint, User(id="mallory"))
        payload = {**_consent(), "consent_token": token}
        response = await endpoint.handle_consent(payload, User())
        assert response.error == "invalid_request"
        assert await codes.count() == 0

    async def test_token_does_not_cover_a_changed_scope(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        endpoint = _endpoint(Client("app"), codes)
        token = await self._token(endpoint, User(), scope="openid")
        payload = {**_consent(scope="openid profile"), "consent_token": token}
        response = await endpoint.handle_consent(payload, User())
        assert response.error == "invalid_request"
        assert await codes.count() == 0

    async def test_expired_token_is_refused(self, codes: MockStorage[AuthCode]) -> None:
        endpoint = _endpoint(Client("app"), codes)
        request = AuthorizationRequest.model_validate({
            "response_type": "code",
            **{k: v for k, v in _consent().items() if k != "approved"},
        })
        token = endpoint._consent_token("alice", request, expires=1)
        payload = {**_consent(), "consent_token": token}
        response = await endpoint.handle_consent(payload, User())
        assert response.error == "invalid_request"
