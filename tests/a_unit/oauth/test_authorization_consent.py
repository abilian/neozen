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
from neozen.web.oauth.authorization_endpoint import AuthorizationEndpoint
from tests.conftest import MockStorage

REGISTERED_URI = "https://app.example.com/callback"
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@dataclasses.dataclass
class Client(OAuthClientModel):
    client_id: str
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


@pytest.mark.anyio
class TestHandleConsent:
    async def test_valid_consent_issues_code(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        response = await _endpoint(Client("app"), codes).handle_consent(
            _consent(), User()
        )
        assert response.error is None
        assert response.code
        assert response.redirect_uri == REGISTERED_URI

    async def test_unregistered_redirect_uri_is_rejected(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        response = await _endpoint(Client("app"), codes).handle_consent(
            _consent(redirect_uri="https://evil.example.com/steal"), User()
        )
        assert response.error == "invalid_request"
        assert response.redirect_uri is None
        assert await codes.count() == 0

    async def test_denial_with_unregistered_redirect_uri_does_not_redirect(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        response = await _endpoint(Client("app"), codes).handle_consent(
            _consent(redirect_uri="https://evil.example.com/", approved=False),
            User(),
        )
        assert response.redirect_uri is None

    async def test_scope_beyond_client_allowance_is_rejected(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        response = await _endpoint(Client("app"), codes).handle_consent(
            _consent(scope="openid admin"), User()
        )
        assert response.error == "invalid_scope"
        assert await codes.count() == 0

    async def test_public_client_cannot_downgrade_to_plain(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        client = Client("app", client_type="public")
        response = await _endpoint(client, codes).handle_consent(
            _consent(code_challenge_method="plain"), User()
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
        response = await _endpoint(Client("app"), codes).handle_consent(
            _consent_without_pkce(), User()
        )
        assert response.error == "invalid_request"
        assert await codes.count() == 0

    async def test_confidential_client_may_skip_pkce_when_not_required(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        endpoint = _endpoint(Client("app"), codes, require_pkce=False)
        response = await endpoint.handle_consent(_consent_without_pkce(), User())
        assert response.code
        [code] = await codes.get_many_by()
        assert code.code_challenge is None
        assert code.code_challenge_method is None

    async def test_public_client_always_needs_pkce(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        client = Client("app", client_type="public")
        endpoint = _endpoint(client, codes, require_pkce=False)
        response = await endpoint.handle_consent(_consent_without_pkce(), User())
        assert response.error == "invalid_request"
        assert await codes.count() == 0

    async def test_empty_pkce_form_fields_count_as_absent(
        self, codes: MockStorage[AuthCode]
    ) -> None:
        """A consent form renders absent values as empty hidden fields."""
        endpoint = _endpoint(Client("app"), codes, require_pkce=False)
        payload = _consent(code_challenge="", code_challenge_method="")
        response = await endpoint.handle_consent(payload, User())
        assert response.code


@pytest.mark.anyio
async def test_defaulted_redirect_uri_is_not_recorded(
    codes: MockStorage[AuthCode],
) -> None:
    """The token request need not repeat a redirect_uri it never sent."""
    payload = _consent()
    del payload["redirect_uri"]
    response = await _endpoint(Client("app"), codes).handle_consent(payload, User())
    assert response.redirect_uri == REGISTERED_URI
    [code] = await codes.get_many_by()
    assert code.redirect_uri is None
