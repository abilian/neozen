"""OAuth 2.1 Authorization Code Grant implementation for NeoZen."""

from __future__ import annotations

import typing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import dishka
from pydantic import AnyUrl, BaseModel, Field, HttpUrl, ValidationError

from neozen.core.crypto import generate_token_hash_pair
from neozen.core.oauth.exceptions import (
    AuthorizationErrorCode,
    AuthorizationRedirectError,
    InvalidClientError,
    UnauthenticatedSubjectError,
)
from neozen.core.oauth.models import (
    OAuthAuthorizationCodeModel,
    OAuthClientModel,
    OAuthGrantModel,
)
from neozen.core.oauth.types import CodeChallengeMethod
from neozen.core.repository import DoesNotExist, RepositoryProtocol
from neozen.core.subject import Subject


class MissingOrInvalidClientIDError(InvalidClientError):
    """Error raised when the client_id is missing or invalid in the request."""

    def __init__(self) -> None:
        super().__init__("The 'client_id' parameter is missing or invalid.")


class AuthorizationCodeGrantRedirectionError(AuthorizationRedirectError):
    """Error that should be redirected to the client application.

    Extends AuthorizationRedirectError with error_uri for HTTP redirects.
    """

    error_uri: HttpUrl | None

    def __init__(
        self,
        error: AuthorizationErrorCode,
        error_description: str | None = None,
        error_uri: HttpUrl | None = None,
    ) -> None:
        self.error_uri = error_uri
        super().__init__(error, error_description)


class AuthorizationCodeGrantRequest(BaseModel):
    """Request model for Authorization Code Grant."""

    response_type: str
    client_id: str
    redirect_uri: AnyUrl | None = None
    scope: str | None = None
    state: str | None = None
    code_challenge: typing.Annotated[str, Field(pattern=r"^[A-Za-z0-9\-\._~]{43,128}$")]
    code_challenge_method: CodeChallengeMethod = "plain"


@dataclass
class AuthorizationCodeGrantConsentResponse:
    """Response when user consent is required."""

    client: OAuthClientModel
    scope: str | None
    redirect_uri: str | None
    state: str | None
    code_challenge: str
    code_challenge_method: CodeChallengeMethod


@dataclass
class AuthorizationCodeGrantGrantedResponse[S: Subject]:
    """Response when authorization is granted."""

    subject: S
    client: OAuthClientModel
    code: str
    authorization_code: OAuthAuthorizationCodeModel


_DEFAULT_CODE_PREFIX = "nz_ac_"


class AuthorizationCodeGrant[
    OC: OAuthClientModel,
    OG: OAuthGrantModel,
    OAC: OAuthAuthorizationCodeModel,
]:
    """OAuth 2.1 Authorization Code Grant handler.

    Implements the authorization code flow with PKCE support.
    """

    def __init__(
        self,
        oauth_client_storage: RepositoryProtocol[OC],
        oauth_grant_storage: RepositoryProtocol[OG],
        oauth_authorization_code_storage: RepositoryProtocol[OAC],
        code_hash_key: str,
        code_prefix: str = _DEFAULT_CODE_PREFIX,
    ) -> None:
        self.oauth_client_storage = oauth_client_storage
        self.oauth_grant_storage = oauth_grant_storage
        self.oauth_authorization_code_storage = oauth_authorization_code_storage
        self.code_hash_key = code_hash_key
        self.code_prefix = code_prefix

    async def __call__[S: Subject](
        self, subject: S | None, payload: dict[str, typing.Any]
    ) -> (
        AuthorizationCodeGrantConsentResponse | AuthorizationCodeGrantGrantedResponse[S]
    ):
        """Process an authorization code grant request.

        Args:
            subject: The authenticated subject, or None if not authenticated.
            payload: The request payload containing OAuth parameters.

        Returns:
            Either a consent response (if user hasn't granted access) or
            a granted response (with authorization code).

        Raises:
            UnauthenticatedSubjectError: If subject is not authenticated.
            MissingOrInvalidClientIDError: If client_id is missing or invalid.
            AuthorizationCodeGrantRedirectionError: For other request errors.

        """
        if subject is None:
            raise UnauthenticatedSubjectError

        try:
            request = AuthorizationCodeGrantRequest.model_validate(payload)
        except ValidationError as e:
            errors = e.errors()
            client_id_error = next(
                (err for err in errors if err["loc"] == ("client_id",)), None
            )
            if client_id_error and client_id_error["type"] == "missing":
                raise MissingOrInvalidClientIDError from e
            raise AuthorizationCodeGrantRedirectionError(error="invalid_request") from e

        try:
            client = await self.oauth_client_storage.get_one_by(
                client_id=request.client_id
            )
        except DoesNotExist as e:
            raise MissingOrInvalidClientIDError from e

        try:
            _ = await self.oauth_grant_storage.get_one_by(
                client_id=client.client_id, subject_id=subject.id
            )
        except DoesNotExist:
            return AuthorizationCodeGrantConsentResponse(
                client=client,
                scope=request.scope,
                redirect_uri=str(request.redirect_uri),
                state=request.state,
                code_challenge=request.code_challenge,
                code_challenge_method=request.code_challenge_method,
            )
        else:
            code, code_hash = generate_token_hash_pair(
                self.code_hash_key, prefix=self.code_prefix
            )
            authorization_code = await self.oauth_authorization_code_storage.create(
                code=code_hash,
                client_id=client.client_id,
                subject_id=subject.id,
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
                response_type=request.response_type,
                redirect_uri=str(request.redirect_uri),
                scope=request.scope,
                code_challenge=request.code_challenge,
                code_challenge_method=request.code_challenge_method,
            )
            return AuthorizationCodeGrantGrantedResponse(
                subject=subject,
                client=client,
                code=code,
                authorization_code=authorization_code,
            )


class AuthorizationCodeGrantProvider(dishka.Provider):
    """Dishka provider for Authorization Code Grant."""

    def __init__(
        self, code_hash_key: str, code_prefix: str = _DEFAULT_CODE_PREFIX
    ) -> None:
        super().__init__()
        self.code_hash_key = code_hash_key
        self.code_prefix = code_prefix

    @dishka.provide(scope=dishka.Scope.REQUEST)
    def get_authorization_code_grant[
        OC: OAuthClientModel,
        OG: OAuthGrantModel,
        OAC: OAuthAuthorizationCodeModel,
    ](
        self,
        oauth_client_storage: RepositoryProtocol[OC],
        oauth_grant_storage: RepositoryProtocol[OG],
        oauth_authorization_code_storage: RepositoryProtocol[OAC],
    ) -> AuthorizationCodeGrant[OC, OG, OAC]:
        return AuthorizationCodeGrant(
            oauth_client_storage=oauth_client_storage,
            oauth_grant_storage=oauth_grant_storage,
            oauth_authorization_code_storage=oauth_authorization_code_storage,
            code_hash_key=self.code_hash_key,
            code_prefix=self.code_prefix,
        )


__all__ = [
    "AuthorizationCodeGrant",
    "AuthorizationCodeGrantConsentResponse",
    "AuthorizationCodeGrantGrantedResponse",
    "AuthorizationCodeGrantProvider",
    "AuthorizationCodeGrantRedirectionError",
    "AuthorizationCodeGrantRequest",
    "MissingOrInvalidClientIDError",
]
