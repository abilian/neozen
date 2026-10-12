"""WebAuthn/Passkey authentication factor for NeoZen.

Implements WebAuthn (FIDO2) passwordless authentication with:
- Passkey registration
- Passkey authentication
- Credential management
"""

from __future__ import annotations

import secrets
import typing
from dataclasses import dataclass, field
from datetime import UTC, datetime

from neozen.core.exceptions import NeoZenException
from neozen.core.repository import DoesNotExist
from neozen.core.subject import Subject


class WebAuthnError(NeoZenException):
    """Base exception for WebAuthn errors."""


class WebAuthnRegistrationError(WebAuthnError):
    """Raised when WebAuthn registration fails."""


class WebAuthnAuthenticationError(WebAuthnError):
    """Raised when WebAuthn authentication fails."""


class WebAuthnCredentialNotFoundError(WebAuthnError):
    """Raised when a credential is not found."""

    def __init__(self, credential_id: str | None = None) -> None:
        msg = "WebAuthn credential not found"
        if credential_id:
            msg = f"WebAuthn credential not found: {credential_id}"
        super().__init__(msg)


class WebAuthnChallengeExpiredError(WebAuthnError):
    """Raised when a challenge has expired."""

    def __init__(self) -> None:
        super().__init__("WebAuthn challenge has expired")


class WebAuthnCredentialModel(typing.Protocol):
    """Protocol for WebAuthn credential records."""

    id: str
    subject_id: str
    credential_id: str
    public_key: str
    sign_count: int
    transports: str
    device_type: str
    backed_up: bool
    name: str
    created_at: datetime
    last_used_at: datetime | None


class WebAuthnChallengeModel(typing.Protocol):
    """Protocol for WebAuthn challenge records."""

    id: str
    challenge: str
    subject_id: str | None
    operation: str  # "registration" or "authentication"
    expires_at: datetime


class WebAuthnCredentialRepositoryProtocol[Model: WebAuthnCredentialModel](
    typing.Protocol
):
    """Protocol for WebAuthn credential storage."""

    async def get_one_by(self, **filters: typing.Any) -> Model: ...

    async def get_many_by(
        self,
        *,
        offset: int = 0,
        limit: int | None = None,
        **filters: typing.Any,
    ) -> list[Model]: ...

    async def create(self, **data: typing.Any) -> Model: ...

    async def update_obj(self, obj: Model, **data: typing.Any) -> Model: ...

    async def delete(self, obj: Model) -> None: ...


class WebAuthnChallengeRepositoryProtocol[Model: WebAuthnChallengeModel](
    typing.Protocol
):
    """Protocol for WebAuthn challenge storage."""

    async def get_one_by(self, **filters: typing.Any) -> Model: ...

    async def create(self, **data: typing.Any) -> Model: ...

    async def delete(self, obj: Model) -> None: ...


@dataclass(frozen=True)
class WebAuthnConfig:
    """Configuration for WebAuthn factor.

    Attributes:
        rp_id: The relying party ID (usually the domain).
        rp_name: The relying party display name.
        origin: The expected origin (e.g., "https://example.com").
        challenge_timeout_seconds: How long challenges are valid.
        user_verification: User verification requirement.

    """

    rp_id: str
    rp_name: str
    origin: str
    challenge_timeout_seconds: int = 300  # 5 minutes
    user_verification: str = "preferred"  # "required", "preferred", "discouraged"


@dataclass(frozen=True)
class RegistrationOptions:
    """Options for WebAuthn registration.

    Attributes:
        options_json: JSON-serializable options for the browser.
        challenge: The challenge value.

    """

    options_json: dict[str, typing.Any]
    challenge: str


@dataclass(frozen=True)
class AuthenticationOptions:
    """Options for WebAuthn authentication.

    Attributes:
        options_json: JSON-serializable options for the browser.
        challenge: The challenge value.

    """

    options_json: dict[str, typing.Any]
    challenge: str


def _load_webauthn_modules() -> tuple[typing.Any, typing.Any, typing.Any]:
    """Lazily import the optional ``webauthn`` package and its helpers.

    Returns ``(webauthn, webauthn_structs, webauthn_helpers)``. Raises
    ``ImportError`` if the package isn't installed; callers decide whether
    that's a hard failure (registration / authentication) or a soft no-op
    (``__post_init__`` lazy-load).
    """
    import webauthn  # noqa: PLC0415
    from webauthn import helpers as webauthn_helpers  # noqa: PLC0415
    from webauthn.helpers import structs as webauthn_structs  # noqa: PLC0415

    return webauthn, webauthn_structs, webauthn_helpers


@dataclass
class WebAuthnFactor[S: Subject]:
    """WebAuthn/Passkey authentication factor.

    Provides passwordless authentication using WebAuthn/FIDO2.
    """

    config: WebAuthnConfig
    credential_repository: WebAuthnCredentialRepositoryProtocol[typing.Any]
    challenge_repository: WebAuthnChallengeRepositoryProtocol[typing.Any]
    id_generator: typing.Callable[[], str] | None = None
    _webauthn: typing.Any = field(default=None, repr=False)
    _webauthn_structs: typing.Any = field(default=None, repr=False)
    _webauthn_helpers: typing.Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Import webauthn lazily (no-op if the optional dep is absent)."""
        try:
            modules = _load_webauthn_modules()
        except ImportError:
            return
        object.__setattr__(self, "_webauthn", modules[0])
        object.__setattr__(self, "_webauthn_structs", modules[1])
        object.__setattr__(self, "_webauthn_helpers", modules[2])

    def _generate_id(self) -> str:
        """Generate a unique ID."""
        if self.id_generator:
            return self.id_generator()
        return secrets.token_hex(16)

    def _generate_challenge(self) -> bytes:
        """Generate a cryptographically secure challenge."""
        return secrets.token_bytes(32)

    async def begin_registration(
        self,
        subject: S,
        *,
        user_name: str | None = None,
        user_display_name: str | None = None,
    ) -> RegistrationOptions:
        """Begin WebAuthn registration for a subject.

        Args:
            subject: The subject to register a credential for.
            user_name: The user name (defaults to subject.id).
            user_display_name: The user display name.

        Returns:
            Registration options to pass to the browser.

        Raises:
            WebAuthnError: If webauthn library is not available.

        """
        if self._webauthn is None:
            msg = "webauthn package is required for WebAuthn support"
            raise WebAuthnError(msg)

        # Get existing credentials to exclude
        existing = await self.credential_repository.get_many_by(subject_id=subject.id)
        exclude_credentials = [
            self._webauthn.base64url_to_bytes(cred.credential_id) for cred in existing
        ]

        # Generate registration options
        options = self._webauthn.generate_registration_options(
            rp_id=self.config.rp_id,
            rp_name=self.config.rp_name,
            user_id=subject.id.encode("utf-8"),
            user_name=user_name or subject.id,
            user_display_name=user_display_name or user_name or subject.id,
            exclude_credentials=[
                self._webauthn_structs.PublicKeyCredentialDescriptor(id=cred_id)
                for cred_id in exclude_credentials
            ],
            authenticator_selection=self._webauthn_structs.AuthenticatorSelectionCriteria(
                user_verification=self._webauthn_structs.UserVerificationRequirement(
                    self.config.user_verification
                ),
            ),
        )

        # Store challenge
        challenge_b64 = self._webauthn_helpers.bytes_to_base64url(options.challenge)
        expires_at = datetime.now(UTC) + __import__("datetime").timedelta(
            seconds=self.config.challenge_timeout_seconds
        )

        await self.challenge_repository.create(
            id=self._generate_id(),
            challenge=challenge_b64,
            subject_id=subject.id,
            operation="registration",
            expires_at=expires_at,
        )

        # Convert to JSON-serializable dict
        options_json = self._webauthn.options_to_json(options)

        return RegistrationOptions(
            options_json=__import__("json").loads(options_json),
            challenge=challenge_b64,
        )

    async def complete_registration(
        self,
        subject: S,
        credential_name: str,
        response: dict[str, typing.Any],
    ) -> typing.Any:
        """Complete WebAuthn registration.

        Args:
            subject: The subject registering.
            credential_name: A name for this credential.
            response: The credential response from the browser.

        Returns:
            The created WebAuthn credential.

        Raises:
            WebAuthnChallengeExpiredError: If the challenge has expired.
            WebAuthnRegistrationError: If registration verification fails.

        """
        if self._webauthn is None:
            msg = "webauthn package is required for WebAuthn support"
            raise WebAuthnError(msg)

        # Get and validate challenge
        try:
            challenge_record = await self.challenge_repository.get_one_by(
                subject_id=subject.id,
                operation="registration",
            )
        except DoesNotExist:
            msg = "No registration challenge found"
            raise WebAuthnRegistrationError(msg) from None

        if datetime.now(UTC) > challenge_record.expires_at:
            await self.challenge_repository.delete(challenge_record)
            raise WebAuthnChallengeExpiredError

        try:
            # Parse the registration response
            credential = self._webauthn_structs.RegistrationCredential.model_validate(
                response
            )

            # Verify the registration
            verification = self._webauthn.verify_registration_response(
                credential=credential,
                expected_challenge=self._webauthn.base64url_to_bytes(
                    challenge_record.challenge
                ),
                expected_rp_id=self.config.rp_id,
                expected_origin=self.config.origin,
            )

            # Store the credential
            credential_record = await self.credential_repository.create(
                id=self._generate_id(),
                subject_id=subject.id,
                credential_id=self._webauthn_helpers.bytes_to_base64url(
                    verification.credential_id
                ),
                public_key=self._webauthn_helpers.bytes_to_base64url(
                    verification.credential_public_key
                ),
                sign_count=verification.sign_count,
                transports=",".join(
                    t.value for t in (credential.response.transports or [])
                ),
                device_type=verification.credential_device_type,
                backed_up=verification.credential_backed_up,
                name=credential_name,
                created_at=datetime.now(UTC),
                last_used_at=None,
            )

            # Clean up challenge
            await self.challenge_repository.delete(challenge_record)

            return credential_record

        except Exception as e:
            if isinstance(
                e, (WebAuthnChallengeExpiredError, WebAuthnRegistrationError)
            ):
                raise
            msg = f"Registration verification failed: {e}"
            raise WebAuthnRegistrationError(msg) from e

    async def begin_authentication(
        self,
        subject: S | None = None,
    ) -> AuthenticationOptions:
        """Begin WebAuthn authentication.

        Args:
            subject: Optional subject to authenticate (for non-discoverable credentials).

        Returns:
            Authentication options to pass to the browser.

        """
        if self._webauthn is None:
            msg = "webauthn package is required for WebAuthn support"
            raise WebAuthnError(msg)

        allow_credentials = []
        subject_id = None

        if subject is not None:
            subject_id = subject.id
            credentials = await self.credential_repository.get_many_by(
                subject_id=subject.id
            )
            allow_credentials = [
                self._webauthn_structs.PublicKeyCredentialDescriptor(
                    id=self._webauthn.base64url_to_bytes(cred.credential_id),
                    transports=[
                        self._webauthn_structs.AuthenticatorTransport(t)
                        for t in cred.transports.split(",")
                        if t
                    ],
                )
                for cred in credentials
            ]

        options = self._webauthn.generate_authentication_options(
            rp_id=self.config.rp_id,
            allow_credentials=allow_credentials or None,
            user_verification=self._webauthn_structs.UserVerificationRequirement(
                self.config.user_verification
            ),
        )

        # Store challenge
        challenge_b64 = self._webauthn_helpers.bytes_to_base64url(options.challenge)
        expires_at = datetime.now(UTC) + __import__("datetime").timedelta(
            seconds=self.config.challenge_timeout_seconds
        )

        await self.challenge_repository.create(
            id=self._generate_id(),
            challenge=challenge_b64,
            subject_id=subject_id,
            operation="authentication",
            expires_at=expires_at,
        )

        options_json = self._webauthn.options_to_json(options)

        return AuthenticationOptions(
            options_json=__import__("json").loads(options_json),
            challenge=challenge_b64,
        )

    async def complete_authentication(
        self,
        response: dict[str, typing.Any],
        challenge: str,
    ) -> tuple[str, typing.Any]:
        """Complete WebAuthn authentication.

        Args:
            response: The assertion response from the browser.
            challenge: The challenge that was sent.

        Returns:
            Tuple of (subject_id, credential_record).

        Raises:
            WebAuthnChallengeExpiredError: If the challenge has expired.
            WebAuthnAuthenticationError: If authentication fails.
            WebAuthnCredentialNotFoundError: If the credential is not found.

        """
        if self._webauthn is None:
            msg = "webauthn package is required for WebAuthn support"
            raise WebAuthnError(msg)

        # Get and validate challenge
        try:
            challenge_record = await self.challenge_repository.get_one_by(
                challenge=challenge,
                operation="authentication",
            )
        except DoesNotExist:
            msg = "No authentication challenge found"
            raise WebAuthnAuthenticationError(msg) from None

        if datetime.now(UTC) > challenge_record.expires_at:
            await self.challenge_repository.delete(challenge_record)
            raise WebAuthnChallengeExpiredError

        try:
            return await self._verify_authentication_inner(challenge_record, response)
        except Exception as e:
            if isinstance(
                e,
                (
                    WebAuthnChallengeExpiredError,
                    WebAuthnAuthenticationError,
                    WebAuthnCredentialNotFoundError,
                ),
            ):
                raise
            msg = f"Authentication verification failed: {e}"
            raise WebAuthnAuthenticationError(msg) from e

    async def _verify_authentication_inner(
        self,
        challenge_record: typing.Any,
        response: dict[str, typing.Any],
    ) -> tuple[str, typing.Any]:
        """Parse + verify the authentication response and update sign count.

        Raises ``WebAuthnCredentialNotFoundError`` if the credential isn't
        registered; any other failure propagates and is wrapped by the
        caller as ``WebAuthnAuthenticationError``.
        """
        credential = self._webauthn_structs.AuthenticationCredential.model_validate(
            response
        )
        credential_id_b64 = self._webauthn_helpers.bytes_to_base64url(credential.raw_id)
        try:
            cred_record = await self.credential_repository.get_one_by(
                credential_id=credential_id_b64
            )
        except DoesNotExist:
            raise WebAuthnCredentialNotFoundError(credential_id_b64) from None

        verification = self._webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=self._webauthn.base64url_to_bytes(
                challenge_record.challenge
            ),
            expected_rp_id=self.config.rp_id,
            expected_origin=self.config.origin,
            credential_public_key=self._webauthn.base64url_to_bytes(
                cred_record.public_key
            ),
            credential_current_sign_count=cred_record.sign_count,
        )

        updated_cred = await self.credential_repository.update_obj(
            cred_record,
            sign_count=verification.new_sign_count,
            last_used_at=datetime.now(UTC),
        )
        await self.challenge_repository.delete(challenge_record)
        return cred_record.subject_id, updated_cred

    async def list_credentials(self, subject: S) -> list[typing.Any]:
        """List all WebAuthn credentials for a subject.

        Args:
            subject: The subject to list credentials for.

        Returns:
            List of credential records.

        """
        return await self.credential_repository.get_many_by(subject_id=subject.id)

    async def delete_credential(self, subject: S, credential_id: str) -> None:
        """Delete a WebAuthn credential.

        Args:
            subject: The subject who owns the credential.
            credential_id: The credential ID to delete.

        Raises:
            WebAuthnCredentialNotFoundError: If the credential is not found.

        """

        try:
            cred = await self.credential_repository.get_one_by(
                subject_id=subject.id,
                credential_id=credential_id,
            )
            await self.credential_repository.delete(cred)
        except DoesNotExist:
            raise WebAuthnCredentialNotFoundError(credential_id) from None

    async def rename_credential(
        self,
        subject: S,
        credential_id: str,
        new_name: str,
    ) -> typing.Any:
        """Rename a WebAuthn credential.

        Args:
            subject: The subject who owns the credential.
            credential_id: The credential ID to rename.
            new_name: The new name for the credential.

        Returns:
            The updated credential record.

        Raises:
            WebAuthnCredentialNotFoundError: If the credential is not found.

        """

        try:
            cred = await self.credential_repository.get_one_by(
                subject_id=subject.id,
                credential_id=credential_id,
            )
            return await self.credential_repository.update_obj(cred, name=new_name)
        except DoesNotExist:
            raise WebAuthnCredentialNotFoundError(credential_id) from None


__all__ = [
    "AuthenticationOptions",
    "RegistrationOptions",
    "WebAuthnAuthenticationError",
    "WebAuthnChallengeExpiredError",
    "WebAuthnChallengeModel",
    "WebAuthnChallengeRepositoryProtocol",
    "WebAuthnConfig",
    "WebAuthnCredentialModel",
    "WebAuthnCredentialNotFoundError",
    "WebAuthnCredentialRepositoryProtocol",
    "WebAuthnError",
    "WebAuthnFactor",
    "WebAuthnRegistrationError",
]
