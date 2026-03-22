"""Protocol definitions for authentication factors."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class FactorProtocol(Protocol):
    """Protocol for authentication factors.

    Authentication factors are methods of verifying identity, such as:
    - Knowledge factors (password, PIN)
    - Possession factors (TOTP, SMS, hardware key)
    - Inherence factors (biometrics)

    Factors support enrollment (setting up the factor) and authentication
    (verifying identity). Not all factors require explicit enrollment
    (e.g., password may be set during registration).

    Example implementation:
        class MyFactor:
            @property
            def factor_id(self) -> str:
                return "my_factor"

            @property
            def display_name(self) -> str:
                return "My Custom Factor"

            @property
            def factor_type(self) -> str:
                return "possession"

            async def is_enrolled(self, subject_id: str) -> bool:
                # Check if subject has this factor enrolled
                ...

            async def supports_subject(self, subject_id: str) -> bool:
                # Check if this factor can be used by the subject
                return True
    """

    @property
    def factor_id(self) -> str:
        """Unique identifier for this factor type.

        Should be a short, lowercase string like "password", "totp", "webauthn".
        """
        ...

    @property
    def display_name(self) -> str:
        """Human-readable name for UI display.

        Examples: "Password", "Authenticator App", "Security Key"
        """
        ...

    @property
    def factor_type(self) -> str:
        """The type of factor.

        One of:
        - "knowledge": Something the user knows (password, PIN)
        - "possession": Something the user has (phone, hardware key)
        - "inherence": Something the user is (biometrics)
        """
        ...

    async def is_enrolled(self, subject_id: str) -> bool:
        """Check if the subject has this factor enrolled.

        Args:
            subject_id: The subject to check.

        Returns:
            True if the subject has enrolled this factor.
        """
        ...

    async def supports_subject(self, subject_id: str) -> bool:
        """Check if this factor can be used by the subject.

        Some factors may have requirements (e.g., email verified).
        Default should return True.

        Args:
            subject_id: The subject to check.

        Returns:
            True if the subject can use this factor.
        """
        ...


@runtime_checkable
class EnrollableFactorProtocol(FactorProtocol, Protocol):
    """Protocol for factors that support explicit enrollment.

    Some factors require a multi-step enrollment process:
    1. begin_enrollment - Start enrollment, return setup data
    2. complete_enrollment - Verify and finalize enrollment
    """

    async def begin_enrollment(
        self,
        subject_id: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Begin the enrollment process.

        Args:
            subject_id: The subject enrolling.
            **kwargs: Factor-specific enrollment options.

        Returns:
            Enrollment data (e.g., QR code, challenge).
        """
        ...

    async def complete_enrollment(
        self,
        subject_id: str,
        verification: Any,
        **kwargs: Any,
    ) -> bool:
        """Complete and verify enrollment.

        Args:
            subject_id: The subject completing enrollment.
            verification: Verification data (e.g., TOTP code, attestation).
            **kwargs: Additional options.

        Returns:
            True if enrollment was successful.
        """
        ...

    async def unenroll(self, subject_id: str) -> None:
        """Remove this factor from a subject.

        Args:
            subject_id: The subject to unenroll.
        """
        ...


@runtime_checkable
class AuthenticatingFactorProtocol(FactorProtocol, Protocol):
    """Protocol for factors that can authenticate.

    Most factors support authentication (verifying identity).
    """

    async def authenticate(
        self,
        subject_id: str,
        credential: Any,
        **kwargs: Any,
    ) -> bool:
        """Verify authentication using this factor.

        Args:
            subject_id: The subject authenticating.
            credential: The credential to verify (password, TOTP code, etc.)
            **kwargs: Additional context.

        Returns:
            True if authentication succeeded.
        """
        ...


@runtime_checkable
class ChallengingFactorProtocol(FactorProtocol, Protocol):
    """Protocol for factors that use challenge-response.

    Some factors (like WebAuthn) require a challenge to be generated
    before authentication can proceed.
    """

    async def begin_authentication(
        self,
        subject_id: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Begin authentication by generating a challenge.

        Args:
            subject_id: The subject authenticating.
            **kwargs: Additional options.

        Returns:
            Challenge data to send to the client.
        """
        ...

    async def complete_authentication(
        self,
        subject_id: str,
        response: Any,
        **kwargs: Any,
    ) -> bool:
        """Complete authentication by verifying the response.

        Args:
            subject_id: The subject authenticating.
            response: The client's response to the challenge.
            **kwargs: Additional context.

        Returns:
            True if authentication succeeded.
        """
        ...
