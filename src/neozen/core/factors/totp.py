"""TOTP (Time-based One-Time Password) authentication factor for NeoZen.

Implements RFC 6238 TOTP with:
- Enrollment with QR code generation
- Authentication with code verification
- Backup codes for recovery
"""

from __future__ import annotations

import base64
import io
import secrets
import typing
from dataclasses import dataclass, field
from datetime import UTC, datetime

from neozen.core.exceptions import NeoZenException

# Error messages
_PYOTP_REQUIRED = "pyotp is required for TOTP support"
_NO_ENROLLMENT_PENDING = "No TOTP enrollment pending"


class TOTPError(NeoZenException):
    """Base exception for TOTP errors."""


class TOTPNotEnabledError(TOTPError):
    """Raised when TOTP is not enabled for a subject."""

    def __init__(self) -> None:
        super().__init__("TOTP is not enabled for this account")


class InvalidTOTPCodeError(TOTPError):
    """Raised when a TOTP code is invalid."""

    def __init__(self) -> None:
        super().__init__("Invalid TOTP code")


class InvalidBackupCodeError(TOTPError):
    """Raised when a backup code is invalid."""

    def __init__(self) -> None:
        super().__init__("Invalid or already used backup code")


class TOTPAlreadyEnabledError(TOTPError):
    """Raised when trying to enable TOTP that's already enabled."""

    def __init__(self) -> None:
        super().__init__("TOTP is already enabled for this account")


class TOTPSubjectModel(typing.Protocol):
    """Protocol for subjects with TOTP support."""

    id: str
    totp_secret: str | None
    totp_enabled: bool
    totp_confirmed_at: datetime | None


class BackupCodeModel(typing.Protocol):
    """Protocol for backup code records."""

    id: str
    subject_id: str
    code_hash: str
    used_at: datetime | None
    created_at: datetime


class BackupCodeRepositoryProtocol[Model: BackupCodeModel](typing.Protocol):
    """Protocol for backup code storage."""

    async def get_many_by(
        self,
        *,
        offset: int = 0,
        limit: int | None = None,
        **filters: typing.Any,
    ) -> list[Model]: ...

    async def get_one_by(self, **filters: typing.Any) -> Model: ...

    async def create(self, **data: typing.Any) -> Model: ...

    async def update_obj(self, obj: Model, **data: typing.Any) -> Model: ...

    async def delete(self, obj: Model) -> None: ...


class SubjectRepositoryProtocol[S: TOTPSubjectModel](typing.Protocol):
    """Protocol for subject storage."""

    async def update_obj(self, obj: S, **data: typing.Any) -> S: ...


class PasswordHasherProtocol(typing.Protocol):
    """Protocol for password hashers (used for backup codes)."""

    def verify_and_update(
        self, password: str | bytes, hash: str | bytes
    ) -> tuple[bool, str | None]: ...

    def hash(
        self,
        password: str | bytes,
        *,
        salt: bytes | None = None,
    ) -> str: ...


@dataclass(frozen=True)
class TOTPConfig:
    """Configuration for TOTP factor.

    Attributes:
        issuer: The issuer name shown in authenticator apps.
        digits: Number of digits in TOTP code (default 6).
        interval: Time interval in seconds (default 30).
        algorithm: Hash algorithm (default SHA1 for compatibility).
        backup_code_count: Number of backup codes to generate.
        backup_code_length: Length of each backup code.

    """

    issuer: str = "NeoZen"
    digits: int = 6
    interval: int = 30
    algorithm: str = "SHA1"
    backup_code_count: int = 10
    backup_code_length: int = 8


@dataclass(frozen=True)
class TOTPEnrollmentResult:
    """Result of TOTP enrollment initiation.

    Attributes:
        secret: The base32-encoded secret key.
        provisioning_uri: The otpauth:// URI for QR codes.
        qr_code_data_uri: Base64 data URI of QR code image.

    """

    secret: str
    provisioning_uri: str
    qr_code_data_uri: str | None = None


def _render_qr_data_uri(provisioning_uri: str) -> str:
    """Render the provisioning URI as a base64-encoded PNG data URI.

    Raises ``ImportError`` if the optional ``qrcode`` dependency is not
    installed; callers decide whether that's a hard failure or a soft
    "no QR code today" outcome.
    """
    import qrcode  # noqa: PLC0415

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")  # type: ignore[call-arg]  # ty: ignore[unknown-argument]
    buffer.seek(0)
    base64_data = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{base64_data}"


@dataclass
class TOTPFactor[S: TOTPSubjectModel]:
    """TOTP-based two-factor authentication.

    Provides enrollment, verification, and backup code management
    following RFC 6238.
    """

    config: TOTPConfig
    subject_repository: SubjectRepositoryProtocol[S]
    backup_code_repository: BackupCodeRepositoryProtocol[typing.Any] | None = None
    hasher: PasswordHasherProtocol | None = None
    id_generator: typing.Callable[[], str] | None = None
    _pyotp: typing.Any = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Import pyotp lazily."""
        try:
            import pyotp  # noqa: PLC0415

            self._pyotp = pyotp
        except ImportError:
            pass

    def _generate_id(self) -> str:
        """Generate a unique ID."""
        if self.id_generator:
            return self.id_generator()
        return secrets.token_hex(16)

    def _generate_secret(self) -> str:
        """Generate a new TOTP secret."""
        if self._pyotp is None:
            raise TOTPError(_PYOTP_REQUIRED)
        return self._pyotp.random_base32()

    def _get_totp(self, secret: str) -> typing.Any:
        """Create a TOTP instance for the given secret."""
        if self._pyotp is None:
            raise TOTPError(_PYOTP_REQUIRED)
        return self._pyotp.TOTP(
            secret,
            digits=self.config.digits,
            interval=self.config.interval,
        )

    def _generate_qr_code(self, provisioning_uri: str) -> str | None:
        """Generate a QR code data URI for the provisioning URI.

        Returns None if the optional ``qrcode`` dependency is not installed.
        """
        try:
            return _render_qr_data_uri(provisioning_uri)
        except ImportError:
            return None

    def _generate_backup_codes(self) -> list[str]:
        """Generate a set of backup codes."""
        codes = []
        for _ in range(self.config.backup_code_count):
            # Generate alphanumeric code, uppercase for readability
            code = "".join(
                secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
                for _ in range(self.config.backup_code_length)
            )
            # Format as XXXX-XXXX for 8 char codes
            if len(code) == 8:
                code = f"{code[:4]}-{code[4:]}"
            codes.append(code)
        return codes

    def _normalize_backup_code(self, code: str) -> str:
        """Normalize a backup code by removing dashes and uppercasing."""
        return code.replace("-", "").upper()

    async def begin_enrollment(
        self,
        subject: S,
        account_name: str | None = None,
    ) -> TOTPEnrollmentResult:
        """Begin TOTP enrollment for a subject.

        Generates a new secret but does NOT enable TOTP until confirmed.

        Args:
            subject: The subject to enroll.
            account_name: The account name shown in authenticator apps.

        Returns:
            Enrollment result with secret and QR code.

        Raises:
            TOTPAlreadyEnabledError: If TOTP is already enabled.

        """
        if subject.totp_enabled:
            raise TOTPAlreadyEnabledError

        if self._pyotp is None:
            raise TOTPError(_PYOTP_REQUIRED)

        secret = self._generate_secret()

        # Store secret but don't enable yet
        await self.subject_repository.update_obj(
            subject,
            totp_secret=secret,
            totp_enabled=False,
            totp_confirmed_at=None,
        )

        totp = self._get_totp(secret)
        provisioning_uri = totp.provisioning_uri(
            name=account_name or subject.id,
            issuer_name=self.config.issuer,
        )

        qr_code = self._generate_qr_code(provisioning_uri)

        return TOTPEnrollmentResult(
            secret=secret,
            provisioning_uri=provisioning_uri,
            qr_code_data_uri=qr_code,
        )

    async def confirm_enrollment(
        self,
        subject: S,
        code: str,
    ) -> tuple[S, list[str]]:
        """Confirm TOTP enrollment by verifying a code.

        Args:
            subject: The subject to confirm enrollment for.
            code: The TOTP code to verify.

        Returns:
            Tuple of updated subject and list of backup codes.

        Raises:
            TOTPError: If no enrollment is pending.
            InvalidTOTPCodeError: If the code is invalid.

        """
        if subject.totp_secret is None:
            raise TOTPError(_NO_ENROLLMENT_PENDING)

        if subject.totp_enabled:
            raise TOTPAlreadyEnabledError

        totp = self._get_totp(subject.totp_secret)
        if not totp.verify(code, valid_window=1):
            raise InvalidTOTPCodeError

        # Enable TOTP
        updated_subject = await self.subject_repository.update_obj(
            subject,
            totp_enabled=True,
            totp_confirmed_at=datetime.now(UTC),
        )

        # Generate backup codes
        backup_codes = await self._generate_and_store_backup_codes(subject.id)

        return updated_subject, backup_codes

    async def _generate_and_store_backup_codes(self, subject_id: str) -> list[str]:
        """Generate and store backup codes."""
        if self.backup_code_repository is None or self.hasher is None:
            return []

        # Delete existing backup codes
        existing = await self.backup_code_repository.get_many_by(subject_id=subject_id)
        for code in existing:
            await self.backup_code_repository.delete(code)

        # Generate new codes
        codes = self._generate_backup_codes()
        now = datetime.now(UTC)

        for code in codes:
            normalized = self._normalize_backup_code(code)
            code_hash = self.hasher.hash(normalized)
            await self.backup_code_repository.create(
                id=self._generate_id(),
                subject_id=subject_id,
                code_hash=code_hash,
                used_at=None,
                created_at=now,
            )

        return codes

    async def authenticate(
        self,
        subject: S,
        code: str,
    ) -> bool:
        """Authenticate using a TOTP code.

        Args:
            subject: The subject to authenticate.
            code: The TOTP code to verify.

        Returns:
            True if authentication succeeds.

        Raises:
            TOTPNotEnabledError: If TOTP is not enabled.
            InvalidTOTPCodeError: If the code is invalid.

        """
        if not subject.totp_enabled or subject.totp_secret is None:
            raise TOTPNotEnabledError

        totp = self._get_totp(subject.totp_secret)
        if not totp.verify(code, valid_window=1):
            raise InvalidTOTPCodeError

        return True

    async def use_backup_code(
        self,
        subject: S,
        code: str,
    ) -> bool:
        """Authenticate using a backup code.

        Args:
            subject: The subject to authenticate.
            code: The backup code to use.

        Returns:
            True if authentication succeeds.

        Raises:
            TOTPNotEnabledError: If TOTP is not enabled.
            InvalidBackupCodeError: If the code is invalid or already used.

        """
        if not subject.totp_enabled:
            raise TOTPNotEnabledError

        if self.backup_code_repository is None or self.hasher is None:
            raise InvalidBackupCodeError

        normalized = self._normalize_backup_code(code)

        # Find matching unused backup code
        backup_codes = await self.backup_code_repository.get_many_by(
            subject_id=subject.id,
            used_at=None,
        )

        for backup_code in backup_codes:
            is_match, _ = self.hasher.verify_and_update(
                normalized, backup_code.code_hash
            )
            if is_match:
                # Mark as used
                await self.backup_code_repository.update_obj(
                    backup_code,
                    used_at=datetime.now(UTC),
                )
                return True

        raise InvalidBackupCodeError

    async def disable(self, subject: S) -> S:
        """Disable TOTP for a subject.

        Args:
            subject: The subject to disable TOTP for.

        Returns:
            The updated subject.

        """
        # Delete backup codes
        if self.backup_code_repository:
            existing = await self.backup_code_repository.get_many_by(
                subject_id=subject.id
            )
            for code in existing:
                await self.backup_code_repository.delete(code)

        # Disable TOTP
        return await self.subject_repository.update_obj(
            subject,
            totp_secret=None,
            totp_enabled=False,
            totp_confirmed_at=None,
        )

    async def regenerate_backup_codes(self, subject: S) -> list[str]:
        """Regenerate backup codes for a subject.

        Args:
            subject: The subject to regenerate codes for.

        Returns:
            List of new backup codes.

        Raises:
            TOTPNotEnabledError: If TOTP is not enabled.

        """
        if not subject.totp_enabled:
            raise TOTPNotEnabledError

        return await self._generate_and_store_backup_codes(subject.id)

    async def get_remaining_backup_codes_count(self, subject: S) -> int:
        """Get the count of remaining unused backup codes.

        Args:
            subject: The subject to check.

        Returns:
            Number of remaining unused backup codes.

        """
        if self.backup_code_repository is None:
            return 0

        codes = await self.backup_code_repository.get_many_by(
            subject_id=subject.id,
            used_at=None,
        )
        return len(codes)


__all__ = [
    "BackupCodeModel",
    "BackupCodeRepositoryProtocol",
    "InvalidBackupCodeError",
    "InvalidTOTPCodeError",
    "TOTPAlreadyEnabledError",
    "TOTPConfig",
    "TOTPEnrollmentResult",
    "TOTPError",
    "TOTPFactor",
    "TOTPNotEnabledError",
    "TOTPSubjectModel",
]
