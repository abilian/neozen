"""ID Token generation and verification (OIDC Core 1.0 Section 2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from neozen.core.oidc.keys import KeyManager


@dataclass(frozen=True)
class IDTokenClaims:
    """ID Token claims (OIDC Core 1.0 Section 2).

    Required claims: iss, sub, aud, exp, iat
    Conditionally required: auth_time (if max_age requested), nonce
    Optional: standard profile/email claims
    """

    iss: str  # Issuer
    sub: str  # Subject identifier
    aud: str | list[str]  # Audience (client_id)
    exp: int  # Expiration (Unix timestamp)
    iat: int  # Issued at (Unix timestamp)

    # Conditional
    auth_time: int | None = None
    nonce: str | None = None

    # Standard profile claims
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    middle_name: str | None = None
    nickname: str | None = None
    preferred_username: str | None = None
    profile: str | None = None
    picture: str | None = None
    website: str | None = None
    gender: str | None = None
    birthdate: str | None = None
    zoneinfo: str | None = None
    locale: str | None = None
    updated_at: int | None = None

    # Email
    email: str | None = None
    email_verified: bool | None = None

    # Phone
    phone_number: str | None = None
    phone_number_verified: bool | None = None

    # Address
    address: dict[str, Any] | None = None

    # Session
    acr: str | None = None  # Authentication Context Class Reference
    amr: list[str] | None = None  # Authentication Methods References
    azp: str | None = None  # Authorized party

    # Extra/custom claims
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a dict suitable for JWT encoding (omits None fields)."""
        # Standard claims only -- skip None values and the `extra` bucket
        result: dict[str, Any] = {}
        for key, value in self.__dict__.items():
            if key == "extra":
                continue
            if value is None:
                continue
            result[key] = value
        # Merge in extra claims (extra takes lower precedence)
        for key, value in self.extra.items():
            if key not in result:
                result[key] = value
        return result


class IDTokenGenerator:
    """Generates signed ID tokens (JWTs).

    Example:
        generator = IDTokenGenerator(
            key_manager=key_manager,
            issuer="https://auth.example.com",
        )
        token = await generator.generate(
            subject_id="user_123",
            client_id="client_abc",
            scopes=["openid", "email"],
            claims={"email": "alice@example.com"},
            nonce="n-0S6_WzA2Mj",
        )
    """

    def __init__(
        self,
        key_manager: KeyManager,
        issuer: str,
        *,
        default_lifetime: timedelta = timedelta(hours=1),
    ) -> None:
        self.key_manager = key_manager
        self.issuer = issuer
        self.default_lifetime = default_lifetime

    async def generate(
        self,
        subject_id: str,
        client_id: str,
        scopes: list[str],
        *,
        claims: dict[str, Any] | None = None,
        nonce: str | None = None,
        auth_time: datetime | None = None,
        lifetime: timedelta | None = None,
    ) -> str:
        """Generate a signed ID token.

        Args:
            subject_id: The authenticated subject's ID (becomes `sub`).
            client_id: The OAuth client receiving the token (becomes `aud`).
            scopes: Granted scopes -- must include "openid".
            claims: Additional claims (email, name, etc.) to include.
            nonce: Optional nonce from the auth request.
            auth_time: Time of the original authentication.
            lifetime: Token lifetime override.

        Returns:
            The signed JWT as a compact-serialized string.
        """
        # Lazy import: pyjwt is an optional extra
        import jwt  # noqa: PLC0415

        if "openid" not in scopes:
            msg = "ID token requires the 'openid' scope"
            raise ValueError(msg)

        signing_key = await self.key_manager.get_active_signing_key()

        now = datetime.now(UTC)
        exp = now + (lifetime or self.default_lifetime)

        token_claims = IDTokenClaims(
            iss=self.issuer,
            sub=subject_id,
            aud=client_id,
            exp=int(exp.timestamp()),
            iat=int(now.timestamp()),
            auth_time=int(auth_time.timestamp()) if auth_time else None,
            nonce=nonce,
            azp=client_id,
            extra=claims or {},
        )

        return jwt.encode(
            token_claims.to_dict(),
            signing_key.private_pem,
            algorithm=signing_key.alg,
            headers={"kid": signing_key.kid},
        )


class IDTokenVerifier:
    """Verifies ID tokens (used for testing or relying-party flows).

    Production OIDC clients should use a dedicated OIDC client library,
    but this verifier is useful for testing the provider's own tokens.
    """

    def __init__(
        self,
        key_manager: KeyManager,
        issuer: str,
    ) -> None:
        self.key_manager = key_manager
        self.issuer = issuer

    async def verify(
        self,
        token: str,
        *,
        audience: str,
        verify_exp: bool = True,
    ) -> dict[str, Any]:
        """Verify an ID token and return its claims.

        Args:
            token: The JWT to verify.
            audience: Expected audience (client_id).
            verify_exp: Refuse an expired token. A logout hint may be
                expired (OIDC RP-Initiated Logout §2).

        Returns:
            The decoded claims dictionary.

        Raises:
            jwt.InvalidTokenError: If verification fails.
        """
        import jwt  # noqa: PLC0415

        # Get key id from header
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            msg = "ID token missing 'kid' header"
            raise jwt.InvalidTokenError(msg)

        signing_key = await self.key_manager.get_key_by_id(kid)
        if signing_key is None:
            msg = f"Unknown key id: {kid}"
            raise jwt.InvalidTokenError(msg)

        # Build public key from JWK for verification.
        # PyJWT can verify with a PEM-encoded public key directly.
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

        private_key = serialization.load_pem_private_key(
            signing_key.private_pem,
            password=None,
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return jwt.decode(
            token,
            public_pem,
            algorithms=[signing_key.alg],
            audience=audience,
            issuer=self.issuer,
            options={"verify_exp": verify_exp},
        )


__all__ = [
    "IDTokenClaims",
    "IDTokenGenerator",
    "IDTokenVerifier",
]
