"""Key management for OIDC ID token signing.

Provides JWK/JWKS dataclasses and a `KeyManager` protocol with an
in-memory implementation that generates RSA (RS256) or P-256 (ES256) keys
via the `cryptography` library.

Production deployments should implement `KeyManager` against a
persistent store (database, file, KMS) and rotate keys periodically.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

SigningAlgorithm = Literal["RS256", "ES256"]


def _b64url(raw: bytes) -> str:
    """Encode bytes as base64url (no padding)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_uint(value: int) -> str:
    """Encode an unsigned integer as base64url (no padding)."""
    byte_length = (value.bit_length() + 7) // 8
    return _b64url(value.to_bytes(byte_length, "big"))


@dataclass(frozen=True)
class JWK:
    """A JSON Web Key (RFC 7517).

    Supports RSA and EC keys. The `kid` (key ID) is used to identify
    which key was used to sign a JWT.
    """

    kty: str  # Key type (RSA, EC)
    kid: str  # Key ID
    use: str  # "sig" for signing
    alg: str  # Algorithm (RS256, ES256)
    # RSA fields
    n: str | None = None  # Modulus (base64url)
    e: str | None = None  # Exponent (base64url)
    # EC fields
    crv: str | None = None  # Curve
    x: str | None = None
    y: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary (omits None fields)."""
        result: dict[str, Any] = {
            "kty": self.kty,
            "kid": self.kid,
            "use": self.use,
            "alg": self.alg,
        }
        for key in ("n", "e", "crv", "x", "y"):
            value = getattr(self, key)
            if value is not None:
                result[key] = value
        return result


@dataclass(frozen=True)
class JWKS:
    """A JSON Web Key Set (RFC 7517 Section 5)."""

    keys: list[JWK] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"keys": [k.to_dict() for k in self.keys]}


@dataclass(frozen=True)
class SigningKey:
    """A signing key with its private material.

    `private_pem` is the PEM-encoded private key bytes used by the
    JWT library to sign tokens. `public_jwk` is the public-only
    representation that goes into the JWKS endpoint.
    """

    kid: str
    alg: str
    private_pem: bytes
    public_jwk: JWK
    is_active: bool = True


class KeyManager(Protocol):
    """Protocol for managing OIDC signing keys."""

    async def get_active_signing_key(self) -> SigningKey:
        """Get the current active signing key."""
        ...

    async def get_jwks(self) -> JWKS:
        """Get the public JWKS for token verification.

        Should include all keys (active + recently rotated) so
        previously-issued tokens can still be verified.
        """
        ...

    async def get_key_by_id(self, kid: str) -> SigningKey | None:
        """Look up a key by its `kid`."""
        ...

    async def rotate_key(self) -> SigningKey:
        """Generate a new key and mark it active.

        The previously active key is kept for verification of
        outstanding tokens.
        """
        ...


def _generate_signing_key(alg: SigningAlgorithm) -> SigningKey:
    """Generate a signing key: RSA 2048 for RS256, P-256 for ES256."""
    # Lazy import: pyjwt[crypto] / cryptography is an optional extra.
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: PLC0415

    kid = secrets.token_urlsafe(16)
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    if alg == "RS256":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_numbers = private_key.public_key().public_numbers()
        public_jwk = JWK(
            kty="RSA",
            kid=kid,
            use="sig",
            alg=alg,
            n=_b64url_uint(rsa_numbers.n),
            e=_b64url_uint(rsa_numbers.e),
        )
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())
        ec_numbers = private_key.public_key().public_numbers()
        # RFC 7518 §6.2.1: coordinates are the full 32 bytes for P-256.
        public_jwk = JWK(
            kty="EC",
            kid=kid,
            use="sig",
            alg=alg,
            crv="P-256",
            x=_b64url(ec_numbers.x.to_bytes(32, "big")),
            y=_b64url(ec_numbers.y.to_bytes(32, "big")),
        )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return SigningKey(kid=kid, alg=alg, private_pem=private_pem, public_jwk=public_jwk)


class InMemoryKeyManager:
    """In-memory `KeyManager` for development and testing.

    Generates keys on first access, using `algorithm`. Not suitable for
    production: keys are lost on process restart.

    Example:
        manager = InMemoryKeyManager()
        key = await manager.get_active_signing_key()
        jwks = await manager.get_jwks()
    """

    def __init__(self, algorithm: SigningAlgorithm = "RS256") -> None:
        self.algorithm = algorithm
        self._keys: dict[str, SigningKey] = {}
        self._active_kid: str | None = None

    async def get_active_signing_key(self) -> SigningKey:
        if self._active_kid is None:
            await self.rotate_key()
        assert self._active_kid is not None
        return self._keys[self._active_kid]

    async def get_jwks(self) -> JWKS:
        if not self._keys:
            await self.rotate_key()
        return JWKS(keys=[k.public_jwk for k in self._keys.values()])

    async def get_key_by_id(self, kid: str) -> SigningKey | None:
        return self._keys.get(kid)

    async def rotate_key(self) -> SigningKey:
        # Mark previous active key as inactive (still kept for verification)
        if self._active_kid is not None:
            old = self._keys[self._active_kid]
            self._keys[self._active_kid] = SigningKey(
                kid=old.kid,
                alg=old.alg,
                private_pem=old.private_pem,
                public_jwk=old.public_jwk,
                is_active=False,
            )

        new_key = _generate_signing_key(self.algorithm)
        self._keys[new_key.kid] = new_key
        self._active_kid = new_key.kid
        return new_key

    def add_key(self, key: SigningKey) -> None:
        """Manually add a pre-generated key (for testing)."""
        self._keys[key.kid] = key
        if key.is_active:
            self._active_kid = key.kid


__all__ = [
    "JWK",
    "JWKS",
    "InMemoryKeyManager",
    "KeyManager",
    "SigningAlgorithm",
    "SigningKey",
]
